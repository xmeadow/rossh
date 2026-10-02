/*
 * The session layer — authentication and `exec`.
 *
 * The interesting part is what is *not* here: wolfSSH verifies the client's
 * publickey signature itself. Our authentication callback only has to answer the
 * question "may this key log in?", which makes the whole thing a byte comparison
 * against a file. That is the pattern wolfSSH's own echoserver uses.
 */

#include <wolfssl/options.h>
#include <wolfssh/ssh.h>
#include <wolfssl/wolfcrypt/coding.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "session.h"

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/wait.h>
#endif

typedef struct {
    WOLFSSH          *ssh;
    const keylist_t  *keys;
} session_t;

/* One connection at a time (spec.md §7), so one of these is enough. */
static session_t g_session;

/* ------------------------------------------------------------------ keys --- */

static int is_key_type(const char *tok)
{
    return strcmp(tok, "ssh-ed25519") == 0
        || strcmp(tok, "ssh-rsa") == 0
        || strncmp(tok, "ecdsa-sha2-", 11) == 0;
}

/* Hand-rolled on purpose: strtok_r is not reliably present across the two
 * platforms this builds for. Returns the next whitespace-delimited token, or
 * NULL. Writes a NUL over the delimiter. */
static char *next_token(char **cursor)
{
    char *p = *cursor;
    char *start;

    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    if (*p == '\0') {
        *cursor = p;
        return NULL;
    }
    start = p;
    while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
        p++;
    if (*p != '\0') {
        *p = '\0';
        p++;
    }
    *cursor = p;
    return start;
}

int keylist_load(keylist_t *list, const char *path)
{
    FILE *f;
    char  line[2048];

    memset(list, 0, sizeof *list);

    f = fopen(path, "r");
    if (f == NULL)
        return -1;

    while (fgets(line, sizeof line, f) != NULL) {
        char *cursor = line;
        char *tok;
        char *b64 = NULL;
        byte  blob[KEYLIST_MAX_BLOB];
        word32 blobSz = sizeof blob;
        int   stored;

        /* The key blob is the token after the first token that names a key type;
         * anything before it is options, anything after is a comment. */
        while ((tok = next_token(&cursor)) != NULL) {
            if (is_key_type(tok)) {
                b64 = next_token(&cursor);
                break;
            }
        }
        if (b64 == NULL)
            continue;               /* blank line or comment */

        if (Base64_Decode((const byte *)b64, (word32)strlen(b64),
                          blob, &blobSz) != 0) {
            printf("keys: cannot decode a key in %s, skipped\n", path);
            continue;
        }
        if (list->count >= KEYLIST_MAX_KEYS) {
            printf("keys: %s holds more than %d keys, rest ignored\n",
                   path, KEYLIST_MAX_KEYS);
            break;
        }

        stored = list->count++;
        memcpy(list->blobs[stored], blob, blobSz);
        list->sizes[stored] = blobSz;
    }

    fclose(f);
    return 0;
}

int keylist_contains(const keylist_t *list, const byte *blob, word32 sz)
{
    int i;

    for (i = 0; i < list->count; i++) {
        if (list->sizes[i] == sz && memcmp(list->blobs[i], blob, sz) == 0)
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ auth --- */

static int auth_cb(byte auth_type, WS_UserAuthData *auth, void *ctx)
{
    session_t *s = (session_t *)ctx;

    switch (auth_type) {
    case WOLFSSH_USERAUTH_PUBLICKEY:
        printf("auth: publickey offered by '%.*s'\n",
               (int)auth->usernameSz, (const char *)auth->username);
        if (keylist_contains(s->keys, auth->sf.publicKey.publicKey,
                             auth->sf.publicKey.publicKeySz)) {
            printf("auth: key accepted\n");
            return WOLFSSH_USERAUTH_SUCCESS;
        }
        printf("auth: key not in the authorised list\n");
        return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;

    case WOLFSSH_USERAUTH_PASSWORD:
        /* Off by default; the config layer (M4) decides per user. */
        printf("auth: password refused (no password is configured)\n");
        return WOLFSSH_USERAUTH_INVALID_PASSWORD;

    default:
        printf("auth: method %d refused\n", (int)auth_type);
        return WOLFSSH_USERAUTH_FAILURE;
    }
}

/* ------------------------------------------------------------- command ----- */

static void send_to_channel(const char *data, size_t len, void *ctx)
{
    int rc = wolfSSH_ChannelSend((WOLFSSH_CHANNEL *)ctx,
                                 (const byte *)data, (word32)len);
    if (rc != WS_SUCCESS)
        printf("exec: channel send failed (%d), output truncated\n", rc);
}

#ifdef _WIN32
/*
 * Run `command` through cmd.exe with stdout and stderr on one pipe, feeding
 * every chunk to the sink as it arrives.
 *
 * Two things learned on the target (docs/reactos.md): cmd.exe must be reached by
 * full path, because PATH is broken there, and stdin is deliberately not
 * connected — wSSH's stdin semantics are unusable anyway.
 */
static int run_and_stream(const char *command, void (*sink)(const char *, size_t, void *), void *ctx)
{
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;
    HANDLE              rd = NULL, wr = NULL;
    char                shell[MAX_PATH + 32];
    char                line[MAX_PATH + 4096];
    DWORD               env_len;
    int                 status;
    char                buf[4096];

    env_len = GetEnvironmentVariableA("SystemRoot", shell, sizeof shell - 20);
    if (env_len > 0 && env_len < sizeof shell - 20)
        strcat(shell, "\\system32\\cmd.exe");
    else
        strcpy(shell, "cmd.exe");

    snprintf(line, sizeof line, "\"%s\" /c %s", shell, command);

    sa.nLength              = sizeof sa;
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle       = TRUE;
    if (!CreatePipe(&rd, &wr, &sa, 0))
        return -1;

    memset(&si, 0, sizeof si);
    si.cb          = sizeof si;
    si.dwFlags     = STARTF_USESTDHANDLES;
    si.hStdOutput  = wr;
    si.hStdError   = wr;
    si.hStdInput   = NULL;

    memset(&pi, 0, sizeof pi);
    if (!CreateProcessA(NULL, line, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(rd);
        CloseHandle(wr);
        return -1;
    }

    /* Our copy of the write end has to go, or the read never sees EOF. */
    CloseHandle(wr);

    for (;;) {
        DWORD got = 0;
        if (!ReadFile(rd, buf, (DWORD)sizeof buf, &got, NULL) || got == 0)
            break;
        sink(buf, (size_t)got, ctx);
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    {
        DWORD code = 1;
        if (!GetExitCodeProcess(pi.hProcess, &code))
            code = 1;
        status = (int)code;
    }

    CloseHandle(rd);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return status;
}
#else
static int run_and_stream(const char *command, void (*sink)(const char *, size_t, void *), void *ctx)
{
    FILE  *p;
    char   line[8192];
    char   buf[4096];
    int    rc;

    /* popen only gives us stdout, so stderr is folded in here. The target path
     * above does it properly with two handles on one pipe. */
    snprintf(line, sizeof line, "%s 2>&1", command);

    p = popen(line, "r");
    if (p == NULL)
        return -1;

    for (;;) {
        size_t n = fread(buf, 1, sizeof buf, p);
        if (n > 0)
            sink(buf, n, ctx);
        if (n < sizeof buf)
            break;
    }

    rc = pclose(p);
    return (rc == -1) ? -1 : WEXITSTATUS(rc);
}
#endif

/* --------------------------------------------------------------- channel --- */

static int channel_open_cb(WOLFSSH_CHANNEL *channel, void *ctx)
{
    (void)ctx;
    printf("channel: open (%s)\n", wolfSSH_ChannelGetType(channel));
    return WS_SUCCESS;
}

static int channel_exec_cb(WOLFSSH_CHANNEL *channel, void *ctx)
{
    session_t  *s = (session_t *)ctx;
    const char *command = wolfSSH_ChannelGetSessionCommand(channel);
    int         status;

    if (command == NULL) {
        printf("exec: no command in the request\n");
        return WS_BAD_ARGUMENT;
    }

    printf("exec: %s\n", command);
    status = run_and_stream(command, send_to_channel, channel);

    if (status < 0) {
        printf("exec: could not run the command\n");
        status = 127;
    }

    printf("exec: exit status %d\n", status);
    /* Deliberately no wolfSSH_ChannelExit() here: closing the channel from
     * inside the callback races the exit-status message and the client answers a
     * close for a channel that is already gone, which surfaced as a connection
     * reset instead of an exit status. wolfsshd does it the same way — set the
     * status, let the session layer close. */
    wolfSSH_SetExitStatus(s->ssh, (word32)status);
    return WS_SUCCESS;
}

/* ---------------------------------------------------------------- wiring --- */

int session_configure(WOLFSSH_CTX *ctx)
{
    wolfSSH_SetUserAuth(ctx, auth_cb);
    wolfSSH_CTX_SetChannelOpenCb(ctx, channel_open_cb);
    /* The exec callback is what M2 is for. `shell` is deliberately not
     * registered: there is no pty, so a shell request should fail rather than
     * hang (spec.md §4.3). */
    wolfSSH_CTX_SetChannelReqExecCb(ctx, channel_exec_cb);
    return 0;
}

int session_bind(WOLFSSH *ssh, const keylist_t *keys)
{
    g_session.ssh  = ssh;
    g_session.keys = keys;
    wolfSSH_SetUserAuthCtx(ssh, &g_session);
    wolfSSH_SetChannelReqCtx(ssh, &g_session);
    return 0;
}
