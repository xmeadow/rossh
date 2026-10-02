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
#include <wolfssh/wolfsftp.h>
#include <wolfssl/wolfcrypt/coding.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "session.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <windows.h>
#else
    #include <sys/wait.h>
    #include <sys/select.h>
    #include <sys/ioctl.h>
    #include <termios.h>
    #include <pty.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <signal.h>
    #include <errno.h>
    #include <time.h>
#endif

typedef struct {
    WOLFSSH          *ssh;
    const keylist_t  *keys;
    WOLFSSH_CHANNEL  *shell;     /* set once a `shell` request arrives */
    int               term_w;    /* terminal size, from pty-req / window-change */
    int               term_h;
    int               term_set;
    int               pty_fd;    /* the live pty master, for resize; -1 otherwise */
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

/*
 * Push command output out of the channel.
 *
 * wolfSSH_ChannelSend() returns the number of bytes the peer accepted, not a
 * status: a chunk larger than the peer's window or maximum packet size is sent
 * only in part, and the rest has to follow. Treating that partial count as an
 * error is how output used to get silently truncated — `whoami` arrived, the
 * second command in the same line did not.
 */
static void send_to_channel(const char *data, size_t len, void *ctx)
{
    WOLFSSH_CHANNEL *channel = (WOLFSSH_CHANNEL *)ctx;
    size_t           sent    = 0;
    int              stalls  = 0;

    while (sent < len) {
        word32 n  = (word32)(len - sent);
        int    rc = wolfSSH_ChannelSend(channel, (const byte *)data + sent, n);

        if (rc > 0) {                      /* the peer took that many bytes */
            sent += ((size_t)rc > (size_t)n) ? (size_t)n : (size_t)rc;
            stalls = 0;
            continue;
        }

        if (rc == WS_WINDOW_FULL || rc == WS_WANT_WRITE) {
            /* The window is exhausted. The peer owes us an adjustment once it
             * has read; on a blocking socket, pumping the session is what lets
             * it arrive. Give up only if the peer never gets there. */
            if (++stalls > 1000) {
                printf("exec: the channel window stayed full, output truncated\n");
                return;
            }
            if (wolfSSH_worker(g_session.ssh, NULL) < 0 &&
                wolfSSH_get_error(g_session.ssh) == WS_EOF)
                return;                    /* peer gone */
            continue;
        }

        printf("exec: channel send failed (%d), output truncated\n", rc);
        return;
    }
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

/* ------------------------------------------------------------- subsystem --- */

/* A client asks for a subsystem by name in a channel request. We know one:
 * "sftp". Accepting it hands the session to wolfSSH's SFTP server, which owns
 * the filesystem side itself (port.c on Windows). Returning non-zero rejects
 * the request. */
static int channel_subsys_cb(WOLFSSH_CHANNEL *channel, void *ctx)
{
    const char *name = wolfSSH_ChannelGetSessionCommand(channel);

    (void)ctx;
    printf("subsystem: %s\n", (name != NULL) ? name : "(none)");

    if (name != NULL && strcmp(name, "sftp") == 0)
        return WS_SUCCESS;

    printf("subsystem: unknown, refused\n");
    return WS_FATAL_ERROR;
}

/*
 * Serve the SFTP subsystem until the client goes away.
 *
 * `root` is the jail: every path the client sends is resolved against it and
 * cannot walk above it. Without one wolfSSH resolves against the process's
 * working directory, which is rarely what a server wants — M4 makes this
 * per-user, from the config.
 */
int session_sftp(WOLFSSH *ssh, const char *root)
{
    int ret;
    int error;

    if (root != NULL) {
        if (wolfSSH_SFTP_SetDefaultPath(ssh, root) != WS_SUCCESS) {
            printf("sftp: cannot use root '%s'\n", root);
            return WS_FATAL_ERROR;
        }
    }
    printf("sftp: serving from '%s'\n", (root != NULL) ? root : "(cwd)");
    fflush(stdout);

    /* The version exchange is already done: wolfSSH_accept() runs the SFTP init
     * itself and reports WS_SFTP_COMPLETE. What is left is to say where files
     * live — done above — and then answer requests. On a blocking socket a
     * WANT_READ just means the next call blocks in recv(). */
    for (;;) {
        ret   = wolfSSH_SFTP_read(ssh);
        error = wolfSSH_get_error(ssh);

        if (error == WS_EOF)
            break;
        if (error == WS_WANT_READ || error == WS_WANT_WRITE ||
            error == WS_WINDOW_FULL || error == WS_CHAN_RXD ||
            ret == WS_REKEYING)
            continue;
        if (ret < 0)
            break;
    }

    printf("sftp: session ended (%d)\n", ret);
    fflush(stdout);
    return ret;
}

/* ----------------------------------------------------------------- shell --- */

/*
 * Interactive shell (M5).
 *
 * The request is trivial — remember the channel, let wolfSSH answer success.
 * The work is moving bytes between the SSH channel and whatever plays the shell,
 * and that is where the two targets diverge:
 *
 *   POSIX    forkpty() gives a real terminal: line editing, echo, Ctrl-C and
 *            full-screen programs all come for free. Nothing to emulate.
 *   Windows  CreateProcess(cmd.exe) on pipes. cmd.exe prints its prompt into a
 *            pipe and reads command lines from one, but it does not echo and
 *            has no line editor without a console. So we echo and edit the line
 *            ourselves and only ever hand cmd.exe a finished line. Full-screen
 *            programs are out of reach here; the prompt and the loop are not.
 *
 * The connection socket goes non-blocking for the duration, so a full channel
 * window cannot wedge the session (send_to_channel already copes with
 * WS_WANT_WRITE).
 */

static void shell_sleep_ms(int ms)
{
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

#ifndef _WIN32
static void shell_set_nonblocking(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0)
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int shell_write_all(int fd, const byte *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n > 0) {
            buf += n;
            len -= (size_t)n;
        }
        else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            shell_sleep_ms(1);
        }
        else {
            return -1;
        }
    }
    return 0;
}

static int shell_posix(WOLFSSH *ssh, WOLFSSH_CHANNEL *channel, WS_SOCKET_T fd)
{
    struct winsize ws;
    int            master = -1;
    pid_t          pid;
    byte           buf[4096];
    int            done = 0;

    ws.ws_col    = (unsigned short)((g_session.term_set && g_session.term_w > 0)
                                    ? g_session.term_w : 80);
    ws.ws_row    = (unsigned short)((g_session.term_set && g_session.term_h > 0)
                                    ? g_session.term_h : 24);
    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;

    pid = forkpty(&master, NULL, NULL, &ws);
    if (pid < 0) {
        printf("shell: forkpty failed (%d)\n", errno);
        return -1;
    }
    if (pid == 0) {
        const char *sh = getenv("SHELL");
        if (sh == NULL || *sh == '\0')
            sh = "/bin/sh";
        execl(sh, sh, "-i", (char *)NULL);
        execl("/bin/sh", "sh", "-i", (char *)NULL);
        _exit(127);
    }

    g_session.pty_fd = master;
    shell_set_nonblocking(master);
    shell_set_nonblocking((int)fd);
    printf("shell: pty open, pid %d (%ux%u)\n",
           (int)pid, (unsigned)ws.ws_col, (unsigned)ws.ws_row);
    fflush(stdout);

    while (!done) {
        int progressed = 0;

        for (;;) {                              /* the shell -> the client */
            ssize_t n = read(master, buf, sizeof buf);
            if (n > 0) {
                send_to_channel((const char *)buf, (size_t)n, channel);
                progressed = 1;
            }
            else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            }
            else {
                done = 1;                       /* EOF: the shell exited */
                break;
            }
        }

        while (!done) {                         /* the client -> the shell */
            int rc = wolfSSH_stream_read(ssh, buf, (word32)sizeof buf);
            if (rc > 0) {
                if (shell_write_all(master, buf, (size_t)rc) != 0)
                    done = 1;
                progressed = 1;
            }
            else {
                int e = wolfSSH_get_error(ssh);
                if (rc == WS_WANT_READ || e == WS_WANT_READ ||
                    e == WS_WANT_WRITE || e == WS_CHAN_RXD || rc == WS_REKEYING)
                    break;
                done = 1;                       /* the client closed */
            }
        }

        if (!done && !progressed)
            shell_sleep_ms(20);
    }

    g_session.pty_fd = -1;
    if (master >= 0)
        close(master);
    kill(pid, SIGHUP);
    waitpid(pid, NULL, 0);
    printf("shell: session ended\n");
    fflush(stdout);
    return 0;
}
#else
/*
 * The child's output has to be read without blocking the loop (which also has
 * to service the socket), and ReactOS' PeekNamedPipe is not dependable enough to
 * poll with. So the blocking read lives on its own thread and only ever touches
 * this ring; the loop drains it.
 */
#define PIPE_RING 65536

typedef struct {
    CRITICAL_SECTION lock;
    HANDLE           rd;
    byte             buf[PIPE_RING];
    size_t           head;
    size_t           count;
    int              closed;
} pipe_ring_t;

static DWORD WINAPI pipe_reader(LPVOID arg)
{
    pipe_ring_t *r = (pipe_ring_t *)arg;
    byte         tmp[2048];

    for (;;) {
        DWORD got = 0, k;

        if (!ReadFile(r->rd, tmp, (DWORD)sizeof tmp, &got, NULL) || got == 0)
            break;

        EnterCriticalSection(&r->lock);
        for (k = 0; k < got; k++) {
            if (r->count < PIPE_RING) {
                r->buf[(r->head + r->count) % PIPE_RING] = tmp[k];
                r->count++;
            }
            /* A full ring means the client is far behind; drop rather than block
             * the reader, since a blocked reader also stalls cmd.exe. */
        }
        LeaveCriticalSection(&r->lock);
    }

    EnterCriticalSection(&r->lock);
    r->closed = 1;
    LeaveCriticalSection(&r->lock);
    return 0;
}

static size_t pipe_ring_drain(pipe_ring_t *r, byte *out, size_t cap)
{
    size_t n, k;

    EnterCriticalSection(&r->lock);
    n = (r->count < cap) ? r->count : cap;
    for (k = 0; k < n; k++) {
        out[k]   = r->buf[r->head];
        r->head  = (r->head + 1) % PIPE_RING;
    }
    r->count -= n;
    LeaveCriticalSection(&r->lock);
    return n;
}

static int pipe_ring_closed(pipe_ring_t *r)
{
    int c;

    EnterCriticalSection(&r->lock);
    c = r->closed;
    LeaveCriticalSection(&r->lock);
    return c;
}

static int shell_windows(WOLFSSH *ssh, WOLFSSH_CHANNEL *channel, WS_SOCKET_T fd)
{
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;
    HANDLE              in_r = NULL, in_w = NULL, out_r = NULL, out_w = NULL;
    HANDLE              reader = NULL;
    pipe_ring_t         ring;
    char                shell[MAX_PATH + 32];
    char                line[1024];
    size_t              lineLen = 0;
    byte                buf[4096];
    DWORD               envLen, written;
    u_long              one = 1;
    int                 done = 0, i;

    sa.nLength              = sizeof sa;
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle       = TRUE;
    if (!CreatePipe(&in_r, &in_w, &sa, 0))
        return -1;
    if (!CreatePipe(&out_r, &out_w, &sa, 0)) {
        CloseHandle(in_r);
        CloseHandle(in_w);
        return -1;
    }
    /* Our ends must not be inherited, or the child keeps the pipe open and the
     * read never sees EOF. */
    SetHandleInformation(in_w,  HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);

    envLen = GetEnvironmentVariableA("SystemRoot", shell, sizeof shell - 20);
    if (envLen > 0 && envLen < sizeof shell - 20)
        strcat(shell, "\\system32\\cmd.exe");
    else
        strcpy(shell, "cmd.exe");

    memset(&si, 0, sizeof si);
    si.cb         = sizeof si;
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdInput  = in_r;
    si.hStdOutput = out_w;
    si.hStdError  = out_w;

    memset(&pi, 0, sizeof pi);
    if (!CreateProcessA(NULL, shell, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(in_r);  CloseHandle(in_w);
        CloseHandle(out_r); CloseHandle(out_w);
        return -1;
    }
    CloseHandle(in_r);
    CloseHandle(out_w);

    memset(&ring, 0, sizeof ring);
    ring.rd = out_r;
    InitializeCriticalSection(&ring.lock);
    reader = CreateThread(NULL, 0, pipe_reader, &ring, 0, NULL);

    ioctlsocket(fd, FIONBIO, &one);
    printf("shell: cmd.exe pid %lu\n", (unsigned long)pi.dwProcessId);
    fflush(stdout);

    while (!done) {
        int    progressed = 0;
        size_t n;

        while ((n = pipe_ring_drain(&ring, buf, sizeof buf)) > 0) {   /* shell -> client */
            send_to_channel((const char *)buf, n, channel);
            progressed = 1;
        }
        if (pipe_ring_closed(&ring)) {
            /* cmd.exe is gone and the reader has the last of its output; the
             * drain above already emptied the ring, so the session is over. */
            done = 1;
            break;
        }

        while (!done) {                         /* the client -> the shell */
            int rc = wolfSSH_stream_read(ssh, buf, (word32)sizeof buf);

            if (rc <= 0) {
                int e = wolfSSH_get_error(ssh);
                if (rc == WS_WANT_READ || e == WS_WANT_READ ||
                    e == WS_WANT_WRITE || e == WS_CHAN_RXD || rc == WS_REKEYING)
                    break;
                /* The client stopped sending (EOF) or went away. Close cmd.exe's
                 * stdin so it sees EOF and exits once it has finished what it
                 * already has; keep draining until it does. Ending here instead
                 * would cut off the reply. */
                if (in_w != NULL) {
                    CloseHandle(in_w);
                    in_w = NULL;
                }
                break;
            }
            progressed = 1;
            for (i = 0; i < rc; i++) {
                byte c = buf[i];

                if (c == '\r' || c == '\n') {          /* end of line */
                    send_to_channel("\r\n", 2, channel);
                    if (in_w != NULL && lineLen > 0)
                        WriteFile(in_w, line, (DWORD)lineLen, &written, NULL);
                    if (in_w != NULL)
                        WriteFile(in_w, "\r\n", 2, &written, NULL);
                    lineLen = 0;
                }
                else if (c == 0x7f || c == 0x08) {      /* backspace */
                    if (lineLen > 0) {
                        lineLen--;
                        send_to_channel("\b \b", 3, channel);
                    }
                }
                else if (c == 0x03) {                   /* Ctrl-C */
                    send_to_channel("^C\r\n", 4, channel);
                    lineLen = 0;
                }
                else if (c == 0x04) {                   /* Ctrl-D */
                    if (lineLen == 0 && in_w != NULL) {
                        CloseHandle(in_w);              /* EOF: cmd.exe exits */
                        in_w = NULL;
                    }
                }
                else if (c >= 0x20) {                   /* printable: echo it */
                    if (lineLen < sizeof line)
                        line[lineLen++] = (char)c;
                    send_to_channel((const char *)&c, 1, channel);
                }
                /* escape sequences and other control bytes are dropped */
            }
        }

        if (!done && !progressed)
            shell_sleep_ms(20);
    }

    if (in_w != NULL)
        CloseHandle(in_w);
    CloseHandle(out_r);                         /* unblocks the reader */
    if (reader != NULL) {
        WaitForSingleObject(reader, 2000);
        CloseHandle(reader);
    }
    DeleteCriticalSection(&ring.lock);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    printf("shell: session ended\n");
    fflush(stdout);
    return 0;
}
#endif

static int channel_shell_cb(WOLFSSH_CHANNEL *channel, void *ctx)
{
    session_t *s = (session_t *)ctx;

    printf("shell: request (pty=%d)\n", wolfSSH_ChannelIsPty(channel));
    s->shell = channel;
    return WS_SUCCESS;
}

/* pty-req and window-change both land here, before the shell starts and while it
 * runs. Native builds apply it to the live pty; Windows just remembers it, since
 * cmd.exe does not care. */
static int term_resize_cb(WOLFSSH *ssh, word32 w, word32 h,
                          word32 pw, word32 ph, void *ctx)
{
    session_t *s = (session_t *)ctx;

    (void)ssh; (void)pw; (void)ph;
    s->term_w   = (int)w;
    s->term_h   = (int)h;
    s->term_set = 1;
    printf("shell: terminal %ux%u\n", (unsigned)w, (unsigned)h);

#ifndef _WIN32
    if (s->pty_fd >= 0) {                       /* live resize of a running shell */
        struct winsize ws;
        ws.ws_col    = (unsigned short)w;
        ws.ws_row    = (unsigned short)h;
        ws.ws_xpixel = 0;
        ws.ws_ypixel = 0;
        ioctl(s->pty_fd, TIOCSWINSZ, &ws);
    }
#endif
    return WS_SUCCESS;
}

int session_shell_requested(void)
{
    return g_session.shell != NULL;
}

int session_shell(WOLFSSH *ssh, WS_SOCKET_T fd)
{
    if (g_session.shell == NULL)
        return -1;
#ifdef _WIN32
    return shell_windows(ssh, g_session.shell, fd);
#else
    return shell_posix(ssh, g_session.shell, fd);
#endif
}

/* ---------------------------------------------------------------- wiring --- */

int session_configure(WOLFSSH_CTX *ctx)
{
    wolfSSH_SetUserAuth(ctx, auth_cb);
    wolfSSH_CTX_SetChannelOpenCb(ctx, channel_open_cb);
    /* `exec` runs one command (M2); `shell` starts the interactive session (M5).
     * Both are request callbacks; the shell one only records the channel. */
    wolfSSH_CTX_SetChannelReqExecCb(ctx, channel_exec_cb);
    wolfSSH_CTX_SetChannelReqSubsysCb(ctx, channel_subsys_cb);
    wolfSSH_CTX_SetChannelReqShellCb(ctx, channel_shell_cb);
    return 0;
}

int session_bind(WOLFSSH *ssh, const keylist_t *keys)
{
    g_session.ssh      = ssh;
    g_session.keys     = keys;
    g_session.shell    = NULL;
    g_session.term_w   = 80;
    g_session.term_h   = 24;
    g_session.term_set = 0;
    g_session.pty_fd   = -1;
    wolfSSH_SetUserAuthCtx(ssh, &g_session);
    wolfSSH_SetChannelReqCtx(ssh, &g_session);
    wolfSSH_SetTerminalResizeCb(ssh, term_resize_cb);
    wolfSSH_SetTerminalResizeCtx(ssh, &g_session);
    return 0;
}
