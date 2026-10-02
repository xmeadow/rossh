/*
 * The client half — `ssh [user@]host [command]`.
 *
 * Deliberately the same shape as the server: pin the offered algorithms, offer
 * an ed25519 key, run one thing, report its exit status. What it does *not*
 * share is the transport handling — a client connects instead of accepting, and
 * it is the one that has to decide whether it trusts the host key it is given.
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssh/ssh.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "b64.h"
#include "rng.h"
#include "client.h"

#ifdef _WIN32
    #include <winsock2.h>
    typedef SOCKET csock_t;
    #define CSOCK_INVALID INVALID_SOCKET
    #define cclose(f)     closesocket(f)
#else
    #include <sys/socket.h>
    #include <netdb.h>
    #include <unistd.h>
    typedef int csock_t;
    #define CSOCK_INVALID (-1)
    #define cclose(f)     close(f)
#endif

/* The same offer the server pins (spec.md §4.1): what we are willing to speak,
 * and nothing else. */
static const char *algo_kex     = "curve25519-sha256";
static const char *algo_hostkey = "ssh-ed25519";
static const char *algo_cipher  = "aes256-gcm@openssh.com,"
                                  "aes128-gcm@openssh.com,aes256-ctr";
static const char *algo_mac     = "hmac-sha2-256";
static const char *algo_keys    = "ssh-ed25519";

/* -v/--verbose: where a session stalls, so a remote box with no debugger can
 * still say which step it reached. stderr, never stdout — stdout is the
 * remote command's output. */
static int g_verbose;
#define VTRACE(...) do { if (g_verbose) fprintf(stderr, __VA_ARGS__); } while (0)

/*
 * What the auth callback has to hand wolfSSH: the key type, the public blob in
 * wire form, and the private half. All three are filled in once, before the
 * session starts.
 */
typedef struct {
    const byte *priv;
    word32      privSz;
    const byte *type;
    word32      typeSz;
    const byte *pub;
    word32      pubSz;
} ckey_t;

static ckey_t g_key;

/*
 * wolfSSH asks which method to use and, for publickey, wants the key material
 * in the reply. There is nothing to decide here: we have exactly one key.
 */
static int userauth_cb(byte auth_type, WS_UserAuthData *auth, void *ctx)
{
    (void)ctx;

    if (auth_type != WOLFSSH_USERAUTH_PUBLICKEY)
        return WOLFSSH_USERAUTH_FAILURE;

    auth->sf.publicKey.publicKeyType   = g_key.type;
    auth->sf.publicKey.publicKeyTypeSz = g_key.typeSz;
    auth->sf.publicKey.publicKey       = g_key.pub;
    auth->sf.publicKey.publicKeySz     = g_key.pubSz;
    auth->sf.publicKey.privateKey      = g_key.priv;
    auth->sf.publicKey.privateKeySz    = g_key.privSz;

    return WOLFSSH_USERAUTH_SUCCESS;
}

/*
 * The wire form of the public half: string "ssh-ed25519", then string key.
 * Deriving it from the private key means a client key is only ever one file.
 */
static int derive_public(const byte *der, word32 derSz, byte *blob, word32 *blobSz)
{
    ed25519_key key;
    byte        pub[ED25519_PUB_KEY_SIZE];
    word32      pubSz = (word32)sizeof pub;
    word32      idx   = 0;
    word32      out   = 0;
    int         rc;

    if (wc_ed25519_init(&key) != 0)
        return -1;
    rc = wc_Ed25519PrivateKeyDecode(der, &idx, &key, derSz);
    if (rc == 0)
        rc = wc_ed25519_export_public(&key, pub, &pubSz);
    wc_ed25519_free(&key);
    if (rc != 0)
        return -1;

    blob[out++] = 0;
    blob[out++] = 0;
    blob[out++] = 0;
    blob[out++] = 11;
    memcpy(blob + out, "ssh-ed25519", 11);
    out += 11;
    blob[out++] = 0;
    blob[out++] = 0;
    blob[out++] = 0;
    blob[out++] = (byte)pubSz;
    memcpy(blob + out, pub, pubSz);
    out += pubSz;

    *blobSz = out;
    return 0;
}

static word32 put_u32(byte *out, word32 at, word32 v)
{
    out[at++] = (byte)(v >> 24);
    out[at++] = (byte)(v >> 16);
    out[at++] = (byte)(v >> 8);
    out[at++] = (byte)v;
    return at;
}

static word32 put_blob(byte *out, word32 at, const byte *s, word32 n)
{
    at = put_u32(out, at, n);
    if (n > 0) {
        memcpy(out + at, s, n);
        at += n;
    }
    return at;
}

/*
 * wolfSSH's userauth callback wants the private key in OpenSSH's own container
 * ("openssh-key-v1"), not the PKCS#8 DER that `--genkey` writes: its ASN.1
 * reader merely copies the DER through, and the auth path then rejects it with
 * WS_KEY_AUTH_MAGIC_E. So build the container here, from the decoded key.
 */
static int build_openssh_key(const byte *der, word32 derSz,
                             byte *out, word32 cap, word32 *outSz)
{
    ed25519_key key;
    byte        priv[ED25519_PRV_KEY_SIZE];
    byte        pub_blob[96];
    word32      pub_blob_sz = 0;
    word32      priv_sz     = (word32)sizeof priv;
    word32      idx = 0, at = 0, sect, sect_sz, pad, i;
    int         rc;

    if (derive_public(der, derSz, pub_blob, &pub_blob_sz) != 0)
        return -1;

    if (wc_ed25519_init(&key) != 0)
        return -1;
    rc = wc_Ed25519PrivateKeyDecode(der, &idx, &key, derSz);
    if (rc == 0)
        rc = wc_ed25519_export_private(&key, priv, &priv_sz);
    wc_ed25519_free(&key);
    if (rc != 0)
        return -1;

    /* magic, cipher, kdf, kdf options, key count, public key */
    memcpy(out + at, "openssh-key-v1", 15);
    at += 15;
    at = put_blob(out, at, (const byte *)"none", 4);
    at = put_blob(out, at, (const byte *)"none", 4);
    at = put_blob(out, at, (const byte *)"", 0);
    at = put_u32(out, at, 1);
    at = put_blob(out, at, pub_blob, pub_blob_sz);

    /* the private section is itself a string: check bytes, key type, key,
     * comment, then padding to the cipher's block size. */
    at = put_u32(out, at, 0);                 /* length, filled in below */
    sect = at;
    at = put_u32(out, at, 0x526f5353);       /* check1 */
    at = put_u32(out, at, 0x526f5353);       /* check2 must match */
    at = put_blob(out, at, (const byte *)"ssh-ed25519", 11);
    at = put_blob(out, at, pub_blob + 19, 32); /* past the two strings */
    at = put_blob(out, at, priv, priv_sz);
    at = put_blob(out, at, (const byte *)"", 0);

    pad = 8 - ((at - sect) % 8);
    for (i = 1; i <= pad; i++)
        out[at++] = (byte)i;

    sect_sz = at - sect;
    out[sect - 4] = (byte)(sect_sz >> 24);
    out[sect - 3] = (byte)(sect_sz >> 16);
    out[sect - 2] = (byte)(sect_sz >> 8);
    out[sect - 1] = (byte)sect_sz;

    if (at > cap)
        return -1;
    *outSz = at;
    return 0;
}

static csock_t tcp_connect(const char *host, int port)
{
    struct hostent     *he;
    struct sockaddr_in  sa;
    csock_t             fd;

    he = gethostbyname(host);
    if (he == NULL) {
        fprintf(stderr, "ssh: cannot resolve '%s'\n", host);
        return CSOCK_INVALID;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == CSOCK_INVALID) {
        fprintf(stderr, "ssh: cannot create a socket\n");
        return CSOCK_INVALID;
    }

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((unsigned short)port);
    memcpy(&sa.sin_addr, he->h_addr_list[0], (size_t)he->h_length);

    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        fprintf(stderr, "ssh: cannot connect to %s:%d\n", host, port);
        cclose(fd);
        return CSOCK_INVALID;
    }
    return fd;
}

static size_t slurp(const char *path, byte *buf, size_t cap)
{
    FILE  *f;
    size_t n;

    f = fopen(path, "rb");
    if (f == NULL)
        return 0;
    n = fread(buf, 1, cap, f);
    fclose(f);
    return n;
}

/*
 * Trust on first use, which is what a small deployment wants and what OpenSSH
 * did for years: the first key seen for a host is written down, and any later
 * one that differs is refused rather than quietly accepted.
 */
static int known_host_ok(const client_opts_t *o, const char *b64)
{
    FILE *f;
    char  line[512];
    int   known = 0;

    if (o->known_hosts == NULL)
        return 1;                          /* nothing to remember with */

    f = fopen(o->known_hosts, "r");
    if (f != NULL) {
        while (fgets(line, sizeof line, f) != NULL) {
            char *sep = strchr(line, ' ');
            char *end;

            if (sep == NULL)
                continue;
            *sep = '\0';
            if (strcmp(line, o->host) != 0)
                continue;

            known = 1;
            sep++;
            end = strpbrk(sep, "\r\n");
            if (end != NULL)
                *end = '\0';
            if (strcmp(sep, b64) == 0) {
                fclose(f);
                return 1;
            }
        }
        fclose(f);
    }

    if (known) {
        fprintf(stderr,
                "ssh: the host key of %s does NOT match the one on record — "
                "refusing to connect\n", o->host);
        return 0;
    }

    f = fopen(o->known_hosts, "a");
    if (f != NULL) {
        fprintf(f, "%s %s\n", o->host, b64);
        fclose(f);
        fprintf(stderr, "ssh: added the host key of %s to %s\n",
                o->host, o->known_hosts);
    }
    return 1;
}

/* Called by wolfSSH once the host key is known. Zero accepts, non-zero refuses. */
static int hostkey_cb(const byte *pubKey, word32 pubKeySz, void *ctx)
{
    const client_opts_t *o = (const client_opts_t *)ctx;
    char    b64[256];
    int     b64Sz;

    if (o->insecure) {
        fprintf(stderr, "ssh: WARNING — the host key is not being verified\n");
        return 0;
    }

    b64Sz = b64_encode_nl(pubKey, pubKeySz, b64, sizeof b64);
    if (b64Sz < 0) {
        fprintf(stderr, "ssh: cannot encode the host key\n");
        return -1;
    }

    return known_host_ok(o, b64) ? 0 : -1;
}

static int session_run(const client_opts_t *o)
{
    WOLFSSH_CTX *ctx = NULL;
    WOLFSSH     *ssh = NULL;
    csock_t      fd  = CSOCK_INVALID;
    byte         key[4096];
    size_t       keySz;
    char         buf[4096];
    int          rc;
    int          status = 255;

    keySz = slurp(o->key_path, key, sizeof key);
    if (keySz == 0) {
        fprintf(stderr, "ssh: cannot read the private key '%s'\n", o->key_path);
        return 255;
    }
    VTRACE("ssh: read %u bytes of key from '%s'\n", (unsigned)keySz, o->key_path);

    /* Fill the auth material in once: the private half in the shape wolfSSH
     * asks for, and the public blob derived from it, so a client key stays one
     * file. */
    {
        static byte priv_buf[1024];
        static byte pub_blob[96];
        word32      privSz = 0;
        word32      pubSz  = 0;

        /* Both halves come from the one DER file: the public wire blob for the
         * auth request, and the private half in the OpenSSH container wolfSSH
         * insists on there. */
        if (derive_public(key, (word32)keySz, pub_blob, &pubSz) != 0 ||
            build_openssh_key(key, (word32)keySz, priv_buf, sizeof priv_buf,
                              &privSz) != 0) {
            fprintf(stderr, "ssh: '%s' is not a usable ed25519 key\n",
                    o->key_path);
            return 255;
        }

        g_key.priv   = priv_buf;
        g_key.privSz = privSz;
        g_key.type   = (const byte *)"ssh-ed25519";
        g_key.typeSz = 11;
        g_key.pub    = pub_blob;
        g_key.pubSz  = pubSz;
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "ssh: out of memory\n");
        return 255;
    }

    if (wolfSSH_CTX_SetAlgoListKex(ctx, algo_kex) < 0 ||
        wolfSSH_CTX_SetAlgoListKey(ctx, algo_hostkey) < 0 ||
        wolfSSH_CTX_SetAlgoListCipher(ctx, algo_cipher) < 0 ||
        wolfSSH_CTX_SetAlgoListMac(ctx, algo_mac) < 0 ||
        wolfSSH_CTX_SetAlgoListKeyAccepted(ctx, algo_keys) < 0) {
        fprintf(stderr, "ssh: this build cannot offer the required algorithms\n");
        wolfSSH_CTX_free(ctx);
        return 255;
    }

    wolfSSH_SetUserAuth(ctx, userauth_cb);
    wolfSSH_CTX_SetPublicKeyCheck(ctx, hostkey_cb);
    if (wolfSSH_CTX_UsePrivateKey_buffer(ctx, key, (word32)keySz,
                                         WOLFSSH_FORMAT_ASN1) != WS_SUCCESS) {
        fprintf(stderr, "ssh: '%s' is not a usable ed25519 key\n", o->key_path);
        wolfSSH_CTX_free(ctx);
        return 255;
    }

    fd = tcp_connect(o->host, o->port);
    if (fd == CSOCK_INVALID) {
        wolfSSH_CTX_free(ctx);
        return 255;
    }
    VTRACE("ssh: connected to %s:%d as '%s'\n", o->host, o->port, o->user);

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL) {
        cclose(fd);
        wolfSSH_CTX_free(ctx);
        return 255;
    }

    wolfSSH_set_fd(ssh, (WS_SOCKET_T)fd);
    wolfSSH_SetUsername(ssh, o->user);
    wolfSSH_SetPublicKeyCheckCtx(ssh, (void *)o);

    if (o->command != NULL &&
        wolfSSH_SetChannelType(ssh, WOLFSSH_SESSION_EXEC,
                               (byte *)o->command,
                               (word32)strlen(o->command)) != WS_SUCCESS) {
        fprintf(stderr, "ssh: cannot request a command\n");
        goto done;
    }

    rc = wolfSSH_connect(ssh);
    VTRACE("ssh: wolfSSH_connect rc=%d err=%d\n", rc, wolfSSH_get_error(ssh));
    /* The return value can be a plain failure while the *error* says the
     * handshake actually finished and the peer already sent channel data
     * (WS_CHAN_RXD) — which is the normal case here, since the command's output
     * may be waiting before we ever ask for it. */
    {
        int err = wolfSSH_get_error(ssh);
        if (rc != WS_SUCCESS && err != WS_CHAN_RXD &&
            err != WS_WANT_READ && err != WS_WANT_WRITE) {
            fprintf(stderr,
                    "ssh: the session could not be established (%d, error %d)\n",
                    rc, err);
            goto done;
        }
    }

    for (;;) {
        rc = wolfSSH_stream_read(ssh, (byte *)buf, (word32)sizeof buf);
        if (rc > 0) {
            VTRACE("ssh: read %d bytes\n", rc);
            fwrite(buf, 1, (size_t)rc, stdout);
            fflush(stdout);
            continue;
        }
        rc = wolfSSH_get_error(ssh);
        if (rc == WS_WANT_READ || rc == WS_WANT_WRITE || rc == WS_CHAN_RXD)
            continue;
        break;
    }
    fflush(stdout);
    VTRACE("ssh: channel closed (err=%d)\n", wolfSSH_get_error(ssh));

    /* The exit status travels as its own channel request, which can land after
     * the command's output has ended. Give the session one more turn before
     * asking for it. */
    wolfSSH_worker(ssh, NULL);
    status = wolfSSH_GetExitStatus(ssh);
    VTRACE("ssh: exit status %d\n", status);
    if (status < 0)
        status = 1;

done:
    if (ssh != NULL) {
        wolfSSH_shutdown(ssh);
        wolfSSH_free(ssh);
    }
    if (fd != CSOCK_INVALID)
        cclose(fd);
    wolfSSH_CTX_free(ctx);
    return status;
}

#ifdef DEBUG_WOLFSSH
/* wolfSSH's default logging callback writes to stdout, which for a client is the
 * remote command's output. Send the protocol trace to stderr instead. */
static void cli_log_cb(enum wolfSSH_LogLevel level, const char *const msg)
{
    (void)level;
    fprintf(stderr, "wolfSSH: %s\n", msg);
}
#endif

static void client_usage(void)
{
    fprintf(stderr,
        "usage: ssh [-p port] [-i key] [-l user] [--known-hosts file]\n"
        "           [--insecure] [-v] [user@]host [command]\n"
        "\n"
        "  -i key            PKCS#8 DER ed25519 private key "
        "(rossh --genkey <path>)\n"
        "  --known-hosts f   trust-on-first-use store (default: known_hosts)\n"
        "  --insecure        do not verify the host key (prints a warning)\n"
        "  -v                trace each step to stderr\n");
}

int client_main(int argc, char **argv)
{
    client_opts_t o;
    const char   *target = NULL;
    char          user[128];
    char          command[2048];
    const char   *at;
    int           i;
    int           have_command = 0;

    memset(&o, 0, sizeof o);
    o.port        = 22;
    o.known_hosts = "known_hosts";

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (strcmp(a, "--client") == 0)
            continue;
        if (strcmp(a, "-p") == 0 && i + 1 < argc)
            o.port = atoi(argv[++i]);
        else if (strcmp(a, "-i") == 0 && i + 1 < argc)
            o.key_path = argv[++i];
        else if (strcmp(a, "-l") == 0 && i + 1 < argc)
            o.user = argv[++i];
        else if (strcmp(a, "--known-hosts") == 0 && i + 1 < argc)
            o.known_hosts = argv[++i];
        else if (strcmp(a, "--insecure") == 0)
            o.insecure = 1;
        else if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0)
            g_verbose = 1;
        else if (target == NULL && a[0] != '-')
            target = a;
        else
            break;                         /* the command starts here */
    }

    if (target == NULL) {
        client_usage();
        return 2;
    }

    /* Everything left over is the command, joined back together — cmd.exe gets
     * one line, the way it does from a shell. */
    command[0] = '\0';
    for (; i < argc; i++) {
        if (have_command && strlen(command) + 1 < sizeof command)
            strcat(command, " ");
        if (strlen(command) + strlen(argv[i]) < sizeof command)
            strcat(command, argv[i]);
        have_command = 1;
    }
    if (have_command)
        o.command = command;

    if (o.key_path == NULL) {
        fprintf(stderr, "ssh: no key given — use -i <key>, or --genkey one\n");
        client_usage();
        return 2;
    }

    /* Split [user@]host. */
    at = strchr(target, '@');
    if (at != NULL) {
        size_t n = (size_t)(at - target);
        if (n >= sizeof user)
            n = sizeof user - 1;
        memcpy(user, target, n);
        user[n]  = '\0';
        o.user   = user;
        o.host   = at + 1;
    }
    else {
        o.host = target;
        if (o.user == NULL)
            o.user = "rossh";              /* a default, since we have no $USER */
    }

    if (o.user == NULL || o.user[0] == '\0') {
        fprintf(stderr, "ssh: no user name — use -l <user> or user@host\n");
        return 2;
    }

#ifdef _WIN32
    /* Winsock has to be up before gethostbyname() or socket(). On Linux this is
     * implicit, which is why the native build never missed it. */
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            fprintf(stderr, "ssh: WSAStartup failed\n");
            return 255;
        }
    }
#endif

    /* wolfCrypt's global state — in particular the mutex guarding its DRBG —
     * has to exist before the first RNG use. The key exchange draws random
     * numbers, so the client needs the same start-up the server does; without
     * it the first RNG call deadlocks on ReactOS (a zeroed mutex is harmless on
     * Linux, which is why the native build never missed it). */
    rng_start();

#ifdef DEBUG_WOLFSSH
    wolfSSH_SetLoggingCb(cli_log_cb);
    wolfSSH_Debugging_ON();
#endif

    return session_run(&o);
}
