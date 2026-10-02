/*
 * rossh — an SSH server and client for ReactOS.
 *
 * Server mode binds a listener, offers the modern suite of spec.md §4.1, and
 * serves one session at a time: publickey auth, `exec`, and the SFTP subsystem.
 * Client mode — entered when the program is invoked as `ssh`, or with --client —
 * connects out and runs one command. Both live in this one binary; see
 * src/client.c.
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssh/ssh.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "b64.h"
#include "config.h"
#include "hostkey.h"
#include "log.h"
#include "rng.h"
#include "server.h"
#include "service.h"
#include "setup.h"
#include "session.h"
#include "client.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <io.h>
    typedef SOCKET socket_t;
    #define socklen_type int
    #define close_socket closesocket
#else
    #include <arpa/inet.h>
    #include <errno.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <unistd.h>
    typedef int socket_t;
    #define socklen_type socklen_t
    #define close_socket close
    #ifndef INVALID_SOCKET
        #define INVALID_SOCKET (-1)
    #endif
#endif

static const char server_banner[] = "rossh M1";

/* Exactly spec.md §4.1. Widening this is a deliberate decision, never a default:
 * no SHA-1, no dh-group1, no CBC, no 'none'. */
static const char algo_kex[]     = "curve25519-sha256";
static const char algo_hostkey[] = "ssh-ed25519";
static const char algo_cipher[]  = "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr";
static const char algo_mac[]     = "hmac-sha2-256";
static const char algo_keys[]    = "ssh-ed25519";

/* The authorised keys. File scope so 32 KB of key material does not sit on the
 * stack. */
static keylist_t g_keys;

static int load_host_key(WOLFSSH_CTX *ctx, const char *path)
{
    FILE *f;
    long  size;
    byte *buf;
    int   rc;

    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "rossh: cannot open host key '%s'\n", path);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) <= 0) {
        fprintf(stderr, "rossh: host key '%s' is empty or unreadable\n", path);
        fclose(f);
        return -1;
    }
    rewind(f);

    buf = (byte *)malloc((size_t)size);
    if (buf == NULL || fread(buf, 1, (size_t)size, f) != (size_t)size) {
        fprintf(stderr, "rossh: cannot read host key '%s'\n", path);
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);

    /* PKCS#8 DER, not PEM and not OpenSSH's own format. wolfSSH only handles
     * those two when it is built with WOLFSSH_CERTS (--enable-certs), which is
     * X.509 support we deliberately do not carry; without it they answer
     * WS_UNIMPLEMENTED_E. Ed25519 keys themselves are decoded from PKCS#8.
     * See docs/build.md. */
    rc = wolfSSH_CTX_UsePrivateKey_buffer(ctx, buf, (word32)size,
                                          WOLFSSH_FORMAT_ASN1);
    memset(buf, 0, (size_t)size);
    free(buf);

    if (rc < 0) {
        fprintf(stderr, "rossh: host key '%s' rejected (%d); expected a "
                        "PKCS#8 DER ed25519 key\n", path, rc);
        return -1;
    }
    return 0;
}

/* A short pause, and the platform's last socket error. */
static void pause_ms(unsigned ms)
{
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts;
    ts.tv_sec  = (time_t)(ms / 1000);
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

static int last_socket_error(void)
{
#ifdef _WIN32
    return (int)WSAGetLastError();
#else
    return errno;
#endif
}

static socket_t listen_on(const char *addr, int port)
{
    socket_t           fd;
    struct sockaddr_in sa;
    int                one = 1;
    unsigned long      ip;   /* in_addr_t is POSIX; winsock has no such name */

    /* inet_addr, not inet_pton: the former has existed since forever and is
     * what ReactOS is certain to have. */
    ip = inet_addr(addr);
    if (ip == INADDR_NONE) {
        fprintf(stderr, "rossh: '%s' is not a valid bind address\n", addr);
        return INVALID_SOCKET;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET)
        return INVALID_SOCKET;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);

    memset(&sa, 0, sizeof sa);
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = ip;
    sa.sin_port        = htons((unsigned short)port);

    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0 ||
        listen(fd, 8) != 0) {
        close_socket(fd);
        return INVALID_SOCKET;
    }
    return fd;
}

/*
 * A trace file, written and flushed at each stage.
 *
 * On the target this is the only channel that proved reliable: wSSH's exec
 * forwards stdout and not stderr, buffering hides what does arrive, and a process
 * that hangs before its first line is otherwise completely invisible. A file is
 * independent of all of that.
 */
static FILE *g_trace = NULL;

static void trace(const char *msg)
{
    if (g_trace == NULL)
        return;
    fprintf(g_trace, "%s\n", msg);
    fflush(g_trace);
}

static void trace_open(const char *path)
{
    g_trace = fopen(path, "w");
    if (g_trace == NULL)
        fprintf(stderr, "rossh: cannot write trace file '%s'\n", path);
    else
        trace("trace open");
}

/* Are we `ssh`? True when the program name says so — which is why shipping the
 * same binary as ssh.exe is enough — or when --client was asked for. */
static int is_ssh_invocation(const char *argv0)
{
    const char *base = argv0;
    const char *p;

    for (p = argv0; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\')
            base = p + 1;
    }
    return (base[0] == 's' || base[0] == 'S') &&
           (base[1] == 's' || base[1] == 'S') &&
           (base[2] == 'h' || base[2] == 'H');
}

static int client_requested(int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--client") == 0)
            return 1;
    }
    return 0;
}

/* ----------------------------------------------------------------- server -- */

static socket_t    g_listen_fd = INVALID_SOCKET;
static volatile int g_stop;

void server_request_stop(void)
{
    socket_t fd = g_listen_fd;

    g_stop = 1;
    g_listen_fd = INVALID_SOCKET;
    if (fd != INVALID_SOCKET)
        close_socket(fd);              /* unblocks accept() */
}

int server_run(const config_t *cfg, int once)
{
    WOLFSSH_CTX *ctx;
    unsigned     failures = 0;
    int          rc;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) {
        log_error("wolfSSH_CTX_new failed");
        return 1;
    }

    session_configure(ctx);
    wolfSSH_CTX_SetBanner(ctx, server_banner);

    /* Pin the offer. A rejection here is a build problem, not a runtime one. */
    if ((rc = wolfSSH_CTX_SetAlgoListKex(ctx, algo_kex)) < 0 ||
        (rc = wolfSSH_CTX_SetAlgoListKey(ctx, algo_hostkey)) < 0 ||
        (rc = wolfSSH_CTX_SetAlgoListCipher(ctx, algo_cipher)) < 0 ||
        (rc = wolfSSH_CTX_SetAlgoListMac(ctx, algo_mac)) < 0 ||
        (rc = wolfSSH_CTX_SetAlgoListKeyAccepted(ctx, algo_keys)) < 0) {
        log_error("wolfSSH rejected an algorithm list (%d)", rc);
        wolfSSH_CTX_free(ctx);
        return 1;
    }

    if (load_host_key(ctx, cfg->host_key) != 0) {
        wolfSSH_CTX_free(ctx);
        return 1;
    }
    log_info("host key '%s' loaded", cfg->host_key);
    trace("host key loaded");

    if (cfg->authorized_keys[0] != '\0') {
        if (keylist_load(&g_keys, cfg->authorized_keys) != 0) {
            log_error("cannot read authorised keys '%s'", cfg->authorized_keys);
            wolfSSH_CTX_free(ctx);
            return 1;
        }
        log_info("authorised keys: %d loaded from %s",
                 g_keys.count, cfg->authorized_keys);
    }
    else {
        log_warn("no authorized_keys configured, every login is refused");
    }

    g_listen_fd = listen_on(cfg->bind, cfg->port);
    if (g_listen_fd == INVALID_SOCKET) {
        log_error("bind/listen failed on %s:%d (%d)",
                  cfg->bind, cfg->port, last_socket_error());
        wolfSSH_CTX_free(ctx);
        return 1;
    }

    log_info("rossh listening on %s:%d", cfg->bind, cfg->port);
    trace("listening");
    log_info("  kex      %s", algo_kex);
    log_info("  host key %s", algo_hostkey);
    log_info("  cipher   %s", algo_cipher);
    log_info("  mac      %s", algo_mac);

    for (;;) {
        struct sockaddr_in peer;
        socklen_type       plen = sizeof peer;
        socket_t           lfd = g_listen_fd;
        socket_t           cfd;
        WOLFSSH           *ssh;

        if (g_stop || lfd == INVALID_SOCKET)
            break;

        cfd = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (cfd == INVALID_SOCKET) {
            /* A server must never spin here. ReactOS is quite capable of
             * failing accept() persistently, and a busy loop takes the whole
             * VM down with it: the network stack stops answering, and there is
             * no out-of-band way back in. Pause, and give up after a run of
             * failures instead of burning the machine. */
            if (g_stop)
                break;
            if (++failures == 1)
                log_warn("accept failed (%d), backing off", last_socket_error());
            if (failures >= 30) {
                log_error("accept keeps failing, giving up");
                break;
            }
            pause_ms(200);
            continue;
        }
        failures = 0;
        trace("connection accepted");

        log_info("--- connection from %s", inet_ntoa(peer.sin_addr));

        ssh = wolfSSH_new(ctx);
        if (ssh == NULL) {
            close_socket(cfd);
            if (once)
                break;
            continue;
        }
        session_bind(ssh, &g_keys);

        wolfSSH_set_fd(ssh, (WS_SOCKET_T)cfd);
        rc = wolfSSH_accept(ssh);
        log_debug("wolfSSH_accept -> %d", rc);

        /* A client that asked for the sftp subsystem is handed to the SFTP
         * server here — wolfSSH_accept() reports that with WS_SFTP_COMPLETE,
         * having already run the version exchange. exec requests were answered
         * by their channel callback. */
        if (rc == WS_SFTP_COMPLETE) {
            session_sftp(ssh, cfg->sftp_root[0] != '\0' ? cfg->sftp_root : NULL);
        }

        /* Close the session properly. Without this the socket is dropped as
         * soon as accept() returns, and the client sees a connection reset
         * instead of its exit status. */
        for (;;) {
            rc = wolfSSH_shutdown(ssh);
            if (rc != WS_WANT_READ && rc != WS_WANT_WRITE)
                break;
        }
        log_debug("wolfSSH_shutdown -> %d", rc);

        wolfSSH_free(ssh);
        close_socket(cfd);

        if (once)
            break;
    }

    trace("exiting");
    if (g_listen_fd != INVALID_SOCKET) {
        close_socket(g_listen_fd);
        g_listen_fd = INVALID_SOCKET;
    }
    wolfSSH_CTX_free(ctx);
    return 0;
}

int main(int argc, char **argv)
{
    config_t     cfg;
    int          once = 0;                  /* --once: serve one connection, then exit */
    int          service_mode = 0;          /* the service controller's child */
    int          install_mode = 0;
    int          uninstall_mode = 0;
    const char  *genkey_path = NULL;
    const char  *port_arg = NULL;
    const char  *key_arg  = NULL;
    const char  *config_path = NULL;
    int          i;
    int          rc;

    /* `ssh': the same binary wearing the other hat. Decided here — before the
     * stream fiddling below, because folding stderr into stdout is a server
     * workaround and exactly wrong for a client. */
    if (is_ssh_invocation(argv[0]) || client_requested(argc, argv))
        return client_main(argc, argv);

    /* `setup' is a subcommand: rossh setup [options] [dir]. */
    if (argc > 1 && strcmp(argv[1], "setup") == 0)
        return setup_main(argc, argv);

    /* Line-wise output, and everything on one stream: wSSH's exec forwards
     * stdout and not stderr, and an error nobody can see is worse than one on
     * the wrong stream. Measured on the target — see docs/build.md. */
    setvbuf(stdout, NULL, _IONBF, 0);
#ifdef _WIN32
    _dup2(1, 2);
#else
    dup2(1, 2);
#endif

    /* Configuration first: defaults, then a file if one was named, then the
     * command line. --config is picked out here so that the log can be opened
     * before anything else has something to say. */
    config_defaults(&cfg);
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[i + 1];
            break;
        }
    }
    config_load(&cfg, config_path);

    log_open(cfg.log_file);
    if (log_set_level(cfg.log_level) != 0) {
        log_warn("unknown log_level '%s', keeping info", cfg.log_level);
        log_set_level("info");
    }
    log_info("rossh: start");

    /* Arguments. Everything after this point can block, so a trace option — or
     * a simple typo — has to be handled before any of it. The command line wins
     * over the config file. */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
            i++;                   /* already applied above */
        else if (strcmp(argv[i], "--genkey") == 0 && i + 1 < argc)
            genkey_path = argv[++i];
        else if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc)
            snprintf(cfg.bind, sizeof cfg.bind, "%s", argv[++i]);
        else if (strcmp(argv[i], "--trace") == 0 && i + 1 < argc)
            trace_open(argv[++i]);
        else if (strcmp(argv[i], "--authorized-keys") == 0 && i + 1 < argc)
            snprintf(cfg.authorized_keys, sizeof cfg.authorized_keys,
                     "%s", argv[++i]);
        else if (strcmp(argv[i], "--sftp-root") == 0 && i + 1 < argc)
            snprintf(cfg.sftp_root, sizeof cfg.sftp_root, "%s", argv[++i]);
        else if (strcmp(argv[i], "--once") == 0)
            once = 1;
        else if (strcmp(argv[i], "--service") == 0)
            service_mode = 1;
        else if (strcmp(argv[i], "--install") == 0) {
            install_mode = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-')
                config_path = argv[++i];
        }
        else if (strcmp(argv[i], "--uninstall") == 0)
            uninstall_mode = 1;
        else if (argv[i][0] != '-' && port_arg == NULL)
            port_arg = argv[i];
        else if (argv[i][0] != '-' && key_arg == NULL)
            key_arg  = argv[i];
        else {
            log_error("unexpected argument '%s'", argv[i]);
            return 1;
        }
    }
    if (port_arg != NULL) {
        int p = atoi(port_arg);

        if (p > 0 && p < 65536)
            cfg.port = p;
        else
            log_warn("ignoring the port argument '%s'", port_arg);
    }
    if (key_arg != NULL)
        snprintf(cfg.host_key, sizeof cfg.host_key, "%s", key_arg);
    trace("args parsed");

    if (install_mode || uninstall_mode) {
        if (install_mode)
            return service_install(config_path);
        return service_uninstall();
    }

#ifdef _WIN32
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            log_error("WSAStartup failed");
            return 1;
        }
    }
#endif
    trace("winsock up");

#ifdef DEBUG_WOLFSSH
    /* make deps EXTRA_CPPFLAGS=-DDEBUG_WOLFSSH && make DEBUG=1 */
    wolfSSH_Debugging_ON();
#endif

    rng_start();
    trace("rng done");

    if (genkey_path != NULL) {
        rc = hostkey_generate(genkey_path);
        trace(rc == 0 ? "genkey ok" : "genkey failed");
        return (rc == 0) ? 0 : 1;
    }

    if (service_mode)
        return service_run(config_path);

    return server_run(&cfg, once);
}
