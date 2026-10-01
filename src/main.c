/*
 * rossh — an SSH server for ReactOS.
 *
 * M1 scope: offer the modern algorithm suite from spec.md §4.1, carry a client
 * all the way through key exchange, and then refuse every authentication on
 * purpose. Serving a session is M2. Only the loopback interface is bound, so
 * nothing is exposed while the pieces are still coming together.
 */

#include <wolfssl/options.h>
#include <wolfssh/ssh.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rng.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET socket_t;
    #define socklen_type int
    #define close_socket closesocket
#else
    #include <arpa/inet.h>
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

#define DEFAULT_PORT 2222
#define DEFAULT_KEY  "rossh_hostkey.der"

static const char server_banner[] = "rossh M1";

/* Exactly spec.md §4.1. Widening this is a deliberate decision, never a default:
 * no SHA-1, no dh-group1, no CBC, no 'none'. */
static const char algo_kex[]     = "curve25519-sha256";
static const char algo_hostkey[] = "ssh-ed25519";
static const char algo_cipher[]  = "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr";
static const char algo_mac[]     = "hmac-sha2-256";
static const char algo_keys[]    = "ssh-ed25519";

/*
 * M1: every authentication is refused. The milestone is that a stock client
 * reaches this point without a single -o flag.
 */
static int deny_auth(byte authType, WS_UserAuthData *authData, void *ctx)
{
    (void)authData;
    (void)ctx;
    printf("auth: refused (method %d)\n", (int)authType);
    return WOLFSSH_USERAUTH_FAILURE;
}

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

/*
 * Create a host key. rossh owns this because the target has neither openssl nor
 * ssh-keygen.
 *
 * The file has to carry the key's own public half: wolfSSH re-decodes it on
 * every key exchange and needs the public key to build the reply, and wolfSSL
 * does not derive it. wc_Ed25519PrivateKeyToDer() writes the private part only,
 * which fails later with PUBLIC_KEY_E (-134); wc_Ed25519KeyToDer() writes both.
 */
static int generate_host_key(const char *path)
{
    WC_RNG      rng;
    ed25519_key key;
    byte        der[256];
    int         derSz = 0;
    FILE       *f;

    if (wc_InitRng(&rng) != 0) {
        fprintf(stderr, "rossh: cannot start the RNG\n");
        return -1;
    }
    if (wc_ed25519_init(&key) != 0) {
        fprintf(stderr, "rossh: cannot initialise ed25519\n");
        wc_FreeRng(&rng);
        return -1;
    }

    if (wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key) != 0) {
        fprintf(stderr, "rossh: key generation failed\n");
        goto done;
    }

    derSz = wc_Ed25519KeyToDer(&key, der, sizeof der);
    if (derSz <= 0) {
        fprintf(stderr, "rossh: key export failed (%d)\n", derSz);
        goto done;
    }

    f = fopen(path, "wb");
    if (f == NULL) {
        fprintf(stderr, "rossh: cannot write '%s'\n", path);
        derSz = -1;
        goto done;
    }
    if (fwrite(der, 1, (size_t)derSz, f) != (size_t)derSz) {
        fprintf(stderr, "rossh: short write to '%s'\n", path);
        fclose(f);
        derSz = -1;
        goto done;
    }
    fclose(f);
    printf("wrote a %d-byte ed25519 host key to %s\n", derSz, path);

done:
    wc_ed25519_free(&key);
    wc_FreeRng(&rng);
    return (derSz > 0) ? 0 : -1;
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

int main(int argc, char **argv)
{
    int          port;
    const char  *key_path;
    const char  *bind_addr = "127.0.0.1";   /* loopback unless asked otherwise */
    WOLFSSH_CTX *ctx;
    socket_t     lfd;
    int          rc;

    /* Line-wise output. This process writes into pipes and log files, and a
     * block-buffered stdout hides exactly the diagnostics you need when
     * something does not come up. */
    setvbuf(stdout, NULL, _IONBF, 0);
    fprintf(stderr, "rossh: start\n");

#ifdef _WIN32
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            fprintf(stderr, "rossh: WSAStartup failed\n");
            return 1;
        }
    }
#endif

    rng_start();

#ifdef DEBUG_WOLFSSH
    /* make deps EXTRA_CPPFLAGS=-DDEBUG_WOLFSSH && make DEBUG=1 */
    wolfSSH_Debugging_ON();
#endif

    /* Arguments: optional --genkey <file> and --bind <addr>, then [port] [key]. */
    {
        const char *port_arg = NULL;
        const char *key_arg  = NULL;
        int         i;

        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--genkey") == 0 && i + 1 < argc)
                return (generate_host_key(argv[++i]) == 0) ? 0 : 1;
            else if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc)
                bind_addr = argv[++i];
            else if (port_arg == NULL)
                port_arg = argv[i];
            else if (key_arg == NULL)
                key_arg = argv[i];
            else {
                fprintf(stderr, "rossh: unexpected argument '%s'\n", argv[i]);
                return 1;
            }
        }
        port     = (port_arg != NULL) ? atoi(port_arg) : DEFAULT_PORT;
        key_path = (key_arg  != NULL) ? key_arg  : DEFAULT_KEY;
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "rossh: wolfSSH_CTX_new failed\n");
        return 1;
    }

    wolfSSH_SetUserAuth(ctx, deny_auth);
    wolfSSH_CTX_SetBanner(ctx, server_banner);

    /* Pin the offer. A rejection here is a build problem, not a runtime one. */
    if ((rc = wolfSSH_CTX_SetAlgoListKex(ctx, algo_kex)) < 0 ||
        (rc = wolfSSH_CTX_SetAlgoListKey(ctx, algo_hostkey)) < 0 ||
        (rc = wolfSSH_CTX_SetAlgoListCipher(ctx, algo_cipher)) < 0 ||
        (rc = wolfSSH_CTX_SetAlgoListMac(ctx, algo_mac)) < 0 ||
        (rc = wolfSSH_CTX_SetAlgoListKeyAccepted(ctx, algo_keys)) < 0) {
        fprintf(stderr, "rossh: wolfSSH rejected an algorithm list (%d)\n", rc);
        return 1;
    }

    if (load_host_key(ctx, key_path) != 0)
        return 1;
    printf("host key '%s' loaded\n", key_path);

    lfd = listen_on(bind_addr, port);
    if (lfd == INVALID_SOCKET) {
        perror("rossh: bind/listen");
        return 1;
    }

    printf("rossh listening on %s:%d\n", bind_addr, port);
    printf("  kex      %s\n", algo_kex);
    printf("  host key %s\n", algo_hostkey);
    printf("  cipher   %s\n", algo_cipher);
    printf("  mac      %s\n", algo_mac);
    fflush(stdout);

    for (;;) {
        struct sockaddr_in peer;
        socklen_type       plen = sizeof peer;
        socket_t           cfd;
        WOLFSSH           *ssh;

        cfd = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (cfd == INVALID_SOCKET)
            continue;

        printf("--- connection from %s\n", inet_ntoa(peer.sin_addr));
        fflush(stdout);

        ssh = wolfSSH_new(ctx);
        if (ssh == NULL) {
            close_socket(cfd);
            continue;
        }

        wolfSSH_set_fd(ssh, (WS_SOCKET_T)cfd);
        rc = wolfSSH_accept(ssh);
        printf("wolfSSH_accept -> %d\n", rc);
        fflush(stdout);

        wolfSSH_free(ssh);
        close_socket(cfd);
    }
}
