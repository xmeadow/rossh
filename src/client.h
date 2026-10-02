#ifndef ROSSH_CLIENT_H
#define ROSSH_CLIENT_H

/*
 * The client half — `ssh [user@]host [command]`.
 *
 * Same binary, different hat: main() picks this mode when it was started as
 * `ssh`, or asked for it with --client. Key material is the same PKCS#8 DER
 * ed25519 that `rossh --genkey` writes, so a client key and a host key are the
 * same kind of thing.
 */

typedef struct {
    const char *host;
    int         port;
    const char *user;
    const char *key_path;     /* PKCS#8 DER ed25519 private key */
    const char *command;      /* NULL = no command (not supported yet) */
    const char *known_hosts;  /* trust-on-first-use store; NULL = do not persist */
    int         insecure;     /* skip host key verification entirely */
} client_opts_t;

/* Parses client arguments and runs one session. Returns the remote exit status,
 * or 255 when the session could not be established. */
int client_main(int argc, char **argv);

#endif /* ROSSH_CLIENT_H */
