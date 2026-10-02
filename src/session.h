#ifndef ROSSH_SESSION_H
#define ROSSH_SESSION_H

#include <wolfssl/options.h>
#include <wolfssh/ssh.h>

/*
 * The session layer: who may log in, and what happens when they run something.
 *
 * M2 — publickey authentication against a file, and `exec` through the native
 * process API, with stdout and stderr both forwarded and a real exit status.
 * M5 — an interactive `shell`, on a pty natively and on a pipe-fed cmd.exe on
 * Windows (see session_shell below).
 */

#define KEYLIST_MAX_KEYS 32
#define KEYLIST_MAX_BLOB 1024

/*
 * Authorised keys, one per line, in the shape wSSH's `user_<name>.pub` files use
 * (and OpenSSH's authorized_keys):
 *
 *   [options] ssh-ed25519 AAAAC3Nza... comment
 *
 * Options and comments are ignored; only the decoded key blob counts. Any key
 * type is accepted — the blob is compared byte for byte, so whatever the client
 * offers either matches a line or does not.
 */
typedef struct {
    byte   blobs[KEYLIST_MAX_KEYS][KEYLIST_MAX_BLOB];
    word32 sizes[KEYLIST_MAX_KEYS];
    int    count;
} keylist_t;

/* Reads `path` into `list`. Returns 0 on success, -1 if it cannot be read. */
int keylist_load(keylist_t *list, const char *path);

/* Does `blob` match one of the loaded keys? */
int keylist_contains(const keylist_t *list, const byte *blob, word32 sz);

/* Installs the authentication and channel callbacks on the context. */
int session_configure(WOLFSSH_CTX *ctx);

/* Binds one connection: the callbacks find the key list and the WOLFSSH* here.
 * Single-connection at a time, like the rest of M2 (spec.md §7). */
int session_bind(WOLFSSH *ssh, const keylist_t *keys);

/* Serves the SFTP subsystem (M3) until the connection ends. `root`, when not
 * NULL, is the jail every path is resolved against. */
int session_sftp(WOLFSSH *ssh, const char *root);

/* True once a `shell` request has arrived on the current connection. The request
 * callback only records it; main runs the loop once wolfSSH_accept() returns. */
int session_shell_requested(void);

/* Runs the interactive shell for the current connection until it ends. `fd` is
 * the connection socket: the loop polls it for keystrokes while draining the
 * shell process's output. */
int session_shell(WOLFSSH *ssh, WS_SOCKET_T fd);

#endif /* ROSSH_SESSION_H */
