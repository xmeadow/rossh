#ifndef ROSSH_SESSION_H
#define ROSSH_SESSION_H

#include <wolfssl/options.h>
#include <wolfssh/ssh.h>

#include "config.h"

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

/* Installs the authentication and channel callbacks on the context. Shared by
 * every connection — the per-connection state lives in a session_t. */
int session_configure(WOLFSSH_CTX *ctx);

/* One connection's state: its WOLFSSH, the authorised keys (re-read per
 * connection) and the shell bookkeeping. Opaque to callers, which only create,
 * start and free it — so several connections can be in flight at once. */
typedef struct session session_t;

session_t *session_new(void);
void       session_free(session_t *s);

/* Attach a freshly accepted connection: remember its WOLFSSH and socket, load
 * the authorised keys from cfg and point the callbacks at this session. */
int session_start(session_t *s, WOLFSSH *ssh, const config_t *cfg,
                  WS_SOCKET_T fd);

/* Apply (or clear, when `seconds` is <= 0) a receive and send timeout to the
 * connection socket. A timeout makes wolfSSH report WS_WANT_READ instead of
 * blocking forever, which is how login grace and idle timeouts are enforced. */
void session_set_io_timeout(WS_SOCKET_T fd, int seconds);

/* Serves the SFTP subsystem (M3) until the connection ends. `root`, when not
 * NULL, is the jail every path is resolved against. `idle_timeout` bounds how
 * long a silent client may hold the session (0 = no bound). */
int session_sftp(WOLFSSH *ssh, const char *root, int idle_timeout);

/* True once a `shell` request has arrived on this connection. The request
 * callback only records it; the caller runs the loop once wolfSSH_accept()
 * returns. */
int session_shell_requested(session_t *s);

/* Runs the interactive shell for this connection until it ends. `fd` is the
 * connection socket: the loop polls it for keystrokes while draining the shell
 * process's output. */
int session_shell(session_t *s, WS_SOCKET_T fd);

#endif /* ROSSH_SESSION_H */
