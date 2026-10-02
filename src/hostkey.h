/*
 * ed25519 key creation, in rossh itself: the target has neither openssl nor
 * ssh-keygen (docs/build.md). Shared by `rossh --genkey` and `rossh setup`.
 */

#ifndef ROSSH_HOSTKEY_H
#define ROSSH_HOSTKEY_H

/*
 * Write a fresh ed25519 key to `path` as PKCS#8 DER, and its OpenSSH one-line
 * public half to `<path>.pub`. Returns 0 on success, -1 otherwise.
 */
int hostkey_generate(const char *path);

#endif /* ROSSH_HOSTKEY_H */
