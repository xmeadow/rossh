/*
 * `rossh setup` — make this machine connectable in one step (spec.md §10, M4d).
 *
 * Everything the installer needs, in the binary itself, so a future setup.exe
 * is only a wrapper: generate a host key, write a config, authorise a key,
 * install the service (auto-start), open the firewall. Afterwards the machine
 * answers on its port.
 *
 *   rossh setup [--key <pubkey-file>] [--port <n>] [--no-firewall] [dir]
 *
 * `dir` defaults to the directory of the running executable, so a portable
 * setup keeps everything together. With no --key, a client key is generated in
 * `dir` and authorised, so there is always a way in.
 */

#ifndef ROSSH_SETUP_H
#define ROSSH_SETUP_H

/* argv[0] is "setup"; options and an optional directory follow. */
int setup_main(int argc, char **argv);

#endif /* ROSSH_SETUP_H */
