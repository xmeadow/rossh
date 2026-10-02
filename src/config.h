/*
 * rossh's configuration.
 *
 * A small, sshd-flavoured `key = value` file — not wSSH's sections. wSSH is
 * being replaced, so mirroring its format buys nothing; what it would cost is a
 * parser tied to a dead tool's quirks. See spec.md §5.
 *
 * There is no config file unless one is named with --config, so a bare command
 * line (and every test script) behaves exactly as before.
 */

#ifndef ROSSH_CONFIG_H
#define ROSSH_CONFIG_H

#define CONFIG_DEFAULT_PORT     2222
#define CONFIG_DEFAULT_BIND     "127.0.0.1"
#define CONFIG_DEFAULT_HOST_KEY "rossh_hostkey.der"

#define CONFIG_PATH_MAX 512

typedef struct {
    int  port;
    char bind[64];
    char host_key[CONFIG_PATH_MAX];
    char authorized_keys[CONFIG_PATH_MAX];  /* "" = none; every login refused */
    char sftp_root[CONFIG_PATH_MAX];        /* "" = the SFTP subsystem is off */
    char log_file[CONFIG_PATH_MAX];         /* "" = stderr only */
    char log_level[16];
} config_t;

/* The built-in defaults: loopback, port 2222, no keys, no SFTP. */
void config_defaults(config_t *cfg);

/*
 * Overlay the `key = value` lines of `path` onto `cfg`. A missing file is not an
 * error, so a bare command line keeps working; unknown keys and bad values are
 * reported to stderr and skipped, never fatal.
 */
void config_load(config_t *cfg, const char *path);

#endif /* ROSSH_CONFIG_H */
