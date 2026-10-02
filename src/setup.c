#include "setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "hostkey.h"
#include "log.h"
#include "rng.h"
#include "service.h"

#ifdef _WIN32
    #include <windows.h>
    #define DIR_SEP '\\'
#else
    #include <sys/stat.h>
    #define DIR_SEP '/'
#endif

static int file_exists(const char *path)
{
    FILE *f = fopen(path, "rb");

    if (f == NULL)
        return 0;
    fclose(f);
    return 1;
}

static void join_path(const char *dir, const char *name, char *out, size_t cap)
{
    size_t n = strlen(dir);

    if (n > 0 && dir[n - 1] != '/' && dir[n - 1] != '\\')
        snprintf(out, cap, "%s%c%s", dir, DIR_SEP, name);
    else
        snprintf(out, cap, "%s%s", dir, name);
}

static void make_dir(const char *path)
{
#ifdef _WIN32
    CreateDirectoryA(path, NULL);       /* exists already is fine */
#else
    mkdir(path, 0777);
#endif
}

#ifdef _WIN32
static void default_dir(char *out, size_t cap)
{
    char  full[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, full, sizeof full);

    if (n > 0 && n < sizeof full) {
        char *slash = strrchr(full, '\\');

        if (slash != NULL) {
            *slash = '\0';
            snprintf(out, cap, "%s", full);
            return;
        }
    }
    snprintf(out, cap, ".");
}
#else
static void default_dir(char *out, size_t cap)
{
    snprintf(out, cap, ".");
}
#endif

/* Turn a possibly-relative directory into an absolute one, so the paths written
 * into the config still resolve when the service runs from System32. */
static void absolute_dir(const char *in, char *out, size_t cap)
{
#ifdef _WIN32
    char  tmp[MAX_PATH];
    DWORD n = GetFullPathNameA(in, (DWORD)sizeof tmp, tmp, NULL);

    if (n > 0 && n < sizeof tmp) {
        snprintf(out, cap, "%s", tmp);
        return;
    }
#endif
    snprintf(out, cap, "%s", in);
}

static int write_config(const char *path, int port, const char *hostkey,
                        const char *authkeys, const char *sftp_root,
                        const char *logfile)
{
    FILE *f = fopen(path, "w");

    if (f == NULL) {
        log_error("cannot write config '%s'", path);
        return -1;
    }
    fprintf(f,
        "# rossh — written by `rossh setup`\n"
        "port            = %d\n"
        "bind            = 0.0.0.0\n"
        "host_key        = %s\n"
        "authorized_keys = %s\n"
        "sftp_root       = %s\n"
        "log_file        = %s\n"
        "log_level       = info\n",
        port, hostkey, authkeys, sftp_root, logfile);
    fclose(f);
    log_info("wrote config %s", path);
    return 0;
}

/* Is this exact line already in `authkeys`? */
static int key_line_present(const char *authkeys, const char *want)
{
    char  line[2048];
    FILE *f = fopen(authkeys, "r");
    int   found = 0;

    if (f == NULL)
        return 0;
    while (fgets(line, sizeof line, f) != NULL) {
        char *nl = strpbrk(line, "\r\n");

        if (nl != NULL)
            *nl = '\0';
        if (strcmp(line, want) == 0) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

/*
 * Authorise every public-key line of `src` in `authkeys` — a `.pub` holds one
 * line, but a file of several is just as valid, and that is how a bootstrap key
 * file (the operator's and the installer's, say) gets in. Blank lines and
 * comments are ignored; anything that is not an `ssh-` line at all is an error,
 * so pointing --key at the wrong file says so rather than doing nothing.
 */
static int authorize_key(const char *authkeys, const char *src)
{
    char  line[2048];
    FILE *f;
    int   saw_key = 0, added = 0;

    f = fopen(src, "r");
    if (f == NULL) {
        log_error("cannot read key file '%s'", src);
        return -1;
    }

    while (fgets(line, sizeof line, f) != NULL) {
        char *nl = strpbrk(line, "\r\n");
        char *s  = line;
        FILE *a;

        if (nl != NULL)
            *nl = '\0';
        while (*s == ' ' || *s == '\t')
            s++;
        if (strncmp(s, "ssh-", 4) != 0)
            continue;                   /* blank line or comment */
        saw_key = 1;
        if (key_line_present(authkeys, s))
            continue;

        a = fopen(authkeys, "a");
        if (a == NULL) {
            log_error("cannot write '%s'", authkeys);
            fclose(f);
            return -1;
        }
        fprintf(a, "%s\n", s);
        fclose(a);
        added = 1;
    }
    fclose(f);

    if (!saw_key) {
        log_error("'%s' has no public key lines", src);
        return -1;
    }
    if (added)
        log_info("authorised key(s) from %s", src);
    else
        log_info("keys from %s were already authorised", src);
    return 0;
}

static void add_firewall(int port)
{
#ifdef _WIN32
    char cmd[256];
    int  rc;

    /* Delete first so re-running does not pile up rules; both are best-effort. */
    snprintf(cmd, sizeof cmd,
             "netsh advfirewall firewall delete rule name=\"rossh %d\" "
             ">nul 2>nul", port);
    system(cmd);

    snprintf(cmd, sizeof cmd,
             "netsh advfirewall firewall add rule name=\"rossh %d\" "
             "dir=in action=allow protocol=TCP localport=%d >nul", port, port);
    rc = system(cmd);
    if (rc == 0)
        log_info("opened the firewall for TCP %d", port);
    else
        log_warn("could not add a firewall rule for TCP %d (%d) — add one by hand",
                 port, rc);
#else
    (void)port;
    log_info("no firewall step on this platform");
#endif
}

int setup_main(int argc, char **argv)
{
    char  dir_raw[CONFIG_PATH_MAX];
    char  dir[CONFIG_PATH_MAX];
    char  config_path[CONFIG_PATH_MAX];
    char  hostkey_path[CONFIG_PATH_MAX];
    char  authkeys_path[CONFIG_PATH_MAX];
    char  log_path[CONFIG_PATH_MAX];
    char  client_path[CONFIG_PATH_MAX];
    char  client_pub[CONFIG_PATH_MAX + 8];
    char  key_arg[CONFIG_PATH_MAX] = "";
    const char *dir_arg = NULL;
    int   port = CONFIG_DEFAULT_PORT;
    int   no_firewall = 0;
    int   i;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
            snprintf(key_arg, sizeof key_arg, "%s", argv[++i]);
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            int p = atoi(argv[++i]);

            if (p < 1 || p > 65535) {
                fprintf(stderr, "rossh setup: bad --port\n");
                return 2;
            }
            port = p;
        }
        else if (strcmp(argv[i], "--no-firewall") == 0)
            no_firewall = 1;
        else if (argv[i][0] != '-' && dir_arg == NULL)
            dir_arg = argv[i];
        else {
            fprintf(stderr, "rossh setup: unexpected argument '%s'\n", argv[i]);
            return 2;
        }
    }

    if (dir_arg != NULL)
        snprintf(dir_raw, sizeof dir_raw, "%s", dir_arg);
    else
        default_dir(dir_raw, sizeof dir_raw);
    absolute_dir(dir_raw, dir, sizeof dir);

    join_path(dir, "rossh.conf",      config_path,  sizeof config_path);
    join_path(dir, "hostkey.der",     hostkey_path, sizeof hostkey_path);
    join_path(dir, "authorized_keys", authkeys_path, sizeof authkeys_path);
    join_path(dir, "rossh.log",       log_path,     sizeof log_path);
    join_path(dir, "client.der",      client_path,  sizeof client_path);

    log_info("rossh setup: %s", dir);

    /* The RNG has to exist before any key is made (see rng.c). */
    rng_start();

    make_dir(dir);

    /* 1. host key */
    if (file_exists(hostkey_path))
        log_info("host key already present: %s", hostkey_path);
    else if (hostkey_generate(hostkey_path) != 0)
        return 1;

    /* 2. config (never clobber one that is already there) */
    if (file_exists(config_path))
        log_info("config already present: %s", config_path);
    else if (write_config(config_path, port, hostkey_path, authkeys_path,
                          dir, log_path) != 0)
        return 1;

    /* 3. an authorised key — the given one, or a fresh client key */
    if (key_arg[0] != '\0') {
        if (authorize_key(authkeys_path, key_arg) != 0)
            return 1;
        client_pub[0] = '\0';
    }
    else if (file_exists(authkeys_path)) {
        log_info("authorised keys already present: %s", authkeys_path);
        client_pub[0] = '\0';
    }
    else {
        if (hostkey_generate(client_path) != 0)
            return 1;
        snprintf(client_pub, sizeof client_pub, "%s.pub", client_path);
        if (authorize_key(authkeys_path, client_pub) != 0)
            return 1;
        log_info("no --key given; made a client key: %s", client_pub);
    }

    /* 4. the service */
    if (service_install(config_path) != 0) {
#ifdef _WIN32
        log_error("could not install the service");
        return 1;
#else
        log_warn("no service on this platform; run: rossh --config %s",
                 config_path);
#endif
    }

    /* 5. the firewall */
    if (!no_firewall)
        add_firewall(port);

    log_info("setup complete — listening on 0.0.0.0:%d", port);
    log_info("  config   %s", config_path);
    if (client_pub[0] != '\0')
        log_info("  client   %s  (authorised)", client_pub);
    log_info("  connect  ssh -p %d <user>@<this-host>", port);
    return 0;
}
