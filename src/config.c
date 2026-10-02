#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void copy_str(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);

    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

void config_defaults(config_t *cfg)
{
    memset(cfg, 0, sizeof *cfg);
    cfg->port = CONFIG_DEFAULT_PORT;
    copy_str(cfg->bind,     sizeof cfg->bind,     CONFIG_DEFAULT_BIND);
    copy_str(cfg->host_key, sizeof cfg->host_key, CONFIG_DEFAULT_HOST_KEY);
    copy_str(cfg->log_level, sizeof cfg->log_level, "info");
    /* authorized_keys, sftp_root and log_file default to empty. */
}

/* Trim leading and trailing whitespace in place; returns the new start. */
static char *trim(char *s)
{
    char *end;

    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;
    end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
                       end[-1] == '\r' || end[-1] == '\n'))
        *--end = '\0';
    return s;
}

/* Drop one pair of surrounding double quotes, if present. */
static void strip_quotes(char *v)
{
    size_t n = strlen(v);

    if (n >= 2 && v[0] == '"' && v[n - 1] == '"') {
        memmove(v, v + 1, n - 2);
        v[n - 2] = '\0';
    }
}

static int str_ieq(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        int ca = *a, cb = *b;

        if (ca >= 'A' && ca <= 'Z') ca += 'a' - 'A';
        if (cb >= 'A' && cb <= 'Z') cb += 'a' - 'A';
        if (ca != cb)
            return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

void config_load(config_t *cfg, const char *path)
{
    FILE *f;
    char  line[CONFIG_PATH_MAX + 64];
    int   lineno = 0;

    if (path == NULL || path[0] == '\0')
        return;

    f = fopen(path, "r");
    if (f == NULL) {
        fprintf(stderr, "rossh: config '%s' not found, using defaults\n", path);
        return;
    }

    while (fgets(line, sizeof line, f) != NULL) {
        char *key, *val, *eq;

        lineno++;
        key = trim(line);
        if (key[0] == '\0' || key[0] == '#' || key[0] == ';')
            continue;

        eq = strchr(key, '=');
        if (eq == NULL) {
            fprintf(stderr, "rossh: %s:%d: not 'key = value', skipped\n",
                    path, lineno);
            continue;
        }
        *eq = '\0';
        val = trim(eq + 1);
        key = trim(key);
        strip_quotes(val);

        if (str_ieq(key, "port")) {
            char *end = NULL;
            long  p = strtol(val, &end, 10);

            if (end == val || *end != '\0' || p < 1 || p > 65535) {
                fprintf(stderr, "rossh: %s:%d: bad port '%s'\n",
                        path, lineno, val);
                continue;
            }
            cfg->port = (int)p;
        }
        else if (str_ieq(key, "bind"))
            copy_str(cfg->bind, sizeof cfg->bind, val);
        else if (str_ieq(key, "host_key"))
            copy_str(cfg->host_key, sizeof cfg->host_key, val);
        else if (str_ieq(key, "authorized_keys"))
            copy_str(cfg->authorized_keys, sizeof cfg->authorized_keys, val);
        else if (str_ieq(key, "sftp_root"))
            copy_str(cfg->sftp_root, sizeof cfg->sftp_root, val);
        else if (str_ieq(key, "log_file"))
            copy_str(cfg->log_file, sizeof cfg->log_file, val);
        else if (str_ieq(key, "log_level"))
            copy_str(cfg->log_level, sizeof cfg->log_level, val);
        else
            fprintf(stderr, "rossh: %s:%d: unknown key '%s', skipped\n",
                    path, lineno, key);
    }

    fclose(f);
}
