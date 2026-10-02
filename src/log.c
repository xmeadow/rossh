#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static FILE       *log_fp;
static log_level_t log_threshold = LOG_INFO;

static const char *level_name(log_level_t level)
{
    switch (level) {
        case LOG_ERROR: return "ERROR";
        case LOG_WARN:  return "WARN";
        case LOG_INFO:  return "INFO";
        case LOG_DEBUG: return "DEBUG";
        default:        return "?";
    }
}

void log_open(const char *path)
{
    log_close();
    if (path == NULL || path[0] == '\0')
        return;
    log_fp = fopen(path, "a");
    if (log_fp == NULL)
        fprintf(stderr, "rossh: cannot open log file '%s'\n", path);
}

void log_close(void)
{
    if (log_fp != NULL) {
        fclose(log_fp);
        log_fp = NULL;
    }
}

int log_set_level(const char *name)
{
    char   low[16];
    size_t i, n;

    if (name == NULL)
        return -1;

    n = strlen(name);
    if (n >= sizeof low)
        n = sizeof low - 1;
    for (i = 0; i < n; i++) {
        char c = name[i];

        low[i] = (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
    }
    low[n] = '\0';

    if (strcmp(low, "error") == 0)                                  /* ERROR */
        log_threshold = LOG_ERROR;
    else if (strcmp(low, "warn") == 0 || strcmp(low, "warning") == 0)
        log_threshold = LOG_WARN;
    else if (strcmp(low, "info") == 0)
        log_threshold = LOG_INFO;
    else if (strcmp(low, "debug") == 0)
        log_threshold = LOG_DEBUG;
    else
        return -1;

    return 0;
}

/*
 * The timestamp is formatted by hand rather than with strftime(): ReactOS's
 * C runtime is the thinnest part of the platform (docs/reactos.md), and a
 * struct tm needs nothing more than arithmetic.
 */
static void timestamp(char *out, size_t cap)
{
    time_t    now = time(NULL);
    struct tm *lt = localtime(&now);

    out[0] = '\0';
    if (lt == NULL)
        return;
    snprintf(out, cap, "%04d-%02d-%02d %02d:%02d:%02d",
             lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
             lt->tm_hour, lt->tm_min, lt->tm_sec);
}

void log_write(log_level_t level, const char *fmt, ...)
{
    char    msg[1024];
    char    stamp[80];
    va_list ap;

    if (level > log_threshold)
        return;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);

    timestamp(stamp, sizeof stamp);

    if (log_fp != NULL) {
        fprintf(log_fp, "%s [%s] %s\n", stamp, level_name(level), msg);
        fflush(log_fp);
    }
    fprintf(stderr, "%s [%s] %s\n", stamp, level_name(level), msg);
}
