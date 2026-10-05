#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <pthread.h>
#endif

#define LOG_PATH_MAX 600

static FILE       *log_fp;
static log_level_t log_threshold = LOG_INFO;
static char        log_path[LOG_PATH_MAX];
static long        log_max;      /* bytes; 0 = never rotate */
static long        log_size;     /* bytes written to log_fp so far */

/*
 * The log is shared by every connection thread. On POSIX the mutex is static;
 * on Windows a CRITICAL_SECTION needs a one-time init, which is safe without a
 * lock because the first log line is written before any connection thread
 * exists (main logs "rossh: start" and only then starts listening).
 */
#ifdef _WIN32
static CRITICAL_SECTION g_lock;
static int              g_lock_ready;

static void log_lock(void)
{
    if (!g_lock_ready) {
        InitializeCriticalSection(&g_lock);
        g_lock_ready = 1;
    }
    EnterCriticalSection(&g_lock);
}

static void log_unlock(void)
{
    LeaveCriticalSection(&g_lock);
}
#else
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static void log_lock(void)   { pthread_mutex_lock(&g_lock); }
static void log_unlock(void) { pthread_mutex_unlock(&g_lock); }
#endif

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

/* Rename the current file aside and start a fresh one. Called with the lock
 * held, or from log_open() before any thread exists. */
static void log_rotate(void)
{
    char bak[LOG_PATH_MAX + 4];

    if (log_fp != NULL) {
        fclose(log_fp);
        log_fp = NULL;
    }
    if (log_path[0] == '\0')
        return;

    snprintf(bak, sizeof bak, "%s.1", log_path);
    remove(bak);                        /* one generation, replace the old one */
    rename(log_path, bak);

    log_fp   = fopen(log_path, "a");
    log_size = 0;
}

void log_set_max_size(long bytes)
{
    log_max = (bytes > 0) ? bytes : 0;
}

void log_open(const char *path)
{
    long size = 0;

    log_close();

    if (path == NULL || path[0] == '\0')
        return;

    snprintf(log_path, sizeof log_path, "%s", path);
    log_fp = fopen(path, "a");
    if (log_fp == NULL) {
        fprintf(stderr, "rossh: cannot open log file '%s'\n", path);
        log_path[0] = '\0';
        return;
    }
    if (fseek(log_fp, 0, SEEK_END) == 0)
        size = ftell(log_fp);
    log_size = (size > 0) ? size : 0;

    if (log_max > 0 && log_size >= log_max)
        log_rotate();
}

void log_close(void)
{
    log_lock();
    if (log_fp != NULL) {
        fclose(log_fp);
        log_fp = NULL;
    }
    log_path[0] = '\0';
    log_size = 0;
    log_unlock();
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

    /* One lock for the whole line, so two sessions' lines never interleave. */
    log_lock();

    if (log_fp != NULL && log_max > 0 && log_size >= log_max)
        log_rotate();

    if (log_fp != NULL) {
        int n = fprintf(log_fp, "%s [%s] %s\n", stamp, level_name(level), msg);

        if (n > 0)
            log_size += n;
        fflush(log_fp);
    }
    fprintf(stderr, "%s [%s] %s\n", stamp, level_name(level), msg);

    log_unlock();
}
