/*
 * rossh's log.
 *
 * One sink, a level threshold, and an optional file. The console copy goes to
 * stderr because the server folds stderr into stdout (docs/build.md) — so the
 * messages still reach an existing `cmd.exe` pipe and the test scripts, while a
 * service, which has no console, still gets the file.
 *
 * The file is guarded by a mutex: with one thread per connection, several
 * sessions write here at once. It also rotates at a size cap, so a long-running
 * service cannot fill the disk with one unbounded file.
 */

#ifndef ROSSH_LOG_H
#define ROSSH_LOG_H

typedef enum {
    LOG_ERROR = 0,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
} log_level_t;

/* Append to `path`. An empty or NULL path leaves logging to the console only;
 * a file that cannot be opened is reported and ignored. */
void log_open(const char *path);
void log_close(void);

/* Rotate the file once it reaches `bytes` (0 = never). Set this before
 * log_open: an already oversized file is rotated on open. */
void log_set_max_size(long bytes);

/* Threshold by name — error, warn/warning, info, debug, case-insensitive.
 * Returns 0, or -1 for an unknown name (the level is left unchanged). */
int log_set_level(const char *name);

void log_write(log_level_t level, const char *fmt, ...);

#define log_error(...) log_write(LOG_ERROR, __VA_ARGS__)
#define log_warn(...)  log_write(LOG_WARN,  __VA_ARGS__)
#define log_info(...)  log_write(LOG_INFO,  __VA_ARGS__)
#define log_debug(...) log_write(LOG_DEBUG, __VA_ARGS__)

#endif /* ROSSH_LOG_H */
