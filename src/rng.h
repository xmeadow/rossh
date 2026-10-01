#ifndef ROSSH_RNG_H
#define ROSSH_RNG_H

#include <stddef.h>

/*
 * The entropy pool.
 *
 * Start it once, before anything asks wolfSSL for random numbers. From then on
 * the pool is the only seed wolfSSL gets — see src/rng.c and spec.md §6.1.
 */
void rng_start(void);

/* Mix bytes into the pool. `tag` is mixed in too, to keep sources apart. */
void rng_add(const void *buf, size_t len, const char *tag);

/* Draw bytes from the pool. */
void rng_bytes(void *out, size_t len);

#endif /* ROSSH_RNG_H */
