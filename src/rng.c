/*
 * The entropy pool — the only source of key material rossh has.
 *
 * ReactOS' only system RNG is SystemFunction036, which both CryptGenRandom and
 * BCryptGenRandom funnel into. It is seeded from QueryPerformanceCounter plus a
 * counter, and expanded with RtlRandom, a linear congruential generator; its own
 * source carries the warning that it "will NOT OUTPUT CRYPTOGRAPHIC-SAFE RANDOM
 * NUMBERS".
 *
 * So rossh never asks the platform for random numbers. It asks the platform for
 * *entropy*, mixes that into a pool of its own, and installs the pool as the
 * only seed wolfSSL will ever see. WC_RNG_SEED_CB (see tools/build-deps.sh)
 * removes wolfSSL's built-in seeding path, which means wc_SetSeed_Cb() below is
 * not a supplement to the platform RNG — it replaces it.
 *
 * Honest limitation, from spec.md §6.1: we cannot manufacture entropy the
 * platform does not have. Mixing raises the cost for an attacker who can observe
 * tick counts; it does not make the pool unforgeable.
 */

#include <wolfssl/options.h>

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/wc_port.h>   /* wolfCrypt_Init */

#ifndef WC_RNG_SEED_CB
    #error "Build with -DWC_RNG_SEED_CB, and configure wolfSSL the same way. See tools/build-deps.sh."
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
    /* Documented in ntsecapi.h as RtlGenRandom; declared here so the build does
     * not depend on that header being present. */
    BOOLEAN WINAPI SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);
    #define RtlGenRandom SystemFunction036
#else
    #include <unistd.h>
    #include <pthread.h>
#endif

#include "rng.h"

/* The pool is process-wide, and with one thread per connection several sessions
 * can reach it at once — the seed callback runs when a connection's RNG is
 * first used. Every public entry takes this lock; the mixing helpers below run
 * only from under it. */
#ifdef _WIN32
static CRITICAL_SECTION g_rng_lock;
#define rng_lock_init() InitializeCriticalSection(&g_rng_lock)
#define rng_lock()      EnterCriticalSection(&g_rng_lock)
#define rng_unlock()    LeaveCriticalSection(&g_rng_lock)
#else
static pthread_mutex_t g_rng_lock = PTHREAD_MUTEX_INITIALIZER;
#define rng_lock_init() ((void)0)
#define rng_lock()      pthread_mutex_lock(&g_rng_lock)
#define rng_unlock()    pthread_mutex_unlock(&g_rng_lock)
#endif

#define POOL_SIZE 32

static byte   pool[POOL_SIZE];
static word32 pool_calls;

/* wolfSSL's *_Init/_Final returning either 0 or WOLFSSL_SUCCESS, depending on
 * the function. Treat both as success rather than betting on one. */
static int sha_ok(int rc)
{
    return rc == 0 || rc == 1;
}

/* pool = SHA256(pool || data) */
static void mix(const void *data, size_t len)
{
    wc_Sha256 sha;
    byte      out[POOL_SIZE];

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, pool, POOL_SIZE);
    if (len > 0)
        wc_Sha256Update(&sha, (const byte *)data, (word32)len);
    if (!sha_ok(wc_Sha256Final(&sha, out)))
        memset(out, 0, sizeof out);
    wc_Sha256Free(&sha);

    memcpy(pool, out, POOL_SIZE);
}

/*
 * Entropy from the platform. Weak on ReactOS — which is the point: it is one
 * ingredient, never the recipe.
 */
static size_t platform_entropy(byte *buf, size_t len)
{
#ifdef _WIN32
    /* RtlGenRandom (advapi32's SystemFunction036) — deliberately *not*
     * CryptAcquireContext.
     *
     * The CryptoAPI container machinery is the heavy, stateful path: on ReactOS
     * it is a real candidate for blocking, and it buys nothing here. RtlGenRandom
     * is a plain computation there (dll/win32/advapi32/misc/sysfunc.c), and on
     * real Windows it is the very same generator that the CryptoAPI path ends in.
     *
     * To be accurate about the evidence: the on-target hang we chased turned out
     * to sit *before* main, so this is a precaution, not a proven fix. It is kept
     * because it is simpler and because the CryptoAPI path has no advantage here.
     *
     * The quality on ReactOS is poor — tick-count seeded, see docs/reactos.md —
     * which is precisely why it is only ever one ingredient in the pool below and
     * never the source of it. */
    if (len > 0xffffffffu)
        return 0;
    return RtlGenRandom(buf, (ULONG)len) ? len : 0;
#else
    FILE  *f;
    size_t got;

    f = fopen("/dev/urandom", "rb");
    if (f == NULL)
        return 0;
    got = fread(buf, 1, len, f);
    fclose(f);
    return got;
#endif
}

/* Sources that cost nothing and differ between boots and connections. */
static void stir_cheap_sources(void)
{
    struct {
        long long      monotonic;
        unsigned long  pid;
        unsigned long  tid;
        long long      wall;
        const void    *stack;
    } s;

    memset(&s, 0, sizeof s);

#ifdef _WIN32
    {
        LARGE_INTEGER qpc;
        QueryPerformanceCounter(&qpc);
        s.monotonic = (long long)qpc.QuadPart;
    }
    s.pid = (unsigned long)GetCurrentProcessId();
    s.tid = (unsigned long)GetCurrentThreadId();
#else
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        s.monotonic = (long long)ts.tv_sec * 1000000000LL + (long long)ts.tv_nsec;
    }
    s.pid = (unsigned long)getpid();
#endif
    s.wall  = (long long)time(NULL);
    s.stack = &s;   /* address of a local: catches ASLR */

    rng_lock();
    mix(&s, sizeof s);
    rng_unlock();
}

void rng_add(const void *buf, size_t len, const char *tag)
{
    rng_lock();
    if (tag != NULL)
        mix(tag, strlen(tag));
    if (len > 0)
        mix(buf, len);
    pool_calls++;
    rng_unlock();
}

void rng_bytes(void *out, size_t len)
{
    byte  *p = (byte *)out;
    byte   block[POOL_SIZE];

    rng_lock();
    while (len > 0) {
        wc_Sha256 sha;
        byte      digest[POOL_SIZE];
        size_t    take;

        pool_calls++;
        wc_InitSha256(&sha);
        wc_Sha256Update(&sha, pool, POOL_SIZE);
        wc_Sha256Update(&sha, (const byte *)&pool_calls, sizeof pool_calls);
        if (!sha_ok(wc_Sha256Final(&sha, digest)))
            memset(digest, 0, sizeof digest);
        wc_Sha256Free(&sha);

        /* Fold the output back in, so the state moves forward on every call. */
        memcpy(block, digest, POOL_SIZE);
        mix(digest, POOL_SIZE);

        take = (len < POOL_SIZE) ? len : POOL_SIZE;
        memcpy(p, block, take);
        p   += take;
        len -= take;
    }
    rng_unlock();
    memset(block, 0, sizeof block);
}

/* Handed to wolfSSL through wc_SetSeed_Cb(): the one and only seed. */
static int seed_cb(OS_Seed *os, byte *seed, word32 sz)
{
    byte   entropy[64];
    size_t got;

    (void)os;

    got = platform_entropy(entropy, sizeof entropy);
    rng_add(entropy, got, "os");
    if (got > 0)
        memset(entropy, 0, got);

    stir_cheap_sources();
    rng_bytes(seed, sz);
    return 0;
}

void rng_start(void)
{
    byte   entropy[64];
    size_t got;
    int    rc;

    rng_lock_init();

    /* wolfSSL's global state has to be initialised once, before any other
     * wolfSSL call. In particular this creates the mutex that guards its DRBG
     * state; without it wc_InitRng() locks an all-zero CRITICAL_SECTION. On
     * Linux that is invisible, because a zeroed pthread mutex is already valid
     * — which is why the native tests passed — but on Windows it is an access
     * violation inside ntdll, and on ReactOS the same lock simply never
     * returns. That is the whole reason the server looked hung before it ever
     * seeded a key. */
    rc = wolfCrypt_Init();
    if (rc != 0)
        fprintf(stderr, "rossh: wolfCrypt_Init failed (%d)\n", rc);

    /* A domain separator, so an empty pool is never a valid state. */
    mix("rossh/entropy/v1", 16);

    got = platform_entropy(entropy, sizeof entropy);
    rng_add(entropy, got, "os-start");
    if (got > 0)
        memset(entropy, 0, got);

    stir_cheap_sources();

    /* From here on wolfSSL has no seeding path of its own. */
    wc_SetSeed_Cb(seed_cb);

    fprintf(stderr, "rng: pool primed with %u bytes of platform entropy\n",
            (unsigned)got);
}
