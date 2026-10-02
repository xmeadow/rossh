#include "hostkey.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>

#include <stdio.h>
#include <string.h>

#include "b64.h"
#include "log.h"

/*
 * Write `<path>.pub`, the OpenSSH one-line form of an ed25519 key's public half.
 *
 * The wire form of that half is: string "ssh-ed25519", then string key — the
 * very blob a client offers and that authorized_keys carries, so one encoding
 * serves both ends and no other tool is needed to move a key between them.
 */
static int write_public_line(const ed25519_key *key, const char *path)
{
    byte   blob[64];
    byte   b64[128];
    byte   pub[ED25519_PUB_KEY_SIZE];
    word32 pubSz = (word32)sizeof pub;
    word32 idx   = 0;
    int    b64Sz;
    char   pub_path[512];
    FILE  *f;

    if (wc_ed25519_export_public(key, pub, &pubSz) != 0)
        return -1;

    blob[idx++] = 0;
    blob[idx++] = 0;
    blob[idx++] = 0;
    blob[idx++] = 11;
    memcpy(blob + idx, "ssh-ed25519", 11);
    idx += 11;
    blob[idx++] = 0;
    blob[idx++] = 0;
    blob[idx++] = 0;
    blob[idx++] = (byte)pubSz;
    memcpy(blob + idx, pub, pubSz);
    idx += pubSz;

    b64Sz = b64_encode_nl(blob, idx, (char *)b64, sizeof b64);
    if (b64Sz < 0)
        return -1;

    snprintf(pub_path, sizeof pub_path, "%s.pub", path);
    f = fopen(pub_path, "w");
    if (f == NULL)
        return -1;
    fprintf(f, "ssh-ed25519 %s rossh\n", (const char *)b64);
    fclose(f);

    log_info("wrote the public half to %s", pub_path);
    return 0;
}

/*
 * The key file has to carry its own public half: wolfSSH re-decodes it on every
 * key exchange and needs the public key to build the reply, and wolfSSL does not
 * derive it. wc_Ed25519PrivateKeyToDer() writes the private part only, which
 * fails later with PUBLIC_KEY_E (-134); wc_Ed25519KeyToDer() writes both.
 */
int hostkey_generate(const char *path)
{
    WC_RNG      rng;
    ed25519_key key;
    byte        der[256];
    int         derSz = 0;
    FILE       *f;

    if (wc_InitRng(&rng) != 0) {
        log_error("cannot start the RNG");
        return -1;
    }
    if (wc_ed25519_init(&key) != 0) {
        log_error("cannot initialise ed25519");
        wc_FreeRng(&rng);
        return -1;
    }

    if (wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &key) != 0) {
        log_error("key generation failed");
        goto done;
    }

    derSz = wc_Ed25519KeyToDer(&key, der, sizeof der);
    if (derSz <= 0) {
        log_error("key export failed (%d)", derSz);
        goto done;
    }

    f = fopen(path, "wb");
    if (f == NULL) {
        log_error("cannot write '%s'", path);
        derSz = -1;
        goto done;
    }
    if (fwrite(der, 1, (size_t)derSz, f) != (size_t)derSz) {
        log_error("short write to '%s'", path);
        fclose(f);
        derSz = -1;
        goto done;
    }
    fclose(f);

    log_info("wrote a %d-byte ed25519 key to %s", derSz, path);
    write_public_line(&key, path);

done:
    wc_ed25519_free(&key);
    wc_FreeRng(&rng);
    return (derSz > 0) ? 0 : -1;
}
