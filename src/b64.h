/*
 * One-line base64 encoding.
 *
 * Both the server and the client need it — a public key line and a known_hosts
 * entry — and neither can rely on wolfSSL's Base64_Encode() across our builds
 * (see src/b64.c). This is the shared, minimal form.
 */

#ifndef ROSSH_B64_H
#define ROSSH_B64_H

#include <stddef.h>

/* Encoded length including the terminating NUL. */
size_t b64_encoded_size(size_t inSz);

/*
 * Encode `in` as one unwrapped base64 line, NUL-terminated. `outCap` must be at
 * least b64_encoded_size(inSz). Returns the length written (excluding the NUL),
 * or -1 if the buffer is too small.
 */
int b64_encode_nl(const unsigned char *in, size_t inSz,
                  char *out, size_t outCap);

#endif /* ROSSH_B64_H */
