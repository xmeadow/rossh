/*
 * Base64 encoding, one line, no wrapping.
 *
 * wolfSSL has Base64_Encode(), but it is not in every build we produce: the
 * win32 library is configured --enable-cryptonly, which drops the encoder. The
 * alternative — turning it back on — adds code and imports to the image ReactOS
 * has to load (docs/reactos.md section 9), for a handful of bytes we can write
 * ourselves. And Base64_Encode() wraps at 64 columns, which is exactly what a
 * public key line or a known_hosts entry does not want.
 *
 * No padding is ever dropped: SSH key blobs are framed, so a '.pub' line stays
 * byte-identical to what OpenSSH emits.
 */

#include "b64.h"

static const char tbl[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t b64_encoded_size(size_t inSz)
{
    return 4 * ((inSz + 2) / 3) + 1;    /* + NUL */
}

int b64_encode_nl(const unsigned char *in, size_t inSz,
                  char *out, size_t outCap)
{
    size_t i = 0, o = 0;

    if (outCap < b64_encoded_size(inSz))
        return -1;

    for (; i + 2 < inSz; i += 3) {
        out[o++] = tbl[ in[i]      >> 2];
        out[o++] = tbl[(in[i]      & 0x03) << 4 | in[i + 1] >> 4];
        out[o++] = tbl[(in[i + 1]  & 0x0f) << 2 | in[i + 2] >> 6];
        out[o++] = tbl[ in[i + 2]  & 0x3f];
    }

    if (inSz - i == 1) {
        out[o++] = tbl[ in[i]      >> 2];
        out[o++] = tbl[(in[i]      & 0x03) << 4];
        out[o++] = '=';
        out[o++] = '=';
    }
    else if (inSz - i == 2) {
        out[o++] = tbl[ in[i]      >> 2];
        out[o++] = tbl[(in[i]      & 0x03) << 4 | in[i + 1] >> 4];
        out[o++] = tbl[(in[i + 1]  & 0x0f) << 2];
        out[o++] = '=';
    }

    out[o] = '\0';
    return (int)o;
}
