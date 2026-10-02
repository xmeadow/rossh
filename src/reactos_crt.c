/*
 * ReactOS compatibility: the seven C11 Annex K "secure" CRT functions that
 * wolfSSH's Windows port calls and that ReactOS's msvcrt.dll does not export.
 *
 *   port.c: fopen_s, mbstowcs_s, wcstombs_s, strncat_s
 *   ssh.c:  strncpy_s, strtok_s, _snprintf_s
 *
 * mingw-w64 declares these __declspec(dllimport), so those calls go through the
 * import pointers __imp__*. The linker therefore records a real import from
 * msvcrt.dll, ReactOS's loader cannot resolve it, and - instead of failing the
 * process - it never starts it: the process exists, but its entry point is
 * never reached, so nothing runs and nothing is printed. That is the wall
 * described in docs/reactos.md section 9, and this file is its fix.
 *
 * Defining the import pointers, and the functions they point at, satisfies the
 * references locally so the import never enters the image. The semantics are
 * MSVC's, which is what wolfSSH was written against - in particular
 * mbstowcs_s is called with the character count as both the buffer size and
 * the limit, and the caller pads the buffer by one, so the terminator is
 * written at index n.
 *
 * Windows only: the native build compiles wolfSSH's POSIX path and never
 * references any of these.
 */

#ifdef _WIN32

#include <stddef.h>
#include <stdarg.h>

typedef int errno_t;
typedef struct _iobuf FILE;   /* mingw's FILE, without pulling in <stdio.h> */

/*
 * The CRT headers cannot be included here: they redeclare these functions as
 * dllimport, which forbids a local definition. The shim's own dependencies are
 * declared by hand instead. vsnprintf and strtok_r are not msvcrt exports at
 * all - mingw provides them - so they always resolve locally.
 */
extern FILE  *fopen(const char *, const char *);
extern int    vsnprintf(char *, size_t, const char *, va_list);
extern char  *strtok_r(char *, const char *, char **);
extern size_t mbstowcs(wchar_t *, const char *, size_t);
extern size_t wcstombs(char *, const wchar_t *, size_t);

#define CRT_EINVAL 22
#define CRT_ERANGE 34

errno_t strncpy_s(char *dst, size_t dstsz, const char *src, size_t count)
{
    size_t i;

    if (dst == NULL || dstsz == 0)
        return CRT_EINVAL;
    if (src == NULL) {
        dst[0] = '\0';
        return CRT_EINVAL;
    }

    for (i = 0; i < count && i + 1 < dstsz && src[i] != '\0'; i++)
        dst[i] = src[i];
    dst[i] = '\0';

    return (i == count && src[i] != '\0') ? CRT_ERANGE : 0;
}

errno_t strncat_s(char *dst, size_t dstsz, const char *src, size_t count)
{
    size_t i = 0, j;

    if (dst == NULL || dstsz == 0)
        return CRT_EINVAL;
    while (i < dstsz && dst[i] != '\0')
        i++;
    if (i == dstsz) {
        dst[0] = '\0';
        return CRT_EINVAL;
    }
    if (src == NULL) {
        dst[i] = '\0';
        return CRT_EINVAL;
    }

    for (j = 0; j < count && i + 1 < dstsz && src[j] != '\0'; i++, j++)
        dst[i] = src[j];
    dst[i] = '\0';

    return (j == count && src[j] != '\0') ? CRT_ERANGE : 0;
}

char *strtok_s(char *str, const char *delim, char **context)
{
    return strtok_r(str, delim, context);
}

int _snprintf_s(char *buf, size_t sizeOfBuffer, size_t count, const char *fmt,
                ...)
{
    va_list ap;
    int r;

    if (buf == NULL || sizeOfBuffer == 0)
        return -1;

    va_start(ap, fmt);
    r = vsnprintf(buf, sizeOfBuffer, fmt, ap);
    va_end(ap);

    /* Truncation is only acceptable when count == _TRUNCATE, i.e. (size_t)-1. */
    if (r < 0 || ((size_t)r >= sizeOfBuffer && count != (size_t)-1)) {
        buf[0] = '\0';
        return -1;
    }
    return r;
}

errno_t fopen_s(FILE **f, const char *filename, const char *mode)
{
    if (f == NULL)
        return CRT_EINVAL;
    *f = NULL;
    if (filename == NULL || mode == NULL)
        return CRT_EINVAL;

    *f = fopen(filename, mode);
    return (*f != NULL) ? 0 : CRT_EINVAL;
}

errno_t mbstowcs_s(size_t *pReturnValue, wchar_t *wcstr, size_t sizeInWords,
                   const char *mbstr, size_t count)
{
    size_t n, lim;

    if (pReturnValue != NULL)
        *pReturnValue = 0;
    if (mbstr == NULL)
        return CRT_EINVAL;

    if (wcstr == NULL) {                       /* size query */
        n = mbstowcs(NULL, mbstr, 0);
        if (n == (size_t)-1)
            return CRT_EINVAL;
        if (pReturnValue != NULL)
            *pReturnValue = n + 1;             /* characters, terminator included */
        return 0;
    }

    if (sizeInWords == 0)
        return CRT_EINVAL;
    lim = (count != 0 && count < sizeInWords) ? count : sizeInWords;

    n = mbstowcs(wcstr, mbstr, lim);
    if (n == (size_t)-1) {
        wcstr[0] = L'\0';
        return CRT_EINVAL;
    }
    wcstr[n] = L'\0';                          /* caller pads the buffer by one */
    if (pReturnValue != NULL)
        *pReturnValue = n + 1;
    return 0;
}

errno_t wcstombs_s(size_t *pReturnValue, char *mbstr, size_t sizeInBytes,
                   const wchar_t *wcstr, size_t count)
{
    size_t n, lim;

    if (pReturnValue != NULL)
        *pReturnValue = 0;
    if (wcstr == NULL)
        return CRT_EINVAL;

    if (mbstr == NULL) {                       /* size query */
        n = wcstombs(NULL, wcstr, 0);
        if (n == (size_t)-1)
            return CRT_EINVAL;
        if (pReturnValue != NULL)
            *pReturnValue = n + 1;
        return 0;
    }

    if (sizeInBytes == 0)
        return CRT_EINVAL;
    lim = (count != 0 && count < sizeInBytes) ? count : sizeInBytes;

    n = wcstombs(mbstr, wcstr, lim);
    if (n == (size_t)-1) {
        mbstr[0] = '\0';
        return CRT_EINVAL;
    }
    if (n < sizeInBytes)
        mbstr[n] = '\0';
    else
        mbstr[sizeInBytes - 1] = '\0';
    if (pReturnValue != NULL)
        *pReturnValue = n + 1;
    return 0;
}

/*
 * The import pointers wolfSSH's objects reference. The __asm__ label is
 * required: the i386 C decoration would otherwise turn __imp__strncpy_s into
 * ___imp__strncpy_s. Defining these here keeps libmsvcrt.a's import stubs out
 * of the link, so no unresolvable import reaches the loader.
 */
void *const __imp__strncpy_s   __asm__("__imp__strncpy_s")   = (void *)strncpy_s;
void *const __imp__strncat_s   __asm__("__imp__strncat_s")   = (void *)strncat_s;
void *const __imp__strtok_s    __asm__("__imp__strtok_s")    = (void *)strtok_s;
void *const __imp___snprintf_s __asm__("__imp___snprintf_s") = (void *)_snprintf_s;
void *const __imp__fopen_s     __asm__("__imp__fopen_s")     = (void *)fopen_s;
void *const __imp__mbstowcs_s  __asm__("__imp__mbstowcs_s")  = (void *)mbstowcs_s;
void *const __imp__wcstombs_s  __asm__("__imp__wcstombs_s")  = (void *)wcstombs_s;

#endif /* _WIN32 */
