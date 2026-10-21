/**
 * @file safe_str.c
 * @brief Bounded string operations (see safe_str.h for the contract).
 */
#include "netaudit/safe_str.h"

bool safe_strncpy_n(char *dst, size_t dst_size, const char *src, size_t n)
{
    if (!dst || dst_size == 0) return false;
    if (!src) { dst[0] = '\0'; return true; }

    size_t len = 0;
    while (len < n && src[len] != '\0') len++;

    bool fits = len < dst_size;
    if (!fits) len = dst_size - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
    return fits;
}

bool safe_strcpy(char *dst, size_t dst_size, const char *src)
{
    return safe_strncpy_n(dst, dst_size, src, (size_t)-1);
}

bool safe_strcat(char *dst, size_t dst_size, const char *src)
{
    if (!dst || dst_size == 0) return false;
    size_t used = 0;                 /* strnlen() is POSIX, not C11 */
    while (used < dst_size && dst[used] != '\0') used++;
    if (used == dst_size) {          /* dst was not terminated: repair it */
        dst[dst_size - 1] = '\0';
        return false;
    }
    return safe_strcpy(dst + used, dst_size - used, src);
}

bool safe_vsnprintf(char *dst, size_t dst_size, const char *fmt, va_list ap)
{
    if (!dst || dst_size == 0) return false;
    int needed = vsnprintf(dst, dst_size, fmt, ap);
    if (needed < 0) {
        dst[0] = '\0';
        return false;
    }
    return (size_t)needed < dst_size;
}

bool safe_snprintf(char *dst, size_t dst_size, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    bool ok = safe_vsnprintf(dst, dst_size, fmt, ap);
    va_end(ap);
    return ok;
}

/* -- Inspection ------------------------------------------------------------ */

int str_cmp_ci(const char *a, const char *b)
{
    if (a == b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    for (;; a++, b++) {
        int ca = tolower((unsigned char)*a);
        int cb = tolower((unsigned char)*b);
        if (ca != cb || ca == '\0') return ca - cb;
    }
}

bool str_eq_ci(const char *a, const char *b)
{
    return str_cmp_ci(a, b) == 0;
}

bool str_starts_with(const char *s, const char *prefix)
{
    if (!s || !prefix) return false;
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

bool str_starts_with_ci(const char *s, const char *prefix)
{
    if (!s || !prefix) return false;
    for (; *prefix; s++, prefix++) {
        if (tolower((unsigned char)*s) != tolower((unsigned char)*prefix))
            return false;           /* also stops at the end of s */
    }
    return true;
}

bool str_ends_with_ci(const char *s, const char *suffix)
{
    if (!s || !suffix) return false;
    size_t sl = strlen(s), xl = strlen(suffix);
    return xl <= sl && str_eq_ci(s + sl - xl, suffix);
}

bool str_contains_ci(const char *haystack, const char *needle)
{
    if (!haystack || !needle) return false;
    if (*needle == '\0') return true;
    for (; *haystack; haystack++) {
        if (str_starts_with_ci(haystack, needle)) return true;
    }
    return false;
}

bool str_to_int(const char *s, int *out)
{
    if (!s || !out || *s == '\0') return false;
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') return false;
    if (v < INT_MIN || v > INT_MAX) return false;
    *out = (int)v;
    return true;
}

/* -- In-place editing ------------------------------------------------------ */

char *str_trim(char *s)
{
    if (!s) return s;
    char *start = s;
    while (*start && isspace((unsigned char)*start)) start++;

    size_t len = strlen(start);
    while (len > 0 && isspace((unsigned char)start[len - 1])) len--;

    memmove(s, start, len);
    s[len] = '\0';
    return s;
}

int str_tokenize(char *line, char *words[], int max)
{
    if (!line || !words || max <= 0) return 0;

    int  n = 0;
    char *p = line;
    while (*p && n < max) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '\0') break;

        if (*p == '"') {
            words[n++] = ++p;
            while (*p && *p != '"') p++;
        } else {
            words[n++] = p;
            while (*p && !isspace((unsigned char)*p)) p++;
        }
        if (*p) *p++ = '\0';
    }
    return n;
}
