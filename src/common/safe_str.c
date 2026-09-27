/**
 * @file safe_str.c
 * @brief Memory-safe string utilities and logging implementation.
 *
 * Every string copy/format in net-audit goes through these wrappers.
 * Raw strcpy / gets / unbounded sprintf are never used in the codebase.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include "common.h"

/* -- Logging --------------------------------------------------------------- */

LogLevel g_log_level = LOG_INFO;

static const char *level_prefix[] = {
    "[DBG] ", "[INF] ", "[WRN] ", "[ERR] "
};

void audit_log(LogLevel level, const char *fmt, ...)
{
    if (level < g_log_level) return;

    FILE *dest = stderr;   /* Always stderr: keep stdout clean for report output */
    fputs(level_prefix[level], dest);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(dest, fmt, ap);
    va_end(ap);

    fputc('\n', dest);
}

/* -- Safe string functions ------------------------------------------------- */

/**
 * @brief Bounded copy; always NUL-terminates. Warns on truncation.
 */
char *safe_strncpy(char *dst, const char *src, size_t dst_size)
{
    if (!dst || dst_size == 0) return dst;
    if (!src) { dst[0] = '\0'; return dst; }

    size_t src_len = strlen(src);
    if (src_len >= dst_size) {
        LOG_WRN("safe_strncpy: truncating '%.*s...' to %zu bytes",
                (int)(dst_size > 16 ? 16 : dst_size), src, dst_size - 1);
    }

    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
    return dst;
}

/**
 * @brief Bounded printf; warns on truncation.
 */
int safe_snprintf(char *buf, size_t buf_size, const char *fmt, ...)
{
    if (!buf || buf_size == 0) return -1;

    va_list ap;
    va_start(ap, fmt);
    int needed = vsnprintf(buf, buf_size, fmt, ap);
    va_end(ap);

    if (needed < 0) {
        LOG_ERR("safe_snprintf: encoding error");
        buf[0] = '\0';
        return -1;
    }
    if ((size_t)needed >= buf_size) {
        LOG_WRN("safe_snprintf: output truncated (%d bytes needed, %zu available)",
                needed, buf_size);
    }
    return needed;
}

/**
 * @brief Trim leading and trailing ASCII whitespace in-place.
 */
char *str_trim(char *s)
{
    if (!s) return s;

    /* Trim leading */
    char *p = s;
    while (*p && isspace((unsigned char)*p)) p++;

    if (p != s) memmove(s, p, strlen(p) + 1);

    /* Trim trailing */
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[--len] = '\0';
    }
    return s;
}

/**
 * @brief Case-sensitive prefix check.
 */
bool str_starts_with(const char *s, const char *prefix)
{
    if (!s || !prefix) return false;
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/**
 * @brief Case-insensitive prefix check.
 */
bool str_starts_with_ci(const char *s, const char *prefix)
{
    if (!s || !prefix) return false;
    size_t plen = strlen(prefix);
    size_t slen = strlen(s);
    if (slen < plen) return false;
    for (size_t i = 0; i < plen; i++) {
        if (tolower((unsigned char)s[i]) != tolower((unsigned char)prefix[i]))
            return false;
    }
    return true;
}

/**
 * @brief Case-insensitive substring search.
 */
bool str_contains_ci(const char *haystack, const char *needle)
{
    if (!haystack || !needle) return false;
    size_t nlen = strlen(needle);
    if (nlen == 0) return true;
    size_t hlen = strlen(haystack);
    if (hlen < nlen) return false;

    for (size_t i = 0; i <= hlen - nlen; i++) {
        size_t j;
        for (j = 0; j < nlen; j++) {
            if (tolower((unsigned char)haystack[i+j]) !=
                tolower((unsigned char)needle[j]))
                break;
        }
        if (j == nlen) return true;
    }
    return false;
}

/**
 * @brief Human-readable error string for an AUDIT_* code.
 */
const char *audit_strerror(int rc)
{
    switch (rc) {
        case AUDIT_OK:          return "success";
        case AUDIT_ERR_IO:      return "I/O error";
        case AUDIT_ERR_PARSE:   return "parse error";
        case AUDIT_ERR_OOM:     return "out of memory";
        case AUDIT_ERR_ARG:     return "invalid argument";
        case AUDIT_ERR_LIMIT:   return "internal limit exceeded";
        case AUDIT_ERR_VENDOR:  return "unknown vendor";
        default:                return "unknown error";
    }
}

/**
 * @brief Portable case-insensitive string comparison.
 * Replaces portable_strcasecmp (POSIX) / _stricmp (Windows) without platform macros.
 */
int portable_strcasecmp(const char *a, const char *b)
{
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return  1;
    while (*a && *b) {
        int ca = tolower((unsigned char)*a);
        int cb = tolower((unsigned char)*b);
        if (ca != cb) return ca - cb;
        a++; b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}


/**
 * @brief Portable case-insensitive bounded string comparison.
 * Replaces portable_strncasecmp (POSIX) / _strnicmp (Windows).
 */
int portable_strncasecmp(const char *a, const char *b, size_t n)
{
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return  1;
    for (size_t i = 0; i < n && (*a || *b); i++, a++, b++) {
        int ca = tolower((unsigned char)*a);
        int cb = tolower((unsigned char)*b);
        if (ca != cb) return ca - cb;
    }
    return 0;
}

