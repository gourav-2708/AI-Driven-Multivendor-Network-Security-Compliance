/**
 * @file safe_str.h
 * @brief Bounded string operations. Every string copy, concatenation and
 *        formatted write in net-audit goes through these functions.
 *
 * Contract shared by all writers below:
 *   - the destination is always NUL-terminated when dst_size > 0;
 *   - they never write more than dst_size bytes;
 *   - they return false (or a negative value) when output was truncated,
 *     so callers can decide whether truncation matters.
 */
#ifndef NETAUDIT_SAFE_STR_H
#define NETAUDIT_SAFE_STR_H

#include "netaudit/banned.h"
#include "netaudit/compiler.h"

/* -- Bounded writers ------------------------------------------------------ */
bool safe_strcpy(char *dst, size_t dst_size, const char *src);
bool safe_strcat(char *dst, size_t dst_size, const char *src);
bool safe_snprintf(char *dst, size_t dst_size, const char *fmt, ...)
     NA_PRINTF(3, 4);
bool safe_vsnprintf(char *dst, size_t dst_size, const char *fmt, va_list ap)
     NA_PRINTF(3, 0);

/** Copy at most n bytes of src (stops early at NUL). */
bool safe_strncpy_n(char *dst, size_t dst_size, const char *src, size_t n);

/* -- Inspection (never write) --------------------------------------------- */
bool str_eq_ci(const char *a, const char *b);
bool str_starts_with(const char *s, const char *prefix);
bool str_starts_with_ci(const char *s, const char *prefix);
bool str_ends_with_ci(const char *s, const char *suffix);
bool str_contains_ci(const char *haystack, const char *needle);
int  str_cmp_ci(const char *a, const char *b);

/** Parse a whole decimal integer; false on junk, empty input or overflow. */
bool str_to_int(const char *s, int *out);

/* -- In-place editing ------------------------------------------------------ */
/** Trim leading/trailing whitespace in place; returns s. */
char *str_trim(char *s);

/**
 * Split @p line in place into whitespace-separated words.
 * A double-quoted word may contain spaces; the quotes are removed.
 * At most @p max words are produced; the remainder of the line is ignored.
 * @return number of words stored in @p words.
 */
int  str_tokenize(char *line, char *words[], int max);

#endif /* NETAUDIT_SAFE_STR_H */
