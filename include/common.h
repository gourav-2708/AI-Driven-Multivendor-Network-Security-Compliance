/**
 * @file common.h
 * @brief Common utilities, error codes, safe-string wrappers, and logging
 *        macros shared across all net-audit modules.
 */
#ifndef NET_AUDIT_COMMON_H
#define NET_AUDIT_COMMON_H

#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

/* Error codes */
#define AUDIT_OK         0
#define AUDIT_ERR_IO     1
#define AUDIT_ERR_PARSE  2
#define AUDIT_ERR_OOM    3
#define AUDIT_ERR_ARG    4
#define AUDIT_ERR_LIMIT  5
#define AUDIT_ERR_VENDOR 6

/* Logging */
typedef enum { LOG_DEBUG=0, LOG_INFO, LOG_WARN, LOG_ERROR } LogLevel;
extern LogLevel g_log_level;
void audit_log(LogLevel level, const char *fmt, ...);
#define LOG_DBG(...)  audit_log(LOG_DEBUG, __VA_ARGS__)
#define LOG_INF(...)  audit_log(LOG_INFO,  __VA_ARGS__)
#define LOG_WRN(...)  audit_log(LOG_WARN,  __VA_ARGS__)
#define LOG_ERR(...)  audit_log(LOG_ERROR, __VA_ARGS__)

/* Safe string utilities */

/* Portable case-insensitive comparison (replaces portable_strcasecmp/_stricmp) */
int portable_strcasecmp(const char *a, const char *b);
int portable_strncasecmp(const char *a, const char *b, size_t n);
char       *safe_strncpy(char *dst, const char *src, size_t dst_size);
int         safe_snprintf(char *buf, size_t buf_size, const char *fmt, ...);
char       *str_trim(char *s);
bool        str_starts_with(const char *s, const char *prefix);
bool        str_starts_with_ci(const char *s, const char *prefix);
bool        str_contains_ci(const char *haystack, const char *needle);
const char *audit_strerror(int rc);

#endif /* NET_AUDIT_COMMON_H */



