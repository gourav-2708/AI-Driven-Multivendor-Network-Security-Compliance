/**
 * @file log.c
 * @brief Levelled diagnostics to stderr.
 */
#include "netaudit/log.h"
#include "netaudit/safe_str.h"

static LogLevel s_level = LOG_WARN;

void log_set_level(LogLevel level) { s_level = level; }
LogLevel log_get_level(void)       { return s_level; }

void audit_log(LogLevel level, const char *fmt, ...)
{
    static const char *const prefix[] = { "[DBG] ", "[INF] ", "[WRN] ", "[ERR] " };

    if (level < s_level || level >= LOG_SILENT) return;

    fputs(prefix[level], stderr);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
