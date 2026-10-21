/**
 * @file log.h
 * @brief Levelled diagnostics. Always written to stderr so that stdout
 *        carries nothing but the report.
 */
#ifndef NETAUDIT_LOG_H
#define NETAUDIT_LOG_H

#include "netaudit/compiler.h"

typedef enum { LOG_DEBUG = 0, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_SILENT } LogLevel;

void     log_set_level(LogLevel level);
LogLevel log_get_level(void);
void     audit_log(LogLevel level, const char *fmt, ...) NA_PRINTF(2, 3);

#define LOG_DBG(...) audit_log(LOG_DEBUG, __VA_ARGS__)
#define LOG_INF(...) audit_log(LOG_INFO,  __VA_ARGS__)
#define LOG_WRN(...) audit_log(LOG_WARN,  __VA_ARGS__)
#define LOG_ERR(...) audit_log(LOG_ERROR, __VA_ARGS__)

#endif /* NETAUDIT_LOG_H */
