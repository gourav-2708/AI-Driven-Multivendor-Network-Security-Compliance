/**
 * @file platform.h
 * @brief The only OS-specific surface of net-audit (POSIX and Win32).
 */
#ifndef NETAUDIT_PLATFORM_H
#define NETAUDIT_PLATFORM_H

#include <stdbool.h>
#include <stdio.h>
#include "netaudit/bounds.h"
#include "netaudit/status.h"

/**
 * Append the paths of regular files in @p dir whose extension is .cfg,
 * .conf or .txt (case-insensitive) to @p paths, sorted by name.
 * Not recursive.
 * @param count in: entries already used; out: entries used afterwards.
 * @return AUDIT_ERR_IO if the directory cannot be read,
 *         AUDIT_ERR_LIMIT if @p max entries would be exceeded.
 */
AuditStatus platform_list_configs(const char *dir,
                                  char paths[][NA_MAX_PATH],
                                  int *count, int max);

/** True when @p fp is an interactive terminal. */
bool platform_is_tty(FILE *fp);

/** Best effort: let a Windows console interpret ANSI escapes. */
void platform_enable_ansi(FILE *fp);

/** Stop newline translation on @p fp (needed for exact CRLF in CSV). */
void platform_set_binary(FILE *fp);

#endif /* NETAUDIT_PLATFORM_H */
