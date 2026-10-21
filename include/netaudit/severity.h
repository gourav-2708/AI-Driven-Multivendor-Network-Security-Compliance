/**
 * @file severity.h
 * @brief Finding severities, ordered most to least severe.
 */
#ifndef NETAUDIT_SEVERITY_H
#define NETAUDIT_SEVERITY_H

#include <stdbool.h>

typedef enum {
    SEV_CRITICAL = 0,
    SEV_HIGH,
    SEV_MEDIUM,
    SEV_LOW,
    SEV_COUNT
} Severity;

/** "CRITICAL", "HIGH", ... */
const char *severity_label(Severity s);

/** ANSI colour escape for terminal output. */
const char *severity_ansi(Severity s);

/** Case-insensitive parse of "critical" / "high" / "medium" / "low". */
bool severity_parse(const char *name, Severity *out);

/** True when @p s is at least as severe as @p threshold. */
static inline bool severity_at_least(Severity s, Severity threshold)
{
    return s <= threshold;
}

#endif /* NETAUDIT_SEVERITY_H */
