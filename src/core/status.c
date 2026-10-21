/**
 * @file status.c
 * @brief Status-code descriptions and severity metadata.
 */
#include "netaudit/safe_str.h"
#include "netaudit/severity.h"
#include "netaudit/status.h"

const char *audit_strerror(AuditStatus rc)
{
    switch (rc) {
    case AUDIT_OK:         return "success";
    case AUDIT_ERR_IO:     return "I/O error";
    case AUDIT_ERR_PARSE:  return "parse error";
    case AUDIT_ERR_ARG:    return "invalid argument";
    case AUDIT_ERR_LIMIT:  return "capacity limit exceeded";
    case AUDIT_ERR_VENDOR: return "unknown or undetectable vendor";
    }
    return "unknown error";
}

static const char *const k_sev_labels[SEV_COUNT] = {
    "CRITICAL", "HIGH", "MEDIUM", "LOW"
};

static const char *const k_sev_ansi[SEV_COUNT] = {
    "\033[1;31m",   /* CRITICAL: bold red */
    "\033[0;31m",   /* HIGH:     red      */
    "\033[0;33m",   /* MEDIUM:   yellow   */
    "\033[0;34m"    /* LOW:      blue     */
};

const char *severity_label(Severity s)
{
    return ((unsigned)s < SEV_COUNT) ? k_sev_labels[s] : "UNKNOWN";
}

const char *severity_ansi(Severity s)
{
    return ((unsigned)s < SEV_COUNT) ? k_sev_ansi[s] : "";
}

bool severity_parse(const char *name, Severity *out)
{
    if (!name || !out) return false;
    for (int s = 0; s < SEV_COUNT; s++) {
        if (str_eq_ci(name, k_sev_labels[s])) {
            *out = (Severity)s;
            return true;
        }
    }
    return false;
}
