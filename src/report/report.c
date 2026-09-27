/**
 * @file report.c
 * @brief Report dispatch — routes calls to the correct format implementation.
 */

#include <string.h>
#include "report.h"
#include "common.h"

int report_device(const AuditResult *result, const ReportOptions *opts)
{
    if (!result || !opts) return AUDIT_ERR_ARG;
    switch (opts->format) {
        case REPORT_CSV:  return report_csv_device(result, opts);
        case REPORT_JSON: return report_json_device(result, opts);
        default:          return report_text_device(result, opts);
    }
}

int report_aggregate(const AuditResult **results, int count,
                     const ReportOptions *opts)
{
    if (!results || !opts || count <= 0) return AUDIT_ERR_ARG;
    switch (opts->format) {
        case REPORT_CSV:  return report_csv_aggregate(results, count, opts);
        case REPORT_JSON: return report_json_aggregate(results, count, opts);
        default:          return report_text_aggregate(results, count, opts);
    }
}

const char *report_format_name(ReportFormat fmt)
{
    switch (fmt) {
        case REPORT_CSV:  return "csv";
        case REPORT_JSON: return "json";
        default:          return "text";
    }
}

bool report_parse_format(const char *name, ReportFormat *out)
{
    if (!name || !out) return false;
    if (portable_strcasecmp(name, "csv")  == 0) { *out = REPORT_CSV;  return true; }
    if (portable_strcasecmp(name, "json") == 0) { *out = REPORT_JSON; return true; }
    if (portable_strcasecmp(name, "text") == 0 ||
        portable_strcasecmp(name, "txt")  == 0) { *out = REPORT_TEXT; return true; }
    return false;
}

