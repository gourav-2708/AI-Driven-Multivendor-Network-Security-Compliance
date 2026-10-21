/**
 * @file report_internal.h
 * @brief Interface implemented by each report format.
 */
#ifndef NETAUDIT_REPORT_INTERNAL_H
#define NETAUDIT_REPORT_INTERNAL_H

#include "netaudit/report.h"

typedef struct ReportFormatOps {
    void (*begin)(ReportSession *s);                        /* first device */
    void (*device)(ReportSession *s, const AuditResult *r, int index);
    void (*end)(ReportSession *s);                          /* after last   */
} ReportFormatOps;

extern const ReportFormatOps REPORT_OPS_TEXT;
extern const ReportFormatOps REPORT_OPS_CSV;
extern const ReportFormatOps REPORT_OPS_JSON;

/** Whether a finding passes the session's severity filter. */
static inline bool report_shows(const ReportSession *s, const Finding *f)
{
    return severity_at_least(f->severity, s->opts.min_severity);
}

int report_count_shown(const ReportSession *s, const AuditResult *r);

/** Fleet average score (integer, as reported since v1). */
int report_average_score(const ReportSession *s);

#endif /* NETAUDIT_REPORT_INTERNAL_H */
