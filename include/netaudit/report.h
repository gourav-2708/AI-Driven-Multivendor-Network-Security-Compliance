/**
 * @file report.h
 * @brief Streaming compliance-report writer (text, CSV, JSON).
 *
 * Reports are produced device by device so the auditor only ever holds one
 * DeviceModel/AuditResult in memory:
 *
 *     report_begin(&s, &opts, fleet);
 *     for each audited device: report_device(&s, &result);
 *     report_end(&s);
 *
 * In single-device mode the output is one device report. In fleet mode
 * every device is reported in turn, followed by fleet-wide totals. Nothing
 * is written until the first device arrives, so a run that audits nothing
 * leaves the output empty.
 */
#ifndef NETAUDIT_REPORT_H
#define NETAUDIT_REPORT_H

#include <stdbool.h>
#include <stdio.h>
#include "netaudit/bounds.h"
#include "netaudit/engine.h"
#include "netaudit/severity.h"
#include "netaudit/status.h"

typedef enum { REPORT_TEXT = 0, REPORT_CSV, REPORT_JSON } ReportFormat;

typedef struct {
    ReportFormat format;
    FILE        *out;
    bool         color;          /* ANSI colour (text format only)     */
    Severity     min_severity;   /* hide findings less severe than this */
} ReportOptions;

/** Per-device numbers kept for the fleet summary. */
typedef struct {
    char hostname[NA_MAX_HOSTNAME];
    char vendor[NA_MAX_VENDOR];
    int  score;
    int  sev_counts[SEV_COUNT];
} DeviceSummary;

struct ReportFormatOps;

typedef struct {
    ReportOptions                 opts;
    const struct ReportFormatOps *ops;
    bool                          fleet;
    bool                          started;
    int                           device_count;
    int                           score_sum;
    int                           finding_total;
    int                           visible_total;   /* after severity filter */
    int                           sev_totals[SEV_COUNT];
    DeviceSummary                 devices[NA_MAX_INPUT_FILES];
} ReportSession;

AuditStatus report_begin(ReportSession *s, const ReportOptions *opts, bool fleet);
AuditStatus report_device(ReportSession *s, const AuditResult *r);
AuditStatus report_end(ReportSession *s);

/** Findings in the session that passed the severity filter. */
int report_visible_findings(const ReportSession *s);

bool        report_format_parse(const char *name, ReportFormat *out);
const char *report_format_name(ReportFormat f);

#endif /* NETAUDIT_REPORT_H */
