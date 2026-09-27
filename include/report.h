/**
 * @file report.h
 * @brief Compliance report generation API.
 *
 * Three output formats: REPORT_TEXT, REPORT_CSV, REPORT_JSON.
 */
#ifndef NET_AUDIT_REPORT_H
#define NET_AUDIT_REPORT_H

#include <stdio.h>
#include <stdbool.h>
#include "model.h"

typedef enum { REPORT_TEXT=0, REPORT_CSV, REPORT_JSON } ReportFormat;

typedef struct {
    ReportFormat format;
    FILE        *output;
    bool         color;
    Severity     min_severity;
} ReportOptions;

int  report_device(const AuditResult *result, const ReportOptions *opts);
int  report_aggregate(const AuditResult **results, int count,
                      const ReportOptions *opts);

/* Internal format implementations */
int report_text_device(const AuditResult *r, const ReportOptions *o);
int report_text_aggregate(const AuditResult **rs, int n, const ReportOptions *o);
int report_csv_device(const AuditResult *r, const ReportOptions *o);
int report_csv_aggregate(const AuditResult **rs, int n, const ReportOptions *o);
int report_json_device(const AuditResult *r, const ReportOptions *o);
int report_json_aggregate(const AuditResult **rs, int n, const ReportOptions *o);

const char *report_format_name(ReportFormat fmt);
bool        report_parse_format(const char *name, ReportFormat *out);

#endif /* NET_AUDIT_REPORT_H */
