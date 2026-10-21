/**
 * @file report_csv.c
 * @brief RFC 4180 CSV report: one row per finding, CRLF line endings.
 */
#include "netaudit/safe_str.h"
#include "report_internal.h"

static void field(FILE *fp, const char *s, bool last)
{
    fputc('"', fp);
    for (; s && *s; s++) {
        if (*s == '"') fputc('"', fp);
        fputc(*s, fp);
    }
    fputc('"', fp);
    fputs(last ? "\r\n" : ",", fp);
}

static void csv_begin(ReportSession *s)
{
    fputs("device,vendor,rule_id,severity,section,description,remediation\r\n",
          s->opts.out);
}

static void csv_device(ReportSession *s, const AuditResult *r, int index)
{
    FILE *fp = s->opts.out;
    (void)index;
    for (int i = 0; i < r->finding_count; i++) {
        const Finding *f = &r->findings[i];
        if (!report_shows(s, f)) continue;
        field(fp, model_hostname(r->device), false);
        field(fp, r->device->vendor, false);
        field(fp, f->rule->id, false);
        field(fp, severity_label(f->severity), false);
        field(fp, f->section, false);
        field(fp, f->description, false);
        field(fp, f->remediation, true);
    }
}

const ReportFormatOps REPORT_OPS_CSV = {
    .begin  = csv_begin,
    .device = csv_device,
    .end    = NULL,
};
