/**
 * @file report_csv.c
 * @brief CSV compliance report formatter (RFC 4180).
 *
 * Emits one row per finding. Fields are always double-quoted and internal
 * double-quotes are escaped by doubling them.
 */

#include <stdio.h>
#include <string.h>
#include "report.h"
#include "model.h"
#include "common.h"

/** Write a CSV-quoted field (with trailing comma if not last). */
static void csv_field(FILE *fp, const char *s, bool last)
{
    fputc('"', fp);
    for (const char *p = s; *p; p++) {
        if (*p == '"') fputc('"', fp);
        fputc(*p, fp);
    }
    fputc('"', fp);
    if (!last) fputc(',', fp);
}

static void csv_header(FILE *fp)
{
    fprintf(fp, "device,vendor,rule_id,severity,section,description,remediation\r\n");
}

int report_csv_device(const AuditResult *r, const ReportOptions *o)
{
    FILE *fp = o->output ? o->output : stdout;
    const DeviceModel *d = r->device;

    csv_header(fp);
    for (int i = 0; i < r->finding_count; i++) {
        const Finding *f = &r->findings[i];
        if (f->severity > o->min_severity) continue;

        csv_field(fp, d->hostname[0] ? d->hostname : "(unknown)", false);
        csv_field(fp, d->vendor, false);
        csv_field(fp, f->rule_id, false);
        csv_field(fp, SEVERITY_LABELS[f->severity], false);
        csv_field(fp, f->affected_section, false);
        csv_field(fp, f->description, false);
        csv_field(fp, f->remediation, true);
        fprintf(fp, "\r\n");
    }
    return AUDIT_OK;
}

int report_csv_aggregate(const AuditResult **rs, int n,
                         const ReportOptions *o)
{
    FILE *fp = o->output ? o->output : stdout;
    csv_header(fp);

    for (int i = 0; i < n; i++) {
        const AuditResult *r = rs[i];
        const DeviceModel *d = r->device;
        for (int j = 0; j < r->finding_count; j++) {
            const Finding *f = &r->findings[j];
            if (f->severity > o->min_severity) continue;

            csv_field(fp, d->hostname[0] ? d->hostname : "(unknown)", false);
            csv_field(fp, d->vendor, false);
            csv_field(fp, f->rule_id, false);
            csv_field(fp, SEVERITY_LABELS[f->severity], false);
            csv_field(fp, f->affected_section, false);
            csv_field(fp, f->description, false);
            csv_field(fp, f->remediation, true);
            fprintf(fp, "\r\n");
        }
    }
    return AUDIT_OK;
}
