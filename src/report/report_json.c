/**
 * @file report_json.c
 * @brief JSON report (RFC 8259), hand-written with no library dependency.
 *
 * Schema (stable; consumed by the web and desktop front-ends):
 *   device report: { "report_type": "device", "hostname", "vendor",
 *                    "version", "source", "score", "critical", "high",
 *                    "medium", "low", "findings": [ {...} ] }
 *   fleet report:  { "report_type": "aggregate", "devices": [ <device
 *                    object without report_type> ], "devices_audited",
 *                    "avg_score", "total_critical", "total_high",
 *                    "total_medium", "total_low" }
 *   finding:       { "rule_id", "severity", "section", "line",
 *                    "description", "remediation" }
 */
#include "netaudit/safe_str.h"
#include "report_internal.h"

static void json_string(FILE *fp, const char *s)
{
    fputc('"', fp);
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  fputs("\\\"", fp); break;
        case '\\': fputs("\\\\", fp); break;
        case '\n': fputs("\\n", fp);  break;
        case '\r': fputs("\\r", fp);  break;
        case '\t': fputs("\\t", fp);  break;
        default:
            if (c < 0x20 || c == 0x7f) fprintf(fp, "\\u%04x", c);
            else                       fputc(c, fp);
        }
    }
    fputc('"', fp);
}

static void kv_str(FILE *fp, int indent, const char *key, const char *val, bool last)
{
    fprintf(fp, "%*s", indent, "");
    json_string(fp, key);
    fputs(": ", fp);
    json_string(fp, val);
    fputs(last ? "\n" : ",\n", fp);
}

static void kv_int(FILE *fp, int indent, const char *key, int val, bool last)
{
    fprintf(fp, "%*s", indent, "");
    json_string(fp, key);
    fprintf(fp, ": %d%s", val, last ? "\n" : ",\n");
}

static void finding(FILE *fp, int indent, const Finding *f, bool last)
{
    fprintf(fp, "%*s{\n", indent, "");
    kv_str(fp, indent + 2, "rule_id",     f->rule->id, false);
    kv_str(fp, indent + 2, "severity",    severity_label(f->severity), false);
    kv_str(fp, indent + 2, "section",     f->section, false);
    kv_int(fp, indent + 2, "line",        f->line_number, false);
    kv_str(fp, indent + 2, "description", f->description, false);
    kv_str(fp, indent + 2, "remediation", f->remediation, true);
    fprintf(fp, "%*s}%s\n", indent, "", last ? "" : ",");
}

static void device_body(ReportSession *s, const AuditResult *r, int indent)
{
    FILE *fp = s->opts.out;
    const DeviceModel *d = r->device;

    kv_str(fp, indent, "hostname", model_hostname(d), false);
    kv_str(fp, indent, "vendor",   d->vendor, false);
    kv_str(fp, indent, "version",  d->os_version, false);
    kv_str(fp, indent, "source",   d->source_file, false);
    kv_int(fp, indent, "score",    r->score, false);
    kv_int(fp, indent, "critical", r->sev_counts[SEV_CRITICAL], false);
    kv_int(fp, indent, "high",     r->sev_counts[SEV_HIGH], false);
    kv_int(fp, indent, "medium",   r->sev_counts[SEV_MEDIUM], false);
    kv_int(fp, indent, "low",      r->sev_counts[SEV_LOW], false);

    fprintf(fp, "%*s\"findings\": [\n", indent, "");
    int remaining = report_count_shown(s, r);
    for (int i = 0; i < r->finding_count; i++) {
        if (!report_shows(s, &r->findings[i])) continue;
        finding(fp, indent + 2, &r->findings[i], --remaining == 0);
    }
    fprintf(fp, "%*s]\n", indent, "");
}

static void json_begin(ReportSession *s)
{
    if (!s->fleet) return;
    fputs("{\n  \"report_type\": \"aggregate\",\n  \"devices\": [\n", s->opts.out);
}

static void json_device(ReportSession *s, const AuditResult *r, int index)
{
    FILE *fp = s->opts.out;
    if (!s->fleet) {
        fputs("{\n", fp);
        kv_str(fp, 2, "report_type", "device", false);
        device_body(s, r, 2);
        fputs("}\n", fp);
        return;
    }
    if (index > 0) fputs(",\n", fp);
    fputs("    {\n", fp);
    device_body(s, r, 6);
    fputs("    }", fp);
}

static void json_end(ReportSession *s)
{
    if (!s->fleet) return;
    FILE *fp = s->opts.out;
    fputs("\n  ],\n", fp);
    kv_int(fp, 2, "devices_audited", s->device_count, false);
    kv_int(fp, 2, "avg_score",       report_average_score(s), false);
    kv_int(fp, 2, "total_critical",  s->sev_totals[SEV_CRITICAL], false);
    kv_int(fp, 2, "total_high",      s->sev_totals[SEV_HIGH], false);
    kv_int(fp, 2, "total_medium",    s->sev_totals[SEV_MEDIUM], false);
    kv_int(fp, 2, "total_low",       s->sev_totals[SEV_LOW], true);
    fputs("}\n", fp);
}

const ReportFormatOps REPORT_OPS_JSON = {
    .begin  = json_begin,
    .device = json_device,
    .end    = json_end,
};
