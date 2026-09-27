/**
 * @file report_json.c
 * @brief JSON-lite compliance report formatter (hand-rolled, no external deps).
 *
 * Generates RFC 8259-compliant JSON without any library dependency.
 * Special characters in strings are properly escaped.
 */

#include <stdio.h>
#include <string.h>
#include "report.h"
#include "model.h"
#include "common.h"

/** Emit a JSON-escaped string value (no surrounding quotes). */
static void json_str_content(FILE *fp, const char *s)
{
    for (const char *p = s; *p; p++) {
        switch (*p) {
            case '"':  fputs("\\\"", fp); break;
            case '\\': fputs("\\\\", fp); break;
            case '\n': fputs("\\n",  fp); break;
            case '\r': fputs("\\r",  fp); break;
            case '\t': fputs("\\t",  fp); break;
            default:
                if ((unsigned char)*p < 0x20)
                    fprintf(fp, "\\u%04x", (unsigned char)*p);
                else
                    fputc(*p, fp);
        }
    }
}

static void json_str(FILE *fp, const char *s)
{
    fputc('"', fp);
    json_str_content(fp, s);
    fputc('"', fp);
}

static void json_kv_str(FILE *fp, const char *key, const char *val,
                        bool last, int indent)
{
    fprintf(fp, "%*s", indent, "");
    json_str(fp, key);
    fputs(": ", fp);
    json_str(fp, val ? val : "");
    if (!last) fputc(',', fp);
    fputc('\n', fp);
}

static void json_kv_int(FILE *fp, const char *key, int val,
                        bool last, int indent)
{
    fprintf(fp, "%*s", indent, "");
    json_str(fp, key);
    fprintf(fp, ": %d", val);
    if (!last) fputc(',', fp);
    fputc('\n', fp);
}

static void emit_finding(FILE *fp, const Finding *f, bool last, int indent)
{
    fprintf(fp, "%*s{\n", indent, "");
    json_kv_str(fp, "rule_id",  f->rule_id,                        false, indent+2);
    json_kv_str(fp, "severity", SEVERITY_LABELS[f->severity],      false, indent+2);
    json_kv_str(fp, "section",  f->affected_section,               false, indent+2);
    json_kv_str(fp, "description", f->description,                 false, indent+2);
    json_kv_str(fp, "remediation", f->remediation,                 true,  indent+2);
    fprintf(fp, "%*s}%s\n", indent, "", last ? "" : ",");
}

static void emit_device_obj(FILE *fp, const AuditResult *r,
                            const ReportOptions *o, bool last, int indent)
{
    const DeviceModel *d = r->device;
    fprintf(fp, "%*s{\n", indent, "");
    json_kv_str(fp, "hostname",   d->hostname[0] ? d->hostname : "(unknown)", false, indent+2);
    json_kv_str(fp, "vendor",     d->vendor,        false, indent+2);
    json_kv_str(fp, "version",    d->os_version,    false, indent+2);
    json_kv_str(fp, "source",     d->source_file,   false, indent+2);
    json_kv_int(fp, "score",      r->score,          false, indent+2);
    json_kv_int(fp, "critical",   r->sev_counts[SEV_CRITICAL], false, indent+2);
    json_kv_int(fp, "high",       r->sev_counts[SEV_HIGH],     false, indent+2);
    json_kv_int(fp, "medium",     r->sev_counts[SEV_MEDIUM],   false, indent+2);
    json_kv_int(fp, "low",        r->sev_counts[SEV_LOW],      false, indent+2);

    /* findings array */
    fprintf(fp, "%*s\"findings\": [\n", indent+2, "");
    int shown = 0;
    /* Count shown first to know when to omit trailing comma */
    int show_count = 0;
    for (int i = 0; i < r->finding_count; i++)
        if (r->findings[i].severity <= o->min_severity) show_count++;

    for (int i = 0; i < r->finding_count; i++) {
        const Finding *f = &r->findings[i];
        if (f->severity > o->min_severity) continue;
        shown++;
        emit_finding(fp, f, (shown == show_count), indent+4);
    }
    fprintf(fp, "%*s]\n", indent+2, "");
    fprintf(fp, "%*s}%s\n", indent, "", last ? "" : ",");
}

int report_json_device(const AuditResult *r, const ReportOptions *o)
{
    FILE *fp = o->output ? o->output : stdout;
    const DeviceModel *d = r->device;

    /* Emit a single flat object: no nested anonymous object */
    fprintf(fp, "{\n");
    json_kv_str(fp, "report_type", "device",                               false, 2);
    json_kv_str(fp, "hostname",    d->hostname[0] ? d->hostname : "(unknown)", false, 2);
    json_kv_str(fp, "vendor",      d->vendor,                              false, 2);
    json_kv_str(fp, "version",     d->os_version,                          false, 2);
    json_kv_str(fp, "source",      d->source_file,                         false, 2);
    json_kv_int(fp, "score",       r->score,                               false, 2);
    json_kv_int(fp, "critical",    r->sev_counts[SEV_CRITICAL],            false, 2);
    json_kv_int(fp, "high",        r->sev_counts[SEV_HIGH],                false, 2);
    json_kv_int(fp, "medium",      r->sev_counts[SEV_MEDIUM],              false, 2);
    json_kv_int(fp, "low",         r->sev_counts[SEV_LOW],                 false, 2);

    /* findings array */
    fprintf(fp, "  \"findings\": [\n");
    int shown = 0;
    int show_count = 0;
    for (int i = 0; i < r->finding_count; i++)
        if (r->findings[i].severity <= o->min_severity) show_count++;

    for (int i = 0; i < r->finding_count; i++) {
        const Finding *f = &r->findings[i];
        if (f->severity > o->min_severity) continue;
        shown++;
        emit_finding(fp, f, (shown == show_count), 4);
    }
    fprintf(fp, "  ]\n}\n");
    return AUDIT_OK;
}


int report_json_aggregate(const AuditResult **rs, int n,
                          const ReportOptions *o)
{
    FILE *fp = o->output ? o->output : stdout;

    int total_score = 0;
    int total_sev[SEV_COUNT] = {0};
    for (int i = 0; i < n; i++) {
        total_score += rs[i]->score;
        for (int s = 0; s < SEV_COUNT; s++)
            total_sev[s] += rs[i]->sev_counts[s];
    }
    int avg = (n > 0) ? total_score / n : 0;

    fprintf(fp, "{\n");
    fprintf(fp, "  \"report_type\": \"aggregate\",\n");
    json_kv_int(fp, "devices_audited", n,                    false, 2);
    json_kv_int(fp, "avg_score",       avg,                  false, 2);
    json_kv_int(fp, "total_critical",  total_sev[SEV_CRITICAL], false, 2);
    json_kv_int(fp, "total_high",      total_sev[SEV_HIGH],     false, 2);
    json_kv_int(fp, "total_medium",    total_sev[SEV_MEDIUM],   false, 2);
    json_kv_int(fp, "total_low",       total_sev[SEV_LOW],      false, 2);
    fprintf(fp, "  \"devices\": [\n");
    for (int i = 0; i < n; i++) {
        emit_device_obj(fp, rs[i], o, (i == n-1), 4);
    }
    fprintf(fp, "  ]\n}\n");
    return AUDIT_OK;
}
