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
 *                    "description", "remediation",
 *                    "frameworks": { "<framework key>": [ "<control>" ] } }
 *
 * The rule catalogue (--list-rules --format json) is a separate document:
 *   { "version", "frameworks": [ { "key", "title", "label" } ],
 *     "rules": [ { "id", "severity", "category", "category_code", "title",
 *                  "description", "remediation", "frameworks": {...} } ] }
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

/* "frameworks": { "cis_v8": ["4.6", "12.6"], ... } - every framework is
 * present, with an empty array when the rule maps to nothing in it. */
static void frameworks(FILE *fp, int indent, const Rule *rule)
{
    fprintf(fp, "%*s\"frameworks\": {", indent, "");
    for (int f = 0; f < FW_COUNT; f++) {
        fputs(f ? ", " : " ", fp);
        json_string(fp, framework_key((Framework)f));
        fputs(": [", fp);
        const char *cursor = NULL;
        char id[NA_MAX_CONTROL];
        for (int k = 0; rule_next_control(rule, (Framework)f, &cursor, id, sizeof(id)); k++) {
            if (k) fputs(", ", fp);
            json_string(fp, id);
        }
        fputc(']', fp);
    }
    fputs(" }\n", fp);
}

static void finding(FILE *fp, int indent, const Finding *f, bool last)
{
    fprintf(fp, "%*s{\n", indent, "");
    kv_str(fp, indent + 2, "rule_id",     f->rule->id, false);
    kv_str(fp, indent + 2, "severity",    severity_label(f->severity), false);
    kv_str(fp, indent + 2, "section",     f->section, false);
    kv_int(fp, indent + 2, "line",        f->line_number, false);
    kv_str(fp, indent + 2, "description", f->description, false);
    kv_str(fp, indent + 2, "remediation", f->remediation, false);
    frameworks(fp, indent + 2, f->rule);
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

void report_rule_catalogue_json(FILE *fp, const char *version)
{
    fputs("{\n", fp);
    kv_str(fp, 2, "version", version, false);
    fputs("  \"frameworks\": [\n", fp);
    for (int f = 0; f < FW_COUNT; f++) {
        fputs("    { \"key\": ", fp);
        json_string(fp, framework_key((Framework)f));
        fputs(", \"title\": ", fp);
        json_string(fp, framework_title((Framework)f));
        fputs(", \"label\": ", fp);
        json_string(fp, framework_label((Framework)f));
        fprintf(fp, " }%s\n", f + 1 < FW_COUNT ? "," : "");
    }
    fputs("  ],\n  \"rules\": [\n", fp);
    size_t n = rules_count();
    for (size_t i = 0; i < n; i++) {
        const Rule *r = rules_at(i);
        fputs("    {\n", fp);
        kv_str(fp, 6, "id",            r->id, false);
        kv_str(fp, 6, "severity",      severity_label(r->severity), false);
        kv_str(fp, 6, "category",      rule_category_title(r->category), false);
        kv_str(fp, 6, "category_code", rule_category_code(r->category), false);
        kv_str(fp, 6, "title",         r->title, false);
        kv_str(fp, 6, "description",   r->description, false);
        kv_str(fp, 6, "remediation",   r->remediation, false);
        frameworks(fp, 6, r);
        fprintf(fp, "    }%s\n", i + 1 < n ? "," : "");
    }
    fputs("  ]\n}\n", fp);
}

const ReportFormatOps REPORT_OPS_JSON = {
    .begin  = json_begin,
    .device = json_device,
    .end    = json_end,
};
