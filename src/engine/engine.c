/**
 * @file engine.c
 * @brief Rule evaluation loop, finding collection and scoring.
 */
#include "netaudit/engine.h"
#include "netaudit/log.h"
#include "netaudit/safe_str.h"

/* -- Categories ------------------------------------------------------------- */

static const struct { const char *code; const char *title; } k_categories[CAT_COUNT] = {
    [CAT_AUTH]   = { "AUTH",   "Authentication" },
    [CAT_PASSWD] = { "PASSWD", "Passwords"      },
    [CAT_ACL]    = { "ACL",    "Access Control" },
    [CAT_SNMP]   = { "SNMP",   "SNMP"           },
    [CAT_SVC]    = { "SVC",    "Services"       },
    [CAT_LOG]    = { "LOG",    "Logging"        },
    [CAT_NTP]    = { "NTP",    "Time Sync"      },
    [CAT_INTF]   = { "INTF",   "Interfaces"     },
};

const char *rule_category_code(RuleCategory c)
{
    return (unsigned)c < CAT_COUNT ? k_categories[c].code : "?";
}

const char *rule_category_title(RuleCategory c)
{
    return (unsigned)c < CAT_COUNT ? k_categories[c].title : "?";
}

/* -- Findings ---------------------------------------------------------------- */

static void add_finding(FindingSink *sink, Severity sev, const char *desc,
                        const char *rem, int line, const char *fmt, va_list ap)
{
    AuditResult *r = sink->result;
    if (r->finding_count >= NA_MAX_FINDINGS) {
        r->dropped_findings++;
        return;
    }
    Finding *f = &r->findings[r->finding_count++];
    f->rule        = sink->rule;
    f->severity    = sev;
    f->description = desc;
    f->remediation = rem;
    f->line_number = line;
    safe_vsnprintf(f->section, sizeof(f->section), fmt, ap);
    r->sev_counts[sev]++;
}

void finding_report(FindingSink *sink, int line, const char *fmt, ...)
{
    const Rule *rule = sink->rule;
    va_list ap;
    va_start(ap, fmt);
    add_finding(sink, rule->severity, rule->description, rule->remediation,
                line, fmt, ap);
    va_end(ap);
}

void finding_report_variant(FindingSink *sink, Severity sev, const char *desc,
                            const char *rem, int line, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    add_finding(sink, sev,
                desc ? desc : sink->rule->description,
                rem  ? rem  : sink->rule->remediation,
                line, fmt, ap);
    va_end(ap);
}

/* -- Engine ------------------------------------------------------------------- */

AuditStatus engine_run(const DeviceModel *model, AuditResult *out)
{
    if (!model || !out) return AUDIT_ERR_ARG;

    memset(out, 0, sizeof(*out));
    out->device = model;

    FindingSink sink = { .result = out };
    for (size_t i = 0; i < rules_count(); i++) {
        sink.rule = rules_at(i);
        sink.rule->check(model, &sink);
    }
    out->score = score_compute(out->sev_counts);

    if (out->dropped_findings > 0)
        LOG_WRN("%s: %d finding(s) beyond the limit of %d were dropped",
                model->source_file, out->dropped_findings, NA_MAX_FINDINGS);
    LOG_INF("%s: %d finding(s), score %d/100",
            model_hostname(model), out->finding_count, out->score);
    return AUDIT_OK;
}

/* -- Scoring ------------------------------------------------------------------- */

static const struct { int per_finding; int cap; } k_penalty[SEV_COUNT] = {
    [SEV_CRITICAL] = { 15, 60 },
    [SEV_HIGH]     = {  8, 24 },
    [SEV_MEDIUM]   = {  4, 12 },
    [SEV_LOW]      = {  1,  4 },
};

void score_penalty(Severity s, int *per_finding, int *cap)
{
    if ((unsigned)s >= SEV_COUNT) s = SEV_LOW;
    if (per_finding) *per_finding = k_penalty[s].per_finding;
    if (cap)         *cap = k_penalty[s].cap;
}

int score_compute(const int sev_counts[SEV_COUNT])
{
    int deduction = 0;
    for (int s = 0; s < SEV_COUNT; s++) {
        int d = k_penalty[s].per_finding * sev_counts[s];
        deduction += d < k_penalty[s].cap ? d : k_penalty[s].cap;
    }
    return deduction >= 100 ? 0 : 100 - deduction;
}
