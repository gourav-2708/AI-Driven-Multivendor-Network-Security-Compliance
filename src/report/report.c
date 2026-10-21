/**
 * @file report.c
 * @brief Report session: format dispatch and fleet bookkeeping.
 */
#include "netaudit/safe_str.h"
#include "report_internal.h"

static const struct {
    const char            *name;
    ReportFormat           format;
    const ReportFormatOps *ops;
} k_formats[] = {
    { "text", REPORT_TEXT, &REPORT_OPS_TEXT },
    { "txt",  REPORT_TEXT, &REPORT_OPS_TEXT },
    { "csv",  REPORT_CSV,  &REPORT_OPS_CSV  },
    { "json", REPORT_JSON, &REPORT_OPS_JSON },
};

bool report_format_parse(const char *name, ReportFormat *out)
{
    for (size_t i = 0; name && out && i < NA_ARRAY_LEN(k_formats); i++) {
        if (str_eq_ci(name, k_formats[i].name)) {
            *out = k_formats[i].format;
            return true;
        }
    }
    return false;
}

const char *report_format_name(ReportFormat f)
{
    for (size_t i = 0; i < NA_ARRAY_LEN(k_formats); i++)
        if (k_formats[i].format == f) return k_formats[i].name;
    return "text";
}

static const ReportFormatOps *ops_for(ReportFormat f)
{
    for (size_t i = 0; i < NA_ARRAY_LEN(k_formats); i++)
        if (k_formats[i].format == f) return k_formats[i].ops;
    return &REPORT_OPS_TEXT;
}

AuditStatus report_begin(ReportSession *s, const ReportOptions *opts, bool fleet)
{
    if (!s || !opts || !opts->out) return AUDIT_ERR_ARG;
    memset(s, 0, sizeof(*s));
    s->opts  = *opts;
    s->ops   = ops_for(opts->format);
    s->fleet = fleet;
    return AUDIT_OK;
}

AuditStatus report_device(ReportSession *s, const AuditResult *r)
{
    if (!s || !r || !r->device) return AUDIT_ERR_ARG;
    if (!s->fleet && s->device_count > 0) return AUDIT_ERR_LIMIT;
    if (s->device_count >= NA_MAX_INPUT_FILES) return AUDIT_ERR_LIMIT;

    DeviceSummary *d = &s->devices[s->device_count];
    safe_strcpy(d->hostname, sizeof(d->hostname), model_hostname(r->device));
    safe_strcpy(d->vendor, sizeof(d->vendor), r->device->vendor);
    d->score = r->score;
    for (int i = 0; i < SEV_COUNT; i++) {
        d->sev_counts[i] = r->sev_counts[i];
        s->sev_totals[i] += r->sev_counts[i];
    }
    s->score_sum     += r->score;
    s->finding_total += r->finding_count;
    s->visible_total += report_count_shown(s, r);

    if (!s->started) {
        s->started = true;
        if (s->ops->begin) s->ops->begin(s);
    }
    s->ops->device(s, r, s->device_count);
    s->device_count++;
    return ferror(s->opts.out) ? AUDIT_ERR_IO : AUDIT_OK;
}

AuditStatus report_end(ReportSession *s)
{
    if (!s) return AUDIT_ERR_ARG;
    if (s->started && s->ops->end) s->ops->end(s);
    if (fflush(s->opts.out) != 0 || ferror(s->opts.out)) return AUDIT_ERR_IO;
    return AUDIT_OK;
}

int report_visible_findings(const ReportSession *s)
{
    return s ? s->visible_total : 0;
}

int report_count_shown(const ReportSession *s, const AuditResult *r)
{
    int n = 0;
    for (int i = 0; i < r->finding_count; i++)
        if (report_shows(s, &r->findings[i])) n++;
    return n;
}

int report_average_score(const ReportSession *s)
{
    return s->device_count > 0 ? s->score_sum / s->device_count : 0;
}
