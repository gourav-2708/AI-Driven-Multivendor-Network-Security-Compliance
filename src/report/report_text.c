/**
 * @file report_text.c
 * @brief Human-readable report with optional ANSI colour.
 */
#include "netaudit/safe_str.h"
#include "report_internal.h"

#define RULE_WIDTH 76

#define C_RESET  "\033[0m"
#define C_BOLD   "\033[1m"
#define C_GREEN  "\033[0;32m"
#define C_YELLOW "\033[0;33m"
#define C_RED    "\033[0;31m"
#define C_CYAN   "\033[0;36m"
#define C_WHITE  "\033[1;37m"

static const char *clr(const ReportSession *s, const char *code)
{
    return s->opts.color ? code : "";
}

static const char *score_color(int score)
{
    return score >= 80 ? C_GREEN : score >= 50 ? C_YELLOW : C_RED;
}

static void hr(const ReportSession *s, char ch)
{
    FILE *fp = s->opts.out;
    fputs(clr(s, C_CYAN), fp);
    for (int i = 0; i < RULE_WIDTH; i++) fputc(ch, fp);
    fputs(clr(s, C_RESET), fp);
    fputc('\n', fp);
}

static void banner(const ReportSession *s, const char *title)
{
    hr(s, '=');
    fprintf(s->opts.out, "  %s%s%s\n", clr(s, C_BOLD), title, clr(s, C_RESET));
    hr(s, '=');
}

static void heading(const ReportSession *s, const char *title)
{
    fprintf(s->opts.out, "\n%s-- %s --%s\n", clr(s, C_CYAN), title, clr(s, C_RESET));
}

static void category_summary(const ReportSession *s, const AuditResult *r)
{
    heading(s, "Policy Category Summary");
    for (int c = 0; c < CAT_COUNT; c++) {
        bool failed = false;
        for (int i = 0; i < r->finding_count && !failed; i++)
            failed = r->findings[i].rule->category == (RuleCategory)c;

        const char *title = rule_category_title((RuleCategory)c);
        const char *code  = rule_category_code((RuleCategory)c);
        char name[48];
        if (str_eq_ci(title, code))
            safe_strcpy(name, sizeof(name), title);
        else
            safe_snprintf(name, sizeof(name), "%s (%s)", title, code);
        fprintf(s->opts.out, "  %-35s %s%s%s\n", name,
                clr(s, failed ? C_RED : C_GREEN), failed ? "FAIL" : "PASS",
                clr(s, C_RESET));
    }
}

static void findings(const ReportSession *s, const AuditResult *r)
{
    FILE *fp = s->opts.out;
    heading(s, "Findings");
    if (r->finding_count == 0) {
        fprintf(fp, "  %sNo findings. Device is fully compliant.%s\n",
                clr(s, C_GREEN), clr(s, C_RESET));
        return;
    }
    int shown = 0;
    for (int i = 0; i < r->finding_count; i++) {
        const Finding *f = &r->findings[i];
        if (!report_shows(s, f)) continue;
        shown++;
        const char *sev = clr(s, severity_ansi(f->severity));
        fprintf(fp, "\n  %s[%s] %s%s (%s)\n", sev, f->rule->id, f->description,
                clr(s, C_RESET), severity_label(f->severity));
        fprintf(fp, "  Section     : %s\n", f->section);
        fprintf(fp, "  Remediation : %s\n", f->remediation);
    }
    if (shown == 0)
        fprintf(fp, "  (all findings are below the minimum severity)\n");
}

static void text_device(ReportSession *s, const AuditResult *r, int index)
{
    FILE *fp = s->opts.out;
    const DeviceModel *d = r->device;
    (void)index;

    banner(s, "NET-AUDIT COMPLIANCE REPORT");
    fprintf(fp, "  Device  : %s%s%s\n", clr(s, C_WHITE), model_hostname(d), clr(s, C_RESET));
    fprintf(fp, "  Vendor  : %s\n", d->vendor);
    fprintf(fp, "  Version : %s\n", d->os_version[0] ? d->os_version : "n/a");
    fprintf(fp, "  Source  : %s\n", d->source_file);
    hr(s, '-');
    fprintf(fp, "  Compliance Score : %s%d / 100%s\n",
            clr(s, score_color(r->score)), r->score, clr(s, C_RESET));
    fprintf(fp, "  Total Findings   : %d  (Critical:%d  High:%d  Medium:%d  Low:%d)\n",
            r->finding_count, r->sev_counts[SEV_CRITICAL], r->sev_counts[SEV_HIGH],
            r->sev_counts[SEV_MEDIUM], r->sev_counts[SEV_LOW]);

    category_summary(s, r);
    findings(s, r);
    hr(s, '=');
    fputc('\n', fp);
}

static void text_end(ReportSession *s)
{
    if (!s->fleet) return;
    FILE *fp = s->opts.out;
    int avg = report_average_score(s);

    banner(s, "NET-AUDIT FLEET SUMMARY");
    fprintf(fp, "  Devices audited             : %d\n", s->device_count);
    fprintf(fp, "  Fleet Compliance Score (avg): %s%d / 100%s\n",
            clr(s, score_color(avg)), avg, clr(s, C_RESET));
    fprintf(fp, "  Total Findings              : %d  (Critical:%d  High:%d  Medium:%d  Low:%d)\n",
            s->finding_total, s->sev_totals[SEV_CRITICAL], s->sev_totals[SEV_HIGH],
            s->sev_totals[SEV_MEDIUM], s->sev_totals[SEV_LOW]);

    heading(s, "Per-Device Summary");
    fprintf(fp, "  %-30s %-9s %7s  %4s  %4s  %4s  %4s\n",
            "Hostname", "Vendor", "Score", "CRIT", "HIGH", "MED", "LOW");
    hr(s, '-');
    for (int i = 0; i < s->device_count; i++) {
        const DeviceSummary *d = &s->devices[i];
        fprintf(fp, "  %-30s %-9s %s%3d/100%s  %4d  %4d  %4d  %4d\n",
                d->hostname, d->vendor, clr(s, score_color(d->score)), d->score,
                clr(s, C_RESET), d->sev_counts[SEV_CRITICAL], d->sev_counts[SEV_HIGH],
                d->sev_counts[SEV_MEDIUM], d->sev_counts[SEV_LOW]);
    }
    hr(s, '=');
    fputc('\n', fp);
}

const ReportFormatOps REPORT_OPS_TEXT = {
    .begin  = NULL,
    .device = text_device,
    .end    = text_end,
};
