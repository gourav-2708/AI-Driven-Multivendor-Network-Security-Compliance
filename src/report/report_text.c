/**
 * @file report_text.c
 * @brief Human-readable plain-text (ANSI colour) compliance report formatter.
 */

#include <stdio.h>
#include <string.h>
#include "report.h"
#include "model.h"
#include "common.h"

#define RESET  "\033[0m"
#define BOLD   "\033[1m"
#define GREEN  "\033[0;32m"
#define CYAN   "\033[0;36m"
#define WHITE  "\033[1;37m"

static const char *clr(const ReportOptions *o, const char *code)
{
    return o->color ? code : "";
}

static void print_rule(char rule, FILE *fp,
                       const ReportOptions *o)
{
    fprintf(fp, "%s%c%s", clr(o,CYAN), rule, clr(o,RESET));
    for (int i = 0; i < 74; i++) fputc(rule, fp);
    fprintf(fp, "%s%c%s\n", clr(o,CYAN), rule, clr(o,RESET));
}

static void print_header(const char *title, FILE *fp, const ReportOptions *o)
{
    print_rule('=', fp, o);
    fprintf(fp, "  %s%s%s\n", clr(o,BOLD), title, clr(o,RESET));
    print_rule('=', fp, o);
}

static void print_section(const char *title, FILE *fp, const ReportOptions *o)
{
    fprintf(fp, "\n%s-- %s --%s\n", clr(o,CYAN), title, clr(o,RESET));
}

static const char *pass_fail(bool pass)
{
    if (pass) return "\033[0;32mPASS\033[0m";
    return "\033[0;31mFAIL\033[0m";
}

int report_text_device(const AuditResult *r, const ReportOptions *o)
{
    FILE *fp = o->output ? o->output : stdout;
    const DeviceModel *d = r->device;

    /* -- Device header ---------------------------------------------------- */
    print_header("NET-AUDIT COMPLIANCE REPORT", fp, o);
    fprintf(fp, "  Device  : %s%s%s\n", clr(o,WHITE), d->hostname[0] ? d->hostname : "(unknown)", clr(o,RESET));
    fprintf(fp, "  Vendor  : %s\n", d->vendor);
    fprintf(fp, "  Version : %s\n", d->os_version[0] ? d->os_version : "n/a");
    fprintf(fp, "  Source  : %s\n", d->source_file);
    print_rule('-', fp, o);

    /* -- Score ------------------------------------------------------------ */
    const char *score_color = (r->score >= 80) ? GREEN :
                              (r->score >= 50) ? "\033[0;33m" : "\033[0;31m";
    fprintf(fp, "  Compliance Score : %s%d / 100%s\n",
            clr(o, score_color), r->score, clr(o,RESET));
    fprintf(fp, "  Total Findings   : %d  "
            "(Critical:%d  High:%d  Medium:%d  Low:%d)\n",
            r->finding_count,
            r->sev_counts[SEV_CRITICAL], r->sev_counts[SEV_HIGH],
            r->sev_counts[SEV_MEDIUM],   r->sev_counts[SEV_LOW]);

    /* -- Category summary ------------------------------------------------- */
    print_section("Policy Category Summary", fp, o);

    typedef struct { const char *name; const char *prefixes[4]; } Cat;
    Cat categories[] = {
        { "Authentication (AUTH)",    {"AUTH-", NULL, NULL, NULL} },
        { "Passwords (PASSWD)",       {"PASSWD-", NULL, NULL, NULL} },
        { "Access Control (ACL)",     {"ACL-", NULL, NULL, NULL} },
        { "SNMP",                     {"SNMP-", NULL, NULL, NULL} },
        { "Services (SVC)",           {"SVC-", NULL, NULL, NULL} },
        { "Logging (LOG)",            {"LOG-", NULL, NULL, NULL} },
        { "NTP",                      {"NTP-", NULL, NULL, NULL} },
        { "Interfaces (INTF)",        {"INTF-", NULL, NULL, NULL} },
    };
    int ncat = (int)(sizeof(categories)/sizeof(categories[0]));

    for (int c = 0; c < ncat; c++) {
        bool has_finding = false;
        for (int i = 0; i < r->finding_count; i++) {
            if (str_starts_with(r->findings[i].rule_id, categories[c].prefixes[0])) {
                has_finding = true; break;
            }
        }
        const char *pf = o->color ? pass_fail(!has_finding) :
                         (has_finding ? "FAIL" : "PASS");
        fprintf(fp, "  %-35s %s\n", categories[c].name, pf);
    }

    /* -- Findings --------------------------------------------------------- */
    if (r->finding_count == 0) {
        print_section("Findings", fp, o);
        fprintf(fp, "  %sNo findings. Device is fully compliant.%s\n",
                clr(o,GREEN), clr(o,RESET));
    } else {
        print_section("Findings", fp, o);
        int shown = 0;
        for (int i = 0; i < r->finding_count; i++) {
            const Finding *f = &r->findings[i];
            if (f->severity > o->min_severity) continue;
            shown++;
            fprintf(fp, "\n  %s[%s]%s %s%s%s (%s)\n",
                    clr(o, SEVERITY_COLORS[f->severity]), f->rule_id,
                    clr(o,RESET),
                    clr(o, SEVERITY_COLORS[f->severity]), f->description,
                    clr(o,RESET),
                    SEVERITY_LABELS[f->severity]);
            fprintf(fp, "  Section     : %s\n", f->affected_section);
            fprintf(fp, "  Remediation : %s\n", f->remediation);
        }
        if (shown == 0)
            fprintf(fp, "  (All findings filtered by minimum severity)\n");
    }

    print_rule('=', fp, o);
    fputc('\n', fp);
    return AUDIT_OK;
}

int report_text_aggregate(const AuditResult **rs, int n,
                          const ReportOptions *o)
{
    FILE *fp = o->output ? o->output : stdout;

    print_header("NET-AUDIT AGGREGATE COMPLIANCE SUMMARY", fp, o);
    fprintf(fp, "  Devices audited: %d\n", n);

    int total_findings = 0, total_score = 0;
    int total_sev[SEV_COUNT] = {0};

    for (int i = 0; i < n; i++) {
        total_findings += rs[i]->finding_count;
        total_score    += rs[i]->score;
        for (int s = 0; s < SEV_COUNT; s++)
            total_sev[s] += rs[i]->sev_counts[s];
    }

    int avg_score = (n > 0) ? total_score / n : 0;
    const char *score_color = (avg_score >= 80) ? GREEN :
                              (avg_score >= 50) ? "\033[0;33m" : "\033[0;31m";
    fprintf(fp, "  Fleet Compliance Score (avg): %s%d / 100%s\n",
            clr(o,score_color), avg_score, clr(o,RESET));
    fprintf(fp, "  Total Findings: %d  "
            "(Critical:%d  High:%d  Medium:%d  Low:%d)\n",
            total_findings,
            total_sev[SEV_CRITICAL], total_sev[SEV_HIGH],
            total_sev[SEV_MEDIUM],   total_sev[SEV_LOW]);

    print_section("Per-Device Summary", fp, o);
    fprintf(fp, "  %-30s %6s  %8s  %4s  %4s  %6s  %3s\n",
            "Hostname", "Vendor", "Score", "CRIT", "HIGH", "MED", "LOW");
    print_rule('-', fp, o);

    for (int i = 0; i < n; i++) {
        const AuditResult *r = rs[i];
        const char *sc = (r->score >= 80) ? GREEN :
                         (r->score >= 50) ? "\033[0;33m" : "\033[0;31m";
        fprintf(fp, "  %-30s %-8s %s%3d/100%s  %4d  %4d  %6d  %3d\n",
                r->device->hostname[0] ? r->device->hostname : "(unknown)",
                r->device->vendor,
                clr(o,sc), r->score, clr(o,RESET),
                r->sev_counts[SEV_CRITICAL], r->sev_counts[SEV_HIGH],
                r->sev_counts[SEV_MEDIUM],   r->sev_counts[SEV_LOW]);
    }

    print_rule('=', fp, o);
    fputc('\n', fp);
    return AUDIT_OK;
}

