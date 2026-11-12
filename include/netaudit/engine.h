/**
 * @file engine.h
 * @brief Deterministic heuristic rule engine.
 *
 * A Rule is static data (id, category, severity, wording) plus a check
 * function. The check inspects a DeviceModel and calls finding_report*()
 * once for every violation it sees - zero, one or many times. Rule
 * metadata is the single source of the text that ends up in reports.
 *
 * Rules live in src/engine/rules_<category>.c. Adding a rule means adding
 * one entry (and its check function) to the matching file.
 */
#ifndef NETAUDIT_ENGINE_H
#define NETAUDIT_ENGINE_H

#include <stddef.h>
#include "netaudit/bounds.h"
#include "netaudit/compiler.h"
#include "netaudit/model.h"
#include "netaudit/severity.h"
#include "netaudit/status.h"

typedef enum {
    CAT_AUTH = 0,
    CAT_PASSWD,
    CAT_ACL,
    CAT_SNMP,
    CAT_SVC,
    CAT_LOG,
    CAT_NTP,
    CAT_INTF,
    CAT_COUNT
} RuleCategory;

/** "AUTH", "PASSWD", ... */
const char *rule_category_code(RuleCategory c);
/** "Authentication", "Passwords", ... */
const char *rule_category_title(RuleCategory c);

/* -- Compliance frameworks ----------------------------------------------------
 * Every rule names the controls it gives evidence for in each framework.
 * Control lists are comma-separated ("AC-17(2), SC-8"); "" means the rule
 * maps to nothing in that framework. The mapping is carried into the JSON
 * report and the rule catalogue, so front-ends never keep their own copy. */
typedef enum {
    FW_CIS = 0,     /* CIS Critical Security Controls v8 (safeguards)   */
    FW_PCI,         /* PCI DSS v4.0 (requirements)                      */
    FW_ISO,         /* ISO/IEC 27001:2022 Annex A (controls)            */
    FW_NIST,        /* NIST SP 800-53 Rev. 5 (controls)                 */
    FW_COUNT
} Framework;

/** Stable JSON key: "cis_v8", "pci_dss_4", "iso_27001_2022", "nist_800_53_r5". */
const char *framework_key(Framework f);
/** Display name, e.g. "PCI DSS v4.0". */
const char *framework_title(Framework f);
/** Short label for one-line listings, e.g. "PCI". */
const char *framework_label(Framework f);

struct FindingSink;

typedef struct Rule {
    const char  *id;            /* "AUTH-001"                            */
    RuleCategory category;
    Severity     severity;      /* default severity of a finding         */
    const char  *title;         /* one-line summary for rule listings    */
    const char  *description;   /* finding text shown in reports         */
    const char  *remediation;   /* how to fix it                          */
    void       (*check)(const DeviceModel *m, struct FindingSink *sink);
    const char  *controls[FW_COUNT];   /* framework mapping, see Framework */
} Rule;

/**
 * Iterate the controls a rule maps to in one framework.
 * Start with *cursor = NULL; each call copies the next control id into
 * @p out and returns true, or returns false when the list is exhausted.
 */
bool rule_next_control(const Rule *r, Framework f, const char **cursor,
                       char *out, size_t out_size);

/** One violation. Text pointers reference static rule data. */
typedef struct {
    const Rule *rule;
    Severity    severity;
    const char *description;
    const char *remediation;
    char        section[NA_MAX_SECTION];   /* where in the config        */
    int         line_number;               /* -1 when not attributable   */
} Finding;

typedef struct AuditResult {
    const DeviceModel *device;
    Finding            findings[NA_MAX_FINDINGS];
    int                finding_count;
    int                dropped_findings;   /* exceeded NA_MAX_FINDINGS    */
    int                sev_counts[SEV_COUNT];
    int                score;              /* 0..100, 100 = no findings   */
} AuditResult;

/** Passed to check functions; collects findings for the current rule. */
typedef struct FindingSink {
    AuditResult *result;
    const Rule  *rule;
} FindingSink;

/** Report a violation using the rule's default severity and wording. */
void finding_report(FindingSink *sink, int line_number,
                    const char *section_fmt, ...) NA_PRINTF(3, 4);

/** Report a violation with severity/wording that differ from the default. */
void finding_report_variant(FindingSink *sink, Severity severity,
                            const char *description, const char *remediation,
                            int line_number, const char *section_fmt, ...)
     NA_PRINTF(6, 7);

/* -- Rule registry ---------------------------------------------------------- */
size_t      rules_count(void);
const Rule *rules_at(size_t index);
const Rule *rules_find(const char *id);

/* -- Engine ------------------------------------------------------------------ */
/** Evaluate every rule against @p model into a freshly reset @p out. */
AuditStatus engine_run(const DeviceModel *model, AuditResult *out);

/* -- Scoring ------------------------------------------------------------------ */
/**
 * Compliance score: 100 minus a per-severity penalty, where each severity's
 * contribution is capped so one noisy category cannot zero the score alone.
 *     CRITICAL 15/finding (cap 60)   HIGH 8 (cap 24)
 *     MEDIUM    4/finding (cap 12)   LOW  1 (cap  4)
 */
int  score_compute(const int sev_counts[SEV_COUNT]);
void score_penalty(Severity s, int *per_finding, int *cap);

#endif /* NETAUDIT_ENGINE_H */
