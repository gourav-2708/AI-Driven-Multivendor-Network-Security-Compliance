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

struct FindingSink;

typedef struct Rule {
    const char  *id;            /* "AUTH-001"                            */
    RuleCategory category;
    Severity     severity;      /* default severity of a finding         */
    const char  *title;         /* one-line summary for rule listings    */
    const char  *description;   /* finding text shown in reports         */
    const char  *remediation;   /* how to fix it                          */
    void       (*check)(const DeviceModel *m, struct FindingSink *sink);
} Rule;

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
