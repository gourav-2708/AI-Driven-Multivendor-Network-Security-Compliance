/**
 * @file engine.h
 * @brief Heuristic rule engine API.
 *
 * Adding a new rule:
 *   1. Write a CheckFn in rules_table.c (or a new .c file).
 *   2. Add a Rule entry to rules_table[] in rules_table.c. Done.
 */
#ifndef NET_AUDIT_ENGINE_H
#define NET_AUDIT_ENGINE_H

#include "model.h"

typedef bool (*CheckFn)(const DeviceModel *model,
                        struct AuditResult *result,
                        Finding *out);

typedef struct Rule {
    const char *rule_id;
    Severity    severity;
    const char *description;
    const char *remediation;
    CheckFn     check;
} Rule;

int         engine_run(const DeviceModel *model, AuditResult *out_result);
void        engine_add_finding(AuditResult *result, const Finding *f);
void        engine_compute_score(AuditResult *result);
const Rule *rules_get_table(int *count);

#endif /* NET_AUDIT_ENGINE_H */
