/**
 * @file rule_engine.c
 * @brief Heuristic rule engine � iterates the rules table and evaluates
 *        each rule against a normalised DeviceModel.
 */

#include <string.h>
#include "engine.h"
#include "model.h"
#include "common.h"

/**
 * @brief Add a single Finding to an AuditResult (bounds-checked).
 */
void engine_add_finding(AuditResult *result, const Finding *f)
{
    if (!result || !f) return;
    if (result->finding_count >= MAX_FINDINGS) {
        LOG_WRN("engine_add_finding: MAX_FINDINGS (%d) reached; dropping finding %s",
                MAX_FINDINGS, f->rule_id);
        return;
    }
    result->findings[result->finding_count++] = *f;
    result->sev_counts[f->severity]++;
}

/**
 * @brief Compute compliance score from accumulated sev_counts.
 *
 * Uses a proportional per-category penalty capped per severity level so a
 * single very bad category cannot collapse the entire score to zero.
 *
 * Per-category contribution (each capped at its max_cap):
 *   Critical : each finding costs 15 pts, capped at 60  (>=4 crits => -60)
 *   High     : each finding costs  8 pts, capped at 24  (>=3 high  => -24)
 *   Medium   : each finding costs  4 pts, capped at 12  (>=3 med   => -12)
 *   Low      : each finding costs  1 pt,  capped at  4  (>=4 low   =>  -4)
 *
 * Total max deduction = 100, so a perfect disaster = score 0.
 * But typical real configs with 4C/4H/2M/2L get ~20-30, not 0.
 */
void engine_compute_score(AuditResult *result)
{
    if (!result) return;
    /* {cost_per_finding, max_cap} indexed by severity (CRITICAL=0..LOW=3) */
    static const int cost[4] = {15, 8, 4, 1};
    static const int cap[4]  = {60, 24, 12, 4};
    int deduction = 0;
    for (int s = 0; s < SEV_COUNT; s++) {
        int contrib = cost[s] * result->sev_counts[s];
        if (contrib > cap[s]) contrib = cap[s];
        deduction += contrib;
    }
    result->score = (deduction >= 100) ? 0 : (100 - deduction);
}

/**
 * @brief Run all rules against @p model and populate @p out_result.
 */
int engine_run(const DeviceModel *model, AuditResult *out_result)
{
    if (!model || !out_result) {
        LOG_ERR("engine_run: NULL argument");
        return AUDIT_ERR_ARG;
    }

    int rule_count = 0;
    const Rule *rules = rules_get_table(&rule_count);

    LOG_INF("engine_run: evaluating %d rules against '%s' (%s)",
            rule_count, model->hostname, model->vendor);

    for (int i = 0; i < rule_count; i++) {
        const Rule *rule = &rules[i];
        if (!rule->check) continue;

        Finding f;
        memset(&f, 0, sizeof(f));

        bool violated = rule->check(model, out_result, &f);
        if (violated) {
            /* Ensure rule_id and severity from the table if not set by check fn */
            if (f.rule_id[0] == '\0')
                safe_strncpy(f.rule_id, rule->rule_id, MAX_RULE_ID_LEN);
            if (f.severity == 0 && rule->severity != 0)
                f.severity = rule->severity;
            engine_add_finding(out_result, &f);
        }
    }

    engine_compute_score(out_result);

    LOG_INF("engine_run: %d findings, compliance score: %d/100",
            out_result->finding_count, out_result->score);

    return AUDIT_OK;
}
