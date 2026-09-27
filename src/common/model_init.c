/**
 * @file model_init.c
 * @brief DeviceModel and AuditResult initialisation helpers,
 *        and severity metadata tables.
 */

#include <string.h>
#include "model.h"

/* -- Severity metadata tables ---------------------------------------------- */

const char *const SEVERITY_LABELS[SEV_COUNT] = {
    "CRITICAL", "HIGH", "MEDIUM", "LOW"
};

/** ANSI escape sequences; reset with \033[0m */
const char *const SEVERITY_COLORS[SEV_COUNT] = {
    "\033[1;31m",   /* CRITICAL — bold red    */
    "\033[0;31m",   /* HIGH     — red         */
    "\033[0;33m",   /* MEDIUM   — yellow      */
    "\033[0;34m"    /* LOW      — blue        */
};

/** Compliance-score deduction per finding at each severity. */
const int SEVERITY_WEIGHTS[SEV_COUNT] = {
    40,   /* CRITICAL */
    20,   /* HIGH     */
    10,   /* MEDIUM   */
     5    /* LOW      */
};

/* -- Initialisation -------------------------------------------------------- */

/**
 * @brief Zero-initialise a DeviceModel to safe defaults.
 */
void model_init(DeviceModel *m)
{
    if (!m) return;
    memset(m, 0, sizeof(*m));
    /* ssh_version = 0 means "not configured" */
}

/**
 * @brief Zero-initialise an AuditResult and bind it to a device model.
 */
void result_init(AuditResult *r, DeviceModel *device)
{
    if (!r) return;
    memset(r, 0, sizeof(*r));
    r->device = device;
    r->score  = 100;
}
