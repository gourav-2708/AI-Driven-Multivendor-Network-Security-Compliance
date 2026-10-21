/**
 * @file cli.h
 * @brief Command-line parsing and the audit pipeline entry point.
 */
#ifndef NETAUDIT_CLI_H
#define NETAUDIT_CLI_H

#include <stdbool.h>
#include <stdio.h>
#include "netaudit/bounds.h"
#include "netaudit/log.h"
#include "netaudit/report.h"
#include "netaudit/severity.h"
#include "netaudit/status.h"

#define NET_AUDIT_VERSION "2.0.0"

/** Process exit codes (also documented in --help and README). */
enum {
    EXIT_CLEAN    = 0,  /* every input audited, no finding at/above --severity */
    EXIT_FINDINGS = 1,  /* every input audited, findings reported              */
    EXIT_USAGE    = 2,  /* bad options, unreadable output, nothing audited     */
    EXIT_PARTIAL  = 3   /* some inputs could not be audited                    */
};

typedef enum {
    CLI_RUN = 0,
    CLI_HELP,
    CLI_VERSION,
    CLI_LIST_RULES,
    CLI_LIST_VENDORS
} CliAction;

typedef enum { COLOR_AUTO = 0, COLOR_NEVER, COLOR_ALWAYS } ColorMode;

typedef struct {
    CliAction    action;
    char         vendor[NA_MAX_VENDOR];     /* "" = auto-detect          */
    ReportFormat format;
    char         output_path[NA_MAX_PATH];  /* "" = stdout               */
    Severity     min_severity;
    ColorMode    color;
    LogLevel     log_level;
    bool         exit_zero;                 /* findings do not set exit 1 */
    char         inputs[NA_MAX_INPUT_FILES][NA_MAX_PATH];
    int          input_count;
} CliOptions;

/**
 * Parse argv into @p out. Prints a diagnostic to @p err on failure.
 * Directories given with --dir are expanded into @p out->inputs here.
 */
AuditStatus cli_parse(int argc, char **argv, CliOptions *out, FILE *err);

void cli_print_usage(FILE *fp, const char *prog);

/** Run the action selected in @p opts; returns a process exit code. */
int audit_main(const CliOptions *opts);

#endif /* NETAUDIT_CLI_H */
