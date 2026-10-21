/**
 * @file audit.c
 * @brief The audit pipeline: detect -> parse -> evaluate -> report.
 *
 * One DeviceModel and one AuditResult are reused for every input file, and
 * each device is streamed to the report as soon as it is evaluated, so
 * memory use is constant regardless of how many files are audited.
 */
#include "netaudit/cli.h"
#include "netaudit/engine.h"
#include "netaudit/log.h"
#include "netaudit/parser.h"
#include "netaudit/platform.h"
#include "netaudit/report.h"
#include "netaudit/safe_str.h"

/* Large objects live in static storage, not on the stack. */
static DeviceModel   s_model;
static AuditResult   s_result;
static ReportSession s_report;

static void list_rules(FILE *fp)
{
    fprintf(fp, "%-11s %-9s %-15s %s\n", "RULE", "SEVERITY", "CATEGORY", "TITLE");
    for (size_t i = 0; i < rules_count(); i++) {
        const Rule *r = rules_at(i);
        fprintf(fp, "%-11s %-9s %-15s %s\n", r->id, severity_label(r->severity),
                rule_category_title(r->category), r->title);
    }
}

static void list_vendors(FILE *fp)
{
    for (int i = 0; i < parser_count(); i++) {
        const VendorParser *p = parser_at(i);
        fprintf(fp, "%-10s %s\n", p->name, p->display_name);
    }
}

/* Audit one file into s_result. */
static AuditStatus audit_file(const char *path, const VendorParser *forced)
{
    const VendorParser *parser = forced;
    if (!parser) {
        int confidence = 0;
        parser = parser_detect(path, &confidence);
        if (!parser) {
            LOG_ERR("'%s': could not detect the vendor (use --vendor)", path);
            return AUDIT_ERR_VENDOR;
        }
        LOG_INF("'%s': detected %s (confidence %d)", path,
                parser->display_name, confidence);
    }

    model_init(&s_model);
    AuditStatus rc = parser->parse(path, &s_model);
    if (rc != AUDIT_OK) {
        LOG_ERR("'%s': %s", path, audit_strerror(rc));
        return rc;
    }
    model_finalize(&s_model);
    if (s_model.overflow_count > 0)
        LOG_WRN("'%s': %d element(s) exceeded built-in limits and were ignored",
                path, s_model.overflow_count);

    return engine_run(&s_model, &s_result);
}

static bool want_color(const CliOptions *o, FILE *out)
{
    if (o->format != REPORT_TEXT || o->color == COLOR_NEVER) return false;
    if (o->color == COLOR_ALWAYS) return true;
    const char *no_color = getenv("NO_COLOR");     /* https://no-color.org */
    return platform_is_tty(out) && !(no_color && no_color[0]);
}

int audit_main(const CliOptions *o)
{
    log_set_level(o->log_level);
    parser_registry_init();

    switch (o->action) {
    case CLI_HELP:         cli_print_usage(stdout, "net-audit"); return EXIT_CLEAN;
    case CLI_VERSION:      printf("net-audit %s\n", NET_AUDIT_VERSION); return EXIT_CLEAN;
    case CLI_LIST_RULES:   list_rules(stdout);   return EXIT_CLEAN;
    case CLI_LIST_VENDORS: list_vendors(stdout); return EXIT_CLEAN;
    case CLI_RUN:          break;
    }

    if (o->input_count == 0) {
        fprintf(stderr, "error: no input files (see --help)\n");
        return EXIT_USAGE;
    }

    const VendorParser *forced = NULL;
    if (o->vendor[0]) {
        forced = parser_find(o->vendor);
        if (!forced) {
            fprintf(stderr, "error: unknown vendor '%s' (see --list-vendors)\n", o->vendor);
            return EXIT_USAGE;
        }
    }

    FILE *out = stdout;
    bool binary = o->format == REPORT_CSV;          /* exact CRLF rows */
    if (o->output_path[0]) {
        out = fopen(o->output_path, binary ? "wb" : "w");
        if (!out) {
            fprintf(stderr, "error: cannot open output file '%s': %s\n",
                    o->output_path, strerror(errno));
            return EXIT_USAGE;
        }
    } else if (binary) {
        platform_set_binary(stdout);
    }

    ReportOptions ropts = {
        .format       = o->format,
        .out          = out,
        .color        = want_color(o, out),
        .min_severity = o->min_severity,
    };
    if (ropts.color) platform_enable_ansi(out);

    report_begin(&s_report, &ropts, o->input_count > 1);

    int failed = 0;
    AuditStatus io = AUDIT_OK;
    for (int i = 0; i < o->input_count && io == AUDIT_OK; i++) {
        if (audit_file(o->inputs[i], forced) != AUDIT_OK) {
            failed++;
            continue;
        }
        io = report_device(&s_report, &s_result);
    }
    if (io == AUDIT_OK) io = report_end(&s_report);

    if (out != stdout && fclose(out) != 0 && io == AUDIT_OK) io = AUDIT_ERR_IO;
    if (io != AUDIT_OK) {
        fprintf(stderr, "error: failed writing the report: %s\n", audit_strerror(io));
        return EXIT_USAGE;
    }
    if (s_report.device_count == 0) {
        fprintf(stderr, "Error: no files were successfully audited.\n");
        return EXIT_USAGE;
    }
    if (failed > 0) {
        LOG_WRN("%d of %d input(s) could not be audited", failed, o->input_count);
        return EXIT_PARTIAL;
    }
    if (o->exit_zero) return EXIT_CLEAN;
    return report_visible_findings(&s_report) > 0 ? EXIT_FINDINGS : EXIT_CLEAN;
}
