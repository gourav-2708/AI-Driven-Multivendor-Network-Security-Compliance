/**
 * @file cli.c
 * @brief Command-line option parsing.
 *
 * Accepts "--opt value" and "--opt=value". Everything not starting with
 * '-' is an input file; "--" ends option parsing.
 */
#include "netaudit/cli.h"
#include "netaudit/platform.h"
#include "netaudit/safe_str.h"

void cli_print_usage(FILE *fp, const char *prog)
{
    fprintf(fp,
        "net-audit %s - multi-vendor network security compliance auditor\n"
        "\n"
        "Usage: %s [OPTIONS] <config-file>...\n"
        "       %s [OPTIONS] --dir <directory>\n"
        "\n"
        "Options:\n"
        "  -v, --vendor <name>        Force vendor (cisco, juniper, fortinet);\n"
        "                             default: auto-detect per file\n"
        "  -f, --format <fmt>         text (default), csv or json\n"
        "  -o, --output <file>        Write the report to a file instead of stdout\n"
        "  -d, --dir <directory>      Audit every .cfg/.conf/.txt file in a directory\n"
        "  -s, --severity <level>     Report findings at or above: critical, high,\n"
        "                             medium, low (default: low)\n"
        "      --color, --no-color    Force/disable ANSI colour (default: if a terminal)\n"
        "      --verbose              Debug logging on stderr\n"
        "  -q, --quiet                Errors only on stderr\n"
        "      --list-rules           Print the rule catalogue and exit\n"
        "      --list-vendors         Print supported vendors and exit\n"
        "  -V, --version              Print version and exit\n"
        "  -h, --help                 Show this help\n"
        "\n"
        "Exit status:\n"
        "  0  all inputs audited, no findings at or above --severity\n"
        "  1  all inputs audited, findings reported\n"
        "  2  usage error, unwritable output, or no input could be audited\n"
        "  3  some inputs could not be audited\n",
        NET_AUDIT_VERSION, prog, prog);
}

/* Match argv[*i] against a short/long option that takes a value.
 * Supports "--long value", "--long=value" and "-s value". */
static bool take_value(int argc, char **argv, int *i, const char *shrt,
                       const char *lng, const char **value, bool *missing)
{
    const char *arg = argv[*i];
    size_t ll = strlen(lng);
    if (strncmp(arg, lng, ll) == 0 && arg[ll] == '=') {
        *value = arg + ll + 1;
        return true;
    }
    if ((shrt && strcmp(arg, shrt) == 0) || strcmp(arg, lng) == 0) {
        if (*i + 1 >= argc) { *missing = true; return true; }
        *value = argv[++*i];
        return true;
    }
    return false;
}

static AuditStatus add_input(CliOptions *o, const char *path, FILE *err)
{
    if (o->input_count >= NA_MAX_INPUT_FILES) {
        fprintf(err, "error: too many input files (limit %d)\n", NA_MAX_INPUT_FILES);
        return AUDIT_ERR_LIMIT;
    }
    if (!safe_strcpy(o->inputs[o->input_count], NA_MAX_PATH, path)) {
        fprintf(err, "error: path too long: %s\n", path);
        return AUDIT_ERR_ARG;
    }
    o->input_count++;
    return AUDIT_OK;
}

AuditStatus cli_parse(int argc, char **argv, CliOptions *o, FILE *err)
{
    memset(o, 0, sizeof(*o));
    o->format       = REPORT_TEXT;
    o->min_severity = SEV_LOW;
    o->color        = COLOR_AUTO;
    o->log_level    = LOG_WARN;
    o->action       = CLI_RUN;

    bool options_done = false;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *val = NULL;
        bool missing = false;

        if (options_done || a[0] != '-') {
            AuditStatus rc = add_input(o, a, err);
            if (rc != AUDIT_OK) return rc;
            continue;
        }
        if (strcmp(a, "--") == 0) { options_done = true; continue; }

        if (take_value(argc, argv, &i, "-v", "--vendor", &val, &missing)) {
            if (!missing) safe_strcpy(o->vendor, sizeof(o->vendor), val);  /* validated later */
        } else if (take_value(argc, argv, &i, "-f", "--format", &val, &missing)) {
            if (!missing && !report_format_parse(val, &o->format)) {
                fprintf(err, "error: unknown format '%s' (text, csv, json)\n", val);
                return AUDIT_ERR_ARG;
            }
        } else if (take_value(argc, argv, &i, "-o", "--output", &val, &missing)) {
            if (!missing && !safe_strcpy(o->output_path, sizeof(o->output_path), val)) {
                fprintf(err, "error: output path too long\n");
                return AUDIT_ERR_ARG;
            }
        } else if (take_value(argc, argv, &i, "-s", "--severity", &val, &missing)) {
            if (!missing && !severity_parse(val, &o->min_severity)) {
                fprintf(err, "error: unknown severity '%s' (critical, high, medium, low)\n", val);
                return AUDIT_ERR_ARG;
            }
        } else if (take_value(argc, argv, &i, "-d", "--dir", &val, &missing)) {
            if (!missing) {
                AuditStatus rc = platform_list_configs(val, o->inputs, &o->input_count,
                                                       NA_MAX_INPUT_FILES);
                if (rc == AUDIT_ERR_LIMIT) {
                    fprintf(err, "error: too many input files (limit %d)\n", NA_MAX_INPUT_FILES);
                    return rc;
                }
                if (rc != AUDIT_OK) {
                    fprintf(err, "error: cannot read directory '%s'\n", val);
                    return rc;
                }
            }
        } else if (strcmp(a, "--no-color") == 0 || strcmp(a, "--no-colour") == 0) {
            o->color = COLOR_NEVER;
        } else if (strcmp(a, "--color") == 0 || strcmp(a, "--colour") == 0) {
            o->color = COLOR_ALWAYS;
        } else if (strcmp(a, "--verbose") == 0) {
            o->log_level = LOG_DEBUG;
        } else if (strcmp(a, "-q") == 0 || strcmp(a, "--quiet") == 0) {
            o->log_level = LOG_ERROR;
        } else if (strcmp(a, "--exit-zero") == 0) {
            o->exit_zero = true;
        } else if (strcmp(a, "--list-rules") == 0) {
            o->action = CLI_LIST_RULES;
        } else if (strcmp(a, "--list-vendors") == 0) {
            o->action = CLI_LIST_VENDORS;
        } else if (strcmp(a, "-V") == 0 || strcmp(a, "--version") == 0) {
            o->action = CLI_VERSION;
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            o->action = CLI_HELP;
        } else {
            fprintf(err, "error: unknown option '%s' (see --help)\n", a);
            return AUDIT_ERR_ARG;
        }

        if (missing) {
            fprintf(err, "error: option '%s' needs a value\n", a);
            return AUDIT_ERR_ARG;
        }
    }
    return AUDIT_OK;
}
