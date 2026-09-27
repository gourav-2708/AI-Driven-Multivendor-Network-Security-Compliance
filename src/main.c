/**
 * @file main.c
 * @brief net-audit CLI entry point and top-level orchestration.
 *
 * Usage:
 *   net-audit [OPTIONS] <config-file> [<config-file> ...]
 *   net-audit [OPTIONS] --dir <config-directory>
 *
 * Options:
 *   -v, --vendor <cisco|juniper|fortinet>  Force vendor tag (skip auto-detect)
 *   -f, --format <text|csv|json>           Output format (default: text)
 *   -o, --output <file>                    Write to file instead of stdout
 *   --severity <critical|high|medium|low>  Minimum severity to report
 *   --no-color                             Disable ANSI colour
 *   --verbose                              Enable debug logging
 *   -h, --help                             Show this help
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
#  include <windows.h>
#  include <io.h>
#  define IS_WIN 1
#else
#  include <dirent.h>
#  define IS_WIN 0
#endif

#include "common.h"
#include "model.h"
#include "parser.h"
#include "engine.h"
#include "report.h"

#define MAX_FILES 128

/* -- Usage ----------------------------------------------------------------- */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS] <config-file> [<config-file>...]\n"
        "       %s [OPTIONS] --dir <directory>\n"
        "\n"
        "Options:\n"
        "  -v, --vendor <cisco|juniper|fortinet>  Force vendor (skip auto-detect)\n"
        "  -f, --format <text|csv|json>           Output format (default: text)\n"
        "  -o, --output <file>                    Write report to file\n"
        "  --severity <critical|high|medium|low>  Minimum severity filter\n"
        "  --no-color                             Disable ANSI colour\n"
        "  --verbose                              Enable debug logging\n"
        "  -h, --help                             Show this help\n",
        prog, prog);
}

/* -- Severity name ? enum -------------------------------------------------- */
static bool parse_severity(const char *s, Severity *out)
{
    if (!s || !out) return false;
    if (portable_strcasecmp(s, "critical") == 0) { *out = SEV_CRITICAL; return true; }
    if (portable_strcasecmp(s, "high")     == 0) { *out = SEV_HIGH;     return true; }
    if (portable_strcasecmp(s, "medium")   == 0) { *out = SEV_MEDIUM;   return true; }
    if (portable_strcasecmp(s, "low")      == 0) { *out = SEV_LOW;      return true; }
    return false;
}

/* -- Collect .cfg/.conf files from a directory ----------------------------- */
static int collect_dir(const char *dirpath, char out_paths[][MAX_PATH_LEN],
                       int max_out)
{
    int count = 0;

#ifdef _WIN32
    char pattern[MAX_PATH_LEN];
    safe_snprintf(pattern, sizeof(pattern), "%s\\*", dirpath);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        const char *name = fd.cFileName;
        size_t nlen = strlen(name);
        bool ok = (nlen > 4 &&
                   (portable_strcasecmp(name + nlen - 4, ".cfg")  == 0 ||
                    portable_strcasecmp(name + nlen - 5, ".conf") == 0 ||
                    portable_strcasecmp(name + nlen - 4, ".txt")  == 0));
        if (ok && count < max_out) {
            safe_snprintf(out_paths[count++], MAX_PATH_LEN,
                          "%s\\%s", dirpath, name);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *dp = opendir(dirpath);
    if (!dp) return 0;
    struct dirent *de;
    while ((de = readdir(dp)) != NULL && count < max_out) {
        const char *name = de->d_name;
        size_t nlen = strlen(name);
        bool ok = (nlen > 4 &&
                   (portable_strcasecmp(name + nlen - 4, ".cfg")  == 0 ||
                    portable_strcasecmp(name + nlen - 5, ".conf") == 0 ||
                    portable_strcasecmp(name + nlen - 4, ".txt")  == 0));
        if (ok) {
            safe_snprintf(out_paths[count++], MAX_PATH_LEN,
                          "%s/%s", dirpath, name);
        }
    }
    closedir(dp);
#endif
    return count;
}

/* -- Main ------------------------------------------------------------------ */
int main(int argc, char *argv[])
{
    if (argc < 2) { usage(argv[0]); return EXIT_FAILURE; }

    /* -- Register all vendor parsers ----------------------------------- */
    cisco_parser_register();
    juniper_parser_register();
    fortinet_parser_register();

    /* -- Parse CLI arguments ------------------------------------------- */
    char        forced_vendor[MAX_VENDOR_LEN] = {0};
    ReportFormat fmt       = REPORT_TEXT;
    char         outfile[MAX_PATH_LEN]        = {0};
    Severity     min_sev   = SEV_LOW;
    bool         color     = true;
    bool         do_dir    = false;
    char         dirpath[MAX_PATH_LEN]        = {0};

    /* Collect input files */
    static char file_list[MAX_FILES][MAX_PATH_LEN];
    int         file_count = 0;

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-v") == 0 ||
             strcmp(argv[i], "--vendor") == 0) && i+1 < argc) {
            safe_strncpy(forced_vendor, argv[++i], sizeof(forced_vendor));
        } else if ((strcmp(argv[i], "-f") == 0 ||
                    strcmp(argv[i], "--format") == 0) && i+1 < argc) {
            if (!report_parse_format(argv[++i], &fmt)) {
                fprintf(stderr, "Unknown format: %s\n", argv[i]);
                return EXIT_FAILURE;
            }
        } else if ((strcmp(argv[i], "-o") == 0 ||
                    strcmp(argv[i], "--output") == 0) && i+1 < argc) {
            safe_strncpy(outfile, argv[++i], sizeof(outfile));
        } else if (strcmp(argv[i], "--severity") == 0 && i+1 < argc) {
            if (!parse_severity(argv[++i], &min_sev)) {
                fprintf(stderr, "Unknown severity: %s\n", argv[i]);
                return EXIT_FAILURE;
            }
        } else if (strcmp(argv[i], "--no-color") == 0) {
            color = false;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            g_log_level = LOG_DEBUG;
        } else if (strcmp(argv[i], "--dir") == 0 && i+1 < argc) {
            do_dir = true;
            safe_strncpy(dirpath, argv[++i], sizeof(dirpath));
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return EXIT_SUCCESS;
        } else if (argv[i][0] != '-') {
            if (file_count < MAX_FILES) {
                safe_strncpy(file_list[file_count++], argv[i],
                             MAX_PATH_LEN);
            }
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    /* Collect files from directory */
    if (do_dir) {
        int added = collect_dir(dirpath, &file_list[file_count],
                                MAX_FILES - file_count);
        file_count += added;
        LOG_INF("Collected %d config file(s) from '%s'", added, dirpath);
    }

    if (file_count == 0) {
        fprintf(stderr, "Error: no input files specified.\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* -- Open output stream --------------------------------------------- */
    FILE *out_fp = stdout;
    if (outfile[0] != '\0') {
        out_fp = fopen(outfile, "w");
        if (!out_fp) {
            fprintf(stderr, "Error: cannot open output file '%s'\n", outfile);
            return EXIT_FAILURE;
        }
    }

    ReportOptions ropts = {
        .format       = fmt,
        .output       = out_fp,
        .color        = color && (out_fp == stdout),
        .min_severity = min_sev
    };

    /* -- Audit each file ----------------------------------------------- */
    /* Use stack-allocated storage for up to MAX_FILES devices */
    static DeviceModel models[MAX_FILES];
    static AuditResult results[MAX_FILES];
    const AuditResult *result_ptrs[MAX_FILES];
    int audited = 0;

    /* CSV aggregate header — emit once before per-device rows */
    bool csv_header_done = false;

    for (int i = 0; i < file_count; i++) {
        const char *filepath = file_list[i];
        LOG_INF("Processing: %s", filepath);

        model_init(&models[audited]);
        result_init(&results[audited], &models[audited]);

        /* Detect or look up parser */
        const VendorParser *parser = NULL;
        if (forced_vendor[0]) {
            parser = parser_find_by_vendor(forced_vendor);
            if (!parser) {
                LOG_ERR("No parser registered for vendor '%s'", forced_vendor);
                continue;
            }
        } else {
            parser = parser_detect(filepath);
            if (!parser) {
                LOG_WRN("Cannot detect vendor for '%s'; skipping", filepath);
                continue;
            }
        }

        /* Parse */
        int rc = parser->parse(filepath, &models[audited]);
        if (rc != AUDIT_OK) {
            LOG_ERR("Parse error (%s) for '%s'", audit_strerror(rc), filepath);
            continue;
        }

        /* Run rules engine */
        rc = engine_run(&models[audited], &results[audited]);
        if (rc != AUDIT_OK) {
            LOG_ERR("Engine error (%s) for '%s'", audit_strerror(rc), filepath);
            continue;
        }

        /* Emit per-device report (not for aggregate-only JSON) */
        if (fmt == REPORT_CSV) {
            if (!csv_header_done && file_count == 1) {
                report_csv_device(&results[audited], &ropts);
                csv_header_done = true;
            } else if (!csv_header_done) {
                /* Will be handled by aggregate */
            }
        } else if (file_count == 1) {
            report_device(&results[audited], &ropts);
        }

        result_ptrs[audited] = &results[audited];
        audited++;
    }

    /* -- Aggregate report (multiple devices) --------------------------- */
    if (audited > 1) {
        report_aggregate(result_ptrs, audited, &ropts);
    } else if (audited == 1 && file_count > 1) {
        /* Single result from multiple inputs (e.g., one succeeded) */
        report_device(&results[0], &ropts);
    } else if (audited == 0) {
        fprintf(stderr, "Error: no files were successfully audited.\n");
        if (out_fp != stdout) fclose(out_fp);
        return EXIT_FAILURE;
    }

    if (out_fp != stdout) fclose(out_fp);
    return EXIT_SUCCESS;
}

