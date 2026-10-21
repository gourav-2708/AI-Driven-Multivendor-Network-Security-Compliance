/**
 * @file test_report.c
 * @brief Report writers: JSON well-formedness, CSV quoting, filtering,
 *        single-device vs fleet shape.
 *
 * Reports are written to a scratch file in the working directory and read
 * back (tmpfile() is unreliable on Windows).
 */
#include "harness.h"
#include "netaudit/report.h"

#define SUITE "report"
#define SCRATCH "net-audit-test-report.tmp"
#define OUT_MAX (256 * 1024)

static DeviceModel s_m;
static AuditResult s_r;
static ReportSession s_s;
static char s_out[OUT_MAX];

/* -- Minimal JSON validator (RFC 8259 grammar, no semantic checks) -------- */

static const char *ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static const char *value(const char *p, int depth);

static const char *string(const char *p)
{
    if (*p++ != '"') return NULL;
    while (*p && *p != '"') {
        if ((unsigned char)*p < 0x20) return NULL;
        if (*p == '\\') {
            p++;
            if (*p == 'u') {
                for (int i = 1; i <= 4; i++) if (!isxdigit((unsigned char)p[i])) return NULL;
                p += 4;
            } else if (!strchr("\"\\/bfnrt", *p) || !*p) {
                return NULL;
            }
        }
        p++;
    }
    return *p == '"' ? p + 1 : NULL;
}

static const char *number(const char *p)
{
    const char *start = p;
    if (*p == '-') p++;
    if (!isdigit((unsigned char)*p)) return NULL;
    while (isdigit((unsigned char)*p)) p++;
    return p > start ? p : NULL;
}

static const char *container(const char *p, int depth, char close, bool object)
{
    p = ws(p + 1);
    if (*p == close) return p + 1;
    for (;;) {
        if (object) {
            if (!(p = string(ws(p)))) return NULL;
            p = ws(p);
            if (*p++ != ':') return NULL;
        }
        if (!(p = value(p, depth + 1))) return NULL;
        p = ws(p);
        if (*p == close) return p + 1;
        if (*p++ != ',') return NULL;
    }
}

static const char *value(const char *p, int depth)
{
    if (depth > 32) return NULL;
    p = ws(p);
    switch (*p) {
    case '{': return container(p, depth, '}', true);
    case '[': return container(p, depth, ']', false);
    case '"': return string(p);
    case 't': return strncmp(p, "true", 4)  == 0 ? p + 4 : NULL;
    case 'f': return strncmp(p, "false", 5) == 0 ? p + 5 : NULL;
    case 'n': return strncmp(p, "null", 4)  == 0 ? p + 4 : NULL;
    default:  return number(p);
    }
}

static bool json_valid(const char *text)
{
    const char *end = value(text, 0);
    return end && *ws(end) == '\0';
}

/* -- Helpers ---------------------------------------------------------------- */

/* Audit @p files (fixture names) into one report and capture its text. */
static const char *render(ReportFormat fmt, Severity min, bool fleet,
                          const char *const files[], int nfiles)
{
    FILE *fp = fopen(SCRATCH, "wb");
    CHECK(fp != NULL);
    if (!fp) return "";

    ReportOptions o = { .format = fmt, .out = fp, .color = false, .min_severity = min };
    CHECK(report_begin(&s_s, &o, fleet) == AUDIT_OK);
    for (int i = 0; i < nfiles; i++) {
        CHECK(audit_fixture(files[i], &s_m, &s_r));
        CHECK(report_device(&s_s, &s_r) == AUDIT_OK);
    }
    CHECK(report_end(&s_s) == AUDIT_OK);
    fclose(fp);

    fp = fopen(SCRATCH, "rb");
    size_t n = fp ? fread(s_out, 1, sizeof(s_out) - 1, fp) : 0;
    if (fp) fclose(fp);
    s_out[n] = '\0';
    remove(SCRATCH);
    return s_out;
}

static int occurrences(const char *hay, const char *needle)
{
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

static const char *const k_one[]   = { "cisco_sample.cfg" };
static const char *const k_fleet[] = { "cisco_sample.cfg", "juniper_sample.conf",
                                       "fortinet_sample.conf", "test_01_cisco_secure.cfg" };

/* -- Tests -------------------------------------------------------------------- */

static void json_device_is_valid(void)
{
    const char *out = render(REPORT_JSON, SEV_LOW, false, k_one, 1);
    CHECK(json_valid(out));
    CHECK(strstr(out, "\"report_type\": \"device\"") != NULL);
    CHECK(strstr(out, "\"hostname\": \"core-router-01\"") != NULL);
    CHECK_INT(occurrences(out, "\"rule_id\""), s_r.finding_count);
}

static void json_fleet_is_valid(void)
{
    const char *out = render(REPORT_JSON, SEV_LOW, true, k_fleet, 4);
    CHECK(json_valid(out));
    CHECK(strstr(out, "\"report_type\": \"aggregate\"") != NULL);
    CHECK(strstr(out, "\"devices_audited\": 4") != NULL);
    CHECK_INT(occurrences(out, "\"hostname\""), 4);
    /* A device with zero findings must still produce a valid empty array. */
    CHECK(strstr(out, "\"findings\": [\n      ]") != NULL);
}

static void json_filters_by_severity(void)
{
    const char *out = render(REPORT_JSON, SEV_CRITICAL, false, k_one, 1);
    CHECK(json_valid(out));
    CHECK_INT(occurrences(out, "\"rule_id\""), s_r.sev_counts[SEV_CRITICAL]);
    CHECK(strstr(out, "\"severity\": \"HIGH\"") == NULL);
    /* counts still describe the whole device, not the filtered view */
    CHECK(strstr(out, "\"high\": 0") == NULL);
}

static void csv_quoting_and_rows(void)
{
    const char *out = render(REPORT_CSV, SEV_LOW, true, k_fleet, 4);
    CHECK(str_starts_with(out, "device,vendor,rule_id,severity,section,description,remediation\r\n"));
    int rows = occurrences(out, "\r\n") - 1;
    CHECK_INT(rows, s_s.visible_total);
    CHECK_INT(occurrences(out, "\n"), occurrences(out, "\r\n"));   /* CRLF only */
    CHECK(strstr(out, "\"interface 'GigabitEthernet0/2'\"") != NULL);
}

/* Hostile names - quotes, commas, backslashes, control characters - must be
 * escaped so neither the CSV nor the JSON can be broken out of. */
static void hostile_text_is_escaped(void)
{
    model_init(&s_m);
    safe_strcpy(s_m.hostname, sizeof(s_m.hostname), "evil\"host,\\\t");
    safe_strcpy(s_m.vendor, sizeof(s_m.vendor), "cisco");
    model_interface(&s_m, "Gi0/1\",\"x");            /* triggers INTF-001 */
    engine_run(&s_m, &s_r);

    FILE *fp = fopen(SCRATCH, "wb");
    CHECK(fp != NULL);
    if (!fp) return;
    ReportOptions o = { .format = REPORT_CSV, .out = fp, .min_severity = SEV_LOW };
    report_begin(&s_s, &o, false);
    report_device(&s_s, &s_r);
    report_end(&s_s);
    long json_at = ftell(fp);
    o.format = REPORT_JSON;
    report_begin(&s_s, &o, false);
    report_device(&s_s, &s_r);
    report_end(&s_s);
    fclose(fp);

    fp = fopen(SCRATCH, "rb");
    size_t n = fp ? fread(s_out, 1, sizeof(s_out) - 1, fp) : 0;
    if (fp) fclose(fp);
    s_out[n] = '\0';
    remove(SCRATCH);

    /* CSV: inner quotes doubled, field stays one quoted cell */
    CHECK(strstr(s_out, "\"evil\"\"host,\\\t\"") != NULL);
    CHECK(strstr(s_out, "\"interface 'Gi0/1\"\",\"\"x'\"") != NULL);
    /* JSON: \" \\ and \t escapes, document still well-formed */
    CHECK(json_at > 0 && json_valid(s_out + json_at));
    CHECK(strstr(s_out + json_at, "evil\\\"host,\\\\\\t") != NULL);
}

static void text_device_and_fleet(void)
{
    const char *out = render(REPORT_TEXT, SEV_LOW, false, k_one, 1);
    CHECK(strstr(out, "NET-AUDIT COMPLIANCE REPORT") != NULL);
    CHECK(strstr(out, "Authentication (AUTH)") != NULL);
    CHECK(strstr(out, "\033[") == NULL);          /* colour off */

    out = render(REPORT_TEXT, SEV_HIGH, true, k_fleet, 4);
    CHECK_INT(occurrences(out, "NET-AUDIT COMPLIANCE REPORT"), 4);
    CHECK(strstr(out, "NET-AUDIT FLEET SUMMARY") != NULL);
    CHECK(strstr(out, "(LOW)") == NULL);          /* filtered */
}

static void empty_session_writes_nothing(void)
{
    const char *out = render(REPORT_JSON, SEV_LOW, true, NULL, 0);
    CHECK_STR(out, "");
    CHECK_INT(report_visible_findings(&s_s), 0);
}

static void single_mode_rejects_second_device(void)
{
    FILE *fp = fopen(SCRATCH, "wb");
    CHECK(fp != NULL);
    if (!fp) return;
    ReportOptions o = { .format = REPORT_JSON, .out = fp, .min_severity = SEV_LOW };
    report_begin(&s_s, &o, false);
    CHECK(audit_fixture("cisco_sample.cfg", &s_m, &s_r));
    CHECK(report_device(&s_s, &s_r) == AUDIT_OK);
    CHECK(report_device(&s_s, &s_r) == AUDIT_ERR_LIMIT);
    report_end(&s_s);
    fclose(fp);
    remove(SCRATCH);
}

static void format_names(void)
{
    ReportFormat f;
    CHECK(report_format_parse("JSON", &f) && f == REPORT_JSON);
    CHECK(report_format_parse("txt", &f) && f == REPORT_TEXT);
    CHECK(!report_format_parse("xml", &f));
    CHECK_STR(report_format_name(REPORT_CSV), "csv");
}

void suite_report(void)
{
    TEST(json_device_is_valid);
    TEST(json_fleet_is_valid);
    TEST(json_filters_by_severity);
    TEST(csv_quoting_and_rows);
    TEST(hostile_text_is_escaped);
    TEST(text_device_and_fleet);
    TEST(empty_session_writes_nothing);
    TEST(single_mode_rejects_second_device);
    TEST(format_names);
}
