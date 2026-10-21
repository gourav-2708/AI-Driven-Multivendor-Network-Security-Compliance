/**
 * @file harness.c
 * @brief Test registry, assertions and fixture helpers.
 */
#include "harness.h"
#include "netaudit/log.h"

#define MAX_TESTS 256

typedef struct { const char *suite, *name; TestFn fn; } TestCase;

static TestCase s_tests[MAX_TESTS];
static int      s_count;
static int      s_checks, s_failures;
static char     s_fixture_dir[NA_MAX_PATH] = "tests/fixtures";

void test_add(const char *suite, const char *name, TestFn fn)
{
    if (s_count >= MAX_TESTS) {
        fprintf(stderr, "harness: too many tests (max %d)\n", MAX_TESTS);
        return;
    }
    s_tests[s_count++] = (TestCase){ suite, name, fn };
}

void check_impl(bool ok, const char *expr, const char *file, int line)
{
    s_checks++;
    if (ok) return;
    s_failures++;
    fprintf(stderr, "\n    FAIL %s:%d: %s", file, line, expr);
}

void check_int_impl(long got, long want, const char *expr, const char *file, int line)
{
    s_checks++;
    if (got == want) return;
    s_failures++;
    fprintf(stderr, "\n    FAIL %s:%d: %s is %ld, expected %ld", file, line, expr, got, want);
}

void check_str_impl(const char *got, const char *want, const char *expr,
                    const char *file, int line)
{
    s_checks++;
    if (got && want && strcmp(got, want) == 0) return;
    s_failures++;
    fprintf(stderr, "\n    FAIL %s:%d: %s is \"%s\", expected \"%s\"", file, line,
            expr, got ? got : "(null)", want ? want : "(null)");
}

int test_run(const char *filter)
{
    int failed_tests = 0, ran = 0;
    for (int i = 0; i < s_count; i++) {
        const TestCase *t = &s_tests[i];
        if (filter && !str_contains_ci(t->name, filter) && !str_eq_ci(t->suite, filter))
            continue;
        int before = s_failures;
        printf("  %-10s %-44s ", t->suite, t->name);
        fflush(stdout);
        t->fn();
        bool ok = s_failures == before;
        if (!ok) { failed_tests++; fputc('\n', stderr); }
        printf("%s\n", ok ? "ok" : "FAILED");
        ran++;
    }
    printf("\n%d test(s), %d check(s): %d test(s) failed\n", ran, s_checks, failed_tests);
    return failed_tests == 0 && ran > 0 ? 0 : 1;
}

/* -- Fixtures ----------------------------------------------------------------- */

void fixture_set_dir(const char *dir)
{
    safe_strcpy(s_fixture_dir, sizeof(s_fixture_dir), dir);
}

const char *fixture(const char *name)
{
    static char path[4][NA_MAX_PATH];   /* a few results may be live at once */
    static int  slot;
    char *p = path[slot++ % 4];
    safe_snprintf(p, NA_MAX_PATH, "%s/%s", s_fixture_dir, name);
    return p;
}

const VendorParser *load_fixture(const char *name, DeviceModel *m)
{
    const char *path = fixture(name);
    const VendorParser *p = parser_detect(path, NULL);
    model_init(m);
    if (!p || p->parse(path, m) != AUDIT_OK) return NULL;
    model_finalize(m);
    return p;
}

bool audit_fixture(const char *name, DeviceModel *m, AuditResult *r)
{
    return load_fixture(name, m) && engine_run(m, r) == AUDIT_OK;
}

int count_rule(const AuditResult *r, const char *rule_id)
{
    int n = 0;
    for (int i = 0; i < r->finding_count; i++)
        if (strcmp(r->findings[i].rule->id, rule_id) == 0) n++;
    return n;
}
