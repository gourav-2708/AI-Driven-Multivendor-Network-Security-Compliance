/**
 * @file test_runner.c
 * @brief Minimal test harness implementation.
 */
#include <stdio.h>
#include "test_runner.h"

TestCase g_tests[MAX_TESTS];
int      g_test_count = 0;
int      g_pass = 0;
int      g_fail = 0;

void test_register(const char *name, void (*fn)(void))
{
    if (g_test_count >= MAX_TESTS) return;
    g_tests[g_test_count].name = name;
    g_tests[g_test_count].fn   = fn;
    g_test_count++;
}

void test_assert_impl(bool cond, const char *expr,
                      const char *file, int line)
{
    if (cond) { g_pass++; }
    else { g_fail++; fprintf(stderr, "  FAIL: %s:%d — %s\n", file, line, expr); }
}

int test_run_all(void)
{
    printf("Running %d test(s)...\n", g_test_count);
    for (int i = 0; i < g_test_count; i++) {
        int pf = g_fail;
        printf("  [%2d/%d] %-45s ", i+1, g_test_count, g_tests[i].name);
        fflush(stdout);
        g_tests[i].fn();
        printf("%s\n", (g_fail == pf) ? "PASS" : "FAIL");
    }
    printf("\nResults: %d passed, %d failed\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
