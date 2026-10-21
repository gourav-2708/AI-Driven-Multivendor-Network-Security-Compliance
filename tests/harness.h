/**
 * @file harness.h
 * @brief Minimal dependency-free test harness plus shared fixtures helpers.
 */
#ifndef NETAUDIT_TEST_HARNESS_H
#define NETAUDIT_TEST_HARNESS_H

#include "netaudit/engine.h"
#include "netaudit/model.h"
#include "netaudit/parser.h"
#include "netaudit/safe_str.h"

typedef void (*TestFn)(void);

void test_add(const char *suite, const char *name, TestFn fn);
int  test_run(const char *filter);

void check_impl(bool ok, const char *expr, const char *file, int line);
void check_int_impl(long got, long want, const char *expr, const char *file, int line);
void check_str_impl(const char *got, const char *want, const char *expr,
                    const char *file, int line);

#define CHECK(cond)          check_impl(!!(cond), #cond, __FILE__, __LINE__)
#define CHECK_INT(got, want) check_int_impl((long)(got), (long)(want), #got, __FILE__, __LINE__)
#define CHECK_STR(got, want) check_str_impl((got), (want), #got, __FILE__, __LINE__)
#define TEST(fn)             test_add(SUITE, #fn, fn)

/* -- Fixtures ---------------------------------------------------------------- */
void        fixture_set_dir(const char *dir);
const char *fixture(const char *name);   /* path inside the fixtures dir */

/* Detect + parse + finalize a fixture into @p m. Returns the parser used. */
const VendorParser *load_fixture(const char *name, DeviceModel *m);

/* load_fixture() then engine_run(). */
bool audit_fixture(const char *name, DeviceModel *m, AuditResult *r);

/* Number of findings for @p rule_id in @p r. */
int  count_rule(const AuditResult *r, const char *rule_id);

/* -- Suites -------------------------------------------------------------------- */
void suite_safe_str(void);
void suite_parsers(void);
void suite_rules(void);
void suite_report(void);
void suite_regression(void);

#endif /* NETAUDIT_TEST_HARNESS_H */
