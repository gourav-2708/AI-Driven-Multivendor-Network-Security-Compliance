/**
 * @file test_runner.h
 * @brief Minimal test harness API (no external dependencies, no GCC constructors).
 */
#ifndef TEST_RUNNER_H
#define TEST_RUNNER_H

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define MAX_TESTS 128

typedef struct {
    const char *name;
    void (*fn)(void);
} TestCase;

/* Test registry */
extern TestCase  g_tests[];
extern int       g_test_count;

/* Assertion counters */
extern int g_pass;
extern int g_fail;

void test_register(const char *name, void (*fn)(void));
int  test_run_all(void);
void test_assert_impl(bool cond, const char *expr,
                      const char *file, int line);

#define ASSERT(cond) \
    test_assert_impl(!!(cond), #cond, __FILE__, __LINE__)

#define ASSERT_STR_EQ(a, b) \
    test_assert_impl(strcmp((a),(b))==0, #a " == " #b, __FILE__, __LINE__)

#define ASSERT_INT_EQ(a, b) \
    test_assert_impl((a)==(b), #a " == " #b, __FILE__, __LINE__)

#endif /* TEST_RUNNER_H */
