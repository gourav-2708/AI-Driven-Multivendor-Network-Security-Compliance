/**
 * @file test_safe_str.c
 * @brief Bounded string helpers: truncation, termination, tokenizing.
 */
#include "harness.h"

#define SUITE "safe_str"

static void copy_fits_and_truncates(void)
{
    char buf[6];
    CHECK(safe_strcpy(buf, sizeof(buf), "hello"));
    CHECK_STR(buf, "hello");
    CHECK(!safe_strcpy(buf, sizeof(buf), "hello world"));
    CHECK_STR(buf, "hello");                    /* truncated, terminated */
    CHECK(safe_strcpy(buf, sizeof(buf), NULL));
    CHECK_STR(buf, "");
    CHECK(!safe_strcpy(buf, 0, "x"));           /* no room at all */
}

static void copy_n_stops_early(void)
{
    char buf[16];
    CHECK(safe_strncpy_n(buf, sizeof(buf), "abcdef", 3));
    CHECK_STR(buf, "abc");
    CHECK(safe_strncpy_n(buf, sizeof(buf), "ab", 10));
    CHECK_STR(buf, "ab");
}

static void concat_bounds(void)
{
    char buf[8] = "abc";
    CHECK(safe_strcat(buf, sizeof(buf), "def"));
    CHECK_STR(buf, "abcdef");
    CHECK(!safe_strcat(buf, sizeof(buf), "ghij"));
    CHECK_STR(buf, "abcdefg");
    CHECK_INT(strlen(buf), 7);
}

static void snprintf_reports_truncation(void)
{
    char buf[8];
    CHECK(safe_snprintf(buf, sizeof(buf), "%d-%s", 42, "ok"));
    CHECK_STR(buf, "42-ok");
    CHECK(!safe_snprintf(buf, sizeof(buf), "%s", "0123456789"));
    CHECK_STR(buf, "0123456");
}

static void trim_and_compare(void)
{
    char s[] = "  \t value with space \r\n";
    CHECK_STR(str_trim(s), "value with space");
    CHECK(str_eq_ci("GigabitEthernet0/1", "gigabitethernet0/1"));
    CHECK(str_starts_with_ci("Interface Gi0/1", "interface"));
    CHECK(!str_starts_with_ci("int", "interface"));
    CHECK(str_ends_with_ci("router.CONF", ".conf"));
    CHECK(str_contains_ci("OOB Management", "management"));
}

static void to_int_validates(void)
{
    int v = 0;
    CHECK(str_to_int("15", &v));
    CHECK_INT(v, 15);
    CHECK(str_to_int("-3", &v));
    CHECK_INT(v, -3);
    CHECK(!str_to_int("", &v));
    CHECK(!str_to_int("12abc", &v));
    CHECK(!str_to_int("99999999999999999999", &v));
}

static void tokenize_handles_quotes(void)
{
    char line[] = "set name \"WAN Uplink\"  srcaddr all \"\"";
    char *w[8];
    int n = str_tokenize(line, w, 8);
    CHECK_INT(n, 6);
    CHECK_STR(w[0], "set");
    CHECK_STR(w[2], "WAN Uplink");
    CHECK_STR(w[4], "all");
    CHECK_STR(w[5], "");

    char many[] = "a b c d e";
    CHECK_INT(str_tokenize(many, w, 3), 3);     /* capped, no overflow */
    CHECK_STR(w[2], "c");
}

void suite_safe_str(void)
{
    TEST(copy_fits_and_truncates);
    TEST(copy_n_stops_early);
    TEST(concat_bounds);
    TEST(snprintf_reports_truncation);
    TEST(trim_and_compare);
    TEST(to_int_validates);
    TEST(tokenize_handles_quotes);
}
