/**
 * @file test_main.c
 * @brief Test runner entry point.
 *
 * Usage: net-audit-tests [fixtures-dir] [filter]
 *   fixtures-dir  defaults to tests/fixtures (run from the repository root)
 *   filter        run only tests whose name contains it, or one suite
 */
#include "harness.h"
#include "netaudit/log.h"

int main(int argc, char **argv)
{
    if (argc > 1) fixture_set_dir(argv[1]);
    log_set_level(LOG_SILENT);
    parser_registry_init();

    suite_safe_str();
    suite_parsers();
    suite_rules();
    suite_report();
    suite_regression();

    return test_run(argc > 2 ? argv[2] : NULL);
}
