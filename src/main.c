/**
 * @file main.c
 * @brief net-audit entry point: parse the command line, run the audit.
 */
#include "netaudit/cli.h"

int main(int argc, char **argv)
{
    static CliOptions opts;       /* ~33 KB of input paths: not on the stack */

    if (cli_parse(argc, argv, &opts, stderr) != AUDIT_OK)
        return EXIT_USAGE;
    return audit_main(&opts);
}
