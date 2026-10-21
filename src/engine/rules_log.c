/**
 * @file rules_log.c
 * @brief LOG-* rules: remote and local event logging.
 */
#include "rules_internal.h"

static void check_log001(const DeviceModel *m, FindingSink *sink)
{
    if (m->logging.server_count == 0)
        finding_report(sink, -1, "logging");
}

static void check_log002(const DeviceModel *m, FindingSink *sink)
{
    if (!m->logging.buffered_enabled)
        finding_report(sink, -1, "logging buffered");
}

const Rule RULES_LOG[] = {
    { "LOG-001", CAT_LOG, SEV_MEDIUM,
      "No remote syslog server",
      "No remote syslog server configured",
      "Send logs to at least one remote collector ('logging host <ip>'; "
      "JunOS 'syslog host'; FortiOS 'log syslogd setting'). Centralised logs "
      "are required for security monitoring and incident response.",
      check_log001 },

    { "LOG-002", CAT_LOG, SEV_LOW,
      "No local buffered logging",
      "Buffered (local) logging not enabled",
      "Enable a local log buffer ('logging buffered 65536 informational'; "
      "JunOS 'syslog file'; FortiOS memory/disk logging) as a fallback when "
      "the collector is unreachable.",
      check_log002 },
};
DEFINE_RULE_GROUP_COUNT(RULES_LOG);
