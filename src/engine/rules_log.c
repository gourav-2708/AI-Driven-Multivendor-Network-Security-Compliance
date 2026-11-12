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

static void check_log003(const DeviceModel *m, FindingSink *sink)
{
    if (!m->logging.timestamps)
        finding_report(sink, -1, "logging / timestamps");
}

const Rule RULES_LOG[] = {
    { "LOG-001", CAT_LOG, SEV_MEDIUM,
      "No remote syslog server",
      "No remote syslog server configured",
      "Send logs to at least one remote collector ('logging host <ip>'; "
      "JunOS 'syslog host'; FortiOS 'log syslogd setting'). Centralised logs "
      "are required for security monitoring and incident response.",
      check_log001,
      { "8.2, 8.9", "10.2.1, 10.3.3", "A.8.15, A.8.16", "AU-4(1), AU-9(2)" } },

    { "LOG-002", CAT_LOG, SEV_LOW,
      "No local buffered logging",
      "Buffered (local) logging not enabled",
      "Enable a local log buffer ('logging buffered 65536 informational'; "
      "JunOS 'syslog file'; FortiOS memory/disk logging) as a fallback when "
      "the collector is unreachable.",
      check_log002,
      { "8.2, 8.3", "10.2.1", "A.8.15", "AU-4, AU-12" } },

    { "LOG-003", CAT_LOG, SEV_LOW,
      "Log entries are not timestamped",
      "Log messages do not carry a date and time",
      "Stamp every message: 'service timestamps log datetime msec "
      "show-timezone' (IOS), 'logging timestamp' (ASA). Without "
      "timestamps, events cannot be ordered or matched across devices.",
      check_log003,
      { "8.5", "10.2.2", "A.8.15, A.8.17", "AU-3, AU-8" } },
};
DEFINE_RULE_GROUP_COUNT(RULES_LOG);
