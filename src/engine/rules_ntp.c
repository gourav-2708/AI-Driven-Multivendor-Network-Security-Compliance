/**
 * @file rules_ntp.c
 * @brief NTP-* rules: time synchronisation.
 */
#include "rules_internal.h"

static void check_ntp001(const DeviceModel *m, FindingSink *sink)
{
    if (m->ntp.server_count == 0)
        finding_report(sink, -1, "ntp");
}

static void check_ntp002(const DeviceModel *m, FindingSink *sink)
{
    if (m->ntp.server_count > 0 && !m->ntp.authenticated)
        finding_report(sink, -1, "ntp authenticate");
}

static void check_ntp003(const DeviceModel *m, FindingSink *sink)
{
    if (m->ntp.server_count == 1)
        finding_report(sink, -1, "ntp server %s", m->ntp.servers[0]);
}

const Rule RULES_NTP[] = {
    { "NTP-001", CAT_NTP, SEV_MEDIUM,
      "NTP not configured",
      "NTP not configured; device clock may be unsynchronised",
      "Configure at least two trusted NTP servers. Accurate time is needed "
      "for log correlation, certificate validation and AAA event ordering.",
      check_ntp001,
      { "8.4", "10.6.1, 10.6.2", "A.8.17", "AU-8, SC-45(1)" } },

    { "NTP-002", CAT_NTP, SEV_LOW,
      "NTP without authentication",
      "NTP configured without authentication",
      "Enable NTP authentication with trusted keys ('ntp authenticate', "
      "'ntp authentication-key', 'ntp trusted-key'). Unauthenticated NTP "
      "responses can be spoofed.",
      check_ntp002,
      { "8.4", "10.6.3", "A.8.17", "AU-8, SC-45" } },

    { "NTP-003", CAT_NTP, SEV_LOW,
      "Only one NTP server",
      "Only one NTP server is configured; there is no second time source",
      "Configure at least two NTP servers so the clock stays correct when "
      "one source fails or drifts.",
      check_ntp003,
      { "8.4", "10.6.2", "A.8.17", "SC-45(2)" } },
};
DEFINE_RULE_GROUP_COUNT(RULES_NTP);
