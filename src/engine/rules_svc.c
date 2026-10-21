/**
 * @file rules_svc.c
 * @brief SVC-* rules: insecure or unnecessary network services.
 */
#include "rules_internal.h"

static void check_svc001(const DeviceModel *m, FindingSink *sink)
{
    if (m->mgmt.http_enabled)
        finding_report(sink, -1, "management access / http");
}

static void check_svc002(const DeviceModel *m, FindingSink *sink)
{
    if (m->services.cdp_global)
        finding_report(sink, -1, "service / cdp run");
}

static void check_svc003(const DeviceModel *m, FindingSink *sink)
{
    if (m->services.tcp_small_servers || m->services.udp_small_servers)
        finding_report(sink, -1, "service %s%s%s",
                       m->services.tcp_small_servers ? "tcp-small-servers" : "",
                       m->services.tcp_small_servers &&
                       m->services.udp_small_servers ? " / " : "",
                       m->services.udp_small_servers ? "udp-small-servers" : "");
}

const Rule RULES_SVC[] = {
    { "SVC-001", CAT_SVC, SEV_HIGH,
      "Plain HTTP management server enabled",
      "Plain-text HTTP management access is enabled",
      "Disable HTTP management ('no ip http server'; remove 'http' from "
      "web-management or allowaccess) and use HTTPS with TLS 1.2 or later "
      "and a valid certificate.",
      check_svc001 },

    { "SVC-002", CAT_SVC, SEV_MEDIUM,
      "CDP enabled globally",
      "CDP (Cisco Discovery Protocol) enabled globally",
      "Run 'no cdp run', or at least 'no cdp enable' on every external and "
      "untrusted interface. CDP discloses platform, version and addressing.",
      check_svc002 },

    { "SVC-003", CAT_SVC, SEV_MEDIUM,
      "TCP/UDP small servers enabled",
      "TCP/UDP small servers enabled (echo, chargen, discard, daytime)",
      "Disable with 'no service tcp-small-servers' and 'no service "
      "udp-small-servers'. These services are obsolete and can be abused for "
      "amplification attacks.",
      check_svc003 },
};
DEFINE_RULE_GROUP_COUNT(RULES_SVC);
