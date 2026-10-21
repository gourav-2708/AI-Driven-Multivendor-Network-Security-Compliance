/**
 * @file test_regression.c
 * @brief Golden results for every fixture: vendor, hostname, score and the
 *        exact ordered list of rule IDs reported.
 *
 * A change here is a change in what users see. When one is intended,
 * update the row and say why in the commit message.
 */
#include "harness.h"

#define SUITE "golden"

typedef struct {
    const char *file;
    const char *vendor;
    const char *hostname;
    int         score;
    const char *rule_ids;   /* space-separated, in report order */
} Golden;

static const Golden k_golden[] = {
    { "cisco_sample.cfg", "cisco", "core-router-01", 2,
      "AUTH-001 AUTH-002 AUTH-003 AUTH-004 PASSWD-001 ACL-001 ACL-002 SNMP-001 SNMP-001 "
      "SNMP-002 SNMP-002 SVC-001 SVC-002 SVC-003 LOG-001 LOG-002 NTP-001 INTF-001" },
    { "fortinet_sample.conf", "fortinet", "FortiGate-Branch", 6,
      "AUTH-001 AUTH-002 AUTH-003 PASSWD-001 ACL-001 ACL-002 SNMP-001 SNMP-002 SVC-001 "
      "LOG-001 LOG-002 NTP-001 INTF-001" },
    { "juniper_sample.conf", "juniper", "edge-router-jnpr", 7,
      "AUTH-001 AUTH-003 PASSWD-001 ACL-001 ACL-002 SNMP-001 SNMP-001 SNMP-002 SNMP-002 "
      "SVC-001 LOG-001 NTP-001 INTF-001" },
    { "test_01_cisco_secure.cfg", "cisco", "branch-firewall-secure", 100,
      "" },
    { "test_02_cisco_critical.cfg", "cisco", "legacy-core-router", 1,
      "AUTH-001 AUTH-002 AUTH-003 AUTH-004 PASSWD-001 ACL-001 ACL-001 ACL-001 ACL-002 "
      "SNMP-001 SNMP-001 SNMP-001 SNMP-001 SNMP-002 SNMP-002 SNMP-002 SNMP-002 SVC-001 "
      "SVC-002 SVC-003 LOG-001 LOG-002 NTP-001 INTF-001 INTF-001" },
    { "test_03_cisco_medium.cfg", "cisco", "campus-distribution-sw", 40,
      "AUTH-003 AUTH-004 SNMP-001 SNMP-001 SNMP-002 SNMP-002 SVC-001 SVC-002 NTP-002 "
      "INTF-001" },
    { "test_04_cisco_poor.cfg", "cisco", "isp-edge-router", 1,
      "AUTH-001 AUTH-002 PASSWD-001 ACL-001 ACL-002 SNMP-001 SNMP-002 SVC-001 SVC-002 "
      "LOG-001 LOG-002 NTP-001 INTF-001 INTF-001" },
    { "test_05_juniper_secure.conf", "juniper", "juniper-srx-secure", 77,
      "AUTH-002 ACL-001" },
    { "test_06_juniper_critical.conf", "juniper", "juniper-legacy-router", 7,
      "AUTH-001 AUTH-002 AUTH-003 AUTH-004 PASSWD-001 ACL-001 ACL-001 SNMP-001 SNMP-001 "
      "SNMP-001 SNMP-002 SNMP-002 SNMP-002 LOG-001 NTP-001 INTF-001" },
    { "test_07_juniper_medium.conf", "juniper", "juniper-mx-datacenter", 45,
      "AUTH-002 AUTH-003 SNMP-001 SNMP-001 SNMP-002 SNMP-002 NTP-002" },
    { "test_08_fortinet_secure.conf", "fortinet", "fortinet-fg-secure", 85,
      "ACL-001" },
    { "test_09_fortinet_critical.conf", "fortinet", "fortinet-fg-critical", 4,
      "AUTH-001 AUTH-002 AUTH-003 PASSWD-001 ACL-001 SNMP-001 SNMP-001 SNMP-002 SNMP-002 "
      "SVC-001 LOG-001 LOG-002 NTP-001 INTF-001 INTF-001 INTF-001 INTF-001" },
    { "test_10_fortinet_medium.conf", "fortinet", "fortinet-branch-medium", 14,
      "AUTH-001 AUTH-002 AUTH-003 PASSWD-001 ACL-001 ACL-001 SNMP-001 SNMP-002 SVC-001 "
      "LOG-002 NTP-002" },
    { "edge/ios_bom_crlf.cfg", "cisco", "edge-ios", 50,
      "AUTH-004 ACL-001 ACL-002 SNMP-001 SNMP-002" },
    { "edge/junos_compact.conf", "juniper", "edge-junos", 100,
      "" },
    { "edge/fortios_nested.conf", "fortinet", "edge fortigate", 99,
      "NTP-002" },
    { "edge/long_line.cfg", "cisco", "long-line", 71,
      "AUTH-002 AUTH-004 SVC-002 LOG-001 LOG-002 NTP-001" },
};

static void every_fixture_matches_golden(void)
{
    static DeviceModel m;
    static AuditResult r;

    for (size_t i = 0; i < NA_ARRAY_LEN(k_golden); i++) {
        const Golden *g = &k_golden[i];
        bool ok = audit_fixture(g->file, &m, &r);
        check_impl(ok, g->file, __FILE__, __LINE__);
        if (!ok) continue;

        char ids[1024] = "";
        for (int f = 0; f < r.finding_count; f++) {
            if (f) safe_strcat(ids, sizeof(ids), " ");
            safe_strcat(ids, sizeof(ids), r.findings[f].rule->id);
        }
        check_str_impl(m.vendor, g->vendor, g->file, __FILE__, __LINE__);
        check_str_impl(model_hostname(&m), g->hostname, g->file, __FILE__, __LINE__);
        check_int_impl(r.score, g->score, g->file, __FILE__, __LINE__);
        check_str_impl(ids, g->rule_ids, g->file, __FILE__, __LINE__);
    }
}

void suite_regression(void)
{
    TEST(every_fixture_matches_golden);
}
