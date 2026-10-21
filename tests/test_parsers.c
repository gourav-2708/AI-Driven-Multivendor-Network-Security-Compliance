/**
 * @file test_parsers.c
 * @brief Vendor detection and parser-to-model mapping.
 */
#include "harness.h"

#define SUITE "parsers"

static DeviceModel s_m;   /* large: static, reused by every test */

static const SnmpCommunity *community(const DeviceModel *m, const char *name)
{
    for (int i = 0; i < m->snmp.community_count; i++)
        if (strcmp(m->snmp.communities[i].name, name) == 0) return &m->snmp.communities[i];
    return NULL;
}

static const Interface *iface(const DeviceModel *m, const char *name)
{
    for (int i = 0; i < m->interface_count; i++)
        if (strcmp(m->interfaces[i].name, name) == 0) return &m->interfaces[i];
    return NULL;
}

static const AclEntry *acl_entry(const DeviceModel *m, const char *acl, int idx)
{
    for (int i = 0; i < m->acl_count; i++)
        if (strcmp(m->acls[i].name, acl) == 0 && idx < m->acls[i].entry_count)
            return &m->acls[i].entries[idx];
    return NULL;
}

/* -- Registry and detection ----------------------------------------------------- */

static void registry_has_builtins(void)
{
    CHECK_INT(parser_count(), 3);
    CHECK(parser_find("cisco") != NULL);
    CHECK(parser_find("JUNIPER") != NULL);       /* case-insensitive */
    CHECK(parser_find("fortinet") != NULL);
    CHECK(parser_find("arista") == NULL);
}

static void detects_every_fixture(void)
{
    static const struct { const char *file, *vendor; } k[] = {
        { "cisco_sample.cfg",             "cisco"    },
        { "test_01_cisco_secure.cfg",     "cisco"    },
        { "test_02_cisco_critical.cfg",   "cisco"    },
        { "test_03_cisco_medium.cfg",     "cisco"    },
        { "test_04_cisco_poor.cfg",       "cisco"    },
        { "juniper_sample.conf",          "juniper"  },
        { "test_05_juniper_secure.conf",  "juniper"  },
        { "test_06_juniper_critical.conf","juniper"  },
        { "test_07_juniper_medium.conf",  "juniper"  },
        { "fortinet_sample.conf",         "fortinet" },
        { "test_08_fortinet_secure.conf", "fortinet" },
        { "test_09_fortinet_critical.conf","fortinet"},
        { "test_10_fortinet_medium.conf", "fortinet" },
        { "edge/ios_bom_crlf.cfg",        "cisco"    },
        { "edge/junos_compact.conf",      "juniper"  },
        { "edge/fortios_nested.conf",     "fortinet" },
    };
    for (size_t i = 0; i < NA_ARRAY_LEN(k); i++) {
        const VendorParser *p = parser_detect(fixture(k[i].file), NULL);
        CHECK(p != NULL);
        if (p) CHECK_STR(p->name, k[i].vendor);
    }
}

static void rejects_unknown_and_missing(void)
{
    CHECK(parser_detect(fixture("edge/unknown_vendor.txt"), NULL) == NULL);
    CHECK(parser_detect(fixture("does-not-exist.cfg"), NULL) == NULL);
    CHECK(parser_find("cisco")->parse(fixture("does-not-exist.cfg"), &s_m) == AUDIT_ERR_IO);
}

/* -- Cisco IOS --------------------------------------------------------------------- */

static void cisco_sample_model(void)
{
    CHECK(load_fixture("cisco_sample.cfg", &s_m) != NULL);
    CHECK_STR(s_m.hostname, "core-router-01");
    CHECK_STR(s_m.vendor, "cisco");
    CHECK_STR(s_m.os_version, "15.7");

    CHECK(s_m.auth.enable_password_set);
    CHECK(!s_m.auth.enable_secret_set);
    CHECK(!s_m.auth.password_encryption);
    CHECK(!s_m.auth.aaa_configured);
    CHECK(s_m.auth.plaintext_user_password);
    CHECK(s_m.mgmt.telnet_enabled);
    CHECK(!s_m.mgmt.ssh_enabled);
    CHECK(s_m.mgmt.http_enabled);
    CHECK(s_m.services.cdp_global);
    CHECK(s_m.services.tcp_small_servers && s_m.services.udp_small_servers);

    CHECK_INT(s_m.snmp.community_count, 2);
    const SnmpCommunity *pub = community(&s_m, "public");
    const SnmpCommunity *prv = community(&s_m, "private");
    CHECK(pub && pub->access == SNMP_RO && !pub->restricted);
    CHECK(prv && prv->access == SNMP_RW);

    CHECK_INT(s_m.interface_count, 5);
    const Interface *g2 = iface(&s_m, "GigabitEthernet0/2");
    CHECK(g2 && g2->is_management);              /* by description */
    const Interface *g0 = iface(&s_m, "GigabitEthernet0/0");
    CHECK(g0 && strcmp(g0->description, "WAN Uplink") == 0);
    CHECK(g0 && strcmp(g0->acl_in, "INBOUND_WAN") == 0);
    const Interface *lo = iface(&s_m, "Loopback0");
    CHECK(lo && lo->is_loopback && !lo->is_management);

    const AclEntry *any = acl_entry(&s_m, "INSECURE_ACL", 0);
    CHECK(any && any->is_any_any && any->action == ACL_PERMIT);
    const AclEntry *host = acl_entry(&s_m, "INBOUND_WAN", 0);
    CHECK(host && !host->is_any_any);

    CHECK_INT(s_m.ntp.server_count, 0);
    CHECK_INT(s_m.logging.server_count, 0);
    CHECK(!s_m.logging.buffered_enabled);
}

static void cisco_secure_negations(void)
{
    CHECK(load_fixture("test_01_cisco_secure.cfg", &s_m) != NULL);
    CHECK(!s_m.services.cdp_global);             /* "no cdp run" */
    CHECK(!s_m.mgmt.http_enabled);               /* "no ip http server" */
    CHECK(s_m.mgmt.https_enabled);
    CHECK(!s_m.services.tcp_small_servers);
    CHECK_INT(s_m.mgmt.ssh_version, 2);
    CHECK_INT(s_m.logging.server_count, 1);      /* "logging host" form */
    CHECK_STR(s_m.logging.servers[0], "10.0.1.200");
    CHECK(s_m.ntp.authenticated);
    /* '!' inside a community string is data, not a comment */
    const SnmpCommunity *c = community(&s_m, "Xr7!mN2qP");
    CHECK(c && c->restricted);
}

static void cisco_bom_crlf_and_variants(void)
{
    CHECK(load_fixture("edge/ios_bom_crlf.cfg", &s_m) != NULL);
    CHECK_STR(s_m.hostname, "edge-ios");          /* BOM stripped, CR stripped */
    CHECK_INT(s_m.mgmt.ssh_version, 1);
    CHECK(!s_m.mgmt.telnet_enabled);
    CHECK_STR(s_m.logging.servers[0], "192.0.2.50");   /* logging host vrf X */
    CHECK_STR(s_m.ntp.servers[0], "192.0.2.10");        /* ntp server vrf X  */

    const Interface *g0 = iface(&s_m, "GigabitEthernet0/0");
    CHECK(g0 && strcmp(g0->description, "Uplink to core - primary") == 0);
    const Interface *mg = iface(&s_m, "Management1");
    CHECK(mg && mg->dynamic_address && mg->is_management);
    const Interface *g9 = iface(&s_m, "GigabitEthernet0/9");
    CHECK(g9 && g9->shutdown);

    const AclEntry *web = acl_entry(&s_m, "EDGE_IN", 0);   /* remark skipped */
    CHECK(web && web->action == ACL_PERMIT && !web->is_any_any);  /* port-limited */
    const AclEntry *std99 = acl_entry(&s_m, "99", 0);
    CHECK(std99 && std99->is_any_any);
}

static void cisco_long_line_truncated_safely(void)
{
    CHECK(load_fixture("edge/long_line.cfg", &s_m) != NULL);
    CHECK_STR(s_m.hostname, "long-line");
    const Interface *it = iface(&s_m, "GigabitEthernet0/1");
    CHECK(it != NULL);
    if (it) {
        CHECK_INT(strlen(it->description), NA_MAX_IFDESC - 1);
        CHECK_STR(it->ip_address, "10.0.0.1");  /* parsing resumes after it */
    }
}

/* -- Juniper JunOS ----------------------------------------------------------------- */

static void juniper_sample_model(void)
{
    CHECK(load_fixture("juniper_sample.conf", &s_m) != NULL);
    CHECK_STR(s_m.hostname, "edge-router-jnpr");
    CHECK_STR(s_m.vendor, "juniper");
    CHECK_STR(s_m.os_version, "21.4R3");
    CHECK(s_m.mgmt.telnet_enabled);
    CHECK(s_m.mgmt.ssh_enabled);
    CHECK(s_m.mgmt.http_enabled);
    CHECK(s_m.auth.aaa_configured);
    CHECK(s_m.auth.enable_password_set);
    CHECK(s_m.auth.local_users);
    CHECK(s_m.logging.buffered_enabled);
    CHECK_INT(s_m.logging.server_count, 0);

    const SnmpCommunity *pub = community(&s_m, "public");
    const SnmpCommunity *prv = community(&s_m, "private");
    CHECK(pub && pub->access == SNMP_RO);
    CHECK(prv && prv->access == SNMP_RW);

    /* Slash-containing names must survive intact (ge-0/0/0, not "ge-0"). */
    CHECK_INT(s_m.interface_count, 5);
    const Interface *ge0 = iface(&s_m, "ge-0/0/0");
    CHECK(ge0 && strcmp(ge0->acl_in, "WAN_FILTER") == 0);
    CHECK(ge0 && strcmp(ge0->ip_address, "203.0.113.5") == 0);
    CHECK(ge0 && strcmp(ge0->subnet_mask, "30") == 0);
    const Interface *me0 = iface(&s_m, "me0");
    CHECK(me0 && me0->is_management);
    const Interface *ge2 = iface(&s_m, "ge-0/0/2");
    CHECK(ge2 && ge2->ip_address[0] == '\0');

    const AclEntry *est = acl_entry(&s_m, "WAN_FILTER", 0);
    const AclEntry *all = acl_entry(&s_m, "WAN_FILTER", 1);
    const AclEntry *dny = acl_entry(&s_m, "WAN_FILTER", 2);
    CHECK(est && est->action == ACL_PERMIT && !est->is_any_any);  /* has "from" */
    CHECK(all && all->is_any_any);
    CHECK(dny && dny->action == ACL_DENY);
}

static void juniper_compact_syntax(void)
{
    CHECK(load_fixture("edge/junos_compact.conf", &s_m) != NULL);
    CHECK_STR(s_m.hostname, "edge-junos");
    CHECK(!s_m.mgmt.telnet_enabled);             /* "inactive: telnet" */
    CHECK(s_m.mgmt.ssh_enabled);
    CHECK(s_m.mgmt.https_enabled && !s_m.mgmt.http_enabled);
    CHECK(s_m.auth.aaa_configured);
    CHECK(s_m.ntp.authenticated);
    const SnmpCommunity *c = community(&s_m, "Ab3$xY9!kLmn");
    CHECK(c && c->restricted);
    const Interface *ge1 = iface(&s_m, "ge-0/0/1");
    CHECK(ge1 && ge1->shutdown);
    const Interface *fxp = iface(&s_m, "fxp0");
    CHECK(fxp && fxp->is_management && strcmp(fxp->acl_in, "MGMT_IN") == 0);
}

static void juniper_srx_policies(void)
{
    CHECK(load_fixture("test_06_juniper_critical.conf", &s_m) != NULL);
    const AclEntry *e1 = acl_entry(&s_m, "policy permit-all", 0);
    const AclEntry *e2 = acl_entry(&s_m, "policy permit-all", 1);
    CHECK(e1 && e1->is_any_any);
    CHECK(e2 && e2->is_any_any);
    CHECK(s_m.auth.enable_password_set);         /* plain-text-password-value */
    CHECK(!s_m.mgmt.ssh_enabled);
}

static void juniper_ignores_routing_policy_terms(void)
{
    CHECK(load_fixture("test_07_juniper_medium.conf", &s_m) != NULL);
    CHECK_INT(s_m.acl_count, 0);                  /* policy-options is not a filter */
    CHECK_INT(s_m.ntp.server_count, 2);
}

/* -- Fortinet FortiOS ------------------------------------------------------------- */

static void fortinet_sample_model(void)
{
    CHECK(load_fixture("fortinet_sample.conf", &s_m) != NULL);
    CHECK_STR(s_m.hostname, "FortiGate-Branch");
    CHECK_STR(s_m.vendor, "fortinet");
    CHECK(s_m.auth.enable_password_set);
    CHECK(s_m.mgmt.telnet_enabled);
    CHECK(s_m.mgmt.http_enabled);                /* "https ssh http": order-safe */
    CHECK(s_m.mgmt.https_enabled);
    CHECK(s_m.snmp.v1_enabled);
    const SnmpCommunity *pub = community(&s_m, "public");
    CHECK(pub && !pub->restricted);
    CHECK_INT(s_m.logging.server_count, 0);      /* syslogd status disable */
    CHECK_INT(s_m.ntp.server_count, 0);
    const Interface *mgmt = iface(&s_m, "mgmt");
    CHECK(mgmt && mgmt->is_management);
    const Interface *dmz = iface(&s_m, "dmz");
    CHECK(dmz && dmz->ip_address[0] == '\0');
}

static void fortinet_secure_nested_sections(void)
{
    CHECK(load_fixture("test_08_fortinet_secure.conf", &s_m) != NULL);
    CHECK(!s_m.mgmt.telnet_enabled);             /* admin-telnet-port 0 */
    CHECK(s_m.auth.aaa_configured);              /* remote-auth enable */
    CHECK(s_m.logging.buffered_enabled);         /* log memory setting */
    CHECK_INT(s_m.logging.server_count, 1);
    CHECK_STR(s_m.ntp.servers[0], "10.30.1.100"); /* config ntpserver (nested) */
    CHECK(s_m.ntp.authenticated);
    const SnmpCommunity *c = community(&s_m, "FG!SecureSNMP2024");
    CHECK(c && c->restricted);                   /* config hosts (nested) */

    const AclEntry *allow = acl_entry(&s_m, "policy 1 (LAN-to-WAN)", 0);
    const AclEntry *deny  = acl_entry(&s_m, "policy 2 (Deny-All-Inbound)", 0);
    CHECK(allow && allow->is_any_any);
    CHECK(deny && deny->action == ACL_DENY && !deny->is_any_any);
}

static void fortinet_edge_cases(void)
{
    CHECK(load_fixture("edge/fortios_nested.conf", &s_m) != NULL);
    CHECK_STR(s_m.hostname, "edge fortigate");    /* quoted, with a space */
    CHECK(s_m.auth.enable_secret_set && !s_m.auth.enable_password_set);  /* ENC */
    CHECK(s_m.auth.aaa_configured);              /* config user radius */
    CHECK_INT(s_m.snmp.community_count, 1);      /* disabled one skipped */
    CHECK_INT(s_m.logging.server_count, 1);
    CHECK_STR(s_m.logging.servers[0], "192.0.2.51");
    CHECK_STR(s_m.ntp.servers[0], "fortiguard");
    const Interface *p2 = iface(&s_m, "port2");
    CHECK(p2 && p2->dynamic_address);
    CHECK(acl_entry(&s_m, "policy 11 (disabled-open)", 0) == NULL);
    const AclEntry *web = acl_entry(&s_m, "policy 12 (web-only)", 0);
    CHECK(web && web->action == ACL_PERMIT && !web->is_any_any);
}

void suite_parsers(void)
{
    TEST(registry_has_builtins);
    TEST(detects_every_fixture);
    TEST(rejects_unknown_and_missing);
    TEST(cisco_sample_model);
    TEST(cisco_secure_negations);
    TEST(cisco_bom_crlf_and_variants);
    TEST(cisco_long_line_truncated_safely);
    TEST(juniper_sample_model);
    TEST(juniper_compact_syntax);
    TEST(juniper_srx_policies);
    TEST(juniper_ignores_routing_policy_terms);
    TEST(fortinet_sample_model);
    TEST(fortinet_secure_nested_sections);
    TEST(fortinet_edge_cases);
}
