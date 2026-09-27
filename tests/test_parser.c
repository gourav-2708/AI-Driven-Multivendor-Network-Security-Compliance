/**
 * @file test_parser.c
 * @brief Parser unit tests.
 */

#include <stdio.h>
#include <string.h>
#include "test_runner.h"
#include "parser.h"
#include "model.h"
#include "common.h"

static const char *fixture(const char *name)
{
    static char path[512];
    snprintf(path, sizeof(path), "fixtures/%s", name);
    FILE *f = fopen(path, "r");
    if (f) { fclose(f); return path; }
    snprintf(path, sizeof(path), "../fixtures/%s", name);
    f = fopen(path, "r");
    if (f) { fclose(f); return path; }
    snprintf(path, sizeof(path), "fixtures/%s", name);
    return path;
}

/* -- Cisco tests ----------------------------------------------------------- */
static void test_cisco_detect(void) {
    cisco_parser_register();
    const VendorParser *p = parser_find_by_vendor("cisco");
    ASSERT(p != NULL);
    ASSERT(p->detect(fixture("cisco_sample.cfg")));
}

static void test_cisco_hostname(void) {
    const VendorParser *p = parser_find_by_vendor("cisco");
    ASSERT(p != NULL);
    static DeviceModel m; model_init(&m);
    int rc = p->parse(fixture("cisco_sample.cfg"), &m);
    ASSERT_INT_EQ(rc, AUDIT_OK);
    ASSERT_STR_EQ(m.hostname, "core-router-01");
    ASSERT_STR_EQ(m.vendor,   "cisco");
}

static void test_cisco_auth_flags(void) {
    const VendorParser *p = parser_find_by_vendor("cisco");
    static DeviceModel m; model_init(&m);
    p->parse(fixture("cisco_sample.cfg"), &m);
    ASSERT(m.auth.enable_password_set);
    ASSERT(!m.auth.enable_secret_set);
    ASSERT(!m.auth.service_password_encrypt);
    ASSERT(!m.auth.aaa_configured);
    ASSERT(m.auth.telnet_on_vty);
}

static void test_cisco_snmp(void) {
    const VendorParser *p = parser_find_by_vendor("cisco");
    static DeviceModel m; model_init(&m);
    p->parse(fixture("cisco_sample.cfg"), &m);
    ASSERT(m.snmp.enabled);
    ASSERT_STR_EQ(m.snmp.community_ro, "public");
    ASSERT_STR_EQ(m.snmp.community_rw, "private");
    ASSERT(!m.snmp.has_restricting_acl);
}

static void test_cisco_interfaces(void) {
    const VendorParser *p = parser_find_by_vendor("cisco");
    static DeviceModel m; model_init(&m);
    p->parse(fixture("cisco_sample.cfg"), &m);
    ASSERT(m.interface_count >= 3);
}

static void test_cisco_acl_any_any(void) {
    const VendorParser *p = parser_find_by_vendor("cisco");
    static DeviceModel m; model_init(&m);
    p->parse(fixture("cisco_sample.cfg"), &m);
    bool found = false;
    for (int i = 0; i < m.acl_count; i++) {
        if (strcmp(m.acls[i].name, "INSECURE_ACL") == 0) {
            for (int j = 0; j < m.acls[i].entry_count; j++)
                if (m.acls[i].entries[j].is_any_any) found = true;
        }
    }
    ASSERT(found);
}

static void test_cisco_services(void) {
    const VendorParser *p = parser_find_by_vendor("cisco");
    static DeviceModel m; model_init(&m);
    p->parse(fixture("cisco_sample.cfg"), &m);
    ASSERT(m.services.http_enabled);
    ASSERT(!m.services.https_enabled);
    ASSERT(m.services.tcp_small_servers);
    ASSERT(m.services.udp_small_servers);
}

static void test_cisco_ntp_logging(void) {
    const VendorParser *p = parser_find_by_vendor("cisco");
    static DeviceModel m; model_init(&m);
    p->parse(fixture("cisco_sample.cfg"), &m);
    ASSERT_INT_EQ(m.ntp.server_count, 0);
    ASSERT_INT_EQ(m.logging.server_count, 0);
    ASSERT(!m.logging.buffered_enabled);
}

/* -- Juniper tests ---------------------------------------------------------- */
static void test_juniper_detect(void) {
    juniper_parser_register();
    const VendorParser *p = parser_find_by_vendor("juniper");
    ASSERT(p != NULL);
    ASSERT(p->detect(fixture("juniper_sample.conf")));
}

static void test_juniper_hostname(void) {
    const VendorParser *p = parser_find_by_vendor("juniper");
    static DeviceModel m; model_init(&m);
    int rc = p->parse(fixture("juniper_sample.conf"), &m);
    ASSERT_INT_EQ(rc, AUDIT_OK);
    ASSERT_STR_EQ(m.hostname, "edge-router-jnpr");
    ASSERT_STR_EQ(m.vendor,   "juniper");
}

static void test_juniper_telnet(void) {
    const VendorParser *p = parser_find_by_vendor("juniper");
    static DeviceModel m; model_init(&m);
    p->parse(fixture("juniper_sample.conf"), &m);
    ASSERT(m.auth.telnet_on_vty);
    ASSERT(m.auth.ssh_enabled);
}

static void test_juniper_snmp(void) {
    const VendorParser *p = parser_find_by_vendor("juniper");
    static DeviceModel m; model_init(&m);
    p->parse(fixture("juniper_sample.conf"), &m);
    ASSERT(m.snmp.enabled);
    ASSERT_STR_EQ(m.snmp.community_ro, "public");
}

static void test_juniper_interfaces(void) {
    const VendorParser *p = parser_find_by_vendor("juniper");
    static DeviceModel m; model_init(&m);
    p->parse(fixture("juniper_sample.conf"), &m);
    ASSERT(m.interface_count >= 3);
    bool found_me0 = false;
    for (int i = 0; i < m.interface_count; i++)
        if (strcmp(m.interfaces[i].name, "me0") == 0) found_me0 = true;
    ASSERT(found_me0);
}

/* -- Fortinet tests --------------------------------------------------------- */
static void test_fortinet_detect(void) {
    fortinet_parser_register();
    const VendorParser *p = parser_find_by_vendor("fortinet");
    ASSERT(p != NULL);
    ASSERT(p->detect(fixture("fortinet_sample.conf")));
}

static void test_fortinet_hostname(void) {
    const VendorParser *p = parser_find_by_vendor("fortinet");
    static DeviceModel m; model_init(&m);
    int rc = p->parse(fixture("fortinet_sample.conf"), &m);
    ASSERT_INT_EQ(rc, AUDIT_OK);
    ASSERT_STR_EQ(m.hostname, "FortiGate-Branch");
    ASSERT_STR_EQ(m.vendor,   "fortinet");
}

static void test_fortinet_auth(void) {
    const VendorParser *p = parser_find_by_vendor("fortinet");
    static DeviceModel m; model_init(&m);
    p->parse(fixture("fortinet_sample.conf"), &m);
    ASSERT(m.auth.enable_password_set);
}

static void test_fortinet_snmp(void) {
    const VendorParser *p = parser_find_by_vendor("fortinet");
    static DeviceModel m; model_init(&m);
    p->parse(fixture("fortinet_sample.conf"), &m);
    ASSERT(m.snmp.enabled);
    ASSERT_STR_EQ(m.snmp.community_ro, "public");
}

static void test_fortinet_services(void) {
    const VendorParser *p = parser_find_by_vendor("fortinet");
    static DeviceModel m; model_init(&m);
    p->parse(fixture("fortinet_sample.conf"), &m);
    ASSERT(m.services.http_enabled || m.auth.telnet_on_vty);
}

/* -- Auto-detect tests ----------------------------------------------------- */
static void test_auto_detect_cisco(void) {
    cisco_parser_register();
    juniper_parser_register();
    fortinet_parser_register();
    const VendorParser *p = parser_detect(fixture("cisco_sample.cfg"));
    ASSERT(p != NULL);
    ASSERT_STR_EQ(p->vendor_name, "cisco");
}

static void test_auto_detect_juniper(void) {
    const VendorParser *p = parser_detect(fixture("juniper_sample.conf"));
    ASSERT(p != NULL);
    ASSERT_STR_EQ(p->vendor_name, "juniper");
}

static void test_auto_detect_fortinet(void) {
    const VendorParser *p = parser_detect(fixture("fortinet_sample.conf"));
    ASSERT(p != NULL);
    ASSERT_STR_EQ(p->vendor_name, "fortinet");
}

/* -- main ------------------------------------------------------------------- */
int main(void)
{
    g_log_level = LOG_ERROR;

    test_register("cisco_detect",          test_cisco_detect);
    test_register("cisco_hostname",        test_cisco_hostname);
    test_register("cisco_auth_flags",      test_cisco_auth_flags);
    test_register("cisco_snmp",            test_cisco_snmp);
    test_register("cisco_interfaces",      test_cisco_interfaces);
    test_register("cisco_acl_any_any",     test_cisco_acl_any_any);
    test_register("cisco_services",        test_cisco_services);
    test_register("cisco_ntp_logging",     test_cisco_ntp_logging);
    test_register("juniper_detect",        test_juniper_detect);
    test_register("juniper_hostname",      test_juniper_hostname);
    test_register("juniper_telnet",        test_juniper_telnet);
    test_register("juniper_snmp",          test_juniper_snmp);
    test_register("juniper_interfaces",    test_juniper_interfaces);
    test_register("fortinet_detect",       test_fortinet_detect);
    test_register("fortinet_hostname",     test_fortinet_hostname);
    test_register("fortinet_auth",         test_fortinet_auth);
    test_register("fortinet_snmp",         test_fortinet_snmp);
    test_register("fortinet_services",     test_fortinet_services);
    test_register("auto_detect_cisco",     test_auto_detect_cisco);
    test_register("auto_detect_juniper",   test_auto_detect_juniper);
    test_register("auto_detect_fortinet",  test_auto_detect_fortinet);

    return test_run_all();
}

