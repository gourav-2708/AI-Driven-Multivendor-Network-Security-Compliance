/**
 * @file test_engine.c
 * @brief Rule engine unit tests.
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "test_runner.h"
#include "engine.h"
#include "model.h"
#include "common.h"

static bool has_finding(const AuditResult *r, const char *rule_id) {
    for (int i = 0; i < r->finding_count; i++)
        if (strcmp(r->findings[i].rule_id, rule_id) == 0) return true;
    return false;
}

/* AUTH-001 */
static void test_auth001_triggers(void) {
    static DeviceModel m; model_init(&m);
    m.auth.enable_password_set = true; m.auth.enable_secret_set = false;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(has_finding(&r, "AUTH-001"));
}
static void test_auth001_passes(void) {
    static DeviceModel m; model_init(&m);
    m.auth.enable_secret_set = true; m.auth.enable_password_set = false;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(!has_finding(&r, "AUTH-001"));
}

/* AUTH-002 */
static void test_auth002_triggers(void) {
    static DeviceModel m; model_init(&m); m.auth.aaa_configured = false;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(has_finding(&r, "AUTH-002"));
}
static void test_auth002_passes(void) {
    static DeviceModel m; model_init(&m); m.auth.aaa_configured = true;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(!has_finding(&r, "AUTH-002"));
}

/* AUTH-003 */
static void test_auth003_triggers(void) {
    static DeviceModel m; model_init(&m); m.auth.telnet_on_vty = true;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(has_finding(&r, "AUTH-003"));
}
static void test_auth003_passes(void) {
    static DeviceModel m; model_init(&m);
    m.auth.telnet_on_vty = false; m.services.telnet_enabled = false;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(!has_finding(&r, "AUTH-003"));
}

/* AUTH-004 */
static void test_auth004_no_ssh(void) {
    static DeviceModel m; model_init(&m); m.auth.ssh_enabled = false;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(has_finding(&r, "AUTH-004"));
}
static void test_auth004_sshv2_ok(void) {
    static DeviceModel m; model_init(&m);
    m.auth.ssh_enabled = true; m.auth.ssh_version = 2;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(!has_finding(&r, "AUTH-004"));
}

/* PASSWD-001 */
static void test_passwd001_triggers(void) {
    static DeviceModel m; model_init(&m);
    m.auth.service_password_encrypt = false; m.auth.enable_password_set = true;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(has_finding(&r, "PASSWD-001"));
}
static void test_passwd001_passes(void) {
    static DeviceModel m; model_init(&m);
    m.auth.service_password_encrypt = true; m.auth.enable_secret_set = true;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(!has_finding(&r, "PASSWD-001"));
}

/* ACL-001 */
static void test_acl001_triggers(void) {
    static DeviceModel m; model_init(&m);
    m.acl_count = 1;
    strncpy(m.acls[0].name, "BAD", MAX_ACLNAME_LEN-1);
    m.acls[0].entry_count = 1;
    m.acls[0].entries[0].action = ACL_PERMIT;
    m.acls[0].entries[0].is_any_any = true;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(has_finding(&r, "ACL-001"));
}
static void test_acl001_passes(void) {
    static DeviceModel m; model_init(&m); m.acl_count = 0;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(!has_finding(&r, "ACL-001"));
}

/* ACL-002 */
static void test_acl002_triggers(void) {
    static DeviceModel m; model_init(&m);
    m.interface_count = 1;
    strncpy(m.interfaces[0].name, "mgmt0", MAX_IFNAME_LEN-1);
    m.interfaces[0].is_management = true;
    m.interfaces[0].shutdown = false;
    m.interfaces[0].acl_in[0] = '\0';
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(has_finding(&r, "ACL-002"));
}
static void test_acl002_passes(void) {
    static DeviceModel m; model_init(&m);
    m.interface_count = 1;
    strncpy(m.interfaces[0].name, "mgmt0", MAX_IFNAME_LEN-1);
    m.interfaces[0].is_management = true;
    strncpy(m.interfaces[0].acl_in, "MGMT_ACL", MAX_ACLNAME_LEN-1);
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(!has_finding(&r, "ACL-002"));
}

/* SNMP-001 */
static void test_snmp001_public(void) {
    static DeviceModel m; model_init(&m);
    m.snmp.enabled = true; m.snmp.version = SNMP_V2C;
    strncpy(m.snmp.community_ro, "public", MAX_COMMUNITY_LEN-1);
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(has_finding(&r, "SNMP-001"));
}
static void test_snmp001_v3_ok(void) {
    static DeviceModel m; model_init(&m);
    m.snmp.enabled = true; m.snmp.version = SNMP_V3;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(!has_finding(&r, "SNMP-001"));
}

/* LOG-001 */
static void test_log001_triggers(void) {
    static DeviceModel m; model_init(&m); m.logging.server_count = 0;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(has_finding(&r, "LOG-001"));
}
static void test_log001_passes(void) {
    static DeviceModel m; model_init(&m);
    m.logging.server_count = 1;
    strncpy(m.logging.servers[0], "10.0.0.1", MAX_IP_LEN-1);
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(!has_finding(&r, "LOG-001"));
}

/* NTP-001/002 */
static void test_ntp001_triggers(void) {
    static DeviceModel m; model_init(&m); m.ntp.server_count = 0;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(has_finding(&r, "NTP-001"));
}
static void test_ntp_both_ok(void) {
    static DeviceModel m; model_init(&m);
    m.ntp.server_count = 2;
    strncpy(m.ntp.servers[0], "1.1.1.1", MAX_IP_LEN-1);
    strncpy(m.ntp.servers[1], "2.2.2.2", MAX_IP_LEN-1);
    m.ntp.authenticated = true;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(!has_finding(&r, "NTP-001"));
    ASSERT(!has_finding(&r, "NTP-002"));
}
static void test_ntp002_no_auth(void) {
    static DeviceModel m; model_init(&m);
    m.ntp.server_count = 1;
    strncpy(m.ntp.servers[0], "1.1.1.1", MAX_IP_LEN-1);
    m.ntp.authenticated = false;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(has_finding(&r, "NTP-002"));
}

/* Score */
static void test_score_perfect(void) {
    static DeviceModel m; model_init(&m);
    m.auth.enable_secret_set        = true;
    m.auth.aaa_configured           = true;
    m.auth.ssh_enabled              = true; m.auth.ssh_version = 2;
    m.auth.service_password_encrypt = true;
    m.services.http_enabled         = false; m.services.https_enabled = true;
    m.services.cdp_global           = false;
    m.snmp.enabled = true; m.snmp.version = SNMP_V3;
    m.snmp.has_restricting_acl = true;
    m.logging.server_count = 1;
    strncpy(m.logging.servers[0], "10.0.0.1", MAX_IP_LEN-1);
    m.logging.buffered_enabled = true;
    m.ntp.server_count = 2;
    strncpy(m.ntp.servers[0], "1.1.1.1", MAX_IP_LEN-1);
    strncpy(m.ntp.servers[1], "2.2.2.2", MAX_IP_LEN-1);
    m.ntp.authenticated = true;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(r.sev_counts[SEV_CRITICAL] == 0);
    ASSERT(r.sev_counts[SEV_HIGH]     == 0);
    ASSERT(r.score > 80);
}
static void test_score_worst(void) {
    static DeviceModel m; model_init(&m);
    m.auth.enable_password_set = true;
    static AuditResult r; result_init(&r, &m); engine_run(&m, &r);
    ASSERT(r.score < 100);
    ASSERT(r.finding_count > 0);
}

int main(void)
{
    g_log_level = LOG_ERROR;
    test_register("auth001_triggers",      test_auth001_triggers);
    test_register("auth001_passes",        test_auth001_passes);
    test_register("auth002_triggers",      test_auth002_triggers);
    test_register("auth002_passes",        test_auth002_passes);
    test_register("auth003_triggers",      test_auth003_triggers);
    test_register("auth003_passes",        test_auth003_passes);
    test_register("auth004_no_ssh",        test_auth004_no_ssh);
    test_register("auth004_sshv2_ok",      test_auth004_sshv2_ok);
    test_register("passwd001_triggers",    test_passwd001_triggers);
    test_register("passwd001_passes",      test_passwd001_passes);
    test_register("acl001_triggers",       test_acl001_triggers);
    test_register("acl001_passes",         test_acl001_passes);
    test_register("acl002_triggers",       test_acl002_triggers);
    test_register("acl002_passes",         test_acl002_passes);
    test_register("snmp001_public",        test_snmp001_public);
    test_register("snmp001_v3_ok",         test_snmp001_v3_ok);
    test_register("log001_triggers",       test_log001_triggers);
    test_register("log001_passes",         test_log001_passes);
    test_register("ntp001_triggers",       test_ntp001_triggers);
    test_register("ntp_both_ok",           test_ntp_both_ok);
    test_register("ntp002_no_auth",        test_ntp002_no_auth);
    test_register("score_perfect",         test_score_perfect);
    test_register("score_worst",           test_score_worst);
    return test_run_all();
}

