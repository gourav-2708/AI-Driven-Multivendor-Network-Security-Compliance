/**
 * @file test_rules.c
 * @brief Every rule against synthetic models: one case that must trigger,
 *        one that must not. Plus the rule catalogue and scoring.
 */
#include "harness.h"

#define SUITE "rules"

static DeviceModel s_m;
static AuditResult s_r;

/* A model that violates nothing; tests flip one thing at a time. */
static DeviceModel *clean_model(void)
{
    DeviceModel *m = &s_m;
    model_init(m);
    safe_strcpy(m->hostname, sizeof(m->hostname), "unit");
    m->auth.aaa_configured      = true;
    m->auth.enable_secret_set   = true;
    m->auth.password_encryption = true;
    m->mgmt.ssh_enabled         = true;
    m->mgmt.ssh_version         = 2;
    m->mgmt.https_enabled       = true;
    m->logging.buffered_enabled = true;
    model_add_log_server(m, "192.0.2.50");
    model_add_ntp_server(m, "192.0.2.10");
    m->ntp.authenticated = true;
    return m;
}

static int run(const char *rule_id)
{
    engine_run(&s_m, &s_r);
    return count_rule(&s_r, rule_id);
}

static void catalogue_is_complete(void)
{
    static const char *const ids[] = {
        "AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "PASSWD-001",
        "ACL-001", "ACL-002", "SNMP-001", "SNMP-002", "SVC-001", "SVC-002",
        "SVC-003", "LOG-001", "LOG-002", "NTP-001", "NTP-002", "INTF-001",
    };
    CHECK_INT(rules_count(), NA_ARRAY_LEN(ids));
    for (size_t i = 0; i < NA_ARRAY_LEN(ids); i++) {
        const Rule *r = rules_at(i);
        CHECK(r != NULL);
        if (!r) continue;
        CHECK_STR(r->id, ids[i]);                 /* stable report order */
        CHECK(r->check && r->title && r->description && r->remediation);
        CHECK(str_starts_with(r->id, rule_category_code(r->category)));
    }
    CHECK(rules_find("snmp-002") == rules_at(8));
    CHECK(rules_find("NOPE-001") == NULL);
}

static void clean_model_has_no_findings(void)
{
    clean_model();
    engine_run(&s_m, &s_r);
    CHECK_INT(s_r.finding_count, 0);
    CHECK_INT(s_r.score, 100);
}

static void auth_rules(void)
{
    clean_model()->auth.enable_password_set = true;
    CHECK_INT(run("AUTH-001"), 0);                /* secret also set */
    s_m.auth.enable_secret_set = false;
    CHECK_INT(run("AUTH-001"), 1);

    clean_model()->auth.aaa_configured = false;
    CHECK_INT(run("AUTH-002"), 1);

    clean_model()->mgmt.telnet_enabled = true;
    CHECK_INT(run("AUTH-003"), 1);

    clean_model()->mgmt.ssh_enabled = false;
    CHECK_INT(run("AUTH-004"), 1);
    CHECK(s_r.findings[0].severity == SEV_HIGH);
}

static void ssh_v1_is_medium_variant(void)
{
    clean_model()->mgmt.ssh_version = 1;
    CHECK_INT(run("AUTH-004"), 1);
    CHECK(s_r.findings[0].severity == SEV_MEDIUM);
    CHECK(str_contains_ci(s_r.findings[0].description, "SSHv1"));
    CHECK_INT(s_r.sev_counts[SEV_MEDIUM], 1);
}

static void passwd_rule(void)
{
    clean_model()->auth.plaintext_user_password = true;
    CHECK_INT(run("PASSWD-001"), 0);              /* encryption on */
    s_m.auth.password_encryption = false;
    CHECK_INT(run("PASSWD-001"), 1);
    clean_model()->auth.password_encryption = false;
    CHECK_INT(run("PASSWD-001"), 0);              /* nothing plaintext */
}

static void acl_rules(void)
{
    DeviceModel *m = clean_model();
    Acl *acl = model_acl(m, "EDGE");
    AclEntry *a = model_acl_add_entry(m, acl);
    a->action = ACL_PERMIT;
    AclEntry *b = model_acl_add_entry(m, acl);
    b->action = ACL_PERMIT; b->is_any_any = true; b->line_number = 7;
    AclEntry *c = model_acl_add_entry(m, acl);
    c->action = ACL_DENY;   c->is_any_any = true;   /* deny any any is fine */
    CHECK_INT(run("ACL-001"), 1);
    CHECK_STR(s_r.findings[0].section, "ACL 'EDGE' entry 2 (line 7)");
    CHECK_INT(s_r.findings[0].line_number, 7);

    m = clean_model();
    Interface *mg = model_interface(m, "mgmt0");
    mg->is_management = true;
    CHECK_INT(run("ACL-002"), 1);
    safe_strcpy(mg->acl_in, sizeof(mg->acl_in), "MGMT_IN");
    CHECK_INT(run("ACL-002"), 0);
    mg->acl_in[0] = '\0';
    mg->shutdown = true;
    CHECK_INT(run("ACL-002"), 0);
}

static void snmp_rules(void)
{
    static const struct { const char *name; bool weak; } k[] = {
        { "public", true }, { "PRIVATE", true }, { "short1!", true },
        { "companyRO", true },                  /* only 2 character classes */
        { "Xr7!mN2qP", false }, { "FG!SecureSNMP2024", false },
        { "lowercaseonly123", true }, { "Mixed-Case-Words", false },
    };
    for (size_t i = 0; i < NA_ARRAY_LEN(k); i++) {
        SnmpCommunity *c = model_snmp_community(clean_model(), k[i].name);
        c->restricted = true;
        CHECK_INT(run("SNMP-001"), k[i].weak ? 1 : 0);
        CHECK_INT(run("SNMP-002"), 0);
    }

    model_snmp_community(clean_model(), "Unrestricted#99");
    CHECK_INT(run("SNMP-002"), 1);
    /* Custom community strings are credentials: never printed in full. */
    CHECK(strstr(s_r.findings[0].section, "Unrestricted#99") == NULL);
    CHECK(strstr(s_r.findings[0].section, "Un***") != NULL);
}

static void service_rules(void)
{
    clean_model()->mgmt.http_enabled = true;
    CHECK_INT(run("SVC-001"), 1);                 /* even with HTTPS on */
    clean_model()->services.cdp_global = true;
    CHECK_INT(run("SVC-002"), 1);
    clean_model()->services.udp_small_servers = true;
    CHECK_INT(run("SVC-003"), 1);
    CHECK_STR(s_r.findings[0].section, "service udp-small-servers");
}

static void logging_and_ntp_rules(void)
{
    clean_model()->logging.server_count = 0;
    CHECK_INT(run("LOG-001"), 1);
    clean_model()->logging.buffered_enabled = false;
    CHECK_INT(run("LOG-002"), 1);
    clean_model()->ntp.server_count = 0;
    CHECK_INT(run("NTP-001"), 1);
    CHECK_INT(run("NTP-002"), 0);                 /* nothing to authenticate */
    clean_model()->ntp.authenticated = false;
    CHECK_INT(run("NTP-002"), 1);
}

static void interface_rule(void)
{
    DeviceModel *m = clean_model();
    model_interface(m, "Gi0/1");                                 /* bare: flagged */
    safe_strcpy(model_interface(m, "Gi0/2")->description, NA_MAX_IFDESC, "x");
    model_interface(m, "Gi0/3")->shutdown = true;
    model_interface(m, "Gi0/4")->dynamic_address = true;
    model_interface(m, "Loopback0");
    CHECK_INT(run("INTF-001"), 1);
    CHECK_STR(s_r.findings[0].section, "interface 'Gi0/1'");
}

static void model_capacity_is_enforced(void)
{
    DeviceModel *m = clean_model();
    for (int i = 0; i < NA_MAX_INTERFACES; i++) {
        char name[16];
        safe_snprintf(name, sizeof(name), "e%d", i);
        model_interface(m, name);
    }
    CHECK(model_interface(m, "one-too-many") == NULL);
    CHECK_INT(m->overflow_count, 1);
    CHECK_INT(run("INTF-001"), NA_MAX_INTERFACES);
}

static void scoring(void)
{
    int none[SEV_COUNT] = { 0, 0, 0, 0 };
    int one_each[SEV_COUNT] = { 1, 1, 1, 1 };
    int many[SEV_COUNT] = { 10, 10, 10, 10 };
    int capped_low[SEV_COUNT] = { 0, 0, 0, 50 };
    CHECK_INT(score_compute(none), 100);
    CHECK_INT(score_compute(one_each), 100 - 15 - 8 - 4 - 1);
    CHECK_INT(score_compute(many), 0);
    CHECK_INT(score_compute(capped_low), 96);   /* LOW capped at 4 */

    int per, cap;
    score_penalty(SEV_CRITICAL, &per, &cap);
    CHECK_INT(per, 15);
    CHECK_INT(cap, 60);
}

void suite_rules(void)
{
    TEST(catalogue_is_complete);
    TEST(clean_model_has_no_findings);
    TEST(auth_rules);
    TEST(ssh_v1_is_medium_variant);
    TEST(passwd_rule);
    TEST(acl_rules);
    TEST(snmp_rules);
    TEST(service_rules);
    TEST(logging_and_ntp_rules);
    TEST(interface_rule);
    TEST(model_capacity_is_enforced);
    TEST(scoring);
}
