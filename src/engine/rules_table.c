/**
 * @file rules_table.c
 * @brief Data-driven rules table — all 16 compliance rules.
 *
 * Each Rule entry contains: rule_id, severity, description, remediation
 * guidance, and a check function.  The check function receives the
 * DeviceModel and returns true (plus fills a Finding) when the rule is
 * violated.
 *
 * To add a new rule:
 *   1. Implement a static check function (CheckFn signature).
 *   2. Add a Rule entry to the s_rules[] array below.
 *   3. Recompile — no other files need changing.
 */

#include <string.h>
#include <stdio.h>
#include "engine.h"
#include "model.h"
#include "common.h"

/* -- Convenience macro to fill a Finding ---------------------------------- */
#define FILL_FINDING(f, rid, sev, desc, section, rem) do { \
    safe_strncpy((f)->rule_id,          (rid),  MAX_RULE_ID_LEN);   \
    (f)->severity = (sev);                                           \
    safe_strncpy((f)->description,      (desc), MAX_DESC_LEN);      \
    safe_strncpy((f)->affected_section, (section), MAX_SECTION_LEN);\
    safe_strncpy((f)->remediation,      (rem),  MAX_REMEDIATION_LEN);\
    (f)->line_number = -1;                                           \
} while(0)

/* ======================================================================== */
/*  AUTH rules                                                               */
/* ======================================================================== */

static bool check_AUTH001(const DeviceModel *m, struct AuditResult *r,
                           Finding *out)
{
    (void)r;
    /* Plaintext enable password without enable secret */
    if (m->auth.enable_password_set && !m->auth.enable_secret_set) {
        FILL_FINDING(out, "AUTH-001", SEV_CRITICAL,
            "Plaintext 'enable password' set without 'enable secret'",
            "auth / enable password",
            "Replace 'enable password' with 'enable secret <hash>'. "
            "Enable secret uses MD5 hashing and cannot be read from config. "
            "Also enable 'service password-encryption'.");
        return true;
    }
    return false;
}

static bool check_AUTH002(const DeviceModel *m, struct AuditResult *r,
                           Finding *out)
{
    (void)r;
    if (!m->auth.aaa_configured) {
        FILL_FINDING(out, "AUTH-002", SEV_HIGH,
            "AAA (Authentication, Authorization, Accounting) not configured",
            "auth / aaa",
            "Configure 'aaa new-model' and define authentication/authorization "
            "method lists for login and exec. Use RADIUS or TACACS+ for "
            "centralised accounting.");
        return true;
    }
    return false;
}

static bool check_AUTH003(const DeviceModel *m, struct AuditResult *r,
                           Finding *out)
{
    (void)r;
    if (m->auth.telnet_on_vty || m->services.telnet_enabled) {
        FILL_FINDING(out, "AUTH-003", SEV_HIGH,
            "Telnet permitted on VTY lines (cleartext management access)",
            "auth / line vty / transport input",
            "Set 'transport input ssh' on all VTY lines and disable Telnet "
            "globally. Ensure SSH version 2 is configured with RSA keys >= 2048 bits.");
        return true;
    }
    return false;
}

static bool check_AUTH004(const DeviceModel *m, struct AuditResult *r,
                           Finding *out)
{
    (void)r;
    if (!m->auth.ssh_enabled) {
        FILL_FINDING(out, "AUTH-004", SEV_HIGH,
            "SSH not enabled; no encrypted management access configured",
            "auth / ssh",
            "Enable SSHv2: 'ip ssh version 2', generate RSA keys with "
            "'crypto key generate rsa modulus 4096', and restrict VTY "
            "lines to 'transport input ssh'.");
        return true;
    }
    if (m->auth.ssh_enabled && m->auth.ssh_version == 1) {
        FILL_FINDING(out, "AUTH-004", SEV_MEDIUM,
            "SSHv1 configured; SSHv1 is cryptographically broken",
            "auth / ssh version",
            "Upgrade to 'ip ssh version 2'. SSHv1 is vulnerable to "
            "man-in-the-middle and protocol downgrade attacks.");
        return true;
    }
    return false;
}

/* ======================================================================== */
/*  PASSWD rules                                                             */
/* ======================================================================== */

static bool check_PASSWD001(const DeviceModel *m, struct AuditResult *r,
                             Finding *out)
{
    (void)r;
    if (!m->auth.service_password_encrypt &&
        (m->auth.enable_password_set || m->auth.local_users_configured)) {
        FILL_FINDING(out, "PASSWD-001", SEV_CRITICAL,
            "Passwords may be stored in plaintext: 'service password-encryption' not enabled",
            "service password-encryption",
            "Enable 'service password-encryption' to apply type-7 obfuscation "
            "as a minimum. Prefer 'enable secret' (MD5) or type-9 secrets where "
            "supported. Audit all user accounts and remove default credentials.");
        return true;
    }
    return false;
}

/* ======================================================================== */
/*  ACL rules                                                                */
/* ======================================================================== */

static bool check_ACL001(const DeviceModel *m, struct AuditResult *r,
                          Finding *out)
{
    for (int i = 0; i < m->acl_count; i++) {
        for (int j = 0; j < m->acls[i].entry_count; j++) {
            const AclEntry *ae = &m->acls[i].entries[j];
            if (ae->action == ACL_PERMIT && ae->is_any_any) {
                char section[MAX_SECTION_LEN];
                safe_snprintf(section, sizeof(section),
                              "ACL '%s' entry %d (line %d)",
                              m->acls[i].name, j + 1, ae->line_number);
                FILL_FINDING(out, "ACL-001", SEV_CRITICAL,
                    "ACL contains unrestricted 'permit any any' (allows all traffic)",
                    section,
                    "Remove or replace 'permit any any' entries with specific "
                    "source/destination/port rules. Apply a default-deny policy "
                    "at the end of all ACLs. Review and document all permit rules.");
                engine_add_finding(r, out);
                /* continue checking other ACLs */
            }
        }
    }
    return false; /* findings added directly via engine_add_finding */
}

static bool check_ACL002(const DeviceModel *m, struct AuditResult *r,
                          Finding *out)
{
    /* Check management interfaces for missing inbound ACL */
    for (int i = 0; i < m->interface_count; i++) {
        const Interface *iface = &m->interfaces[i];
        if (!iface->shutdown && iface->is_management &&
            iface->acl_in[0] == '\0') {
            char section[MAX_SECTION_LEN];
            safe_snprintf(section, sizeof(section),
                          "interface '%s'", iface->name);
            FILL_FINDING(out, "ACL-002", SEV_HIGH,
                "Management interface has no inbound ACL applied",
                section,
                "Apply an inbound ACL to all management interfaces that "
                "restricts access to known management hosts and permits only "
                "required management protocols (SSH, SNMP, HTTPS).");
            engine_add_finding(r, out);
        }
    }
    (void)r; /* suppress if no findings added */
    return false;
}

/* ======================================================================== */
/*  SNMP rules                                                               */
/* ======================================================================== */

static bool check_SNMP001(const DeviceModel *m, struct AuditResult *r,
                           Finding *out)
{
    (void)r;
    if (!m->snmp.enabled) return false;

    bool default_comm = (portable_strcasecmp(m->snmp.community_ro, "public")  == 0 ||
                         portable_strcasecmp(m->snmp.community_ro, "private") == 0 ||
                         portable_strcasecmp(m->snmp.community_rw, "public")  == 0 ||
                         portable_strcasecmp(m->snmp.community_rw, "private") == 0);

    bool insecure_ver = (m->snmp.version == SNMP_V1 ||
                         m->snmp.version == SNMP_V2C);

    if (default_comm || (insecure_ver && m->snmp.community_ro[0])) {
        char section[MAX_SECTION_LEN];
        safe_snprintf(section, sizeof(section),
            "snmp / community '%s'",
            m->snmp.community_ro[0] ? m->snmp.community_ro : m->snmp.community_rw);
        FILL_FINDING(out, "SNMP-001", SEV_CRITICAL,
            "SNMPv1/v2c with default or weak community strings ('public'/'private')",
            section,
            "Replace default community strings with strong, random strings. "
            "Migrate to SNMPv3 with authentication (SHA) and privacy (AES-128+). "
            "Remove SNMPv1/v2c configurations once SNMPv3 is working.");
        return true;
    }
    return false;
}

static bool check_SNMP002(const DeviceModel *m, struct AuditResult *r,
                           Finding *out)
{
    (void)r;
    if (!m->snmp.enabled) return false;

    if (!m->snmp.has_restricting_acl && m->snmp.version != SNMP_V3) {
        FILL_FINDING(out, "SNMP-002", SEV_HIGH,
            "SNMP enabled without a restricting ACL",
            "snmp-server / access-list",
            "Apply an ACL to the SNMP server configuration to restrict "
            "queries to known NMS hosts. On Cisco: 'snmp-server community "
            "<str> RO <acl-number>'.");
        return true;
    }
    return false;
}

/* ======================================================================== */
/*  Service rules                                                            */
/* ======================================================================== */

static bool check_SVC001(const DeviceModel *m, struct AuditResult *r,
                          Finding *out)
{
    (void)r;
    if (m->services.http_enabled && !m->services.https_enabled) {
        FILL_FINDING(out, "SVC-001", SEV_HIGH,
            "Plain HTTP management server enabled without HTTPS",
            "service / ip http server",
            "Disable 'ip http server' and enable 'ip http secure-server'. "
            "If HTTPS is required, configure a valid SSL/TLS certificate and "
            "enforce TLS 1.2 or higher.");
        return true;
    }
    return false;
}

static bool check_SVC002(const DeviceModel *m, struct AuditResult *r,
                          Finding *out)
{
    (void)r;
    if (m->services.cdp_global) {
        FILL_FINDING(out, "SVC-002", SEV_MEDIUM,
            "CDP (Cisco Discovery Protocol) enabled globally",
            "service / cdp run",
            "Disable CDP on all external-facing and untrusted interfaces: "
            "'no cdp enable' per interface. Consider 'no cdp run' globally "
            "and re-enable only on trusted internal segments where needed.");
        return true;
    }
    return false;
}

static bool check_SVC003(const DeviceModel *m, struct AuditResult *r,
                          Finding *out)
{
    (void)r;
    if (m->services.tcp_small_servers || m->services.udp_small_servers) {
        FILL_FINDING(out, "SVC-003", SEV_MEDIUM,
            "TCP/UDP small servers enabled (echo, chargen, discard, daytime)",
            "service tcp-small-servers / udp-small-servers",
            "Disable with 'no service tcp-small-servers' and "
            "'no service udp-small-servers'. These services are obsolete "
            "and can be abused in amplification attacks.");
        return true;
    }
    return false;
}

/* ======================================================================== */
/*  Logging rules                                                            */
/* ======================================================================== */

static bool check_LOG001(const DeviceModel *m, struct AuditResult *r,
                          Finding *out)
{
    (void)r;
    if (m->logging.server_count == 0) {
        FILL_FINDING(out, "LOG-001", SEV_MEDIUM,
            "No remote syslog server configured",
            "logging",
            "Configure at least one remote syslog server: 'logging <ip>'. "
            "Set the logging level appropriately (informational or higher). "
            "Centralised logging is required for security monitoring and "
            "incident response.");
        return true;
    }
    return false;
}

static bool check_LOG002(const DeviceModel *m, struct AuditResult *r,
                          Finding *out)
{
    (void)r;
    if (!m->logging.buffered_enabled) {
        FILL_FINDING(out, "LOG-002", SEV_LOW,
            "Buffered (local) logging not enabled",
            "logging buffered",
            "Enable local buffered logging: 'logging buffered 65536 informational'. "
            "Local logging provides a fallback when the syslog server is unreachable.");
        return true;
    }
    return false;
}

/* ======================================================================== */
/*  NTP rules                                                                */
/* ======================================================================== */

static bool check_NTP001(const DeviceModel *m, struct AuditResult *r,
                          Finding *out)
{
    (void)r;
    if (m->ntp.server_count == 0) {
        FILL_FINDING(out, "NTP-001", SEV_MEDIUM,
            "NTP not configured — device clock may be unsynchronised",
            "ntp",
            "Configure at least two NTP servers from trusted sources: "
            "'ntp server <ip>'. Accurate time is critical for log correlation, "
            "certificate validation, and AAA event ordering.");
        return true;
    }
    return false;
}

static bool check_NTP002(const DeviceModel *m, struct AuditResult *r,
                          Finding *out)
{
    (void)r;
    if (m->ntp.server_count > 0 && !m->ntp.authenticated) {
        FILL_FINDING(out, "NTP-002", SEV_LOW,
            "NTP configured without authentication",
            "ntp authenticate",
            "Enable NTP authentication: 'ntp authenticate', "
            "'ntp authentication-key <id> md5 <key>', 'ntp trusted-key <id>'. "
            "Without authentication, NTP responses can be spoofed.");
        return true;
    }
    return false;
}

/* ======================================================================== */
/*  Interface rules                                                          */
/* ======================================================================== */

static bool check_INTF001(const DeviceModel *m, struct AuditResult *r,
                           Finding *out)
{
    for (int i = 0; i < m->interface_count; i++) {
        const Interface *iface = &m->interfaces[i];
        /* Flag active interfaces with no IP and no description */
        if (!iface->shutdown &&
            iface->ip_address[0] == '\0' &&
            !iface->is_loopback &&
            iface->description[0] == '\0') {
            char section[MAX_SECTION_LEN];
            safe_snprintf(section, sizeof(section),
                          "interface '%s'", iface->name);
            FILL_FINDING(out, "INTF-001", SEV_LOW,
                "Interface is active but has no IP address or description assigned",
                section,
                "Shut down unused interfaces with 'shutdown'. Add descriptions "
                "to active interfaces with 'description <purpose>'. Document "
                "all interfaces in the network inventory.");
            engine_add_finding(r, out);
        }
    }
    return false;
}

/* ======================================================================== */
/*  Global rules table                                                       */
/* ======================================================================== */

static const Rule s_rules[] = {
    /* AUTH */
    { "AUTH-001", SEV_CRITICAL,
      "Plaintext enable password instead of enable secret",
      "Replace with 'enable secret'; enable 'service password-encryption'.",
      check_AUTH001 },

    { "AUTH-002", SEV_HIGH,
      "No AAA configuration present",
      "Configure 'aaa new-model' with RADIUS/TACACS+ method lists.",
      check_AUTH002 },

    { "AUTH-003", SEV_HIGH,
      "Telnet permitted on VTY lines (cleartext)",
      "Set 'transport input ssh' on all VTY lines; disable Telnet globally.",
      check_AUTH003 },

    { "AUTH-004", SEV_HIGH,
      "SSH not enabled or SSHv1 in use",
      "Enable SSHv2; generate RSA keys >= 2048 bits.",
      check_AUTH004 },

    /* PASSWD */
    { "PASSWD-001", SEV_CRITICAL,
      "Passwords stored in plaintext (no service password-encryption)",
      "Enable 'service password-encryption'; use 'enable secret' and type-9 hashes.",
      check_PASSWD001 },

    /* ACL */
    { "ACL-001", SEV_CRITICAL,
      "ACL contains unrestricted 'permit any any'",
      "Replace with specific permit rules; add explicit deny at end.",
      check_ACL001 },

    { "ACL-002", SEV_HIGH,
      "Management interface missing inbound ACL",
      "Apply a restrictive inbound ACL to all management interfaces.",
      check_ACL002 },

    /* SNMP */
    { "SNMP-001", SEV_CRITICAL,
      "SNMPv1/v2c with default community strings",
      "Use SNMPv3 with auth/priv; remove default community strings.",
      check_SNMP001 },

    { "SNMP-002", SEV_HIGH,
      "SNMP enabled without restricting ACL",
      "Apply ACL to SNMP community to restrict to known NMS hosts.",
      check_SNMP002 },

    /* Services */
    { "SVC-001", SEV_HIGH,
      "Plain HTTP management server enabled",
      "Disable HTTP server; enable HTTPS (TLS 1.2+).",
      check_SVC001 },

    { "SVC-002", SEV_MEDIUM,
      "CDP enabled globally",
      "Disable CDP on external/untrusted interfaces; limit to internal use.",
      check_SVC002 },

    { "SVC-003", SEV_MEDIUM,
      "TCP/UDP small servers enabled",
      "Disable with 'no service tcp-small-servers' and 'no service udp-small-servers'.",
      check_SVC003 },

    /* Logging */
    { "LOG-001", SEV_MEDIUM,
      "No remote syslog server configured",
      "Configure 'logging <syslog-server-ip>' with appropriate level.",
      check_LOG001 },

    { "LOG-002", SEV_LOW,
      "Local buffered logging not enabled",
      "Enable 'logging buffered 65536 informational' as a local fallback.",
      check_LOG002 },

    /* NTP */
    { "NTP-001", SEV_MEDIUM,
      "NTP not configured",
      "Configure at least two NTP servers from trusted infrastructure.",
      check_NTP001 },

    { "NTP-002", SEV_LOW,
      "NTP configured without authentication",
      "Enable 'ntp authenticate' with trusted keys to prevent time spoofing.",
      check_NTP002 },

    /* Interfaces */
    { "INTF-001", SEV_LOW,
      "Active interface with no IP address or description",
      "Shut down unused interfaces; add descriptions to all active interfaces.",
      check_INTF001 },
};

static const int s_rule_count = (int)(sizeof(s_rules) / sizeof(s_rules[0]));

/**
 * @brief Return the global rules table.
 */
const Rule *rules_get_table(int *count)
{
    if (count) *count = s_rule_count;
    return s_rules;
}

