/**
 * @file rules_auth.c
 * @brief AUTH-* rules: privileged credentials, AAA and management sessions.
 */
#include "rules_internal.h"

#define MAX_IDLE_TIMEOUT_MIN 15

static void check_auth001(const DeviceModel *m, FindingSink *sink)
{
    if (m->auth.enable_password_set && !m->auth.enable_secret_set)
        finding_report(sink, -1, "auth / enable password");
}

static void check_auth002(const DeviceModel *m, FindingSink *sink)
{
    if (!m->auth.aaa_configured)
        finding_report(sink, -1, "auth / aaa");
}

static void check_auth003(const DeviceModel *m, FindingSink *sink)
{
    if (m->mgmt.telnet_enabled)
        finding_report(sink, -1, "management access / telnet");
}

static void check_auth004(const DeviceModel *m, FindingSink *sink)
{
    if (!m->mgmt.ssh_enabled) {
        finding_report(sink, -1, "management access / ssh");
    } else if (m->mgmt.ssh_version == 1) {
        finding_report_variant(sink, SEV_MEDIUM,
            "SSHv1 configured; SSHv1 is cryptographically broken",
            "Allow only SSH protocol version 2 (IOS: 'ip ssh version 2'; "
            "JunOS: 'protocol-version v2'). SSHv1 is vulnerable to "
            "man-in-the-middle and protocol downgrade attacks.",
            -1, "management access / ssh version");
    }
}

static void check_auth005(const DeviceModel *m, FindingSink *sink)
{
    int t = m->mgmt.idle_timeout_min;
    if (t == NA_TIMEOUT_NEVER)
        finding_report(sink, -1, "management access / idle timeout (none)");
    else if (t > MAX_IDLE_TIMEOUT_MIN)
        finding_report(sink, -1, "management access / idle timeout (%d min)", t);
}

static void check_auth006(const DeviceModel *m, FindingSink *sink)
{
    if (!m->mgmt.login_banner)
        finding_report(sink, -1, "management access / login banner");
}

static void check_auth007(const DeviceModel *m, FindingSink *sink)
{
    if (!m->mgmt.access_restricted)
        finding_report(sink, -1, "management access / permitted sources");
}

static void check_auth008(const DeviceModel *m, FindingSink *sink)
{
    if (!m->auth.login_lockout)
        finding_report(sink, -1, "auth / login attempts");
}

const Rule RULES_AUTH[] = {
    { "AUTH-001", CAT_AUTH, SEV_CRITICAL,
      "Plaintext enable password without enable secret",
      "Privileged password stored in plaintext or reversible form, with no hashed secret",
      "Replace 'enable password' with 'enable secret <hash>' (IOS), use "
      "encrypted-password (JunOS) or ENC-hashed admin passwords (FortiOS). "
      "Hashed secrets cannot be read back from the configuration.",
      check_auth001,
      { "", "8.3.2", "A.5.17, A.8.5", "IA-5(1)" } },

    { "AUTH-002", CAT_AUTH, SEV_HIGH,
      "No AAA configuration",
      "AAA (Authentication, Authorization, Accounting) not configured",
      "Enable centralised AAA: 'aaa new-model' with RADIUS/TACACS+ method "
      "lists (IOS), 'authentication-order' with radius/tacplus servers "
      "(JunOS), or remote-auth admins backed by 'config user radius' (FortiOS).",
      check_auth002,
      { "6.7, 12.5", "8.2.1", "A.5.15, A.5.16, A.8.5", "AC-2, IA-2" } },

    { "AUTH-003", CAT_AUTH, SEV_HIGH,
      "Telnet permitted for management",
      "Telnet permitted for device management (cleartext credentials)",
      "Allow SSH only: 'transport input ssh' on all VTY lines (IOS), remove "
      "'system services telnet' (JunOS), remove 'telnet' from interface "
      "allowaccess (FortiOS).",
      check_auth003,
      { "3.10, 4.6, 12.6", "2.2.7, 8.3.2", "A.8.5, A.8.20, A.8.24", "AC-17(2), CM-7, SC-8" } },

    { "AUTH-004", CAT_AUTH, SEV_HIGH,
      "SSH not enabled or SSHv1 in use",
      "SSH not enabled; no encrypted management access configured",
      "Enable SSHv2: 'ip ssh version 2' and 'crypto key generate rsa modulus "
      "4096' (IOS), 'system services ssh' (JunOS), 'ssh' in allowaccess "
      "(FortiOS). Then restrict management to SSH.",
      check_auth004,
      { "4.6, 12.6", "2.2.7", "A.8.20, A.8.24", "AC-17(2), SC-8, SC-13" } },

    { "AUTH-005", CAT_AUTH, SEV_MEDIUM,
      "Management sessions do not time out when idle",
      "Idle management sessions are never closed, or stay open longer than 15 minutes",
      "Close idle sessions after 15 minutes or less: 'exec-timeout 10 0' on "
      "console and VTY lines (IOS/NX-OS), 'idle-timeout' in the login class "
      "(JunOS) or under 'management ssh' (EOS), 'admintimeout' (FortiOS), "
      "'ssh timeout' (ASA), management idle-timeout (PAN-OS).",
      check_auth005,
      { "4.3", "8.2.8", "A.8.5", "AC-12, SC-10" } },

    { "AUTH-006", CAT_AUTH, SEV_LOW,
      "No login banner",
      "No login banner warns users before they authenticate",
      "Show a legal notice before login: 'banner login' (IOS, NX-OS, EOS, "
      "ASA), 'system login message' (JunOS), 'pre-login-banner' (FortiOS), "
      "login-banner (PAN-OS). Do not include device or site details in it.",
      check_auth006,
      { "", "", "", "AC-8" } },

    { "AUTH-007", CAT_AUTH, SEV_MEDIUM,
      "Management access not restricted to trusted hosts",
      "Management logins are accepted from any source address",
      "Limit who can reach the management plane: 'access-class <acl> in' on "
      "every VTY line (IOS/NX-OS), an input filter on lo0 (JunOS), "
      "'trusthost' on every admin (FortiOS), 'ip access-group' under "
      "'management ssh' (EOS), specific 'ssh'/'http' source networks (ASA), "
      "permitted-ip (PAN-OS).",
      check_auth007,
      { "12.3", "", "A.8.3, A.8.20", "AC-17, SC-7" } },

    { "AUTH-008", CAT_AUTH, SEV_MEDIUM,
      "No lockout after failed logins",
      "Repeated failed logins are not limited or locked out",
      "Slow down password guessing: 'login block-for' (IOS/NX-OS), 'aaa "
      "local authentication attempts max-fail' (IOS/ASA), 'system login "
      "retry-options' (JunOS), 'aaa authentication policy lockout' (EOS), "
      "admin-lockout failed-attempts (PAN-OS).",
      check_auth008,
      { "", "8.3.4", "A.8.5", "AC-7" } },
};
DEFINE_RULE_GROUP_COUNT(RULES_AUTH);
