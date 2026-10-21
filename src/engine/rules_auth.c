/**
 * @file rules_auth.c
 * @brief AUTH-* rules: privileged credentials, AAA and management protocols.
 */
#include "rules_internal.h"

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

const Rule RULES_AUTH[] = {
    { "AUTH-001", CAT_AUTH, SEV_CRITICAL,
      "Plaintext enable password without enable secret",
      "Privileged password stored in plaintext or reversible form, with no hashed secret",
      "Replace 'enable password' with 'enable secret <hash>' (IOS), use "
      "encrypted-password (JunOS) or ENC-hashed admin passwords (FortiOS). "
      "Hashed secrets cannot be read back from the configuration.",
      check_auth001 },

    { "AUTH-002", CAT_AUTH, SEV_HIGH,
      "No AAA configuration",
      "AAA (Authentication, Authorization, Accounting) not configured",
      "Enable centralised AAA: 'aaa new-model' with RADIUS/TACACS+ method "
      "lists (IOS), 'authentication-order' with radius/tacplus servers "
      "(JunOS), or remote-auth admins backed by 'config user radius' (FortiOS).",
      check_auth002 },

    { "AUTH-003", CAT_AUTH, SEV_HIGH,
      "Telnet permitted for management",
      "Telnet permitted for device management (cleartext credentials)",
      "Allow SSH only: 'transport input ssh' on all VTY lines (IOS), remove "
      "'system services telnet' (JunOS), remove 'telnet' from interface "
      "allowaccess (FortiOS).",
      check_auth003 },

    { "AUTH-004", CAT_AUTH, SEV_HIGH,
      "SSH not enabled or SSHv1 in use",
      "SSH not enabled; no encrypted management access configured",
      "Enable SSHv2: 'ip ssh version 2' and 'crypto key generate rsa modulus "
      "4096' (IOS), 'system services ssh' (JunOS), 'ssh' in allowaccess "
      "(FortiOS). Then restrict management to SSH.",
      check_auth004 },
};
DEFINE_RULE_GROUP_COUNT(RULES_AUTH);
