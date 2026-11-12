/**
 * @file rules_passwd.c
 * @brief PASSWD-* rules: how credentials are stored and what is required of them.
 */
#include "rules_internal.h"

static void check_passwd001(const DeviceModel *m, FindingSink *sink)
{
    bool plaintext = m->auth.enable_password_set || m->auth.plaintext_user_password;
    if (plaintext && !m->auth.password_encryption)
        finding_report(sink, -1, "service password-encryption");
}

static void check_passwd002(const DeviceModel *m, FindingSink *sink)
{
    if (!m->auth.password_policy)
        finding_report(sink, -1, "auth / password policy");
}

static void check_passwd003(const DeviceModel *m, FindingSink *sink)
{
    if (m->auth.weak_hash)
        finding_report(sink, -1, "auth / password hash type");
}

const Rule RULES_PASSWD[] = {
    { "PASSWD-001", CAT_PASSWD, SEV_CRITICAL,
      "Plaintext passwords without password encryption",
      "Passwords stored in plaintext: password encryption is not enabled",
      "Store credentials hashed: 'secret' instead of 'password' (type 8/9 "
      "where supported) and 'service password-encryption' as a minimum on "
      "IOS; encrypted-password on JunOS; ENC admin passwords on FortiOS. "
      "Remove default credentials.",
      check_passwd001,
      { "", "8.3.2", "A.5.17, A.8.5", "IA-5(1)" } },

    { "PASSWD-002", CAT_PASSWD, SEV_MEDIUM,
      "No local password policy",
      "No minimum length or complexity is enforced for local passwords",
      "Enforce a minimum length of 12 or more: 'security passwords "
      "min-length' (IOS), 'system login password minimum-length' (JunOS), "
      "'config system password-policy' (FortiOS), 'password strength-check' "
      "(NX-OS), 'password-policy minimum-length' (ASA), password-complexity "
      "(PAN-OS).",
      check_passwd002,
      { "5.2", "8.3.6", "A.5.17", "IA-5(1)" } },

    { "PASSWD-003", CAT_PASSWD, SEV_MEDIUM,
      "Credentials stored with a legacy hash",
      "A credential uses a legacy or reversible hash (MD5, IOS type 4, 5 or 7)",
      "Re-enter the credential so it is stored with a modern algorithm: "
      "IOS 'algorithm-type scrypt' (type 9) or sha256 (type 8), JunOS "
      "'system login password format sha512', ASA pbkdf2. Type 7 and MD5 "
      "hashes are recovered quickly from a leaked configuration.",
      check_passwd003,
      { "", "8.3.2", "A.5.17, A.8.24", "IA-5(1), SC-13" } },
};
DEFINE_RULE_GROUP_COUNT(RULES_PASSWD);
