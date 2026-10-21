/**
 * @file rules_passwd.c
 * @brief PASSWD-* rules: how credentials are stored in the configuration.
 */
#include "rules_internal.h"

static void check_passwd001(const DeviceModel *m, FindingSink *sink)
{
    bool plaintext = m->auth.enable_password_set || m->auth.plaintext_user_password;
    if (plaintext && !m->auth.password_encryption)
        finding_report(sink, -1, "service password-encryption");
}

const Rule RULES_PASSWD[] = {
    { "PASSWD-001", CAT_PASSWD, SEV_CRITICAL,
      "Plaintext passwords without password encryption",
      "Passwords stored in plaintext: password encryption is not enabled",
      "Store credentials hashed: 'secret' instead of 'password' (type 8/9 "
      "where supported) and 'service password-encryption' as a minimum on "
      "IOS; encrypted-password on JunOS; ENC admin passwords on FortiOS. "
      "Remove default credentials.",
      check_passwd001 },
};
DEFINE_RULE_GROUP_COUNT(RULES_PASSWD);
