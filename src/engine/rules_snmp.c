/**
 * @file rules_snmp.c
 * @brief SNMP-* rules: community strength and access restriction.
 *
 * Community strings are credentials, so reports never print a custom one
 * in full: only well-known defaults (which are public knowledge anyway)
 * are shown verbatim; anything else is reduced to its first two characters.
 */
#include "netaudit/safe_str.h"
#include "rules_internal.h"

#define MIN_COMMUNITY_LEN      8
#define MIN_COMMUNITY_CLASSES  3

static bool is_default_community(const char *name)
{
    static const char *const k_defaults[] = {
        "public", "private", "community", "snmp", "snmpd", "admin", "cisco",
        "default", "manager", "monitor", "read", "write", "secret", "system",
        "netman", "network", "router", "switch", "test", "guest",
    };
    for (size_t i = 0; i < NA_ARRAY_LEN(k_defaults); i++)
        if (str_eq_ci(name, k_defaults[i])) return true;
    return false;
}

/* Weak: a known default, shorter than 8 characters, or fewer than three of
 * the four character classes (lower, upper, digit, symbol). */
static bool is_weak_community(const char *name)
{
    if (is_default_community(name) || strlen(name) < MIN_COMMUNITY_LEN)
        return true;
    bool lower = false, upper = false, digit = false, other = false;
    for (const char *p = name; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (islower(c))      lower = true;
        else if (isupper(c)) upper = true;
        else if (isdigit(c)) digit = true;
        else                 other = true;
    }
    return (lower + upper + digit + other) < MIN_COMMUNITY_CLASSES;
}

static void redact(const char *name, char *out, size_t out_size)
{
    if (is_default_community(name))
        safe_strcpy(out, out_size, name);
    else
        safe_snprintf(out, out_size, "%.2s***", name);
}

static void check_snmp001(const DeviceModel *m, FindingSink *sink)
{
    for (int i = 0; i < m->snmp.community_count; i++) {
        const SnmpCommunity *c = &m->snmp.communities[i];
        if (!is_weak_community(c->name)) continue;
        char shown[NA_MAX_COMMUNITY];
        redact(c->name, shown, sizeof(shown));
        finding_report(sink, c->line_number, "snmp / community '%s' (%s)",
                       shown, c->access == SNMP_RW ? "read-write" : "read-only");
    }
}

static void check_snmp002(const DeviceModel *m, FindingSink *sink)
{
    for (int i = 0; i < m->snmp.community_count; i++) {
        const SnmpCommunity *c = &m->snmp.communities[i];
        if (c->restricted) continue;
        char shown[NA_MAX_COMMUNITY];
        redact(c->name, shown, sizeof(shown));
        finding_report(sink, c->line_number, "snmp / community '%s'", shown);
    }
}

const Rule RULES_SNMP[] = {
    { "SNMP-001", CAT_SNMP, SEV_CRITICAL,
      "SNMPv1/v2c with default or weak community strings",
      "SNMPv1/v2c community string is a default or easily guessed value",
      "Replace default and short community strings with long random values "
      "(8+ characters, mixed classes). Migrate to SNMPv3 with SHA "
      "authentication and AES privacy, then remove v1/v2c communities.",
      check_snmp001 },

    { "SNMP-002", CAT_SNMP, SEV_HIGH,
      "SNMP community without restricting ACL",
      "SNMP community is not restricted to known management hosts",
      "Bind every community to an ACL or client list of NMS addresses "
      "(IOS: 'snmp-server community <str> RO <acl>'; JunOS: 'clients'; "
      "FortiOS: community 'hosts').",
      check_snmp002 },
};
DEFINE_RULE_GROUP_COUNT(RULES_SNMP);
