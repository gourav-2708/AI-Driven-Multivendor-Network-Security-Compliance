/**
 * @file rules_acl.c
 * @brief ACL-* rules: packet filters, firewall policies and management ACLs.
 */
#include "rules_internal.h"

static void check_acl001(const DeviceModel *m, FindingSink *sink)
{
    for (int i = 0; i < m->acl_count; i++) {
        const Acl *acl = &m->acls[i];
        for (int j = 0; j < acl->entry_count; j++) {
            const AclEntry *e = &acl->entries[j];
            if (e->action == ACL_PERMIT && e->is_any_any)
                finding_report(sink, e->line_number, "ACL '%s' entry %d (line %d)",
                               acl->name, j + 1, e->line_number);
        }
    }
}

static void check_acl002(const DeviceModel *m, FindingSink *sink)
{
    for (int i = 0; i < m->interface_count; i++) {
        const Interface *it = &m->interfaces[i];
        if (it->is_management && !it->shutdown && it->acl_in[0] == '\0')
            finding_report(sink, it->line_number, "interface '%s'", it->name);
    }
}

const Rule RULES_ACL[] = {
    { "ACL-001", CAT_ACL, SEV_CRITICAL,
      "ACL or policy permits any source to any destination",
      "ACL contains unrestricted 'permit any any' (allows all traffic)",
      "Replace 'permit any any' entries (or all/all/ALL accept policies) with "
      "rules naming specific sources, destinations and services. End every "
      "ACL with an explicit deny and document each permit.",
      check_acl001 },

    { "ACL-002", CAT_ACL, SEV_HIGH,
      "Management interface missing inbound ACL",
      "Management interface has no inbound ACL applied",
      "Apply an inbound ACL/filter to every management interface that admits "
      "only known management hosts and the required protocols (SSH, SNMP, "
      "HTTPS).",
      check_acl002 },
};
DEFINE_RULE_GROUP_COUNT(RULES_ACL);
