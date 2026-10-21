/**
 * @file rules_intf.c
 * @brief INTF-* rules: interface hygiene.
 */
#include "rules_internal.h"

static void check_intf001(const DeviceModel *m, FindingSink *sink)
{
    for (int i = 0; i < m->interface_count; i++) {
        const Interface *it = &m->interfaces[i];
        if (it->shutdown || it->is_loopback) continue;
        if (it->ip_address[0] || it->dynamic_address || it->description[0]) continue;
        finding_report(sink, it->line_number, "interface '%s'", it->name);
    }
}

const Rule RULES_INTF[] = {
    { "INTF-001", CAT_INTF, SEV_LOW,
      "Active interface with no IP or description",
      "Interface is active but has no IP address or description assigned",
      "Shut down unused interfaces and describe every active one "
      "('description <purpose>') so the inventory stays auditable.",
      check_intf001 },
};
DEFINE_RULE_GROUP_COUNT(RULES_INTF);
