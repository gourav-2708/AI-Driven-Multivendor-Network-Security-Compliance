/**
 * @file rules_internal.h
 * @brief Rule groups exported by the rules_<category>.c files.
 *
 * Each category file defines a `const Rule RULES_<CAT>[]` table and its
 * length. rule_registry.c concatenates the groups in report order.
 */
#ifndef NETAUDIT_RULES_INTERNAL_H
#define NETAUDIT_RULES_INTERNAL_H

#include "netaudit/engine.h"

#define DECLARE_RULE_GROUP(name)        \
    extern const Rule   name[];         \
    extern const size_t name##_COUNT

DECLARE_RULE_GROUP(RULES_AUTH);
DECLARE_RULE_GROUP(RULES_PASSWD);
DECLARE_RULE_GROUP(RULES_ACL);
DECLARE_RULE_GROUP(RULES_SNMP);
DECLARE_RULE_GROUP(RULES_SVC);
DECLARE_RULE_GROUP(RULES_LOG);
DECLARE_RULE_GROUP(RULES_NTP);
DECLARE_RULE_GROUP(RULES_INTF);

#define DEFINE_RULE_GROUP_COUNT(name) \
    const size_t name##_COUNT = sizeof(name) / sizeof(name[0])

#endif /* NETAUDIT_RULES_INTERNAL_H */
