/**
 * @file rule_registry.c
 * @brief Ordered view over all rule groups.
 */
#include "netaudit/safe_str.h"
#include "rules_internal.h"

static const struct {
    const Rule   *rules;
    const size_t *count;
} k_groups[] = {
    { RULES_AUTH,   &RULES_AUTH_COUNT   },
    { RULES_PASSWD, &RULES_PASSWD_COUNT },
    { RULES_ACL,    &RULES_ACL_COUNT    },
    { RULES_SNMP,   &RULES_SNMP_COUNT   },
    { RULES_SVC,    &RULES_SVC_COUNT    },
    { RULES_LOG,    &RULES_LOG_COUNT    },
    { RULES_NTP,    &RULES_NTP_COUNT    },
    { RULES_INTF,   &RULES_INTF_COUNT   },
};

size_t rules_count(void)
{
    size_t total = 0;
    for (size_t g = 0; g < NA_ARRAY_LEN(k_groups); g++) total += *k_groups[g].count;
    return total;
}

const Rule *rules_at(size_t index)
{
    for (size_t g = 0; g < NA_ARRAY_LEN(k_groups); g++) {
        if (index < *k_groups[g].count) return &k_groups[g].rules[index];
        index -= *k_groups[g].count;
    }
    return NULL;
}

const Rule *rules_find(const char *id)
{
    for (size_t i = 0; i < rules_count(); i++) {
        const Rule *r = rules_at(i);
        if (str_eq_ci(r->id, id)) return r;
    }
    return NULL;
}
