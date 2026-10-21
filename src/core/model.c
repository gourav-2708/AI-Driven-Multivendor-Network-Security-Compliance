/**
 * @file model.c
 * @brief DeviceModel initialisation and bounded find-or-add helpers.
 */
#include "netaudit/log.h"
#include "netaudit/model.h"
#include "netaudit/safe_str.h"

void model_init(DeviceModel *m)
{
    if (m) memset(m, 0, sizeof(*m));
}

const char *model_hostname(const DeviceModel *m)
{
    return (m && m->hostname[0]) ? m->hostname : "(unknown)";
}

/* Record (and log at debug level) an element dropped for lack of space.
 * The audit pipeline reports the per-device total as a warning. */
static void note_overflow(DeviceModel *m, const char *what, int cap)
{
    m->overflow_count++;
    LOG_DBG("%s: more than %d %s; extra entries ignored",
            m->source_file[0] ? m->source_file : "config", cap, what);
}

Interface *model_interface(DeviceModel *m, const char *name)
{
    if (!m || !name || !name[0]) return NULL;

    for (int i = 0; i < m->interface_count; i++) {
        if (str_eq_ci(m->interfaces[i].name, name)) return &m->interfaces[i];
    }
    if (m->interface_count >= NA_MAX_INTERFACES) {
        note_overflow(m, "interfaces", NA_MAX_INTERFACES);
        return NULL;
    }
    Interface *it = &m->interfaces[m->interface_count++];
    safe_strcpy(it->name, sizeof(it->name), name);
    it->line_number = -1;
    it->is_loopback = str_starts_with_ci(name, "loopback") ||
                      str_starts_with_ci(name, "lo0");
    return it;
}

Acl *model_acl(DeviceModel *m, const char *name)
{
    if (!m || !name || !name[0]) return NULL;

    for (int i = 0; i < m->acl_count; i++) {
        if (str_eq_ci(m->acls[i].name, name)) return &m->acls[i];
    }
    if (m->acl_count >= NA_MAX_ACLS) {
        note_overflow(m, "ACLs/filters/policies", NA_MAX_ACLS);
        return NULL;
    }
    Acl *acl = &m->acls[m->acl_count++];
    safe_strcpy(acl->name, sizeof(acl->name), name);
    return acl;
}

AclEntry *model_acl_add_entry(DeviceModel *m, Acl *acl)
{
    if (!m || !acl) return NULL;
    if (acl->entry_count >= NA_MAX_ACL_ENTRIES) {
        note_overflow(m, "entries in one ACL", NA_MAX_ACL_ENTRIES);
        return NULL;
    }
    AclEntry *e = &acl->entries[acl->entry_count++];
    memset(e, 0, sizeof(*e));
    e->line_number = -1;
    return e;
}

SnmpCommunity *model_snmp_community(DeviceModel *m, const char *name)
{
    if (!m || !name || !name[0]) return NULL;

    m->snmp.enabled = true;
    for (int i = 0; i < m->snmp.community_count; i++) {
        if (strcmp(m->snmp.communities[i].name, name) == 0)
            return &m->snmp.communities[i];
    }
    if (m->snmp.community_count >= NA_MAX_COMMUNITIES) {
        note_overflow(m, "SNMP communities", NA_MAX_COMMUNITIES);
        return NULL;
    }
    SnmpCommunity *c = &m->snmp.communities[m->snmp.community_count++];
    memset(c, 0, sizeof(*c));
    safe_strcpy(c->name, sizeof(c->name), name);
    c->line_number = -1;
    return c;
}

static bool add_unique(DeviceModel *m, char list[][NA_MAX_ADDR], int *count,
                       int cap, const char *what, const char *addr)
{
    if (!addr || !addr[0]) return false;
    for (int i = 0; i < *count; i++) {
        if (str_eq_ci(list[i], addr)) return true;
    }
    if (*count >= cap) {
        note_overflow(m, what, cap);
        return false;
    }
    safe_strcpy(list[*count], NA_MAX_ADDR, addr);
    (*count)++;
    return true;
}

bool model_add_ntp_server(DeviceModel *m, const char *addr)
{
    return m && add_unique(m, m->ntp.servers, &m->ntp.server_count,
                           NA_MAX_NTP_SERVERS, "NTP servers", addr);
}

bool model_add_log_server(DeviceModel *m, const char *addr)
{
    return m && add_unique(m, m->logging.servers, &m->logging.server_count,
                           NA_MAX_LOG_SERVERS, "syslog servers", addr);
}

static bool looks_like_management(const char *text)
{
    return str_contains_ci(text, "mgmt") || str_contains_ci(text, "management");
}

void model_finalize(DeviceModel *m)
{
    if (!m) return;
    for (int i = 0; i < m->interface_count; i++) {
        Interface *it = &m->interfaces[i];
        if (it->is_loopback) {
            it->is_management = false;
            continue;
        }
        if (looks_like_management(it->name) ||
            looks_like_management(it->description) ||
            str_eq_ci(it->name, "me0") || str_eq_ci(it->name, "fxp0") ||
            str_eq_ci(it->name, "em0"))
            it->is_management = true;
    }
}
