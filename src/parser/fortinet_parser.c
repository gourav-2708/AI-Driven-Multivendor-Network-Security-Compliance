/**
 * @file fortinet_parser.c
 * @brief Fortinet FortiOS configuration parser.
 *
 * FortiOS uses a "config ... / edit ... / set ... / next / end" syntax.
 * This parser tracks the config block stack to identify relevant stanzas
 * and extract security-relevant settings into a DeviceModel.
 *
 * Detected markers: lines beginning with "config system" or "config firewall"
 * or the "#config-version" header that FortiOS prepends to backups.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "parser.h"
#include "model.h"
#include "common.h"

#define LINE_BUF   1024
#define MAX_DEPTH  16

/* -- detect() -------------------------------------------------------------- */
static bool fortinet_detect(const char *filepath)
{
    FILE *f = fopen(filepath, "r");
    if (!f) return false;

    char line[LINE_BUF];
    int  checked = 0;
    bool found   = false;

    while (!found && checked < 30 && fgets(line, sizeof(line), f)) {
        str_trim(line);
        if (str_starts_with(line, "#config-version") ||
            str_starts_with_ci(line, "config system global") ||
            str_starts_with_ci(line, "config system interface") ||
            str_starts_with_ci(line, "config firewall") ||
            str_starts_with_ci(line, "config log") ||
            str_starts_with_ci(line, "config system snmp"))
        {
            found = true;
        }
        checked++;
    }
    fclose(f);
    return found;
}

/* -- parse() --------------------------------------------------------------- */
static int fortinet_parse(const char *filepath, DeviceModel *m)
{
    FILE *f = fopen(filepath, "r");
    if (!f) {
        LOG_ERR("fortinet_parse: cannot open '%s'", filepath);
        return AUDIT_ERR_IO;
    }

    safe_strncpy(m->vendor, "fortinet", sizeof(m->vendor));
    safe_strncpy(m->source_file, filepath, sizeof(m->source_file));

    char line[LINE_BUF];
    int  lineno = 0;

    /* Config block stack */
    char ctx[MAX_DEPTH][128];
    int  depth = 0;
    for (int i = 0; i < MAX_DEPTH; i++) ctx[i][0] = '\0';

    /* Current objects being parsed */
    char cur_if[MAX_IFNAME_LEN]     = {0};
    char cur_policy[64]             = {0};
    char cur_community[MAX_COMMUNITY_LEN] = {0};
    bool in_interface  = false;
    bool in_policy     = false;
    bool in_community  = false;
    bool in_ntp        = false;
    bool in_syslog     = false;
    bool in_snmp_comm  = false;
    bool in_snmp_sys   = false;
    bool in_admin      = false;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        str_trim(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        /* Build path string */
        char path[512] = {0};
        for (int d = 0; d <= depth && d < MAX_DEPTH; d++) {
            if (ctx[d][0]) {
                strncat(path, ctx[d], sizeof(path)-strlen(path)-1);
                strncat(path, "/",    sizeof(path)-strlen(path)-1);
            }
        }

        /* -- Block control keywords ------------------------------------- */
        if (str_starts_with_ci(line, "config ")) {
            if (depth < MAX_DEPTH - 1) {
                depth++;
                safe_strncpy(ctx[depth], line + strlen("config "),
                             sizeof(ctx[depth]));
                str_trim(ctx[depth]);
            }

            /* Track which block we entered */
            in_interface = str_contains_ci(ctx[depth], "system interface");
            in_policy    = str_contains_ci(ctx[depth], "firewall policy") ||
                           str_contains_ci(ctx[depth], "firewall6 policy");
            in_community = str_contains_ci(ctx[depth], "system snmp community");
            in_snmp_sys  = str_contains_ci(ctx[depth], "system snmp sysinfo");
            in_ntp       = str_contains_ci(ctx[depth], "system ntp");
            in_syslog    = str_contains_ci(ctx[depth], "log syslogd") ||
                           str_contains_ci(ctx[depth], "log fortianalyzer");
            in_admin     = str_contains_ci(ctx[depth], "system admin");
            continue;
        }

        if (str_starts_with_ci(line, "end")) {
            if (depth > 0) { ctx[depth][0] = '\0'; depth--; }
            /* Recompute state for parent block */
            in_interface = (depth > 0) && str_contains_ci(ctx[depth], "system interface");
            in_policy    = (depth > 0) && (str_contains_ci(ctx[depth], "firewall policy") ||
                                           str_contains_ci(ctx[depth], "firewall6 policy"));
            in_community = (depth > 0) && str_contains_ci(ctx[depth], "system snmp community");
            in_snmp_sys  = (depth > 0) && str_contains_ci(ctx[depth], "system snmp sysinfo");
            in_ntp       = (depth > 0) && str_contains_ci(ctx[depth], "system ntp");
            in_syslog    = (depth > 0) && (str_contains_ci(ctx[depth], "log syslogd") ||
                                           str_contains_ci(ctx[depth], "log fortianalyzer"));
            in_admin     = (depth > 0) && str_contains_ci(ctx[depth], "system admin");
            continue;
        }

        if (str_starts_with_ci(line, "edit ")) {
            char tok[128];
            if (sscanf(line + strlen("edit "), "%127s", tok) == 1) {
                /* Strip surrounding quotes */
                char *s = tok, *e = tok + strlen(tok) - 1;
                if (*s == '"') s++;
                if (*e == '"') { *e = '\0'; }

                if (in_interface) {
                    safe_strncpy(cur_if, s, sizeof(cur_if));
                    /* Find or create interface */
                    bool found = false;
                    for (int i = 0; i < m->interface_count; i++) {
                        if (portable_strcasecmp(m->interfaces[i].name, cur_if) == 0) {
                            found = true; break;
                        }
                    }
                    if (!found && m->interface_count < MAX_INTERFACES) {
                        safe_strncpy(m->interfaces[m->interface_count++].name,
                                     cur_if, MAX_IFNAME_LEN);
                    }
                }
                if (in_policy) {
                    safe_strncpy(cur_policy, s, sizeof(cur_policy));
                }
                if (in_community) {
                    in_snmp_comm = true;
                    safe_strncpy(cur_community, s, sizeof(cur_community));
                    m->snmp.enabled = true;
                    if (m->snmp.version < SNMP_V2C)
                        m->snmp.version = SNMP_V2C;
                }
            }
            continue;
        }

        if (str_starts_with_ci(line, "next")) {
            if (in_interface) cur_if[0] = '\0';
            if (in_policy)    cur_policy[0] = '\0';
            if (in_community) { in_snmp_comm = false; cur_community[0] = '\0'; }
            continue;
        }

        /* -- set directives --------------------------------------------- */
        if (!str_starts_with_ci(line, "set ")) goto next_line;
        const char *set_line = line + strlen("set ");

        /* system global */
        if (depth > 0 && str_contains_ci(ctx[depth], "system global")) {
            if (str_starts_with_ci(set_line, "hostname ")) {
                char tok[MAX_HOSTNAME_LEN];
                if (sscanf(set_line + strlen("hostname "), "%127s", tok) == 1) {
                    char *s = tok;
                    if (*s == '"') s++;
                    char *e = s + strlen(s) - 1;
                    if (*e == '"') *e = '\0';
                    safe_strncpy(m->hostname, s, sizeof(m->hostname));
                }
            }
            if (str_starts_with_ci(set_line, "admin-telnet-port") ||
                str_contains_ci(set_line, "telnet enable"))
                m->auth.telnet_on_vty = true;
            if (str_starts_with_ci(set_line, "admin-ssh-port"))
                m->auth.ssh_enabled = true;
            if (str_starts_with_ci(set_line, "strong-crypto enable"))
                m->auth.service_password_encrypt = true;
        }

        /* system interface */
        if (in_interface && cur_if[0]) {
            int idx = -1;
            for (int i = 0; i < m->interface_count; i++) {
                if (portable_strcasecmp(m->interfaces[i].name, cur_if) == 0)
                    { idx = i; break; }
            }
            if (idx < 0) goto next_line;
            Interface *iface = &m->interfaces[idx];

            if (str_starts_with_ci(set_line, "ip ")) {
                char ip[MAX_IP_LEN], mask[MAX_MASK_LEN];
                ip[0] = mask[0] = '\0';
                sscanf(set_line + strlen("ip "), "%47s %47s", ip, mask);
                safe_strncpy(iface->ip_address,  ip,   MAX_IP_LEN);
                safe_strncpy(iface->subnet_mask, mask, MAX_MASK_LEN);
            }
            if (str_starts_with_ci(set_line, "status down"))
                iface->shutdown = true;
            if (str_starts_with_ci(set_line, "allowaccess")) {
                /* e.g. "set allowaccess ping https ssh telnet http" */
                const char *acc = set_line + strlen("allowaccess");
                if (str_contains_ci(acc, "telnet")) {
                    m->auth.telnet_on_vty = true;
                    m->services.telnet_enabled = true;
                }
                if (str_contains_ci(acc, "http") &&
                    !str_contains_ci(acc, "https"))
                    m->services.http_enabled = true;
                if (str_contains_ci(acc, "https"))
                    m->services.https_enabled = true;
                if (str_contains_ci(acc, "ssh")) {
                    m->auth.ssh_enabled  = true;
                    m->auth.ssh_version  = 2;
                }
            }
            if (str_starts_with_ci(set_line, "description "))
                safe_strncpy(iface->description,
                             set_line + strlen("description "),
                             sizeof(iface->description));
            if (str_starts_with_ci(set_line, "type loopback"))
                iface->is_loopback = true;
            /* role classification not used in model */
            if (str_contains_ci(cur_if, "mgmt") ||
                str_contains_ci(set_line, "ha-mgmt"))
                iface->is_management = true;
        }

        /* system admin — check for plaintext passwords */
        if (in_admin) {
            if (str_starts_with_ci(set_line, "password "))
                m->auth.enable_password_set = true;  /* plaintext */
            if (str_starts_with_ci(set_line, "passwd-time") ||
                str_starts_with_ci(set_line, "accprofile"))
                m->auth.local_users_configured = true;
        }

        /* firewall policy — detect any-any rules */
        if (in_policy && cur_policy[0]) {
            if (str_starts_with_ci(set_line, "srcaddr \"all\"") ||
                str_starts_with_ci(set_line, "srcaddr all")) {
                if (m->acl_count < MAX_ACLS) {
                    int ai = -1;
                    for (int i = 0; i < m->acl_count; i++) {
                        if (strcmp(m->acls[i].name, cur_policy) == 0)
                            { ai = i; break; }
                    }
                    if (ai == -1) {
                        ai = m->acl_count++;
                        safe_strncpy(m->acls[ai].name, cur_policy, MAX_ACLNAME_LEN);
                    }
                    if (m->acls[ai].entry_count < MAX_ACL_ENTRIES) {
                        AclEntry *ae = &m->acls[ai].entries[m->acls[ai].entry_count];
                        ae->action = ACL_PERMIT;
                        safe_strncpy(ae->src_addr, "any", MAX_IP_LEN);
                        safe_strncpy(ae->dst_addr, "any", MAX_IP_LEN);
                        ae->is_any_any  = true;
                        ae->line_number = lineno;
                        m->acls[ai].entry_count++;
                    }
                }
            }
            /* action accept already processed */
            /* action deny is benign */
        }

        /* SNMP sysinfo */
        if (in_snmp_sys) {
            if (str_starts_with_ci(set_line, "status enable"))
                m->snmp.enabled = true;
        }

        /* SNMP community */
        if (in_snmp_comm) {
            if (str_starts_with_ci(set_line, "name ")) {
                char tok[MAX_COMMUNITY_LEN];
                if (sscanf(set_line + strlen("name "), "%63s", tok) == 1) {
                    char *s = tok, *e = tok + strlen(tok) - 1;
                    if (*s == '"') s++;
                    if (*e == '"') *e = '\0';
                    safe_strncpy(m->snmp.community_ro, s, MAX_COMMUNITY_LEN);
                }
            }
            if (str_starts_with_ci(set_line, "query-v1-status enable") ||
                str_starts_with_ci(set_line, "trap-v1-status enable"))
                m->snmp.version = SNMP_V1;
            if (str_starts_with_ci(set_line, "query-v2c-status enable") ||
                str_starts_with_ci(set_line, "trap-v2c-status enable"))
                if (m->snmp.version < SNMP_V2C) m->snmp.version = SNMP_V2C;
        }

        /* NTP */
        if (in_ntp) {
            /* ntpsync enable: server directives parsed below */
            if (str_starts_with_ci(set_line, "server ") ||
                str_starts_with_ci(set_line, "server1 ") ||
                str_starts_with_ci(set_line, "server2 ")) {
                char tok[MAX_IP_LEN];
                if (sscanf(set_line, "%*s %47s", tok) == 1 &&
                    m->ntp.server_count < MAX_NTP_SERVERS)
                    safe_strncpy(m->ntp.servers[m->ntp.server_count++],
                                 tok, MAX_IP_LEN);
            }
            if (str_starts_with_ci(set_line, "authentication enable"))
                m->ntp.authenticated = true;
        }

        /* Syslog */
        if (in_syslog) {
            /* syslog status enable: server parsed below */
            if (str_starts_with_ci(set_line, "server ")) {
                char tok[MAX_IP_LEN];
                if (sscanf(set_line + strlen("server "), "%47s", tok) == 1 &&
                    m->logging.server_count < MAX_LOG_SERVERS)
                    safe_strncpy(m->logging.servers[m->logging.server_count++],
                                 tok, MAX_IP_LEN);
            }
        }

    next_line:;
    }

    /* Infer HTTPS if SSH allowed */
    if (m->auth.ssh_enabled && !m->services.http_enabled)
        m->services.https_enabled = true;

    fclose(f);
    LOG_INF("fortinet_parse: parsed '%s' — %d interfaces, %d ACLs",
            filepath, m->interface_count, m->acl_count);
    return AUDIT_OK;
}

/* -- Registration ---------------------------------------------------------- */

static const VendorParser s_fortinet_parser = {
    .vendor_name = "fortinet",
    .detect      = fortinet_detect,
    .parse       = fortinet_parse
};

void fortinet_parser_register(void)
{
    parser_register(&s_fortinet_parser);
}


