/**
 * @file cisco_parser.c
 * @brief Cisco IOS configuration parser.
 *
 * Parses subset of Cisco IOS flat-text configuration syntax and populates
 * a DeviceModel.  The parser is line-oriented; it processes one logical
 * line at a time after stripping comments and leading whitespace.
 *
 * Detected markers:
 *   - File begins with "!" (Cisco comment) lines, or
 *   - Contains "version" followed by a version number, or
 *   - Contains "hostname" directive at the start of a line.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "parser.h"
#include "model.h"
#include "common.h"

#define LINE_BUF 1024

/* -- Helper: extract first token after a prefix --------------------------- */
static bool get_token_after(const char *line, const char *prefix, char *out, size_t out_size)
{
    if (!str_starts_with_ci(line, prefix)) return false;
    const char *rest = line + strlen(prefix);
    while (*rest && isspace((unsigned char)*rest)) rest++;
    if (*rest == '\0') return false;

    /* copy until whitespace or end */
    size_t i = 0;
    while (*rest && !isspace((unsigned char)*rest) && i < out_size - 1)
        out[i++] = *rest++;
    out[i] = '\0';
    return (i > 0);
}

/* -- detect() -------------------------------------------------------------- */
static bool cisco_detect(const char *filepath)
{
    FILE *f = fopen(filepath, "r");
    if (!f) return false;

    char line[LINE_BUF];
    int  lines_checked = 0;
    bool found = false;

    /* First line heuristics to reject Juniper/Fortinet syntax */
    bool has_exclamation = false;
    bool has_juniper     = false;
    bool has_fortinet    = false;
    bool has_cisco_key   = false;

    while (lines_checked < 30 && fgets(line, sizeof(line), f)) {
        str_trim(line);
        /* Juniper markers */
        if (str_starts_with(line, "## ") ||
            str_contains_ci(line, "junos") ||
            str_starts_with(line, "system {") ||
            str_starts_with(line, "interfaces {"))
            has_juniper = true;
        /* Fortinet markers */
        if (str_starts_with(line, "#config-version") ||
            str_starts_with_ci(line, "config system global") ||
            str_starts_with_ci(line, "config system interface") ||
            str_starts_with_ci(line, "config firewall") ||
            str_starts_with_ci(line, "config log"))
            has_fortinet = true;
        /* Cisco markers */
        if (str_starts_with(line, "!"))
            has_exclamation = true;
        if (str_starts_with_ci(line, "enable secret") ||
            str_starts_with_ci(line, "enable password") ||
            str_starts_with_ci(line, "ip access-list") ||
            str_starts_with_ci(line, "ip route") ||
            str_starts_with_ci(line, "snmp-server") ||
            str_starts_with_ci(line, "service password") ||
            str_starts_with_ci(line, "aaa new-model"))
            has_cisco_key = true;
        lines_checked++;
    }
    found = !has_juniper && !has_fortinet &&
            (has_exclamation || has_cisco_key);
    fclose(f);
    return found;
}

/* -- parse() --------------------------------------------------------------- */
static int cisco_parse(const char *filepath, DeviceModel *m)
{
    FILE *f = fopen(filepath, "r");
    if (!f) {
        LOG_ERR("cisco_parse: cannot open '%s'", filepath);
        return AUDIT_ERR_IO;
    }

    safe_strncpy(m->vendor, "cisco", sizeof(m->vendor));
    safe_strncpy(m->source_file, filepath, sizeof(m->source_file));

    char line[LINE_BUF];
    int  lineno = 0;

    /* State for nested blocks */
    bool in_interface = false;
    bool in_line_vty  = false;
    bool in_acl       = false;
    char current_if[MAX_IFNAME_LEN]  = {0};
    char current_acl[MAX_ACLNAME_LEN] = {0};
    bool acl_is_extended = false;

    /* Helper to find/create interface by name */
#define find_or_create_iface(name_str, idx_out) do {                 \
        (idx_out) = -1;                                              \
        for (int _i = 0; _i < m->interface_count; _i++) {           \
            if (portable_strcasecmp(m->interfaces[_i].name, (name_str)) == 0)\
                { (idx_out) = _i; break; }                          \
        }                                                            \
        if ((idx_out) == -1 && m->interface_count < MAX_INTERFACES) {\
            (idx_out) = m->interface_count++;                        \
            safe_strncpy(m->interfaces[(idx_out)].name, (name_str), \
                         MAX_IFNAME_LEN);                            \
            /* Cisco default: CDP on, proxy-arp on */                \
            m->interfaces[(idx_out)].cdp_enabled = true;            \
            m->interfaces[(idx_out)].proxy_arp   = true;            \
        }                                                            \
    } while(0)

    while (fgets(line, sizeof(line), f)) {
        lineno++;

        /* Detect block indentation BEFORE stripping whitespace */
        bool is_indented = isspace((unsigned char)(line[0]));

        /* Strip inline comment (lines beginning with '!' are comments) */
        {
            char *bang = strchr(line, '!');
            if (bang && bang == line) { str_trim(line); continue; }
            if (bang) { *bang = '\0'; }
        }
        str_trim(line);
        if (line[0] == '\0') continue;

        if (!is_indented) {
            in_interface = false;
            in_line_vty  = false;
            in_acl       = false;
            current_if[0]  = '\0';
            current_acl[0] = '\0';
        }

        /* -- Top-level directives --------------------------------------- */
        char tok[128];

        /* hostname */
        if (get_token_after(line, "hostname ", m->hostname, sizeof(m->hostname)))
            goto next_line;

        /* version */
        if (get_token_after(line, "version ", m->os_version, sizeof(m->os_version)))
            goto next_line;

        /* enable secret */
        if (str_starts_with_ci(line, "enable secret")) {
            m->auth.enable_secret_set = true;
            goto next_line;
        }

        /* enable password (plaintext) */
        if (str_starts_with_ci(line, "enable password")) {
            m->auth.enable_password_set = true;
            goto next_line;
        }

        /* service password-encryption */
        if (str_starts_with_ci(line, "service password-encryption")) {
            m->auth.service_password_encrypt = true;
            goto next_line;
        }

        /* username */
        if (str_starts_with_ci(line, "username ")) {
            m->auth.local_users_configured = true;
            goto next_line;
        }

        /* aaa new-model */
        if (str_starts_with_ci(line, "aaa new-model")) {
            m->auth.aaa_configured = true;
            goto next_line;
        }

        /* ip ssh version */
        if (str_starts_with_ci(line, "ip ssh version ")) {
            m->auth.ssh_enabled = true;
            char ver[8] = {0};
            get_token_after(line, "ip ssh version ", ver, sizeof(ver));
            m->auth.ssh_version = atoi(ver);
            goto next_line;
        }

        /* crypto key generate rsa — implies SSH */
        if (str_starts_with_ci(line, "crypto key generate rsa")) {
            m->auth.ssh_enabled = true;
            goto next_line;
        }

        /* ip http server */
        if (str_starts_with_ci(line, "ip http server") &&
            !str_contains_ci(line, "secure") &&
            !str_contains_ci(line, "no ip http server")) {
            m->services.http_enabled = true;
            goto next_line;
        }
        if (str_starts_with_ci(line, "no ip http server") &&
            !str_contains_ci(line, "secure")) {
            m->services.http_enabled = false;
            goto next_line;
        }

        /* ip http secure-server */
        if (str_starts_with_ci(line, "ip http secure-server")) {
            m->services.https_enabled = true;
            goto next_line;
        }

        /* cdp run */
        if (str_starts_with_ci(line, "cdp run")) {
            m->services.cdp_global = true;
            goto next_line;
        }
        if (str_starts_with_ci(line, "no cdp run")) {
            m->services.cdp_global = false;
            goto next_line;
        }

        /* service tcp-small-servers / udp-small-servers */
        if (str_starts_with_ci(line, "service tcp-small-servers")) {
            m->services.tcp_small_servers = true;
            goto next_line;
        }
        if (str_starts_with_ci(line, "service udp-small-servers")) {
            m->services.udp_small_servers = true;
            goto next_line;
        }

        /* NTP */
        if (str_starts_with_ci(line, "ntp server ")) {
            if (m->ntp.server_count < MAX_NTP_SERVERS) {
                get_token_after(line, "ntp server ", tok, sizeof(tok));
                safe_strncpy(m->ntp.servers[m->ntp.server_count++],
                             tok, MAX_IP_LEN);
            }
            goto next_line;
        }
        if (str_starts_with_ci(line, "ntp authenticate")) {
            m->ntp.authenticated = true;
            goto next_line;
        }

        /* Logging */
        if (str_starts_with_ci(line, "logging buffered")) {
            m->logging.buffered_enabled = true;
            char sz[16] = {0};
            if (get_token_after(line, "logging buffered ", sz, sizeof(sz)))
                m->logging.buffered_size = atoi(sz);
            goto next_line;
        }
        if (str_starts_with_ci(line, "logging console"))
            { m->logging.console_enabled = true; goto next_line; }
        if (str_starts_with_ci(line, "logging ")) {
            /* logging <ip-address> */
            get_token_after(line, "logging ", tok, sizeof(tok));
            if (tok[0] >= '0' && tok[0] <= '9' &&
                m->logging.server_count < MAX_LOG_SERVERS) {
                safe_strncpy(m->logging.servers[m->logging.server_count++],
                             tok, MAX_IP_LEN);
            }
            goto next_line;
        }

        /* SNMP */
        if (str_starts_with_ci(line, "snmp-server community ")) {
            m->snmp.enabled = true;
            /* snmp-server community <string> RO|RW [acl] */
            char comm[MAX_COMMUNITY_LEN], rw[8], acl_tok[MAX_ACLNAME_LEN];
            comm[0] = rw[0] = acl_tok[0] = '\0';
            sscanf(line + strlen("snmp-server community "),
                   "%63s %7s %63s", comm, rw, acl_tok);
            if (portable_strcasecmp(rw, "RW") == 0 || portable_strcasecmp(rw, "write") == 0) {
                safe_strncpy(m->snmp.community_rw, comm, MAX_COMMUNITY_LEN);
            } else {
                safe_strncpy(m->snmp.community_ro, comm, MAX_COMMUNITY_LEN);
            }
            if (m->snmp.version < SNMP_V2C) m->snmp.version = SNMP_V2C;
            if (acl_tok[0] != '\0') {
                m->snmp.has_restricting_acl = true;
                safe_strncpy(m->snmp.acl_name, acl_tok, MAX_ACLNAME_LEN);
            }
            goto next_line;
        }
        if (str_starts_with_ci(line, "snmp-server version 3") ||
            str_contains_ci(line, "snmp-server group") ||
            str_contains_ci(line, "snmp-server user")) {
            m->snmp.enabled  = true;
            m->snmp.version  = SNMP_V3;
            goto next_line;
        }

        /* Interface block start */
        if (str_starts_with_ci(line, "interface ")) {
            in_interface = true;
            in_line_vty  = false;
            in_acl       = false;
            get_token_after(line, "interface ", current_if, sizeof(current_if));
            int idx;
            find_or_create_iface(current_if, idx);
            (void)idx;
            goto next_line;
        }

        /* Line vty block */
        if (str_starts_with_ci(line, "line vty")) {
            in_line_vty  = true;
            in_interface = false;
            in_acl       = false;
            goto next_line;
        }

        /* ACL block */
        if (str_starts_with_ci(line, "ip access-list extended ")) {
            in_acl = true; acl_is_extended = true;
            in_interface = false; in_line_vty = false;
            get_token_after(line, "ip access-list extended ",
                            current_acl, sizeof(current_acl));
            if (m->acl_count < MAX_ACLS) {
                safe_strncpy(m->acls[m->acl_count].name, current_acl,
                             MAX_ACLNAME_LEN);
                m->acls[m->acl_count].is_extended = true;
                m->acl_count++;
            }
            goto next_line;
        }
        if (str_starts_with_ci(line, "ip access-list standard ")) {
            in_acl = true; acl_is_extended = false;
            in_interface = false; in_line_vty = false;
            get_token_after(line, "ip access-list standard ",
                            current_acl, sizeof(current_acl));
            if (m->acl_count < MAX_ACLS) {
                safe_strncpy(m->acls[m->acl_count].name, current_acl,
                             MAX_ACLNAME_LEN);
                m->acls[m->acl_count].is_extended = false;
                m->acl_count++;
            }
            goto next_line;
        }
        /* Numbered ACL: access-list <num> permit|deny ... */
        if (str_starts_with_ci(line, "access-list ")) {
            char num[16], action[8], proto[32], src[48], dst[48];
            num[0] = action[0] = proto[0] = src[0] = dst[0] = '\0';
            int matched = sscanf(line + strlen("access-list "),
                                 "%15s %7s %31s %47s %47s",
                                 num, action, proto, src, dst);
            if (matched >= 2) {
                /* Find or create numbered ACL */
                int ai = -1;
                for (int i = 0; i < m->acl_count; i++) {
                    if (strcmp(m->acls[i].name, num) == 0) { ai = i; break; }
                }
                if (ai == -1 && m->acl_count < MAX_ACLS) {
                    ai = m->acl_count++;
                    safe_strncpy(m->acls[ai].name, num, MAX_ACLNAME_LEN);
                }
                if (ai >= 0 && m->acls[ai].entry_count < MAX_ACL_ENTRIES) {
                    AclEntry *ae = &m->acls[ai].entries[m->acls[ai].entry_count++];
                    ae->action = (portable_strcasecmp(action, "permit") == 0) ?
                                 ACL_PERMIT : ACL_DENY;
                    safe_strncpy(ae->protocol, proto, MAX_PROTO_LEN);
                    safe_strncpy(ae->src_addr, src,   MAX_IP_LEN);
                    safe_strncpy(ae->dst_addr, dst,   MAX_IP_LEN);
                    ae->line_number = lineno;
                    /* Detect any-any */
                    if ((portable_strcasecmp(src, "any") == 0 || portable_strcasecmp(src, "0.0.0.0") == 0) &&
                        (portable_strcasecmp(dst, "any") == 0 || dst[0] == '\0')) {
                        if (ae->action == ACL_PERMIT) ae->is_any_any = true;
                    }
                }
            }
            goto next_line;
        }

        /* -- Indented (nested) directives ------------------------------- */
        if (in_interface) {
            char *trimmed = line;
            while (isspace((unsigned char)*trimmed)) trimmed++;

            int idx = -1;
            find_or_create_iface(current_if, idx);
            if (idx < 0) goto next_line;
            Interface *iface = &m->interfaces[idx];

            if (str_starts_with_ci(trimmed, "ip address ")) {
                char ip[MAX_IP_LEN], mask[MAX_MASK_LEN];
                ip[0] = mask[0] = '\0';
                sscanf(trimmed + strlen("ip address "),
                       "%47s %47s", ip, mask);
                safe_strncpy(iface->ip_address,  ip,   MAX_IP_LEN);
                safe_strncpy(iface->subnet_mask, mask, MAX_MASK_LEN);
            } else if (str_starts_with_ci(trimmed, "shutdown")) {
                iface->shutdown = true;
            } else if (str_starts_with_ci(trimmed, "no shutdown")) {
                iface->shutdown = false;
            } else if (str_starts_with_ci(trimmed, "no cdp enable")) {
                iface->cdp_enabled = false;
            } else if (str_starts_with_ci(trimmed, "no ip proxy-arp")) {
                iface->proxy_arp = false;
            } else if (str_starts_with_ci(trimmed, "ip access-group ")) {
                char aname[MAX_ACLNAME_LEN], dir[8];
                aname[0] = dir[0] = '\0';
                sscanf(trimmed + strlen("ip access-group "),
                       "%63s %7s", aname, dir);
                if (portable_strcasecmp(dir, "in") == 0)
                    safe_strncpy(iface->acl_in,  aname, MAX_ACLNAME_LEN);
                else
                    safe_strncpy(iface->acl_out, aname, MAX_ACLNAME_LEN);
            } else if (str_starts_with_ci(trimmed, "description ")) {
                get_token_after(trimmed, "description ",
                                iface->description, sizeof(iface->description));
            } else if (str_starts_with_ci(trimmed, "loopback")) {
                iface->is_loopback = true;
            }
            if (portable_strncasecmp(current_if, "loopback", 8) == 0)
                iface->is_loopback = true;
            if (str_contains_ci(current_if, "mgmt") ||
                str_contains_ci(current_if, "management"))
                iface->is_management = true;
        }

        if (in_line_vty) {
            char *trimmed = line;
            while (isspace((unsigned char)*trimmed)) trimmed++;

            /* transport input telnet|ssh|all|none */
            if (str_starts_with_ci(trimmed, "transport input ")) {
                char tport[64] = {0};
                get_token_after(trimmed, "transport input ", tport, sizeof(tport));
                if (portable_strcasecmp(tport, "telnet") == 0 ||
                    portable_strcasecmp(tport, "all")    == 0)
                    m->auth.telnet_on_vty = true;
                if (portable_strcasecmp(tport, "ssh") == 0 ||
                    portable_strcasecmp(tport, "all") == 0)
                    m->auth.ssh_enabled = true;
            }
        }

        if (in_acl) {
            char *trimmed = line;
            while (isspace((unsigned char)*trimmed)) trimmed++;

            /* find the current ACL */
            int ai = -1;
            for (int i = 0; i < m->acl_count; i++) {
                if (portable_strcasecmp(m->acls[i].name, current_acl) == 0) {
                    ai = i; break;
                }
            }
            if (ai >= 0 && m->acls[ai].entry_count < MAX_ACL_ENTRIES) {
                char action[8], proto[32], src[48], dst[48];
                action[0] = proto[0] = src[0] = dst[0] = '\0';
                int matched = sscanf(trimmed,
                    "%7s %31s %47s %47s", action, proto, src, dst);
                if (matched >= 1 &&
                    (portable_strcasecmp(action, "permit") == 0 ||
                     portable_strcasecmp(action, "deny")   == 0)) {
                    AclEntry *ae = &m->acls[ai].entries[m->acls[ai].entry_count++];
                    ae->action = (portable_strcasecmp(action, "permit") == 0) ?
                                 ACL_PERMIT : ACL_DENY;
                    if (acl_is_extended) {
                        safe_strncpy(ae->protocol, proto, MAX_PROTO_LEN);
                        safe_strncpy(ae->src_addr, src,   MAX_IP_LEN);
                        safe_strncpy(ae->dst_addr, dst,   MAX_IP_LEN);
                    } else {
                        /* Standard ACL: action [src] */
                        safe_strncpy(ae->src_addr, proto, MAX_IP_LEN);
                    }
                    ae->line_number = lineno;
                    if (ae->action == ACL_PERMIT &&
                        (portable_strcasecmp(ae->src_addr, "any") == 0) &&
                        (ae->dst_addr[0] == '\0' ||
                         portable_strcasecmp(ae->dst_addr, "any") == 0))
                        ae->is_any_any = true;
                }
            }
        }

    next_line:;
    }

    /* Defaults for Cisco if not explicitly disabled */
    if (m->services.cdp_global == false) {
        /* CDP is on by default in IOS unless 'no cdp run' seen */
        /* We set it true at start, 'no cdp run' clears it */
        m->services.cdp_global = true;
    }

    fclose(f);
    LOG_INF("cisco_parse: parsed '%s' — %d interfaces, %d ACLs",
            filepath, m->interface_count, m->acl_count);
    return AUDIT_OK;
}

/* -- Registration ---------------------------------------------------------- */

static const VendorParser s_cisco_parser = {
    .vendor_name = "cisco",
    .detect      = cisco_detect,
    .parse       = cisco_parse
};

/**
 * @brief Register the Cisco IOS parser with the global registry.
 */
void cisco_parser_register(void)
{
    parser_register(&s_cisco_parser);
}




