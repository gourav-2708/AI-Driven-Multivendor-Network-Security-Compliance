/**
 * @file cisco_ios.c
 * @brief Cisco IOS / IOS-XE configuration parser.
 *
 * IOS configs are line-oriented. A non-indented line is a global command
 * and may open a sub-mode (interface, line vty, ip access-list); indented
 * lines that follow belong to that sub-mode. Lines whose first non-blank
 * character is '!' are comments ('!' elsewhere is data, e.g. inside an
 * SNMP community string).
 */
#include "netaudit/line_reader.h"
#include "netaudit/log.h"
#include "netaudit/parser.h"
#include "netaudit/safe_str.h"

typedef enum { MODE_GLOBAL, MODE_INTERFACE, MODE_VTY, MODE_ACL, MODE_OTHER } IosMode;

typedef struct {
    DeviceModel *m;
    IosMode      mode;
    Interface   *iface;          /* MODE_INTERFACE */
    Acl         *acl;            /* MODE_ACL       */
    bool         acl_extended;
    bool         cdp_disabled;
    int          line;
} IosState;

#define W(i)      ((i) < n ? w[i] : "")
#define IS(i, s)  str_eq_ci(W(i), (s))

/* Text of @p line after its first word, e.g. the free-form part of
 * "description Uplink to core". */
static const char *after_first_word(const char *line)
{
    while (*line && !isspace((unsigned char)*line)) line++;
    while (isspace((unsigned char)*line)) line++;
    return line;
}

/* -- probe ------------------------------------------------------------------- */

static int ios_probe(const ConfigSample *s)
{
    static const char *const strong[] = {
        "enable secret", "enable password", "service password-encryption",
        "aaa new-model", "ip access-list", "access-list ", "snmp-server ",
        "line vty", "ip route ", "ip http ", "ip ssh ", "cdp run", "no cdp run",
        "service timestamps", "boot-start-marker",
    };
    for (size_t i = 0; i < NA_ARRAY_LEN(strong); i++) {
        if (sample_has_prefix_ci(s, strong[i])) return 80;
    }
    if (sample_has_prefix(s, "!") && sample_has_prefix_ci(s, "hostname "))
        return 60;
    if (sample_has_prefix(s, "!")) return 40;
    return 0;
}

/* -- ACL entries --------------------------------------------------------------- */

/* Consume one address spec ("any", "host A", "A WILDCARD", "object-group X")
 * starting at w[*i]. Returns true when the spec matches every address. */
static bool take_address(char *w[], int n, int *i, char *out, size_t out_size)
{
    const char *t = W(*i);
    if (str_eq_ci(t, "any") || str_eq_ci(t, "any4") || str_eq_ci(t, "any6")) {
        safe_strcpy(out, out_size, "any");
        (*i)++;
        return true;
    }
    if (str_eq_ci(t, "host") || str_eq_ci(t, "object-group") ||
        str_eq_ci(t, "addrgroup")) {
        safe_strcpy(out, out_size, W(*i + 1));
        *i += 2;
        return false;
    }
    safe_strcpy(out, out_size, t);
    bool all = str_eq_ci(t, "0.0.0.0") &&
               str_eq_ci(W(*i + 1), "255.255.255.255");
    *i += (*i + 1 < n && strchr(W(*i + 1), '.') != NULL) ? 2 : 1;
    return all;
}

static bool is_port_operator(const char *t)
{
    return str_eq_ci(t, "eq") || str_eq_ci(t, "neq") || str_eq_ci(t, "lt") ||
           str_eq_ci(t, "gt") || str_eq_ci(t, "range");
}

/* Parse "[seq] permit|deny ..." into @p acl. */
static void ios_acl_entry(IosState *st, Acl *acl, bool extended,
                          char *w[], int n)
{
    int i = 0;
    int seq;
    if (str_to_int(W(0), &seq)) i++;                 /* optional sequence  */
    if (!IS(i, "permit") && !IS(i, "deny")) return;  /* remark, etc.       */

    AclEntry *e = model_acl_add_entry(st->m, acl);
    if (!e) return;
    e->action = IS(i, "permit") ? ACL_PERMIT : ACL_DENY;
    e->line_number = st->line;
    i++;

    bool src_all, dst_all = true, port_limited = false;
    if (extended) {
        safe_strcpy(e->protocol, sizeof(e->protocol), W(i));
        i++;
        src_all = take_address(w, n, &i, e->src_addr, sizeof(e->src_addr));
        if (is_port_operator(W(i))) {
            port_limited = true;
            i += IS(i, "range") ? 3 : 2;
        }
        dst_all = take_address(w, n, &i, e->dst_addr, sizeof(e->dst_addr));
        if (is_port_operator(W(i))) port_limited = true;
    } else {
        src_all = take_address(w, n, &i, e->src_addr, sizeof(e->src_addr));
    }
    e->is_any_any = e->action == ACL_PERMIT && src_all && dst_all &&
                    !port_limited;
}

/* "access-list N permit|deny ..." (numbered ACL, global mode). */
static void ios_numbered_acl(IosState *st, char *w[], int n)
{
    int num;
    if (n < 3 || !str_to_int(W(1), &num)) return;
    bool extended = (num >= 100 && num <= 199) || (num >= 2000 && num <= 2699);
    Acl *acl = model_acl(st->m, W(1));
    if (acl) ios_acl_entry(st, acl, extended, w + 2, n - 2);
}

/* -- Global commands ---------------------------------------------------------- */

static void ios_snmp_community(IosState *st, char *w[], int n)
{
    /* snmp-server community NAME [view V] [RO|RW] [ACL] */
    SnmpCommunity *c = model_snmp_community(st->m, W(2));
    if (!c) return;
    c->line_number = st->line;
    c->access = SNMP_RO;
    for (int i = 3; i < n; i++) {
        if (IS(i, "view"))       { i++; continue; }
        if (IS(i, "ro"))         { c->access = SNMP_RO; continue; }
        if (IS(i, "rw"))         { c->access = SNMP_RW; continue; }
        if (IS(i, "ipv6"))       { i++; continue; }
        c->restricted = true;    /* trailing word is an ACL name/number */
    }
}

static void ios_logging(IosState *st, char *w[], int n)
{
    DeviceModel *m = st->m;
    if (IS(1, "buffered")) { m->logging.buffered_enabled = true; return; }
    if (IS(1, "host")) {
        /* logging host [ipv6] [vrf V] ADDR ... */
        int i = 2;
        while (IS(i, "ipv6") || IS(i, "vrf")) i += IS(i, "vrf") ? 2 : 1;
        model_add_log_server(m, W(i));
        return;
    }
    /* Legacy form "logging ADDR": first character is a digit or ':' */
    const char *a = W(1);
    if (isdigit((unsigned char)a[0]) || (a[0] == ':' && a[1] != '\0'))
        model_add_log_server(m, a);
}

static void ios_no_command(IosState *st, char *w[], int n)
{
    DeviceModel *m = st->m;
    (void)n;
    if (IS(1, "cdp") && IS(2, "run"))                  st->cdp_disabled = true;
    else if (IS(1, "service") && IS(2, "password-encryption"))
        m->auth.password_encryption = false;
    else if (IS(1, "service") && IS(2, "tcp-small-servers"))
        m->services.tcp_small_servers = false;
    else if (IS(1, "service") && IS(2, "udp-small-servers"))
        m->services.udp_small_servers = false;
    else if (IS(1, "ip") && IS(2, "http") && IS(3, "server"))
        m->mgmt.http_enabled = false;
    else if (IS(1, "ip") && IS(2, "http") && IS(3, "secure-server"))
        m->mgmt.https_enabled = false;
    else if (IS(1, "logging") && IS(2, "buffered"))
        m->logging.buffered_enabled = false;
}

static void ios_global(IosState *st, char *w[], int n)
{
    DeviceModel *m = st->m;
    st->mode = MODE_GLOBAL;

    if (IS(0, "no"))               { ios_no_command(st, w, n); return; }
    if (IS(0, "hostname"))         { safe_strcpy(m->hostname, sizeof(m->hostname), W(1)); return; }
    if (IS(0, "version"))          { safe_strcpy(m->os_version, sizeof(m->os_version), W(1)); return; }

    if (IS(0, "enable") && IS(1, "secret"))   { m->auth.enable_secret_set = true; return; }
    if (IS(0, "enable") && IS(1, "password")) { m->auth.enable_password_set = true; return; }
    if (IS(0, "service") && IS(1, "password-encryption")) { m->auth.password_encryption = true; return; }
    if (IS(0, "service") && IS(1, "tcp-small-servers"))   { m->services.tcp_small_servers = true; return; }
    if (IS(0, "service") && IS(1, "udp-small-servers"))   { m->services.udp_small_servers = true; return; }

    if (IS(0, "username")) {
        m->auth.local_users = true;
        for (int i = 2; i < n; i++)
            if (IS(i, "password")) m->auth.plaintext_user_password = true;
        return;
    }
    if (IS(0, "aaa") && IS(1, "new-model")) { m->auth.aaa_configured = true; return; }

    if (IS(0, "ip") && IS(1, "ssh") && IS(2, "version")) {
        int v;
        m->mgmt.ssh_enabled = true;
        if (str_to_int(W(3), &v)) m->mgmt.ssh_version = v;
        return;
    }
    if (IS(0, "crypto") && IS(1, "key") && IS(2, "generate") && IS(3, "rsa")) {
        m->mgmt.ssh_enabled = true;
        return;
    }
    if (IS(0, "ip") && IS(1, "http") && IS(2, "server"))        { m->mgmt.http_enabled = true; return; }
    if (IS(0, "ip") && IS(1, "http") && IS(2, "secure-server")) { m->mgmt.https_enabled = true; return; }
    if (IS(0, "cdp") && IS(1, "run"))                           { st->cdp_disabled = false; return; }

    if (IS(0, "ntp") && IS(1, "server")) {
        int i = 2;
        if (IS(i, "vrf")) i += 2;
        model_add_ntp_server(m, W(i));
        return;
    }
    if (IS(0, "ntp") && IS(1, "authenticate")) { m->ntp.authenticated = true; return; }
    if (IS(0, "logging"))                      { ios_logging(st, w, n); return; }

    if (IS(0, "snmp-server") && IS(1, "community") && n >= 3) {
        ios_snmp_community(st, w, n);
        return;
    }
    if (IS(0, "snmp-server") &&
        (IS(1, "group") || IS(1, "user") ||
         (IS(1, "host") && n > 4 && IS(3, "version") && IS(4, "3")))) {
        m->snmp.enabled = true;
        m->snmp.v3_configured = true;
        return;
    }

    if (IS(0, "interface") && n >= 2) {
        st->iface = model_interface(m, W(1));
        if (st->iface) st->iface->line_number = st->line;
        st->mode = st->iface ? MODE_INTERFACE : MODE_OTHER;
        return;
    }
    if (IS(0, "line")) {
        st->mode = IS(1, "vty") ? MODE_VTY : MODE_OTHER;
        return;
    }
    if (IS(0, "ip") && IS(1, "access-list") && n >= 4 &&
        (IS(2, "extended") || IS(2, "standard"))) {
        st->acl = model_acl(m, W(3));
        st->acl_extended = !IS(2, "standard");
        st->mode = st->acl ? MODE_ACL : MODE_OTHER;
        return;
    }
    if (IS(0, "access-list")) { ios_numbered_acl(st, w, n); return; }

    st->mode = MODE_OTHER;          /* unknown block: ignore its body */
}

/* -- Sub-mode commands --------------------------------------------------------- */

static void ios_interface(IosState *st, char *w[], int n, const char *raw)
{
    Interface *it = st->iface;
    if (IS(0, "ip") && IS(1, "address")) {
        if (IS(2, "dhcp") || IS(2, "negotiated")) {
            it->dynamic_address = true;
        } else {
            safe_strcpy(it->ip_address, sizeof(it->ip_address), W(2));
            safe_strcpy(it->subnet_mask, sizeof(it->subnet_mask), W(3));
        }
    } else if (IS(0, "shutdown")) {
        it->shutdown = true;
    } else if (IS(0, "no") && IS(1, "shutdown")) {
        it->shutdown = false;
    } else if (IS(0, "description")) {
        safe_strcpy(it->description, sizeof(it->description),
                    after_first_word(raw));
    } else if (IS(0, "ip") && IS(1, "access-group") && n >= 4) {
        if (IS(3, "in"))
            safe_strcpy(it->acl_in, sizeof(it->acl_in), W(2));
        else
            safe_strcpy(it->acl_out, sizeof(it->acl_out), W(2));
    }
}

/* Only telnet matters here: "transport input ssh" permits SSH on the lines
 * but does not start the SSH server (that needs keys / "ip ssh version"). */
static void ios_vty(IosState *st, char *w[], int n)
{
    if (!(IS(0, "transport") && IS(1, "input"))) return;
    for (int i = 2; i < n; i++) {
        if (IS(i, "telnet") || IS(i, "all")) st->m->mgmt.telnet_enabled = true;
    }
}

/* -- parse ---------------------------------------------------------------------- */

static AuditStatus ios_parse(const char *path, DeviceModel *m)
{
    LineReader r;
    AuditStatus rc = line_reader_open(&r, path);
    if (rc != AUDIT_OK) return rc;

    safe_strcpy(m->vendor, sizeof(m->vendor), "cisco");
    safe_strcpy(m->source_file, sizeof(m->source_file), path);

    IosState st = { .m = m, .mode = MODE_GLOBAL };
    char raw[NA_MAX_LINE];
    char *words[NA_MAX_TOKENS];
    char *line;

    while ((line = line_reader_next(&r)) != NULL) {
        st.line = r.line_number;
        bool indented = isspace((unsigned char)line[0]);
        str_trim(line);
        if (line[0] == '\0' || line[0] == '!') continue;

        safe_strcpy(raw, sizeof(raw), line);
        int n = str_tokenize(line, words, NA_MAX_TOKENS);
        if (n == 0) continue;

        if (!indented || st.mode == MODE_GLOBAL) {
            ios_global(&st, words, n);
            continue;
        }
        switch (st.mode) {
        case MODE_INTERFACE: ios_interface(&st, words, n, raw);                 break;
        case MODE_VTY:       ios_vty(&st, words, n);                            break;
        case MODE_ACL:       ios_acl_entry(&st, st.acl, st.acl_extended, words, n); break;
        default:                                                                break;
        }
    }

    rc = line_reader_failed(&r) ? AUDIT_ERR_IO : AUDIT_OK;
    line_reader_close(&r);

    /* CDP runs by default on IOS unless "no cdp run" is present. */
    m->services.cdp_global = !st.cdp_disabled;

    LOG_INF("cisco: parsed '%s' (%d lines, %d interfaces, %d ACLs)",
            path, r.line_number, m->interface_count, m->acl_count);
    return rc;
}

const VendorParser PARSER_CISCO_IOS = {
    .name         = "cisco",
    .display_name = "Cisco IOS",
    .probe        = ios_probe,
    .parse        = ios_parse,
};
