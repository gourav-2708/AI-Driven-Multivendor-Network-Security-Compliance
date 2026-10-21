/**
 * @file fortinet_fortios.c
 * @brief Fortinet FortiOS configuration parser.
 *
 * FortiOS backups are built from four keywords:
 *     config <section...>   open a section (sections nest)
 *     edit <key>            open a table entry inside a section
 *     set <attr> <values>   assign an attribute (also unset/append)
 *     next / end            close the entry / the section
 *
 * The parser keeps a stack of open sections and entries. Attributes whose
 * meaning depends on several lines (a firewall policy's addresses, action
 * and service; a syslog server and its status) are accumulated on the
 * stack frame and committed to the model when the frame closes.
 */
#include "netaudit/line_reader.h"
#include "netaudit/log.h"
#include "netaudit/parser.h"
#include "netaudit/safe_str.h"

#define FOS_MAX_DEPTH 16
#define FOS_NAME      96

typedef enum { FRAME_CONFIG, FRAME_EDIT } FrameKind;

typedef struct {
    FrameKind kind;
    char      name[FOS_NAME];   /* section path or entry key */
    int       line;

    /* Accumulators (meaning depends on the section). */
    char      label[NA_MAX_ACLNAME];        /* policy name / community   */
    char      server[NA_MAX_ADDR];          /* syslog / analyzer server  */
    bool      enabled, disabled;            /* explicit status / ntpsync */
    bool      accept;                       /* policy action             */
    bool      src_all, dst_all, svc_all;    /* policy match              */
    bool      restricted;                   /* SNMP community host list  */
    bool      v1;                           /* SNMP community v1 enabled */
    bool      type_custom;                  /* system ntp: type custom   */
} FFrame;

typedef struct {
    DeviceModel *m;
    FFrame       stack[FOS_MAX_DEPTH];
    int          depth;
    int          line;
} FState;

#define W(i)      ((i) < n ? w[i] : "")
#define IS(i, s)  str_eq_ci(W(i), (s))

/* -- Context helpers ----------------------------------------------------------- */

static FFrame *top(FState *st)
{
    return st->depth > 0 ? &st->stack[st->depth - 1] : NULL;
}

/* The @p nth innermost section (0 = innermost) and its frame index. */
static int section_index(const FState *st, int nth)
{
    for (int i = st->depth - 1; i >= 0; i--) {
        if (st->stack[i].kind == FRAME_CONFIG && nth-- == 0) return i;
    }
    return -1;
}

static const char *section(const FState *st, int nth)
{
    int i = section_index(st, nth);
    return i >= 0 ? st->stack[i].name : "";
}

/* The entry ("edit") frame directly inside section frame @p sec, if open. */
static FFrame *entry_of(FState *st, int sec)
{
    if (sec < 0 || sec + 1 >= st->depth) return NULL;
    FFrame *f = &st->stack[sec + 1];
    return f->kind == FRAME_EDIT ? f : NULL;
}

static bool any_word(char *w[], int n, int from, const char *value)
{
    for (int i = from; i < n; i++)
        if (str_eq_ci(w[i], value)) return true;
    return false;
}

static bool section_is(const FState *st, int nth, const char *name)
{
    return str_eq_ci(section(st, nth), name);
}

static bool is_policy_section(const char *s)
{
    return str_eq_ci(s, "firewall policy") || str_eq_ci(s, "firewall policy6") ||
           str_eq_ci(s, "firewall6 policy");
}

static bool is_syslog_section(const char *s)
{
    return (str_starts_with_ci(s, "log syslogd") ||
            str_starts_with_ci(s, "log fortianalyzer")) &&
           str_ends_with_ci(s, " setting");
}

/* -- "set" handlers --------------------------------------------------------------- */

static void set_interface(FState *st, FFrame *e, char *w[], int n)
{
    DeviceModel *m = st->m;
    Interface *it = model_interface(m, e->name);
    if (!it) return;

    if (IS(1, "ip") && !IS(2, "0.0.0.0")) {
        safe_strcpy(it->ip_address, sizeof(it->ip_address), W(2));
        safe_strcpy(it->subnet_mask, sizeof(it->subnet_mask), W(3));
    }
    if (IS(1, "mode") && (IS(2, "dhcp") || IS(2, "pppoe"))) it->dynamic_address = true;
    if (IS(1, "status")) it->shutdown = IS(2, "down");
    if (IS(1, "type") && IS(2, "loopback")) it->is_loopback = true;
    if (IS(1, "description"))
        safe_strcpy(it->description, sizeof(it->description), W(2));
    if (IS(1, "alias") && it->description[0] == '\0')
        safe_strcpy(it->description, sizeof(it->description), W(2));

    if (IS(1, "allowaccess")) {
        bool all = any_word(w, n, 2, "all");
        if (all || any_word(w, n, 2, "telnet")) m->mgmt.telnet_enabled = true;
        if (all || any_word(w, n, 2, "http"))   m->mgmt.http_enabled = true;
        if (all || any_word(w, n, 2, "https"))  m->mgmt.https_enabled = true;
        if (all || any_word(w, n, 2, "ssh")) {
            m->mgmt.ssh_enabled = true;
            m->mgmt.ssh_version = 2;
        }
    }
}

static void set_admin(FState *st, char *w[], int n)
{
    AuthConfig *a = &st->m->auth;
    a->local_users = true;
    if (IS(1, "password")) {
        if (IS(2, "ENC")) {
            a->enable_secret_set = true;
        } else {
            a->enable_password_set = true;
            a->plaintext_user_password = true;
        }
    }
    if (IS(1, "remote-auth") && IS(2, "enable")) a->aaa_configured = true;
}

static void set_policy(FFrame *e, char *w[], int n)
{
    if (IS(1, "name"))   safe_strcpy(e->label, sizeof(e->label), W(2));
    if (IS(1, "action")) e->accept = IS(2, "accept");
    if (IS(1, "status")) e->disabled = IS(2, "disable");
    if (IS(1, "srcaddr") || IS(1, "srcaddr6"))
        e->src_all = e->src_all || any_word(w, n, 2, "all");
    if (IS(1, "dstaddr") || IS(1, "dstaddr6"))
        e->dst_all = e->dst_all || any_word(w, n, 2, "all");
    if (IS(1, "service"))
        e->svc_all = e->svc_all || any_word(w, n, 2, "ALL");
}

static void handle_set(FState *st, char *w[], int n)
{
    DeviceModel *m = st->m;
    FFrame *t = top(st);
    if (!t) return;
    const char *sec = section(st, 0);
    int sec_i = section_index(st, 0);
    FFrame *entry = entry_of(st, sec_i);

    if (str_eq_ci(sec, "system global")) {
        if (IS(1, "hostname"))
            safe_strcpy(m->hostname, sizeof(m->hostname), W(2));
        if (IS(1, "admin-telnet") && IS(2, "enable")) m->mgmt.telnet_enabled = true;
        return;
    }
    if (str_eq_ci(sec, "system interface") && entry) { set_interface(st, entry, w, n); return; }
    if (str_eq_ci(sec, "system admin") && entry)     { set_admin(st, w, n);            return; }
    if (is_policy_section(sec) && entry)             { set_policy(entry, w, n);        return; }

    if (str_eq_ci(sec, "system snmp sysinfo")) {
        if (IS(1, "status") && IS(2, "enable")) m->snmp.enabled = true;
        return;
    }
    if (str_eq_ci(sec, "system snmp community") && entry) {
        if (IS(1, "name"))   safe_strcpy(entry->label, sizeof(entry->label), W(2));
        if (IS(1, "status")) entry->disabled = IS(2, "disable");
        if ((IS(1, "query-v1-status") || IS(1, "trap-v1-status")) && IS(2, "enable"))
            entry->v1 = true;
        return;
    }
    /* config hosts / hosts6 nested inside an SNMP community entry */
    if ((str_eq_ci(sec, "hosts") || str_eq_ci(sec, "hosts6")) &&
        section_is(st, 1, "system snmp community")) {
        FFrame *community = entry_of(st, section_index(st, 1));
        if (community && IS(1, "ip") &&
            !(IS(2, "0.0.0.0") && (n < 4 || IS(3, "0.0.0.0"))) &&
            !IS(2, "0.0.0.0/0") && !IS(2, "::/0"))
            community->restricted = true;
        return;
    }

    if (str_eq_ci(sec, "system ntp") || section_is(st, 1, "system ntp")) {
        FFrame *ntp = &st->stack[section_index(st, str_eq_ci(sec, "system ntp") ? 0 : 1)];
        if (IS(1, "ntpsync")) { ntp->enabled = IS(2, "enable"); ntp->disabled = IS(2, "disable"); }
        if (IS(1, "type"))    ntp->type_custom = IS(2, "custom");
        if (IS(1, "server") || IS(1, "server1") || IS(1, "server2"))
            model_add_ntp_server(m, W(2));
        if (IS(1, "authentication") && IS(2, "enable")) m->ntp.authenticated = true;
        return;
    }

    if (is_syslog_section(sec)) {
        if (IS(1, "status")) { t->enabled = IS(2, "enable"); t->disabled = IS(2, "disable"); }
        if (IS(1, "server")) safe_strcpy(t->server, sizeof(t->server), W(2));
        return;
    }
    if (str_eq_ci(sec, "log memory setting") || str_eq_ci(sec, "log disk setting")) {
        if (IS(1, "status") && IS(2, "enable")) m->logging.buffered_enabled = true;
        return;
    }
}

/* -- Frame open / close ------------------------------------------------------------- */

static void push(FState *st, FrameKind kind, const char *name)
{
    if (st->depth >= FOS_MAX_DEPTH) {
        LOG_WRN("%s:%d: nesting deeper than %d ignored", st->m->source_file,
                st->line, FOS_MAX_DEPTH);
        return;
    }
    FFrame *f = &st->stack[st->depth++];
    memset(f, 0, sizeof(*f));
    f->kind = kind;
    f->line = st->line;
    safe_strcpy(f->name, sizeof(f->name), name);

    const char *sec = section(st, 0);
    if (kind == FRAME_EDIT && str_eq_ci(sec, "system interface")) {
        Interface *it = model_interface(st->m, name);
        if (it) it->line_number = st->line;
    }
    if (kind == FRAME_EDIT && str_eq_ci(sec, "system admin"))
        st->m->auth.local_users = true;
    if (kind == FRAME_EDIT &&
        (str_eq_ci(sec, "user radius") || str_eq_ci(sec, "user tacacs+") ||
         str_eq_ci(sec, "user ldap")))
        st->m->auth.aaa_configured = true;
    if (kind == FRAME_EDIT && str_eq_ci(sec, "system snmp user")) {
        st->m->snmp.enabled = true;
        st->m->snmp.v3_configured = true;
    }
}

static void commit_entry(FState *st, const FFrame *e, const char *sec)
{
    DeviceModel *m = st->m;
    if (e->disabled) return;

    if (is_policy_section(sec)) {
        char name[NA_MAX_ACLNAME];
        if (e->label[0]) safe_snprintf(name, sizeof(name), "policy %s (%s)", e->name, e->label);
        else             safe_snprintf(name, sizeof(name), "policy %s", e->name);
        AclEntry *ae = model_acl_add_entry(m, model_acl(m, name));
        if (!ae) return;
        ae->action = e->accept ? ACL_PERMIT : ACL_DENY;   /* FortiOS default: deny */
        safe_strcpy(ae->src_addr, sizeof(ae->src_addr), e->src_all ? "all" : "match");
        safe_strcpy(ae->dst_addr, sizeof(ae->dst_addr), e->dst_all ? "all" : "match");
        safe_strcpy(ae->protocol, sizeof(ae->protocol), e->svc_all ? "ALL" : "match");
        ae->is_any_any = e->accept && e->src_all && e->dst_all && e->svc_all;
        ae->line_number = e->line;
        return;
    }
    if (str_eq_ci(sec, "system snmp community") && e->label[0]) {
        SnmpCommunity *c = model_snmp_community(m, e->label);
        if (!c) return;
        c->restricted = e->restricted;
        c->line_number = e->line;
        if (e->v1) m->snmp.v1_enabled = true;
    }
}

static void commit_section(FState *st, const FFrame *s)
{
    DeviceModel *m = st->m;
    if (is_syslog_section(s->name)) {
        if (s->enabled && s->server[0]) model_add_log_server(m, s->server);
        return;
    }
    if (str_eq_ci(s->name, "system ntp")) {
        if (s->disabled) {                       /* ntpsync disable */
            m->ntp.server_count = 0;
            m->ntp.authenticated = false;
        } else if (s->enabled && !s->type_custom && m->ntp.server_count == 0) {
            model_add_ntp_server(m, "fortiguard");   /* FortiGuard NTP */
        }
    }
}

static void pop(FState *st)
{
    if (st->depth == 0) return;
    FFrame *f = &st->stack[st->depth - 1];
    if (f->kind == FRAME_EDIT) {
        char sec[FOS_NAME];
        safe_strcpy(sec, sizeof(sec), section(st, 0));
        commit_entry(st, f, sec);
    } else {
        commit_section(st, f);
    }
    st->depth--;
}

static void handle_line(FState *st, char *w[], int n)
{
    if (IS(0, "config") && n >= 2) {
        char name[FOS_NAME] = "";
        for (int i = 1; i < n; i++) {
            if (i > 1) safe_strcat(name, sizeof(name), " ");
            safe_strcat(name, sizeof(name), w[i]);
        }
        push(st, FRAME_CONFIG, name);
    } else if (IS(0, "edit") && n >= 2) {
        FFrame *t = top(st);
        if (t && t->kind == FRAME_EDIT) pop(st);     /* tolerate missing "next" */
        push(st, FRAME_EDIT, W(1));
    } else if (IS(0, "next")) {
        FFrame *t = top(st);
        if (t && t->kind == FRAME_EDIT) pop(st);
    } else if (IS(0, "end")) {
        while (st->depth > 0 && top(st)->kind == FRAME_EDIT) pop(st);
        pop(st);
    } else if (IS(0, "set") || IS(0, "append")) {
        handle_set(st, w, n);
    }
}

/* -- probe / parse --------------------------------------------------------------------- */

static int fos_probe(const ConfigSample *s)
{
    if (sample_has_prefix(s, "#config-version=")) return 95;
    if (sample_has_prefix_ci(s, "config system ") || sample_has_prefix_ci(s, "config firewall ") ||
        sample_has_prefix_ci(s, "config log ") || sample_has_prefix_ci(s, "config user ") ||
        sample_has_prefix_ci(s, "config router "))
        return 85;
    return 0;
}

static AuditStatus fos_parse(const char *path, DeviceModel *m)
{
    static FState st;                  /* ~4 KB: keep it off the stack */
    LineReader r;
    AuditStatus rc = line_reader_open(&r, path);
    if (rc != AUDIT_OK) return rc;

    safe_strcpy(m->vendor, sizeof(m->vendor), "fortinet");
    safe_strcpy(m->source_file, sizeof(m->source_file), path);
    memset(&st, 0, sizeof(st));
    st.m = m;

    char *words[NA_MAX_TOKENS];
    char *line;
    while ((line = line_reader_next(&r)) != NULL) {
        st.line = r.line_number;
        str_trim(line);
        if (line[0] == '\0' || line[0] == '#') continue;
        int n = str_tokenize(line, words, NA_MAX_TOKENS);
        handle_line(&st, words, n);
    }
    while (st.depth > 0) pop(&st);      /* commit anything left open */

    rc = line_reader_failed(&r) ? AUDIT_ERR_IO : AUDIT_OK;
    line_reader_close(&r);

    LOG_INF("fortinet: parsed '%s' (%d lines, %d interfaces, %d policies)",
            path, r.line_number, m->interface_count, m->acl_count);
    return rc;
}

const VendorParser PARSER_FORTINET_FORTIOS = {
    .name         = "fortinet",
    .display_name = "Fortinet FortiOS",
    .probe        = fos_probe,
    .parse        = fos_parse,
};
