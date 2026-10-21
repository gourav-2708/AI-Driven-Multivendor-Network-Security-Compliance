/**
 * @file juniper_junos.c
 * @brief Juniper JunOS (curly-brace "show configuration") parser.
 *
 * A small lexer turns the text into statements:
 *     words... {     opens a block whose header is the words
 *     words... ;     a leaf statement
 *     }              closes the innermost block
 * Comments (#..., ##..., / * ... * /) and list brackets are skipped, quoted
 * strings are single words, and a statement may span several lines or share
 * a line with others ("log { session-init; }").
 *
 * Handlers receive each block open, leaf and block close together with the
 * stack of enclosing block headers, so context checks are structural
 * ("parent block is `services`") rather than string matching on a path.
 * Interface names such as ge-0/0/0 therefore need no special treatment.
 */
#include "netaudit/line_reader.h"
#include "netaudit/log.h"
#include "netaudit/parser.h"
#include "netaudit/safe_str.h"

#define JUNOS_MAX_DEPTH  24
#define JUNOS_WORD       96
#define JUNOS_HDR_WORDS   4

typedef struct {
    char  w[JUNOS_HDR_WORDS][JUNOS_WORD];   /* first words of the header  */
    int   line;
    bool  inactive;                          /* "inactive:" block/subtree  */

    /* Accumulators for firewall-filter terms and SRX security policies. */
    Acl  *acl;
    bool  has_match;     /* term: a non-empty "from" condition           */
    bool  permit, deny;
    bool  src_any, dst_any, app_any;
} JFrame;

typedef struct {
    DeviceModel *m;
    JFrame       stack[JUNOS_MAX_DEPTH];
    int          depth;          /* open frames stored on the stack       */
    int          lost_depth;     /* frames beyond JUNOS_MAX_DEPTH         */

    char         sw[NA_MAX_TOKENS][JUNOS_WORD];   /* current statement     */
    int          sn;
    int          stmt_line;
    bool         in_comment;     /* inside a / * ... * / comment          */
} JState;

/* -- Context helpers ------------------------------------------------------------ */

/* Header keyword of the frame @p up levels above the innermost (0). */
static const char *kw_up(const JState *st, int up)
{
    if (up < 0 || up >= st->depth) return "";
    return st->stack[st->depth - 1 - up].w[0];
}

static bool parent_is(const JState *st, const char *kw)
{
    return str_eq_ci(kw_up(st, 0), kw);
}

/* True when the outermost frame is @p kw (top-level stanza). */
static bool under_top(const JState *st, const char *kw)
{
    return st->depth > 0 && str_eq_ci(st->stack[0].w[0], kw);
}

/* Index of the innermost frame with keyword @p kw, or -1. */
static int find_frame(const JState *st, const char *kw)
{
    for (int i = st->depth - 1; i >= 0; i--)
        if (str_eq_ci(st->stack[i].w[0], kw)) return i;
    return -1;
}

static bool under_system(const JState *st)  { return under_top(st, "system"); }

/* snmp may appear at top level or (non-canonically) inside system. */
static int snmp_frame(const JState *st)
{
    if (under_top(st, "snmp")) return 0;
    if (under_system(st) && st->depth > 1 && str_eq_ci(st->stack[1].w[0], "snmp"))
        return 1;
    return -1;
}

/* The interface currently being configured, if any. */
static Interface *current_interface(JState *st)
{
    if (!under_top(st, "interfaces") || st->depth < 2) return NULL;
    return model_interface(st->m, st->stack[1].w[0]);
}

static bool is_any_address(const char *w)
{
    return str_eq_ci(w, "any") || str_eq_ci(w, "any-ipv4") ||
           str_eq_ci(w, "any-ipv6");
}

/* -- Statement handlers --------------------------------------------------------- */

#define W(i)      ((i) < n ? w[i] : "")
#define IS(i, s)  str_eq_ci(W(i), (s))

static void handle_system(JState *st, char w[][JUNOS_WORD], int n, bool block)
{
    DeviceModel *m = st->m;
    const char *parent = kw_up(st, 0);

    if (IS(0, "host-name") && str_eq_ci(parent, "system"))
        safe_strcpy(m->hostname, sizeof(m->hostname), W(1));

    if (IS(0, "authentication-order") || IS(0, "radius-server") ||
        IS(0, "tacplus-server"))
        m->auth.aaa_configured = true;

    if (find_frame(st, "root-authentication") >= 0) {
        if (IS(0, "encrypted-password") || IS(0, "ssh-rsa") ||
            IS(0, "ssh-ecdsa") || IS(0, "ssh-ed25519"))
            m->auth.enable_secret_set = true;
        if (IS(0, "plain-text-password") || IS(0, "plain-text-password-value"))
            m->auth.enable_password_set = true;
    }
    if (find_frame(st, "login") >= 0) {
        if (IS(0, "user")) m->auth.local_users = true;
        if (IS(0, "plain-text-password") || IS(0, "plain-text-password-value"))
            m->auth.plaintext_user_password = true;
    }

    /* system { services { telnet; ssh { ... } web-management { http; } } } */
    if (str_eq_ci(parent, "services")) {
        if (IS(0, "telnet")) m->mgmt.telnet_enabled = true;
        if (IS(0, "ssh")) {
            m->mgmt.ssh_enabled = true;
            if (m->mgmt.ssh_version == 0) m->mgmt.ssh_version = 2;
        }
    }
    if (str_eq_ci(parent, "services") || str_eq_ci(parent, "web-management")) {
        if (IS(0, "http"))  m->mgmt.http_enabled = true;
        if (IS(0, "https")) m->mgmt.https_enabled = true;
    }
    if (str_eq_ci(parent, "ssh") && str_eq_ci(kw_up(st, 1), "services") &&
        IS(0, "protocol-version")) {
        for (int i = 1; i < n; i++)
            if (IS(i, "v1")) m->mgmt.ssh_version = 1;
    }

    if (str_eq_ci(parent, "syslog")) {
        if (IS(0, "host") && !IS(1, "local")) model_add_log_server(m, W(1));
        if (IS(0, "file")) m->logging.buffered_enabled = true;
    }

    if (str_eq_ci(parent, "ntp")) {
        if (IS(0, "server")) model_add_ntp_server(m, W(1));
        if (IS(0, "authentication-key")) m->ntp.authenticated = true;
    }
    (void)block;
}

static void handle_snmp(JState *st, char w[][JUNOS_WORD], int n, bool block)
{
    DeviceModel *m = st->m;
    int base = snmp_frame(st);
    int rel  = st->depth - 1 - base;      /* 0 = directly inside snmp { } */

    m->snmp.enabled = true;
    if (rel == 0 && IS(0, "community")) {
        SnmpCommunity *c = model_snmp_community(m, W(1));
        if (c) c->line_number = st->stmt_line;
    }
    if (rel == 0 && IS(0, "v3")) m->snmp.v3_configured = true;

    if (parent_is(st, "community")) {
        SnmpCommunity *c = model_snmp_community(m, st->stack[st->depth - 1].w[1]);
        if (!c) return;
        if (IS(0, "authorization") && str_contains_ci(W(1), "write"))
            c->access = SNMP_RW;
        if (IS(0, "clients") || IS(0, "client-list-name"))
            c->restricted = true;
    }
    (void)block;
}

static void handle_interface(JState *st, char w[][JUNOS_WORD], int n, bool block)
{
    if (st->depth == 1) {                 /* "ge-0/0/0 {" itself */
        if (block && !IS(0, "interface-range")) {
            Interface *it = model_interface(st->m, W(0));
            if (it) it->line_number = st->stmt_line;
        }
        return;
    }
    Interface *it = current_interface(st);
    if (!it) return;

    if (IS(0, "description"))
        safe_strcpy(it->description, sizeof(it->description), W(1));
    if (IS(0, "disable") && !block && st->depth == 2)
        it->shutdown = true;
    if (IS(0, "address") && it->ip_address[0] == '\0') {
        char addr[NA_MAX_ADDR];
        safe_strcpy(addr, sizeof(addr), W(1));
        char *slash = strchr(addr, '/');
        if (slash) {
            safe_strcpy(it->subnet_mask, sizeof(it->subnet_mask), slash + 1);
            *slash = '\0';
        }
        safe_strcpy(it->ip_address, sizeof(it->ip_address), addr);
    }
    if (IS(0, "dhcp") || IS(0, "dhcp-client"))
        it->dynamic_address = true;
    if (parent_is(st, "filter")) {
        if (IS(0, "input"))  safe_strcpy(it->acl_in,  sizeof(it->acl_in),  W(1));
        if (IS(0, "output")) safe_strcpy(it->acl_out, sizeof(it->acl_out), W(1));
    }
    if (IS(0, "filter") && IS(1, "input"))  safe_strcpy(it->acl_in,  sizeof(it->acl_in),  W(2));
    if (IS(0, "filter") && IS(1, "output")) safe_strcpy(it->acl_out, sizeof(it->acl_out), W(2));
}

/* Innermost firewall term or security policy frame, if we are inside one. */
static JFrame *rule_frame(JState *st, const char *kw)
{
    int i = find_frame(st, kw);
    return i >= 0 ? &st->stack[i] : NULL;
}

static void handle_rule_leaf(JState *st, char w[][JUNOS_WORD], int n)
{
    /* Firewall filter terms */
    JFrame *term = under_top(st, "firewall") ? rule_frame(st, "term") : NULL;
    if (term && term->acl) {
        if (find_frame(st, "from") > find_frame(st, "term")) term->has_match = true;
        bool in_then = parent_is(st, "then");
        int  a = in_then ? 0 : (IS(0, "then") ? 1 : -1);
        if (a >= 0) {
            if (IS(a, "accept"))                     term->permit = true;
            if (IS(a, "discard") || IS(a, "reject")) term->deny = true;
        }
    }

    /* SRX security policies */
    JFrame *pol = under_top(st, "security") ? rule_frame(st, "policy") : NULL;
    if (pol && pol->acl) {
        if (parent_is(st, "match")) {
            for (int i = 1; i < n; i++) {
                if (IS(0, "source-address")      && is_any_address(W(i))) pol->src_any = true;
                if (IS(0, "destination-address") && is_any_address(W(i))) pol->dst_any = true;
                if (IS(0, "application")         && IS(i, "any"))          pol->app_any = true;
            }
        }
        if (parent_is(st, "then")) {
            if (IS(0, "permit"))                    pol->permit = true;
            if (IS(0, "deny") || IS(0, "reject"))   pol->deny = true;
        }
    }
}

static void dispatch(JState *st, char w[][JUNOS_WORD], int n, bool block)
{
    if (n == 0) return;
    if (st->depth == 0 && IS(0, "version"))
        safe_strcpy(st->m->os_version, sizeof(st->m->os_version), W(1));

    if (snmp_frame(st) >= 0)               handle_snmp(st, w, n, block);
    else if (under_system(st))             handle_system(st, w, n, block);
    if (under_top(st, "interfaces"))       handle_interface(st, w, n, block);
    handle_rule_leaf(st, w, n);
}

/* -- Block events ---------------------------------------------------------------- */

static void open_block(JState *st)
{
    bool inactive = st->depth > 0 && st->stack[st->depth - 1].inactive;
    int  first = 0;
    if (st->sn > 0 && str_eq_ci(st->sw[0], "inactive:")) { inactive = true; first = 1; }
    if (st->sn > 0 && str_eq_ci(st->sw[0], "protect:"))   first = 1;

    if (!inactive) dispatch(st, st->sw + first, st->sn - first, true);

    if (st->depth >= JUNOS_MAX_DEPTH) { st->lost_depth++; return; }

    JFrame *f = &st->stack[st->depth];
    memset(f, 0, sizeof(*f));
    for (int i = 0; i < JUNOS_HDR_WORDS && first + i < st->sn; i++)
        safe_strcpy(f->w[i], JUNOS_WORD, st->sw[first + i]);
    f->line = st->stmt_line;
    f->inactive = inactive;

    /* Prepare rule accumulators. */
    if (!inactive && under_top(st, "firewall") &&
        str_eq_ci(f->w[0], "term") && parent_is(st, "filter")) {
        char name[NA_MAX_ACLNAME];
        safe_snprintf(name, sizeof(name), "%s", st->stack[st->depth - 1].w[1]);
        f->acl = model_acl(st->m, name);
    }
    if (!inactive && under_top(st, "security") && str_eq_ci(f->w[0], "policy") &&
        find_frame(st, "policies") >= 0) {
        char name[NA_MAX_ACLNAME];
        safe_snprintf(name, sizeof(name), "policy %s", f->w[1]);
        f->acl = model_acl(st->m, name);
    }
    st->depth++;
}

static void close_block(JState *st)
{
    if (st->lost_depth > 0) { st->lost_depth--; return; }
    if (st->depth == 0) return;               /* unbalanced '}' */

    JFrame *f = &st->stack[--st->depth];
    if (!f->acl || f->inactive || (!f->permit && !f->deny)) return;

    AclEntry *e = model_acl_add_entry(st->m, f->acl);
    if (!e) return;
    e->action = f->permit ? ACL_PERMIT : ACL_DENY;
    e->line_number = f->line;
    if (str_eq_ci(f->w[0], "term")) {
        safe_strcpy(e->src_addr, sizeof(e->src_addr), f->has_match ? "match" : "any");
        safe_strcpy(e->dst_addr, sizeof(e->dst_addr), f->has_match ? "match" : "any");
        e->is_any_any = f->permit && !f->has_match;
    } else {
        safe_strcpy(e->src_addr, sizeof(e->src_addr), f->src_any ? "any" : "match");
        safe_strcpy(e->dst_addr, sizeof(e->dst_addr), f->dst_any ? "any" : "match");
        e->is_any_any = f->permit && f->src_any && f->dst_any && f->app_any;
    }
}

static void leaf(JState *st)
{
    if (st->sn == 0) return;
    bool inactive = st->depth > 0 && st->stack[st->depth - 1].inactive;
    if (inactive || str_eq_ci(st->sw[0], "inactive:")) return;
    int first = str_eq_ci(st->sw[0], "protect:") ? 1 : 0;
    dispatch(st, st->sw + first, st->sn - first, false);
}

/* -- Lexer ----------------------------------------------------------------------- */

static void push_word(JState *st, const char *start, size_t len, int line)
{
    if (st->sn == 0) st->stmt_line = line;
    if (st->sn >= NA_MAX_TOKENS) return;
    safe_strncpy_n(st->sw[st->sn++], JUNOS_WORD, start, len);
}

static void lex_line(JState *st, const char *p, int line)
{
    while (*p) {
        if (st->in_comment) {
            const char *end = strstr(p, "*/");
            if (!end) return;
            st->in_comment = false;
            p = end + 2;
            continue;
        }
        unsigned char c = (unsigned char)*p;
        if (isspace(c) || c == '[' || c == ']') { p++; continue; }
        if (c == '#') return;
        if (c == '/' && p[1] == '*') { st->in_comment = true; p += 2; continue; }
        if (c == '{') { open_block(st);  st->sn = 0; p++; continue; }
        if (c == ';') { leaf(st);        st->sn = 0; p++; continue; }
        if (c == '}') {
            leaf(st);                     /* tolerate a missing ';' */
            st->sn = 0;
            close_block(st);
            p++;
            continue;
        }
        if (c == '"') {
            const char *start = ++p;
            while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; }
            push_word(st, start, (size_t)(p - start), line);
            if (*p) p++;
            continue;
        }
        const char *start = p;
        while (*p && !isspace((unsigned char)*p) && !strchr("{};\"[]#", *p)) p++;
        push_word(st, start, (size_t)(p - start), line);
    }
}

/* -- probe / parse ---------------------------------------------------------------- */

static int junos_probe(const ConfigSample *s)
{
    if (sample_has_prefix(s, "## Last commit") || sample_contains_ci(s, "junos"))
        return 90;
    if (sample_has_prefix(s, "system {") || sample_has_prefix(s, "interfaces {") ||
        sample_has_prefix(s, "security {") || sample_has_prefix(s, "firewall {") ||
        sample_has_prefix(s, "snmp {"))
        return 75;
    for (int i = 0; i < s->count; i++) {
        size_t len = strlen(s->lines[i]);
        if (len > 2 && s->lines[i][len - 1] == '{' && !str_starts_with(s->lines[i], "!"))
            return 30;
    }
    return 0;
}

static AuditStatus junos_parse(const char *path, DeviceModel *m)
{
    static JState st;           /* ~6 KB: keep it off the stack */
    LineReader r;
    AuditStatus rc = line_reader_open(&r, path);
    if (rc != AUDIT_OK) return rc;

    safe_strcpy(m->vendor, sizeof(m->vendor), "juniper");
    safe_strcpy(m->source_file, sizeof(m->source_file), path);

    memset(&st, 0, sizeof(st));
    st.m = m;

    char *line;
    while ((line = line_reader_next(&r)) != NULL)
        lex_line(&st, line, r.line_number);

    rc = line_reader_failed(&r) ? AUDIT_ERR_IO : AUDIT_OK;
    line_reader_close(&r);

    if (st.depth != 0 || st.lost_depth != 0)
        LOG_WRN("%s: unbalanced braces (%d block(s) left open)", path,
                st.depth + st.lost_depth);

    LOG_INF("juniper: parsed '%s' (%d lines, %d interfaces, %d filters/policies)",
            path, r.line_number, m->interface_count, m->acl_count);
    return rc;
}

const VendorParser PARSER_JUNIPER_JUNOS = {
    .name         = "juniper",
    .display_name = "Juniper JunOS",
    .probe        = junos_probe,
    .parse        = junos_parse,
};
