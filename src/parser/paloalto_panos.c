/**
 * @file paloalto_panos.c
 * @brief Palo Alto Networks PAN-OS configuration parser.
 *
 * PAN-OS configurations come in two forms, and both are accepted:
 *
 *   XML   the exported running-config.xml:
 *             <deviceconfig><system><hostname>fw1</hostname>...
 *   set   "set cli config-output-format set" / "show config running":
 *             set deviceconfig system hostname fw1
 *
 * Both are reduced to the same thing: a path of words ending in a value.
 * An XML leaf becomes its element names from the root down, with
 * <entry name="X"> contributing "X" and <member> contributing nothing, so
 * the XML above and the set line above yield the same words. One handler
 * (apply) then reads those words.
 *
 * Settings that span several statements (a security rule's source,
 * destination, application, service and action) are collected while
 * consecutive statements name the same rule and committed when it changes.
 */
#include "netaudit/line_reader.h"
#include "netaudit/log.h"
#include "netaudit/parser.h"
#include "netaudit/safe_str.h"

#define PAN_MAX_DEPTH   32
#define PAN_NAME        96
#define PAN_TEXT       256

/* PAN-OS closes idle administrator sessions after 60 minutes by default. */
#define PAN_DEFAULT_TIMEOUT_MIN 60

typedef struct {
    char name[NA_MAX_ACLNAME];
    int  line;
    bool src_any, dst_any, app_any, svc_any;
    bool allow, has_action, disabled;
} PanRule;

typedef struct {
    DeviceModel *m;
    int          line;

    PanRule      rule;                /* security rule being collected */
    bool         permitted_ip;        /* management permitted-ip list  */
    bool         permitted_any;

    /* XML reader */
    char         path[PAN_MAX_DEPTH][PAN_NAME];
    bool         counted[PAN_MAX_DEPTH];   /* element adds a word to the path */
    bool         had_child[PAN_MAX_DEPTH];
    int          depth;
    char         tag[PAN_TEXT];       /* tag being read, without < >   */
    int          tag_len;
    char         text[PAN_TEXT];      /* character data of the element */
    int          text_len;
    bool         in_tag, in_comment;
    int          dashes;              /* '-' run length inside a comment */
    char         quote;               /* inside an attribute value     */
} PState;

#define W(i)      ((i) < n ? w[i] : "")
#define IS(i, s)  str_eq_ci(W(i), (s))

/* Index of @p word in the path, or -1. */
static int at(char *w[], int n, const char *word)
{
    for (int i = 0; i < n; i++)
        if (str_eq_ci(w[i], word)) return i;
    return -1;
}

/* True when w[i..] starts with the given words. */
static bool seq(char *w[], int n, int i, const char *a, const char *b)
{
    return i >= 0 && IS(i, a) && (b == NULL || IS(i + 1, b));
}

static bool yes(const char *v) { return str_eq_ci(v, "yes"); }

/* -- Security rules -------------------------------------------------------------- */

static void commit_rule(PState *st)
{
    PanRule *r = &st->rule;
    if (r->name[0] && r->has_action && !r->disabled) {
        char name[NA_MAX_ACLNAME];
        safe_snprintf(name, sizeof(name), "rule %s", r->name);
        AclEntry *e = model_acl_add_entry(st->m, model_acl(st->m, name));
        if (e) {
            e->action = r->allow ? ACL_PERMIT : ACL_DENY;
            safe_strcpy(e->src_addr, sizeof(e->src_addr), r->src_any ? "any" : "match");
            safe_strcpy(e->dst_addr, sizeof(e->dst_addr), r->dst_any ? "any" : "match");
            safe_strcpy(e->protocol, sizeof(e->protocol),
                        r->app_any && r->svc_any ? "any" : "match");
            e->is_any_any = r->allow && r->src_any && r->dst_any &&
                            r->app_any && r->svc_any;
            e->line_number = r->line;
        }
    }
    memset(r, 0, sizeof(*r));
}

/* "... security rules NAME <attribute> <values...>" */
static void security_rule(PState *st, char *w[], int n, int name)
{
    PanRule *r = &st->rule;
    if (strcmp(r->name, W(name)) != 0) {
        commit_rule(st);
        safe_strcpy(r->name, sizeof(r->name), W(name));
        r->line = st->line;
    }
    int a = name + 1;                       /* attribute */
    bool any = false;
    for (int i = a + 1; i < n; i++)
        if (IS(i, "any")) any = true;

    if (IS(a, "source"))           r->src_any = r->src_any || any;
    else if (IS(a, "destination")) r->dst_any = r->dst_any || any;
    else if (IS(a, "application")) r->app_any = r->app_any || any;
    else if (IS(a, "service")) {
        /* "application-default" limits ports only when applications are named. */
        for (int i = a + 1; i < n; i++)
            if (IS(i, "any") || IS(i, "application-default")) r->svc_any = true;
    } else if (IS(a, "action")) {
        r->has_action = true;
        r->allow = IS(a + 1, "allow");
    } else if (IS(a, "disabled")) {
        r->disabled = yes(W(a + 1));
    }
}

/* -- Everything else --------------------------------------------------------------- */

static void device_system(PState *st, char *w[], int n, int s)
{
    DeviceModel *m = st->m;                  /* w[s] is the word after "system" */
    if (IS(s, "hostname")) {
        safe_strcpy(m->hostname, sizeof(m->hostname), W(s + 1));
    } else if (IS(s, "login-banner")) {
        if (W(s + 1)[0]) m->mgmt.login_banner = true;
    } else if (IS(s, "service")) {
        /* Telnet and HTTP are off unless "disable-telnet no" / "disable-http no". */
        if (IS(s + 1, "disable-telnet")) m->mgmt.telnet_enabled = m->mgmt.telnet_enabled || !yes(W(s + 2));
        if (IS(s + 1, "disable-http"))   m->mgmt.http_enabled   = m->mgmt.http_enabled   || !yes(W(s + 2));
        if (IS(s + 1, "disable-ssh")   && yes(W(s + 2))) m->mgmt.ssh_enabled = false;
        if (IS(s + 1, "disable-https") && yes(W(s + 2))) m->mgmt.https_enabled = false;
    } else if (IS(s, "permitted-ip")) {
        st->permitted_ip = true;
        if (IS(s + 1, "0.0.0.0/0") || IS(s + 1, "::/0")) st->permitted_any = true;
    } else if (IS(s, "ntp-servers")) {
        /* ntp-servers primary-ntp-server ntp-server-address A
         * ntp-servers primary-ntp-server authentication-type symmetric-key ... */
        if (IS(s + 2, "ntp-server-address")) model_add_ntp_server(m, W(s + 3));
        if (IS(s + 2, "authentication-type") &&
            (IS(s + 3, "symmetric-key") || IS(s + 3, "autokey")))
            m->ntp.authenticated = true;
    } else if (IS(s, "snmp-setting") && IS(s + 1, "access-setting")) {
        m->snmp.enabled = true;
        if (IS(s + 3, "v3")) m->snmp.v3_configured = true;
        if (IS(s + 4, "snmp-community-string") && W(s + 5)[0]) {
            SnmpCommunity *c = model_snmp_community(m, W(s + 5));
            if (c && c->line_number < 0) c->line_number = st->line;
        }
    } else if (IS(s, "authentication-profile")) {
        if (W(s + 1)[0]) m->auth.aaa_configured = true;   /* for non-local admins */
    }
}

static void mgt_config(PState *st, char *w[], int n, int s)
{
    AuthConfig *a = &st->m->auth;            /* w[s] is the word after "mgt-config" */
    if (IS(s, "users")) {
        a->local_users = true;
        if (IS(s + 2, "phash")) {
            a->enable_secret_set = true;
            if (str_starts_with(W(s + 3), "$1$")) a->weak_hash = true;
        }
        if (IS(s + 2, "authentication-profile") && W(s + 3)[0]) a->aaa_configured = true;
    } else if (IS(s, "password-complexity")) {
        if ((IS(s + 1, "enabled") && yes(W(s + 2))) || IS(s + 1, "minimum-length"))
            a->password_policy = true;
    }
}

/* "network interface ethernet NAME ..." (also aggregate-ethernet) */
static void network_interface(PState *st, char *w[], int n, int name)
{
    Interface *it = model_interface(st->m, W(name));
    if (!it) return;
    if (it->line_number < 0) it->line_number = st->line;
    int a = name + 1;
    if (IS(a, "comment")) {
        safe_strcpy(it->description, sizeof(it->description), W(a + 1));
    } else if (IS(a, "link-state")) {
        it->shutdown = IS(a + 1, "down");
    } else if (IS(a, "layer3")) {
        if (IS(a + 1, "ip") && it->ip_address[0] == '\0') {
            char addr[NA_MAX_ADDR];
            safe_strcpy(addr, sizeof(addr), W(a + 2));
            char *slash = strchr(addr, '/');
            if (slash) {
                safe_strcpy(it->subnet_mask, sizeof(it->subnet_mask), slash + 1);
                *slash = '\0';
            }
            safe_strcpy(it->ip_address, sizeof(it->ip_address), addr);
        }
        if (IS(a + 1, "dhcp-client") || IS(a + 1, "pppoe")) it->dynamic_address = true;
    }
}

/* One statement: a path of words ending in its value(s). */
static void apply(PState *st, char *w[], int n)
{
    DeviceModel *m = st->m;
    int i;

    /* Security policy: "rulebase security rules NAME ..." (also pre-/post-rulebase). */
    for (i = 0; i + 2 < n; i++) {
        if (IS(i, "security") && IS(i + 1, "rules") && i > 0 &&
            str_ends_with_ci(W(i - 1), "rulebase")) {
            security_rule(st, w, n, i + 2);
            return;
        }
    }
    commit_rule(st);                          /* left the rule we were collecting */

    if ((i = at(w, n, "deviceconfig")) >= 0) {
        if (seq(w, n, i + 1, "system", NULL)) {
            device_system(st, w, n, i + 2);
        } else if (seq(w, n, i + 1, "setting", "management")) {
            int v;
            if (IS(i + 3, "idle-timeout") && str_to_int(W(i + 4), &v))
                m->mgmt.idle_timeout_min = v > 0 ? v : NA_TIMEOUT_NEVER;
            if (IS(i + 3, "admin-lockout") && IS(i + 4, "failed-attempts") &&
                str_to_int(W(i + 5), &v) && v > 0)
                m->auth.login_lockout = true;
        }
        return;
    }
    if ((i = at(w, n, "mgt-config")) >= 0) { mgt_config(st, w, n, i + 1); return; }

    if ((i = at(w, n, "log-settings")) >= 0) {
        /* log-settings syslog PROFILE server NAME server ADDR */
        if (IS(i + 1, "syslog") && IS(i + 3, "server") && IS(i + 5, "server"))
            model_add_log_server(m, W(i + 6));
        return;
    }
    if ((i = at(w, n, "interface-management-profile")) >= 0) {
        /* interface-management-profile NAME telnet yes */
        if (IS(i + 2, "telnet") && yes(W(i + 3))) m->mgmt.telnet_enabled = true;
        if (IS(i + 2, "http")   && yes(W(i + 3))) m->mgmt.http_enabled = true;
        return;
    }
    if ((i = at(w, n, "network")) >= 0 && IS(i + 1, "interface") &&
        (IS(i + 2, "ethernet") || IS(i + 2, "aggregate-ethernet")) && n > i + 3) {
        network_interface(st, w, n, i + 3);
        return;
    }
}

/* -- set form ---------------------------------------------------------------------- */

static void set_line(PState *st, char *line)
{
    char *words[NA_MAX_TOKENS];
    char *kept[NA_MAX_TOKENS];
    int n = str_tokenize(line, words, NA_MAX_TOKENS);
    if (n < 3 || !str_eq_ci(words[0], "set")) return;
    int k = 0;
    for (int i = 1; i < n; i++) {
        if (strcmp(words[i], "[") == 0 || strcmp(words[i], "]") == 0) continue;
        kept[k++] = words[i];
    }
    apply(st, kept, k);
}

/* -- XML form ---------------------------------------------------------------------- */

/* Emit the open elements plus the text collected so far as one statement. */
static void xml_emit(PState *st, bool with_text)
{
    char *w[PAN_MAX_DEPTH + 1];
    int n = 0;
    for (int i = 0; i < st->depth && i < PAN_MAX_DEPTH; i++)
        if (st->counted[i]) w[n++] = st->path[i];
    if (with_text) w[n++] = st->text;
    if (n > 0) apply(st, w, n);
}

static const struct { const char *name; char c; } k_entities[] = {
    { "&amp;", '&' }, { "&lt;", '<' }, { "&gt;", '>' },
    { "&quot;", '"' }, { "&apos;", '\'' },
};

/* Replace the predefined entities in @p s, in place. */
static void xml_unescape(char *s)
{
    char *out = s;
    while (*s) {
        size_t i;
        for (i = 0; i < NA_ARRAY_LEN(k_entities); i++) {
            size_t len = strlen(k_entities[i].name);
            if (strncmp(s, k_entities[i].name, len) == 0) {
                *out++ = k_entities[i].c;
                s += len;
                break;
            }
        }
        if (i == NA_ARRAY_LEN(k_entities)) *out++ = *s++;
    }
    *out = '\0';
}

/* Value of attribute @p attr in the tag text, copied to @p out. */
static bool xml_attr(const char *tag, const char *attr, char *out, size_t out_size)
{
    size_t alen = strlen(attr);
    for (const char *p = tag; (p = strstr(p, attr)) != NULL; p += alen) {
        if (p == tag || !isspace((unsigned char)p[-1]) || p[alen] != '=') continue;
        char q = p[alen + 1];
        if (q != '"' && q != '\'') continue;
        const char *v = p + alen + 2;
        const char *end = strchr(v, q);
        if (!end) return false;
        safe_strncpy_n(out, out_size, v, (size_t)(end - v));
        xml_unescape(out);
        return true;
    }
    return false;
}

static void xml_tag(PState *st)
{
    char *t = st->tag;
    size_t len = strlen(t);
    if (t[0] == '?' || t[0] == '!') return;           /* declaration, DOCTYPE */

    if (t[0] == '/') {                                /* </name> */
        if (st->depth == 0) return;
        int d = st->depth - 1;
        str_trim(st->text);
        if (d < PAN_MAX_DEPTH && !st->had_child[d] && st->text[0])
            xml_emit(st, true);
        st->depth--;
        st->text_len = 0;
        st->text[0] = '\0';
        return;
    }

    bool self_closing = len > 0 && t[len - 1] == '/';
    if (self_closing) t[len - 1] = '\0';

    char name[PAN_NAME];
    size_t name_len = strcspn(t, " \t\r\n");
    safe_strncpy_n(name, sizeof(name), t, name_len);

    if (st->depth > 0 && st->depth <= PAN_MAX_DEPTH) st->had_child[st->depth - 1] = true;
    if (st->depth < PAN_MAX_DEPTH) {
        int d = st->depth;
        st->had_child[d] = false;
        st->counted[d] = !str_eq_ci(name, "member");
        if (str_eq_ci(name, "entry")) {
            if (!xml_attr(t, "name", st->path[d], PAN_NAME)) st->path[d][0] = '\0';
        } else {
            safe_strcpy(st->path[d], PAN_NAME, name);
        }
        if (d == 0 && str_eq_ci(name, "config"))
            xml_attr(t, "version", st->m->os_version, sizeof(st->m->os_version));
    }
    st->depth++;
    st->text_len = 0;
    st->text[0] = '\0';

    if (self_closing) {                               /* <none/> is a value too */
        if (st->depth <= PAN_MAX_DEPTH) xml_emit(st, false);
        st->depth--;
    }
}

static void xml_text_char(PState *st, char c)
{
    if (st->text_len < PAN_TEXT - 1) {
        st->text[st->text_len++] = c;
        st->text[st->text_len] = '\0';
    }
}

/* Replace a predefined entity that has just been completed at the end of
 * the text buffer. */
static void xml_entity(PState *st)
{
    for (size_t i = 0; i < NA_ARRAY_LEN(k_entities); i++) {
        size_t len = strlen(k_entities[i].name);
        if ((size_t)st->text_len >= len &&
            strcmp(st->text + st->text_len - len, k_entities[i].name) == 0) {
            st->text_len -= (int)len;
            st->text[st->text_len++] = k_entities[i].c;
            st->text[st->text_len] = '\0';
            return;
        }
    }
}

/* Feed @p len bytes of XML. The reader keeps all of its state in @p st, so
 * the input may be cut anywhere - line length does not matter. */
static void xml_feed(PState *st, const char *p, size_t len)
{
    for (const char *end = p + len; p < end; p++) {
        char c = *p;
        if (c == '\n') st->line++;

        if (st->in_comment) {                         /* ends with "-->" */
            if (c == '>' && st->dashes >= 2) st->in_comment = false;
            st->dashes = c == '-' ? st->dashes + 1 : 0;
            continue;
        }
        if (st->in_tag) {
            if (st->quote) {
                if (c == st->quote) st->quote = '\0';
            } else if (c == '"' || c == '\'') {
                st->quote = c;
            } else if (c == '>') {
                st->in_tag = false;
                st->tag[st->tag_len] = '\0';
                xml_tag(st);
                continue;
            }
            if (st->tag_len < PAN_TEXT - 1) st->tag[st->tag_len++] = c;
            if (st->tag_len == 3 && strncmp(st->tag, "!--", 3) == 0) {
                st->in_tag = false;
                st->in_comment = true;
                st->dashes = 0;
            }
            continue;
        }
        if (c == '<') {
            st->in_tag = true;
            st->tag_len = 0;
            st->quote = '\0';
            continue;
        }
        if (c == '\0') continue;
        xml_text_char(st, (c == '\n' || c == '\r' || c == '\t') ? ' ' : c);
        if (c == ';') xml_entity(st);
    }
}

/* The XML export is read in blocks rather than lines: a compact export can
 * put the whole document on one line. */
static AuditStatus xml_file(PState *st, const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return AUDIT_ERR_IO;
    char buf[NA_MAX_LINE];
    size_t got;
    st->line = 1;
    while ((got = fread(buf, 1, sizeof(buf), fp)) > 0)
        xml_feed(st, buf, got);
    AuditStatus rc = ferror(fp) ? AUDIT_ERR_IO : AUDIT_OK;
    fclose(fp);
    return rc;
}

/* -- probe / parse ------------------------------------------------------------------ */

static int panos_probe(const ConfigSample *s)
{
    if (sample_has_prefix(s, "<?xml") || sample_has_prefix(s, "<config")) {
        if (sample_contains_ci(s, "paloaltonetworks") || sample_contains_ci(s, "<mgt-config>") ||
            sample_contains_ci(s, "<deviceconfig>") || sample_contains_ci(s, "<devices>"))
            return 95;
        if (sample_has_prefix(s, "<config")) return 60;
    }
    if (sample_has_prefix(s, "set deviceconfig ") || sample_has_prefix(s, "set mgt-config ") ||
        sample_has_prefix(s, "set rulebase ") || sample_has_prefix(s, "set network interface ") ||
        sample_has_prefix(s, "set shared "))
        return 90;
    return 0;
}

static AuditStatus panos_parse(const char *path, DeviceModel *m)
{
    static PState st;                  /* ~4 KB: keep it off the stack */
    LineReader r;
    AuditStatus rc = line_reader_open(&r, path);
    if (rc != AUDIT_OK) return rc;

    safe_strcpy(m->vendor, sizeof(m->vendor), "paloalto");
    safe_strcpy(m->source_file, sizeof(m->source_file), path);
    memset(&st, 0, sizeof(st));
    st.m = m;

    /* PAN-OS defaults: SSH and HTTPS management on, Telnet and HTTP off;
     * logs are kept locally and always timestamped. */
    m->mgmt.ssh_enabled = true;
    m->mgmt.ssh_version = 2;
    m->mgmt.https_enabled = true;
    m->logging.buffered_enabled = true;
    m->logging.timestamps = true;
    m->auth.password_encryption = true;       /* passwords are stored as phash */

    bool xml = false;
    r.quiet = true;                    /* XML lines may be long; see xml_file */
    char *line;
    while ((line = line_reader_next(&r)) != NULL) {
        st.line = r.line_number;
        str_trim(line);
        if (line[0] == '\0' || line[0] == '#') continue;
        if (line[0] == '<') { xml = true; break; }
        set_line(&st, line);
    }
    rc = line_reader_failed(&r) ? AUDIT_ERR_IO : AUDIT_OK;
    int lines = r.line_number;
    line_reader_close(&r);

    if (xml && rc == AUDIT_OK) {
        rc = xml_file(&st, path);
        lines = st.line;
    }
    commit_rule(&st);

    m->mgmt.access_restricted = st.permitted_ip && !st.permitted_any;
    if (m->mgmt.idle_timeout_min == 0) m->mgmt.idle_timeout_min = PAN_DEFAULT_TIMEOUT_MIN;
    /* SNMP has no ACL of its own: it follows the management permitted-ip list. */
    for (int i = 0; i < m->snmp.community_count; i++)
        m->snmp.communities[i].restricted = m->mgmt.access_restricted;

    LOG_INF("paloalto: parsed '%s' (%d lines, %d interfaces, %d rules)",
            path, lines, m->interface_count, m->acl_count);
    return rc;
}

const VendorParser PARSER_PALOALTO_PANOS = {
    .name         = "paloalto",
    .display_name = "Palo Alto PAN-OS",
    .probe        = panos_probe,
    .parse        = panos_parse,
};
