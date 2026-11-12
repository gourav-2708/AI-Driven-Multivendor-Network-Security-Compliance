/**
 * @file cisco_ios.c
 * @brief Parser for the IOS-style CLI family: Cisco IOS / IOS-XE, Cisco
 *        NX-OS, Cisco ASA and Arista EOS.
 *
 * These configs are line-oriented. A non-indented line is a global command
 * and may open a sub-mode (interface, line vty, ip access-list, management
 * ssh); indented lines that follow belong to that sub-mode. Lines whose
 * first non-blank character is '!' are comments ('!' elsewhere is data,
 * e.g. inside an SNMP community string).
 *
 * The four systems share most commands. Where they differ - how passwords
 * are stored, which services run by default, how SSH and SNMP are
 * configured - the code branches on the dialect. Each dialect is registered
 * as its own VendorParser with its own probe.
 */
#include "netaudit/line_reader.h"
#include "netaudit/log.h"
#include "netaudit/parser.h"
#include "netaudit/safe_str.h"

typedef enum { DIALECT_IOS, DIALECT_NXOS, DIALECT_ASA, DIALECT_EOS } Dialect;

typedef enum {
    MODE_GLOBAL, MODE_INTERFACE, MODE_VTY, MODE_CONSOLE, MODE_ACL,
    MODE_MGMT_SSH, MODE_MGMT_TELNET, MODE_MGMT_CONSOLE, MODE_MGMT_API,
    MODE_MGMT_SECURITY, MODE_OTHER
} IosMode;

/* NX-OS closes idle sessions after 30 minutes unless told otherwise. */
#define NXOS_DEFAULT_TIMEOUT_MIN 30

typedef struct {
    DeviceModel *m;
    Dialect      dialect;
    IosMode      mode;
    Interface   *iface;          /* MODE_INTERFACE */
    Acl         *acl;            /* MODE_ACL       */
    bool         acl_extended;
    int          line;
    const char  *raw;            /* current line, trimmed, before tokenising */

    char banner_end[4];          /* delimiter of a multi-line banner being skipped */

    bool cdp_disabled;
    bool source_route_disabled;
    bool plaintext_seen;         /* a cleartext credential was found */

    /* VTY lines: management is "restricted" when every block has an ACL. */
    int  vty_blocks, vty_with_acl;
    bool vty_block_has_acl;

    /* NX-OS */
    bool nxos_ssh_disabled, nxos_strength_check_off;
    /* EOS */
    bool eos_ssh_shutdown, eos_ssh_acl, eos_telnet_on;
    bool eos_api_on, eos_api_http, eos_api_no_https;
    /* ASA */
    bool asa_logging_enabled;
    int  asa_mgmt_sources, asa_mgmt_any;
    char asa_global_acl[NA_MAX_ACLNAME];
    char asa_nameif[NA_MAX_INTERFACES][NA_MAX_IFNAME];   /* by interface index */
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

static bool looks_like_address(const char *t)
{
    return isdigit((unsigned char)t[0]) || strchr(t, ':') != NULL;
}

/* -- probes ------------------------------------------------------------------ */

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

static int nxos_probe(const ConfigSample *s)
{
    if (sample_contains_ci(s, "NX-OS") || sample_has_prefix_ci(s, "boot nxos"))
        return 92;
    if (sample_has_prefix(s, "!Command:") || sample_has_prefix_ci(s, "feature ") ||
        sample_has_prefix_ci(s, "vdc ") || sample_has_prefix_ci(s, "switchname "))
        return 88;
    return 0;
}

static int eos_probe(const ConfigSample *s)
{
    if (sample_contains_ci(s, "EOS-") || sample_contains_ci(s, "Arista"))
        return 92;
    if (sample_has_prefix_ci(s, "management api ") || sample_has_prefix_ci(s, "management ssh") ||
        sample_has_prefix_ci(s, "transceiver qsfp") || sample_has_prefix_ci(s, "daemon ") ||
        sample_has_prefix_ci(s, "service routing protocols model"))
        return 86;
    return 0;
}

static int asa_probe(const ConfigSample *s)
{
    if (sample_has_prefix_ci(s, "ASA Version") || sample_has_prefix_ci(s, "PIX Version"))
        return 95;
    if (sample_has_prefix_ci(s, "nameif ") && sample_has_prefix_ci(s, "security-level "))
        return 88;
    return 0;
}

/* -- Credentials -------------------------------------------------------------- */

typedef enum { CRED_PLAIN, CRED_REVERSIBLE, CRED_WEAK_HASH, CRED_HASHED } CredKind;

/* How the credential that follows w[i] ("password" or "secret") is stored. */
static CredKind credential_kind(const IosState *st, char *w[], int n, int i)
{
    switch (st->dialect) {
    case DIALECT_ASA:                     /* password VALUE [encrypted|pbkdf2] */
        for (int k = i + 2; k < n; k++) {
            if (IS(k, "pbkdf2")) return CRED_HASHED;
            if (IS(k, "encrypted") || IS(k, "nt-encrypted")) return CRED_WEAK_HASH;
        }
        return CRED_PLAIN;
    case DIALECT_NXOS:                    /* password 0|5 VALUE */
        if (IS(i + 1, "0")) return CRED_PLAIN;
        return str_starts_with(W(i + 2), "$1$") ? CRED_WEAK_HASH : CRED_HASHED;
    case DIALECT_EOS:                     /* secret 0|5|sha512 VALUE */
        if (IS(i + 1, "0")) return CRED_PLAIN;
        if (IS(i + 1, "5") || str_starts_with(W(i + 2), "$1$")) return CRED_WEAK_HASH;
        return CRED_HASHED;
    case DIALECT_IOS:
        break;
    }
    if (IS(i, "secret"))                  /* IOS: secret [4|5|8|9] VALUE */
        return (IS(i + 1, "4") || IS(i + 1, "5")) ? CRED_WEAK_HASH : CRED_HASHED;
    return IS(i + 1, "7") ? CRED_REVERSIBLE : CRED_PLAIN;
}

static void note_credential(IosState *st, CredKind k, bool privileged)
{
    AuthConfig *a = &st->m->auth;
    if (k == CRED_PLAIN || k == CRED_REVERSIBLE) {
        if (privileged) a->enable_password_set = true;
        else            a->plaintext_user_password = true;
        if (k == CRED_REVERSIBLE) a->weak_hash = true;
        else                      st->plaintext_seen = true;
        return;
    }
    if (k == CRED_WEAK_HASH) a->weak_hash = true;
    /* Outside IOS there is often no enable password: the administrator
     * accounts are the privileged credential. */
    if (privileged || st->dialect != DIALECT_IOS) a->enable_secret_set = true;
}

static void ios_username(IosState *st, char *w[], int n)
{
    st->m->auth.local_users = true;
    for (int i = 2; i < n; i++) {
        if (IS(i, "nopassword")) {
            st->m->auth.plaintext_user_password = true;
            st->plaintext_seen = true;
            return;
        }
        if (IS(i, "password") || IS(i, "secret")) {
            note_credential(st, credential_kind(st, w, n, i), false);
            return;
        }
    }
}

/* -- Sessions ------------------------------------------------------------------ */

/* Record an idle timeout; the longest one (or "never") is what matters. */
static void note_timeout(IosState *st, int minutes)
{
    int *t = &st->m->mgmt.idle_timeout_min;
    if (minutes <= 0)                               *t = NA_TIMEOUT_NEVER;
    else if (*t != NA_TIMEOUT_NEVER && minutes > *t) *t = minutes;
}

/* "exec-timeout MINUTES [SECONDS]" on a console or VTY line. */
static void exec_timeout(IosState *st, char *w[], int n)
{
    int minutes = 0, seconds = 0;
    if (!str_to_int(W(1), &minutes)) return;
    if (n > 2 && !str_to_int(W(2), &seconds)) seconds = 0;
    note_timeout(st, minutes == 0 && seconds > 0 ? 1 : minutes);
}

/* "banner login ^C ... ^C": remember the delimiter so the text lines are
 * skipped instead of being read as commands. */
static void ios_banner(IosState *st, char *w[], int n)
{
    if (IS(1, "login") || IS(1, "motd")) st->m->mgmt.login_banner = true;
    if (st->dialect == DIALECT_ASA) return;          /* one line per command */
    if (st->dialect == DIALECT_EOS) {                /* text ends with "EOF" */
        safe_strcpy(st->banner_end, sizeof(st->banner_end), "EOF");
        return;
    }
    const char *p = after_first_word(after_first_word(st->raw));
    if (*p == '\0') return;
    char delim[3] = { p[0], '\0', '\0' };
    if (p[0] == '^' && p[1] == 'C') delim[1] = 'C';  /* Ctrl-C as shown by IOS */
    p += strlen(delim);
    if (strstr(p, delim) == NULL)                    /* text continues below */
        safe_strcpy(st->banner_end, sizeof(st->banner_end), delim);
}

/* -- ACL entries --------------------------------------------------------------- */

/* Consume one address spec ("any", "host A", "A WILDCARD", "A/LEN",
 * "object-group X") starting at w[*i]. Returns true when it matches every
 * address. */
static bool take_address(const IosState *st, char *w[], int n, int *i,
                         char *out, size_t out_size)
{
    const char *t = W(*i);
    if (str_eq_ci(t, "any") || str_eq_ci(t, "any4") || str_eq_ci(t, "any6")) {
        safe_strcpy(out, out_size, "any");
        (*i)++;
        return true;
    }
    if (str_eq_ci(t, "host") || str_eq_ci(t, "object-group") ||
        str_eq_ci(t, "addrgroup") || str_eq_ci(t, "object") ||
        str_eq_ci(t, "interface")) {
        safe_strcpy(out, out_size, W(*i + 1));
        *i += 2;
        return false;
    }
    safe_strcpy(out, out_size, t);
    if (strchr(t, '/')) {                            /* prefix notation */
        (*i)++;
        return str_eq_ci(t, "0.0.0.0/0") || str_eq_ci(t, "::/0");
    }
    /* IOS writes a wildcard after the address, ASA a netmask. */
    const char *all_bits = st->dialect == DIALECT_ASA ? "0.0.0.0" : "255.255.255.255";
    bool all = str_eq_ci(t, "0.0.0.0") && str_eq_ci(W(*i + 1), all_bits);
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
        if (IS(i, "object-group") || IS(i, "object")) {
            /* ASA service object: the rule is limited to those services. */
            safe_strcpy(e->protocol, sizeof(e->protocol), W(i + 1));
            port_limited = true;
            i += 2;
        } else {
            safe_strcpy(e->protocol, sizeof(e->protocol), W(i));
            i++;
        }
        src_all = take_address(st, w, n, &i, e->src_addr, sizeof(e->src_addr));
        if (is_port_operator(W(i))) {
            port_limited = true;
            i += IS(i, "range") ? 3 : 2;
        }
        dst_all = take_address(st, w, n, &i, e->dst_addr, sizeof(e->dst_addr));
        if (is_port_operator(W(i))) port_limited = true;
    } else {
        src_all = take_address(st, w, n, &i, e->src_addr, sizeof(e->src_addr));
    }
    e->is_any_any = e->action == ACL_PERMIT && src_all && dst_all &&
                    !port_limited;
}

/* IOS "access-list N permit|deny ..." (numbered ACL, global mode). */
static void ios_numbered_acl(IosState *st, char *w[], int n)
{
    int num;
    if (n < 3 || !str_to_int(W(1), &num)) return;
    bool extended = (num >= 100 && num <= 199) || (num >= 2000 && num <= 2699);
    Acl *acl = model_acl(st->m, W(1));
    if (acl) ios_acl_entry(st, acl, extended, w + 2, n - 2);
}

/* ASA "access-list NAME [line N] extended|standard permit|deny ...". */
static void asa_acl(IosState *st, char *w[], int n)
{
    int i = 2;
    if (IS(i, "line")) i += 2;
    bool extended = IS(i, "extended");
    if (!extended && !IS(i, "standard")) return;     /* remark, ethertype... */
    Acl *acl = model_acl(st->m, W(1));
    if (acl) ios_acl_entry(st, acl, extended, w + i + 1, n - i - 1);
}

/* ASA "access-group NAME in|out interface NAMEIF" / "access-group NAME global". */
static void asa_access_group(IosState *st, char *w[], int n)
{
    if (IS(2, "global")) {
        safe_strcpy(st->asa_global_acl, sizeof(st->asa_global_acl), W(1));
        return;
    }
    if (!IS(3, "interface") || n < 5) return;
    for (int i = 0; i < st->m->interface_count; i++) {
        if (!str_eq_ci(st->asa_nameif[i], W(4))) continue;
        Interface *it = &st->m->interfaces[i];
        if (IS(2, "in")) safe_strcpy(it->acl_in, sizeof(it->acl_in), W(1));
        else             safe_strcpy(it->acl_out, sizeof(it->acl_out), W(1));
    }
}

/* -- Global commands ---------------------------------------------------------- */

static void ios_snmp_community(IosState *st, char *w[], int n)
{
    /* IOS/EOS: snmp-server community NAME [view V] [RO|RW] [ACL]
     * NX-OS:   snmp-server community NAME group ROLE | use-acl ACL
     * ASA:     snmp-server community [0|8] NAME (answers configured hosts only) */
    int name = 2;
    if (st->dialect == DIALECT_ASA && (IS(2, "0") || IS(2, "8"))) name = 3;
    if (W(name)[0] == '*') {              /* masked in the export: unknown */
        st->m->snmp.enabled = true;
        return;
    }
    SnmpCommunity *c = model_snmp_community(st->m, W(name));
    if (!c) return;
    if (c->line_number < 0) c->line_number = st->line;
    if (st->dialect == DIALECT_ASA) { c->restricted = true; return; }

    for (int i = name + 1; i < n; i++) {
        if (IS(i, "view"))       { i++; continue; }
        if (IS(i, "ro"))         { c->access = SNMP_RO; continue; }
        if (IS(i, "rw"))         { c->access = SNMP_RW; continue; }
        if (IS(i, "ipv6"))       { i++; continue; }
        if (IS(i, "group")) {
            if (str_eq_ci(W(i + 1), "network-admin")) c->access = SNMP_RW;
            i++;
            continue;
        }
        c->restricted = true;    /* an ACL name/number, or "use-acl NAME" */
    }
}

/* ASA "snmp-server host NAMEIF ADDR [community [0|8] NAME] [version V]". */
static void asa_snmp_host(IosState *st, char *w[], int n)
{
    st->m->snmp.enabled = true;
    for (int i = 4; i < n; i++) {
        if (IS(i, "version") && IS(i + 1, "3")) st->m->snmp.v3_configured = true;
        if (!IS(i, "community")) continue;
        int name = (IS(i + 1, "0") || IS(i + 1, "8")) ? i + 2 : i + 1;
        if (W(name)[0] == '\0' || W(name)[0] == '*') continue;
        SnmpCommunity *c = model_snmp_community(st->m, W(name));
        if (!c) continue;
        if (c->line_number < 0) c->line_number = st->line;
        c->restricted = true;
    }
}

static void ios_logging(IosState *st, char *w[], int n)
{
    DeviceModel *m = st->m;
    if (IS(1, "buffered") || IS(1, "logfile")) { m->logging.buffered_enabled = true; return; }
    if (IS(1, "timestamp")) { m->logging.timestamps = true; return; }
    if (IS(1, "enable"))    { st->asa_logging_enabled = true; return; }

    int i = 1;
    if (IS(i, "vrf")) i += 2;                        /* EOS: logging vrf V host A */
    if (IS(i, "host") || IS(i, "server")) {
        i++;
        while (IS(i, "ipv6") || IS(i, "vrf")) i += IS(i, "vrf") ? 2 : 1;
        if (st->dialect == DIALECT_ASA) i++;         /* logging host NAMEIF ADDR */
        model_add_log_server(m, W(i));
        return;
    }
    /* Legacy IOS form "logging ADDR": first character is a digit or ':' */
    const char *a = W(1);
    if (st->dialect == DIALECT_IOS &&
        (isdigit((unsigned char)a[0]) || (a[0] == ':' && a[1] != '\0')))
        model_add_log_server(m, a);
}

static void ios_no_command(IosState *st, char *w[], int n)
{
    DeviceModel *m = st->m;
    (void)n;
    if (IS(1, "cdp") && (IS(2, "run") || IS(2, "enable")))  st->cdp_disabled = true;
    else if (IS(1, "ip") && IS(2, "source-route"))           st->source_route_disabled = true;
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
    else if (IS(1, "feature") && IS(2, "ssh"))               st->nxos_ssh_disabled = true;
    else if (IS(1, "feature") && IS(2, "telnet"))            m->mgmt.telnet_enabled = false;
    else if (IS(1, "password") && IS(2, "strength-check"))   st->nxos_strength_check_off = true;
}

/* ASA "ssh|telnet|http ADDR MASK NAMEIF": who may open a management session. */
static bool asa_mgmt_source(IosState *st, char *w[], int n)
{
    if (n < 4 || !looks_like_address(W(1))) return false;
    st->asa_mgmt_sources++;
    bool any = (IS(1, "0.0.0.0") || IS(1, "0")) && (IS(2, "0.0.0.0") || IS(2, "0"));
    if (any || IS(1, "::/0")) st->asa_mgmt_any++;
    return true;
}

static void asa_global(IosState *st, char *w[], int n)
{
    DeviceModel *m = st->m;
    int v;
    if (IS(0, "ssh")) {
        if (asa_mgmt_source(st, w, n))                 m->mgmt.ssh_enabled = true;
        else if (IS(1, "version") && str_to_int(W(2), &v)) m->mgmt.ssh_version = v;
        else if (IS(1, "timeout") && str_to_int(W(2), &v)) note_timeout(st, v);
    } else if (IS(0, "telnet")) {
        if (asa_mgmt_source(st, w, n))                 m->mgmt.telnet_enabled = true;
        else if (IS(1, "timeout") && str_to_int(W(2), &v)) note_timeout(st, v);
    } else if (IS(0, "http")) {
        if (IS(1, "server") && IS(2, "enable")) m->mgmt.https_enabled = true;  /* ASDM is HTTPS */
        else asa_mgmt_source(st, w, n);
    } else if (IS(0, "password-policy")) {
        m->auth.password_policy = true;
    } else if (IS(0, "aaa") && IS(1, "authentication") && IS(3, "console")) {
        if (n > 4 && !IS(4, "LOCAL")) m->auth.aaa_configured = true;
    } else if (IS(0, "access-group")) {
        asa_access_group(st, w, n);
    }
}

/* Arista "management ..." sections. */
static IosMode eos_management_mode(char *w[], int n)
{
    if (IS(1, "ssh"))      return MODE_MGMT_SSH;
    if (IS(1, "telnet"))   return MODE_MGMT_TELNET;
    if (IS(1, "console"))  return MODE_MGMT_CONSOLE;
    if (IS(1, "security")) return MODE_MGMT_SECURITY;
    if (IS(1, "api") || IS(1, "http-server")) return MODE_MGMT_API;
    return MODE_OTHER;
}

static void ios_global(IosState *st, char *w[], int n)
{
    DeviceModel *m = st->m;
    st->mode = MODE_GLOBAL;

    if (IS(0, "no"))       { ios_no_command(st, w, n); return; }
    if (IS(0, "hostname") || IS(0, "switchname")) {
        safe_strcpy(m->hostname, sizeof(m->hostname), W(1));
        return;
    }
    if (IS(0, "version"))  { safe_strcpy(m->os_version, sizeof(m->os_version), W(1)); return; }
    if ((IS(0, "ASA") || IS(0, "PIX")) && IS(1, "Version")) {
        safe_strcpy(m->os_version, sizeof(m->os_version), W(2));
        return;
    }
    if (IS(0, "banner"))   { ios_banner(st, w, n); return; }

    if (IS(0, "enable") && (IS(1, "secret") || IS(1, "password"))) {
        note_credential(st, credential_kind(st, w, n, 1), true);
        return;
    }
    if (IS(0, "username")) { ios_username(st, w, n); return; }

    if (IS(0, "service") && IS(1, "password-encryption")) { m->auth.password_encryption = true; return; }
    if (IS(0, "service") && IS(1, "tcp-small-servers"))   { m->services.tcp_small_servers = true; return; }
    if (IS(0, "service") && IS(1, "udp-small-servers"))   { m->services.udp_small_servers = true; return; }
    if (IS(0, "service") && IS(1, "timestamps") && IS(2, "log") && IS(3, "datetime")) {
        m->logging.timestamps = true;
        return;
    }
    if (IS(0, "security") && IS(1, "passwords") && IS(2, "min-length")) {
        m->auth.password_policy = true;
        return;
    }
    if (IS(0, "login") && IS(1, "block-for")) { m->auth.login_lockout = true; return; }

    if (IS(0, "aaa")) {
        if (IS(1, "new-model")) m->auth.aaa_configured = true;
        if (IS(1, "common-criteria") && IS(2, "policy")) m->auth.password_policy = true;
        if (IS(1, "local") && IS(2, "authentication") && IS(3, "attempts"))
            m->auth.login_lockout = true;
        if (IS(1, "authentication") && IS(2, "policy") && IS(3, "lockout"))
            m->auth.login_lockout = true;
        if (st->dialect != DIALECT_IOS && st->dialect != DIALECT_ASA &&
            IS(1, "authentication") && IS(2, "login")) {
            for (int i = 3; i < n; i++)
                if (IS(i, "group")) m->auth.aaa_configured = true;
        }
        if (st->dialect == DIALECT_ASA) asa_global(st, w, n);
        return;
    }

    if (st->dialect == DIALECT_ASA &&
        (IS(0, "ssh") || IS(0, "telnet") || IS(0, "http") ||
         IS(0, "password-policy") || IS(0, "access-group"))) {
        asa_global(st, w, n);
        return;
    }

    if (IS(0, "feature")) {                           /* NX-OS */
        if (IS(1, "telnet")) m->mgmt.telnet_enabled = true;
        return;
    }
    if (IS(0, "nxapi")) {
        if (IS(1, "http"))  m->mgmt.http_enabled = true;
        if (IS(1, "https")) m->mgmt.https_enabled = true;
        return;
    }
    if (IS(0, "management") && st->dialect == DIALECT_EOS) {
        st->mode = eos_management_mode(w, n);
        return;
    }

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
    if (IS(0, "cdp") && (IS(1, "run") || IS(1, "enable")))      { st->cdp_disabled = false; return; }
    if (IS(0, "ip") && IS(1, "source-route"))                   { st->source_route_disabled = false; return; }

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
    if (IS(0, "snmp-server") && IS(1, "host") && st->dialect == DIALECT_ASA) {
        asa_snmp_host(st, w, n);
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
        if (IS(1, "vty")) {
            st->mode = MODE_VTY;
            st->vty_blocks++;
            st->vty_block_has_acl = false;
        } else {
            st->mode = (IS(1, "con") || IS(1, "console")) ? MODE_CONSOLE : MODE_OTHER;
        }
        return;
    }
    if (IS(0, "ip") && IS(1, "access-list")) {
        if (n >= 4 && (IS(2, "extended") || IS(2, "standard"))) {
            st->acl = model_acl(m, W(3));
            st->acl_extended = !IS(2, "standard");
        } else if (n == 3 && st->dialect != DIALECT_IOS) {
            st->acl = model_acl(m, W(2));            /* NX-OS / EOS */
            st->acl_extended = true;
        } else {
            st->acl = NULL;
        }
        st->mode = st->acl ? MODE_ACL : MODE_OTHER;
        return;
    }
    if (IS(0, "access-list")) {
        if (st->dialect == DIALECT_ASA) asa_acl(st, w, n);
        else                            ios_numbered_acl(st, w, n);
        return;
    }

    st->mode = MODE_OTHER;          /* unknown block: ignore its body */
}

/* -- Sub-mode commands --------------------------------------------------------- */

static void set_address(Interface *it, const char *addr, const char *mask)
{
    char buf[NA_MAX_ADDR];
    safe_strcpy(buf, sizeof(buf), addr);
    char *slash = strchr(buf, '/');
    if (slash) {                                     /* NX-OS / EOS: A/LEN */
        *slash = '\0';
        mask = slash + 1;
    }
    safe_strcpy(it->ip_address, sizeof(it->ip_address), buf);
    safe_strcpy(it->subnet_mask, sizeof(it->subnet_mask), mask);
}

static void ios_interface(IosState *st, char *w[], int n)
{
    Interface *it = st->iface;
    if (IS(0, "ip") && IS(1, "address")) {
        if (IS(2, "dhcp") || IS(2, "negotiated") || IS(2, "pppoe"))
            it->dynamic_address = true;
        else
            set_address(it, W(2), W(3));
    } else if (IS(0, "shutdown")) {
        it->shutdown = true;
    } else if (IS(0, "no") && IS(1, "shutdown")) {
        it->shutdown = false;
    } else if (IS(0, "description")) {
        safe_strcpy(it->description, sizeof(it->description),
                    after_first_word(st->raw));
    } else if (IS(0, "ip") && IS(1, "access-group") && n >= 4) {
        if (IS(3, "in"))
            safe_strcpy(it->acl_in, sizeof(it->acl_in), W(2));
        else
            safe_strcpy(it->acl_out, sizeof(it->acl_out), W(2));
    } else if (IS(0, "nameif") && n >= 2) {          /* ASA */
        safe_strcpy(st->asa_nameif[it - st->m->interfaces], NA_MAX_IFNAME, W(1));
    } else if (IS(0, "management-only")) {
        it->is_management = true;
    }
}

/* Console and VTY lines. "transport input ssh" permits SSH on the lines but
 * does not start the SSH server (that needs keys / "ip ssh version"), so
 * only telnet matters there. */
static void ios_line(IosState *st, char *w[], int n)
{
    if (IS(0, "exec-timeout"))                         exec_timeout(st, w, n);
    else if (IS(0, "no") && IS(1, "exec-timeout"))     note_timeout(st, 0);
    if (st->mode != MODE_VTY) return;

    if (IS(0, "transport") && IS(1, "input")) {
        for (int i = 2; i < n; i++)
            if (IS(i, "telnet") || IS(i, "all")) st->m->mgmt.telnet_enabled = true;
    } else if (IS(0, "access-class") && !st->vty_block_has_acl) {
        st->vty_block_has_acl = true;
        st->vty_with_acl++;
    }
}

static void eos_management(IosState *st, char *w[], int n)
{
    int v;
    bool no = IS(0, "no");
    bool shutdown = IS(no ? 1 : 0, "shutdown");

    if (IS(0, "idle-timeout") && str_to_int(W(1), &v) &&
        (st->mode == MODE_MGMT_SSH || st->mode == MODE_MGMT_TELNET ||
         st->mode == MODE_MGMT_CONSOLE))
        note_timeout(st, v);

    switch (st->mode) {
    case MODE_MGMT_SSH:
        if (shutdown) st->eos_ssh_shutdown = !no;
        if (IS(0, "ip") && IS(1, "access-group")) st->eos_ssh_acl = true;
        break;
    case MODE_MGMT_TELNET:
        if (shutdown) st->eos_telnet_on = no;
        break;
    case MODE_MGMT_API:
        if (shutdown) st->eos_api_on = no;
        if (IS(0, "protocol") && IS(1, "http"))                 st->eos_api_http = true;
        if (no && IS(1, "protocol") && IS(2, "https"))          st->eos_api_no_https = true;
        break;
    case MODE_MGMT_SECURITY:
        if (IS(0, "password") && IS(1, "minimum")) st->m->auth.password_policy = true;
        break;
    default:
        break;
    }
}

/* -- Defaults that depend on the whole file ------------------------------------- */

static void finish(IosState *st)
{
    DeviceModel *m = st->m;

    switch (st->dialect) {
    case DIALECT_IOS:
        /* CDP and source routing run on IOS unless switched off. */
        m->services.cdp_global     = !st->cdp_disabled;
        m->services.source_routing = !st->source_route_disabled;
        m->mgmt.access_restricted  = st->vty_blocks > 0 &&
                                     st->vty_with_acl == st->vty_blocks;
        return;

    case DIALECT_NXOS:
        m->services.cdp_global     = !st->cdp_disabled;
        m->services.source_routing = !st->source_route_disabled;
        m->mgmt.access_restricted  = st->vty_blocks > 0 &&
                                     st->vty_with_acl == st->vty_blocks;
        m->mgmt.ssh_enabled        = !st->nxos_ssh_disabled;   /* on by default */
        m->mgmt.ssh_version        = 2;
        m->auth.password_policy    = !st->nxos_strength_check_off;
        m->logging.timestamps      = true;
        if (m->mgmt.idle_timeout_min == 0)
            m->mgmt.idle_timeout_min = NXOS_DEFAULT_TIMEOUT_MIN;
        break;

    case DIALECT_EOS:
        m->mgmt.ssh_enabled       = !st->eos_ssh_shutdown;     /* on by default */
        m->mgmt.ssh_version       = 2;
        m->mgmt.telnet_enabled    = st->eos_telnet_on;
        m->mgmt.http_enabled      = st->eos_api_on && st->eos_api_http;
        m->mgmt.https_enabled     = st->eos_api_on && !st->eos_api_no_https;
        m->mgmt.access_restricted = st->eos_ssh_acl;
        m->logging.timestamps     = true;
        if (m->mgmt.idle_timeout_min == 0)                     /* no default */
            m->mgmt.idle_timeout_min = NA_TIMEOUT_NEVER;
        break;

    case DIALECT_ASA:
        if (m->mgmt.ssh_enabled && m->mgmt.ssh_version == 0) m->mgmt.ssh_version = 2;
        m->mgmt.access_restricted = st->asa_mgmt_sources > 0 && st->asa_mgmt_any == 0;
        if (!st->asa_logging_enabled) {              /* "logging enable" absent */
            m->logging.server_count = 0;
            m->logging.buffered_enabled = false;
        }
        for (int i = 0; st->asa_global_acl[0] && i < m->interface_count; i++) {
            Interface *it = &m->interfaces[i];
            if (it->acl_in[0] == '\0')
                safe_strcpy(it->acl_in, sizeof(it->acl_in), st->asa_global_acl);
        }
        break;
    }
    /* These systems never show a password in clear unless one was entered so. */
    m->auth.password_encryption = !st->plaintext_seen;
}

/* "! device: sw1 (DCS-7050SX, EOS-4.28.3M)" -> "4.28.3M" */
static void eos_version_from_comment(DeviceModel *m, const char *line)
{
    const char *p = strstr(line, "EOS-");
    if (!p || m->os_version[0]) return;
    p += 4;
    size_t len = strcspn(p, ") \t");
    safe_strncpy_n(m->os_version, sizeof(m->os_version), p, len);
}

/* -- parse ---------------------------------------------------------------------- */

static AuditStatus family_parse(const char *path, DeviceModel *m, Dialect dialect,
                                const char *vendor)
{
    static IosState st;                /* ~4 KB: keep it off the stack */
    LineReader r;
    AuditStatus rc = line_reader_open(&r, path);
    if (rc != AUDIT_OK) return rc;

    safe_strcpy(m->vendor, sizeof(m->vendor), vendor);
    safe_strcpy(m->source_file, sizeof(m->source_file), path);

    memset(&st, 0, sizeof(st));
    st.m = m;
    st.dialect = dialect;
    st.mode = MODE_GLOBAL;

    char raw[NA_MAX_LINE];
    char *words[NA_MAX_TOKENS];
    char *line;

    while ((line = line_reader_next(&r)) != NULL) {
        st.line = r.line_number;
        bool indented = isspace((unsigned char)line[0]);
        str_trim(line);

        if (st.banner_end[0]) {                      /* inside banner text */
            bool end = dialect == DIALECT_EOS ? strcmp(line, "EOF") == 0
                                              : strstr(line, st.banner_end) != NULL;
            if (end) st.banner_end[0] = '\0';
            continue;
        }
        if (line[0] == '!' && dialect == DIALECT_EOS) eos_version_from_comment(m, line);
        if (line[0] == '\0' || line[0] == '!') continue;
        if (line[0] == ':' && dialect == DIALECT_ASA) continue;   /* ": Saved" */

        safe_strcpy(raw, sizeof(raw), line);
        st.raw = raw;
        int n = str_tokenize(line, words, NA_MAX_TOKENS);
        if (n == 0) continue;

        if (!indented || st.mode == MODE_GLOBAL) {
            ios_global(&st, words, n);
            continue;
        }
        switch (st.mode) {
        case MODE_INTERFACE: ios_interface(&st, words, n);                          break;
        case MODE_VTY:
        case MODE_CONSOLE:   ios_line(&st, words, n);                               break;
        case MODE_ACL:       ios_acl_entry(&st, st.acl, st.acl_extended, words, n); break;
        case MODE_MGMT_SSH:
        case MODE_MGMT_TELNET:
        case MODE_MGMT_CONSOLE:
        case MODE_MGMT_API:
        case MODE_MGMT_SECURITY: eos_management(&st, words, n);                     break;
        default:                                                                    break;
        }
    }

    rc = line_reader_failed(&r) ? AUDIT_ERR_IO : AUDIT_OK;
    line_reader_close(&r);
    finish(&st);

    LOG_INF("%s: parsed '%s' (%d lines, %d interfaces, %d ACLs)",
            vendor, path, r.line_number, m->interface_count, m->acl_count);
    return rc;
}

static AuditStatus ios_parse(const char *path, DeviceModel *m)
{
    return family_parse(path, m, DIALECT_IOS, "cisco");
}

static AuditStatus nxos_parse(const char *path, DeviceModel *m)
{
    return family_parse(path, m, DIALECT_NXOS, "nxos");
}

static AuditStatus asa_parse(const char *path, DeviceModel *m)
{
    return family_parse(path, m, DIALECT_ASA, "asa");
}

static AuditStatus eos_parse(const char *path, DeviceModel *m)
{
    return family_parse(path, m, DIALECT_EOS, "arista");
}

const VendorParser PARSER_CISCO_IOS = {
    .name         = "cisco",
    .display_name = "Cisco IOS",
    .probe        = ios_probe,
    .parse        = ios_parse,
};

const VendorParser PARSER_CISCO_NXOS = {
    .name         = "nxos",
    .display_name = "Cisco NX-OS",
    .probe        = nxos_probe,
    .parse        = nxos_parse,
};

const VendorParser PARSER_CISCO_ASA = {
    .name         = "asa",
    .display_name = "Cisco ASA",
    .probe        = asa_probe,
    .parse        = asa_parse,
};

const VendorParser PARSER_ARISTA_EOS = {
    .name         = "arista",
    .display_name = "Arista EOS",
    .probe        = eos_probe,
    .parse        = eos_parse,
};
