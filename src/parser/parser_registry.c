/**
 * @file parser_registry.c
 * @brief Vendor-parser registry and confidence-based auto-detection.
 */
#include "netaudit/line_reader.h"
#include "netaudit/log.h"
#include "netaudit/parser.h"
#include "netaudit/safe_str.h"

/* -- Built-in parsers: add new vendors here --------------------------------- */
extern const VendorParser PARSER_CISCO_IOS;
extern const VendorParser PARSER_JUNIPER_JUNOS;
extern const VendorParser PARSER_FORTINET_FORTIOS;

static const VendorParser *const k_builtin[] = {
    &PARSER_CISCO_IOS,
    &PARSER_JUNIPER_JUNOS,
    &PARSER_FORTINET_FORTIOS,
};

/* -- Registry --------------------------------------------------------------- */
static const VendorParser *s_parsers[NA_MAX_PARSERS];
static int                 s_count;

void parser_registry_init(void)
{
    for (size_t i = 0; i < NA_ARRAY_LEN(k_builtin); i++)
        parser_register(k_builtin[i]);
}

AuditStatus parser_register(const VendorParser *p)
{
    if (!p || !p->name || !p->probe || !p->parse) return AUDIT_ERR_ARG;

    for (int i = 0; i < s_count; i++) {
        if (str_eq_ci(s_parsers[i]->name, p->name)) {
            s_parsers[i] = p;
            return AUDIT_OK;
        }
    }
    if (s_count >= NA_MAX_PARSERS) {
        LOG_ERR("parser registry full (%d parsers)", NA_MAX_PARSERS);
        return AUDIT_ERR_LIMIT;
    }
    s_parsers[s_count++] = p;
    return AUDIT_OK;
}

int parser_count(void) { return s_count; }

const VendorParser *parser_at(int index)
{
    return (index >= 0 && index < s_count) ? s_parsers[index] : NULL;
}

const VendorParser *parser_find(const char *name)
{
    for (int i = 0; name && i < s_count; i++) {
        if (str_eq_ci(s_parsers[i]->name, name)) return s_parsers[i];
    }
    return NULL;
}

/* -- Detection --------------------------------------------------------------- */

AuditStatus config_sample_load(const char *path, ConfigSample *out)
{
    if (!out) return AUDIT_ERR_ARG;
    memset(out, 0, sizeof(*out));

    LineReader r;
    AuditStatus rc = line_reader_open(&r, path);
    if (rc != AUDIT_OK) return rc;
    r.quiet = true;                     /* the parser will warn, once */

    char *line;
    while (out->count < CONFIG_SAMPLE_LINES && (line = line_reader_next(&r))) {
        str_trim(line);
        if (line[0] == '\0') continue;
        safe_strcpy(out->lines[out->count++], CONFIG_SAMPLE_WIDTH, line);
    }
    rc = line_reader_failed(&r) ? AUDIT_ERR_IO : AUDIT_OK;
    line_reader_close(&r);
    return rc;
}

const VendorParser *parser_detect(const char *path, int *confidence_out)
{
    static ConfigSample sample;      /* ~6 KB: keep it off the stack */
    if (confidence_out) *confidence_out = 0;
    if (config_sample_load(path, &sample) != AUDIT_OK) return NULL;

    const VendorParser *best = NULL;
    int best_score = 0;
    for (int i = 0; i < s_count; i++) {
        int score = s_parsers[i]->probe(&sample);
        LOG_DBG("detect: %s scores %d for '%s'", s_parsers[i]->name, score, path);
        if (score > best_score) {
            best = s_parsers[i];
            best_score = score;
        }
    }
    if (best_score < PARSER_MIN_CONFIDENCE) return NULL;
    if (confidence_out) *confidence_out = best_score;
    return best;
}

bool sample_has_prefix(const ConfigSample *s, const char *prefix)
{
    for (int i = 0; i < s->count; i++)
        if (str_starts_with(s->lines[i], prefix)) return true;
    return false;
}

bool sample_has_prefix_ci(const ConfigSample *s, const char *prefix)
{
    for (int i = 0; i < s->count; i++)
        if (str_starts_with_ci(s->lines[i], prefix)) return true;
    return false;
}

bool sample_contains_ci(const ConfigSample *s, const char *needle)
{
    for (int i = 0; i < s->count; i++)
        if (str_contains_ci(s->lines[i], needle)) return true;
    return false;
}
