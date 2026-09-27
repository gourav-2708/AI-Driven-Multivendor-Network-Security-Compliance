/**
 * @file parser_registry.c
 * @brief Global vendor-parser registry implementation.
 *
 * Parsers self-register at start-up via parser_register().
 * The engine never references a specific parser directly.
 */

#include <string.h>
#include "parser.h"
#include "common.h"

/* -- Registry storage ------------------------------------------------------ */

static const VendorParser *s_parsers[MAX_PARSERS];
static int                 s_parser_count = 0;

/**
 * @brief Register a vendor parser.
 */
void parser_register(const VendorParser *p)
{
    if (!p) {
        LOG_ERR("parser_register: NULL pointer");
        return;
    }
    if (s_parser_count >= MAX_PARSERS) {
        LOG_ERR("parser_register: registry full (max %d)", MAX_PARSERS);
        return;
    }

    /* Overwrite existing entry for the same vendor name. */
    for (int i = 0; i < s_parser_count; i++) {
        if (portable_strcasecmp(s_parsers[i]->vendor_name, p->vendor_name) == 0) {
            LOG_WRN("parser_register: overwriting existing '%s' parser",
                    p->vendor_name);
            s_parsers[i] = p;
            return;
        }
    }

    s_parsers[s_parser_count++] = p;
    LOG_DBG("parser_register: registered '%s' (total: %d)",
            p->vendor_name, s_parser_count);
}

/**
 * @brief Look up a parser by vendor name (case-insensitive).
 */
const VendorParser *parser_find_by_vendor(const char *vendor_name)
{
    if (!vendor_name) return NULL;
    for (int i = 0; i < s_parser_count; i++) {
        if (portable_strcasecmp(s_parsers[i]->vendor_name, vendor_name) == 0)
            return s_parsers[i];
    }
    return NULL;
}

/**
 * @brief Auto-detect the parser for a config file.
 *
 * Calls each registered parser's detect() function in registration order.
 */
const VendorParser *parser_detect(const char *filepath)
{
    if (!filepath) return NULL;
    for (int i = 0; i < s_parser_count; i++) {
        if (s_parsers[i]->detect && s_parsers[i]->detect(filepath)) {
            LOG_DBG("parser_detect: '%s' matched '%s'",
                    s_parsers[i]->vendor_name, filepath);
            return s_parsers[i];
        }
    }
    LOG_WRN("parser_detect: no parser matched '%s'", filepath);
    return NULL;
}

/**
 * @brief Return number of registered parsers.
 */
int parser_count(void)
{
    return s_parser_count;
}

