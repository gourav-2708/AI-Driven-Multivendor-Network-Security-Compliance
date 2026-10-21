/**
 * @file parser.h
 * @brief Pluggable vendor-parser interface and registry.
 *
 * A vendor parser is a VendorParser value with two callbacks:
 *
 *   probe(sample)  - look at the first lines of a file (already read and
 *                    trimmed into a ConfigSample) and return a confidence
 *                    0..100 that the file is in this vendor's syntax.
 *   parse(path,m)  - fill a zero-initialised DeviceModel from the file.
 *
 * Auto-detection loads the sample once, asks every registered parser, and
 * picks the most confident one (ties go to the earlier registration).
 *
 * Adding a vendor:
 *   1. Create src/parser/<vendor>.c defining `const VendorParser PARSER_X`.
 *   2. Add &PARSER_X to the built-in table in src/parser/parser_registry.c.
 * Nothing else in the code base references a specific parser.
 */
#ifndef NETAUDIT_PARSER_H
#define NETAUDIT_PARSER_H

#include <stdbool.h>
#include "netaudit/model.h"
#include "netaudit/status.h"

#define CONFIG_SAMPLE_LINES   40
#define CONFIG_SAMPLE_WIDTH  160
#define PARSER_MIN_CONFIDENCE 25

/** The first non-blank lines of a config file, trimmed. */
typedef struct {
    char lines[CONFIG_SAMPLE_LINES][CONFIG_SAMPLE_WIDTH];
    int  count;
} ConfigSample;

typedef struct VendorParser {
    const char *name;          /* CLI identifier, e.g. "cisco"            */
    const char *display_name;  /* e.g. "Cisco IOS"                         */
    int         (*probe)(const ConfigSample *sample);
    AuditStatus (*parse)(const char *path, DeviceModel *out);
} VendorParser;

/** Register the built-in parsers. Safe to call more than once. */
void parser_registry_init(void);

/** Register an additional parser (replaces one with the same name). */
AuditStatus parser_register(const VendorParser *p);

int                 parser_count(void);
const VendorParser *parser_at(int index);
const VendorParser *parser_find(const char *name);

/**
 * Pick the parser for @p path by probing its first lines.
 * @param confidence_out optional; receives the winning confidence.
 * @return NULL when the file cannot be read or nothing is confident enough.
 */
const VendorParser *parser_detect(const char *path, int *confidence_out);

/** Read the first CONFIG_SAMPLE_LINES non-blank lines of @p path. */
AuditStatus config_sample_load(const char *path, ConfigSample *out);

/** Helpers for probe() implementations. */
bool sample_has_prefix(const ConfigSample *s, const char *prefix);
bool sample_has_prefix_ci(const ConfigSample *s, const char *prefix);
bool sample_contains_ci(const ConfigSample *s, const char *needle);

#endif /* NETAUDIT_PARSER_H */
