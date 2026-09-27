/**
 * @file parser.h
 * @brief Pluggable vendor-parser vtable interface.
 *
 * Adding a new vendor:
 *   1. Create src/parser/<vendor>_parser.c with detect() and parse().
 *   2. Fill in a VendorParser struct and expose <vendor>_parser_register().
 *   3. Call <vendor>_parser_register() from main.c. No other changes needed.
 */
#ifndef NET_AUDIT_PARSER_H
#define NET_AUDIT_PARSER_H

#include <stdbool.h>
#include "model.h"

#define MAX_PARSERS 16

typedef struct VendorParser {
    const char *vendor_name;
    bool (*detect)(const char *filepath);
    int  (*parse)(const char *filepath, DeviceModel *out_model);
} VendorParser;

void                parser_register(const VendorParser *p);
const VendorParser *parser_find_by_vendor(const char *vendor_name);
const VendorParser *parser_detect(const char *filepath);
int                 parser_count(void);

/* Per-vendor registration entry points */
void cisco_parser_register(void);
void juniper_parser_register(void);
void fortinet_parser_register(void);

#endif /* NET_AUDIT_PARSER_H */
