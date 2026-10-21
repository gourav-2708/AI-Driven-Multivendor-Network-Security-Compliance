/**
 * @file line_reader.h
 * @brief Shared line-oriented file reader for vendor parsers.
 *
 * Handles the details every parser would otherwise repeat: line numbering,
 * CRLF and LF endings, a UTF-8 byte-order mark on the first line, and lines
 * longer than NA_MAX_LINE (truncated, with one warning per file).
 */
#ifndef NETAUDIT_LINE_READER_H
#define NETAUDIT_LINE_READER_H

#include <stdbool.h>
#include <stdio.h>
#include "netaudit/bounds.h"
#include "netaudit/status.h"

typedef struct {
    FILE       *fp;
    const char *path;
    int         line_number;     /* 1-based number of the last line read */
    int         truncated_lines;
    bool        quiet;           /* suppress the truncation warning      */
    char        buf[NA_MAX_LINE];
} LineReader;

AuditStatus line_reader_open(LineReader *r, const char *path);

/**
 * Read the next line (without its line terminator) into the reader's
 * buffer. The buffer is writable and stays valid until the next call.
 * @return the line, or NULL at end of file / on read error.
 */
char *line_reader_next(LineReader *r);

/** True if a read error (not end-of-file) stopped the reader. */
bool  line_reader_failed(const LineReader *r);

void  line_reader_close(LineReader *r);

#endif /* NETAUDIT_LINE_READER_H */
