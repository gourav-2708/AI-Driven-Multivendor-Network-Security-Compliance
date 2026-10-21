/**
 * @file line_reader.c
 * @brief Line reader shared by all vendor parsers.
 */
#include "netaudit/line_reader.h"
#include "netaudit/log.h"
#include "netaudit/safe_str.h"

AuditStatus line_reader_open(LineReader *r, const char *path)
{
    if (!r || !path) return AUDIT_ERR_ARG;
    memset(r, 0, sizeof(*r));
    r->path = path;
    r->fp = fopen(path, "rb");     /* binary: we strip CR ourselves */
    if (!r->fp) {
        LOG_ERR("cannot open '%s': %s", path, strerror(errno));
        return AUDIT_ERR_IO;
    }
    return AUDIT_OK;
}

char *line_reader_next(LineReader *r)
{
    if (!r || !r->fp) return NULL;
    if (!fgets(r->buf, sizeof(r->buf), r->fp)) return NULL;
    r->line_number++;

    size_t len = strlen(r->buf);
    bool complete = len > 0 && r->buf[len - 1] == '\n';
    int c;
    if (!complete && (c = fgetc(r->fp)) != EOF && c != '\n') {
        /* Line longer than the buffer: keep the prefix, drop the rest. */
        while ((c = fgetc(r->fp)) != EOF && c != '\n') { }
        if (r->truncated_lines++ == 0 && !r->quiet) {
            LOG_WRN("%s:%d: line longer than %d bytes truncated",
                    r->path, r->line_number, NA_MAX_LINE - 1);
        }
    }

    while (len > 0 && (r->buf[len - 1] == '\n' || r->buf[len - 1] == '\r'))
        r->buf[--len] = '\0';

    if (r->line_number == 1 && (unsigned char)r->buf[0] == 0xEF &&
        (unsigned char)r->buf[1] == 0xBB && (unsigned char)r->buf[2] == 0xBF)
        memmove(r->buf, r->buf + 3, len - 2);     /* includes the NUL */

    return r->buf;
}

bool line_reader_failed(const LineReader *r)
{
    return r && r->fp && ferror(r->fp);
}

void line_reader_close(LineReader *r)
{
    if (r && r->fp) {
        fclose(r->fp);
        r->fp = NULL;
    }
}
