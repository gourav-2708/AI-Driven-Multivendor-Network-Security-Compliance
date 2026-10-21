/**
 * @file status.h
 * @brief Status codes returned by every fallible net-audit function.
 */
#ifndef NETAUDIT_STATUS_H
#define NETAUDIT_STATUS_H

typedef enum {
    AUDIT_OK = 0,
    AUDIT_ERR_IO,       /* file could not be opened, read or written   */
    AUDIT_ERR_PARSE,    /* input is not a usable configuration          */
    AUDIT_ERR_ARG,      /* invalid argument or command-line option      */
    AUDIT_ERR_LIMIT,    /* a fixed capacity (see bounds.h) was exceeded */
    AUDIT_ERR_VENDOR    /* vendor unknown or could not be detected      */
} AuditStatus;

/** Human-readable text for a status code; never returns NULL. */
const char *audit_strerror(AuditStatus rc);

#endif /* NETAUDIT_STATUS_H */
