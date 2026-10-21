/**
 * @file bounds.h
 * @brief Every fixed capacity used by net-audit, in one place.
 *
 * net-audit never allocates from the heap. All storage is sized by the
 * constants below; when an input exceeds a capacity the excess is dropped
 * and a warning is logged, so a hostile or oversized config can degrade the
 * report but never corrupt memory.
 */
#ifndef NETAUDIT_BOUNDS_H
#define NETAUDIT_BOUNDS_H

/* String buffers (bytes, including the terminating NUL) */
#define NA_MAX_PATH           260
#define NA_MAX_LINE          1024   /* longest config line read verbatim  */
#define NA_MAX_HOSTNAME       128
#define NA_MAX_VENDOR          32
#define NA_MAX_OSVER           64
#define NA_MAX_IFNAME          64
#define NA_MAX_IFDESC         128
#define NA_MAX_ACLNAME         64
#define NA_MAX_COMMUNITY       64
#define NA_MAX_ADDR            48   /* IPv4/IPv6 address or hostname      */
#define NA_MAX_PROTO           32
#define NA_MAX_SECTION        128   /* "affected section" text of finding */

/* Collection capacities */
#define NA_MAX_INTERFACES      64
#define NA_MAX_ACLS            32
#define NA_MAX_ACL_ENTRIES    128
#define NA_MAX_COMMUNITIES     16
#define NA_MAX_NTP_SERVERS      8
#define NA_MAX_LOG_SERVERS      8
#define NA_MAX_FINDINGS       256
#define NA_MAX_INPUT_FILES    128
#define NA_MAX_PARSERS         16
#define NA_MAX_TOKENS          48   /* words per config statement         */

#endif /* NETAUDIT_BOUNDS_H */
