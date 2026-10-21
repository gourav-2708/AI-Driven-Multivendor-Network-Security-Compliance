/**
 * @file model.h
 * @brief Normalised, vendor-agnostic device model.
 *
 * Vendor parsers translate their syntax into a DeviceModel; the rule engine
 * reads nothing else. A field means the same thing for every vendor, so a
 * rule written once applies to Cisco, Juniper and Fortinet alike.
 *
 * Collections are fixed-size arrays (see bounds.h). Use the model_* helpers
 * to add elements: they enforce capacities and de-duplicate by name.
 */
#ifndef NETAUDIT_MODEL_H
#define NETAUDIT_MODEL_H

#include <stdbool.h>
#include "netaudit/bounds.h"

/* -- Interfaces ------------------------------------------------------------ */
typedef struct {
    char name[NA_MAX_IFNAME];
    char description[NA_MAX_IFDESC];
    char ip_address[NA_MAX_ADDR];
    char subnet_mask[NA_MAX_ADDR];   /* dotted mask or prefix length       */
    char acl_in[NA_MAX_ACLNAME];     /* inbound filter / ACL, "" if none   */
    char acl_out[NA_MAX_ACLNAME];
    bool dynamic_address;            /* address comes from DHCP/PPPoE      */
    bool shutdown;
    bool is_loopback;
    bool is_management;
    int  line_number;                /* where the interface is declared    */
} Interface;

/* -- Access lists / firewall filters / security policies -------------------- */
typedef enum { ACL_PERMIT = 0, ACL_DENY } AclAction;

typedef struct {
    AclAction action;
    char      protocol[NA_MAX_PROTO];
    char      src_addr[NA_MAX_ADDR];
    char      dst_addr[NA_MAX_ADDR];
    bool      is_any_any;    /* permits every source to every destination */
    int       line_number;
} AclEntry;

typedef struct {
    char     name[NA_MAX_ACLNAME];
    AclEntry entries[NA_MAX_ACL_ENTRIES];
    int      entry_count;
} Acl;

/* -- Authentication and credential storage -------------------------------- */
typedef struct {
    bool aaa_configured;           /* central AAA (RADIUS/TACACS+/LDAP)     */
    bool enable_secret_set;        /* privileged password stored hashed     */
    bool enable_password_set;      /* privileged password plaintext/rev.    */
    bool password_encryption;      /* service password-encryption or equiv. */
    bool local_users;              /* local accounts are defined            */
    bool plaintext_user_password;  /* a local account uses a clear password */
} AuthConfig;

/* -- Management-plane access ------------------------------------------------ */
typedef struct {
    bool ssh_enabled;
    int  ssh_version;      /* 0 = unspecified, 1 or 2 */
    bool telnet_enabled;
    bool http_enabled;     /* plain-text HTTP management */
    bool https_enabled;
} MgmtAccess;

/* -- SNMP --------------------------------------------------------------------- */
typedef enum { SNMP_RO = 0, SNMP_RW } SnmpAccess;

typedef struct {
    char       name[NA_MAX_COMMUNITY];
    SnmpAccess access;
    bool       restricted;  /* bound to an ACL / client list / host list */
    int        line_number;
} SnmpCommunity;

typedef struct {
    bool          enabled;
    bool          v1_enabled;
    bool          v3_configured;
    SnmpCommunity communities[NA_MAX_COMMUNITIES];   /* v1/v2c communities */
    int           community_count;
} SnmpConfig;

/* -- Logging and time --------------------------------------------------------- */
typedef struct {
    bool buffered_enabled;       /* local buffer / disk / memory log       */
    char servers[NA_MAX_LOG_SERVERS][NA_MAX_ADDR];
    int  server_count;
} LoggingConfig;

typedef struct {
    char servers[NA_MAX_NTP_SERVERS][NA_MAX_ADDR];
    int  server_count;
    bool authenticated;
} NtpConfig;

/* -- Legacy / discovery services ---------------------------------------------- */
typedef struct {
    bool cdp_global;
    bool tcp_small_servers;
    bool udp_small_servers;
} ServiceFlags;

/* -- The device ---------------------------------------------------------------- */
typedef struct {
    char hostname[NA_MAX_HOSTNAME];
    char vendor[NA_MAX_VENDOR];
    char os_version[NA_MAX_OSVER];
    char source_file[NA_MAX_PATH];

    Interface interfaces[NA_MAX_INTERFACES];
    int       interface_count;

    Acl       acls[NA_MAX_ACLS];
    int       acl_count;

    AuthConfig    auth;
    MgmtAccess    mgmt;
    SnmpConfig    snmp;
    LoggingConfig logging;
    NtpConfig     ntp;
    ServiceFlags  services;

    int overflow_count;   /* elements dropped because a capacity was full */
} DeviceModel;

/** Reset every field to its zero/false default. */
void model_init(DeviceModel *m);

/** Hostname, or "(unknown)" when the config did not set one. */
const char *model_hostname(const DeviceModel *m);

/* Find-or-add helpers. Return NULL (and log once) when capacity is full. */
Interface     *model_interface(DeviceModel *m, const char *name);
Acl           *model_acl(DeviceModel *m, const char *name);
AclEntry      *model_acl_add_entry(DeviceModel *m, Acl *acl);
SnmpCommunity *model_snmp_community(DeviceModel *m, const char *name);
bool           model_add_ntp_server(DeviceModel *m, const char *addr);
bool           model_add_log_server(DeviceModel *m, const char *addr);

/**
 * Vendor-neutral post-processing run after every parse:
 * marks interfaces whose name or description identifies them as
 * management ports (mgmt, management, me0, fxp0, em0), never loopbacks.
 */
void model_finalize(DeviceModel *m);

#endif /* NETAUDIT_MODEL_H */
