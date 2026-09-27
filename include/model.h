/**
 * @file model.h
 * @brief Normalized, vendor-agnostic internal device model.
 *
 * All vendor parsers translate their source syntax into this model.
 * The rule engine operates exclusively on this model.
 */
#ifndef NET_AUDIT_MODEL_H
#define NET_AUDIT_MODEL_H

#include <stdbool.h>

/* Buffer sizes */
#define MAX_HOSTNAME_LEN    128
#define MAX_VENDOR_LEN       32
#define MAX_OSVER_LEN        64
#define MAX_IFNAME_LEN       64
#define MAX_ACLNAME_LEN      64
#define MAX_COMMUNITY_LEN    64
#define MAX_IP_LEN           48
#define MAX_MASK_LEN         48
#define MAX_PROTO_LEN        32
#define MAX_PATH_LEN        256

#define MAX_INTERFACES       64
#define MAX_ACLS             32
#define MAX_ACL_ENTRIES     256
#define MAX_NTP_SERVERS       8
#define MAX_LOG_SERVERS       8
#define MAX_FINDINGS        256
#define MAX_RULE_ID_LEN      16
#define MAX_DESC_LEN        256
#define MAX_SECTION_LEN     128
#define MAX_REMEDIATION_LEN 512

/* Severity */
typedef enum {
    SEV_CRITICAL = 0,
    SEV_HIGH,
    SEV_MEDIUM,
    SEV_LOW,
    SEV_COUNT
} Severity;

extern const char *const SEVERITY_LABELS[SEV_COUNT];
extern const char *const SEVERITY_COLORS[SEV_COUNT];
extern const int         SEVERITY_WEIGHTS[SEV_COUNT];

/* Interface */
typedef struct {
    char name[MAX_IFNAME_LEN];
    char ip_address[MAX_IP_LEN];
    char subnet_mask[MAX_MASK_LEN];
    char acl_in[MAX_ACLNAME_LEN];
    char acl_out[MAX_ACLNAME_LEN];
    char description[128];
    bool shutdown;
    bool is_loopback;
    bool is_management;
    bool cdp_enabled;
    bool proxy_arp;
} Interface;

/* ACL */
typedef enum { ACL_PERMIT = 0, ACL_DENY } AclAction;

typedef struct {
    AclAction action;
    char      protocol[MAX_PROTO_LEN];
    char      src_addr[MAX_IP_LEN];
    char      src_mask[MAX_MASK_LEN];
    char      dst_addr[MAX_IP_LEN];
    char      dst_mask[MAX_MASK_LEN];
    bool      is_any_any;
    int       line_number;
} AclEntry;

typedef struct {
    char     name[MAX_ACLNAME_LEN];
    AclEntry entries[MAX_ACL_ENTRIES];
    int      entry_count;
    bool     is_extended;
} Acl;

/* Auth */
typedef struct {
    bool aaa_configured;
    bool enable_secret_set;
    bool enable_password_set;
    bool service_password_encrypt;
    bool ssh_enabled;
    bool telnet_on_vty;
    int  ssh_version;
    bool local_users_configured;
} AuthConfig;

/* SNMP */
typedef enum { SNMP_NONE=0, SNMP_V1, SNMP_V2C, SNMP_V3 } SnmpVersion;

typedef struct {
    bool        enabled;
    SnmpVersion version;
    char        community_ro[MAX_COMMUNITY_LEN];
    char        community_rw[MAX_COMMUNITY_LEN];
    char        acl_name[MAX_ACLNAME_LEN];
    bool        has_restricting_acl;
} SnmpConfig;

/* Logging */
typedef struct {
    bool buffered_enabled;
    bool console_enabled;
    char servers[MAX_LOG_SERVERS][MAX_IP_LEN];
    int  server_count;
    int  buffered_size;
} LoggingConfig;

/* NTP */
typedef struct {
    char servers[MAX_NTP_SERVERS][MAX_IP_LEN];
    int  server_count;
    bool authenticated;
} NtpConfig;

/* Services */
typedef struct {
    bool telnet_enabled;
    bool http_enabled;
    bool https_enabled;
    bool cdp_global;
    bool dhcp_enabled;
    bool finger_enabled;
    bool tcp_small_servers;
    bool udp_small_servers;
    bool bootp_enabled;
} ServiceFlags;

/* Top-level device model */
typedef struct {
    char hostname[MAX_HOSTNAME_LEN];
    char vendor[MAX_VENDOR_LEN];
    char os_version[MAX_OSVER_LEN];
    char source_file[MAX_PATH_LEN];

    Interface interfaces[MAX_INTERFACES];
    int       interface_count;

    Acl       acls[MAX_ACLS];
    int       acl_count;

    AuthConfig    auth;
    SnmpConfig    snmp;
    LoggingConfig logging;
    NtpConfig     ntp;
    ServiceFlags  services;
} DeviceModel;

/* Finding / AuditResult */
typedef struct {
    char     rule_id[MAX_RULE_ID_LEN];
    Severity severity;
    char     description[MAX_DESC_LEN];
    char     affected_section[MAX_SECTION_LEN];
    char     remediation[MAX_REMEDIATION_LEN];
    int      line_number;
} Finding;

typedef struct AuditResult {
    DeviceModel *device;
    Finding      findings[MAX_FINDINGS];
    int          finding_count;
    int          score;
    int          sev_counts[SEV_COUNT];
} AuditResult;

/* Init helpers */
void model_init(DeviceModel *m);
void result_init(AuditResult *r, DeviceModel *device);

#endif /* NET_AUDIT_MODEL_H */
