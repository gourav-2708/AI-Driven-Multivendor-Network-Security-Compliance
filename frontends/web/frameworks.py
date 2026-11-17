# -*- coding: utf-8 -*-
"""
Compliance frameworks: which controls pass, which fail, and which no rule
covers yet.

The rule -> control mapping is not kept here. It lives in the engine's rule
table and arrives through `net-audit --list-rules --format json`. This file
holds only the list of controls that matter for a network device in each
framework, with a short title, so the dashboard can also show the controls
that have no rule yet. Titles are short paraphrases, not the standards' text.
"""
import re

import controls
import engine

# (control id, title). A control listed here with no rule mapped to it is
# reported as "not covered", which is the to-do list for new rules.
CONTROLS = {
    "cis_v8": [
        ("3.10", "Encrypt sensitive data in transit"),
        ("4.1", "Establish and maintain a secure configuration process"),
        ("4.2", "Establish and maintain a secure configuration process for network infrastructure"),
        ("4.3", "Configure automatic session locking"),
        ("4.6", "Securely manage enterprise assets and software"),
        ("4.7", "Manage default accounts"),
        ("4.8", "Uninstall or disable unnecessary services"),
        ("5.2", "Use unique passwords"),
        ("5.4", "Restrict administrator privileges to dedicated administrator accounts"),
        ("6.5", "Require MFA for administrative access"),
        ("6.7", "Centralize access control"),
        ("8.2", "Collect audit logs"),
        ("8.3", "Ensure adequate audit log storage"),
        ("8.4", "Standardize time synchronization"),
        ("8.5", "Collect detailed audit logs"),
        ("8.9", "Centralize audit logs"),
        ("12.1", "Ensure network infrastructure is up to date"),
        ("12.2", "Establish and maintain a secure network architecture"),
        ("12.3", "Securely manage network infrastructure"),
        ("12.5", "Centralize network authentication, authorization and auditing (AAA)"),
        ("12.6", "Use secure network management and communication protocols"),
        ("13.4", "Perform traffic filtering between network segments"),
        ("13.6", "Collect network traffic flow logs"),
    ],
    "pci_dss_4": [
        ("1.2.1", "Configuration standards for network security controls are defined and applied"),
        ("1.2.5", "Allowed services, protocols and ports are identified, approved and needed"),
        ("1.2.6", "Security features protect insecure services, protocols and ports in use"),
        ("1.2.8", "Network device configuration files are protected from unauthorized access"),
        ("1.3.1", "Inbound traffic to the cardholder data environment is restricted"),
        ("1.3.2", "Outbound traffic from the cardholder data environment is restricted"),
        ("1.4.2", "Inbound traffic from untrusted networks is restricted"),
        ("1.4.3", "Anti-spoofing measures block forged source addresses"),
        ("2.2.2", "Vendor default accounts and passwords are changed or disabled"),
        ("2.2.4", "Only necessary services, protocols and functions are enabled"),
        ("2.2.5", "Insecure services in use are justified and secured"),
        ("2.2.6", "System security parameters are set to prevent misuse"),
        ("2.2.7", "Non-console administrative access is encrypted"),
        ("6.3.3", "Security patches and updates are installed in time"),
        ("8.2.1", "Every user has a unique ID"),
        ("8.2.8", "Idle sessions require re-authentication after 15 minutes"),
        ("8.3.2", "Authentication factors are unreadable in transit and in storage"),
        ("8.3.4", "Repeated failed logins lock the account"),
        ("8.3.6", "Passwords meet a minimum length and complexity"),
        ("8.4.1", "MFA protects non-console administrative access"),
        ("10.2.1", "Audit logs are enabled and active"),
        ("10.2.2", "Audit log entries record who, what, when and where"),
        ("10.3.3", "Audit logs are promptly copied to a central log server"),
        ("10.6.1", "Clocks are synchronized using time-synchronization technology"),
        ("10.6.2", "Systems take the correct time from designated time servers"),
        ("10.6.3", "Time settings and time data are protected"),
    ],
    "iso_27001_2022": [
        ("A.5.15", "Access control"),
        ("A.5.16", "Identity management"),
        ("A.5.17", "Authentication information"),
        ("A.5.18", "Access rights"),
        ("A.8.2", "Privileged access rights"),
        ("A.8.3", "Information access restriction"),
        ("A.8.5", "Secure authentication"),
        ("A.8.8", "Management of technical vulnerabilities"),
        ("A.8.9", "Configuration management"),
        ("A.8.13", "Information backup"),
        ("A.8.15", "Logging"),
        ("A.8.16", "Monitoring activities"),
        ("A.8.17", "Clock synchronization"),
        ("A.8.20", "Networks security"),
        ("A.8.21", "Security of network services"),
        ("A.8.22", "Segregation of networks"),
        ("A.8.24", "Use of cryptography"),
    ],
    "nist_800_53_r5": [
        ("AC-2", "Account management"),
        ("AC-3", "Access enforcement"),
        ("AC-4", "Information flow enforcement"),
        ("AC-6", "Least privilege"),
        ("AC-7", "Unsuccessful logon attempts"),
        ("AC-8", "System use notification"),
        ("AC-12", "Session termination"),
        ("AC-17", "Remote access"),
        ("AC-17(2)", "Remote access: confidentiality and integrity using encryption"),
        ("AU-3", "Content of audit records"),
        ("AU-4", "Audit log storage capacity"),
        ("AU-4(1)", "Audit log storage: transfer to alternate storage"),
        ("AU-8", "Time stamps"),
        ("AU-9(2)", "Protection of audit information: store on separate systems"),
        ("AU-12", "Audit record generation"),
        ("CM-2", "Baseline configuration"),
        ("CM-3", "Configuration change control"),
        ("CM-6", "Configuration settings"),
        ("CM-7", "Least functionality"),
        ("IA-2", "Identification and authentication (organizational users)"),
        ("IA-2(1)", "Multi-factor authentication to privileged accounts"),
        ("IA-5", "Authenticator management"),
        ("IA-5(1)", "Authenticator management: password-based authentication"),
        ("SC-5", "Denial-of-service protection"),
        ("SC-7", "Boundary protection"),
        ("SC-7(5)", "Boundary protection: deny by default, allow by exception"),
        ("SC-8", "Transmission confidentiality and integrity"),
        ("SC-10", "Network disconnect"),
        ("SC-13", "Cryptographic protection"),
        ("SC-45", "System time synchronization"),
        ("SC-45(1)", "Time synchronization with an authoritative time source"),
        ("SC-45(2)", "Secondary authoritative time source"),
        ("SI-2", "Flaw remediation"),
        ("SI-4", "System monitoring"),
    ],
}

STATUS_ORDER = ("fail", "accepted", "pass", "attested", "not_assessed", "not_covered", "not_applicable")
STATUS_LABEL = {"fail": "Failing", "accepted": "Risk accepted", "pass": "Passing",
                "attested": "Attested", "not_assessed": "Not assessed", "not_covered": "No rule yet",
                "not_applicable": "Not applicable"}
# Findings in these workflow states count against a control. A finding that
# was marked fixed stays here until an audit verifies it.
OPEN_STATES = ("open", "assigned", "fixed")


def _natural(control_id):
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", control_id)]


def framework_list():
    """[{"key", "title", "label"}] in the engine's order."""
    return engine.catalogue()["frameworks"]


def framework(key):
    for fw in framework_list():
        if fw["key"] == key:
            return fw
    return None


def controls_of(finding):
    """{framework key: [control ids]} for a finding, also for reports stored before v3."""
    mapping = finding.get("frameworks")
    if mapping is None:
        rule = engine.rule(finding.get("rule_id", ""))
        mapping = rule["frameworks"] if rule else {}
    return mapping


def assess(key, findings, device_count, register=None):
    """Control-by-control status of one framework.

    `findings` are the organization's current finding documents (any state);
    fixed and verified ones are ignored. `register` is the organization's
    control register ({(framework key, control id): entry}, see controls.py):
    a control recorded as not applicable leaves the score, and one no rule
    checks counts as attested once it is implemented with evidence and not
    overdue for review. Returns {"key", "title", "controls": [...], "counts":
    {status: n}, "score": share of assessed controls that pass or are attested}.
    """
    register = register or {}
    fw = framework(key)
    if fw is None:
        return None
    titles = dict(CONTROLS.get(key, []))
    rules_for = {}
    for rule in engine.rules():
        for cid in rule["frameworks"].get(key, []):
            rules_for.setdefault(cid, []).append(rule["id"])
    for cid in rules_for:
        titles.setdefault(cid, "")

    by_rule = {}
    for f in findings:
        if f.get("status") in OPEN_STATES + ("risk_accepted",):
            by_rule.setdefault(f["rule_id"], []).append(f)

    out = []
    for cid in sorted(titles, key=_natural):
        rule_ids = rules_for.get(cid, [])
        hits = [f for rid in rule_ids for f in by_rule.get(rid, [])]
        failing = [f for f in hits if f.get("status") in OPEN_STATES]
        entry = register.get((key, cid))
        impl = (entry or {}).get("implementation", "")
        if impl == "not_applicable":
            status = "not_applicable"
        elif not rule_ids:
            status = "attested" if controls.attested(entry) else "not_covered"
        elif device_count == 0:
            status = "not_assessed"
        elif failing:
            status = "fail"
        elif hits:
            status = "accepted"
        else:
            status = "pass"
        out.append({
            "id": cid, "title": titles[cid], "status": status, "rules": rule_ids,
            "findings": hits,
            "devices": sorted({f.get("hostname", "") for f in failing}),
            "register": controls.summary(entry),
        })

    counts = {s: sum(1 for c in out if c["status"] == s) for s in STATUS_ORDER}
    assessed = counts["pass"] + counts["fail"] + counts["accepted"] + counts["attested"]
    passing = counts["pass"] + counts["attested"]
    return {"key": key, "title": fw["title"], "label": fw["label"], "controls": out,
            "counts": counts,
            "score": round(100 * passing / assessed) if assessed else None,
            "covered": sum(1 for c in out if c["rules"]), "total": len(out),
            "owned": sum(1 for c in out if c["register"]["owner"]),
            "review_overdue": sum(1 for c in out if c["register"]["review_overdue"])}


def assess_all(findings, device_count, register=None):
    return [assess(fw["key"], findings, device_count, register) for fw in framework_list()]


def control(key, control_id):
    """(control id, title) when the control is listed for, or mapped in, a framework."""
    for cid, title in CONTROLS.get(key, []):
        if cid == control_id:
            return cid, title
    for rule in engine.rules():
        if control_id in rule["frameworks"].get(key, []):
            return control_id, ""
    return None
