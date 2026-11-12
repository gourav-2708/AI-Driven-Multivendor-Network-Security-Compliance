# -*- coding: utf-8 -*-
"""
Outbound messages: email, Slack, and tickets in Jira or ServiceNow.

Each organization configures its own destinations (Settings > Integrations);
the SMTP server is a setting of the installation. Everything here is best
effort: a failed notification is logged and reported, never raised into the
audit that triggered it.
"""
import base64
import ipaddress
import json
import logging
import smtplib
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage

import config

log = logging.getLogger("net-audit.notify")


class NotifyError(Exception):
    """A delivery problem, with a message that is safe to show to an administrator."""


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def check_url(url):
    """Validate an outbound URL; raises NotifyError when it must not be called."""
    parts = urllib.parse.urlsplit(url or "")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise NotifyError("Enter a full http:// or https:// address.")
    if not config.BLOCK_PRIVATE_URLS:
        return url
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise NotifyError("That host name does not resolve.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise NotifyError("Addresses on private networks are not allowed on this server.")
    return url


def basic_auth(user, secret):
    raw = f"{user}:{secret}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def http(url, payload=None, headers=None, method=None, raw=False):
    """Send a request (JSON body when `payload` is given) and return the decoded reply."""
    check_url(url)
    data = None
    headers = dict(headers or {})
    headers.setdefault("User-Agent", "net-audit")
    headers.setdefault("Accept", "application/json")
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method=method or ("POST" if data else "GET"))
    try:
        with urllib.request.urlopen(req, timeout=config.HTTP_TIMEOUT_S) as resp:
            body = resp.read(20 * 1024 * 1024)
    except urllib.error.HTTPError as err:
        detail = err.read(300).decode("utf-8", "replace").strip()
        raise NotifyError(f"The server answered HTTP {err.code}. {detail}".strip())
    except (urllib.error.URLError, OSError, ValueError) as err:
        raise NotifyError(f"Could not reach the server: {getattr(err, 'reason', err)}")
    if raw:
        return body
    text = body.decode("utf-8", "replace")
    try:
        return json.loads(text) if text.strip() else {}
    except ValueError:
        return {"text": text}


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------
def email_configured():
    return bool(config.SMTP_HOST and config.SMTP_FROM)


def send_email(recipients, subject, body, attachments=()):
    """Send a plain-text email. `attachments` are (filename, bytes, mime type)."""
    recipients = [r for r in recipients if r]
    if not recipients:
        raise NotifyError("No recipients are set.")
    if not email_configured():
        raise NotifyError("Email is not set up on this server (SMTP_HOST and SMTP_FROM).")
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = config.SMTP_FROM, ", ".join(recipients), subject
    msg.set_content(body)
    for name, data, mime in attachments:
        maintype, _, subtype = mime.partition("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    try:
        if config.SMTP_PORT == 465:
            smtp = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=config.HTTP_TIMEOUT_S,
                                    context=ssl.create_default_context())
        else:
            smtp = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=config.HTTP_TIMEOUT_S)
        with smtp:
            if config.SMTP_PORT != 465 and config.SMTP_STARTTLS:
                smtp.starttls(context=ssl.create_default_context())
            if config.SMTP_USER:
                smtp.login(config.SMTP_USER, config.SMTP_PASSWORD)
            smtp.send_message(msg)
    except (smtplib.SMTPException, OSError) as err:
        raise NotifyError(f"The mail server refused the message: {err}")


def send_link(user, subject, intro, link):
    """Email a one-time link. Returns True when it was sent.

    Without SMTP the link is written to the server log instead, so the person
    running a self-hosted install can still finish the reset.
    """
    body = f"{intro}\n\n{link}\n\nIf you did not ask for this, you can ignore this message.\n"
    if email_configured():
        try:
            send_email([user["email"]], subject, body)
            return True
        except NotifyError as err:
            log.error("could not email %s: %s", user["email"], err)
    log.warning("no email sent; one-time link for %s: %s", user["email"], link)
    return False


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
def slack(org, text):
    url = (org.get("settings") or {}).get("slack_webhook")
    if not url:
        raise NotifyError("No Slack webhook is set.")
    http(url, {"text": text})


def alert(org, alert_doc):
    """Send a drift alert to the organization's Slack channel and alert emails."""
    settings = org.get("settings") or {}
    text = f"net-audit alert for {org.get('name', '')}: {alert_doc['message']}"
    link = f"{config.BASE_URL}/devices/{alert_doc['device_id']}" if config.BASE_URL else ""
    if settings.get("slack_webhook"):
        try:
            slack(org, text + (f"\n{link}" if link else ""))
        except NotifyError as err:
            log.error("slack alert failed: %s", err)
    if settings.get("alert_emails") and email_configured():
        try:
            send_email(settings["alert_emails"], f"[net-audit] {alert_doc['message']}",
                       text + (f"\n\n{link}" if link else "") + "\n")
        except NotifyError as err:
            log.error("alert email failed: %s", err)


# ---------------------------------------------------------------------------
# Tickets
# ---------------------------------------------------------------------------
def _ticket_text(finding):
    summary = f"[{finding['rule_id']}] {finding['hostname']}: {finding['description']}"[:250]
    lines = [
        f"Device: {finding['hostname']} ({finding.get('vendor', '')})",
        f"Rule: {finding['rule_id']} ({finding.get('severity', '')})",
        f"Where: {finding.get('section', '')}",
        "",
        finding.get("description", ""),
        "",
        "How to fix:",
        finding.get("remediation", ""),
    ]
    controls = [f"{key}: {', '.join(ids)}" for key, ids in (finding.get("frameworks") or {}).items() if ids]
    if controls:
        lines += ["", "Controls: " + "; ".join(controls)]
    if config.BASE_URL:
        lines += ["", f"{config.BASE_URL}/findings?q={finding['_id']}"]
    return summary, "\n".join(lines)


def _jira(cfg, finding):
    for key in ("url", "email", "token", "project"):
        if not cfg.get(key):
            raise NotifyError("Jira is not fully set up (address, email, API token and project key).")
    base = cfg["url"].rstrip("/")
    summary, description = _ticket_text(finding)
    reply = http(f"{base}/rest/api/2/issue", {"fields": {
        "project": {"key": cfg["project"]}, "summary": summary, "description": description,
        "issuetype": {"name": cfg.get("issue_type") or "Task"}}},
        headers={"Authorization": basic_auth(cfg["email"], cfg["token"])})
    key = reply.get("key")
    if not key:
        raise NotifyError("Jira did not return an issue key.")
    return {"system": "jira", "key": key, "url": f"{base}/browse/{key}"}


def _servicenow(cfg, finding):
    for key in ("url", "user", "password"):
        if not cfg.get(key):
            raise NotifyError("ServiceNow is not fully set up (instance address, user and password).")
    base = cfg["url"].rstrip("/")
    table = cfg.get("table") or "incident"
    summary, description = _ticket_text(finding)
    urgency = {"CRITICAL": "1", "HIGH": "2"}.get(finding.get("severity"), "3")
    reply = http(f"{base}/api/now/table/{urllib.parse.quote(table)}", {
        "short_description": summary, "description": description, "urgency": urgency,
        "category": "network"},
        headers={"Authorization": basic_auth(cfg["user"], cfg["password"])})
    result = reply.get("result") or {}
    if not result.get("sys_id"):
        raise NotifyError("ServiceNow did not return a record.")
    return {"system": "servicenow", "key": result.get("number") or result["sys_id"],
            "url": f"{base}/nav_to.do?uri={table}.do?sys_id={result['sys_id']}"}


def create_ticket(org, finding, system):
    """Open a ticket for a finding; returns {"system", "key", "url"}."""
    settings = org.get("settings") or {}
    if system == "jira":
        return _jira(settings.get("jira") or {}, finding)
    if system == "servicenow":
        return _servicenow(settings.get("servicenow") or {}, finding)
    raise NotifyError("Unknown ticket system.")


def ticket_systems(org):
    """Ticket systems that are set up for the organization."""
    settings = org.get("settings") or {}
    out = []
    if (settings.get("jira") or {}).get("url"):
        out.append(("jira", "Jira"))
    if (settings.get("servicenow") or {}).get("url"):
        out.append(("servicenow", "ServiceNow"))
    return out
