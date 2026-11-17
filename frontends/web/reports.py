# -*- coding: utf-8 -*-
"""
Reports for people who do not read configurations:

  executive_pdf()   one or two pages for management: overall score, trend,
                    top risks in plain language, weakest devices
  evidence_pack()   a ZIP for an auditor: for each framework control its
                    status, the findings behind it and their dates, as PDF
                    and CSV, with a manifest of checksums
  send_scheduled()  emails the executive report weekly or monthly
"""
import csv
import hashlib
import io
import json
import logging
import zipfile

import engine
import frameworks
import inventory
import notify
import pdf
from storage import later, now, store

log = logging.getLogger("net-audit.reports")

ORANGE, INK, GREY, LIGHT = (250, 88, 45), (20, 20, 20), (110, 110, 110), (244, 244, 244)
SEV_COLOR = {"critical": (214, 58, 26), "high": (230, 126, 34), "medium": (214, 170, 0), "low": (60, 150, 190)}
STATUS_COLOR = {"fail": (214, 58, 26), "accepted": (214, 170, 0), "pass": (22, 160, 80),
                "not_assessed": GREY, "not_covered": GREY}
MARGIN = 50
WIDTH = pdf.PAGE_W - 2 * MARGIN
SCHEDULES = (("off", "Do not send"), ("weekly", "Every week"), ("monthly", "Every month"))

# What each rule means for someone outside the network team.
PLAIN = {
    "AUTH-001": ("Administrator password readable in the configuration",
                 "Anyone who sees a copy of the configuration can read the most powerful password on the device."),
    "AUTH-002": ("No central login system",
                 "People sign in with accounts stored on the device itself, so access cannot be granted, removed or reviewed in one place."),
    "AUTH-003": ("Unencrypted remote administration (Telnet)",
                 "Administrator passwords cross the network in clear text and can be captured by anyone on the path."),
    "AUTH-004": ("No secure remote administration",
                 "The device cannot be managed over an encrypted connection, or still allows a version that is broken."),
    "AUTH-005": ("Administrator sessions stay open",
                 "A session left unattended stays signed in, so the next person at that screen has full control."),
    "AUTH-006": ("No legal notice at login",
                 "Without a warning banner it is harder to act against someone who signs in without permission."),
    "AUTH-007": ("Administration reachable from anywhere",
                 "The login prompt answers any address instead of only the management network, which invites password guessing."),
    "AUTH-008": ("Unlimited password guessing",
                 "Nothing slows down or blocks repeated failed sign-ins."),
    "PASSWD-001": ("Passwords stored in clear text",
                   "Passwords can be read straight from the configuration or its backups."),
    "PASSWD-002": ("No password rules",
                   "The device accepts short, simple passwords for local accounts."),
    "PASSWD-003": ("Passwords protected with an outdated method",
                   "Stored passwords use a method that can be reversed or cracked quickly if the configuration leaks."),
    "ACL-001": ("A rule that lets everything through",
                "A filter or firewall rule allows any traffic from anywhere to anywhere, which defeats the filter."),
    "ACL-002": ("Management port without a filter",
                "The port used to administer the device accepts traffic from any source."),
    "SNMP-001": ("Default or guessable monitoring password",
                 "The monitoring password is a well-known default or easy to guess, exposing device details to anyone who tries it."),
    "SNMP-002": ("Monitoring access open to any address",
                 "Monitoring queries are answered for any source instead of only the monitoring servers."),
    "SNMP-003": ("Monitoring password that can change the device",
                 "The monitoring password also allows changes, so learning it means controlling the device."),
    "SNMP-004": ("Unencrypted monitoring protocol",
                 "Monitoring data and its password are sent without encryption."),
    "SVC-001": ("Unencrypted web administration",
                "The web administration page sends passwords in clear text."),
    "SVC-002": ("Device announces itself to neighbours",
                "The device broadcasts its model, software version and addresses to whatever is plugged in next to it."),
    "SVC-003": ("Obsolete network services switched on",
                "Old diagnostic services are running that serve no purpose and can be abused to flood other systems."),
    "SVC-004": ("Senders can choose their own route",
                "Traffic can be steered around the filters that are meant to inspect it."),
    "LOG-001": ("Logs are not sent to a central server",
                "If the device fails or is tampered with, the record of what happened is lost with it."),
    "LOG-002": ("No local log",
                "The device keeps no recent history to look at when the central log server is unreachable."),
    "LOG-003": ("Log entries without a date and time",
                "Events cannot be put in order or matched with other systems during an investigation."),
    "NTP-001": ("Clock not synchronised",
                "Log times cannot be trusted, and certificates and logins that depend on time may fail."),
    "NTP-002": ("Time source not verified",
                "The device accepts the time from any server claiming to be the time source."),
    "NTP-003": ("Only one time source",
                "If the single time server fails or drifts, the clock goes wrong unnoticed."),
    "INTF-001": ("Active ports nobody has documented",
                 "Ports are switched on with no address or description, so nobody can say what they are for."),
}


def verdict(score):
    return "Secure" if score >= 80 else ("At risk" if score >= 50 else "Critical")


def _plain(rule_id, fallback):
    return PLAIN.get(rule_id, (fallback, ""))


# ---------------------------------------------------------------------------
# Layout helper
# ---------------------------------------------------------------------------
class Flow:
    """A cursor that moves down the page and starts a new one when it runs out."""

    def __init__(self, doc, footer):
        self.doc, self.footer, self.y = doc, footer, MARGIN
        self._foot()

    def _foot(self):
        self.doc.line(MARGIN, pdf.PAGE_H - 42, pdf.PAGE_W - MARGIN, pdf.PAGE_H - 42)
        self.doc.text(MARGIN, pdf.PAGE_H - 28, self.footer, 8, color=GREY)
        self.doc.text(pdf.PAGE_W - MARGIN, pdf.PAGE_H - 28, f"Page {self.doc.page_count}", 8,
                      color=GREY, align="right")

    def need(self, height):
        if self.y + height > pdf.PAGE_H - 60:
            self.doc.add_page()
            self._foot()
            self.y = MARGIN + 10

    def heading(self, text):
        self.need(50)
        self.y += 16
        self.doc.text(MARGIN, self.y, text, 13, bold=True)
        self.doc.line(MARGIN, self.y + 6, pdf.PAGE_W - MARGIN, self.y + 6, color=ORANGE, width=1.2)
        self.y += 24

    def para(self, text, size=10, color=INK, indent=0, bold=False):
        lines = pdf.wrap(text, size, WIDTH - indent, bold)
        self.need(len(lines) * size * 1.4)
        self.y = self.doc.paragraph(MARGIN + indent, self.y, text, size, WIDTH - indent,
                                    bold=bold, color=color)

    def table(self, columns, rows, size=8.5):
        """columns: [(title, width, align)]; rows: lists of cell text or (text, colour)."""
        def header():
            self.doc.rect(MARGIN, self.y - 10, WIDTH, 16, fill=LIGHT)
            x = MARGIN
            for title, width, align in columns:
                self.doc.text(x + (width - 4 if align == "right" else 4), self.y, title, size,
                              bold=True, align=align)
                x += width
            self.y += 16

        # A short table stays on one page.
        self.need(40 if len(rows) > 12 else 26 + len(rows) * (size * 1.35 + 5))
        header()
        for row in rows:
            cells = [c if isinstance(c, tuple) else (c, INK) for c in row]
            wrapped = [pdf.wrap(str(text), size, width - 8) for (text, _), (_, width, _) in zip(cells, columns)]
            height = max(len(w) for w in wrapped) * size * 1.35 + 5
            if self.y + height > pdf.PAGE_H - 60:
                self.doc.add_page()
                self._foot()
                self.y = MARGIN + 10
                header()
            x = MARGIN
            for lines, (_, color), (_, width, align) in zip(wrapped, cells, columns):
                yy = self.y
                for line in lines:
                    self.doc.text(x + (width - 4 if align == "right" else 4), yy, line, size,
                                  color=color, align=align)
                    yy += size * 1.35
                x += width
            self.y += height
            self.doc.line(MARGIN, self.y - size, pdf.PAGE_W - MARGIN, self.y - size, color=(228, 228, 228), width=0.4)
        self.y += 6


def _footer(org):
    return f"{org.get('name', '')}  |  net-audit {engine.catalogue().get('version', '')}  |  generated {now().replace('T', ' ').replace('Z', ' UTC')}"


# ---------------------------------------------------------------------------
# Executive report
# ---------------------------------------------------------------------------
def executive_pdf(org):
    org_id = org["_id"]
    ins = inventory.insights(org_id)
    devs = inventory.devices(org_id)
    trend = inventory.fleet_trend(org_id)
    all_findings = inventory.findings(org_id)
    n = ins["devices"]

    doc = pdf.Document(title=f"Network compliance summary - {org.get('name', '')}")
    flow = Flow(doc, _footer(org))

    # Title band
    doc.rect(0, 0, pdf.PAGE_W, 96, fill=INK)
    doc.rect(0, 96, pdf.PAGE_W, 4, fill=ORANGE)
    doc.text(MARGIN, 44, "Network compliance summary", 22, bold=True, color=(255, 255, 255))
    doc.text(MARGIN, 68, f"{org.get('name', '')}  -  {now()[:10]}", 11, color=(210, 210, 210))
    flow.y = 138

    if n == 0:
        flow.para("No devices have been audited yet, so there is nothing to report. Run an audit or "
                  "connect a source of configuration backups, then generate this report again.", 11)
        return doc.render()

    # Score and trend
    score = ins["avg_score"]
    color = STATUS_COLOR["pass"] if score >= 80 else ((214, 150, 0) if score >= 50 else STATUS_COLOR["fail"])
    doc.text(MARGIN, flow.y + 30, str(score), 56, bold=True, color=color)
    num_w = pdf.text_width(str(score), 56, True)
    doc.text(MARGIN + num_w + 8, flow.y + 30, "/ 100", 16, color=GREY)
    doc.text(MARGIN, flow.y + 52, f"{verdict(score)}  -  average of {n} device{'' if n == 1 else 's'}",
             11, bold=True, color=color)

    box_x, box_y, box_w, box_h = pdf.PAGE_W - MARGIN - 250, flow.y - 14, 250, 76
    doc.rect(box_x, box_y, box_w, box_h, fill=LIGHT)
    doc.text(box_x + 8, box_y + 14, "Average score over time", 8, bold=True, color=GREY)
    if len(trend) >= 2:
        lo, hi = 0, 100
        pts = [(box_x + 10 + i * (box_w - 20) / (len(trend) - 1),
                box_y + box_h - 10 - (p["score"] - lo) / (hi - lo) * (box_h - 32)) for i, p in enumerate(trend)]
        doc.polyline(pts)
        doc.text(box_x + 8, box_y + box_h + 11, trend[0]["date"], 7.5, color=GREY)
        doc.text(box_x + box_w - 8, box_y + box_h + 11, trend[-1]["date"], 7.5, color=GREY, align="right")
    else:
        doc.text(box_x + 8, box_y + 44, "A trend appears after audits on two different days.", 8, color=GREY)
    flow.y += 84

    # Plain-language summary
    change = ""
    if len(trend) >= 2 and trend[-1]["score"] != trend[0]["score"]:
        delta = trend[-1]["score"] - trend[0]["score"]
        change = (f" Since {trend[0]['date']} the average score has "
                  f"{'risen' if delta > 0 else 'fallen'} by {abs(delta)} point{'' if abs(delta) == 1 else 's'}.")
    secure = sum(1 for d in devs if d.get("score", 0) >= 80)
    critical = sum(1 for d in devs if d.get("critical", 0) > 0)
    flow.para(
        f"We checked {n} network device{'' if n == 1 else 's'} against {len(engine.rules())} security rules. "
        f"{secure} {'is' if secure == 1 else 'are'} in good shape (a score of 80 or more). "
        f"{critical} {'has' if critical == 1 else 'have'} at least one critical problem: a weakness "
        f"an attacker could use directly.{change}", 10.5)
    flow.y += 8

    # Severity tiles
    tile_w = (WIDTH - 30) / 4
    for i, sev in enumerate(("critical", "high", "medium", "low")):
        x = MARGIN + i * (tile_w + 10)
        doc.rect(x, flow.y, tile_w, 46, fill=LIGHT)
        doc.rect(x, flow.y, 4, 46, fill=SEV_COLOR[sev])
        doc.text(x + 14, flow.y + 24, str(ins["sev"][sev]), 18, bold=True)
        doc.text(x + 14, flow.y + 38, f"{sev} findings", 8, color=GREY)
    flow.y += 60

    # Top risks
    flow.heading("Top risks")
    if not ins["top_risks"]:
        flow.para("No open findings. Every audited device passes every rule.")
    for i, risk in enumerate(ins["top_risks"], start=1):
        title, why = _plain(risk["id"], risk["title"])
        flow.need(48)
        flow.para(f"{i}. {title}", 10.5, bold=True)
        if why:
            flow.para(why, 9.5, indent=14)
        flow.para(f"Affects {risk['devices']} of {n} device{'' if n == 1 else 's'}. "
                  f"Severity: {risk['severity'].lower()}. Rule {risk['id']}.", 8.5, GREY, indent=14)
        flow.y += 5

    # Weakest devices
    flow.heading("Devices that need attention first")
    flow.table([("Device", 190, "left"), ("Type", 110, "left"), ("Site", 85, "left"),
                ("Score", 40, "right"), ("Critical", 35, "right"), ("High", 35, "right")],
               [[d["hostname"], engine.vendor_name(d.get("vendor")), d.get("site") or "-",
                 str(d.get("score", 0)), str(d.get("critical", 0)), str(d.get("high", 0))]
                for d in devs[:8]])

    # Frameworks
    flow.heading("Compliance frameworks")
    rows = []
    for fw in frameworks.assess_all(all_findings, n):
        c = fw["counts"]
        rows.append([fw["title"], f"{fw['score']}%" if fw["score"] is not None else "-",
                     str(c["pass"]), str(c["fail"]), str(c["accepted"]), str(c["not_covered"])])
    flow.table([("Framework", 185, "left"), ("Share passing", 70, "right"), ("Passing", 55, "right"),
                ("Failing", 55, "right"), ("Risk accepted", 70, "right"), ("No rule yet", 60, "right")], rows)
    flow.para("The share is the controls with no open finding, out of the controls net-audit can check. "
              "Controls with no rule yet are outside that share and need other evidence.", 8.5, GREY)

    # Workflow
    flow.heading("What is being done")
    st = ins["open_by_status"]
    for label, key in (("Open, not yet assigned to anyone", "open"), ("Assigned to someone", "assigned"),
                       ("Reported fixed, waiting for the next audit to confirm", "fixed"),
                       ("Risk formally accepted until a set date", "risk_accepted")):
        flow.para(f"{label}: {st.get(key, 0)}", 10)
    return doc.render()


# ---------------------------------------------------------------------------
# Auditor evidence pack
# ---------------------------------------------------------------------------
def _csv(header, rows):
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(header)
    writer.writerows(rows)
    return buf.getvalue().encode("utf-8-sig")       # BOM so Excel reads UTF-8


def _date(stamp):
    return (stamp or "")[:10]


def _evidence_pdf(org, assessed, devs):
    doc = pdf.Document(title=f"Compliance evidence - {org.get('name', '')}")
    flow = Flow(doc, _footer(org))
    doc.text(MARGIN, flow.y + 14, "Compliance evidence", 20, bold=True)
    doc.text(MARGIN, flow.y + 34, f"{org.get('name', '')}  -  as of {now()[:10]}  -  "
                                  f"{len(devs)} device{'' if len(devs) == 1 else 's'} in scope", 10, color=GREY)
    flow.y += 56
    flow.para("Each control below is checked by the listed net-audit rules against the latest audited "
              "configuration of every device in scope. Passing: no device has an open finding for those "
              "rules. Failing: at least one does. Risk accepted: the only findings are ones whose risk "
              "was accepted, with a reason and an expiry date. No rule yet: net-audit does not check "
              "this control, so it needs other evidence. Finding-level detail, with the dates each "
              "finding was first and last seen, is in findings.csv.", 9, GREY)

    for fw in assessed:
        c = fw["counts"]
        flow.heading(fw["title"])
        flow.para(f"{c['pass']} passing, {c['fail']} failing, {c['accepted']} risk accepted, "
                  f"{c['not_assessed']} not assessed, {c['not_covered']} with no rule yet.", 9.5)
        flow.y += 4
        rows = []
        for ctl in fw["controls"]:
            evidence = ""
            if ctl["status"] == "fail":
                names = ctl["devices"]
                evidence = f"{len(names)} device{'' if len(names) == 1 else 's'}: " + ", ".join(names[:6]) \
                           + (" ..." if len(names) > 6 else "")
            elif ctl["status"] == "accepted":
                until = sorted((f.get("risk") or {}).get("expires_at", "")[:10] for f in ctl["findings"])
                evidence = f"{len(ctl['findings'])} accepted, earliest expiry {until[0]}" if until else ""
            rows.append([ctl["id"], ctl["title"], ", ".join(ctl["rules"]) or "-",
                         (frameworks.STATUS_LABEL[ctl["status"]], STATUS_COLOR[ctl["status"]]), evidence])
        flow.table([("Control", 52, "left"), ("Title", 165, "left"), ("Checked by", 90, "left"),
                    ("Status", 62, "left"), ("Evidence", 126, "left")], rows, size=8)
    return doc.render()


def evidence_pack(org, framework_key=None):
    """Build the evidence ZIP for one framework, or for all of them."""
    org_id = org["_id"]
    devs = inventory.devices(org_id)
    all_findings = inventory.findings(org_id)
    keys = [framework_key] if framework_key else [fw["key"] for fw in frameworks.framework_list()]
    assessed = [frameworks.assess(k, all_findings, len(devs)) for k in keys]
    assessed = [a for a in assessed if a]

    control_rows, finding_rows = [], []
    for fw in assessed:
        for ctl in fw["controls"]:
            control_rows.append([fw["title"], ctl["id"], ctl["title"], frameworks.STATUS_LABEL[ctl["status"]],
                                 " ".join(ctl["rules"]), len(ctl["devices"]), len(ctl["findings"]),
                                 " ".join(ctl["devices"])])
    for f in all_findings:
        risk = f.get("risk") or {}
        mapping = frameworks.controls_of(f)
        finding_rows.append([
            f["hostname"], engine.vendor_name(f.get("vendor")), f["rule_id"], f.get("severity", ""),
            f.get("section", ""), f.get("description", ""), inventory.STATUS_LABEL.get(f["status"], f["status"]),
            _date(f.get("first_seen_at")), _date(f.get("last_seen_at")), _date(f.get("resolved_at")),
            f.get("assignee", ""), risk.get("reason", ""), _date(risk.get("expires_at")),
            risk.get("accepted_by", ""), (f.get("ticket") or {}).get("key", ""),
            "; ".join(f"{fw['label']} {', '.join(mapping.get(fw['key'], []))}"
                      for fw in assessed if mapping.get(fw["key"])),
        ])
    device_rows = [[d["hostname"], engine.vendor_name(d.get("vendor")), d.get("version", ""),
                    d.get("site", ""), d.get("owner", ""), d.get("score", ""), d.get("critical", 0),
                    d.get("high", 0), d.get("medium", 0), d.get("low", 0),
                    (d.get("last_audit_at") or "").replace("T", " ").replace("Z", " UTC"),
                    d.get("last_audit_id", "")] for d in devs]

    files = {
        "evidence.pdf": _evidence_pdf(org, assessed, devs),
        "controls.csv": _csv(["framework", "control", "title", "status", "checked_by_rules",
                              "failing_devices", "findings", "failing_device_names"], control_rows),
        "findings.csv": _csv(["device", "type", "rule", "severity", "where", "description", "status",
                              "first_seen", "last_seen", "resolved", "assignee", "risk_reason",
                              "risk_expires", "risk_accepted_by", "ticket", "controls"], finding_rows),
        "devices.csv": _csv(["device", "type", "version", "site", "owner", "score", "critical", "high",
                             "medium", "low", "last_audit", "last_audit_id"], device_rows),
        "README.txt": (
            "net-audit compliance evidence pack\r\n"
            "==================================\r\n\r\n"
            "evidence.pdf   status of every control, per framework\r\n"
            "controls.csv   the same, one row per control\r\n"
            "findings.csv   every finding with its state, dates, owner and risk acceptance\r\n"
            "devices.csv    the devices in scope and when each was last audited\r\n"
            "manifest.json  what produced this pack, and a SHA-256 checksum of each file\r\n\r\n"
            "Scope and limits\r\n"
            "----------------\r\n"
            "The results describe device configurations as last audited, not live device state.\r\n"
            "A control marked \"No rule yet\" is not checked by net-audit and needs other evidence.\r\n"
            "The rule-to-control mapping is published by the net-audit engine\r\n"
            "(net-audit --list-rules --format json) and should be reviewed against your own\r\n"
            "copy of each framework before it is relied on.\r\n").encode("utf-8"),
    }
    manifest = {
        "organization": org.get("name", ""), "generated_at": now(),
        "engine_version": engine.catalogue().get("version", ""),
        "frameworks": [{"key": a["key"], "title": a["title"], "counts": a["counts"]} for a in assessed],
        "devices": len(devs), "findings": len(all_findings),
        "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
    }
    files["manifest.json"] = json.dumps(manifest, indent=2).encode("utf-8")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Scheduled delivery
# ---------------------------------------------------------------------------
def next_delivery(schedule):
    if schedule == "weekly":
        return later(days=7)
    if schedule == "monthly":
        return later(days=30)
    return None


def send_scheduled(org, stamp):
    """Email the executive report when the organization's schedule says it is due."""
    settings = dict(org.get("settings") or {})
    plan = dict(settings.get("report") or {})
    due = plan.get("next_at")
    if plan.get("schedule") not in ("weekly", "monthly") or not due or due > stamp:
        return False
    try:
        notify.send_email(
            plan.get("emails") or [], f"[net-audit] Network compliance summary for {org.get('name', '')}",
            "The latest network compliance summary is attached.\n",
            [(f"net-audit-summary-{stamp[:10]}.pdf", executive_pdf(org), "application/pdf")])
        plan["last_status"] = f"Sent {stamp[:10]}"
    except notify.NotifyError as err:
        log.error("scheduled report for %s failed: %s", org["_id"], err)
        plan["last_status"] = f"Failed {stamp[:10]}: {err}"
    plan["next_at"] = next_delivery(plan["schedule"])
    settings["report"] = plan
    store().update("orgs", org["_id"], {"settings": settings})
    return True
