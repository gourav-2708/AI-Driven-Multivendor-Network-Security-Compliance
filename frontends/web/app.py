# -*- coding: utf-8 -*-
"""
net-audit web dashboard (Flask).

Runs locally (`python frontends/web/app.py`), in the Docker image, and on
Vercel (see vercel.json and the root index.py). This file holds the pages and
the JSON API; the work is done by the modules beside it:

    config      settings from the environment
    storage     documents in MongoDB or SQLite
    accounts    users, organizations, roles, sessions, API tokens, audit log
    engine      runs the C auditor and reads its rule catalogue
    inventory   devices, score history, finding workflow, drift alerts
    frameworks  CIS / PCI DSS / ISO 27001 / NIST 800-53 control status
    intake      Git / Oxidized / folder sources and the scheduler
    notify      email, Slack, Jira, ServiceNow
    reports     executive PDF and auditor evidence pack

Every route except sign-in, sign-up, password reset and /api/health needs a
signed-in user or an API token, and reads and writes only that user's
organization.
"""
import csv
import hmac
import io
import json
import os
import shutil
import sys
from datetime import timedelta
from io import BytesIO
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import (Flask, flash, g, jsonify, redirect, render_template, request,  # noqa: E402
                   send_file, session, url_for)
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge  # noqa: E402
from werkzeug.utils import secure_filename  # noqa: E402

import accounts  # noqa: E402
import config  # noqa: E402
import controls  # noqa: E402
import engine  # noqa: E402
import frameworks  # noqa: E402
import intake  # noqa: E402
import inventory  # noqa: E402
import notify  # noqa: E402
import reports  # noqa: E402
from accounts import AccountError, require  # noqa: E402
from storage import new_id, now, store  # noqa: E402

app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=config.MAX_UPLOAD_BYTES,
    SECRET_KEY=config.secret_key(),
    SESSION_COOKIE_NAME="net_audit_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=config.COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=config.SESSION_HOURS),
)

FINDING_PAGE_LIMIT = 400
LOG_PAGE_LIMIT = 300


# ---------------------------------------------------------------------------
# Request plumbing
# ---------------------------------------------------------------------------
@app.before_request
def _identity():
    accounts.load_identity()


@app.after_request
def _headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if not request.path.startswith("/static/"):
        resp.headers.setdefault("Cache-Control", "no-store")      # pages hold private data
    return resp


def _when(stamp):
    """'2026-11-10T09:30:00Z' -> '2026-11-10 09:30 UTC'."""
    return (stamp[:16].replace("T", " ") + " UTC") if stamp else ""


def _chart(points, width=600, height=140, pad=8):
    """SVG polyline points for a 0-100 score series."""
    if not points:
        return ""
    if len(points) == 1:
        points = points * 2
    step = (width - 2 * pad) / (len(points) - 1)
    return " ".join(f"{pad + i * step:.1f},{height - pad - p['score'] / 100 * (height - 2 * pad):.1f}"
                    for i, p in enumerate(points))


app.jinja_env.filters["when"] = _when
app.jinja_env.filters["day"] = lambda stamp: (stamp or "")[:10]
app.jinja_env.globals.update(chart=_chart, vendor_name=engine.vendor_name,
                             status_label=inventory.STATUS_LABEL,
                             control_label=frameworks.STATUS_LABEL)


@app.context_processor
def inject_globals():
    org = g.get("org")
    return {
        "binary_exists": engine.available(), "max_upload_bytes": config.MAX_UPLOAD_BYTES,
        "ephemeral_history": config.EPHEMERAL_STORAGE, "rules": engine.rules(),
        "offline": config.OFFLINE,
        "engine_version": engine.catalogue().get("version", ""),
        "engine_vendors": engine.vendors(), "fw_list": frameworks.framework_list(),
        "user": g.get("user"), "org": org, "role": g.get("role"),
        "can": lambda needed: accounts.can(g.get("role"), needed),
        "csrf_token": accounts.csrf_token,
        "open_alerts": store().count("alerts", {"org_id": org["_id"], "acknowledged": False}) if org else 0,
        "admin_unlocked": accounts.admin_unlocked() if org else False,
    }


def _safe_next(default):
    """A local path to go back to, never an address on another site."""
    target = request.values.get("next", "")
    if target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return default


def _org_doc(coll, doc_id):
    """A document of the current organization, or None."""
    doc = store().get(coll, doc_id) if doc_id else None
    return doc if doc and doc.get("org_id") == g.org["_id"] else None


def _emails(text):
    """Split a comma/space separated list of addresses, dropping invalid ones."""
    out = []
    for part in (text or "").replace(";", ",").replace("\n", ",").replace(" ", ",").split(","):
        part = accounts.normal_email(part)
        if part and accounts.EMAIL.match(part) and part not in out:
            out.append(part)
    return out[:20]


def _link(endpoint, **values):
    """An absolute link for emails: NET_AUDIT_BASE_URL when set, else this request's host."""
    path = url_for(endpoint, **values)
    return (config.BASE_URL or request.host_url.rstrip("/")) + path


# ---------------------------------------------------------------------------
# Sign-in, sign-up, password reset
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Privacy policy (public)
# ---------------------------------------------------------------------------
def _privacy_facts():
    """What the policy page says about this deployment, without revealing settings."""
    contact = config.PRIVACY_CONTACT
    if contact.startswith(("http://", "https://")):
        href = contact
    elif "@" in contact and " " not in contact:
        href = "mailto:" + contact
    else:
        href = ""
    uri = config.MONGODB_URI.lower()
    if config.MONGODB_URI:
        where = ("a MongoDB Atlas database" if ".mongodb.net" in uri else "a MongoDB database")
    else:
        where = "a database file on the server"
    host = "This service runs on Vercel" if config.ON_VERCEL else "This service runs on the operator's own server"
    return {
        "operator": config.OPERATOR, "contact": contact if href else "", "contact_href": href,
        "updated": config.PRIVACY_UPDATED, "offline": config.OFFLINE,
        "secure_cookie": config.COOKIE_SECURE, "lock_minutes": config.LOGIN_LOCK_MINUTES,
        "max_failures": config.LOGIN_MAX_FAILURES,
        "hosting": f"{host} and stores its information in {where}. These providers process "
                   "the information only to host and store it for the operator.",
    }


@app.route("/privacy")
def privacy_page():
    return render_template("privacy.html", policy=_privacy_facts())


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        accounts.check_csrf()
        try:
            user = accounts.authenticate(request.form.get("email"), request.form.get("password"))
        except AccountError as err:
            flash(str(err), "error")
            return render_template("login.html", email=request.form.get("email", "")), 401
        accounts.sign_in(user)
        accounts.record(user["org_id"], user, "login")
        return redirect(_safe_next(url_for("index")))
    return render_template("login.html", email="")


@app.route("/signup", methods=["GET", "POST"])
def signup_page():
    if g.user:
        return redirect(url_for("index"))
    allowed = accounts.signup_allowed()
    if request.method == "POST":
        accounts.check_csrf()
        try:
            _, user = accounts.create_organization(
                request.form.get("organization"), request.form.get("email"),
                request.form.get("password"), request.form.get("name"))
        except AccountError as err:
            flash(str(err), "error")
            return render_template("signup.html", allowed=allowed, form=request.form), 400
        accounts.sign_in(user)
        accounts.record(user["org_id"], user, "login")
        return redirect(url_for("index"))
    return render_template("signup.html", allowed=allowed, form={})


@app.route("/logout", methods=["POST"])
def logout():
    if g.user and not g.via_token:
        accounts.check_csrf()
        accounts.log("logout")
    accounts.sign_out()
    return redirect(url_for("login_page"))


@app.route("/forgot", methods=["GET", "POST"])
def forgot_page():
    if request.method == "POST":
        accounts.check_csrf()
        user, token = accounts.start_password_reset(request.form.get("email"))
        if user:
            notify.send_link(user, "Reset your net-audit password",
                             "Use this link to choose a new password. It works once, for one hour.",
                             _link("reset_page", token=token))
            accounts.record(user["org_id"], user, "password.reset_requested")
        # The same answer either way, so addresses cannot be probed.
        flash("If that address has an account, a reset link is on its way.", "ok")
        return redirect(url_for("login_page"))
    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_page(token):
    user = accounts.user_for_reset_token(token)
    if not user:
        flash("That link has expired or was already used. Ask for a new one.", "error")
        return redirect(url_for("forgot_page"))
    if request.method == "POST":
        accounts.check_csrf()
        try:
            if request.form.get("password") != request.form.get("confirm"):
                raise AccountError("The two passwords do not match.")
            accounts.set_password(user, request.form.get("password"))
        except AccountError as err:
            flash(str(err), "error")
            return render_template("reset.html", token=token, email=user["email"]), 400
        accounts.record(user["org_id"], user, "password.set")
        flash("Password saved. Sign in with it.", "ok")
        return redirect(url_for("login_page"))
    return render_template("reset.html", token=token, email=user["email"])


# ---------------------------------------------------------------------------
# Audits
# ---------------------------------------------------------------------------
def list_history(org_id, limit=config.HISTORY_LIMIT):
    entries = []
    for d in store().find("audits", {"org_id": org_id}, sort="created_at", desc=True, limit=limit):
        m, r = d.get("meta", {}), d.get("report", {})
        entries.append({
            "id": d["_id"], "timestamp": m.get("timestamp", ""),
            "files": m.get("files", []), "vendor": m.get("vendor", "auto"),
            "devices": r.get("devices_audited", 1 if "hostname" in r else 0),
            "avg_score": r.get("avg_score", r.get("score", "?")),
            "report_type": r.get("report_type", "device"),
            "error": r.get("error"), "by": m.get("by", ""), "source": m.get("source", "upload"),
        })
    return entries


def _load_audit(aid):
    """An audit of the current organization with its display-filtered report."""
    data = _org_doc("audits", aid)
    if not data:
        return None
    meta = data.get("meta", {})
    return {"meta": meta, "report": engine.filtered(data.get("report", {}), meta.get("severity", "low"))}


@app.route("/")
@require()
def index():
    return render_template("index.html", recent=list_history(g.org["_id"], 8),
                           ins=inventory.insights(g.org["_id"]))


@app.route("/results/<aid>")
@require()
def results_page(aid):
    data = _load_audit(aid)
    if not data:
        return redirect(url_for("index"))
    accounts.log("audit.view", aid)
    return render_template("results.html", audit_id=aid, meta=data["meta"], report=data["report"],
                           controls_of=frameworks.controls_of)


@app.route("/history")
@require()
def history_page():
    return render_template("history.html", entries=list_history(g.org["_id"]))


@app.route("/api/health")
def api_health():
    ok_engine = engine.available()
    database = True
    try:
        store().ping()
    except Exception as err:                 # report, never raise: this is the probe
        app.logger.error("database health check failed: %s", type(err).__name__)
        database = False
    ok = ok_engine and database
    return jsonify({"ok": ok, "engine": ok_engine, "database": database,
                    "storage": "mongodb" if config.MONGODB_URI else "sqlite",
                    "ephemeral_history": config.EPHEMERAL_STORAGE,
                    "version": engine.catalogue().get("version", "")}), (200 if ok else 503)


@app.route("/api/audit", methods=["POST"])
@require("auditor")
def api_audit():
    files = [f for f in request.files.getlist("files") if f and f.filename]
    vendor = request.form.get("vendor", "auto")
    severity = request.form.get("severity", "low")
    if (vendor != "auto" and vendor not in dict(engine.vendors())) or severity not in config.SEVERITIES:
        return jsonify({"error": "Invalid vendor or severity."}), 400
    if not files:
        return jsonify({"error": "No files were uploaded."}), 400

    sdir = config.UPLOADS_DIR / new_id(12)
    sdir.mkdir(parents=True)
    saved, names = [], []
    try:
        for i, f in enumerate(files):
            ext = Path(f.filename).suffix.lower()
            if ext not in config.ALLOWED_EXTENSIONS:
                continue
            # Keep the user's name for display; store under a sanitised one.
            safe = (secure_filename(f.filename) or f"upload{ext}")[-80:]
            dest = sdir / f"{i:04d}_{safe}"
            f.save(str(dest))
            saved.append(str(dest))
            names.append(Path(f.filename.replace("\\", "/")).name)
        if not saved:
            return jsonify({"error": "Only .cfg, .conf, .txt, .log and .xml files are accepted."}), 400
        # Always audit everything; `severity` only filters what is shown, so the
        # inventory and the finding workflow see the complete result.
        report = engine.audit(saved, vendor)
    finally:
        shutil.rmtree(sdir, ignore_errors=True)       # never keep uploaded configs

    aid, summary = intake.save_audit(g.org, report, {
        "files": names, "vendor": vendor, "severity": severity,
        "source": "api" if g.via_token else "upload", "by": g.user["email"]})
    accounts.log("audit.run", aid, files=len(names), devices=summary.get("devices", 0))
    if "error" in report:
        return jsonify({"error": report["error"], "audit_id": aid}), 422
    return jsonify({"audit_id": aid, "report": engine.filtered(report, severity), "inventory": summary})


@app.route("/api/history")
@require()
def api_history():
    return jsonify(list_history(g.org["_id"]))


@app.route("/api/result/<aid>")
@require()
def api_result(aid):
    data = _load_audit(aid)
    if not data:
        return jsonify({"error": "Not found"}), 404
    accounts.log("audit.view", aid)
    return jsonify(data)


@app.route("/api/result/<aid>", methods=["DELETE"])
@require("admin")
def api_delete(aid):
    if not _org_doc("audits", aid):
        return jsonify({"error": "Not found"}), 404
    store().delete("audits", aid)
    accounts.log("audit.delete", aid)
    return jsonify({"ok": True})


def _rows(report):
    return engine.devices_of(report)


def _controls_text(finding):
    mapping = frameworks.controls_of(finding)
    return "; ".join(f"{fw['label']} {', '.join(mapping[fw['key']])}"
                     for fw in frameworks.framework_list() if mapping.get(fw["key"]))


@app.route("/api/download/<aid>/<fmt>")
@require()
def api_download(aid, fmt):
    data = _load_audit(aid)
    if not data:
        return jsonify({"error": "Not found"}), 404
    report, meta = data["report"], data["meta"]

    if fmt == "json":
        content, mime = json.dumps(report, indent=2, ensure_ascii=False), "application/json"
    elif fmt == "csv":
        buf = io.StringIO(newline="")
        out = csv.writer(buf, lineterminator="\r\n", quoting=csv.QUOTE_ALL)
        out.writerow(["device", "vendor", "rule_id", "severity", "section", "description",
                      "remediation", "controls"])
        for dev in _rows(report):
            for f in dev.get("findings", []):
                out.writerow([dev.get("hostname", "(unknown)"), dev.get("vendor", ""), f.get("rule_id"),
                              f.get("severity"), f.get("section"), f.get("description"),
                              f.get("remediation"), _controls_text(f)])
        content, mime = buf.getvalue(), "text/csv"
    elif fmt == "txt":
        lines = [f"NET-AUDIT REPORT - {meta.get('timestamp', '')}", "=" * 70]
        for dev in _rows(report):
            lines += ["", f"Device: {dev.get('hostname', '?')} ({dev.get('vendor', '')})",
                      f"Score:  {dev.get('score', '?')}/100", "-" * 70]
            for f in dev.get("findings", []):
                lines.append(f"[{f.get('rule_id', '?')}] {f.get('severity', '')}: {f.get('description', '')}")
                if f.get("section"):
                    lines.append(f"    Where:    {f['section']}")
                if f.get("remediation"):
                    lines.append(f"    Fix:      {f['remediation']}")
                controls = _controls_text(f)
                if controls:
                    lines.append(f"    Controls: {controls}")
            if not dev.get("findings"):
                lines.append("No findings.")
        content, mime = "\n".join(lines) + "\n", "text/plain"
    else:
        return jsonify({"error": "Unknown format"}), 404

    accounts.log("audit.export", aid, format=fmt)
    return send_file(BytesIO(content.encode("utf-8")), as_attachment=True,
                     download_name=f"net-audit-{aid}.{fmt}", mimetype=mime)


@app.route("/api/export/<aid>")
@require()
def api_export(aid):
    return api_download(aid, "json")


# ---------------------------------------------------------------------------
# Device inventory
# ---------------------------------------------------------------------------
@app.route("/devices")
@require()
def devices_page():
    org_id = g.org["_id"]
    devs = inventory.devices(org_id)
    q = request.args.get("q", "").strip().lower()
    if q:
        devs = [d for d in devs if q in " ".join((d.get("hostname", ""), d.get("vendor", ""),
                                                   d.get("site", ""), d.get("owner", ""))).lower()]
    return render_template("devices.html", devices=devs, q=q, total=store().count("devices", {"org_id": org_id}),
                           trend=inventory.fleet_trend(org_id), ins=inventory.insights(org_id))


@app.route("/devices/<dev_id>", methods=["GET", "POST"])
@require()
def device_page(dev_id):
    dev = _org_doc("devices", dev_id)
    if not dev:
        flash("That device is not in the inventory.", "error")
        return redirect(url_for("devices_page"))
    if request.method == "POST":
        if not accounts.can(g.role, "auditor"):
            flash("That needs the auditor role.", "error")
            return redirect(url_for("device_page", dev_id=dev_id))
        changes = {k: (request.form.get(k) or "").strip()[:n]
                   for k, n in (("site", 80), ("owner", 120), ("notes", 1000))}
        store().update("devices", dev_id, changes)
        accounts.log("device.update", dev_id, site=changes["site"], owner=changes["owner"])
        flash("Device details saved.", "ok")
        return redirect(url_for("device_page", dev_id=dev_id))
    found = inventory.findings(g.org["_id"], device_id=dev_id)
    return render_template(
        "device.html", dev=dev, trend=inventory.device_trend(g.org["_id"], dev_id),
        findings=[f for f in found if f["status"] != "verified"],
        verified=sorted((f for f in found if f["status"] == "verified"),
                        key=lambda f: f.get("resolved_at") or "", reverse=True)[:20],
        members=accounts.org_users(g.org["_id"]), tickets=notify.ticket_systems(g.org))


@app.route("/devices/<dev_id>/delete", methods=["POST"])
@require("admin")
def device_delete(dev_id):
    if inventory.delete_device(g.org["_id"], dev_id):
        accounts.log("device.delete", dev_id)
        flash("Device removed from the inventory, with its findings and history.", "ok")
    return redirect(url_for("devices_page"))


@app.route("/api/devices")
@require()
def api_devices():
    return jsonify(inventory.devices(g.org["_id"]))


@app.route("/api/devices/<dev_id>")
@require()
def api_device(dev_id):
    dev = _org_doc("devices", dev_id)
    if not dev:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"device": dev, "trend": inventory.device_trend(g.org["_id"], dev_id),
                    "findings": inventory.findings(g.org["_id"], device_id=dev_id)})


@app.route("/api/trend")
@require()
def api_trend():
    return jsonify(inventory.fleet_trend(g.org["_id"]))


# ---------------------------------------------------------------------------
# Findings and their workflow
# ---------------------------------------------------------------------------
def _filter_findings(args):
    org_id = g.org["_id"]
    inventory.expire_risks(org_id)
    status = args.get("status", "active")
    found = inventory.findings(org_id)
    if status == "active":
        found = [f for f in found if f["status"] != "verified"]
    elif status in inventory.STATUSES:
        found = [f for f in found if f["status"] == status]
    severity = args.get("severity", "").upper()
    if severity in inventory.SEV_ORDER:
        found = [f for f in found if f.get("severity") == severity]
    if args.get("mine") and g.user:
        found = [f for f in found if f.get("assignee") == g.user["email"]]
    q = args.get("q", "").strip().lower()
    if q:
        found = [f for f in found if q in " ".join((
            f["_id"], f.get("hostname", ""), f.get("rule_id", ""), f.get("description", ""),
            f.get("section", ""), f.get("assignee", ""))).lower()]
    return found


@app.route("/findings")
@require()
def findings_page():
    found = _filter_findings(request.args)
    everything = inventory.findings(g.org["_id"])
    counts = {s: sum(1 for f in everything if f["status"] == s) for s in inventory.STATUSES}
    return render_template(
        "findings.html", findings=found[:FINDING_PAGE_LIMIT], shown=len(found), counts=counts,
        limit=FINDING_PAGE_LIMIT, args=request.args, members=accounts.org_users(g.org["_id"]),
        tickets=notify.ticket_systems(g.org))


def _act_on_finding(finding, form):
    """Apply a workflow action from a form or JSON body. Returns the updated finding."""
    action = form.get("action", "")
    if action == "ticket":
        if finding.get("ticket"):
            raise inventory.WorkflowError("This finding already has a ticket.")
        try:
            ticket = notify.create_ticket(g.org, finding, form.get("system", ""))
        except notify.NotifyError as err:
            raise inventory.WorkflowError(str(err))
        finding["ticket"] = ticket
        finding.setdefault("history", []).append(
            {"at": now(), "by": g.user["email"], "action": "ticket", "note": ticket["key"]})
        updated = store().replace("findings", finding)
    else:
        updated = inventory.act(g.org, finding, action, g.user["email"],
                                assignee=form.get("assignee"), reason=form.get("reason"),
                                expires=form.get("expires"), note=form.get("note"))
    accounts.log("finding." + action, finding["_id"], device=finding["hostname"], rule=finding["rule_id"])
    return updated


@app.route("/findings/<fid>", methods=["POST"])
@require("auditor")
def finding_action(fid):
    finding = _org_doc("findings", fid)
    if not finding:
        flash("That finding no longer exists.", "error")
    else:
        try:
            _act_on_finding(finding, request.form)
            flash("Finding updated.", "ok")
        except inventory.WorkflowError as err:
            flash(str(err), "error")
    return redirect(_safe_next(url_for("findings_page")))


@app.route("/api/findings")
@require()
def api_findings():
    return jsonify(_filter_findings(request.args))


@app.route("/api/findings/<fid>", methods=["POST"])
@require("auditor")
def api_finding_action(fid):
    finding = _org_doc("findings", fid)
    if not finding:
        return jsonify({"error": "Not found"}), 404
    try:
        return jsonify(_act_on_finding(finding, request.get_json(silent=True) or request.form))
    except inventory.WorkflowError as err:
        return jsonify({"error": str(err)}), 400


# ---------------------------------------------------------------------------
# Compliance frameworks and reports
# ---------------------------------------------------------------------------
@app.route("/compliance")
@require()
def compliance_page():
    org_id = g.org["_id"]
    inventory.expire_risks(org_id)
    n = store().count("devices", {"org_id": org_id})
    summary = frameworks.assess_all(inventory.findings(org_id), n, controls.register(org_id))
    selected = request.args.get("fw") or (summary[0]["key"] if summary else "")
    current = next((s for s in summary if s["key"] == selected), summary[0] if summary else None)
    return render_template("compliance.html", summary=summary, fw=current, devices=n)


@app.route("/api/compliance")
@require()
def api_compliance():
    org_id = g.org["_id"]
    n = store().count("devices", {"org_id": org_id})
    out = frameworks.assess_all(inventory.findings(org_id), n, controls.register(org_id))
    for fw in out:                                   # findings by id only: keep it small
        for ctl in fw["controls"]:
            ctl["findings"] = [f["_id"] for f in ctl["findings"]]
    return jsonify(out)


# ---------------------------------------------------------------------------
# Control register
# ---------------------------------------------------------------------------
def _control_view(key, control_id):
    """The assessed control (status, rules, findings, register summary), or None."""
    if not frameworks.framework(key) or not frameworks.control(key, control_id):
        return None, None
    org_id = g.org["_id"]
    n = store().count("devices", {"org_id": org_id})
    fw = frameworks.assess(key, inventory.findings(org_id), n, controls.register(org_id))
    ctl = next((c for c in fw["controls"] if c["id"] == control_id), None)
    return fw, ctl


@app.route("/controls/<key>/<control_id>", methods=["GET", "POST"])
@require()
def control_page(key, control_id):
    fw, ctl = _control_view(key, control_id)
    if not ctl:
        flash("That control is not in the framework.", "error")
        return redirect(url_for("compliance_page"))
    here = url_for("control_page", key=key, control_id=control_id)
    entry = controls.get(g.org["_id"], key, control_id)
    if request.method == "POST":
        if not accounts.can(g.role, "admin"):
            flash("Only an administrator can change the control register.", "error")
            return redirect(here)
        if not accounts.admin_unlocked():
            flash("Enter your password to unlock control management.", "error")
            return redirect(url_for("controls_unlock", next=here))
        action = request.form.get("action", "")
        members = {u["email"] for u in accounts.org_users(g.org["_id"]) if u.get("active")}
        try:
            if action == "update":
                changed = controls.update(entry, request.form, g.user["email"], members)
                message = "Control updated." if changed else "Nothing changed."
            elif action == "evidence_add":
                controls.add_evidence(entry, request.form, g.user["email"])
                message = "Evidence added."
            elif action == "evidence_remove":
                controls.remove_evidence(entry, request.form.get("evidence_id", ""), g.user["email"])
                message = "Evidence removed."
            elif action == "reviewed":
                controls.mark_reviewed(entry, request.form, g.user["email"])
                message = "Review recorded."
            else:
                raise controls.ControlError("Unknown action.")
        except controls.ControlError as err:
            flash(str(err), "error")
            return redirect(here)
        if action != "update" or changed:
            controls.save(entry)
            accounts.log("control." + action, f"{key}:{control_id}")
        flash(message, "ok")
        return redirect(here)
    return render_template("control.html", fw=fw, ctl=ctl, entry=entry,
                           members=[u for u in accounts.org_users(g.org["_id"]) if u.get("active")],
                           impl_label=controls.IMPLEMENTATION_LABEL, today=controls.today())


@app.route("/api/controls/<key>/<control_id>")
@require()
def api_control(key, control_id):
    fw, ctl = _control_view(key, control_id)
    if not ctl:
        return jsonify({"error": "Not found"}), 404
    entry = controls.get(g.org["_id"], key, control_id)
    out = dict(ctl, framework=key, findings=[f["_id"] for f in ctl["findings"]],
               evidence=entry.get("evidence") or [], history=entry.get("history") or [])
    return jsonify(out)


@app.route("/controls/unlock", methods=["GET", "POST"])
@require("admin")
def controls_unlock():
    target = _safe_next(url_for("compliance_page"))
    if g.via_token:
        return jsonify({"error": "API tokens cannot change the control register."}), 403
    if request.method == "POST":
        try:
            until = accounts.unlock_admin(request.form.get("password", ""))
        except AccountError as err:
            flash(str(err), "error")
            return render_template("unlock.html", next=target,
                                   config_minutes=config.ADMIN_UNLOCK_MINUTES), 400
        accounts.log("controls.unlock", None, until=until)
        flash(f"Control management unlocked for {config.ADMIN_UNLOCK_MINUTES} minutes.", "ok")
        return redirect(target)
    return render_template("unlock.html", next=target, config_minutes=config.ADMIN_UNLOCK_MINUTES)


@app.route("/controls/lock", methods=["POST"])
@require()
def controls_lock():
    accounts.lock_admin()
    flash("Control management locked.", "ok")
    return redirect(_safe_next(url_for("compliance_page")))


@app.route("/reports/executive.pdf")
@require()
def report_executive():
    accounts.log("report.export", "executive")
    return send_file(BytesIO(reports.executive_pdf(g.org)), mimetype="application/pdf",
                     as_attachment=request.args.get("download") == "1",
                     download_name=f"net-audit-summary-{now()[:10]}.pdf")


@app.route("/reports/evidence.zip")
@require()
def report_evidence():
    key = request.args.get("fw") or None
    if key and not frameworks.framework(key):
        return redirect(url_for("compliance_page"))
    accounts.log("report.export", "evidence", framework=key or "all")
    return send_file(BytesIO(reports.evidence_pack(g.org, key)), mimetype="application/zip",
                     as_attachment=True,
                     download_name=f"net-audit-evidence-{key or 'all'}-{now()[:10]}.zip")


# ---------------------------------------------------------------------------
# Drift alerts
# ---------------------------------------------------------------------------
@app.route("/alerts")
@require()
def alerts_page():
    alerts = store().find("alerts", {"org_id": g.org["_id"]}, sort="at", desc=True, limit=200)
    return render_template("alerts.html", alerts=alerts)


@app.route("/alerts/ack", methods=["POST"])
@require("auditor")
def alerts_ack():
    db = store()
    one = request.form.get("id")
    targets = [_org_doc("alerts", one)] if one else db.find("alerts", {"org_id": g.org["_id"], "acknowledged": False})
    for a in targets:
        if a:
            db.update("alerts", a["_id"], {"acknowledged": True, "acknowledged_by": g.user["email"]})
    accounts.log("alert.ack", one or "all")
    return redirect(url_for("alerts_page"))


@app.route("/api/alerts")
@require()
def api_alerts():
    return jsonify(store().find("alerts", {"org_id": g.org["_id"]}, sort="at", desc=True, limit=200))


# ---------------------------------------------------------------------------
# Sources and schedules
# ---------------------------------------------------------------------------
@app.route("/sources", methods=["GET", "POST"])
@require()
def sources_page():
    if request.method == "POST":
        if not accounts.can(g.role, "admin"):
            flash("That needs the admin role.", "error")
            return redirect(url_for("sources_page"))
        try:
            doc = intake.validate(request.form)
        except intake.IntakeError as err:
            flash(str(err), "error")
            return redirect(url_for("sources_page"))
        doc.update({"_id": new_id(12), "org_id": g.org["_id"], "created_by": g.user["email"]})
        store().insert("sources", doc)
        accounts.log("source.create", doc["_id"], name=doc["name"], type=doc["type"])
        flash("Source added. Run it once to check that it works.", "ok")
        return redirect(url_for("sources_page"))
    sources = sorted(store().find("sources", {"org_id": g.org["_id"]}), key=lambda s: s["name"].lower())
    return render_template("sources.html", sources=[intake.public(s) for s in sources],
                           types=intake.TYPES, schedules=intake.SCHEDULES,
                           intake_root=config.INTAKE_ROOT, scheduler=config.SCHEDULER_ENABLED)


def _run_source(source_id):
    source = _org_doc("sources", source_id)
    if not source:
        return None
    return intake.run_source(g.org, source, g.user["email"])


@app.route("/sources/<source_id>/run", methods=["POST"])
@require("auditor")
def source_run(source_id):
    result = _run_source(source_id)
    if result is None:
        flash("That source no longer exists.", "error")
    else:
        flash(result.get("last_message") or "Done.", "ok" if result.get("last_status") == "ok" else "error")
    return redirect(url_for("sources_page"))


@app.route("/sources/<source_id>/delete", methods=["POST"])
@require("admin")
def source_delete(source_id):
    if _org_doc("sources", source_id):
        store().delete("sources", source_id)
        accounts.log("source.delete", source_id)
        flash("Source removed. Devices it found stay in the inventory.", "ok")
    return redirect(url_for("sources_page"))


@app.route("/api/sources/<source_id>/run", methods=["POST"])
@require("auditor")
def api_source_run(source_id):
    result = _run_source(source_id)
    if result is None:
        return jsonify({"error": "Not found"}), 404
    return jsonify(intake.public(result)), (200 if result.get("last_status") == "ok" else 502)


@app.route("/api/cron")
def api_cron():
    """Run everything that is due. For deployments without a background thread."""
    sent = request.headers.get("Authorization", "")
    if not config.CRON_SECRET or not hmac.compare_digest(sent, "Bearer " + config.CRON_SECRET):
        return jsonify({"error": "Not authorized"}), 401
    return jsonify(intake.run_due())


# ---------------------------------------------------------------------------
# Settings: account, organization, users, tokens, integrations, audit log
# ---------------------------------------------------------------------------
def _settings():
    return dict(g.org.get("settings") or {})


def _save_settings(settings):
    g.org = store().update("orgs", g.org["_id"], {"settings": settings})


@app.route("/settings")
@require()
def settings_page():
    org_id = g.org["_id"]
    admin = accounts.can(g.role, "admin")
    settings = _settings()
    return render_template(
        "settings.html", admin=admin, settings=settings, once=session.pop("once", None),
        members=accounts.org_users(org_id) if admin else [], roles=accounts.ROLES,
        tokens=sorted(store().find("tokens", {"org_id": org_id}), key=lambda t: t["name"]) if admin else [],
        log=store().find("audit_log", {"org_id": org_id}, sort="at", desc=True, limit=LOG_PAGE_LIMIT) if admin else [],
        email_ready=notify.email_configured(), report_schedules=reports.SCHEDULES,
        base_url=config.BASE_URL or request.host_url.rstrip("/"))


@app.route("/settings/password", methods=["POST"])
@require()
def settings_password():
    if g.via_token:
        return jsonify({"error": "Tokens have no password."}), 400
    try:
        accounts.authenticate(g.user["email"], request.form.get("current"))
        if request.form.get("password") != request.form.get("confirm"):
            raise AccountError("The two new passwords do not match.")
        accounts.set_password(g.user, request.form.get("password"))
    except AccountError as err:
        flash(str(err), "error")
        return redirect(url_for("settings_page") + "#account")
    accounts.log("password.set")
    accounts.sign_in(store().get("users", g.user["_id"]))      # keep this session, drop the others
    flash("Password changed. Other sessions were signed out.", "ok")
    return redirect(url_for("settings_page") + "#account")


@app.route("/settings/org", methods=["POST"])
@require("admin")
def settings_org():
    name = (request.form.get("name") or "").strip()
    if not name or len(name) > 80:
        flash("Give the organization a name of up to 80 characters.", "error")
    else:
        g.org = store().update("orgs", g.org["_id"], {"name": name})
        accounts.log("org.rename", name=name)
        flash("Organization renamed.", "ok")
    return redirect(url_for("settings_page") + "#organization")


@app.route("/settings/users", methods=["POST"])
@require("admin")
def settings_invite():
    try:
        user, token = accounts.invite_user(g.org, request.form.get("email"), request.form.get("role"),
                                           request.form.get("name"))
    except AccountError as err:
        flash(str(err), "error")
        return redirect(url_for("settings_page") + "#users")
    link = _link("reset_page", token=token)
    sent = notify.send_link(user, f"You were invited to {g.org['name']} on net-audit",
                            f"{g.user['email']} invited you to {g.org['name']} on net-audit. "
                            "Use this link to choose your password. It works once, for three days.", link)
    accounts.log("user.invite", user["_id"], email=user["email"], role=user["role"])
    session["once"] = {"kind": "invite", "email": user["email"], "link": link, "sent": sent}
    return redirect(url_for("settings_page") + "#users")


@app.route("/settings/users/<uid>", methods=["POST"])
@require("admin")
def settings_user(uid):
    member = _org_doc("users", uid)
    back = redirect(url_for("settings_page") + "#users")
    if not member:
        return back
    action = request.form.get("action")
    last_admin = member["role"] == "admin" and member.get("active") and accounts.admin_count(g.org["_id"]) <= 1
    if action == "role":
        role = request.form.get("role")
        if role not in accounts.ROLES:
            flash("Unknown role.", "error")
        elif last_admin and role != "admin":
            flash("An organization needs at least one active admin.", "error")
        else:
            store().update("users", uid, {"role": role})
            accounts.log("user.role", uid, email=member["email"], role=role)
            flash(f"{member['email']} is now {role}.", "ok")
    elif action in ("deactivate", "activate"):
        if action == "deactivate" and last_admin:
            flash("An organization needs at least one active admin.", "error")
        else:
            active = action == "activate"
            store().update("users", uid, {
                "active": active, "session_version": int(member.get("session_version") or 0) + 1})
            accounts.log("user." + action, uid, email=member["email"])
            flash(f"{member['email']} {'can sign in again' if active else 'can no longer sign in'}.", "ok")
    elif action == "reset":
        user, token = accounts.start_password_reset(member["email"])
        if user:
            link = _link("reset_page", token=token)
            sent = notify.send_link(user, "Reset your net-audit password",
                                    "An administrator started a password reset for you. "
                                    "Use this link to choose a new password. It works once, for one hour.", link)
            accounts.log("user.reset", uid, email=member["email"])
            session["once"] = {"kind": "reset", "email": member["email"], "link": link, "sent": sent}
        else:
            flash("Reactivate the account before resetting its password.", "error")
    return back


@app.route("/settings/tokens", methods=["POST"])
@require("admin")
def settings_token_create():
    try:
        doc, secret = accounts.create_token(g.org, g.user, request.form.get("name"), request.form.get("role"))
    except AccountError as err:
        flash(str(err), "error")
        return redirect(url_for("settings_page") + "#tokens")
    accounts.log("token.create", doc["_id"], name=doc["name"], role=doc["role"])
    session["once"] = {"kind": "token", "name": doc["name"], "secret": secret}
    return redirect(url_for("settings_page") + "#tokens")


@app.route("/settings/tokens/<token_id>/delete", methods=["POST"])
@require("admin")
def settings_token_delete(token_id):
    token = _org_doc("tokens", token_id)
    if token:
        store().delete("tokens", token_id)
        accounts.log("token.revoke", token_id, name=token["name"])
        flash("Token revoked. Anything using it now gets HTTP 401.", "ok")
    return redirect(url_for("settings_page") + "#tokens")


@app.route("/settings/integrations", methods=["POST"])
@require("admin")
def settings_integrations():
    form = request.form
    settings = _settings()
    back = redirect(url_for("settings_page") + "#integrations")

    def secret(group, field):
        """A blank secret field means "keep what is saved"."""
        return form.get(f"{group}_{field}") or (settings.get(group) or {}).get(field, "")

    slack = (form.get("slack_webhook") or "").strip()
    if form.get("slack_clear"):
        slack = ""
    elif not slack:
        slack = settings.get("slack_webhook", "")
    jira = {"url": (form.get("jira_url") or "").strip(), "email": (form.get("jira_email") or "").strip(),
            "token": secret("jira", "token"), "project": (form.get("jira_project") or "").strip().upper(),
            "issue_type": (form.get("jira_issue_type") or "").strip() or "Task"}
    snow = {"url": (form.get("servicenow_url") or "").strip(), "user": (form.get("servicenow_user") or "").strip(),
            "password": secret("servicenow", "password"),
            "table": (form.get("servicenow_table") or "").strip() or "incident"}
    try:
        for url in (slack, jira["url"], snow["url"]):
            if url:
                notify.check_url(url)
    except notify.NotifyError as err:
        flash(str(err), "error")
        return back
    settings.update({"slack_webhook": slack, "alert_emails": _emails(form.get("alert_emails")),
                     "jira": jira if jira["url"] else {}, "servicenow": snow if snow["url"] else {}})
    _save_settings(settings)
    accounts.log("integrations.update", slack=bool(slack), jira=bool(jira["url"]),
                 servicenow=bool(snow["url"]), alert_emails=len(settings["alert_emails"]))
    flash("Integrations saved.", "ok")
    return back


@app.route("/settings/integrations/test", methods=["POST"])
@require("admin")
def settings_integrations_test():
    kind = request.form.get("kind")
    try:
        if kind == "slack":
            notify.slack(g.org, f"net-audit test message from {g.org['name']}.")
        elif kind == "email":
            notify.send_email(_settings().get("alert_emails") or [], "[net-audit] Test message",
                              f"This is a test message from net-audit for {g.org['name']}.\n")
        else:
            raise notify.NotifyError("Unknown test.")
        flash("Test message sent.", "ok")
    except notify.NotifyError as err:
        flash(f"Test failed: {err}", "error")
    return redirect(url_for("settings_page") + "#integrations")


@app.route("/settings/report", methods=["POST"])
@require("admin")
def settings_report():
    schedule = request.form.get("schedule", "off")
    if schedule not in dict(reports.SCHEDULES):
        schedule = "off"
    settings = _settings()
    previous = settings.get("report") or {}
    settings["report"] = {
        "schedule": schedule, "emails": _emails(request.form.get("emails")),
        "next_at": (previous.get("next_at") if previous.get("schedule") == schedule and previous.get("next_at")
                    else reports.next_delivery(schedule)),
        "last_status": previous.get("last_status", "")}
    _save_settings(settings)
    accounts.log("report.schedule", schedule=schedule, recipients=len(settings["report"]["emails"]))
    flash("Report delivery saved.", "ok")
    return redirect(url_for("settings_page") + "#reports")


@app.route("/settings/audit-log.csv")
@require("admin")
def settings_log_csv():
    buf = io.StringIO(newline="")
    out = csv.writer(buf, lineterminator="\r\n")
    out.writerow(["time_utc", "user", "action", "target", "detail", "ip"])
    for e in store().find("audit_log", {"org_id": g.org["_id"]}, sort="at", desc=True, limit=20000):
        out.writerow([e.get("at"), e.get("user"), e.get("action"), e.get("target") or "",
                      json.dumps(e.get("detail") or {}, ensure_ascii=False), e.get("ip", "")])
    accounts.log("auditlog.export")
    return send_file(BytesIO(buf.getvalue().encode("utf-8-sig")), mimetype="text/csv", as_attachment=True,
                     download_name=f"net-audit-audit-log-{now()[:10]}.csv")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
@app.errorhandler(RequestEntityTooLarge)
def too_large(_):
    mb = config.MAX_UPLOAD_BYTES // (1024 * 1024)
    return jsonify({"error": f"Upload too large: the limit is {mb} MB per audit."}), 413


@app.errorhandler(HTTPException)
def http_error(err):
    if accounts.wants_json():
        return jsonify({"error": err.description or err.name}), err.code
    return render_template("message.html", title=err.name, message=err.description), err.code


if config.MONGODB_URI:
    from pymongo.errors import PyMongoError

    @app.errorhandler(PyMongoError)
    def database_error(err):
        # Log only the error type: messages can include cluster host names.
        app.logger.error("MongoDB error: %s", type(err).__name__)
        msg = "The database is unavailable. Please try again shortly."
        return (jsonify({"error": msg}), 503) if accounts.wants_json() else (msg, 503)


if config.SCHEDULER_ENABLED:
    intake.start_scheduler()


if __name__ == "__main__":
    print(f"Auditor: {config.BINARY} ({'found' if engine.available() else 'MISSING - run make'})")
    print(f"Storage: {'MongoDB' if config.MONGODB_URI else config.SQLITE_PATH}")
    port = int(os.environ.get("PORT", "5000"))
    print(f"Open:    http://localhost:{port}")
    app.run(debug=False, host=os.environ.get("NET_AUDIT_HOST", "127.0.0.1"), port=port, threaded=True)
