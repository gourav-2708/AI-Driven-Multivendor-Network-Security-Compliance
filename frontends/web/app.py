# -*- coding: utf-8 -*-
"""
net-audit web dashboard (Flask).

Runs locally (`python frontends/web/app.py`) and on Vercel (see vercel.json and
the root index.py). The dashboard shells out to the compiled C auditor with
`--format json`; it never parses configurations itself.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, send_file, url_for
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Paths and environment
# ---------------------------------------------------------------------------
ON_VERCEL   = bool(os.environ.get("VERCEL"))
BASE_DIR    = Path(__file__).resolve().parent
ROOT_DIR    = BASE_DIR.parent.parent                      # repository root

# Local settings such as MONGODB_URI may live in a git-ignored .env at the root.
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT_DIR / ".env")
except ImportError:
    pass

BINARY_NAME = "net-audit.exe" if sys.platform == "win32" else "net-audit"
# `make` puts the CLI in build/release/; NET_AUDIT_BIN overrides the location.
BINARY      = Path(os.environ.get("NET_AUDIT_BIN") or ROOT_DIR / "build" / "release" / BINARY_NAME)

# Audit history goes to MongoDB when MONGODB_URI is set, otherwise to JSON files.
MONGODB_URI = os.environ.get("MONGODB_URI", "").strip()
MONGODB_DB  = os.environ.get("MONGODB_DB") or "net_audit"  # when the URI names no database
if MONGODB_URI:
    from pymongo import DESCENDING, MongoClient
    from pymongo.errors import PyMongoError

# Uploads and file-based history. Serverless functions may only write under /tmp,
# which is per-instance and temporary; NET_AUDIT_DATA_DIR overrides everywhere.
EPHEMERAL_HISTORY = ON_VERCEL and not MONGODB_URI
DATA_DIR    = Path(os.environ.get("NET_AUDIT_DATA_DIR")
                   or ("/tmp/net-audit" if ON_VERCEL else BASE_DIR))
UPLOADS_DIR = DATA_DIR / "uploads"
HISTORY_DIR = DATA_DIR / "history"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
HISTORY_DIR.mkdir(parents=True, exist_ok=True)

# A deployment bundle may drop the executable bit; run a copy from DATA_DIR then.
if BINARY.exists() and sys.platform != "win32" and not os.access(BINARY, os.X_OK):
    _copy = DATA_DIR / BINARY_NAME
    shutil.copy2(BINARY, _copy)
    _copy.chmod(0o755)
    BINARY = _copy

# Vercel rejects request bodies over 4.5 MB before they reach the app; stay
# below that so users get a readable error instead of a platform error page.
MAX_UPLOAD_BYTES = 4 * 1024 * 1024 if ON_VERCEL else 10 * 1024 * 1024
AUDIT_TIMEOUT_S  = 25          # below the 30 s maxDuration in vercel.json
HISTORY_LIMIT    = 50
INSIGHTS_LIMIT   = 500         # newest MongoDB audits behind the home page numbers
# A stalled connection attempt gets cut off and retried within the overall wait,
# so the wait must be several times the per-attempt limit.
MONGO_CONNECT_TIMEOUT_MS = 5000
MONGO_SELECT_TIMEOUT_MS  = 20000   # still inside the 30 s function limit

VENDORS   = {"auto", "cisco", "juniper", "fortinet"}
SEVERITIES = {"low", "medium", "high", "critical"}
ALLOWED_EXTENSIONS = {".cfg", ".conf", ".txt", ".log"}
AUDIT_ID   = re.compile(r"^[0-9a-f]{8}$")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------
def run_audit(file_paths, vendor="auto", severity="low"):
    cmd = [str(BINARY), "--format", "json", "--severity", severity, "--no-color", "--quiet"]
    if vendor != "auto":
        cmd += ["--vendor", vendor]
    cmd += ["--"] + file_paths                      # never treat a file name as an option
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=AUDIT_TIMEOUT_S, cwd=str(ROOT_DIR))
    except FileNotFoundError:
        return {"error": "The auditor engine is not available on this server."}
    except subprocess.TimeoutExpired:
        return {"error": "The audit took too long and was stopped."}

    raw = r.stdout.strip()
    if not raw:
        lines = [l.strip() for l in r.stderr.splitlines() if l.strip()]
        msg = lines[-1] if lines else "The auditor produced no output."
        if "no files were successfully audited" in msg.lower() or "could not detect the vendor" in msg.lower():
            msg = ("No supported configuration found. Upload Cisco IOS, Juniper JunOS or "
                   "Fortinet FortiOS configs (.cfg, .conf or .txt), or pick the vendor manually.")
        return {"error": msg}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": "The auditor returned an unreadable report."}


# ---------------------------------------------------------------------------
# History storage
# ---------------------------------------------------------------------------
def _history_path(aid):
    """Path for an audit id, or None when the id is malformed (no traversal)."""
    return HISTORY_DIR / f"{aid}.json" if AUDIT_ID.match(aid or "") else None


_audits = None


def _audits_collection():
    """The MongoDB collection; the client is created once and reused between requests."""
    global _audits
    if _audits is None:
        client = MongoClient(MONGODB_URI, appname="net-audit", maxPoolSize=5,
                             serverSelectionTimeoutMS=MONGO_SELECT_TIMEOUT_MS,
                             connectTimeoutMS=MONGO_CONNECT_TIMEOUT_MS)
        collection = client.get_default_database(default=MONGODB_DB)["audits"]
        collection.create_index([("created_at", DESCENDING)])
        _audits = collection
    return _audits


def save_history(aid, meta, report):
    if MONGODB_URI:
        # created_at orders audits written from different time zones; meta.timestamp
        # stays the local time shown to users.
        _audits_collection().insert_one({"_id": aid, "created_at": datetime.now(timezone.utc),
                                         "meta": meta, "report": report})
        return
    with open(_history_path(aid), "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "report": report}, f, indent=2, ensure_ascii=False)


def load_history(aid):
    p = _history_path(aid)
    if not p:
        return None
    if MONGODB_URI:
        return _audits_collection().find_one({"_id": aid}, {"_id": 0, "created_at": 0})
    if not p.exists():
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def delete_history(aid):
    """Remove an audit. Returns False when the id is malformed."""
    p = _history_path(aid)
    if not p:
        return False
    if MONGODB_URI:
        _audits_collection().delete_one({"_id": aid})
    elif p.exists():
        p.unlink()
    return True


def _stored_audits(limit, fields=None):
    """Yield (id, document) for saved audits; MongoDB returns only the newest `limit`."""
    if MONGODB_URI:
        cursor = _audits_collection().find({}, fields).sort("created_at", DESCENDING).limit(limit)
        for d in cursor:
            yield d["_id"], d
        return
    for p in HISTORY_DIR.glob("*.json"):
        try:
            with open(p, encoding="utf-8") as f:
                yield p.stem, json.load(f)
        except (OSError, ValueError):
            continue


# The report fields list_history reads; findings can be large and are not needed.
_SUMMARY_FIELDS = {"created_at": 1, "meta": 1, "report.devices_audited": 1, "report.hostname": 1,
                   "report.avg_score": 1, "report.score": 1, "report.report_type": 1, "report.error": 1}


def list_history():
    entries = []
    for aid, d in _stored_audits(HISTORY_LIMIT, _SUMMARY_FIELDS):
        m, r = d.get("meta", {}), d.get("report", {})
        entries.append({
            "id": aid, "timestamp": m.get("timestamp", ""),
            "files": m.get("files", []), "vendor": m.get("vendor", "auto"),
            "devices": r.get("devices_audited", 1 if "hostname" in r else 0),
            "avg_score": r.get("avg_score", r.get("score", "?")),
            "report_type": r.get("report_type", "device"),
            "error": r.get("error"),
        })
    if not MONGODB_URI:
        entries.sort(key=lambda e: e["timestamp"], reverse=True)   # ids are random
    return entries[:HISTORY_LIMIT]


# ---------------------------------------------------------------------------
# Rule catalogue and history insights (home page)
# ---------------------------------------------------------------------------
_rules_cache = []


def get_rules():
    """The rule catalogue, read from the auditor itself (`--list-rules`)."""
    if not _rules_cache:
        try:
            r = subprocess.run([str(BINARY), "--list-rules"], capture_output=True,
                               text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return []
        # Fixed-width columns: "%-11s %-9s %-15s %s" after a header row.
        for line in r.stdout.splitlines()[1:]:
            if len(line) > 38:
                _rules_cache.append({"id": line[:11].strip(), "severity": line[12:21].strip(),
                                     "category": line[22:37].strip(), "title": line[38:].strip()})
    return _rules_cache


def _report_devices(report):
    if report.get("report_type") == "aggregate":
        return report.get("devices", [])
    return [report] if "hostname" in report else []


def fleet_insights():
    """Fleet numbers from saved history, using the latest result for each device."""
    latest, audits, as_of, newest = {}, 0, "", None
    for _, d in _stored_audits(INSIGHTS_LIMIT):
        meta, devices = d.get("meta", {}), _report_devices(d.get("report", {}))
        if not devices:
            continue
        ts = meta.get("timestamp", "")
        order = d.get("created_at", ts)      # file-based history has only the timestamp
        audits += 1
        if newest is None or order > newest:
            newest, as_of = order, ts
        # Findings are only complete when the audit was not severity-filtered.
        complete = meta.get("severity", "low") == "low"
        for dev in devices:
            key = (dev.get("hostname"), dev.get("vendor"))
            if key not in latest or order > latest[key][0]:
                latest[key] = (order, dev, complete)

    rows = list(latest.values())
    n = len(rows)
    rules = get_rules()
    titles = {r["id"]: r for r in rules}
    sev = {s: sum(dev.get(s, 0) for _, dev, _ in rows) for s in ("critical", "high", "medium", "low")}

    full = [dev for _, dev, complete in rows if complete]
    hits = Counter(rid for dev in full for rid in {f.get("rule_id") for f in dev.get("findings", [])})
    n_rules = len(rules) or 17
    top = [{"id": rid, "pct": round(100 * k / len(full)),
            "title": titles.get(rid, {}).get("title", rid),
            "severity": titles.get(rid, {}).get("severity", "")}
           for rid, k in hits.most_common(6)]
    passed = [1 - len({f.get("rule_id") for f in dev.get("findings", [])}) / n_rules for dev in full]

    vendors = {}
    for _, dev, _ in rows:
        v = vendors.setdefault(dev.get("vendor", ""), [])
        v.append(dev.get("score", 0))

    def pct(k):
        return round(100 * k / n) if n else 0

    return {
        "audits": audits, "devices": n, "as_of": as_of,
        "avg_score": round(sum(dev.get("score", 0) for _, dev, _ in rows) / n) if n else 0,
        "secure_pct": pct(sum(1 for _, dev, _ in rows if dev.get("score", 0) >= 80)),
        "critical_pct": pct(sum(1 for _, dev, _ in rows if dev.get("critical", 0) > 0)),
        "rules_passed_pct": round(100 * sum(passed) / len(passed)) if passed else 0,
        "findings": sum(sev.values()), "sev": sev, "top_rules": top,
        "by_vendor": {k: {"devices": len(v), "avg": round(sum(v) / len(v))} for k, v in vendors.items()},
    }


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.context_processor
def inject_globals():
    return {"binary_exists": BINARY.exists(), "max_upload_bytes": MAX_UPLOAD_BYTES,
            "ephemeral_history": EPHEMERAL_HISTORY, "rules": get_rules()}


@app.route("/")
def index():
    return render_template("index.html", recent=list_history()[:8], ins=fleet_insights())


@app.route("/results/<aid>")
def results_page(aid):
    data = load_history(aid)
    if not data:
        return redirect(url_for("index"))
    return render_template("results.html", audit_id=aid, meta=data["meta"], report=data["report"])


@app.route("/history")
def history_page():
    return render_template("history.html", entries=list_history())


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
@app.route("/api/health")
def api_health():
    engine = BINARY.exists()
    database = True
    if MONGODB_URI:
        try:
            _audits_collection().database.command("ping")
        except PyMongoError as err:
            app.logger.error("MongoDB health check failed: %s", type(err).__name__)
            database = False
    ok = engine and database
    return jsonify({"ok": ok, "engine": engine, "database": database,
                    "storage": "mongodb" if MONGODB_URI else "files",
                    "ephemeral_history": EPHEMERAL_HISTORY}), (200 if ok else 503)


@app.route("/api/audit", methods=["POST"])
def api_audit():
    files    = [f for f in request.files.getlist("files") if f and f.filename]
    vendor   = request.form.get("vendor", "auto")
    severity = request.form.get("severity", "low")
    if vendor not in VENDORS or severity not in SEVERITIES:
        return jsonify({"error": "Invalid vendor or severity."}), 400
    if not files:
        return jsonify({"error": "No files were uploaded."}), 400

    aid  = uuid.uuid4().hex[:8]
    sdir = UPLOADS_DIR / aid
    sdir.mkdir(parents=True)
    saved, names = [], []
    try:
        for i, f in enumerate(files):
            ext = Path(f.filename).suffix.lower()
            if ext not in ALLOWED_EXTENSIONS:
                continue
            # Keep the user's name for display; store under a sanitised one.
            safe = secure_filename(f.filename) or f"upload{ext}"
            dest = sdir / f"{i:02d}_{safe}"
            f.save(str(dest))
            saved.append(str(dest))
            names.append(Path(f.filename.replace("\\", "/")).name)
        if not saved:
            return jsonify({"error": "Only .cfg, .conf, .txt and .log files are accepted."}), 400
        report = run_audit(saved, vendor, severity)
    finally:
        shutil.rmtree(sdir, ignore_errors=True)       # never keep uploaded configs

    meta = {"audit_id": aid,
            "timestamp": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S"),
            "files": names, "vendor": vendor, "severity": severity}
    save_history(aid, meta, report)
    if "error" in report:
        return jsonify({"error": report["error"], "audit_id": aid}), 422
    return jsonify({"audit_id": aid, "report": report})


@app.route("/api/history")
def api_history():
    return jsonify(list_history())


@app.route("/api/result/<aid>")
def api_result(aid):
    data = load_history(aid)
    return jsonify(data) if data else (jsonify({"error": "Not found"}), 404)


@app.route("/api/result/<aid>", methods=["DELETE"])
def api_delete(aid):
    if not delete_history(aid):
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True})


def _rows(report):
    return report.get("devices", [report] if "hostname" in report else [])


@app.route("/api/download/<aid>/<fmt>")
def api_download(aid, fmt):
    data = load_history(aid)
    if not data:
        return jsonify({"error": "Not found"}), 404
    report, meta = data["report"], data["meta"]

    if fmt == "json":
        content, mime = json.dumps(report, indent=2, ensure_ascii=False), "application/json"
    elif fmt == "csv":
        def q(s):
            return '"' + str(s or "").replace('"', '""') + '"'
        rows = ["device,vendor,rule_id,severity,section,description,remediation"]
        for dev in _rows(report):
            for f in dev.get("findings", []):
                rows.append(",".join(q(v) for v in (
                    dev.get("hostname", "(unknown)"), dev.get("vendor", ""), f.get("rule_id"),
                    f.get("severity"), f.get("section"), f.get("description"), f.get("remediation"))))
        content, mime = "\r\n".join(rows) + "\r\n", "text/csv"
    elif fmt == "txt":
        lines = [f"NET-AUDIT REPORT - {meta.get('timestamp', '')}", "=" * 70]
        for dev in _rows(report):
            lines += ["", f"Device: {dev.get('hostname', '?')} ({dev.get('vendor', '')})",
                      f"Score:  {dev.get('score', '?')}/100", "-" * 70]
            for f in dev.get("findings", []):
                lines.append(f"[{f.get('rule_id', '?')}] {f.get('severity', '')}: {f.get('description', '')}")
                if f.get("section"):
                    lines.append(f"    Where: {f['section']}")
                if f.get("remediation"):
                    lines.append(f"    Fix:   {f['remediation']}")
            if not dev.get("findings"):
                lines.append("No findings.")
        content, mime = "\n".join(lines) + "\n", "text/plain"
    else:
        return jsonify({"error": "Unknown format"}), 404

    return send_file(BytesIO(content.encode("utf-8")), as_attachment=True,
                     download_name=f"net-audit-{aid}.{fmt}", mimetype=mime)


@app.route("/api/export/<aid>")
def api_export(aid):
    return api_download(aid, "json")


@app.errorhandler(RequestEntityTooLarge)
def too_large(_):
    mb = MAX_UPLOAD_BYTES // (1024 * 1024)
    return jsonify({"error": f"Upload too large: the limit is {mb} MB per audit."}), 413


if MONGODB_URI:
    @app.errorhandler(PyMongoError)
    def database_error(err):
        # Log only the error type: messages can include cluster host names.
        app.logger.error("MongoDB error: %s", type(err).__name__)
        msg = "The audit history database is unavailable. Please try again shortly."
        return (jsonify({"error": msg}), 503) if request.path.startswith("/api/") else (msg, 503)


if __name__ == "__main__":
    print(f"Auditor: {BINARY} ({'found' if BINARY.exists() else 'MISSING - run make'})")
    print("Open:    http://localhost:5000")
    app.run(debug=False, host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
