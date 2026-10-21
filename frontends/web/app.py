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
BINARY_NAME = "net-audit.exe" if sys.platform == "win32" else "net-audit"
# `make` puts the CLI in build/release/; NET_AUDIT_BIN overrides the location.
BINARY      = Path(os.environ.get("NET_AUDIT_BIN") or ROOT_DIR / "build" / "release" / BINARY_NAME)

# Uploads and audit history. Serverless functions may only write under /tmp,
# which is per-instance and temporary; NET_AUDIT_DATA_DIR overrides everywhere.
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

VENDORS    = {"auto", "cisco", "juniper", "fortinet"}
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


def save_history(aid, meta, report):
    with open(_history_path(aid), "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "report": report}, f, indent=2, ensure_ascii=False)


def load_history(aid):
    p = _history_path(aid)
    if not p or not p.exists():
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def list_history():
    entries = []
    for p in HISTORY_DIR.glob("*.json"):
        try:
            with open(p, encoding="utf-8") as f:
                d = json.load(f)
            m, r = d.get("meta", {}), d.get("report", {})
            entries.append({
                "id": p.stem, "timestamp": m.get("timestamp", ""),
                "files": m.get("files", []), "vendor": m.get("vendor", "auto"),
                "devices": r.get("devices_audited", 1 if "hostname" in r else 0),
                "avg_score": r.get("avg_score", r.get("score", "?")),
                "report_type": r.get("report_type", "device"),
                "error": r.get("error"),
            })
        except (OSError, ValueError):
            continue
    entries.sort(key=lambda e: e["timestamp"], reverse=True)   # ids are random
    return entries[:HISTORY_LIMIT]


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.context_processor
def inject_globals():
    return {"binary_exists": BINARY.exists(), "max_upload_bytes": MAX_UPLOAD_BYTES,
            "ephemeral_history": ON_VERCEL}


@app.route("/")
def index():
    return render_template("index.html", recent=list_history()[:8])


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
    ok = BINARY.exists()
    return jsonify({"ok": ok, "engine": ok, "ephemeral_history": ON_VERCEL}), (200 if ok else 503)


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
    p = _history_path(aid)
    if not p:
        return jsonify({"error": "Not found"}), 404
    if p.exists():
        p.unlink()
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


if __name__ == "__main__":
    print(f"Auditor: {BINARY} ({'found' if BINARY.exists() else 'MISSING - run make'})")
    print("Open:    http://localhost:5000")
    app.run(debug=False, host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
