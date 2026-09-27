# -*- coding: utf-8 -*-
import json, os, shutil, subprocess, sys, uuid
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, redirect, render_template, request, send_file, url_for

BASE_DIR    = Path(__file__).parent
BINARY_DIR  = BASE_DIR.parent
BINARY_NAME = "net-audit.exe" if sys.platform == "win32" else "net-audit"
BINARY      = BINARY_DIR / BINARY_NAME
UPLOADS_DIR = BASE_DIR / "uploads"
HISTORY_DIR = BASE_DIR / "history"
UPLOADS_DIR.mkdir(exist_ok=True)
HISTORY_DIR.mkdir(exist_ok=True)
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

def run_audit(file_paths, vendor="", severity="low"):
    cmd = [str(BINARY), "--format", "json", "--severity", severity, "--no-color"]
    if vendor and vendor != "auto": cmd += ["--vendor", vendor]
    cmd += file_paths
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd=str(BINARY_DIR))
        raw = r.stdout.strip()
        if not raw:
            # Strip [INF]/[WRN] log lines, keep only real errors
            err_lines = [l for l in r.stderr.splitlines()
                         if l.strip() and not l.startswith("[INF]") and not l.startswith("[WRN]")]
            msg = err_lines[-1].strip() if err_lines else "No output from auditor"
            # Make common errors friendlier
            if "no files were successfully audited" in msg.lower():
                msg = "No supported vendor config found. Upload a .cfg, .conf, or .txt file containing Cisco IOS, Juniper JunOS, or Fortinet FortiOS configuration syntax."
            elif "no parser matched" in msg.lower():
                msg = "Vendor auto-detection failed. Try selecting a vendor manually in the options."
            return {"error": msg}
        return json.loads(raw)
    except FileNotFoundError: return {"error": f"Binary not found: {BINARY}"}
    except subprocess.TimeoutExpired: return {"error": "Audit timed out"}
    except json.JSONDecodeError as e: return {"error": f"JSON error: {e}"}

def save_history(aid, meta, report):
    with open(HISTORY_DIR / f"{aid}.json", "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "report": report}, f, indent=2, ensure_ascii=False)

def load_history(aid):
    p = HISTORY_DIR / f"{aid}.json"
    if not p.exists(): return None
    with open(p, encoding="utf-8") as f: return json.load(f)

def list_history():
    entries = []
    for p in sorted(HISTORY_DIR.glob("*.json"), reverse=True):
        try:
            with open(p, encoding="utf-8") as f: d = json.load(f)
            m, r = d.get("meta", {}), d.get("report", {})
            entries.append({"id": p.stem, "timestamp": m.get("timestamp",""),
                "files": m.get("files",[]), "vendor": m.get("vendor","auto"),
                "devices": r.get("devices_audited", 1 if "hostname" in r else 0),
                "avg_score": r.get("avg_score", r.get("score","?")),
                "report_type": r.get("report_type","device")})
        except Exception: pass
    return entries[:50]

@app.route("/")
def index(): return render_template("index.html", binary_exists=BINARY.exists())

@app.route("/results/<aid>")
def results_page(aid):
    data = load_history(aid)
    if not data: return redirect(url_for("index"))
    return render_template("results.html", audit_id=aid, meta=data["meta"], report=data["report"])

@app.route("/history")
def history_page(): return render_template("history.html", entries=list_history())

@app.route("/api/audit", methods=["POST"])
def api_audit():
    if "files" not in request.files: return jsonify({"error": "No files"}), 400
    files    = request.files.getlist("files")
    vendor   = request.form.get("vendor", "auto")
    severity = request.form.get("severity", "low")
    aid  = str(uuid.uuid4())[:8]
    sdir = UPLOADS_DIR / aid
    sdir.mkdir()
    saved, names = [], []
    for f in files:
        if f.filename:
            dest = sdir / Path(f.filename).name
            f.save(str(dest)); saved.append(str(dest)); names.append(f.filename)
    if not saved:
        shutil.rmtree(sdir, ignore_errors=True)
        return jsonify({"error": "No valid files"}), 400
    report = run_audit(saved, vendor, severity)
    shutil.rmtree(sdir, ignore_errors=True)
    meta = {"audit_id": aid, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "files": names, "vendor": vendor, "severity": severity}
    save_history(aid, meta, report)
    if "error" in report: return jsonify({"error": report["error"], "audit_id": aid}), 500
    return jsonify({"audit_id": aid, "report": report})

@app.route("/api/history")
def api_history(): return jsonify(list_history())

@app.route("/api/result/<aid>")
def api_result(aid):
    data = load_history(aid)
    return jsonify(data) if data else (jsonify({"error": "Not found"}), 404)

@app.route("/api/download/<aid>/<fmt>")
def api_download(aid, fmt):
    data = load_history(aid)
    if not data: return jsonify({"error": "Not found"}), 404
    report, meta = data["report"], data["meta"]
    if fmt == "json":
        content, ext = json.dumps(report, indent=2, ensure_ascii=False), "json"
    elif fmt == "csv":
        q = lambda s: chr(34)+str(s or "").replace(chr(34),chr(34)*2)+chr(34)
        rows = ["device,vendor,rule_id,severity,section,description,remediation"]
        for dev in report.get("devices", [report] if "hostname" in report else []):
            hn, vn = dev.get("hostname","(unknown)"), dev.get("vendor","")
            for f in dev.get("findings",[]):
                rows.append(",".join([q(hn),q(vn),q(f.get("rule_id","")),q(f.get("severity","")),
                                      q(f.get("section","")),q(f.get("description","")),q(f.get("remediation",""))]))
        content, ext = "\r\n".join(rows), "csv"
    else:
        lines = [f"NET-AUDIT REPORT - {meta[chr(39)+chr(116)+chr(105)+chr(109)+chr(101)+chr(115)+chr(116)+chr(97)+chr(109)+chr(112)+chr(39)]}","="*70]
        for dev in report.get("devices",[report] if "hostname" in report else []):
            lines += [f"Device: {dev.get(chr(39)+chr(104)+chr(111)+chr(115)+chr(116)+chr(110)+chr(97)+chr(109)+chr(101)+chr(39),chr(63))}",
                      f"Score:  {dev.get(chr(39)+chr(115)+chr(99)+chr(111)+chr(114)+chr(101)+chr(39),chr(63))}/100","-"*40]
            for f in dev.get("findings",[]):
                lines.append(f"  [{f.get(chr(39)+chr(114)+chr(117)+chr(108)+chr(101)+chr(95)+chr(105)+chr(100)+chr(39),chr(63))}] {f.get(chr(39)+chr(100)+chr(101)+chr(115)+chr(99)+chr(114)+chr(105)+chr(112)+chr(116)+chr(105)+chr(111)+chr(110)+chr(39),chr(63))}")
        content, ext = "\n".join(lines), "txt"
    from io import BytesIO
    buf = BytesIO(content.encode("utf-8"))
    return send_file(buf,as_attachment=True,download_name=f"net-audit-{aid}.{ext}",mimetype="text/plain")

@app.route("/api/result/<aid>", methods=["DELETE"])
def api_delete(aid):
    p = HISTORY_DIR / f"{aid}.json"
    if p.exists(): p.unlink()
    return jsonify({"ok": True})

if __name__ == "__main__":
    print(f"Binary: {BINARY} ({chr(70)+chr(79)+chr(85)+chr(78)+chr(68) if BINARY.exists() else chr(77)+chr(73)+chr(83)+chr(83)+chr(73)+chr(78)+chr(71)})")
    print("Open: http://localhost:5000")
    app.run(debug=False, host="0.0.0.0", port=5000)
