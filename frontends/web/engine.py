# -*- coding: utf-8 -*-
"""
The bridge to the C auditor. The dashboard never parses a configuration
itself: it runs the compiled CLI with `--format json` and reads the report.
The rule catalogue, its framework mapping and the vendor list also come from
the binary, so the dashboard cannot drift from the engine.
"""
import json
import subprocess

import config

_catalogue = None
_vendors = None

NO_CONFIG_MESSAGE = ("No supported configuration found. Upload a Cisco IOS, NX-OS or ASA, Juniper "
                     "JunOS, Fortinet FortiOS, Palo Alto PAN-OS or Arista EOS configuration "
                     "(.cfg, .conf, .txt or .xml), or pick the vendor manually.")


def available():
    return config.BINARY.exists()


def _run(args, timeout):
    return subprocess.run([str(config.BINARY)] + args, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout,
                          cwd=str(config.ROOT_DIR))


def catalogue():
    """{"version", "frameworks": [...], "rules": [...]} from `--list-rules --format json`."""
    global _catalogue
    if _catalogue is None:
        try:
            out = _run(["--list-rules", "--format", "json"], 10).stdout
            _catalogue = json.loads(out)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return {"version": "", "frameworks": [], "rules": []}
    return _catalogue


def rules():
    return catalogue()["rules"]


def rule(rule_id):
    for r in rules():
        if r["id"] == rule_id:
            return r
    return None


def vendors():
    """[(key, display name)] from `--list-vendors`."""
    global _vendors
    if _vendors is None:
        try:
            out = _run(["--list-vendors"], 10).stdout
        except (OSError, subprocess.TimeoutExpired):
            return []
        _vendors = [tuple(line.split(None, 1)) for line in out.splitlines() if len(line.split(None, 1)) == 2]
    return _vendors


def vendor_name(key):
    return dict(vendors()).get(key, (key or "").title())


def _audit_batch(paths, vendor):
    cmd = ["--format", "json", "--no-color", "--quiet", "--exit-zero"]
    if vendor != "auto":
        cmd += ["--vendor", vendor]
    cmd += ["--"] + paths                           # never treat a file name as an option
    try:
        r = _run(cmd, config.AUDIT_TIMEOUT_S)
    except FileNotFoundError:
        return {"error": "The auditor engine is not available on this server."}
    except subprocess.TimeoutExpired:
        return {"error": "The audit took too long and was stopped."}

    raw = r.stdout.strip()
    if not raw:
        lines = [l.strip() for l in r.stderr.splitlines() if l.strip()]
        msg = lines[-1] if lines else "The auditor produced no output."
        low = msg.lower()
        if "no files were successfully audited" in low or "could not detect the vendor" in low:
            msg = NO_CONFIG_MESSAGE
        return {"error": msg}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": "The auditor returned an unreadable report."}


def devices_of(report):
    """The device objects of a device or fleet report."""
    if report.get("report_type") == "aggregate":
        return report.get("devices", [])
    return [report] if "hostname" in report else []


def _fleet(devices):
    n = len(devices)
    return {
        "report_type": "aggregate", "devices": devices, "devices_audited": n,
        "avg_score": sum(d.get("score", 0) for d in devices) // n if n else 0,
        "total_critical": sum(d.get("critical", 0) for d in devices),
        "total_high": sum(d.get("high", 0) for d in devices),
        "total_medium": sum(d.get("medium", 0) for d in devices),
        "total_low": sum(d.get("low", 0) for d in devices),
    }


def audit(paths, vendor="auto"):
    """Audit files and return one report with every finding.

    The CLI takes a limited number of files per run, so large sets are audited
    in batches and merged into one fleet report. Files that cannot be audited
    are skipped; an error is returned only when nothing could be.
    """
    if len(paths) <= config.ENGINE_BATCH:
        return _audit_batch(paths, vendor)
    devices, last_error = [], None
    for i in range(0, len(paths), config.ENGINE_BATCH):
        part = _audit_batch(paths[i:i + config.ENGINE_BATCH], vendor)
        if "error" in part:
            last_error = part
            continue
        for d in devices_of(part):
            d = dict(d)
            d.pop("report_type", None)
            devices.append(d)
    if not devices:
        return last_error or {"error": NO_CONFIG_MESSAGE}
    return _fleet(devices)


def filtered(report, severity):
    """A copy of `report` listing only findings at or above `severity`.

    Scores and counts always describe the whole device, as in the CLI.
    """
    if severity not in config.SEVERITIES or severity == "low" or "error" in report:
        return report
    keep = set(config.SEVERITIES[:config.SEVERITIES.index(severity) + 1])

    def trim(device):
        device = dict(device)
        device["findings"] = [f for f in device.get("findings", [])
                              if f.get("severity", "").lower() in keep]
        return device

    if report.get("report_type") == "aggregate":
        out = dict(report)
        out["devices"] = [trim(d) for d in report.get("devices", [])]
        return out
    return trim(report)
