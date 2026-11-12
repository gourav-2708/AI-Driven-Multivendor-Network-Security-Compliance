# -*- coding: utf-8 -*-
"""
What happens to an audit after the report: the device inventory, score
history, the life of each finding, and drift alerts.

Every audit is fed through ingest(). For each device in the report it

  * creates or updates the device in the organization's inventory,
  * records a point on the device's score history,
  * matches the report's findings against the ones already known for that
    device (new ones open, known ones stay as they are, missing ones are
    verified as fixed, ones marked fixed that are still present reopen),
  * raises a drift alert when the score dropped or a critical finding is new.

A finding is identified by device, rule and the section it was reported
against, with the line number left out, so adding a line above an ACL entry
does not turn an old finding into a new one.
"""
import hashlib
import re
import time
from collections import Counter

import engine
import notify
from storage import later, now, store

STATUSES = ("open", "assigned", "risk_accepted", "fixed", "verified")
STATUS_LABEL = {"open": "Open", "assigned": "Assigned", "risk_accepted": "Risk accepted",
                "fixed": "Fixed, awaiting audit", "verified": "Verified fixed"}
ACTIVE = ("open", "assigned", "risk_accepted", "fixed")      # not yet verified
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
MAX_RISK_DAYS = 366
_LINE = re.compile(r"\s*\(line \d+\)")


class WorkflowError(ValueError):
    """A message that is safe to show to the person using the form."""


def device_id(org_id, hostname, vendor):
    return hashlib.sha1(f"{org_id}|{hostname}|{vendor}".encode("utf-8")).hexdigest()[:16]


def finding_id(dev_id, rule_id, section):
    key = f"{dev_id}|{rule_id}|{_LINE.sub('', section or '')}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:20]


def _event(action, by, note=""):
    return {"at": now(), "by": by, "action": action, "note": note}


def _set_status(finding, status, by, action, note=""):
    finding["status"] = status
    finding.setdefault("history", []).append(_event(action, by, note))
    finding["history"] = finding["history"][-50:]


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------
def ingest(org, audit_id, report, source="upload", actor="system"):
    """Apply one report to the inventory. Returns counts for the caller to show."""
    summary = {"devices": 0, "new_findings": 0, "verified": 0, "reopened": 0, "alerts": 0}
    for dev in engine.devices_of(report):
        _ingest_device(org, audit_id, dev, source, actor, summary)
    return summary


def _ingest_device(org, audit_id, dev, source, actor, summary):
    db = store()
    org_id = org["_id"]
    hostname, vendor = dev.get("hostname") or "(unknown)", dev.get("vendor") or ""
    did = device_id(org_id, hostname, vendor)
    known = db.get("devices", did)
    stamp = now()
    counts = {s: int(dev.get(s, 0)) for s in ("critical", "high", "medium", "low")}

    record = dict(known or {"_id": did, "org_id": org_id, "hostname": hostname, "vendor": vendor,
                            "site": "", "owner": "", "notes": "", "first_seen_at": stamp})
    record.update(counts)
    record.update({"version": dev.get("version", ""), "prev_score": (known or {}).get("score"),
                   "score": int(dev.get("score", 0)), "last_audit_id": audit_id,
                   "last_audit_at": stamp, "source": source})

    # -- findings ---------------------------------------------------------
    existing = {f["_id"]: f for f in db.find("findings", {"org_id": org_id, "device_id": did})}
    seen, new_critical = set(), []
    for f in dev.get("findings", []):
        fid = finding_id(did, f.get("rule_id", ""), f.get("section", ""))
        if fid in seen:
            continue
        seen.add(fid)
        facts = {"severity": f.get("severity", ""), "section": f.get("section", ""),
                 "line": f.get("line", -1), "description": f.get("description", ""),
                 "remediation": f.get("remediation", ""), "frameworks": f.get("frameworks") or {},
                 "last_seen_at": stamp, "last_audit_id": audit_id}
        doc = existing.get(fid)
        if doc is None:
            doc = {"_id": fid, "org_id": org_id, "device_id": did, "hostname": hostname,
                   "vendor": vendor, "rule_id": f.get("rule_id", ""), "status": "open",
                   "assignee": "", "risk": None, "ticket": None, "first_seen_at": stamp,
                   "resolved_at": None, "history": [_event("found", "audit")]}
            doc.update(facts)
            db.insert("findings", doc)
            summary["new_findings"] += 1
            if known and doc["severity"] == "CRITICAL":
                new_critical.append(doc)
            continue
        doc.update(facts)
        if doc["status"] in ("fixed", "verified"):
            was = doc["status"]
            doc["resolved_at"] = None
            _set_status(doc, "assigned" if doc.get("assignee") else "open", "audit", "reopened",
                        "Marked fixed, but the audit still finds it." if was == "fixed"
                        else "Found again after it had been verified as fixed.")
            summary["reopened"] += 1
            if doc["severity"] == "CRITICAL" and was == "verified":
                new_critical.append(doc)
        elif doc["status"] == "risk_accepted" and _risk_expired(doc, stamp):
            _reopen_expired(doc)
        db.replace("findings", doc)

    for fid, doc in existing.items():
        if fid in seen or doc["status"] not in ACTIVE:
            continue
        doc["resolved_at"] = stamp
        _set_status(doc, "verified", "audit", "verified", "No longer found by the audit.")
        db.replace("findings", doc)
        summary["verified"] += 1

    record["findings_open"] = len(seen)
    db.replace("devices", record)
    # `seq` orders points recorded within the same second.
    db.insert("scores", {"org_id": org_id, "device_id": did, "at": stamp, "seq": time.time_ns(),
                         "audit_id": audit_id, "score": record["score"], **counts})
    summary["devices"] += 1

    # -- drift ------------------------------------------------------------
    if known is None:
        return
    alerts = []
    if known.get("score") is not None and record["score"] < known["score"]:
        alerts.append(("score_drop", f"{hostname}: score dropped from {known['score']} to "
                                     f"{record['score']}.", {"from": known["score"], "to": record["score"]}))
    if new_critical:
        rules = sorted({f["rule_id"] for f in new_critical})
        alerts.append(("new_critical", f"{hostname}: {len(new_critical)} new critical finding"
                                       f"{'' if len(new_critical) == 1 else 's'} ({', '.join(rules)}).",
                       {"rules": rules, "findings": [f["_id"] for f in new_critical]}))
    for kind, message, detail in alerts:
        alert = db.insert("alerts", {"org_id": org_id, "at": stamp, "kind": kind, "device_id": did,
                                     "hostname": hostname, "message": message, "detail": detail,
                                     "audit_id": audit_id, "acknowledged": False})
        summary["alerts"] += 1
        notify.alert(org, alert)


# ---------------------------------------------------------------------------
# Risk acceptance expiry
# ---------------------------------------------------------------------------
def _risk_expired(finding, stamp):
    expires = (finding.get("risk") or {}).get("expires_at") or ""
    return bool(expires) and expires <= stamp


def _reopen_expired(finding):
    finding["risk"] = None
    _set_status(finding, "assigned" if finding.get("assignee") else "open", "system",
                "risk_expired", "The risk acceptance expired.")


def expire_risks(org_id=None):
    """Reopen findings whose risk acceptance has run out. Returns how many."""
    db = store()
    where = {"status": "risk_accepted"}
    if org_id:
        where["org_id"] = org_id
    stamp, count = now(), 0
    for f in db.find("findings", where):
        if _risk_expired(f, stamp):
            _reopen_expired(f)
            db.replace("findings", f)
            count += 1
    return count


# ---------------------------------------------------------------------------
# Finding workflow (actions taken by people)
# ---------------------------------------------------------------------------
def act(org, finding, action, user_email, **params):
    """Apply a workflow action to a finding and return the updated document."""
    status = finding["status"]
    note = (params.get("note") or "").strip()[:500]

    if action == "assign":
        assignee = (params.get("assignee") or "").strip().lower()
        if assignee and not store().find_one("users", {"org_id": org["_id"], "email": assignee}):
            raise WorkflowError("That person is not a member of this organization.")
        if status == "verified":
            raise WorkflowError("This finding is already verified as fixed.")
        finding["assignee"] = assignee
        if status in ("open", "assigned"):
            status = "assigned" if assignee else "open"
        _set_status(finding, status, user_email, "assigned" if assignee else "unassigned",
                    assignee or note)
    elif action == "accept_risk":
        reason = (params.get("reason") or "").strip()
        expires = (params.get("expires") or "").strip()            # YYYY-MM-DD
        if status not in ("open", "assigned"):
            raise WorkflowError("Only an open finding can have its risk accepted.")
        if len(reason) < 10:
            raise WorkflowError("Write down why the risk is accepted (at least 10 characters).")
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", expires):
            raise WorkflowError("Choose the date the acceptance expires.")
        expires_at = expires + "T23:59:59Z"
        today = now()
        if expires_at <= today:
            raise WorkflowError("The expiry date must be in the future.")
        if expires_at > later(days=MAX_RISK_DAYS):
            raise WorkflowError("A risk can be accepted for at most one year at a time.")
        finding["risk"] = {"reason": reason[:1000], "expires_at": expires_at,
                           "accepted_by": user_email, "accepted_at": today}
        _set_status(finding, "risk_accepted", user_email, "risk_accepted",
                    f"Until {expires}: {reason[:200]}")
    elif action == "fix":
        if status not in ("open", "assigned", "risk_accepted"):
            raise WorkflowError("This finding is not open.")
        finding["risk"] = None
        _set_status(finding, "fixed", user_email, "marked_fixed",
                    note or "Waiting for the next audit of this device to verify.")
    elif action == "reopen":
        if status not in ("risk_accepted", "fixed"):
            raise WorkflowError("This finding is not accepted or marked fixed.")
        finding["risk"] = None
        _set_status(finding, "assigned" if finding.get("assignee") else "open", user_email,
                    "reopened", note)
    elif action == "comment":
        if not note:
            raise WorkflowError("Write a comment first.")
        _set_status(finding, status, user_email, "comment", note)
    else:
        raise WorkflowError("Unknown action.")
    return store().replace("findings", finding)


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------
def devices(org_id):
    return sorted(store().find("devices", {"org_id": org_id}),
                  key=lambda d: (d.get("score", 0), d.get("hostname", "")))


def findings(org_id, **where):
    where = {k: v for k, v in where.items() if v}
    where["org_id"] = org_id
    found = store().find("findings", where)
    found.sort(key=lambda f: (SEV_ORDER.get(f.get("severity"), 9), f.get("hostname", ""),
                              f.get("rule_id", "")))
    return found


def device_trend(org_id, dev_id, limit=60):
    """Score history of one device, oldest first."""
    points = store().find("scores", {"org_id": org_id, "device_id": dev_id},
                          sort="seq", desc=True, limit=limit)
    return list(reversed(points))


def fleet_trend(org_id, days=90):
    """Average device score per day, carrying each device's last score forward."""
    points = store().find("scores", {"org_id": org_id}, sort="seq")
    if not points:
        return []
    latest, out, day = {}, [], None
    for p in points:
        d = p["at"][:10]
        if day is not None and d != day:
            out.append({"date": day, "score": round(sum(latest.values()) / len(latest)),
                        "devices": len(latest)})
        day = d
        latest[p["device_id"]] = p["score"]
    out.append({"date": day, "score": round(sum(latest.values()) / len(latest)),
                "devices": len(latest)})
    return out[-days:]


def delete_device(org_id, dev_id):
    db = store()
    if not db.find_one("devices", {"_id": dev_id, "org_id": org_id}):
        return False
    db.delete_where("findings", {"org_id": org_id, "device_id": dev_id})
    db.delete_where("scores", {"org_id": org_id, "device_id": dev_id})
    db.delete_where("alerts", {"org_id": org_id, "device_id": dev_id})
    return db.delete("devices", dev_id)


def insights(org_id):
    """Fleet numbers for the home page and the executive report."""
    devs = devices(org_id)
    n = len(devs)
    current = [f for f in findings(org_id) if f["status"] != "verified"]
    rules = engine.rules()
    by_id = {r["id"]: r for r in rules}
    sev = {s: sum(d.get(s, 0) for d in devs) for s in ("critical", "high", "medium", "low")}

    affected = Counter()
    per_device = Counter()
    for f in current:
        per_device[(f["device_id"], f["rule_id"])] += 1
    for (_, rid) in per_device:
        affected[rid] += 1
    top = [{"id": rid, "devices": k, "pct": round(100 * k / n) if n else 0,
            "title": by_id.get(rid, {}).get("title", rid),
            "severity": by_id.get(rid, {}).get("severity", "")}
           for rid, k in sorted(affected.items(),
                                key=lambda x: (SEV_ORDER.get(by_id.get(x[0], {}).get("severity"), 9), -x[1]))]
    failing = Counter(did for (did, _) in per_device)
    n_rules = len(rules) or 1
    passed = [1 - failing.get(d["_id"], 0) / n_rules for d in devs]

    vendors = {}
    for d in devs:
        vendors.setdefault(d.get("vendor", ""), []).append(d.get("score", 0))

    def pct(k):
        return round(100 * k / n) if n else 0

    return {
        "audits": store().count("audits", {"org_id": org_id}), "devices": n,
        "as_of": max((d.get("last_audit_at", "") for d in devs), default="")[:16].replace("T", " "),
        "avg_score": round(sum(d.get("score", 0) for d in devs) / n) if n else 0,
        "secure_pct": pct(sum(1 for d in devs if d.get("score", 0) >= 80)),
        "critical_pct": pct(sum(1 for d in devs if d.get("critical", 0) > 0)),
        "rules_passed_pct": round(100 * sum(passed) / n) if n else 0,
        "findings": sum(sev.values()), "sev": sev,
        "top_rules": sorted(top, key=lambda t: -t["devices"])[:6], "top_risks": top[:5],
        "by_vendor": {k: {"devices": len(v), "avg": round(sum(v) / len(v))} for k, v in vendors.items()},
        "open_by_status": dict(Counter(f["status"] for f in current)),
    }
