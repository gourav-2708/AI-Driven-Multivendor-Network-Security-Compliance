# -*- coding: utf-8 -*-
"""
Continuous auditing: sources of configuration backups, and the scheduler that
audits them daily or weekly.

A source is one of
    git        a Git repository of configs, fetched over HTTPS (this is also
               how Oxidized's Git output and a RANCID repository are read)
    oxidized   an Oxidized server, read through its REST API
    directory  a folder on this server, such as a RANCID base directory or a
               mounted backup share (below NET_AUDIT_INTAKE_ROOT only)

run_source() collects the files into a scratch folder, audits them, feeds
the report through the inventory and deletes the files again: as with
uploads, configurations are never kept.
"""
import logging
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.parse
from pathlib import Path

import accounts
import config
import engine
import inventory
import notify
from storage import later, new_id, now, store

log = logging.getLogger("net-audit.intake")

TYPES = (("git", "Git repository"), ("oxidized", "Oxidized server"), ("directory", "Folder on this server"))
SCHEDULES = (("manual", "Only when run by hand"), ("daily", "Every day"), ("weekly", "Every week"))
_INTERVAL = {"daily": {"days": 1}, "weekly": {"days": 7}}
_GIT_URL = re.compile(r"^https://[^\s/@]+(/[^\s]*)?$")
_BRANCH = re.compile(r"^[\w][\w./-]{0,100}$")


class IntakeError(Exception):
    """A problem collecting configs, with a message safe to show to an administrator."""


# ---------------------------------------------------------------------------
# Source definitions
# ---------------------------------------------------------------------------
def validate(form):
    """Turn submitted form fields into a source document, or raise IntakeError."""
    kind = form.get("type", "")
    name = (form.get("name") or "").strip()
    location = (form.get("location") or "").strip()
    schedule = form.get("schedule", "manual")
    vendor = form.get("vendor", "auto")
    if kind not in dict(TYPES):
        raise IntakeError("Choose the kind of source.")
    if not name or len(name) > 60:
        raise IntakeError("Give the source a name of up to 60 characters.")
    if schedule not in dict(SCHEDULES):
        raise IntakeError("Choose a schedule.")
    if vendor != "auto" and vendor not in dict(engine.vendors()):
        raise IntakeError("Unknown vendor.")

    branch = (form.get("branch") or "").strip()
    subdir = (form.get("subdir") or "").strip().strip("/\\")
    if kind == "git":
        if not _GIT_URL.match(location):
            raise IntakeError("Enter the repository's https:// address, without a user name or password in it.")
        if branch and not _BRANCH.match(branch):
            raise IntakeError("That branch name is not valid.")
        _check_outbound(location)
    elif kind == "oxidized":
        _check_outbound(location)
    else:
        _directory(location)                       # raises when not allowed
    if ".." in Path(subdir).parts or Path(subdir).is_absolute():
        raise IntakeError("The sub-folder must be a relative path.")

    return {"type": kind, "name": name, "location": location, "branch": branch, "subdir": subdir,
            "username": (form.get("username") or "").strip()[:100],
            "secret": form.get("secret") or "", "vendor": vendor, "schedule": schedule,
            "next_run_at": _next_run(schedule), "last_run_at": None, "last_status": None,
            "last_message": "", "last_audit_id": None}


def _check_outbound(url):
    try:
        notify.check_url(url)
    except notify.NotifyError as err:
        raise IntakeError(str(err))


def _next_run(schedule):
    return later(**_INTERVAL[schedule]) if schedule in _INTERVAL else None


def _directory(location):
    """Resolve a directory source and make sure it is inside the intake root."""
    if not config.INTAKE_ROOT:
        raise IntakeError("Folder sources are switched off on this server (NET_AUDIT_INTAKE_ROOT is not set).")
    root = Path(config.INTAKE_ROOT).resolve()
    path = (root / location.lstrip("/\\")).resolve() if not Path(location).is_absolute() \
        else Path(location).resolve()
    if path != root and root not in path.parents:
        raise IntakeError(f"The folder must be inside {root}.")
    if not path.is_dir():
        raise IntakeError("That folder does not exist on the server.")
    return path


def public(source):
    """A source without its secret, for pages and the API."""
    out = {k: v for k, v in source.items() if k != "secret"}
    out["has_secret"] = bool(source.get("secret"))
    return out


# ---------------------------------------------------------------------------
# Collecting files
# ---------------------------------------------------------------------------
def _looks_like_config(path):
    """A text file with a config extension, or no extension (RANCID, Oxidized)."""
    name = path.name
    if name.startswith(".") or path.suffix.lower() not in config.ALLOWED_EXTENSIONS | {""}:
        return False
    try:
        if path.is_symlink() or not path.is_file():
            return False
        if not 0 < path.stat().st_size <= config.INTAKE_MAX_FILE_BYTES:
            return False
        with open(path, "rb") as f:
            return b"\0" not in f.read(2048)
    except OSError:
        return False


def _walk(base):
    """Config files below `base`, skipping hidden folders such as .git."""
    found = []
    for root, dirs, files in os.walk(base):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for name in sorted(files):
            p = Path(root) / name
            if _looks_like_config(p):
                found.append(p)
                if len(found) >= config.INTAKE_MAX_FILES:
                    return found
    return found


def _stage(paths, staging):
    """Copy files to short, flat names: the auditor limits path length."""
    staging.mkdir(parents=True, exist_ok=True)
    staged = []
    for i, src in enumerate(paths):
        safe = re.sub(r"[^\w.-]", "_", src.name)[:60] or "config"
        dest = staging / f"{i:04d}_{safe}"
        shutil.copyfile(src, dest)
        staged.append(str(dest))
    return staged


def _collect_git(source, work):
    if shutil.which("git") is None:
        raise IntakeError("Git is not installed on this server.")
    clone = work / "repo"
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1")
    if source.get("secret"):
        # Passed through the environment so the credential never appears in a
        # process listing.
        env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.extraHeader",
                   GIT_CONFIG_VALUE_0="Authorization: " +
                   notify.basic_auth(source.get("username") or "git", source["secret"]))
    cmd = ["git", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
           "-c", "core.hooksPath=/dev/null", "clone", "--quiet", "--depth", "1", "--no-tags",
           "--single-branch"]
    if source.get("branch"):
        cmd += ["--branch", source["branch"]]
    cmd += ["--", source["location"], str(clone)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=config.AUDIT_TIMEOUT_S, env=env)
    except subprocess.TimeoutExpired:
        raise IntakeError("Cloning the repository took too long.")
    if r.returncode != 0:
        lines = [l for l in r.stderr.splitlines() if l.strip()]
        raise IntakeError("Git could not clone the repository: " + (lines[-1][:200] if lines else "unknown error"))
    base = clone / source["subdir"] if source.get("subdir") else clone
    if not base.is_dir():
        raise IntakeError("The sub-folder does not exist in the repository.")
    return _walk(base)


def _collect_oxidized(source, work):
    base = source["location"].rstrip("/")
    headers = {}
    if source.get("secret"):
        headers["Authorization"] = notify.basic_auth(source.get("username") or "", source["secret"])
    try:
        nodes = notify.http(base + "/nodes.json", headers=headers)
    except notify.NotifyError as err:
        raise IntakeError(f"Oxidized: {err}")
    if not isinstance(nodes, list):
        raise IntakeError("Oxidized did not return a node list at /nodes.json.")
    out = work / "nodes"
    out.mkdir(parents=True, exist_ok=True)
    found = []
    for node in nodes[:config.INTAKE_MAX_FILES]:
        name = str(node.get("full_name") or node.get("name") or "")
        if not name:
            continue
        try:
            body = notify.http(f"{base}/node/fetch/{urllib.parse.quote(name)}", headers=headers, raw=True)
        except notify.NotifyError as err:
            log.warning("oxidized: %s skipped: %s", name, err)
            continue
        path = out / (re.sub(r"[^\w.-]", "_", name)[:80] + ".cfg")
        path.write_bytes(body[:config.INTAKE_MAX_FILE_BYTES])
        if _looks_like_config(path):
            found.append(path)
    return found


def collect(source, work):
    """Fetch a source's config files; returns their paths."""
    if source["type"] == "git":
        return _collect_git(source, work)
    if source["type"] == "oxidized":
        return _collect_oxidized(source, work)
    base = _directory(source["location"])
    if source.get("subdir"):
        base = base / source["subdir"]
    return _walk(base)


# ---------------------------------------------------------------------------
# Running a source
# ---------------------------------------------------------------------------
def save_audit(org, report, meta):
    """Store an audit and apply it to the inventory. Returns (audit id, summary)."""
    aid = new_id(8)
    meta = dict(meta, audit_id=aid,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    store().insert("audits", {"_id": aid, "org_id": org["_id"], "meta": meta, "report": report})
    summary = {}
    if "error" not in report:
        summary = inventory.ingest(org, aid, report, meta.get("source", "upload"),
                                   meta.get("by", "system"))
    return aid, summary


def run_source(org, source, actor="scheduler"):
    """Collect, audit and ingest one source. Returns the updated source document."""
    work = config.WORK_DIR / new_id(12)
    status, message, aid = "ok", "", None
    try:
        work.mkdir(parents=True)
        files = collect(source, work)
        if not files:
            raise IntakeError("No configuration files were found.")
        staged = _stage(files, work / "in")
        report = engine.audit(staged, source.get("vendor") or "auto")
        aid, summary = save_audit(org, report, {
            "files": [f"{source['name']} ({len(files)} files)"], "vendor": source.get("vendor") or "auto",
            "severity": "low", "source": "source:" + source["_id"], "by": actor})
        if "error" in report:
            status, message = "failed", report["error"]
        else:
            message = (f"{summary['devices']} device{'' if summary['devices'] == 1 else 's'} audited from "
                       f"{len(files)} files; {summary['new_findings']} new findings, "
                       f"{summary['verified']} verified fixed, {summary['alerts']} alerts.")
    except IntakeError as err:
        status, message = "failed", str(err)
    except Exception as err:                       # keep the scheduler alive
        log.exception("source %s failed", source.get("_id"))
        status, message = "failed", f"Unexpected error: {type(err).__name__}"
    finally:
        shutil.rmtree(work, ignore_errors=True)    # never keep collected configs

    accounts.record(org["_id"], {"email": actor}, "source.run", target=source["_id"],
                    detail={"status": status, "audit_id": aid})
    return store().update("sources", source["_id"], {
        "last_run_at": now(), "last_status": status, "last_message": message[:500],
        "last_audit_id": aid, "next_run_at": _next_run(source.get("schedule"))})


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------
_run_lock = threading.Lock()


def run_due():
    """Run everything that is due now: sources, risk expiry, scheduled reports."""
    if not _run_lock.acquire(blocking=False):
        return {"skipped": "already running"}
    try:
        import reports                           # imported late: reports imports this module's peers
        db = store()
        stamp = now()
        done = {"sources": 0, "risks_reopened": inventory.expire_risks(), "reports": 0}
        for source in db.find("sources"):
            due = source.get("next_run_at")
            if not due or due > stamp:
                continue
            org = db.get("orgs", source["org_id"])
            if org:
                run_source(org, source)
                done["sources"] += 1
        for org in db.find("orgs"):
            if reports.send_scheduled(org, stamp):
                done["reports"] += 1
        return done
    finally:
        _run_lock.release()


def _loop(interval):
    while True:
        time.sleep(interval)
        try:
            run_due()
        except Exception:
            log.exception("scheduler pass failed")


def start_scheduler(interval=60):
    """Start the background scheduler thread (once per process)."""
    thread = threading.Thread(target=_loop, args=(interval,), name="net-audit-scheduler", daemon=True)
    thread.start()
    return thread
