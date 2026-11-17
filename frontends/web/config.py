# -*- coding: utf-8 -*-
"""
Settings for the net-audit web dashboard, read once from the environment.

Every setting has a default that works for a local run. `.env.example` at the
repository root documents each one.
"""
import os
import secrets
import shutil
import sys
from pathlib import Path

ON_VERCEL = bool(os.environ.get("VERCEL"))
BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent.parent                      # repository root

# Local settings may live in a git-ignored .env at the repository root.
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT_DIR / ".env")
except ImportError:
    pass


def _flag(name, default=False):
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(name, default):
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


# ---- Auditor ----------------------------------------------------------------
BINARY_NAME = "net-audit.exe" if sys.platform == "win32" else "net-audit"
# `make` puts the CLI in build/release/; NET_AUDIT_BIN overrides the location.
BINARY = Path(os.environ.get("NET_AUDIT_BIN") or ROOT_DIR / "build" / "release" / BINARY_NAME)

# ---- Storage ----------------------------------------------------------------
# MongoDB when MONGODB_URI is set, otherwise a SQLite file in the data directory.
MONGODB_URI = os.environ.get("MONGODB_URI", "").strip()
MONGODB_DB = os.environ.get("MONGODB_DB") or "net_audit"   # when the URI names no database

# Serverless functions may only write under /tmp, which is per-instance and
# temporary; NET_AUDIT_DATA_DIR overrides the location everywhere.
EPHEMERAL_STORAGE = ON_VERCEL and not MONGODB_URI
DATA_DIR = Path(os.environ.get("NET_AUDIT_DATA_DIR") or ("/tmp/net-audit" if ON_VERCEL else BASE_DIR))
UPLOADS_DIR = DATA_DIR / "uploads"
HISTORY_DIR = DATA_DIR / "history"          # JSON history written before v3; imported once
WORK_DIR = DATA_DIR / "work"                # scratch space for config intake
SQLITE_PATH = DATA_DIR / "net-audit.db"
for _d in (UPLOADS_DIR, HISTORY_DIR, WORK_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# A deployment bundle may drop the executable bit; run a copy from DATA_DIR then.
if BINARY.exists() and sys.platform != "win32" and not os.access(BINARY, os.X_OK):
    _copy = DATA_DIR / BINARY_NAME
    shutil.copy2(BINARY, _copy)
    _copy.chmod(0o755)
    BINARY = _copy

# ---- Limits -----------------------------------------------------------------
# Vercel rejects request bodies over 4.5 MB before they reach the app and stops
# a function after 30 s. A self-hosted install has neither limit, so both are
# settings there.
if ON_VERCEL:
    MAX_UPLOAD_BYTES = 4 * 1024 * 1024
    AUDIT_TIMEOUT_S = 25
else:
    MAX_UPLOAD_BYTES = _int("NET_AUDIT_MAX_UPLOAD_MB", 100) * 1024 * 1024
    AUDIT_TIMEOUT_S = _int("NET_AUDIT_TIMEOUT_S", 300)
ENGINE_BATCH = 100                 # files per auditor run (the CLI accepts 128)
HISTORY_LIMIT = 50
INSIGHTS_LIMIT = 500               # newest audits behind the home page numbers
MONGO_CONNECT_TIMEOUT_MS = 5000
MONGO_SELECT_TIMEOUT_MS = 20000    # still inside the 30 s function limit

ALLOWED_EXTENSIONS = {".cfg", ".conf", ".txt", ".log", ".xml"}
SEVERITIES = ("critical", "high", "medium", "low")

# ---- Accounts ---------------------------------------------------------------
# open:   anyone may create an account, which starts a new organization
# closed: only the first account can be created; everyone else is invited
SIGNUP_MODE = (os.environ.get("NET_AUDIT_SIGNUP") or "open").strip().lower()
COOKIE_SECURE = _flag("NET_AUDIT_COOKIE_SECURE", ON_VERCEL)
SESSION_HOURS = _int("NET_AUDIT_SESSION_HOURS", 12)
PASSWORD_MIN_LENGTH = 12
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_MINUTES = 15
RESET_TOKEN_MINUTES = 60
INVITE_TOKEN_HOURS = 72
# Air-gapped installs: do not make browsers fetch web fonts from the internet.
OFFLINE = _flag("NET_AUDIT_OFFLINE", False)
# Public address of this dashboard, used in links sent by email.
BASE_URL = (os.environ.get("NET_AUDIT_BASE_URL") or "").rstrip("/")


def secret_key():
    """The session-signing key: NET_AUDIT_SECRET_KEY, else one kept in the data directory."""
    key = os.environ.get("NET_AUDIT_SECRET_KEY", "").strip()
    if key:
        return key
    path = DATA_DIR / "secret.key"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    key = secrets.token_hex(32)
    path.write_text(key, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key


# ---- Email (optional) ---------------------------------------------------------
SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = _int("SMTP_PORT", 587)
SMTP_USER = os.environ.get("SMTP_USER", "").strip()
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "").strip() or SMTP_USER
SMTP_STARTTLS = _flag("SMTP_STARTTLS", True)

# ---- Intake and schedules -----------------------------------------------------
# The in-process scheduler runs due sources and reports. A serverless deployment
# has no background thread: call GET /api/cron with CRON_SECRET instead.
SCHEDULER_ENABLED = _flag("NET_AUDIT_SCHEDULER", not ON_VERCEL)
CRON_SECRET = os.environ.get("CRON_SECRET", "").strip()
# "Directory" sources may only read below this folder; unset disables them.
INTAKE_ROOT = os.environ.get("NET_AUDIT_INTAKE_ROOT", "").strip()
# Refuse outbound requests (Oxidized, webhooks, ticket systems) to private or
# loopback addresses. Turn on when strangers can sign up.
BLOCK_PRIVATE_URLS = _flag("NET_AUDIT_BLOCK_PRIVATE_URLS", False)
INTAKE_MAX_FILES = _int("NET_AUDIT_INTAKE_MAX_FILES", 2000)
INTAKE_MAX_FILE_BYTES = 5 * 1024 * 1024
HTTP_TIMEOUT_S = 15
