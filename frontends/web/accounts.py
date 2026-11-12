# -*- coding: utf-8 -*-
"""
Accounts: users, organizations, roles, sessions, API tokens and the audit log.

Every audit, device, finding and report belongs to exactly one organization,
and every user to exactly one organization. A request is authenticated either
by the session cookie (people) or by an API token (pipelines); either way the
handler sees `g.user`, `g.org` and `g.role`, and reads and writes only that
organization's documents.

Roles, lowest to highest:
    viewer   read-only
    auditor  run audits, work on findings, edit the device inventory
    admin    manage users, tokens, integrations and sources; delete audits
"""
import hashlib
import hmac
import re
import secrets
from functools import wraps

from flask import (abort, flash, g, jsonify, redirect, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import config
from storage import later, new_id, now, store

ROLES = ("viewer", "auditor", "admin")
_RANK = {role: i for i, role in enumerate(ROLES)}
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


class AccountError(ValueError):
    """A message that is safe to show to the person using the form."""


def _hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def normal_email(email):
    return (email or "").strip().lower()


def check_password_rules(password):
    if len(password or "") < config.PASSWORD_MIN_LENGTH:
        raise AccountError(f"Use a password of at least {config.PASSWORD_MIN_LENGTH} characters.")
    if len(password) > 256:
        raise AccountError("That password is too long.")


def can(role, needed):
    return _RANK.get(role, -1) >= _RANK[needed]


# ---------------------------------------------------------------------------
# Users and organizations
# ---------------------------------------------------------------------------
def find_user(email):
    return store().find_one("users", {"email": normal_email(email)})


def signup_allowed():
    return config.SIGNUP_MODE != "closed" or store().count("users") == 0


def create_organization(name, email, password, user_name=""):
    """Create an organization and its first administrator."""
    email = normal_email(email)
    name = (name or "").strip()
    if not signup_allowed():
        raise AccountError("Sign-up is closed on this server. Ask an administrator for an invitation.")
    if not name or len(name) > 80:
        raise AccountError("Give the organization a name of up to 80 characters.")
    if not EMAIL.match(email):
        raise AccountError("Enter a valid email address.")
    check_password_rules(password)
    if find_user(email):
        raise AccountError("An account with that email already exists.")

    db = store()
    first = db.count("orgs") == 0
    org = db.insert("orgs", {"_id": new_id(12), "name": name, "settings": {}})
    user = db.insert("users", {
        "_id": new_id(12), "org_id": org["_id"], "email": email,
        "name": (user_name or "").strip()[:80], "role": "admin", "active": True,
        "password_hash": generate_password_hash(password), "failed_logins": 0,
    })
    if first:
        # Audits saved before accounts existed go to the first organization.
        adopted = db.adopt_orphans("audits", org["_id"])
        if adopted:
            record(org["_id"], user, "audit.adopt", detail={"count": adopted})
    record(org["_id"], user, "org.create", target=org["_id"])
    return org, user


def invite_user(org, email, role, name=""):
    """Add a user without a password and return (user, one-time token)."""
    email = normal_email(email)
    if not EMAIL.match(email):
        raise AccountError("Enter a valid email address.")
    if role not in ROLES:
        raise AccountError("Unknown role.")
    if find_user(email):
        raise AccountError("An account with that email already exists.")
    token = secrets.token_urlsafe(32)
    user = store().insert("users", {
        "_id": new_id(12), "org_id": org["_id"], "email": email,
        "name": (name or "").strip()[:80], "role": role, "active": True,
        "password_hash": None, "failed_logins": 0,
        "reset_hash": _hash_token(token), "reset_expires_at": later(hours=config.INVITE_TOKEN_HOURS),
    })
    return user, token


def start_password_reset(email):
    """Return (user, token) for an active account, or (None, None)."""
    user = find_user(email)
    if not user or not user.get("active"):
        return None, None
    token = secrets.token_urlsafe(32)
    store().update("users", user["_id"], {
        "reset_hash": _hash_token(token),
        "reset_expires_at": later(minutes=config.RESET_TOKEN_MINUTES)})
    return user, token


def user_for_reset_token(token):
    if not token:
        return None
    user = store().find_one("users", {"reset_hash": _hash_token(token)})
    if not user or not user.get("active") or (user.get("reset_expires_at") or "") < now():
        return None
    return user


def set_password(user, password):
    check_password_rules(password)
    store().update("users", user["_id"], {
        "password_hash": generate_password_hash(password), "reset_hash": None,
        "reset_expires_at": None, "failed_logins": 0, "locked_until": None,
        # Changing the password signs out every other session.
        "session_version": int(user.get("session_version") or 0) + 1})


def authenticate(email, password):
    """Return the user for a correct email and password, else raise AccountError."""
    generic = AccountError("The email or password is not correct.")
    user = find_user(email)
    if not user or not user.get("active") or not user.get("password_hash"):
        # Spend the same time as a real check so accounts cannot be probed.
        check_password_hash(_DUMMY_HASH, password or "")
        raise generic
    if (user.get("locked_until") or "") > now():
        raise AccountError("Too many failed sign-ins. Try again in a few minutes.")
    if not check_password_hash(user["password_hash"], password or ""):
        failures = int(user.get("failed_logins") or 0) + 1
        changes = {"failed_logins": failures}
        if failures >= config.LOGIN_MAX_FAILURES:
            changes = {"failed_logins": 0, "locked_until": later(minutes=config.LOGIN_LOCK_MINUTES)}
        store().update("users", user["_id"], changes)
        record(user["org_id"], user, "login.failed")
        raise generic
    return store().update("users", user["_id"], {"failed_logins": 0, "locked_until": None,
                                                 "last_login_at": now()})


_DUMMY_HASH = generate_password_hash("net-audit placeholder password")


def org_users(org_id):
    return sorted(store().find("users", {"org_id": org_id}), key=lambda u: u["email"])


def admin_count(org_id):
    return sum(1 for u in org_users(org_id) if u.get("role") == "admin" and u.get("active"))


# ---------------------------------------------------------------------------
# Sessions and CSRF
# ---------------------------------------------------------------------------
def sign_in(user):
    session.clear()
    session.permanent = True
    session["uid"] = user["_id"]
    session["v"] = int(user.get("session_version") or 0)
    session["csrf"] = secrets.token_urlsafe(24)


def sign_out():
    session.clear()


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


def _csrf_ok():
    sent = request.headers.get("X-CSRF-Token") or request.form.get("_csrf") or ""
    return bool(sent) and hmac.compare_digest(sent, session.get("csrf", ""))


def check_csrf():
    """Abort a cookie-authenticated request that changes state without the token."""
    if request.method not in SAFE_METHODS and not _csrf_ok():
        abort(400, description="The form expired. Reload the page and try again.")


# ---------------------------------------------------------------------------
# API tokens
# ---------------------------------------------------------------------------
def create_token(org, user, name, role):
    """Create an API token and return (document, secret shown once)."""
    name = (name or "").strip()
    if not name or len(name) > 60:
        raise AccountError("Give the token a name of up to 60 characters.")
    if role not in ("viewer", "auditor"):
        raise AccountError("A token can be read-only or allowed to submit audits.")
    token_id = new_id(12)
    secret = secrets.token_urlsafe(32)
    doc = store().insert("tokens", {
        "_id": token_id, "org_id": org["_id"], "name": name, "role": role,
        "secret_hash": _hash_token(secret), "created_by": user["email"], "last_used_at": None})
    return doc, f"na_{token_id}_{secret}"


def _token_identity(header):
    """Resolve "Authorization: Bearer na_<id>_<secret>" to (token, org) or None."""
    if not header.startswith("Bearer na_"):
        return None
    parts = header[len("Bearer na_"):].split("_", 1)
    if len(parts) != 2:
        return None
    token = store().get("tokens", parts[0])
    if not token or not hmac.compare_digest(token.get("secret_hash", ""), _hash_token(parts[1])):
        return None
    org = store().get("orgs", token["org_id"])
    if not org:
        return None
    if (token.get("last_used_at") or "")[:13] != now()[:13]:       # at most hourly
        store().update("tokens", token["_id"], {"last_used_at": now()})
    return token, org


# ---------------------------------------------------------------------------
# Request identity
# ---------------------------------------------------------------------------
def load_identity():
    """Set g.user / g.org / g.role from the API token or the session cookie."""
    g.user = g.org = g.role = None
    g.via_token = False
    header = request.headers.get("Authorization", "")
    if header:
        found = _token_identity(header)
        if found:
            token, org = found
            g.org, g.role, g.via_token = org, token["role"], True
            g.user = {"_id": "token:" + token["_id"], "email": "token:" + token["name"],
                      "name": token["name"], "role": token["role"], "org_id": org["_id"]}
        return
    uid = session.get("uid")
    if not uid:
        return
    user = store().get("users", uid)
    if (not user or not user.get("active")
            or int(user.get("session_version") or 0) != session.get("v")):
        session.clear()
        return
    org = store().get("orgs", user["org_id"])
    if org:
        g.user, g.org, g.role = user, org, user["role"]


def wants_json():
    return request.path.startswith("/api/")


def require(role="viewer"):
    """Route decorator: a signed-in user (or token) with at least `role`."""
    def decorate(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.get("user") is None:
                if wants_json():
                    return jsonify({"error": "Sign in or send an API token."}), 401
                return redirect(url_for("login_page", next=request.full_path.rstrip("?")))
            if not g.via_token:
                check_csrf()
            if not can(g.role, role):
                if wants_json():
                    return jsonify({"error": f"This needs the {role} role."}), 403
                flash(f"That needs the {role} role.", "error")
                return redirect(url_for("index"))
            return view(*args, **kwargs)
        return wrapped
    return decorate


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
def record(org_id, user, action, target=None, detail=None):
    """Append one line to the organization's audit log."""
    try:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    except RuntimeError:                    # outside a request (scheduler)
        ip = ""
    store().insert("audit_log", {
        "org_id": org_id, "at": now(), "action": action,
        "user": (user or {}).get("email", "system"), "target": target,
        "detail": detail or {}, "ip": ip})


def log(action, target=None, **detail):
    """Audit-log an action by the current request's user."""
    record(g.org["_id"], g.user, action, target, detail)
