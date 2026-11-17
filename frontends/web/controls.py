# -*- coding: utf-8 -*-
"""
Control register: what an organization records about each framework control,
next to what the audits show.

The audits decide whether a control that a rule checks is passing or failing
(see frameworks.assess). The register adds what no configuration audit can
know: who owns the control, how far it is implemented, why it does not apply,
which documents or links prove it, and when it is next reviewed. A control no
rule checks becomes "Attested" once it is recorded as implemented, has at
least one piece of evidence, and is not overdue for review.

One document per organization, framework and control, in the `controls`
collection, with a deterministic id so it is created on first edit.
"""
import re
from datetime import datetime, timezone

from storage import later, new_id, now, store

IMPLEMENTATION = ("", "implemented", "partial", "planned", "not_applicable")
IMPLEMENTATION_LABEL = {"": "Not recorded", "implemented": "Implemented", "partial": "Partly implemented",
                        "planned": "Planned", "not_applicable": "Not applicable"}
MAX_NOTES = 2000
MAX_EVIDENCE = 50
MAX_EVIDENCE_TEXT = 1000
MAX_LINK = 500
MAX_HISTORY = 200
MAX_REVIEW_DAYS = 3 * 366
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
LINK = re.compile(r"^https?://[^\s<>\"']+$", re.I)


class ControlError(ValueError):
    """A message that is safe to show to the person using the form."""


def doc_id(org_id, framework_key, control_id):
    return f"{org_id}:{framework_key}:{control_id}"


def blank(org_id, framework_key, control_id):
    return {"_id": doc_id(org_id, framework_key, control_id), "org_id": org_id,
            "framework": framework_key, "control": control_id, "owner": "", "implementation": "",
            "na_reason": "", "notes": "", "next_review": "", "last_reviewed_at": "",
            "last_reviewed_by": "", "evidence": [], "history": []}


def get(org_id, framework_key, control_id):
    """The register entry, or a blank one that is not stored yet."""
    found = store().get("controls", doc_id(org_id, framework_key, control_id))
    if found and found.get("org_id") == org_id:
        return found
    return blank(org_id, framework_key, control_id)


def register(org_id):
    """{(framework key, control id): entry} for every stored entry of an organization."""
    return {(d["framework"], d["control"]): d for d in store().find("controls", {"org_id": org_id})}


def today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def review_overdue(entry):
    due = (entry or {}).get("next_review") or ""
    return bool(due) and due < today()


def attested(entry):
    """Recorded as implemented, with evidence, and not overdue for review."""
    return bool(entry) and entry.get("implementation") == "implemented" \
        and bool(entry.get("evidence")) and not review_overdue(entry)


def _history(entry, user_email, action, note=""):
    entry.setdefault("history", []).append({"at": now(), "by": user_email, "action": action,
                                            "note": note[:300]})
    del entry["history"][:-MAX_HISTORY]


def _clean_date(value, what):
    value = (value or "").strip()
    if not value:
        return ""
    if not DATE.match(value):
        raise ControlError(f"Enter the {what} as a date (YYYY-MM-DD).")
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise ControlError(f"Enter the {what} as a real date.")
    return value


def update(entry, form, user_email, members):
    """Change owner, implementation, notes and review date. Returns the changed fields."""
    owner = (form.get("owner") or "").strip().lower()
    if owner and owner not in members:
        raise ControlError("The owner must be a member of this organization.")
    impl = (form.get("implementation") or "").strip()
    if impl not in IMPLEMENTATION:
        raise ControlError("Choose how far the control is implemented.")
    na_reason = (form.get("na_reason") or "").strip()
    if impl == "not_applicable" and len(na_reason) < 10:
        raise ControlError("Write down why the control does not apply (at least 10 characters).")
    if impl != "not_applicable":
        na_reason = ""
    notes = (form.get("notes") or "").strip()
    if len(notes) > MAX_NOTES:
        raise ControlError(f"Keep the notes under {MAX_NOTES} characters.")
    review = _clean_date(form.get("next_review"), "next review date")
    if review and review != entry.get("next_review"):
        if review < today():
            raise ControlError("The next review date cannot be in the past.")
        if review > later(days=MAX_REVIEW_DAYS)[:10]:
            raise ControlError("Plan the next review within three years.")

    new = {"owner": owner, "implementation": impl, "na_reason": na_reason[:500], "notes": notes,
           "next_review": review}
    changed = [k for k, v in new.items() if (entry.get(k) or "") != v]
    if not changed:
        return []
    labels = []
    if "owner" in changed:
        labels.append(f"owner {owner or 'none'}")
    if "implementation" in changed:
        labels.append(IMPLEMENTATION_LABEL[impl].lower())
    if "next_review" in changed:
        labels.append(f"review by {review or 'not set'}")
    if "notes" in changed or "na_reason" in changed:
        labels.append("notes")
    entry.update(new)
    _history(entry, user_email, "updated", ", ".join(labels))
    return changed


def add_evidence(entry, form, user_email):
    text = (form.get("text") or "").strip()
    link = (form.get("link") or "").strip()
    if len(text) < 5:
        raise ControlError("Describe the evidence (at least 5 characters).")
    if len(text) > MAX_EVIDENCE_TEXT:
        raise ControlError(f"Keep the description under {MAX_EVIDENCE_TEXT} characters.")
    if link and (len(link) > MAX_LINK or not LINK.match(link)):
        raise ControlError("A link must start with http:// or https://.")
    if len(entry.get("evidence") or []) >= MAX_EVIDENCE:
        raise ControlError(f"A control can hold at most {MAX_EVIDENCE} pieces of evidence.")
    item = {"id": new_id(10), "at": now(), "by": user_email, "text": text, "link": link}
    entry.setdefault("evidence", []).append(item)
    _history(entry, user_email, "evidence_added", text[:120])
    return item


def remove_evidence(entry, item_id, user_email):
    items = entry.get("evidence") or []
    keep = [e for e in items if e.get("id") != item_id]
    if len(keep) == len(items):
        raise ControlError("That evidence is no longer there.")
    gone = next(e for e in items if e.get("id") == item_id)
    entry["evidence"] = keep
    _history(entry, user_email, "evidence_removed", gone.get("text", "")[:120])


def mark_reviewed(entry, form, user_email):
    review = _clean_date(form.get("next_review"), "next review date")
    if not review:
        raise ControlError("Choose when the control is next reviewed.")
    if review <= today():
        raise ControlError("The next review date must be after today.")
    if review > later(days=MAX_REVIEW_DAYS)[:10]:
        raise ControlError("Plan the next review within three years.")
    entry["last_reviewed_at"] = now()
    entry["last_reviewed_by"] = user_email
    entry["next_review"] = review
    _history(entry, user_email, "reviewed", f"next review by {review}")


def save(entry):
    return store().replace("controls", entry)


def summary(entry):
    """The register fields that travel with a control in lists and the API."""
    entry = entry or {}
    return {"owner": entry.get("owner", ""), "implementation": entry.get("implementation", ""),
            "na_reason": entry.get("na_reason", ""), "notes": entry.get("notes", ""),
            "next_review": entry.get("next_review", ""),
            "last_reviewed_at": entry.get("last_reviewed_at", ""),
            "evidence_count": len(entry.get("evidence") or []),
            "review_overdue": review_overdue(entry)}
