# -*- coding: utf-8 -*-
"""
Document storage for the dashboard: MongoDB when MONGODB_URI is set, otherwise
a SQLite file in the data directory.

Both back-ends expose the same small interface over named collections of JSON
documents. A document is a dict with a string `_id`. Filters are equality on
top-level or dotted fields ({"org_id": x, "meta.vendor": "cisco"}); anything
more is done by the caller on the returned list, which is fine at the sizes
one organization produces.

Timestamps are ISO-8601 UTC strings ("2026-11-10T09:30:00Z") so they sort as
text. MongoDB keeps `created_at` as a native date, as documents written before
v3 did, and converts on the way in and out.
"""
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone

import config

ISO = "%Y-%m-%dT%H:%M:%SZ"


def now():
    return datetime.now(timezone.utc).strftime(ISO)


def later(**delta):
    """An ISO timestamp `delta` from now, e.g. later(hours=1)."""
    return (datetime.now(timezone.utc) + timedelta(**delta)).strftime(ISO)


def parse_time(text):
    try:
        return datetime.strptime(text, ISO).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def new_id(length=16):
    return uuid.uuid4().hex[:length]


class SqliteStore:
    """One table of JSON documents, indexed by collection, organization and time."""

    kind = "sqlite"

    def __init__(self, path):
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS docs ("
            " coll TEXT NOT NULL, id TEXT NOT NULL, org_id TEXT, created_at TEXT,"
            " body TEXT NOT NULL, PRIMARY KEY (coll, id))")
        self._db.execute("CREATE INDEX IF NOT EXISTS docs_org ON docs (coll, org_id, created_at)")

    @staticmethod
    def _path(field):
        return "$." + field

    def _where(self, coll, where):
        sql, args = ["coll = ?"], [coll]
        for field, value in (where or {}).items():
            if field == "_id":
                sql.append("id = ?")
                args.append(value)
            elif field == "org_id":
                sql.append("org_id = ?")
                args.append(value)
            elif isinstance(value, bool):
                sql.append("json_extract(body, ?) = ?")
                args += [self._path(field), 1 if value else 0]
            else:
                sql.append("json_extract(body, ?) = ?")
                args += [self._path(field), value]
        return " AND ".join(sql), args

    def insert(self, coll, doc):
        doc = dict(doc)
        doc.setdefault("_id", new_id())
        doc.setdefault("created_at", now())
        with self._lock:
            self._db.execute(
                "INSERT INTO docs (coll, id, org_id, created_at, body) VALUES (?, ?, ?, ?, ?)",
                (coll, doc["_id"], doc.get("org_id"), doc["created_at"],
                 json.dumps(doc, ensure_ascii=False)))
        return doc

    def replace(self, coll, doc):
        doc = dict(doc)
        doc.setdefault("created_at", now())
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO docs (coll, id, org_id, created_at, body) VALUES (?, ?, ?, ?, ?)",
                (coll, doc["_id"], doc.get("org_id"), doc["created_at"],
                 json.dumps(doc, ensure_ascii=False)))
        return doc

    def get(self, coll, doc_id):
        with self._lock:
            row = self._db.execute("SELECT body FROM docs WHERE coll = ? AND id = ?",
                                   (coll, doc_id)).fetchone()
        return json.loads(row[0]) if row else None

    def find(self, coll, where=None, sort=None, desc=False, limit=None):
        sql, args = self._where(coll, where)
        query = "SELECT body FROM docs WHERE " + sql
        if sort == "created_at":
            query += " ORDER BY created_at" + (" DESC" if desc else "")
        elif sort:
            query += " ORDER BY json_extract(body, ?)" + (" DESC" if desc else "")
            args.append(self._path(sort))
        if limit:
            query += " LIMIT ?"
            args.append(int(limit))
        with self._lock:
            rows = self._db.execute(query, args).fetchall()
        return [json.loads(r[0]) for r in rows]

    def find_one(self, coll, where):
        found = self.find(coll, where, limit=1)
        return found[0] if found else None

    def update(self, coll, doc_id, changes):
        """Set top-level fields of one document. Returns the new document or None."""
        with self._lock:
            doc = self.get(coll, doc_id)
            if doc is None:
                return None
            doc.update(changes)
            self.replace(coll, doc)
        return doc

    def delete(self, coll, doc_id):
        with self._lock:
            cur = self._db.execute("DELETE FROM docs WHERE coll = ? AND id = ?", (coll, doc_id))
        return cur.rowcount > 0

    def delete_where(self, coll, where):
        sql, args = self._where(coll, where)
        with self._lock:
            cur = self._db.execute("DELETE FROM docs WHERE " + sql, args)
        return cur.rowcount

    def count(self, coll, where=None):
        sql, args = self._where(coll, where)
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM docs WHERE " + sql, args).fetchone()[0]

    def adopt_orphans(self, coll, org_id):
        """Give documents that belong to no organization to `org_id`."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE docs SET org_id = ?, body = json_set(body, '$.org_id', ?)"
                " WHERE coll = ? AND org_id IS NULL", (org_id, org_id, coll))
        return cur.rowcount

    def ping(self):
        with self._lock:
            self._db.execute("SELECT 1").fetchone()
        return True


class MongoStore:
    """The same interface over MongoDB collections."""

    kind = "mongodb"

    def __init__(self, uri, default_db):
        from pymongo import MongoClient
        self._client = MongoClient(uri, appname="net-audit", maxPoolSize=5,
                                   serverSelectionTimeoutMS=config.MONGO_SELECT_TIMEOUT_MS,
                                   connectTimeoutMS=config.MONGO_CONNECT_TIMEOUT_MS)
        self._dbh = self._client.get_default_database(default=default_db)
        self._indexed = set()

    def _c(self, coll):
        c = self._dbh[coll]
        if coll not in self._indexed:
            c.create_index([("org_id", 1), ("created_at", -1)])
            self._indexed.add(coll)
        return c

    @staticmethod
    def _in(doc):
        doc = dict(doc)
        doc.setdefault("_id", new_id())
        created = parse_time(doc.get("created_at")) if isinstance(doc.get("created_at"), str) else doc.get("created_at")
        doc["created_at"] = created or datetime.now(timezone.utc)
        return doc

    @classmethod
    def _out(cls, value):
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc).strftime(ISO)
        if isinstance(value, dict):
            return {k: cls._out(v) for k, v in value.items()}
        if isinstance(value, list):
            return [cls._out(v) for v in value]
        return value

    def insert(self, coll, doc):
        doc = self._in(doc)
        self._c(coll).insert_one(doc)
        return self._out(doc)

    def replace(self, coll, doc):
        doc = self._in(doc)
        self._c(coll).replace_one({"_id": doc["_id"]}, doc, upsert=True)
        return self._out(doc)

    def get(self, coll, doc_id):
        return self._out(self._c(coll).find_one({"_id": doc_id}))

    def find(self, coll, where=None, sort=None, desc=False, limit=None):
        cursor = self._c(coll).find(dict(where or {}))
        if sort:
            cursor = cursor.sort(sort, -1 if desc else 1)
        if limit:
            cursor = cursor.limit(int(limit))
        return [self._out(d) for d in cursor]

    def find_one(self, coll, where):
        return self._out(self._c(coll).find_one(dict(where)))

    def update(self, coll, doc_id, changes):
        from pymongo import ReturnDocument
        changes = {k: v for k, v in changes.items() if k != "_id"}
        if isinstance(changes.get("created_at"), str):
            changes["created_at"] = parse_time(changes["created_at"])
        doc = self._c(coll).find_one_and_update({"_id": doc_id}, {"$set": changes},
                                                return_document=ReturnDocument.AFTER)
        return self._out(doc)

    def delete(self, coll, doc_id):
        return self._c(coll).delete_one({"_id": doc_id}).deleted_count > 0

    def delete_where(self, coll, where):
        return self._c(coll).delete_many(dict(where)).deleted_count

    def count(self, coll, where=None):
        return self._c(coll).count_documents(dict(where or {}))

    def adopt_orphans(self, coll, org_id):
        r = self._c(coll).update_many({"org_id": {"$exists": False}}, {"$set": {"org_id": org_id}})
        return r.modified_count

    def ping(self):
        self._dbh.command("ping")
        return True


_store = None
_store_lock = threading.Lock()


def store():
    """The process-wide store, created on first use."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                if config.MONGODB_URI:
                    _store = MongoStore(config.MONGODB_URI, config.MONGODB_DB)
                else:
                    _store = SqliteStore(config.SQLITE_PATH)
                    _import_json_history(_store)
    return _store


def _import_json_history(db):
    """Copy audits saved as JSON files by earlier versions into the database, once.

    The files are left where they are. Imported audits belong to no
    organization until the first one is created, which adopts them.
    """
    if db.count("audits") or db.get("meta", "json-history-imported"):
        return
    imported = 0
    for path in sorted(config.HISTORY_DIR.glob("*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        meta = data.get("meta") or {}
        created = now()
        try:      # meta.timestamp is local time, "YYYY-MM-DD HH:MM:SS"
            local = datetime.strptime(meta.get("timestamp", ""), "%Y-%m-%d %H:%M:%S")
            created = local.astimezone(timezone.utc).strftime(ISO)
        except ValueError:
            pass
        db.replace("audits", {"_id": path.stem, "created_at": created, "meta": meta,
                              "report": data.get("report") or {}})
        imported += 1
    db.replace("meta", {"_id": "json-history-imported", "count": imported})
