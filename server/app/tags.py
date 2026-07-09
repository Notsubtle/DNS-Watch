"""
Client tags/groups (#31) — a user-defined label ("kids", "IoT", "guest", ...)
applied to a set of client IPs, so a dashboard filter or an alert rule can
scope to "all of these devices" instead of one IP or every IP.

State lives in DNS Watch's own writable store (`DNSWATCH_DB_PATH`), the same
file alerts.py/rollups.py/resolve.py/names.py use — never Pi-hole's read-only
FTL db. Deliberately independent of names.py's manual-naming table: a tag is
a group membership, not an identity override, and an IP can carry a manual
name, a tag, both, or neither without one implying the other.
"""

from __future__ import annotations

import os
import sqlite3
import time

STORE_PATH = os.environ.get("DNSWATCH_DB_PATH", "/data/dnswatch.db")

MAX_TAG_NAME_LENGTH = 50


class InvalidTag(ValueError):
    """Raised for a tag name/ip that fails validation — main.py maps this to a 400."""


def _connect() -> sqlite3.Connection:
    parent = os.path.dirname(STORE_PATH)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(STORE_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


# Same memoization pattern as names.py/resolve.py: STORE_PATHs already known
# to have the tables (and WAL mode) set up, so list_tags()/get_tag_ips() —
# called on most dashboard/rule-eval reads once tags exist — don't pay for a
# write transaction each time. Keyed by path so tests that monkeypatch
# STORE_PATH per-test each still get their own real init.
_initialized_stores: set[str] = set()


def init_store() -> None:
    if STORE_PATH in _initialized_stores:
        return
    with _connect() as conn:
        # WAL is a file-level setting (persists in the db header), so this
        # also benefits every other module sharing this same physical file.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS client_tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS client_tag_members (
                tag_id INTEGER NOT NULL REFERENCES client_tags(id) ON DELETE CASCADE,
                ip TEXT NOT NULL,
                PRIMARY KEY (tag_id, ip)
            )
            """
        )
        conn.execute("PRAGMA foreign_keys=ON")
        conn.commit()
    _initialized_stores.add(STORE_PATH)


def _row_to_tag(r: sqlite3.Row, ips: list[str]) -> dict:
    return {"id": r["id"], "name": r["name"], "created_at": r["created_at"], "ips": ips}


def list_tags() -> list[dict]:
    """Every tag on record, each with its current member IPs, newest first."""
    init_store()
    with _connect() as conn:
        tags = conn.execute(
            "SELECT id, name, created_at FROM client_tags ORDER BY created_at DESC"
        ).fetchall()
        members = conn.execute("SELECT tag_id, ip FROM client_tag_members").fetchall()
    by_tag: dict[int, list[str]] = {}
    for m in members:
        by_tag.setdefault(m["tag_id"], []).append(m["ip"])
    return [_row_to_tag(t, sorted(by_tag.get(t["id"], []))) for t in tags]


def get_tag_ips(name: str) -> list[str] | None:
    """Member IPs for a tag looked up by name, or None if no such tag exists
    (distinct from a real, empty tag — the caller needs to tell "unknown tag"
    from "tag exists but has no members yet" apart)."""
    init_store()
    with _connect() as conn:
        row = conn.execute("SELECT id FROM client_tags WHERE name = ?", (name,)).fetchone()
        if row is None:
            return None
        rows = conn.execute(
            "SELECT ip FROM client_tag_members WHERE tag_id = ?", (row["id"],)
        ).fetchall()
    return [r["ip"] for r in rows]


def create_tag(name: str) -> dict:
    name = name.strip()
    if not name:
        raise InvalidTag("tag name cannot be blank")
    if len(name) > MAX_TAG_NAME_LENGTH:
        raise InvalidTag(f"tag name cannot exceed {MAX_TAG_NAME_LENGTH} characters")
    init_store()
    now = int(time.time())
    with _connect() as conn:
        if conn.execute("SELECT 1 FROM client_tags WHERE name = ?", (name,)).fetchone():
            raise InvalidTag(f"a tag named {name!r} already exists")
        cur = conn.execute(
            "INSERT INTO client_tags (name, created_at) VALUES (?, ?)", (name, now)
        )
        conn.commit()
        tag_id = cur.lastrowid
        row = conn.execute(
            "SELECT id, name, created_at FROM client_tags WHERE id = ?", (tag_id,)
        ).fetchone()
    return _row_to_tag(row, [])


def delete_tag(tag_id: int) -> bool:
    """True if a row was actually deleted, so main.py can 404 on an unknown id.
    Membership rows cascade via the FK — see init_store's ON DELETE CASCADE."""
    init_store()
    with _connect() as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        cur = conn.execute("DELETE FROM client_tags WHERE id = ?", (tag_id,))
        conn.commit()
        return cur.rowcount > 0


def add_member(tag_id: int, ip: str) -> bool:
    """True if the tag exists (member add succeeds or the ip was already a
    member — idempotent); False if tag_id doesn't exist, so main.py can 404."""
    init_store()
    with _connect() as conn:
        if not conn.execute("SELECT 1 FROM client_tags WHERE id = ?", (tag_id,)).fetchone():
            return False
        conn.execute(
            "INSERT OR IGNORE INTO client_tag_members (tag_id, ip) VALUES (?, ?)",
            (tag_id, ip),
        )
        conn.commit()
        return True


def remove_member(tag_id: int, ip: str) -> bool:
    init_store()
    with _connect() as conn:
        cur = conn.execute(
            "DELETE FROM client_tag_members WHERE tag_id = ? AND ip = ?", (tag_id, ip)
        )
        conn.commit()
        return cur.rowcount > 0
