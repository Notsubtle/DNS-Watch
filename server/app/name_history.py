"""
Device name-change history: WHEN a device's name changed and to what,
from the two sources DNS Watch itself writes -- a manual override
(names.py) and the reverse-DNS guess cache (resolve.py).

Pi-hole's own name is read live from its FTL db on every request; DNS Watch
has no write path for it and therefore no natural hook to log against
(detecting a Pi-hole-side rename would need a separate polling/diff
mechanism, not a one-line hook like the two sources here) -- deliberately
out of scope for v1, per the naming feature's own scoping note.

Shares DNS Watch's writable store (`DNSWATCH_DB_PATH`) with alerts.py/
rollups.py/resolve.py/names.py, same one-table-per-module convention.
"""

from __future__ import annotations

import os
import sqlite3
import time

STORE_PATH = os.environ.get("DNSWATCH_DB_PATH", "/data/dnswatch.db")


def _connect() -> sqlite3.Connection:
    parent = os.path.dirname(STORE_PATH)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(STORE_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def init_store() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS name_change_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                changed_at INTEGER NOT NULL,
                source TEXT NOT NULL,
                old_name TEXT,
                new_name TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_name_change_log_ip ON name_change_log (ip)")
        conn.commit()


def record_change(ip: str, source: str, old_name: str | None, new_name: str | None) -> None:
    """Append one history row. Callers own the "did it actually change?"
    check (names.py compares against the pre-upsert row, resolve.py against
    the pre-upsert cache value) -- this only guards the trivial no-op case
    defensively, it never queries for the prior value itself."""
    if old_name == new_name:
        return
    init_store()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO name_change_log (ip, changed_at, source, old_name, new_name) VALUES (?, ?, ?, ?, ?)",
            (ip, int(time.time()), source, old_name, new_name),
        )
        conn.commit()


def history_for(ip: str, limit: int = 50) -> list[dict]:
    """Most-recent-first change history for one device."""
    init_store()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT changed_at, source, old_name, new_name FROM name_change_log "
            "WHERE ip = ? ORDER BY changed_at DESC, id DESC LIMIT ?",
            (ip, limit),
        ).fetchall()
    return [dict(r) for r in rows]
