"""
Manual client naming — the user's own name for an IP, an explicit override
that wins over anything DNS Watch or Pi-hole guessed on its own.

Added after real-world testing showed active reverse-DNS (resolve.py) is a
dead end on at least one real network: the LAN's router answers PTR queries
with NXDOMAIN for every client, so there's no automatic name to fall back on
for devices Pi-hole never learned a hostname for. This lets the user close
that gap by hand instead.

Keyed by IP, not MAC: every other part of DNS Watch (queries, rollups,
alerts, anomalies) already keys a client by IP, and many of the clients this
feature exists FOR have no MAC captured by Pi-hole at all (see oui.py) or a
randomized/locally-administered MAC that changes across sessions on modern
mobile OSes — a MAC key would silently never apply for exactly the devices
motivating this feature, or worse, drift across reconnects. The tradeoff:
renaming survives Pi-hole restarts but not a DHCP lease change to a new IP.

State lives in DNS Watch's own writable store (`DNSWATCH_DB_PATH`), the same
file alerts.py/rollups.py/resolve.py use — never Pi-hole's read-only FTL db.
"""

from __future__ import annotations

import ipaddress
import os
import sqlite3
import time

from app import name_history

STORE_PATH = os.environ.get("DNSWATCH_DB_PATH", "/data/dnswatch.db")

MAX_NAME_LENGTH = 100


class InvalidName(ValueError):
    """Raised for a name/ip that fails validation — main.py maps this to a 400."""


def _connect() -> sqlite3.Connection:
    parent = os.path.dirname(STORE_PATH)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(STORE_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


# STORE_PATHs already known to have the table (and WAL mode) set up, so
# get_names() — called on nearly every dashboard read — doesn't pay for a
# write transaction each time. Keyed by path (not a bare bool) so tests that
# monkeypatch STORE_PATH per-test each still get their own real init.
_initialized_stores: set[str] = set()


def init_store() -> None:
    if STORE_PATH in _initialized_stores:
        return
    with _connect() as conn:
        # WAL is a file-level setting (persists in the db header), so this
        # also benefits alerts.py/rollups.py/resolve.py, which share this
        # same physical file in production — readers no longer block on a
        # writer.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS manual_client_names (
                ip TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.commit()
    _initialized_stores.add(STORE_PATH)


def get_names() -> dict[str, str]:
    """ip -> manually-assigned name, for every override on record."""
    init_store()
    with _connect() as conn:
        rows = conn.execute("SELECT ip, name FROM manual_client_names")
        return {r["ip"]: r["name"] for r in rows}


def list_names() -> list[dict]:
    """Every override on record, for the management UI — includes timestamps
    the plain ip->name map from get_names() deliberately omits."""
    init_store()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ip, name, created_at, updated_at FROM manual_client_names "
            "ORDER BY updated_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def set_name(ip: str, name: str) -> None:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise InvalidName(f"not a valid IP address: {ip!r}") from None

    name = name.strip()
    if not name:
        raise InvalidName("name cannot be blank")
    if len(name) > MAX_NAME_LENGTH:
        raise InvalidName(f"name cannot exceed {MAX_NAME_LENGTH} characters")

    now = int(time.time())
    init_store()
    with _connect() as conn:
        prev = conn.execute("SELECT name FROM manual_client_names WHERE ip = ?", (ip,)).fetchone()
        conn.execute(
            "INSERT INTO manual_client_names (ip, name, created_at, updated_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET name=excluded.name, updated_at=excluded.updated_at",
            (ip, name, now, now),
        )
        conn.commit()
    name_history.record_change(ip, "manual", prev["name"] if prev else None, name)


def delete_name(ip: str) -> bool:
    """True if a row was actually deleted, so main.py can 404 on an unknown ip."""
    init_store()
    with _connect() as conn:
        prev = conn.execute("SELECT name FROM manual_client_names WHERE ip = ?", (ip,)).fetchone()
        cur = conn.execute("DELETE FROM manual_client_names WHERE ip = ?", (ip,))
        conn.commit()
        deleted = cur.rowcount > 0
    if deleted:
        name_history.record_change(ip, "manual", prev["name"] if prev else None, None)
    return deleted
