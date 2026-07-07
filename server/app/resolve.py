"""
Active reverse-DNS (PTR) resolution for LAN clients Pi-hole never names.

`db.py` already surfaces a client name when Pi-hole knows one (DHCP lease,
mDNS, or a name set in Pi-hole's own UI — see `_client_join_sql`). Static-IP
or otherwise-silent devices Pi-hole never learns a hostname for still show up
as a bare IP (or a MAC-vendor guess, see `oui.py`). This module closes that
gap by having DNS Watch do its own PTR lookups against those IPs.

mDNS was considered and deliberately left out: this container normally runs
on Docker's default bridge network (see docker-compose.yml), which NATs
outbound traffic and does not forward multicast group membership onto the
host's LAN interface — a bridged container structurally cannot see mDNS
traffic from other LAN devices. Revisit only if the deployment moves to
`network_mode: host` (a real network-isolation trade-off, not a code change).

State (the resolved-name cache) lives in DNS Watch's own writable store
(`DNSWATCH_DB_PATH`), the same file alerts.py/rollups.py use — never Pi-hole's
FTL db. Resolution is active network I/O (a UDP query per unresolved IP), so
it only ever runs from the background scheduler tick in main.py, never
inline on a request thread: a slow or unreachable resolver must not turn
into a slow dashboard load.
"""

from __future__ import annotations

import os
import socket
import sqlite3
import struct
import time

STORE_PATH = os.environ.get("DNSWATCH_DB_PATH", "/data/dnswatch.db")

# Optional explicit reverse-DNS server (e.g. your router's LAN IP, which often
# answers PTR queries for DHCP-leased hostnames even when it isn't Pi-hole's
# configured upstream). Falls back to whatever /etc/resolv.conf lists.
REVERSE_DNS_SERVER = os.environ.get("DNSWATCH_REVERSE_DNS_SERVER") or None

LOOKUP_TIMEOUT_SECONDS = 1.5
# Cap per scheduler tick: worst case (every lookup times out) this adds
# BATCH_SIZE * LOOKUP_TIMEOUT_SECONDS to one shared background-thread tick
# (see main.py's _alert_scheduler) — kept small so a run of unreachable IPs
# can't meaningfully delay alert evaluation/rollups on the same tick.
BATCH_SIZE = 5

# Retry backoff (seconds) for IPs that resolved to nothing, indexed by
# min(attempts, len-1): fast retries at first (transient network hiccup),
# settling to once a day so a permanently silent IP doesn't get hammered.
_FAILURE_BACKOFF = [300, 1800, 21600, 86400]
# Successes are re-checked periodically too — hostnames do change.
_SUCCESS_REFRESH_SECONDS = 86400


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
            CREATE TABLE IF NOT EXISTS resolved_names (
                ip TEXT PRIMARY KEY,
                name TEXT,
                resolved_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.commit()


def get_names() -> dict[str, str]:
    """ip -> resolved hostname, for every successful lookup in the cache.
    Failed/negative lookups (name IS NULL) are excluded — callers only ever
    want a real fallback name here, same contract as db.py's other name maps.
    """
    init_store()
    with _connect() as conn:
        rows = conn.execute("SELECT ip, name FROM resolved_names WHERE name IS NOT NULL")
        return {r["ip"]: r["name"] for r in rows}


def _resolvers() -> list[str]:
    if REVERSE_DNS_SERVER:
        return [REVERSE_DNS_SERVER]
    servers = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) == 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except OSError:
        pass
    return servers


def _reverse_name(ip: str) -> str | None:
    """`d.c.b.a.in-addr.arpa` for IPv4 `a.b.c.d`; None for anything else
    (IPv6 PTR under `.ip6.arpa` is out of scope for this v1 — LAN clients in
    this codebase are consistently addressed by IPv4, see db.py)."""
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return None
    return ".".join(reversed(parts)) + ".in-addr.arpa"


def _build_ptr_query(qname: str) -> bytes:
    header = struct.pack(">HHHHHH", os.getpid() & 0xFFFF, 0x0100, 1, 0, 0, 0)
    question = b"".join(bytes([len(label)]) + label.encode() for label in qname.split(".")) + b"\x00"
    question += struct.pack(">HH", 12, 1)  # QTYPE=PTR, QCLASS=IN
    return header + question


def _skip_name(data: bytes, offset: int) -> int:
    """Advance past a possibly-compressed DNS name, returning the new offset."""
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0:  # compression pointer: 2 bytes total, then done
            return offset + 2
        offset += 1 + length


def _decode_name(data: bytes, offset: int) -> str:
    """Decode a (possibly compressed) DNS name starting at `offset`."""
    labels = []
    seen_pointers = 0
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:
            if seen_pointers > 20:  # guard against a malicious/corrupt pointer loop
                break
            seen_pointers += 1
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels)


def _parse_ptr_response(data: bytes, query_id: int) -> str | None:
    if len(data) < 12:
        return None
    resp_id, flags, qdcount, ancount = struct.unpack(">HHHH", data[:8])
    if resp_id != query_id or ancount == 0:
        return None
    offset = 12
    for _ in range(qdcount):
        offset = _skip_name(data, offset) + 4  # QTYPE + QCLASS
    for _ in range(ancount):
        offset = _skip_name(data, offset)  # answer NAME (unused; just advance past it)
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if rtype == 12:  # PTR
            name = _decode_name(data, offset)
            return name.rstrip(".") or None
        offset += rdlength
    return None


def _lookup(ip: str, timeout: float = LOOKUP_TIMEOUT_SECONDS) -> str | None:
    """One best-effort PTR lookup for `ip`, trying each configured resolver
    in turn. Returns None on any failure — malformed response, timeout, no
    PTR record — never raises; a broken/unreachable resolver must degrade to
    "no name learned this round," not an exception on the scheduler thread."""
    for server in _resolvers():
        name = _lookup_via(ip, server, 53, timeout)
        if name:
            return name
    return None


def _lookup_via(ip: str, server: str, port: int, timeout: float) -> str | None:
    """One PTR query against a specific (server, port) — split out from
    _lookup() so tests can point it at a real loopback fake resolver instead
    of mocking the socket layer away."""
    qname = _reverse_name(ip)
    if qname is None:
        return None
    query_id = os.getpid() & 0xFFFF
    packet = _build_ptr_query(qname)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (server, port))
            data, _ = sock.recvfrom(512)
        return _parse_ptr_response(data, query_id)
    except (OSError, struct.error, IndexError):
        return None


def resolve_batch(candidate_ips: list[str], now: int | None = None) -> int:
    """Resolve up to BATCH_SIZE of `candidate_ips` that are due (new, or past
    their backoff), caching results (positive or negative) either way so a
    dead IP isn't retried every call. Returns how many were actually looked
    up (for tests/observability), not how many succeeded."""
    now = now if now is not None else int(time.time())
    init_store()
    with _connect() as conn:
        due = []
        for ip in candidate_ips:
            row = conn.execute(
                "SELECT next_attempt_at FROM resolved_names WHERE ip = ?", (ip,)
            ).fetchone()
            if row is None or row["next_attempt_at"] <= now:
                due.append(ip)
            if len(due) >= BATCH_SIZE:
                break

        for ip in due:
            name = _lookup(ip)
            if name:
                conn.execute(
                    "INSERT INTO resolved_names (ip, name, resolved_at, attempts, next_attempt_at) "
                    "VALUES (?, ?, ?, 0, ?) "
                    "ON CONFLICT(ip) DO UPDATE SET name=excluded.name, resolved_at=excluded.resolved_at, "
                    "attempts=0, next_attempt_at=excluded.next_attempt_at",
                    (ip, name, now, now + _SUCCESS_REFRESH_SECONDS),
                )
            else:
                prev = conn.execute(
                    "SELECT attempts FROM resolved_names WHERE ip = ?", (ip,)
                ).fetchone()
                attempts = (prev["attempts"] if prev else 0) + 1
                backoff = _FAILURE_BACKOFF[min(attempts - 1, len(_FAILURE_BACKOFF) - 1)]
                conn.execute(
                    "INSERT INTO resolved_names (ip, name, resolved_at, attempts, next_attempt_at) "
                    "VALUES (?, NULL, ?, ?, ?) "
                    "ON CONFLICT(ip) DO UPDATE SET name=NULL, resolved_at=excluded.resolved_at, "
                    "attempts=excluded.attempts, next_attempt_at=excluded.next_attempt_at",
                    (ip, now, attempts, now + backoff),
                )
        conn.commit()
    return len(due)
