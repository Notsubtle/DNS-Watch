"""
Alert rule engine for DNS Watch.

State (rules + fired events) lives in a SEPARATE, writable SQLite database —
never Pi-hole's FTL db, which we only ever open read-only via `db.py`. The
store path defaults to `/data/dnswatch.db` (mount a writable volume there in
Docker) and is created on first use.

Rules are evaluated on demand (when the frontend polls `/api/alerts`) against
current FTL data. Each rule type produces zero or more events; a per-key
cooldown stops the same condition from re-firing on every poll.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import socket
import sqlite3
import ssl
import threading
import time
import urllib.parse
from datetime import datetime, timezone

from app import db, rollups, tags

STORE_PATH = os.environ.get("DNSWATCH_DB_PATH", "/data/dnswatch.db")

# Serialises rule evaluation so the background scheduler and a concurrent
# /api/alerts request can't both pass the dedup/cooldown check and double-insert
# the same event.
_eval_lock = threading.Lock()

VALID_TYPES = {
    "volume_threshold", "new_device", "domain_keyword", "device_quiet",
    "new_vendor", "doh_provider", "digest", "first_seen_domain",
    "correlated_new_device_domain",
}

# Webhook payload shapes. "generic" is DNS Watch's own JSON; "slack"/"discord"
# emit exactly the single field each of those incoming-webhook APIs requires.
VALID_FORMATS = {"generic", "slack", "discord"}
DISCORD_MAX = 1900  # Discord hard-limits `content` at 2000; leave headroom.
SLACK_MAX = 3000

# Default re-fire cooldown per rule type, in seconds, when the rule doesn't
# specify its own. New-device alerts get a long cooldown so a device isn't
# re-announced all day; volume/keyword track their own window.
DEFAULT_COOLDOWN = {
    "volume_threshold": 900,
    "new_device": 86400,
    "domain_keyword": 900,
    "device_quiet": 3600,
    "new_vendor": 86400,
    "doh_provider": 86400,
    "first_seen_domain": 86400,
    "correlated_new_device_domain": 86400,
    # No entry for "digest": its firing is gated on a calendar-period
    # boundary (see digest_schedule / _dedup_exists below), not an
    # elapsed-time cooldown, since that's the whole point of a digest.
}


def _connect() -> sqlite3.Connection:
    # Ensure the parent dir exists (e.g. first run against a fresh volume).
    parent = os.path.dirname(STORE_PATH)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(STORE_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def init_store() -> None:
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alert_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                params TEXT NOT NULL DEFAULT '{}',
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alert_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER,
                rule_name TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info',
                message TEXT NOT NULL,
                dedup_key TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_dedup
                ON alert_events (dedup_key, created_at);
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS digest_schedule (
                rule_id INTEGER PRIMARY KEY,
                last_sent_period TEXT NOT NULL,
                last_sent_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alert_snoozes (
                dedup_key TEXT PRIMARY KEY,
                snoozed_until INTEGER NOT NULL
            );
            """
        )
        # client_ip/domain (#43) are added via ALTER rather than baked into
        # the CREATE TABLE above, matching how every other post-launch
        # alert_events change in this file has been done (new tables, not
        # schema changes to existing ones) -- this is the one field-add
        # exception, needed so a fired event can carry a structured target
        # (for snoozing -- #42 -- and cross-view deep-linking -- #43)
        # instead of only a free-text `message`. Guarded on PRAGMA table_info
        # since SQLite has no ADD COLUMN IF NOT EXISTS, so this stays
        # idempotent across every init_store() call, not just the first.
        existing_cols = {r["name"] for r in conn.execute("PRAGMA table_info(alert_events)")}
        if "client_ip" not in existing_cols:
            conn.execute("ALTER TABLE alert_events ADD COLUMN client_ip TEXT")
        if "domain" not in existing_cols:
            conn.execute("ALTER TABLE alert_events ADD COLUMN domain TEXT")
        conn.commit()


# --------------------------------------------------------------------------
# Settings (webhook delivery)
# --------------------------------------------------------------------------

def _get_raw_settings() -> dict:
    """Full-fidelity settings, including the plaintext webhook secret.

    Internal use only (currently: actually delivering to the webhook). Never
    return this directly from an API route — see get_settings().
    """
    init_store()
    with _connect() as conn:
        rows = conn.execute("SELECT key, value FROM app_settings").fetchall()
    d = {r["key"]: r["value"] for r in rows}
    fmt = d.get("webhook_format", "generic")
    return {
        "webhook_enabled": d.get("webhook_enabled", "0") == "1",
        "webhook_url": d.get("webhook_url", ""),
        "webhook_secret": d.get("webhook_secret", ""),
        "webhook_format": fmt if fmt in VALID_FORMATS else "generic",
    }


def get_settings() -> dict:
    """Settings as exposed over the API.

    The webhook secret is intentionally never returned in plaintext here — only
    whether one is currently set. `GET /api/settings` has no stronger access
    control than the rest of the API (auth is opt-in and off by default), and
    the secret is a bearer credential for an *external* service (ntfy, Home
    Assistant, ...), so it shouldn't be readable back out through this app by
    anyone who can merely reach it.
    """
    raw = _get_raw_settings()
    return {
        "webhook_enabled": raw["webhook_enabled"],
        "webhook_url": raw["webhook_url"],
        "webhook_format": raw["webhook_format"],
        "webhook_secret_set": bool(raw["webhook_secret"]),
    }


def _put(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO app_settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def update_settings(
    *,
    webhook_enabled: bool | None = None,
    webhook_url: str | None = None,
    webhook_secret: str | None = None,
    webhook_format: str | None = None,
) -> dict:
    if webhook_format is not None and webhook_format not in VALID_FORMATS:
        raise ValueError(f"unknown webhook format: {webhook_format}")
    init_store()
    with _connect() as conn:
        if webhook_enabled is not None:
            _put(conn, "webhook_enabled", "1" if webhook_enabled else "0")
        if webhook_url is not None:
            _put(conn, "webhook_url", webhook_url.strip())
        if webhook_secret is not None:
            _put(conn, "webhook_secret", webhook_secret.strip())
        if webhook_format is not None:
            _put(conn, "webhook_format", webhook_format)
        conn.commit()
    return get_settings()


def _summary(events: list[dict]) -> str:
    return "\n".join(f"[{e['severity']}] {e['message']}" for e in events)


def _wrap_payload(fmt: str, summary: str, events: list[dict]) -> dict:
    """Shape a summary string into the body the chosen receiver expects."""
    if fmt == "slack":
        # Slack incoming webhooks require a top-level `text`.
        return {"text": summary[:SLACK_MAX] or "DNS Watch alert"}
    if fmt == "discord":
        # Discord incoming webhooks require a non-empty `content` (≤ 2000 chars).
        return {"content": summary[:DISCORD_MAX] or "DNS Watch alert"}
    # Generic DNS Watch JSON. `text`/`content` still mirror the summary so a
    # generic receiver (ntfy, Home Assistant) gets a human string for free.
    return {
        "event": "dns_watch_alert",
        "count": len(events),
        "text": summary,
        "content": summary,
        "alerts": [
            {
                "rule_name": e["rule_name"],
                "type": e["type"],
                "severity": e["severity"],
                "message": e["message"],
                "created_at": e.get("created_at"),
            }
            for e in events
        ],
    }


ALLOWED_WEBHOOK_SCHEMES = {"http", "https"}


def _is_unsafe_webhook_target(ip_str: str) -> bool:
    """True for addresses a user-supplied webhook URL must never reach.

    Deliberately narrow: DNS Watch is a self-hosted LAN tool whose documented
    webhook feature targets things like a LAN Home Assistant instance or a
    self-hosted ntfy server, so private (RFC1918) and loopback addresses are
    intentionally NOT blocked here — that's the legitimate use case, and our own
    tests deliver to a loopback mock server. What IS blocked: link-local
    addresses (this covers the 169.254.169.254 cloud-metadata endpoint that's
    the classic high-value SSRF target), multicast, unspecified, and IETF
    reserved ranges — none of which are ever a legitimate webhook receiver.
    """
    ip = ipaddress.ip_address(ip_str)
    if ip.is_loopback:
        # Checked first and returned early so loopback can't be caught
        # incidentally by a rule below meant for something else — IPv6 ::1
        # falls inside the ::/8 range is_reserved checks, which would
        # otherwise block loopback for IPv6 only, contradicting the "loopback
        # allowed for both families" policy stated above.
        return False
    return ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved


def _validate_webhook_url(url: str) -> tuple[str | None, str | None]:
    """Validate `url` and resolve it to a single literal IP that has already
    passed the safety check above. Returns (pinned_ip, error) — exactly one
    of the two is set.

    The caller MUST connect to `pinned_ip` directly and must NOT let the HTTP
    client re-resolve the hostname to open the real connection. Resolving
    once here for validation and again later for delivery is a DNS-rebinding
    TOCTOU: an attacker-controlled domain with a short TTL can resolve to a
    safe address for this check, then to 169.254.169.254 (or another blocked
    target) moments later when the real connection opens.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ALLOWED_WEBHOOK_SCHEMES:
        return None, f"unsupported URL scheme {parsed.scheme!r} (must be http or https)"
    if not parsed.hostname:
        return None, "URL has no host"
    try:
        ips = {info[4][0] for info in socket.getaddrinfo(parsed.hostname, None)}
    except OSError as e:
        return None, f"could not resolve host: {e}"
    for ip in ips:
        if _is_unsafe_webhook_target(ip):
            return None, f"refusing to contact {ip} (link-local/metadata/multicast/reserved address)"
    # Every candidate in `ips` was already validated as safe by the loop
    # above (it would have returned by now otherwise), so picking any one of
    # them — sorted() just for a deterministic choice — is safe. This is
    # NOT a "pick the first and check only that one" shortcut; if this ever
    # gets refactored, keep the "reject if ANY resolved IP is unsafe" check
    # ahead of the selection.
    return sorted(ips)[0], None


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """An HTTPSConnection that connects to a pre-validated literal IP — never
    re-resolving the hostname — while still doing normal TLS certificate
    verification and SNI against the real hostname. This is the IP pinning
    that closes the DNS-rebinding gap in `_validate_webhook_url`.

    Delegates the raw TCP connect to HTTPConnection.connect() (self.host is
    already the pinned IP, so no re-resolution happens there either) rather
    than reimplementing it, so TCP_NODELAY and the stdlib's connect audit
    hook still apply. Only the TLS wrap is overridden, to pass the real
    hostname as `server_hostname` instead of the pinned IP HTTPSConnection's
    default `connect()` would otherwise use — the whole reason this class
    exists. The raw socket is closed if the TLS handshake itself fails, so a
    receiver that accepts the TCP connection but never completes (or fails)
    the handshake can't leak a file descriptor per delivery attempt.
    """

    def __init__(self, ip: str, port: int, verify_hostname: str, timeout: float):
        super().__init__(ip, port, timeout=timeout)
        self._verify_hostname = verify_hostname

    def connect(self):
        http.client.HTTPConnection.connect(self)
        try:
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self._verify_hostname)
        except Exception:
            self.sock.close()
            raise


def _host_header(hostname: str, port: int, default_port: int) -> str:
    """Build a Host header value, bracketing IPv6 literals per RFC 7230 —
    `hostname:port` for an IPv6 literal (e.g. "fe80::1:8443") is ambiguous/
    malformed; it must be `[fe80::1]:8443`."""
    host = f"[{hostname}]" if ":" in hostname else hostname
    return host if port == default_port else f"{host}:{port}"


def deliver_webhook(
    url: str, payload: dict, secret: str = "", timeout: float = 5.0
) -> tuple[bool, str | None]:
    """POST the payload as JSON. Returns (ok, error). Never raises — delivery
    problems must not affect alert evaluation or the API response.

    A non-empty `secret` is sent as `Authorization: Bearer <secret>`, which
    covers ntfy access tokens and any receiver that checks a bearer credential.

    Connects to the literal IP `_validate_webhook_url` already validated
    (never re-resolving the hostname — see that function's docstring) and
    does not follow redirects: a 3xx response is returned as-is and treated
    as a non-2xx failure, since a URL that passed validation could redirect
    to a target that wouldn't have.
    """
    if not url:
        return False, "no webhook URL configured"
    pinned_ip, validation_error = _validate_webhook_url(url)
    if validation_error:
        return False, validation_error
    parsed = urllib.parse.urlparse(url)
    try:
        data = json.dumps(payload).encode("utf-8")
        default_port = 443 if parsed.scheme == "https" else 80
        port = parsed.port or default_port
        headers = {
            "Content-Type": "application/json",
            "Host": _host_header(parsed.hostname, port, default_port),
        }
        if secret:
            headers["Authorization"] = f"Bearer {secret}"
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        if parsed.scheme == "https":
            conn = _PinnedHTTPSConnection(pinned_ip, port, parsed.hostname, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(pinned_ip, port, timeout=timeout)
        try:
            conn.request("POST", path, body=data, headers=headers)
            resp = conn.getresponse()
            resp.read()  # drain fully before closing
            ok = 200 <= resp.status < 300
            return ok, None if ok else f"HTTP {resp.status}"
        finally:
            conn.close()
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def test_webhook(url: str, secret: str = "", fmt: str = "generic") -> dict:
    """Synchronous test send so the settings UI can report success/failure."""
    if fmt not in VALID_FORMATS:
        fmt = "generic"
    summary = "DNS Watch test alert — your webhook is configured correctly."
    payload = _wrap_payload(fmt, summary, [])
    if fmt == "generic":
        payload["event"] = "dns_watch_test"
    ok, err = deliver_webhook(url, payload, secret)
    return {"ok": ok, "error": err}


# --------------------------------------------------------------------------
# Rule CRUD
# --------------------------------------------------------------------------

def _row_to_rule(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"],
        "name": r["name"],
        "type": r["type"],
        "enabled": bool(r["enabled"]),
        "params": json.loads(r["params"]),
        "created_at": r["created_at"],
    }


def list_rules() -> list[dict]:
    init_store()
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM alert_rules ORDER BY created_at").fetchall()
    return [_row_to_rule(r) for r in rows]


def create_rule(name: str, type: str, params: dict, enabled: bool = True) -> dict:
    if type not in VALID_TYPES:
        raise ValueError(f"unknown rule type: {type}")
    init_store()
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO alert_rules (name, type, enabled, params, created_at) VALUES (?,?,?,?,?)",
            (name, type, 1 if enabled else 0, json.dumps(params or {}), int(time.time())),
        )
        conn.commit()
        rid = cur.lastrowid
        row = conn.execute("SELECT * FROM alert_rules WHERE id = ?", (rid,)).fetchone()
    return _row_to_rule(row)


def update_rule(rule_id: int, *, name=None, enabled=None, params=None) -> dict | None:
    init_store()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
        if not row:
            return None
        new_name = name if name is not None else row["name"]
        new_enabled = (1 if enabled else 0) if enabled is not None else row["enabled"]
        new_params = json.dumps(params) if params is not None else row["params"]
        conn.execute(
            "UPDATE alert_rules SET name=?, enabled=?, params=? WHERE id=?",
            (new_name, new_enabled, new_params, rule_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
    return _row_to_rule(row)


def delete_rule(rule_id: int) -> bool:
    init_store()
    with _connect() as conn:
        cur = conn.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
        conn.commit()
    return cur.rowcount > 0


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------

def _recently_fired(conn: sqlite3.Connection, dedup_key: str, cooldown: int, now: int) -> bool:
    row = conn.execute(
        "SELECT created_at FROM alert_events WHERE dedup_key = ? ORDER BY created_at DESC LIMIT 1",
        (dedup_key,),
    ).fetchone()
    return bool(row) and (now - row["created_at"]) < cooldown


def _dedup_exists(conn: sqlite3.Connection, dedup_key: str) -> bool:
    """True if `dedup_key` was EVER recorded before, regardless of age.

    Used instead of `_recently_fired`'s elapsed-time check for rule types
    (currently only "digest") whose dedup_key already encodes the exact
    scope that must never repeat -- e.g. "digest:<rule_id>:<period>" for a
    specific calendar period. A time-based cooldown is the wrong guard for
    that: it would either (a) be short enough to let two concurrent
    evaluate() calls both slip through before the first's digest_schedule
    update commits, or (b) be so long it re-implements a second, redundant
    period-tracking mechanism. Existence is exactly the right check: once a
    period's event exists, it must never be inserted again, no matter when.
    """
    return conn.execute(
        "SELECT 1 FROM alert_events WHERE dedup_key = ? LIMIT 1", (dedup_key,)
    ).fetchone() is not None


def _emit(pending: list[dict], rule: dict, severity: str, message: str, dedup_key: str, **extra) -> None:
    pending.append({
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "type": rule["type"],
        "severity": severity,
        "message": message,
        "dedup_key": dedup_key,
        **extra,
    })


def _resolve_rule_client(p: dict) -> str | list[str] | None:
    """Resolves a rule's optional client/tag scoping (#31) into the value
    db.py's aggregate functions accept. Mirrors main.py's
    _resolve_client_filter for live API requests; here the tag name comes
    from the rule's own stored params, not a request query string. A
    deleted/unknown tag name resolves to "no matching clients" (an empty
    list) rather than raising -- a scheduled background eval has no request
    to 400 back to, and "the tag this rule was scoped to no longer exists"
    should make the rule quietly never fire, not crash the eval loop."""
    tag = p.get("tag")
    if tag:
        return tags.get_tag_ips(tag) or []
    return p.get("client") or None


def _describe_scope(p: dict, client: str | list[str] | None) -> str:
    """Human-readable "who" for a rule's fired-event message."""
    if p.get("tag"):
        return f'tag "{p["tag"]}"'
    if isinstance(client, str) and client:
        return client
    return "all clients"


# --------------------------------------------------------------------------
# Digest scheduling
#
# Cooldown (elapsed-seconds-since-last-fire) is the wrong primitive for "once
# a day"/"once a week": it drifts with whenever the eval tick happens to land
# and has no notion of a calendar boundary. Instead we track the last UTC
# calendar period a digest was actually SENT for ("2026-07-09" for daily,
# "2026-W28" -- ISO year-week -- for weekly) per rule, in `digest_schedule`.
# The record is updated in the exact same commit as the alert_events insert
# (see evaluate()), under the same `_eval_lock` that already prevents every
# other rule type from double-firing under concurrent callers, so a crash
# between "decided to fire" and "recorded" can't double-send a digest either.
# --------------------------------------------------------------------------

def _digest_period(freq: str, now: int) -> str:
    dt = datetime.fromtimestamp(now, tz=timezone.utc)
    if freq == "weekly":
        iso_year, iso_week, _ = dt.isocalendar()
        return f"{iso_year}-W{iso_week:02d}"
    return dt.strftime("%Y-%m-%d")  # daily (also the fallback for unknown values)


def _get_digest_schedule(conn: sqlite3.Connection, rule_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT last_sent_period, last_sent_at FROM digest_schedule WHERE rule_id = ?",
        (rule_id,),
    ).fetchone()


def _events_since(conn: sqlite3.Connection, since: int) -> list[dict]:
    """Fired events after `since`, excluding other digests (a digest summarizes
    what happened, not previous digests about what happened)."""
    rows = conn.execute(
        "SELECT * FROM alert_events WHERE created_at > ? AND type != 'digest' "
        "ORDER BY created_at DESC",
        (since,),
    ).fetchall()
    return [
        {
            "id": r["id"], "rule_id": r["rule_id"], "rule_name": r["rule_name"],
            "type": r["type"], "severity": r["severity"], "message": r["message"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def _anomaly_digest_clause(anomalies: list[dict]) -> str | None:
    if not anomalies:
        return None
    counts = {"spike": 0, "silent": 0}
    for anomaly in anomalies:
        kind = anomaly.get("kind")
        if kind in counts:
            counts[kind] += 1
    breakdown = []
    if counts["spike"]:
        breakdown.append(f"{counts['spike']} spike")
    if counts["silent"]:
        breakdown.append(f"{counts['silent']} silent")
    suffix = f": {', '.join(breakdown)}" if breakdown else ""
    return f"{len(anomalies)} anomaly(ies){suffix}"


def _eval_rule(rule: dict, now: int, pending: list[dict]) -> None:
    p = rule["params"]
    if rule["type"] == "volume_threshold":
        window_min = int(p.get("window_minutes", 5))
        threshold = int(p.get("threshold", 1000))
        since = now - window_min * 60
        scope = p.get("scope", "any")
        if scope == "per_client":
            for c in db.top_clients(since, limit=100):
                if c["count"] >= threshold:
                    _emit(pending, rule, "warning",
                          f"{c['name']} made {c['count']} queries in {window_min}m "
                          f"(≥ {threshold})",
                          f"vol:{rule['id']}:{c['ip']}", client_ip=c["ip"])
        else:
            client = _resolve_rule_client(p)
            total = db.summary(client, since, None)["total_queries"]
            if total >= threshold:
                who = _describe_scope(p, client)
                _emit(pending, rule, "warning",
                      f"{total} queries from {who} in {window_min}m (≥ {threshold})",
                      f"vol:{rule['id']}:{p.get('tag') or p.get('client') or 'any'}",
                      client_ip=client if isinstance(client, str) else None)

    elif rule["type"] == "new_device":
        window_min = int(p.get("window_minutes", 1440))
        since = now - window_min * 60
        for c in db.new_clients(since):
            _emit(pending, rule, "info",
                  f"New device seen: {c['name']} ({c['ip']})",
                  f"new:{rule['id']}:{c['ip']}", client_ip=c["ip"])

    elif rule["type"] == "domain_keyword":
        keyword = (p.get("keyword") or "").strip()
        if not keyword:
            return
        window_min = int(p.get("window_minutes", 60))
        min_count = int(p.get("min_count", 1))
        since = now - window_min * 60
        client = _resolve_rule_client(p)
        count = db.count_queries(client, keyword, None, since, None)
        if count >= min_count:
            who = _describe_scope(p, client)
            scope_suffix = "" if who == "all clients" else f" from {who}"
            _emit(pending, rule, "warning",
                  f'{count} queries matching "{keyword}"{scope_suffix} in {window_min}m (≥ {min_count})',
                  f"kw:{rule['id']}", client_ip=client if isinstance(client, str) else None)

    elif rule["type"] == "new_vendor":
        window_min = int(p.get("window_minutes", 1440))
        since = now - window_min * 60
        for c in db.vendor_alert_candidates(since):
            if c["kind"] == "unrecognized":
                message = f"Device with unrecognized vendor joined: {c['name']} ({c['ip']})"
            else:
                message = f"New vendor on the network: {c['vendor']} — {c['name']} ({c['ip']})"
            _emit(pending, rule, "info", message, f"vendor:{rule['id']}:{c['ip']}", client_ip=c["ip"])

    elif rule["type"] == "doh_provider":
        # See db.DOH_PROVIDER_DOMAINS's module note: this detects a client
        # querying a known DoH/DoT provider's OWN domain (setup/fallback
        # lookups Pi-hole can still see), NOT actual DoH/VPN bypass traffic
        # -- that traffic, by definition, never reaches Pi-hole at all.
        window_min = int(p.get("window_minutes", 60))
        since = now - window_min * 60
        for hit in db.doh_provider_hits(since):
            _emit(pending, rule, "warning",
                  f"{hit['name']} ({hit['ip']}) queried known DoH/DoT provider domain "
                  f"{hit['provider']} ({hit['count']}x in {window_min}m) — this device may be "
                  f"setting up or falling back to a DNS resolver that bypasses Pi-hole, "
                  f"not confirmation that it has",
                  f"doh:{rule['id']}:{hit['ip']}:{hit['provider']}",
                  client_ip=hit["ip"], domain=hit["provider"])

    elif rule["type"] == "first_seen_domain":
        # Domain-keyed sibling of new_device/new_vendor (#32): fires when a
        # domain is queried that NO client has ever queried before,
        # network-wide -- backed by rollups.new_domains(), an incrementally
        # maintained table (domain cardinality is unbounded, unlike a LAN's
        # handful of clients, so this can't be a live scan the way
        # new_clients() is). None (not []) means the rollup isn't ready yet
        # -- e.g. before the first backfill completes -- and must be treated
        # as "no signal this tick", not "no new domains".
        window_min = int(p.get("window_minutes", 1440))
        since = now - window_min * 60
        new_doms = rollups.new_domains(since)
        if new_doms is None:
            return
        for d in new_doms:
            _emit(pending, rule, "info",
                  f"New domain seen for the first time: {d['domain']}",
                  f"domain:{rule['id']}:{d['domain']}", domain=d["domain"])

    elif rule["type"] == "correlated_new_device_domain":
        # A brand-new device querying a domain no client has EVER queried
        # before, close together in time, is a much stronger signal than
        # either "new device" or "first-seen domain" alone (#46) -- e.g. a
        # freshly-plugged-in IoT device immediately phoning an unrecognized
        # domain. Built entirely from new_clients()/new_domains(), which
        # new_device/first_seen_domain already compute -- no new collection.
        window_min = int(p.get("window_minutes", 15))
        since = now - window_min * 60
        new_doms = rollups.new_domains(since)
        if new_doms is None:
            return  # rollup not backfilled yet -- no signal this tick, not "no matches"
        new_clients_by_ip = {c["ip"]: c for c in db.new_clients(since)}
        if not new_clients_by_ip:
            return
        for d in new_doms:
            # +1: domain_queriers' upper bound is exclusive (timestamp <
            # until), so a query landing in the SAME second this tick
            # evaluates at -- entirely plausible, since that's often exactly
            # when a just-joined device's first query would be seen -- must
            # not be excluded by the boundary itself.
            queriers = db.domain_queriers(d["domain"], since, now + 1)
            for ip in queriers:
                c = new_clients_by_ip.get(ip)
                if c is None:
                    continue
                if abs(c["first_seen"] - d["first_seen"]) > window_min * 60:
                    continue  # both are "new", but not close enough together in time
                _emit(pending, rule, "warning",
                      f"New device {c['name']} ({ip}) queried newly-seen domain "
                      f"{d['domain']} within {window_min}m of joining the network",
                      f"corr:{rule['id']}:{ip}:{d['domain']}",
                      client_ip=ip, domain=d["domain"])

    elif rule["type"] == "device_quiet":
        # Fire when a client that was active in the *prior* window has gone
        # silent in the *recent* one — device unplugged, offline, or blocked.
        window_min = int(p.get("window_minutes", 60))
        min_prior = int(p.get("min_prior", 20))
        recent = {c["ip"]: c["count"] for c in db.client_counts(now - window_min * 60, now)}
        prior = db.client_counts(now - 2 * window_min * 60, now - window_min * 60)
        for c in prior:
            if c["count"] >= min_prior and recent.get(c["ip"], 0) == 0:
                # Shared with detect_anomalies()'s "silent" case (#6/#7) so the
                # Alerts and Anomalies panels never disagree about the same
                # client going quiet.
                note = db.quiet_presence_note(c["ip"])
                _emit(pending, rule, "warning",
                      f"{c['name']} went quiet — {c['count']} queries in the prior "
                      f"{window_min}m, none since ({note})",
                      f"quiet:{rule['id']}:{c['ip']}", client_ip=c["ip"])

    elif rule["type"] == "digest":
        # Periodic "here's what changed" summary, not a condition trip -- see
        # the digest scheduling block above for why this is gated on a
        # calendar period rather than the cooldown every other rule type uses.
        freq = p.get("period", "daily")
        if freq not in ("daily", "weekly"):
            freq = "daily"
        period = _digest_period(freq, now)
        with _connect() as conn:
            sched = _get_digest_schedule(conn, rule["id"])
            if sched and sched["last_sent_period"] == period:
                return  # already sent this period; nothing to do
            since = sched["last_sent_at"] if sched else now - (86400 if freq == "daily" else 7 * 86400)
            events = _events_since(conn, since)
        new_devices = db.new_clients(since)
        anomalies = db.detect_anomalies()
        parts = []
        if events:
            parts.append(f"{len(events)} alert(s) fired")
        if new_devices:
            names = ", ".join(c["name"] for c in new_devices[:10])
            parts.append(f"{len(new_devices)} new device(s): {names}")
        anomaly_clause = _anomaly_digest_clause(anomalies)
        if anomaly_clause:
            parts.append(anomaly_clause)
        summary = "; ".join(parts) if parts else "no alerts or new devices"
        message = f"{freq.capitalize()} digest — {summary} since the last digest"
        _emit(pending, rule, "info", message, f"digest:{rule['id']}:{period}",
              digest_period=period)


def evaluate() -> list[dict]:
    """Evaluate all enabled rules; persist and return newly-fired events.

    Safe to call from both the background scheduler and request handlers — the
    module-level lock serialises the dedup-check-then-insert so the same event
    can't be written twice by concurrent callers.
    """
    init_store()
    now = int(time.time())
    rules = [r for r in list_rules() if r["enabled"]]
    pending: list[dict] = []
    for rule in rules:
        try:
            _eval_rule(rule, now, pending)
        except Exception:  # noqa: BLE001 — one broken rule shouldn't kill the rest
            continue

    fired: list[dict] = []
    with _eval_lock, _connect() as conn:
        for ev in pending:
            snoozed_until = _snoozed_until(conn, ev["dedup_key"])
            if snoozed_until and snoozed_until > now:
                continue
            if ev["type"] == "digest":
                if _dedup_exists(conn, ev["dedup_key"]):
                    continue
            else:
                cooldown = DEFAULT_COOLDOWN.get(ev["type"], 900)
                if _recently_fired(conn, ev["dedup_key"], cooldown, now):
                    continue
            conn.execute(
                "INSERT INTO alert_events "
                "(rule_id, rule_name, type, severity, message, dedup_key, created_at, client_ip, domain) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (ev["rule_id"], ev["rule_name"], ev["type"], ev["severity"],
                 ev["message"], ev["dedup_key"], now, ev.get("client_ip"), ev.get("domain")),
            )
            if ev["type"] == "digest":
                # Same commit as the event insert above -- a crash between
                # "decided to fire" and "recorded" can't double-send, since
                # either both of these land or neither does.
                conn.execute(
                    "INSERT INTO digest_schedule (rule_id, last_sent_period, last_sent_at) "
                    "VALUES (?,?,?) ON CONFLICT(rule_id) DO UPDATE SET "
                    "last_sent_period = excluded.last_sent_period, last_sent_at = excluded.last_sent_at",
                    (ev["rule_id"], ev["digest_period"], now),
                )
            fired.append({**ev, "created_at": now})
        conn.commit()

    # Push newly-fired alerts out-of-band if a webhook is enabled. Done on a
    # daemon thread so a slow or unreachable endpoint can't stall the /api/alerts
    # response (which the dashboard polls every few seconds).
    if fired:
        settings = _get_raw_settings()  # needs the real secret to deliver
        if settings["webhook_enabled"] and settings["webhook_url"]:
            payload = _wrap_payload(settings["webhook_format"], _summary(fired), fired)
            threading.Thread(
                target=deliver_webhook,
                args=(settings["webhook_url"], payload, settings["webhook_secret"]),
                daemon=True,
            ).start()

    return fired


def list_events(limit: int = 50) -> list[dict]:
    init_store()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM alert_events ORDER BY created_at DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {
            "id": r["id"],
            "rule_id": r["rule_id"],
            "rule_name": r["rule_name"],
            "type": r["type"],
            "severity": r["severity"],
            "message": r["message"],
            "created_at": r["created_at"],
            # dedup_key (#42) and client_ip/domain (#43) let the frontend act
            # on a specific event -- snooze just this recurrence, or deep-link
            # to the client/domain it's about -- instead of only rendering
            # `message` as inert text.
            "dedup_key": r["dedup_key"],
            "client_ip": r["client_ip"],
            "domain": r["domain"],
        }
        for r in rows
    ]


def snooze_event(event_id: int, until: int) -> dict | None:
    """Silence future recurrences of this specific fired event's dedup_key
    until `until` (unix ts), without touching the rule itself or any other
    client/domain/tag it also watches (#42). Returns the affected
    dedup_key/until, or None if `event_id` doesn't exist.

    Deliberately keyed on dedup_key rather than event_id/rule_id: it's the
    exact granularity every rule type already uses to tell "this specific
    recurrence" apart (e.g. "vendor:12:192.168.1.50" is one device's alert
    under one rule, not the whole rule) -- see the module note by DEFAULT_COOLDOWN.
    """
    init_store()
    with _connect() as conn:
        row = conn.execute(
            "SELECT dedup_key FROM alert_events WHERE id = ?", (event_id,)
        ).fetchone()
        if row is None:
            return None
        dedup_key = row["dedup_key"]
        conn.execute(
            "INSERT INTO alert_snoozes (dedup_key, snoozed_until) VALUES (?, ?) "
            "ON CONFLICT(dedup_key) DO UPDATE SET snoozed_until = excluded.snoozed_until",
            (dedup_key, until),
        )
        conn.commit()
    return {"dedup_key": dedup_key, "snoozed_until": until}


def unsnooze(dedup_key: str) -> bool:
    """True if an active snooze was actually removed, so main.py can 404 on
    an unknown/already-expired key."""
    init_store()
    with _connect() as conn:
        cur = conn.execute("DELETE FROM alert_snoozes WHERE dedup_key = ?", (dedup_key,))
        conn.commit()
        return cur.rowcount > 0


def _snoozed_until(conn: sqlite3.Connection, dedup_key: str) -> int | None:
    row = conn.execute(
        "SELECT snoozed_until FROM alert_snoozes WHERE dedup_key = ?", (dedup_key,)
    ).fetchone()
    return row["snoozed_until"] if row else None
