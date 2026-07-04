"""Shared pytest fixtures.

Every db-facing test runs against a freshly-built synthetic Pi-hole FTL database,
parametrized over the schema shapes DNS Watch supports, so a change that only
works on one schema fails loudly here:

  - "new": v6-style `queries.client_id` + a `client` table.
  - "old": `queries.client` TEXT + a `network` table carrying the name.
  - "real": what a REAL Pi-hole v6 on-disk DB actually looks like — `queries.client`
    is a TEXT IP with REAL (fractional-second) timestamps, the `network` table has
    NO name column, and the client name lives on `network_addresses.name`. This
    variant guards two regressions that only surfaced against a real DB snapshot:
    selecting `n.name` off a nameless `network` table (500s), and float-division
    time bucketing that zeroed every timeseries/sparkline bucket.
"""

from __future__ import annotations

import json
import os
import random
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

# Keep the background alert scheduler out of the test process; tests drive
# evaluate() directly. Must be set before app.main is imported.
os.environ.setdefault("ALERT_EVAL_INTERVAL_SECONDS", "0")
os.environ.setdefault("PIHOLE_DB_PATH", "/nonexistent/pihole-FTL.db")

import pytest

CLIENTS = [
    ("192.168.1.10", "laptop"),
    ("192.168.1.11", "phone"),
    ("192.168.1.12", "tv"),
    ("192.168.1.13", None),  # unnamed -> should fall back to IP
]
DOMAINS = ["ads.example.com", "cdn.site.net", "api.service.io",
           "tracker.bad.co", "news.site.com", "video.stream.tv"]
# 2/3 allowed (forwarded/cache), 1/5 blocked (gravity) — mix guarantees both.
STATUSES = [2, 3, 1, 5, 2, 2, 3]
TYPES = [1, 2, 16]  # A, AAAA, HTTPS


def build_ftl(path: str, schema: str, n: int = 500, seed: int = 1) -> None:
    random.seed(seed)
    now = int(time.time())
    conn = sqlite3.connect(path)
    c = conn.cursor()
    if schema == "new":
        c.execute("CREATE TABLE client (id INTEGER PRIMARY KEY, ip TEXT, name TEXT)")
        for i, (ip, name) in enumerate(CLIENTS, 1):
            c.execute("INSERT INTO client VALUES (?,?,?)", (i, ip, name))
        c.execute("CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp INTEGER, "
                  "type INTEGER, status INTEGER, domain TEXT, client_id INTEGER)")
        for _ in range(n):
            c.execute(
                "INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,?)",
                (now - random.randint(0, 3600), random.choice(TYPES),
                 random.choice(STATUSES), random.choice(DOMAINS), random.randint(1, len(CLIENTS))),
            )
    elif schema == "real":
        # Faithful to a REAL Pi-hole v6 on-disk DB: queries.client is a TEXT IP
        # with REAL (fractional-second) timestamps, the `network` table has NO
        # name column, and the client name lives on network_addresses.name.
        c.execute("CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp REAL, "
                  "type INTEGER, status INTEGER, domain TEXT, client TEXT)")
        c.execute("CREATE TABLE network (id INTEGER PRIMARY KEY, hwaddr TEXT, macVendor TEXT)")
        c.execute("CREATE TABLE network_addresses (network_id INTEGER, ip TEXT, "
                  "lastSeen INTEGER, name TEXT, nameUpdated INTEGER)")
        for i, (ip, name) in enumerate(CLIENTS, 1):
            c.execute("INSERT INTO network (id, hwaddr, macVendor) VALUES (?,?,?)",
                      (i, f"de:ad:be:ef:00:{i:02x}", "TestVendor"))
            c.execute(
                "INSERT INTO network_addresses (network_id, ip, lastSeen, name, nameUpdated) "
                "VALUES (?,?,?,?,?)", (i, ip, now, name, now))
        for _ in range(n):
            # +random() forces a fractional part so the float-division bucketing
            # bug actually manifests (integer timestamps would hide it).
            c.execute(
                "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                (float(now - random.randint(0, 3600)) + random.random(), random.choice(TYPES),
                 random.choice(STATUSES), random.choice(DOMAINS), random.choice(CLIENTS)[0]),
            )
    else:
        c.execute("CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp INTEGER, "
                  "type INTEGER, status INTEGER, domain TEXT, client TEXT)")
        c.execute("CREATE TABLE network (id INTEGER PRIMARY KEY, name TEXT)")
        c.execute("CREATE TABLE network_addresses (ip TEXT, network_id INTEGER)")
        for i, (ip, name) in enumerate(CLIENTS, 1):
            c.execute("INSERT INTO network VALUES (?,?)", (i, name))
            c.execute("INSERT INTO network_addresses VALUES (?,?)", (ip, i))
        for _ in range(n):
            c.execute(
                "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                (now - random.randint(0, 3600), random.choice(TYPES),
                 random.choice(STATUSES), random.choice(DOMAINS), random.choice(CLIENTS)[0]),
            )
    conn.commit()
    conn.close()


def add_client_with_hourly_pattern(
    path: str, schema: str, ip: str, name: str, counts_per_hour: list[int], now: int | None = None
) -> None:
    """Add one client with an EXACT hourly query-count pattern, on top of
    whatever `build_ftl()` already populated.

    `build_ftl()`'s own clients are only ever useful for "normal recent
    traffic" tests — their first-ever query is always within the last hour,
    so anomaly-detection tests (which need a real 24h+ history to even be
    eligible, per the new-device exclusion) can't use them. This gives
    anomaly tests deterministic control instead of relying on randomized
    single-hour data.

    `counts_per_hour[-1]` is the most recent hour (ending at `now`),
    `counts_per_hour[0]` the oldest — so the caller can build a steady
    baseline followed by a specific silent/spike/normal recent window.
    """
    now = now if now is not None else int(time.time())
    conn = sqlite3.connect(path)
    c = conn.cursor()

    if schema == "new":
        next_id = c.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM client").fetchone()[0]
        c.execute("INSERT INTO client (id, ip, name) VALUES (?,?,?)", (next_id, ip, name))
    elif schema == "real":
        next_id = c.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM network").fetchone()[0]
        c.execute("INSERT INTO network (id, hwaddr, macVendor) VALUES (?,?,?)",
                  (next_id, f"aa:bb:cc:dd:ee:{next_id:02x}", "TestVendor"))
        c.execute(
            "INSERT INTO network_addresses (network_id, ip, lastSeen, name, nameUpdated) VALUES (?,?,?,?,?)",
            (next_id, ip, now, name, now))
    else:  # old
        next_id = c.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM network").fetchone()[0]
        c.execute("INSERT INTO network VALUES (?,?)", (next_id, name))
        c.execute("INSERT INTO network_addresses VALUES (?,?)", (ip, next_id))

    n_hours = len(counts_per_hour)
    for hour_idx, count in enumerate(counts_per_hour):
        hour_start = now - (n_hours - hour_idx) * 3600
        for _ in range(count):
            ts = hour_start + random.uniform(0, 3599)
            if schema == "new":
                c.execute(
                    "INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,?)",
                    (int(ts), 1, 2, "steady.example.com", next_id),
                )
            else:
                c.execute(
                    "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                    (ts if schema == "real" else int(ts), 1, 2, "steady.example.com", ip),
                )
    conn.commit()
    conn.close()


def insert_queries_at_timestamp(path: str, schema: str, ts: float, n: int) -> list[int]:
    """Insert `n` rows all sharing the EXACT same timestamp `ts`, for the
    first client `build_ftl()` already created (CLIENTS[0]). Returns the
    inserted rows' ids in insertion order.

    `build_ftl()`'s randomized timestamps (spread across an hour) essentially
    never collide, so a tail-cursor test needs this to genuinely exercise the
    same-timestamp tie-breaking a real burst of near-simultaneous queries
    would produce — a spread-out fixture could never catch a bug there.
    """
    conn = sqlite3.connect(path)
    c = conn.cursor()
    ids = []
    for i in range(n):
        domain = f"burst-{i}.example.com"
        if schema == "new":
            c.execute(
                "INSERT INTO queries (timestamp,type,status,domain,client_id) VALUES (?,?,?,?,?)",
                (ts, 1, 2, domain, 1),
            )
        else:
            c.execute(
                "INSERT INTO queries (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
                (ts, 1, 2, domain, CLIENTS[0][0]),
            )
        ids.append(c.lastrowid)
    conn.commit()
    conn.close()
    return ids


def truth(path: str):
    """A plain read-only connection for computing ground truth in assertions."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


@pytest.fixture(params=["new", "old", "real"])
def ftl(request, tmp_path, monkeypatch):
    path = str(tmp_path / "pihole-FTL.db")
    build_ftl(path, request.param)
    from app import db
    monkeypatch.setattr(db, "DB_PATH", path)
    db.detect_schema.cache_clear()
    yield {"path": path, "schema": request.param}
    db.detect_schema.cache_clear()


@pytest.fixture
def store(tmp_path, monkeypatch):
    from app import alerts
    path = str(tmp_path / "dnswatch.db")
    monkeypatch.setattr(alerts, "STORE_PATH", path)
    return path


@pytest.fixture
def client(ftl, store):
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


@pytest.fixture
def webhook():
    """A throwaway HTTP server capturing POSTs; yields (url, received list)."""
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            received.append({
                "auth": self.headers.get("Authorization"),
                "body": json.loads(self.rfile.read(n) or b"{}"),
            })
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/hook", received
    srv.shutdown()
