"""Shared pytest fixtures.

Every db-facing test runs against a freshly-built synthetic Pi-hole FTL database,
parametrized over BOTH schema shapes DNS Watch supports (old `queries.client`
text column + `network` tables, and new v6 `client_id` + `client` table), so a
change that only works on one schema fails loudly here.
"""

from __future__ import annotations

import os
import random
import sqlite3
import time

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


def truth(path: str):
    """A plain read-only connection for computing ground truth in assertions."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


@pytest.fixture(params=["new", "old"])
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
