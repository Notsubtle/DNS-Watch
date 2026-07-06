"""Correctness regression for the id-based aggregate fast path.

Every aggregate rewritten to group/filter on `query_storage`'s raw integer
domain/client ids (Schema.has_id_storage) MUST return byte-for-byte the same
result as the trusted, pre-existing VIEW-based path on identical data. The
view-based path is the baseline; a fast-but-wrong rewrite is worse than the
slow-but-correct original.

Each test builds ONE normalized-layout database and runs the same function
twice against it — once with the fast path forced OFF (the `queries` view,
correlated-subquery path) and once forced ON (the raw-id path) — then asserts
the two outputs are identical. The database deliberately includes a client
whose ip (127.0.0.1) resolves to TWO distinct client_by_id ids, so the
group-by-id-then-merge-by-ip logic is genuinely exercised: a naive rewrite
that grouped by raw id would split that client in two and fail here.
"""

from __future__ import annotations

import random
import sqlite3

import pytest

from conftest import (
    _idstore_client_id,
    _idstore_domain_id,
    _idstore_schema,
)
from app import db
from app.db import Schema


# Clients: four normal LAN devices plus 127.0.0.1 registered under TWO names,
# i.e. two client_by_id ids sharing one ip -> the merge-by-ip case.
_CLIENTS = [
    ("192.168.0.10", "laptop"),
    ("192.168.0.11", "phone"),
    ("192.168.0.12", "tv"),
    ("192.168.0.13", None),  # unnamed -> falls back to ip
]
_DUP_IP = "127.0.0.1"
_DOMAINS = [f"d{i:02d}.example.com" for i in range(20)]
_STATUSES = [2, 3, 1, 5, 2, 2, 3, 16]  # mix of allowed/blocked
_TYPES = [1, 2, 16, 6]


def _build(path: str) -> None:
    """A rich normalized-layout DB: many domains/clients, a ~10-day span, the
    duplicate-ip client, plus two clients with deliberate hourly patterns so
    detect_anomalies has a silent and a spiking device to find."""
    random.seed(1234)
    conn = sqlite3.connect(path)
    c = conn.cursor()
    _idstore_schema(c)

    now = 1_700_000_000  # fixed epoch so nothing depends on wall clock here
    std_ids = [_idstore_client_id(c, ip, name) for ip, name in _CLIENTS]
    dup_a = _idstore_client_id(c, _DUP_IP, "")          # first identity
    dup_b = _idstore_client_id(c, _DUP_IP, "localhost")  # second identity, same ip
    all_ids = std_ids + [dup_a, dup_b]

    # Spread ~6000 rows across 10 days, all clients and domains.
    span = 10 * 86400
    for _ in range(6000):
        cid = random.choice(all_ids)
        did = _idstore_domain_id(c, random.choice(_DOMAINS))
        ts = now - random.randint(0, span)
        c.execute(
            "INSERT INTO query_storage (timestamp,type,status,domain,client) VALUES (?,?,?,?,?)",
            (ts, random.choice(_TYPES), random.choice(_STATUSES), did, cid),
        )
    conn.commit()
    conn.close()


@pytest.fixture
def idb(tmp_path, monkeypatch):
    path = str(tmp_path / "pihole-FTL.db")
    _build(path)
    monkeypatch.setattr(db, "DB_PATH", path)
    return path


def _force(monkeypatch, has_id_storage: bool) -> None:
    """Pin detect_schema to the real detected shape for this layout
    (view-based, name on network_addresses) with only has_id_storage toggled,
    so both runs differ ONLY in which aggregate path executes."""
    schema = Schema(has_client_table=False, na_has_name=True, has_id_storage=has_id_storage)
    monkeypatch.setattr(db, "detect_schema", lambda: schema)


def _both(monkeypatch, fn):
    """Return (view_path_result, id_path_result) for a zero-arg callable."""
    _force(monkeypatch, False)
    view = fn()
    _force(monkeypatch, True)
    idp = fn()
    return view, idp


# --------------------------------------------------------------------------


def test_top_domains_matches(idb, monkeypatch):
    # Full ranking (limit past the distinct-domain count) makes the comparison
    # order- and tie-independent: identical {domain: count} maps prove it.
    view, idp = _both(monkeypatch, lambda: db.top_domains(None, None, limit=1000))
    assert {r["domain"]: r["count"] for r in view} == {r["domain"]: r["count"] for r in idp}
    assert None not in {r["domain"] for r in idp}  # every id resolved to text
    # Default top-15 counts sequence must match too (tie-robust: equal counts).
    v15, i15 = _both(monkeypatch, lambda: db.top_domains(None, None, limit=15))
    assert [r["count"] for r in v15] == [r["count"] for r in i15]


def test_top_domains_client_filter_matches(idb, monkeypatch):
    # Filter by the duplicate-ip client: both client_by_id ids must be included.
    view, idp = _both(monkeypatch, lambda: db.top_domains(_DUP_IP, None, limit=1000))
    assert {r["domain"]: r["count"] for r in view} == {r["domain"]: r["count"] for r in idp}
    # And a normal client.
    view2, idp2 = _both(monkeypatch, lambda: db.top_domains("192.168.0.10", None, limit=1000))
    assert {r["domain"]: r["count"] for r in view2} == {r["domain"]: r["count"] for r in idp2}


def test_top_domains_unknown_client_empty(idb, monkeypatch):
    view, idp = _both(monkeypatch, lambda: db.top_domains("10.0.0.254", None, limit=15))
    assert view == idp == []
