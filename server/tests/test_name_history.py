"""Device name-change history (name_history.py) -- both write sources
(names.py manual overrides, resolve.py's reverse-DNS cache) and the read
path. Pi-hole's own name has no write hook here at all (see the module
docstring), so there's nothing to test for that source in v1.
"""

from __future__ import annotations

import pytest

from app import name_history, names, resolve


@pytest.fixture(autouse=True)
def _isolated_stores(tmp_path, monkeypatch):
    monkeypatch.setattr(name_history, "STORE_PATH", str(tmp_path / "name_history.db"))
    monkeypatch.setattr(names, "STORE_PATH", str(tmp_path / "names.db"))
    monkeypatch.setattr(resolve, "STORE_PATH", str(tmp_path / "resolve.db"))


def test_record_change_appends_and_history_for_returns_most_recent_first():
    name_history.record_change("192.168.1.10", "manual", None, "Laptop")
    name_history.record_change("192.168.1.10", "manual", "Laptop", "Steve's Laptop")

    hist = name_history.history_for("192.168.1.10")
    assert len(hist) == 2
    assert hist[0]["old_name"] == "Laptop" and hist[0]["new_name"] == "Steve's Laptop"
    assert hist[1]["old_name"] is None and hist[1]["new_name"] == "Laptop"


def test_record_change_is_a_noop_when_unchanged():
    name_history.record_change("192.168.1.10", "manual", "Same", "Same")
    assert name_history.history_for("192.168.1.10") == []


def test_history_for_scoped_to_one_ip():
    name_history.record_change("192.168.1.10", "manual", None, "Laptop")
    name_history.record_change("192.168.1.11", "manual", None, "Phone")
    assert len(name_history.history_for("192.168.1.10")) == 1
    assert len(name_history.history_for("192.168.1.11")) == 1


# --------------------------------------------------------------------------
# names.py hooks
# --------------------------------------------------------------------------


def test_set_name_logs_manual_change():
    names.set_name("192.168.1.10", "Laptop")
    hist = name_history.history_for("192.168.1.10")
    assert len(hist) == 1
    assert hist[0]["source"] == "manual"
    assert hist[0]["old_name"] is None
    assert hist[0]["new_name"] == "Laptop"


def test_set_name_rename_logs_old_and_new():
    names.set_name("192.168.1.10", "Laptop")
    names.set_name("192.168.1.10", "Steve's Laptop")
    hist = name_history.history_for("192.168.1.10")
    assert len(hist) == 2
    assert hist[0]["old_name"] == "Laptop"
    assert hist[0]["new_name"] == "Steve's Laptop"


def test_set_name_same_value_does_not_log_again():
    names.set_name("192.168.1.10", "Laptop")
    names.set_name("192.168.1.10", "Laptop")
    assert len(name_history.history_for("192.168.1.10")) == 1


def test_delete_name_logs_manual_removal():
    names.set_name("192.168.1.10", "Laptop")
    names.delete_name("192.168.1.10")
    hist = name_history.history_for("192.168.1.10")
    assert len(hist) == 2
    assert hist[0]["old_name"] == "Laptop"
    assert hist[0]["new_name"] is None


def test_delete_unknown_name_does_not_log():
    assert names.delete_name("192.168.1.99") is False
    assert name_history.history_for("192.168.1.99") == []


# --------------------------------------------------------------------------
# resolve.py hooks
# --------------------------------------------------------------------------


def test_resolve_batch_logs_first_successful_resolution(monkeypatch):
    monkeypatch.setattr(resolve, "_lookup", lambda ip, timeout=None: "phone.lan")
    resolve.resolve_batch(["192.168.1.5"], now=1000)

    hist = name_history.history_for("192.168.1.5")
    assert len(hist) == 1
    assert hist[0]["source"] == "resolved"
    assert hist[0]["old_name"] is None
    assert hist[0]["new_name"] == "phone.lan"


def test_resolve_batch_does_not_log_repeated_same_success(monkeypatch):
    monkeypatch.setattr(resolve, "_lookup", lambda ip, timeout=None: "phone.lan")
    resolve.resolve_batch(["192.168.1.5"], now=1000)
    # Second tick, well past the success-refresh window, same result.
    resolve.resolve_batch(["192.168.1.5"], now=1000 + resolve._SUCCESS_REFRESH_SECONDS + 1)

    assert len(name_history.history_for("192.168.1.5")) == 1


def test_resolve_batch_logs_hostname_change(monkeypatch):
    monkeypatch.setattr(resolve, "_lookup", lambda ip, timeout=None: "phone.lan")
    resolve.resolve_batch(["192.168.1.5"], now=1000)
    monkeypatch.setattr(resolve, "_lookup", lambda ip, timeout=None: "phone2.lan")
    resolve.resolve_batch(["192.168.1.5"], now=1000 + resolve._SUCCESS_REFRESH_SECONDS + 1)

    hist = name_history.history_for("192.168.1.5")
    assert len(hist) == 2
    assert hist[0]["old_name"] == "phone.lan"
    assert hist[0]["new_name"] == "phone2.lan"


def test_resolve_batch_logs_transition_to_failure(monkeypatch):
    monkeypatch.setattr(resolve, "_lookup", lambda ip, timeout=None: "phone.lan")
    resolve.resolve_batch(["192.168.1.5"], now=1000)
    monkeypatch.setattr(resolve, "_lookup", lambda ip, timeout=None: None)
    resolve.resolve_batch(["192.168.1.5"], now=1000 + resolve._SUCCESS_REFRESH_SECONDS + 1)

    hist = name_history.history_for("192.168.1.5")
    assert len(hist) == 2
    assert hist[0]["old_name"] == "phone.lan"
    assert hist[0]["new_name"] is None


def test_resolve_batch_does_not_log_repeated_failure(monkeypatch):
    monkeypatch.setattr(resolve, "_lookup", lambda ip, timeout=None: None)
    resolve.resolve_batch(["192.168.1.6"], now=1000)
    resolve.resolve_batch(["192.168.1.6"], now=1000 + resolve._FAILURE_BACKOFF[0] + 1)

    assert name_history.history_for("192.168.1.6") == []
