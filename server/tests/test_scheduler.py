"""The background scheduler tick must run alert evaluation, the incremental
rollup-cache refresh, the periodic full reconciliation, AND the reverse-DNS
resolution pass, and a failure in any one must not kill the loop or prevent
the others from running (matching the existing alerts.evaluate()
never-die-on-a-transient-error contract)."""

from __future__ import annotations

from app import main


def _run_one_tick(monkeypatch):
    """Let _alert_scheduler's loop body run exactly once, then stop."""
    main._scheduler_stop.clear()

    def _stop_after_wait(_timeout):
        main._scheduler_stop.set()

    monkeypatch.setattr(main._scheduler_stop, "wait", _stop_after_wait)
    main._alert_scheduler()


def _mock_resolve(monkeypatch, calls):
    """resolve.resolve_batch() needs a candidate list from db.clients_missing_name();
    mock both so the resolve step doesn't hit the (absent-in-tests) Pi-hole db."""
    monkeypatch.setattr(main.db, "clients_missing_name", lambda: [])
    monkeypatch.setattr(main.resolve, "resolve_batch", lambda ips: calls.append("resolve"))


def test_tick_runs_alerts_rollups_reconcile_and_resolve(monkeypatch):
    calls = []
    monkeypatch.setattr(main.alerts, "evaluate", lambda: calls.append("alerts"))
    monkeypatch.setattr(main.rollups, "refresh_rollups", lambda: calls.append("rollups"))
    monkeypatch.setattr(main.rollups, "reconcile_rollups", lambda: calls.append("reconcile"))
    _mock_resolve(monkeypatch, calls)

    _run_one_tick(monkeypatch)

    assert calls == ["alerts", "rollups", "reconcile", "resolve"]


def test_rollup_failure_does_not_block_alerts_reconcile_resolve_or_kill_loop(monkeypatch):
    calls = []
    monkeypatch.setattr(main.alerts, "evaluate", lambda: calls.append("alerts"))
    monkeypatch.setattr(main.rollups, "reconcile_rollups", lambda: calls.append("reconcile"))
    _mock_resolve(monkeypatch, calls)

    def _boom():
        raise RuntimeError("simulated rollup refresh failure")

    monkeypatch.setattr(main.rollups, "refresh_rollups", _boom)

    _run_one_tick(monkeypatch)  # must not raise

    assert calls == ["alerts", "reconcile", "resolve"]


def test_reconcile_failure_does_not_block_others_or_kill_loop(monkeypatch):
    calls = []
    monkeypatch.setattr(main.alerts, "evaluate", lambda: calls.append("alerts"))
    monkeypatch.setattr(main.rollups, "refresh_rollups", lambda: calls.append("rollups"))
    _mock_resolve(monkeypatch, calls)

    def _boom():
        raise RuntimeError("simulated reconciliation failure")

    monkeypatch.setattr(main.rollups, "reconcile_rollups", _boom)

    _run_one_tick(monkeypatch)  # must not raise

    assert calls == ["alerts", "rollups", "resolve"]


def test_alert_failure_does_not_block_rollup_reconcile_or_resolve(monkeypatch):
    calls = []
    monkeypatch.setattr(main.rollups, "refresh_rollups", lambda: calls.append("rollups"))
    monkeypatch.setattr(main.rollups, "reconcile_rollups", lambda: calls.append("reconcile"))
    _mock_resolve(monkeypatch, calls)

    def _boom():
        raise RuntimeError("simulated alert failure")

    monkeypatch.setattr(main.alerts, "evaluate", _boom)

    _run_one_tick(monkeypatch)  # must not raise

    assert calls == ["rollups", "reconcile", "resolve"]


def test_resolve_failure_does_not_block_others_or_kill_loop(monkeypatch):
    calls = []
    monkeypatch.setattr(main.alerts, "evaluate", lambda: calls.append("alerts"))
    monkeypatch.setattr(main.rollups, "refresh_rollups", lambda: calls.append("rollups"))
    monkeypatch.setattr(main.rollups, "reconcile_rollups", lambda: calls.append("reconcile"))
    monkeypatch.setattr(main.db, "clients_missing_name", lambda: [])

    def _boom(_ips):
        raise RuntimeError("simulated resolve failure")

    monkeypatch.setattr(main.resolve, "resolve_batch", _boom)

    _run_one_tick(monkeypatch)  # must not raise

    assert calls == ["alerts", "rollups", "reconcile"]
