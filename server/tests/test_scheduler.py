"""The background scheduler tick must run alert evaluation, the incremental
rollup-cache refresh, AND the periodic full reconciliation, and a failure in
any one must not kill the loop or prevent the others from running (matching the
existing alerts.evaluate() never-die-on-a-transient-error contract)."""

from __future__ import annotations

from app import main


def _run_one_tick(monkeypatch):
    """Let _alert_scheduler's loop body run exactly once, then stop."""
    main._scheduler_stop.clear()

    def _stop_after_wait(_timeout):
        main._scheduler_stop.set()

    monkeypatch.setattr(main._scheduler_stop, "wait", _stop_after_wait)
    main._alert_scheduler()


def test_tick_runs_alerts_rollups_and_reconcile(monkeypatch):
    calls = []
    monkeypatch.setattr(main.alerts, "evaluate", lambda: calls.append("alerts"))
    monkeypatch.setattr(main.rollups, "refresh_rollups", lambda: calls.append("rollups"))
    monkeypatch.setattr(main.rollups, "reconcile_rollups", lambda: calls.append("reconcile"))

    _run_one_tick(monkeypatch)

    assert calls == ["alerts", "rollups", "reconcile"]


def test_rollup_failure_does_not_block_alerts_reconcile_or_kill_loop(monkeypatch):
    calls = []
    monkeypatch.setattr(main.alerts, "evaluate", lambda: calls.append("alerts"))
    monkeypatch.setattr(main.rollups, "reconcile_rollups", lambda: calls.append("reconcile"))

    def _boom():
        raise RuntimeError("simulated rollup refresh failure")

    monkeypatch.setattr(main.rollups, "refresh_rollups", _boom)

    _run_one_tick(monkeypatch)  # must not raise

    assert calls == ["alerts", "reconcile"]


def test_reconcile_failure_does_not_block_others_or_kill_loop(monkeypatch):
    calls = []
    monkeypatch.setattr(main.alerts, "evaluate", lambda: calls.append("alerts"))
    monkeypatch.setattr(main.rollups, "refresh_rollups", lambda: calls.append("rollups"))

    def _boom():
        raise RuntimeError("simulated reconciliation failure")

    monkeypatch.setattr(main.rollups, "reconcile_rollups", _boom)

    _run_one_tick(monkeypatch)  # must not raise

    assert calls == ["alerts", "rollups"]


def test_alert_failure_does_not_block_rollup_or_reconcile(monkeypatch):
    calls = []
    monkeypatch.setattr(main.rollups, "refresh_rollups", lambda: calls.append("rollups"))
    monkeypatch.setattr(main.rollups, "reconcile_rollups", lambda: calls.append("reconcile"))

    def _boom():
        raise RuntimeError("simulated alert failure")

    monkeypatch.setattr(main.alerts, "evaluate", _boom)

    _run_one_tick(monkeypatch)  # must not raise

    assert calls == ["rollups", "reconcile"]
