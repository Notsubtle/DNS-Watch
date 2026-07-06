"""The background scheduler tick must run both alert evaluation and the
rollup-cache refresh, and a failure in either must not kill the loop or
prevent the other from running (matching the existing alerts.evaluate()
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


def test_tick_runs_both_alerts_and_rollups(monkeypatch):
    calls = []
    monkeypatch.setattr(main.alerts, "evaluate", lambda: calls.append("alerts"))
    monkeypatch.setattr(main.rollups, "refresh_rollups", lambda: calls.append("rollups"))

    _run_one_tick(monkeypatch)

    assert calls == ["alerts", "rollups"]


def test_rollup_failure_does_not_block_alerts_or_kill_loop(monkeypatch):
    calls = []
    monkeypatch.setattr(main.alerts, "evaluate", lambda: calls.append("alerts"))

    def _boom():
        raise RuntimeError("simulated rollup failure")

    monkeypatch.setattr(main.rollups, "refresh_rollups", _boom)

    _run_one_tick(monkeypatch)  # must not raise

    assert calls == ["alerts"]


def test_alert_failure_does_not_block_rollup_refresh(monkeypatch):
    calls = []

    def _boom():
        raise RuntimeError("simulated alert failure")

    monkeypatch.setattr(main.alerts, "evaluate", _boom)
    monkeypatch.setattr(main.rollups, "refresh_rollups", lambda: calls.append("rollups"))

    _run_one_tick(monkeypatch)  # must not raise

    assert calls == ["rollups"]
