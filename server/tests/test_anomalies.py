"""Anomaly detection ("Silent Talker") — baseline, silent, and spike scenarios.

`build_ftl()`'s own clients are always too new for these checks (their
first-ever query is within the last hour), so every test here adds one
deliberately-shaped client on top via `add_client_with_hourly_pattern()` and
asserts on that client specifically.
"""

from __future__ import annotations

import time

from conftest import add_client_with_hourly_pattern


def test_silent_device_flagged(ftl):
    from app import db
    now = int(time.time())
    # 27 steady baseline hours (~15/hr, well above the 10/hr silent floor)
    # followed by 3 fully silent recent hours.
    pattern = [15] * 27 + [0, 0, 0]
    add_client_with_hourly_pattern(ftl["path"], ftl["schema"], "10.0.0.50", "silent_device", pattern, now)

    hit = next((a for a in db.detect_anomalies() if a["ip"] == "10.0.0.50"), None)
    assert hit is not None
    assert hit["kind"] == "silent"
    assert hit["current_value"] == 0
    assert hit["baseline_avg"] > 10


def test_silent_device_gets_presence_note(ftl):
    """#6/#7: a silent anomaly carries the same presence qualifier a
    device_quiet alert rule would attach — "may be offline/switched resolver"
    when a real MAC is known (only possible on schemas with a `network` table
    that has hwaddr/macVendor: "real"/"idstore" — see #4), "presence cannot be
    determined" otherwise."""
    from app import db
    now = int(time.time())
    pattern = [15] * 27 + [0, 0, 0]
    add_client_with_hourly_pattern(ftl["path"], ftl["schema"], "10.0.0.52", "silent_device2", pattern, now)

    hit = next(a for a in db.detect_anomalies() if a["ip"] == "10.0.0.52")
    if ftl["schema"] in ("real", "idstore"):
        assert hit["presence_note"] == db.PRESENCE_MAC_KNOWN_NOTE
    else:
        assert hit["presence_note"] == db.PRESENCE_MAC_UNKNOWN_NOTE


def test_two_of_three_silent_hours_not_flagged(ftl):
    from app import db
    now = int(time.time())
    # Only 2 of the 3 most recent hours are silent -> must NOT flag yet;
    # the spec requires a full 3-consecutive-hour window.
    pattern = [15] * 27 + [0, 0, 15]
    add_client_with_hourly_pattern(ftl["path"], ftl["schema"], "10.0.0.51", "almost_silent", pattern, now)

    assert not any(a["ip"] == "10.0.0.51" for a in db.detect_anomalies())


def test_low_volume_client_whitelisted_from_silent(ftl):
    from app import db
    now = int(time.time())
    # A "smart scale"-style device: ~2/hr baseline, well under the 10/hr
    # floor. Silent for 3+ hours must still NOT be flagged.
    pattern = [2] * 27 + [0, 0, 0]
    add_client_with_hourly_pattern(ftl["path"], ftl["schema"], "10.0.0.52", "smart_scale", pattern, now)

    assert not any(a["ip"] == "10.0.0.52" for a in db.detect_anomalies())


def test_spike_flagged(ftl):
    from app import db
    now = int(time.time())
    # Alternating 10/20 gives a baseline avg ~14.8, stddev ~5.0 (3-sigma
    # threshold ~29.8). The most recent hour spikes to 40 — well above it.
    baseline = [10, 20] * 13 + [10]  # 27 hours
    pattern = baseline + [15, 15, 40]
    add_client_with_hourly_pattern(ftl["path"], ftl["schema"], "10.0.0.53", "ip_camera", pattern, now)

    hit = next((a for a in db.detect_anomalies() if a["ip"] == "10.0.0.53"), None)
    assert hit is not None
    assert hit["kind"] == "spike"
    assert hit["current_value"] == 40


def test_normal_fluctuation_not_flagged_as_spike(ftl):
    from app import db
    now = int(time.time())
    # Same baseline as the spike test (3-sigma threshold ~29.8), but the
    # current hour only reaches 25 — above average, but comfortably under
    # the 3-sigma bar. Must NOT flag.
    baseline = [10, 20] * 13 + [10]
    pattern = baseline + [15, 15, 25]
    add_client_with_hourly_pattern(ftl["path"], ftl["schema"], "10.0.0.54", "normal_fluct", pattern, now)

    assert not any(a["ip"] == "10.0.0.54" for a in db.detect_anomalies())


def test_new_device_excluded_even_if_it_looks_silent(ftl):
    from app import db
    now = int(time.time())
    # Looks exactly like the flagged-silent scenario, but only 10 hours of
    # total history -> must be excluded by the 24h new-device gate.
    pattern = [15] * 7 + [0, 0, 0]
    add_client_with_hourly_pattern(ftl["path"], ftl["schema"], "10.0.0.55", "brand_new", pattern, now)

    assert not any(a["ip"] == "10.0.0.55" for a in db.detect_anomalies())


def test_api_anomalies_endpoint_shape(client):
    # The `client` fixture's plain random data has no eligible clients (all
    # of build_ftl()'s clients are within the 24h new-device grace period),
    # so this just confirms the route wires up and returns the empty case cleanly.
    resp = client.get("/api/anomalies")
    assert resp.status_code == 200
    assert resp.json() == []


def test_api_anomalies_endpoint_returns_real_anomaly(ftl, client):
    now = int(time.time())
    pattern = [15] * 27 + [0, 0, 0]
    add_client_with_hourly_pattern(ftl["path"], ftl["schema"], "10.0.0.56", "silent_via_api", pattern, now)

    resp = client.get("/api/anomalies")
    assert resp.status_code == 200
    body = resp.json()
    hit = next((a for a in body if a["ip"] == "10.0.0.56"), None)
    assert hit is not None
    assert hit["kind"] == "silent"
    assert hit["name"] == "silent_via_api"


def test_api_latency_health_endpoint_shape(client, ftl):
    """#4: null (not a fake "healthy") when there's no reply_time signal at
    all yet -- see db.network_latency_health's own None contract."""
    resp = client.get("/api/latency-health")
    assert resp.status_code == 200
    assert resp.json() is None
