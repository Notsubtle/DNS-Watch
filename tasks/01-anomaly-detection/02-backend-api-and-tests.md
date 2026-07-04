# Sub-task 2: Backend — API endpoint & tests

Parent: [Feature 1 — Silent Talker / Anomaly Detection](README.md)
Depends on: [Sub-task 1 — baseline & detection engine](01-backend-baseline-engine.md)

## Goal

Expose `db.detect_anomalies()` over the API, and cover the detection logic
with tests before any frontend work starts.

## Implementation plan

1. In `server/app/main.py`, add:
   ```python
   @app.get("/api/anomalies")
   def api_anomalies():
       return db.detect_anomalies()
   ```
   No query params — thresholds are fixed per spec (v1 has no
   user-configurable sensitivity). Follows the same no-params shape as
   `/api/clients`.

2. Do **not** wire this into the `alerts.py` scheduler/webhook path — Feature
   1 is explicitly UI-only in v1 ("Out of Scope: Push Notifications"). The
   background alert-evaluation thread in `main.py`'s `_alert_scheduler()`
   should be untouched.

## Tests (`server/tests/test_db.py`, `server/tests/test_api.py`)

Extend `conftest.py`'s `build_ftl()` (or add a sibling helper) so a test can
construct a client with a deliberately shaped history — this is more
deterministic than relying on the existing random `build_ftl()` output, which
has no controlled baseline/spike scenario built in.

Cases to cover, each across the parametrized `ftl` fixture (old/new/real
schema — see task 1's Dependencies note):

- [x] Client with steady ~15/hr history, silent for the last 3 hours → flagged `silent`
- [x] Same client, silent for only 2 hours → NOT flagged
- [x] Client with steady ~2/hr history (low-volume), silent for 3+ hours → NOT flagged
- [x] Client with steady baseline, current hour count > avg + 3σ → flagged `spike`
- [x] Client with normal variance under 3σ → NOT flagged
- [x] Client first seen < 24h ago, otherwise looks silent/spiky → excluded entirely
- [x] `GET /api/anomalies` returns the expected shape end-to-end via `TestClient`

Implemented in `server/tests/test_anomalies.py` (new file) + `add_client_with_hourly_pattern()` added to `conftest.py`, all 7 cases parametrized across old/new/real schemas (24 tests total).

## Definition of done

- [x] `/api/anomalies` route added
- [x] All new tests pass: `docker run --rm -i -v "$PWD/server":/srv -w /srv python:3.12-slim sh -c "pip install -q -e '.[test]' --break-system-packages && python -m pytest -q"`
- [x] Full existing suite still green (no regressions) — 138/138 passing
