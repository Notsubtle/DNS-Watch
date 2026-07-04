# Sub-task 1: Backend — baseline & detection engine

Parent: [Feature 1 — Silent Talker / Anomaly Detection](README.md)

## Goal

Add the core detection logic to `server/app/db.py` (same module as every
other read-only analytics function — `timeseries()`, `client_activity()`,
etc. — no new module needed).

## Implementation plan

1. **Per-client, per-hour bucketed counts** — a helper that returns a fixed,
   zero-filled series of hourly counts for one client over an arbitrary
   `[since, until)` window (reuse the same bucketing approach `timeseries()`
   already uses, incl. the `CAST(... AS INTEGER)` fix for float timestamps —
   don't reintroduce that bug). Needs to be zero-filled (not sparse), because
   both the silence check (3 *consecutive* zero hours) and the stddev
   calculation depend on empty hours being present as `0`, not missing.

   Suggested signature:
   ```python
   def hourly_client_counts(client_ip: str, since: int, until: int) -> list[int]
   ```

2. **Baseline stats** — mean and population stddev of the baseline window
   (trailing 7 days, *excluding* the last 3 hours — see README's key design
   decision). No native `STDDEV` in SQLite; compute in Python
   (`statistics.pstdev` is fine at this scale — at most 168 buckets/client).

3. **Detection window checks**:
   - *Silent*: baseline avg > 10 AND all of the last 3 hourly buckets == 0.
   - *Spike*: current hour's count > baseline_avg + 3 × baseline_stddev.

4. **Eligibility gate** — before running either check for a client, look up
   its global first-seen (same MIN(timestamp) pattern already used in
   `new_clients()`); skip the client entirely if first-seen is < 24h ago.

5. **Top-level function**:
   ```python
   def detect_anomalies() -> list[dict]
   ```
   Returns one entry per flagged client:
   ```python
   {
     "ip": ..., "name": ...,
     "kind": "silent" | "spike",
     "baseline_avg": float, "baseline_stddev": float,
     "current_value": int,
     "window_since": int, "window_until": int,  # for the frontend's click-through
   }
   ```
   Iterate over `list_clients()` (already exists) rather than inventing a new
   client-enumeration path.

## Edge cases (from spec — make sure each has a code path, not just a comment)

- New device (< 24h history) → excluded from both checks entirely.
- Low-volume client (e.g. a smart scale averaging 1-2/day) → naturally
  excluded from "silent" because its baseline avg won't exceed 10/hr; don't
  add a separate whitelist mechanism, the threshold *is* the whitelist.
- Exactly 2 (not 3) consecutive silent hours → NOT flagged yet.
- A normal fluctuation under 3σ → NOT flagged as a spike.
- Must work identically across all schema variants the `ftl` test fixture
  parametrizes (`old`, `new`, and the incoming `real` variant — see
  Dependencies below) — use `_client_ip_col()` / `_client_join_sql()` like
  every other function in `db.py`, don't hardcode a column name.

## Dependencies

The background task **"Add real-Pi-hole-shaped test fixture"** is adding a
third `ftl` fixture variant (real Pi-hole v6 shape: float timestamps, name on
`network_addresses`, no `client` table) to `server/tests/conftest.py`. Confirm
that's merged (or merge it) before writing tests in task 2, so this new logic
gets validated against the schema your actual Pi-hole DB uses — the two bugs
fixed on 2026-07-04 (`db.py`'s client-name join, float-timestamp bucketing)
both slipped through specifically because the old fixtures didn't match real
Pi-hole. Reuse the same bucketing helper carefully so this feature doesn't
reintroduce either bug.

## Definition of done

- [x] `hourly_client_counts()`, baseline stats, and `detect_anomalies()` added to `db.py`
- [x] No new module, no changes to `alerts.py` (this is automatic analytics, not a user-configured rule)
- [x] Manually sanity-checked against the real Pi-hole snapshot in `uat/pihole-data/` (real client IPs, real volumes) — caught and fixed a real bug (`_client_ip_col()`/`_client_join_sql()` join missing on both `hourly_client_counts()` and `_client_first_seen()`) and, separately, a UAT harness bug (single-file bind mount doesn't follow `snapshot-pihole-db.sh`'s file-replacing `VACUUM INTO` — fixed in `uat/docker-compose.uat.yml`, now mounts the containing directory)
