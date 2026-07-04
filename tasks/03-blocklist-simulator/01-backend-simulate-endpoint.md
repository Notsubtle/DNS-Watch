# Sub-task 1: Backend — REGEXP simulation endpoint

Parent: [Feature 3 — Blocklist Simulator](README.md)

## Goal

A read-only endpoint that answers "how much traffic would this regex have
blocked over the last 7 days, and who'd be affected?"

## Implementation plan

1. In `server/app/db.py`, add:
   ```python
   def simulate_pattern(pattern: str, since: int, limit: int = 10000) -> dict
   ```
   - Compile the pattern up front with `re.compile(pattern)` **before**
     touching SQLite — a compile-time `re.error` is cheap to catch and turns
     directly into a clean 400, rather than surfacing row-by-row deep inside
     a SQL execution.
   - Open a connection and register the matcher:
     ```python
     conn.create_function("REGEXP", 2, lambda pat, val: 1 if compiled.search(val or "") else 0)
     ```
     scoped to this one connection/call — don't add this to the shared
     `_connect()` helper used everywhere else.
   - Two queries, both bounded by `q.timestamp >= since` (default 7 days):
     1. `SELECT COUNT(*) ... WHERE q.domain REGEXP ?` → true total match
        count within the window (still time-bounded, so bounded cost even
        without the `LIMIT`).
     2. `SELECT {client_join}, q.domain ... WHERE q.domain REGEXP ? LIMIT ?`
        → capped row set used to build the domain/client breakdown.
   - Aggregate in Python: `unique_domains`, `clients: [{ip, name, count}]`,
     `top_domains: [{domain, count}]`.
   - **Client impact percentage** (spec's "accounts for 45% of your
     SmartFridge connectivity" example): for each affected client, also look
     up their *total* query count in the same window (reuse
     `client_counts()` or `summary(client=ip, ...)`, already exists) and
     compute `matched / total * 100`. Return this per client rather than
     making the frontend re-fetch each client's totals separately.

2. New route in `server/app/main.py`:
   ```python
   class SimulateRequest(BaseModel):
       pattern: str
       range: str = "7d"

   @app.post("/api/simulate-blocklist")
   def api_simulate_blocklist(body: SimulateRequest):
       since = _since_from_range(body.range, None) or (int(time.time()) - 7 * 86400)
       # Clamp: never allow a wider window than 7 days, regardless of input.
       since = max(since, int(time.time()) - 7 * 86400)
       try:
           return db.simulate_pattern(body.pattern, since)
       except re.error:
           raise HTTPException(status_code=400, detail="Invalid regular expression syntax")
   ```

## Edge cases

- Malformed regex → 400 with a clear `detail`, never a 500.
- Pattern matching everything (e.g. `.*`) → still bounded by the 7-day
  window + `LIMIT 10000`, confirm this doesn't time out against the real
  ~40MB Cube1 snapshot.
- Empty/whitespace pattern → reject with 400 before running any query (an
  empty regex trivially matches every row, which is never a useful
  simulation and would be needlessly expensive).

## Tests

- [x] Valid pattern returns correct total/unique/client breakdown against a synthetic fixture with known matching domains
- [x] Invalid regex (e.g. unbalanced parens) → `400` with the exact expected message
- [x] Match count respects the 7-day clamp even if `range` requests something wider
- [x] Result rows respect `LIMIT 10000` while `total_matches` still reflects the true count
- [x] Client impact percentage matches manually-computed expected values in the fixture
- [x] Covered across all three `ftl` schema variants

## Definition of done

- [x] `simulate_pattern()` + `/api/simulate-blocklist` added
- [x] Tests pass: `docker run --rm -i -v "$PWD/server":/srv -w /srv python:3.12-slim sh -c "pip install -q -e '.[test]' --break-system-packages && python -m pytest -q"` (24 new tests, 175/175 total)

## What actually happened

Implementation matches the plan closely, with one real deviation found during
verification against the live Cube1 snapshot (not caught by synthetic
fixtures — same lesson as Feature 1):

- **`unique_domains` and `total_matches` combined into one query, not two.**
  The plan called for a separate `COUNT(*)` query; a second `COUNT(DISTINCT
  q.domain)` query was added for exactness (see below), and the two were
  then merged into a single `SELECT COUNT(*), COUNT(DISTINCT q.domain) ...`
  once profiling showed the cost of running the REGEXP-evaluating scan
  a third time. Concretely: testing a deliberately worst-case pattern
  (`.*`, matching all ~650k rows in the 7-day window) against the real
  Cube1 snapshot measured **~3.15s with 3 full-table REGEXP scans**
  (COUNT(*), COUNT(DISTINCT domain), and the capped row-fetch); combining
  the first two into one query brought it to **~2.4s with 2 scans**. A
  realistic blocklist-style pattern (e.g. `gstatic`) stays under ~1.6s
  regardless — the worst case only shows up for a pattern broad enough to
  match nearly everything, which is also the least realistic use of this
  feature.
- **`unique_domains` is exact, not derived from the capped row set.** The
  plan's wording ("aggregate in Python: unique_domains, ...") could be read
  as computing it from the same capped `LIMIT`-ed rows used for
  `top_domains`/`clients`. Implemented instead as its own exact
  `COUNT(DISTINCT ...)` (see above) so a pattern matching more than `limit`
  rows still reports its true distinct-domain count — verified this
  actually matters against real data: `gstatic` matched 44k+ rows but only
  20 distinct domains, 2 of which don't appear in the capped 10,000-row
  sample used for the `top_domains` breakdown.
- No other deviations — the compile-before-connect ordering, the
  connection-scoped `REGEXP` function, the 7-day/10,000-row caps, and the
  reuse of `client_counts()` for the impact-percentage denominator all
  worked as planned on the first pass.

## Post-review fix (2026-07-04) — per-client percentages were sampled, not exact

A later full-code review caught a real correctness bug in the first cut: the
per-client `matched_count` / `pct_of_client_traffic` (the spec's headline
"accounts for X% of your SmartFridge" figure) and the `top_domains` counts
were all derived from the un-ordered `LIMIT 10000` row sample, while
`total_count` used the exact full total. So for any pattern matching more
than 10,000 rows, the percentages were understated — measured ~4.4x low for
`gstatic` against the real snapshot (per-client `matched_count` summed to
exactly 10,000 instead of the true ~44,000). The top-by-impact client showed
3.4% when its real share was 13.8%.

Fixed by replacing the capped row-fetch with two exact `GROUP BY` aggregates
(one over domain — which also yields `total_matches` as the sum and
`unique_domains` as the row count — and one over client). Same two
REGEXP-evaluating table scans as before, now aggregated in SQL, so every
number returned is exact. The `.*` worst case measured ~3.6s vs the buggy
version's ~2.4s (GROUP-BY sort overhead over ~6,500 domain groups); realistic
patterns stay sub-2s. The `limit` parameter was removed from
`simulate_pattern()` (no longer materializes rows); `top_domains` is still
capped at 50 entries for display via `TOP_DOMAINS_LIMIT`. Regression test:
`test_breakdown_counts_are_exact_not_sampled` asserts both breakdown sums
equal `total_matches`.
