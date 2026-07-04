# Feature 3 — Blocklist Impact Simulator

Retrospective "what if" tool: paste a Pi-hole-style regex, see how much of
the last 7 days of real traffic it would have blocked, broken down by domain
and affected client — before committing the rule to Pi-hole itself.

Depends on: [Shared tab-navigation shell](../00-shared/01-tab-navigation-shell.md)

## Sub-tasks (in order)

1. [Backend: REGEXP simulation endpoint](01-backend-simulate-endpoint.md)
2. [Frontend: simulator tab](02-frontend-simulator-tab.md)
3. [Verification](03-verification.md)

## Key design decisions

- **One matching engine: real regex, not a separate `LIKE`/wildcard path.**
  The spec's own example (`^(.+[-.])?telemetry[.-]`) is genuine regex —
  matching what Pi-hole's own regex blocklists actually accept. A plain
  substring is already a trivial valid regex, so REGEXP alone covers both
  "simple keyword" and "precise pattern" use cases without maintaining two
  code paths. (Contrast with Feature 2's highlight rules, which are
  deliberately glob-style for a different persona/use case — don't conflate
  the two.)
- **REGEXP is registered on-demand, not globally.** SQLite has no built-in
  `REGEXP`; Python's `sqlite3.Connection.create_function` adds it, but only
  for the connection used by this one endpoint — every other query in
  `db.py` stays exactly as fast as it is today.
- **Hard caps are server-enforced, not client-configurable**: default/only
  window is the last 7 days, results capped at `LIMIT 10000`, regardless of
  what the frontend sends. This is a safety property (spec: "Massive
  Database Size" edge case), not a UX default the user can override away.
- **No "Apply to Pi-hole" button** — intentionally out of scope, DNS Watch
  stays strictly read-only.

## Status: COMPLETE (2026-07-04)

All 3 sub-tasks done and verified — 175/175 backend tests passing (24 new),
full interactive verification against real Pi-hole traffic on the dev stack
(`localhost:5173`) and a targeted smoke-test on the prod-like build
(`localhost:8092`). One real performance finding surfaced during
verification (not visible from synthetic fixtures): a maximally broad
pattern (`.*`, matching virtually the entire 7-day window) measured ~3.15s
against the real Cube1 snapshot with the plan's original two-`COUNT`-query
design; combining both exact aggregates (`total_matches`, `unique_domains`)
into one query brought it to ~2.4s. A realistic blocklist pattern stays
under ~1.6s regardless. See each sub-task file for full detail, including
why `unique_domains` needed to be an exact count rather than derived from
the capped row sample.
