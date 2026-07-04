# Feature 4 — Client "Sleep Mode" / Noise Map

A 7-day × 24-hour heatmap for one selected client, in the user's *actual*
local time, to expose background chatter during hours the device should be
idle — with click-through to the exact queries behind any suspicious cell.

Depends on: [Shared tab-navigation shell](../00-shared/01-tab-navigation-shell.md)

## Sub-tasks (in order)

1. [Backend: heatmap aggregation + drill-down](01-backend-heatmap-aggregation.md)
2. [Frontend: heatmap grid](02-frontend-heatmap-grid.md)
3. [Frontend: cell drill-down modal](03-frontend-drilldown-modal.md)
4. [Verification](04-verification.md)

## Key design decision — timezone conversion happens in Python, not SQLite

SQLite's `strftime(..., 'localtime')` only respects the *container's* OS
timezone — and the `dns-dashboard` container in `docker-compose.yml` doesn't
currently set `TZ` at all (unlike the `pihole` container, which sets
`America/Edmonton`). Relying on container TZ config would make "middle of
the night" silently wrong unless someone remembers to configure it, on this
host or any other DNS Watch gets deployed to.

Instead: the frontend sends its own IANA timezone (`Intl.DateTimeFormat()
.resolvedOptions().timeZone`, read directly from the browser — no user
input needed), and the backend converts every row explicitly using Python's
`zoneinfo.ZoneInfo`. This is correct regardless of the host/container's own
clock configuration.

**Accepted simplification**: the UTC offset for the whole 7-day window is
computed once (from "now"), not per-row. A single week only crosses a DST
boundary twice a year, and this is a home-network diagnostic tool, not a
compliance system — documented here rather than silently glossed over.

## Status: COMPLETE (2026-07-04)

All 4 sub-tasks done and verified — 205/205 backend tests passing (26 new),
full interactive verification against real Pi-hole traffic on the dev stack
(`localhost:5173`) and a targeted smoke-test on the prod-like build
(`localhost:8092`). Confirmed the browser's real IANA timezone
(`America/Edmonton`) actually reaches the backend rather than silently
defaulting to UTC through the Docker network. One real design gap found
during verification: the drill-down endpoint's plan wording implied a
single UTC range per cell, which only holds for the default 7-day window —
fixed to walk every matching calendar day so the round-trip invariant (sum
of all 168 cells' drill-down counts == the grid total) holds for any
`days` value up to the endpoint's own 30-day cap. See each sub-task file
for full detail, including an honest note that no single real device in
this home-network dataset shows a textbook "phone asleep at night"
pattern — timezone *correctness* is verified by deterministic backend
tests, not by eyeballing a grid.
