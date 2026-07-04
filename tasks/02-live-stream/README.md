# Feature 2 — Live "Tail -f" Stream with Visual Triggers

A dedicated real-time console view: new DNS queries stream in continuously
(1-2s polling), with user-defined highlight rules (glob patterns + color) so
a power user can watch exactly what a device does the moment they interact
with it.

Depends on: [Shared tab-navigation shell](../00-shared/01-tab-navigation-shell.md)

## Sub-tasks (in order)

1. [Backend: cursor-based tail endpoint](01-backend-tail-endpoint.md)
2. [Frontend: stream console shell](02-frontend-stream-console-shell.md)
3. [Frontend: flood throttling](03-frontend-throttling.md)
4. [Frontend: highlight rules](04-frontend-highlight-rules.md)
5. [Verification](05-verification.md)

## Key design decisions

- **New endpoint, not a reuse of `/api/queries`.** The existing
  `list_queries()` is built for paging *backwards* from now
  (`ORDER BY timestamp DESC LIMIT/OFFSET`). A tail needs the opposite shape:
  "everything strictly after the last row I've already seen," ascending. See
  task 1.
- **Highlight matching is glob-style (`*netflix*`), not full regex** — this is
  a deliberate difference from Feature 3's simulator, which uses genuine
  Pi-hole-style regex. The spec's own example (`*netflix*`) is a glob, and
  glob is the friendlier syntax for "highlight while I watch," where regex
  is the right tool for "precisely define a blocklist rule." Don't unify
  these two into one matching engine — they solve different problems for
  different personas.
- **`react-window` dependency added** for virtualized rendering — the first
  new frontend dependency beyond React/Vite. Justified because reinventing
  scroll virtualization correctly under flood conditions (see task 3) is
  exactly the kind of thing not worth hand-rolling.
- **Highlight rules persist in `localStorage`**, not the backend — they're a
  personal UI preference, not shared state, so no new API/db table needed.
- **The stream buffer itself is volatile** (per spec) — switching away from
  the tab and back starts a fresh buffer/cursor, it does not resume. This
  falls out for free from the shared tab shell's unmount-on-switch behavior.
- **`react-window` v2, not v1** — the API named in the original plan
  (`FixedSizeList`) belongs to v1; the actual current package is a v2
  rewrite (`List`/`rowComponent`/`rowProps`, own bundled types). Verified
  against the real published package before writing code.
- **Poll interval backs off under load** (1.5s normal → 3s while a flood is
  detected) via a self-scheduling `setTimeout` rather than a fixed
  `setInterval` — keeps a haywire device from also hammering the backend,
  on top of the display-side sampling.

## Status: COMPLETE (2026-07-04)

All 5 sub-tasks done and verified — 151/151 backend tests passing (13 new),
full interactive verification against real Pi-hole traffic on the dev stack
(`localhost:5173`), targeted smoke-test verification on the prod-like build
(`localhost:8092`). See each sub-task file for what was actually found during
verification — two things worth knowing before touching this code again:
Pi-hole's own 60s DB-flush interval is the real "how live is live" floor (not
this feature's poll rate), and the UAT stacks read a periodic snapshot, not
the live Pi-hole DB, so testing "does new traffic show up" here requires
re-running `./uat/snapshot-pihole-db.sh` first.
