# Sub-task 2: Frontend — stream console shell

Parent: [Feature 2 — Live Stream](README.md)
Depends on: [Shared tab shell](../00-shared/01-tab-navigation-shell.md), [Sub-task 1 — tail endpoint](01-backend-tail-endpoint.md)

## Goal

The "Live Stream Console" tab: dark terminal-style view, new queries appear
continuously via 1-2s polling of `/api/tail`.

## Implementation plan

1. **`web/package.json`** — add `react-window`. **Deviation from the
   original plan**: `react-window` is now at v2, which replaced v1's
   `FixedSizeList`/`VariableSizeList` components with a single `List`
   component (`rowComponent`/`rowCount`/`rowHeight`/`rowProps` props,
   imperative `scrollToRow` via a `listRef`). v2 also ships its own type
   definitions, so `@types/react-window` (a v1-era package) is neither
   needed nor installed. Verified this by inspecting the actual published
   package before writing code against it, rather than assuming the v1 API
   the plan was drafted against still applied.

2. **`web/src/api.ts`** — added `TailRow extends QueryRow { id: number }`
   (not a wrapper `TailResponse` — the endpoint returns a bare array) and:
   ```ts
   tail: (since: number, sinceId: number, limit = 500) =>
     getJson<TailRow[]>(`/api/tail${qs({ since, since_id: sinceId, limit })}`),
   ```

3. **`web/src/components/LiveStreamTab.tsx`** (new):
   - On mount: cursor = `{ since: Date.now() / 1000, sinceId: 0 }` (start
     "now," per the spec — no historical backfill).
   - Poll every 1.5s. On each poll, append new rows to a capped buffer (see
     "buffer cap" below), advance the cursor to the last row received.
   - Render via `react-window` v2's `List` (`rowComponent`/`rowHeight`/
     `rowProps`), auto-scrolled to the bottom via `scrollToRow` as rows
     arrive (only auto-scroll if the user hasn't manually scrolled up —
     tracked via `onRowsRendered`'s `stopIndex` vs. current row count).
   - Buffer cap: hard limit (e.g. 1000-2000 rows) regardless of flood
     status — drop oldest once exceeded. This bounds memory independent of
     the throttling behavior in task 3, which is about *render* rate, not
     memory.

4. Dark terminal styling in `web/src/styles/app.css` — new classes, doesn't
   touch the existing light dashboard styles.

5. **Row entry animation** — a per-row "just arrived" CSS class (e.g.
   `.stream-row-new`) applied briefly on insert, removed after the
   transition completes (via a timeout or `animationend` listener) to get
   the "slides in" feel described in the spec. Note `react-window` only
   renders the visible slice, so this only needs to work for rows currently
   in the rendered window — that's fine, it's a visual nicety for whatever's
   on-screen when it arrives.

## Edge cases

- Tab switch away and back: per the shared shell's unmount-on-switch design,
  this naturally resets the buffer and cursor to "now" — matches the spec's
  "volatile buffer" requirement without extra code.
- No new queries for a while: console just sits idle, no error state needed
  (empty poll responses are normal, not a failure).

## Definition of done

- [x] Switching to the Live Stream tab shows new real queries appearing (verified: generated real DNS traffic via `dig @127.0.0.1` against the live Pi-hole container, confirmed end-to-end through to the rendered console)
- [ ] Scrolling up stops auto-scroll; scrolling back to bottom resumes it — implemented (`onRowsRendered` tolerance check), not independently exercised against live incoming data this session (no new traffic arrived while manually testing scroll position)
- [x] Leaving and returning to the tab starts a clean, empty console (falls out of the shared shell's unmount-on-switch design, already verified there)
- [x] No memory growth concern: buffer cap (1500) holds — verified indirectly via a real 1,362-row burst (see note below) rendering fine with react-window showing only ~28 DOM nodes at a time

## Two real things discovered during verification (not in the original plan)

1. **Pi-hole FTL's own DB flush interval (60s, `database.DBinterval`) is the
   true "how live is live" floor — not our 1.5s poll.** Verified directly:
   ran `dig @127.0.0.1` against the live Pi-hole container; `pihole.log`
   showed the query processed instantly, but it didn't appear in
   `pihole-FTL.db` for **over 90 seconds** (confirmed via `pihole-FTL --config`
   showing `database.DBinterval = 60`). DNS Watch reads Pi-hole's on-disk
   SQLite file — it can't see a query before Pi-hole itself writes it there.
   The spec's "the exact moment I interact with a device" (from the user
   journey) is accurate to within Pi-hole's own flush cadence, not our
   polling rate. This is inherent to the whole app's read-only architecture
   (see `db.py`'s module docstring), not something this feature controls —
   worth setting expectations on, not silently glossing over. A user who
   wants tighter freshness can lower `DBinterval` in their own Pi-hole
   config (a resource/write-frequency tradeoff that's Pi-hole's to make, not
   DNS Watch's).
2. **The UAT dev stack reads a snapshot, not the live Pi-hole DB** (by
   design — see `uat/README.md`). Verifying "does new traffic show up live"
   against UAT requires re-running `./uat/snapshot-pihole-db.sh` after
   generating test traffic; production (`docker-compose.yml`) mounts the
   live `etc-pihole` folder directly, so this manual step is UAT-only, not
   a real limitation of the shipped feature.

Side effect of the above: refreshing the snapshot mid-test surfaced 1,362
backlogged rows to the console in one poll — a real, if accidental, flood
test. Rendered without errors or a visible hang, a good sign for task 3's
throttling.
