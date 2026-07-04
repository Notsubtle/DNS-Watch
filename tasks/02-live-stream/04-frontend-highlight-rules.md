# Sub-task 4: Frontend — highlight rules

Parent: [Feature 2 — Live Stream](README.md)
Depends on: [Sub-task 2 — stream console shell](02-frontend-stream-console-shell.md)

## Goal

User-defined glob patterns (e.g. `*netflix*`) with a chosen highlight color,
applied live to matching rows in the stream console.

## Implementation plan

1. **`web/src/components/HighlightRulesModal.tsx`** (new) — same interaction
   pattern as the existing `RulesModal.tsx` (list, add, edit, delete), but
   simpler: no backend calls at all, everything is local state persisted to
   `localStorage` under a single key (e.g. `dnswatch.highlightRules`).
   ```ts
   interface HighlightRule {
     id: string; // crypto.randomUUID() — no server, no autoincrement id
     pattern: string; // glob, e.g. "*netflix*"
     color: string; // hex or CSS color
     field: "domain" | "client"; // what the glob matches against
   }
   ```

2. **Glob → matcher.** Convert the user's glob to a compiled `RegExp` once
   per rule (on save, not per-row): escape regex special characters, then
   replace `*` with `.*`, anchor the whole pattern, case-insensitive. Wrap
   the conversion in try/catch — a pathological pattern shouldn't be
   possible from a glob subset, but the compile step should still fail
   safely (skip the rule, don't crash the console) rather than assume it
   always succeeds.

3. In `LiveStreamTab.tsx`, for each rendered row, check it against the
   compiled rule list (first match wins, or allow multiple — decide based on
   how it looks visually; first-match is simpler and matches the spec's
   single-highlight-per-row mockup) and apply the resulting color as an
   inline style or CSS class.

4. Rules load from `localStorage` on mount and persist on every change —
   confirm they survive a full page reload.

## Edge cases

- Empty pattern → don't add a no-op rule that matches everything.
- Multiple rules matching the same row → pick one deterministically (e.g.
  first rule in list order) rather than an undefined "last write wins" from
  render order.
- `localStorage` unavailable/blocked (rare, but possible in some browser
  privacy modes) → fail silently to "no highlight rules," don't break the
  console.

## Definition of done

- [x] Added a real rule (`*gstatic*`, purple) through the actual UI; confirmed matching real rows (`ssl.gstatic.com`) rendered with the correct highlight background (`rgba(168, 85, 247, 0.2)` — the chosen hex + alpha suffix)
- [x] Reloaded the page fully; confirmed the rule persisted in `localStorage` and reapplied correctly on remount
- [x] Confirmed no false positives via direct unit-level checks in the browser (dynamic `import()` of `highlightRules.ts`): `*netflix*` did not match `www.google.com`; a literal `.` in a pattern (`a.b`) matched only the literal string, not `aXb` — confirming only `*` is treated as a wildcard, everything else is escaped literally

Implementation matches the plan closely, with one addition: a "Highlight rules" button in `.stream-head` (not specified in the original plan, but needed somewhere to actually open `HighlightRulesModal`) and a shared `web/src/highlightRules.ts` module (compile/match/persist logic used by both the modal and `LiveStreamTab`, rather than duplicating it in the modal alone).

## Post-review fix (2026-07-04) — `crypto.randomUUID()` throws on the real LAN deployment

A later full-code review caught a bug the localhost preview could never
surface: the add-rule handler generated ids with `crypto.randomUUID()`, which
only exists in **secure contexts** (HTTPS or `localhost`). DNS Watch's own
documented deployment is plain HTTP over a LAN IP (`http://192.168.x.x:8090`;
see the README's auth/TLS note), which is *not* a secure context — there
`crypto.randomUUID` is `undefined`, so submitting the add-rule form would
throw `TypeError: crypto.randomUUID is not a function`. Every preview test
passed precisely because they ran on `localhost`, where it works.

Fixed with a `makeRuleId()` helper that uses `crypto.randomUUID()` when it's
actually available and otherwise falls back to a
`hr-<base36-time>-<base36-random>` id. These ids are local-only (React keys +
delete matching), so a non-crypto fallback is fine — uniqueness, not
unpredictability, is all that's needed (verified 1000/1000 unique). The
happy path (proper UUID on localhost) was re-confirmed unbroken, and the
guarded fallback is present in the production Vite bundle.
