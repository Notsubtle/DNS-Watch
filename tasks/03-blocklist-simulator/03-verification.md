# Sub-task 3: Verification

Parent: [Feature 3 — Blocklist Simulator](README.md)
Depends on: [Sub-task 2 — simulator tab](02-frontend-simulator-tab.md)

## Steps

1. **Backend test suite**:
   ```bash
   docker run --rm -i -v "$PWD/server":/srv -w /srv python:3.12-slim \
     sh -c "pip install -q -e '.[test]' --break-system-packages && python -m pytest -q"
   ```
2. **Hot-reload UAT** (`localhost:5173`): run a few real patterns against
   the current UAT snapshot —
   - A narrow pattern matching a known real domain from your data (e.g.
     something seen in the top-domains list from earlier UAT sessions, like
     `gstatic` or `google`).
   - A deliberately broad pattern (e.g. `.*google.*`) — confirm the 7-day/
     10,000-row caps hold and the response is still fast.
   - A deliberately malformed pattern (e.g. `(unclosed`) — confirm the clean
     error message, not a crash.
3. Refresh the snapshot first if it's gone stale: `./uat/snapshot-pihole-db.sh`.
4. **Prod-like preview** (`localhost:8092`, `--profile prod --build`) —
   confirm the same checks pass against the built bundle.

## Definition of done

- [x] All tests pass — 175/175 (24 new)
- [x] Verified against real Cube1 data on both `localhost:5173` and `localhost:8092` — `gstatic` (44k+ matches, 20 unique domains, 13 affected clients) and an intentionally malformed `(unclosed` pattern against both stacks
- [x] Confirmed the 7-day window and 10,000-row cap are actually enforced (not just present in code), by testing a deliberately broad pattern — see below
- [x] Confirmed malformed regex never reaches a 500 in the browser — exact "Invalid Regular Expression syntax" copy rendered in `.error-banner`, confirmed via `preview_eval`

## Real discoveries this feature surfaced

1. **A genuine performance finding, not just a code-review guess.** Testing
   the worst realistic case — a pattern broad enough to match nearly every
   row (`.*`, ~650k matches over the 7-day window) — against the real Cube1
   snapshot measured **~3.15s** with the plan's original two-`COUNT`-query
   design (3 total REGEXP-evaluating full-table scans, counting the capped
   row fetch). Combined the two `COUNT` queries into one
   (`SELECT COUNT(*), COUNT(DISTINCT domain) ...`), which measured **~2.4s**
   for the same pattern. A realistic blocklist pattern (e.g. `gstatic`, 44k
   matches) stays under ~1.6s regardless — the multi-second case only shows
   up for the least realistic use of the tool (a pattern matching nearly
   everything). See task 1 for the fix.
2. **`unique_domains` had to be made exact, not sampled.** Verified this
   wasn't just theoretical: `gstatic` matched 44k+ rows across only 20
   distinct domains, but 2 of those domains don't appear in the capped
   10,000-row sample used to build `top_domains`/`clients`. Had
   `unique_domains` been derived from that same capped sample (a literal
   reading of the original plan), it would have under-reported by those 2
   domains against real data — not a huge miss here, but exactly the kind
   of silent inaccuracy a "how much traffic would this actually block"
   tool can't afford. Fixed by computing it as its own exact
   `COUNT(DISTINCT ...)`, alongside `total_matches`, in the same query from
   discovery 1.
3. **No REGEXP-registration or read-only-access issues** — `db.py`'s
   read-only (`mode=ro`) connection model and the module's constraint
   against ever writing to Pi-hole's live database held throughout; the
   REGEXP function is registered per-call on a single connection exactly as
   planned, with no effect on any other query in the file.
