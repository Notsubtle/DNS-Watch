# DNS Watch — Security Audit & Lint Report

**Scope:** `main` branch, commit `091b4e2`. Read-only audit — no code was modified. Covers `server/` (FastAPI/Python), `web/` (React/TypeScript), Dockerfiles, `docker-compose.yml`, `uat/` scripts, `.env.example`.

## Fixes applied (follow-up pass)

All 9 numbered "Findings — Security" items below were addressed in a follow-up pass on top of this audit. Status of each:

| # | Finding | Status | Fix |
|---|---|---|---|
| 1 | DNS-rebinding TOCTOU in webhook SSRF guard | **Fixed** | `_validate_webhook_url()` now returns the validated IP itself; `deliver_webhook()` connects to that literal IP directly (via `http.client`, with correct `Host` header and TLS SNI/hostname verification for https) instead of handing the original URL to a client that re-resolves the hostname. |
| 2 | Unauthenticated/CSRF-exposed `test-webhook` amplifying #1 | **Fixed** | Added `csrf_guard` middleware in `main.py`: rejects POST/PATCH/DELETE requests whose `Origin`/`Referer` header names a different host than the request's own `Host` header. Requests with neither header (non-browser clients) are unaffected. |
| 3 | IPv6 loopback blocked inconsistently with stated policy | **Fixed** | `_is_unsafe_webhook_target()` now checks `is_loopback` first and returns `False` immediately, so `::1` can no longer be caught incidentally by the `is_reserved` check — loopback is now allowed symmetrically for both address families, matching the documented policy. |
| 4 | ReDoS via `/api/simulate-blocklist` | **Fixed** | `simulate_pattern()` now matches with the third-party `regex` engine using a 0.5s per-row timeout; a timed-out row is treated as a non-match rather than blocking the scan. Syntax validation still happens via stdlib `re.compile` first, so the existing `re.error` → HTTP 400 mapping in `main.py` is unchanged. |
| 5 | Unbounded `limit`/`offset`/`domain` scans | **Fixed** | `list_queries()`/`tail_queries()` now clamp `limit`/`offset` locally (not just at the HTTP layer), and the `domain` filter is capped at 253 characters (the max valid DNS name length) before being used in a `LIKE` pattern. |
| 6 | SQL built via f-strings for structural fragments | **Fixed (hardened)** | `_status_where()` now checks `status` against an explicit `VALID_STATUS_FILTERS` allowlist before branching, rather than relying on an if/elif chain that happened to fall through safely. No live injection existed before this change — this is defense-in-depth against a future regression, not a behavior change. |
| 7 | Non-root container execution | **Fixed** | `server/Dockerfile` and `uat/api.Dockerfile` now create and run as a non-root `appuser` (UID 1000, matching the common single-user-host default). Documented in the README as a "Notes / limitations" item since it can require a host permissions adjustment for `PIHOLE_ETC_PATH`/`dnswatch-data` on less common UID setups. |
| 8 | Auth credential passed as plain environment variable | **Fixed** | Added optional `DNSWATCH_AUTH_PASSWORD_FILE` support in `main.py` (reads and strips a file's contents, falling back to `DNSWATCH_AUTH_PASSWORD` if unset/unreadable) plus corresponding `docker-compose.yml`/`.env.example` documentation. Existing `DNSWATCH_AUTH_PASSWORD` setups are unaffected. |
| 9 | Error messages may leak target host on webhook delivery failure | **Not fixed (by design)** | Left as-is. The error only ever reaches the same authenticated/CSRF-protected caller who configured the webhook URL in the first place (now doubly true after fix #2), so there's no cross-user disclosure. Sanitizing it would reduce debuggability (the settings UI's "Send test" button relies on this string to tell the operator *why* delivery failed) for a finding this low-severity. |

Full test suite: **235 passed** (up from 211 at audit time — 9 new regression tests added for fixes #1, #3, and #4) via `docker run ... python -m pytest -q`. No frontend files were touched, so `tsc --noEmit` wasn't re-run for this pass.

## Code review of the fixes themselves

An 8-angle multi-agent code review (correctness, removed-behavior, cross-file, reuse, simplification, efficiency, altitude, conventions) ran against the fix commits before anything was pushed. It found **4 real bugs introduced by the fixes**, all corrected and covered by new regression tests:

| Bug found | Where | Fix |
|---|---|---|
| CSRF guard bypassable via `Origin: null` | `main.py` `csrf_guard` | An opaque "null" Origin (sandboxed iframes, some cross-origin redirects) parses to an empty netloc, which the original check treated as "no conflict" and let through. Now rejects on *any* mismatch, including empty. |
| Malformed Host header for IPv6 webhook targets | `alerts.py` `deliver_webhook` | `parsed.hostname` strips brackets from an IPv6 literal; building `Host: hostname:port` naively produced `fe80::1:8443` instead of the RFC 7230-required `[fe80::1]:8443`, breaking delivery to IPv6 targets on non-default ports. Added `_host_header()` to bracket correctly. |
| Socket leak on TLS handshake failure | `alerts.py` `_PinnedHTTPSConnection` | `self.sock` was only assigned after `wrap_socket()` succeeded, so a receiver that accepted the TCP connection but failed/never completed the handshake leaked the raw socket every delivery attempt. Now closed on any wrap failure; the class also now delegates the raw connect to `HTTPConnection.connect()` instead of reimplementing it, restoring `TCP_NODELAY` and the stdlib connect audit hook the original override silently dropped. |
| Uncaught 500 from `regex`/`re` syntax divergence | `db.py` `simulate_pattern` | Syntax is validated with stdlib `re` but matched with the third-party `regex` engine (for the per-row timeout); `regex.error` isn't a subclass of `re.error`, so a pattern `regex` rejected that `re` accepted raised an unhandled exception instead of the intended 400. Now re-raised as `re.error`. |

It also flagged one **real deployment regression** in the non-root Docker fix (not a bug in application code): switching to a non-root `appuser` only fixes ownership of `/data` at *image build* time — it does nothing for an existing `dnswatch-data` volume created by an older, root-run deployment, whose `dnswatch.db` would stay root-owned and become unwritable after upgrading, silently breaking alert-rule persistence. Fixed with a `docker-entrypoint.sh` that starts as root, chowns `/data`, then drops to `appuser` via `su` before exec'ing the real process — verified with an actual `docker build` + `docker run` against a simulated pre-existing root-owned `dnswatch.db`, not just code inspection.

A `limit=0`/negative-value inconsistency was also fixed as a byproduct: `/api/queries`, `/api/tail`, and `/api/queries.csv` now reject out-of-range values with FastAPI's normal 422 (via `ge=` bounds, matching every other bounded query param in `main.py`) instead of silently reinterpreting them deeper in `db.py` while echoing the caller's original, wrong value back in the response body.

**Lower-priority items noted but not changed:** the CSRF guard's Host-header comparison assumes a reverse proxy forwards the original `Host` unchanged (documented as a caveat in the docstring rather than built into a full trusted-origins allowlist); the `regex` module's per-row timeout has real overhead (~6-7x slower per call, benchmarked) which is an accepted trade-off for this button-triggered batch operation, not a hot path; and a couple of pure duplicated-magic-number/DRY observations (the `limit`/`offset` clamp values live in both `main.py` and `db.py` with no shared constant) were left as-is since fixing them would be a larger refactor for a non-functional concern.

Full test suite after the code-review fixes: **242 passed**.

## Summary

Overall risk posture is **moderate**, appropriate for a self-hosted LAN tool with optional auth. The two invariants that matter most both hold up well: the Pi-hole FTL database is opened read-only through a single, consistently-used connection helper with no bypass, and the webhook secret is never returned by the settings API. However, the SSRF guard on the webhook feature has a genuine **DNS-rebinding TOCTOU gap** (validates a hostname's resolved IPs, then lets a separate HTTP client re-resolve the same hostname at connect time), and this is made directly triggerable by an unauthenticated-by-default `test-webhook` endpoint with no CSRF protection. These two combine into the highest-priority finding: an attacker who gets a LAN user to load a malicious page (or who is on the LAN with SSRF-as-a-service reachable) can force the server to make outbound requests to arbitrary internal targets, bypassing the link-local/metadata blocklist. No SQL injection or Pi-hole write-safety issues were found. No frontend XSS was found.

## Findings — Security

### 1. [High] DNS-rebinding TOCTOU bypasses the webhook SSRF guard
**File:** `server/app/alerts.py:234-248` (validation) vs `server/app/alerts.py:251-271` (delivery)

`_validate_webhook_url()` resolves the hostname once via `socket.getaddrinfo(parsed.hostname, None)` (line 242) and checks *those* IPs against the link-local/multicast/reserved blocklist (`_is_unsafe_webhook_target`, line 218-231). `deliver_webhook()` then builds `urllib.request.Request(url, ...)` from the **original URL string** (line 270) and hands it to `_NO_REDIRECT_OPENER.open(req, ...)`, which performs its own independent DNS resolution when it actually opens the TCP connection. The validated IP and the connected IP are never pinned to be the same address.

**Exploit scenario:** Attacker registers a domain (e.g. `evil.example`) with a very low DNS TTL. They set it as the alert webhook URL (or pass it directly to `/api/settings/test-webhook`, see finding #2 — no persistent rule needed). At validation time the domain resolves to a public IP (passes the check). Milliseconds/seconds later, when `urllib` actually opens the connection, DNS has been rebound to `169.254.169.254` (cloud metadata) or `127.0.0.1:<internal-port>`. The POST goes to the rebound target — the guard never sees it.

**Suggested fix:** Resolve the hostname once, validate the resulting IP, then connect directly to that literal IP address (passing the original hostname via the `Host` header, and via SNI if TLS) so the validated and connected addresses are guaranteed identical. Do not let the HTTP client re-resolve the hostname between check and use.

### 2. [Medium] Unauthenticated SSRF trigger via `/api/settings/test-webhook`, no CSRF protection
**Files:** `server/app/main.py:332-334` (route), `server/app/alerts.py:278-287` (`test_webhook`)

`test_webhook()` will POST to any URL that passes `_validate_webhook_url`, with no prerequisite (no alert rule needs to exist first). Since `DNSWATCH_AUTH_PASSWORD` is optional and off by default, and since HTTP Basic auth (when enabled) has no CSRF defense — the browser attaches cached Basic-auth credentials to any cross-origin request to the origin, and there is no `Origin`/`Referer` check or CSRF token anywhere in `main.py` — a victim merely visiting a malicious page can have their browser silently POST to `/api/settings/test-webhook` (or `/api/alert-rules`, `/api/settings` PATCH, `/api/simulate-blocklist`) with attacker-chosen bodies. This turns finding #1 from "theoretical, requires planting a persistent rule" into "trivially triggerable with a single drive-by request," and independently lets an attacker create/delete alert rules or overwrite the webhook URL/secret.

**Suggested fix:** Add `Origin`/`Referer` validation for state-changing routes (POST/PATCH/DELETE), or move away from HTTP Basic to a session-cookie model with `SameSite=Strict` + a CSRF token. At minimum, rate-limit and require auth specifically on `/api/settings/test-webhook` regardless of the global auth toggle, since it's a direct fetch-any-URL primitive.

### 3. [Low] IPv6 loopback blocked inconsistently with stated policy
**File:** `server/app/alerts.py:218-231`

`_is_unsafe_webhook_target` relies on `ip.is_reserved` (line 231), which happens to return `True` for `::1` (IPv6 loopback) in Python's `ipaddress` module, while IPv4 loopback (`127.0.0.1`) is not blocked by any of the four checks — matching the documented intent that loopback is intentionally allowed (comment, line 223-224, and used by the test suite). This is a functional inconsistency (over-blocking a legitimate IPv6 LAN receiver) rather than a security hole, but it's accidental rather than a deliberate policy choice.

**Suggested fix:** Decide the IPv6 loopback/ULA policy explicitly and check `is_loopback` / `fc00::/7` directly, rather than relying on `is_reserved`'s incidental behavior.

### 4. [Medium] ReDoS via unauthenticated-by-default regex simulation endpoint
**Files:** `server/app/main.py:149-164` (`POST /api/simulate-blocklist`), `server/app/db.py:753,762` (`simulate_pattern`, `re.compile` + SQLite `REGEXP`)

A user-supplied regex pattern is compiled with Python's backtracking `re` engine and registered as a SQLite `REGEXP` function, then evaluated per-row across up to 7 days of query history (potentially hundreds of thousands of rows). An adversarial pattern (e.g. nested-quantifier forms like `(a+)+$`) combined with adversarial-but-plausible domain strings already present in the DB can trigger catastrophic backtracking and hang a worker thread. Since auth is optional and off by default, and this endpoint requires no prior state, it's directly reachable by anyone on the LAN (or via the CSRF path in finding #2 when auth is enabled).

**Suggested fix:** Run the regex match with a timeout (e.g. the third-party `regex` module supports timeouts, or run in a bounded worker/process that can be killed), or cap pattern complexity/length before compiling.

### 5. [Medium] Unbounded `limit`/`offset`/`domain` substring scans (DoS)
**File:** `server/app/db.py:163-164` (`domain` LIKE pattern), `204-260` (`list_queries`, `tail_queries`)

The `domain` filter is applied as `LIKE ?` with a leading wildcard (`f"%{domain}%"`, line 164) and no length cap — forcing a full table scan on every call, unlike other parameters in the same file (e.g. `buckets` is clamped via `max(1, min(buckets, 500))` at line 420). Similarly, `limit`/`offset` in `list_queries` (204-219) and `tail_queries` (238-260) are not bounded within `db.py` itself — the file relies entirely on the HTTP layer to clamp them before calling in. A request for a very large `limit` would materialize a huge Python list via `fetchall()`.

**Suggested fix:** Clamp `limit`/`offset` locally in `db.py` (consistent with how `buckets` is already handled), and cap the length of `domain` before building the LIKE pattern.

### 6. [Medium/Low] SQL built via f-strings for structural fragments (bandit B608)
**File:** `server/app/db.py` — query-builder helpers including `_client_join_sql()` (82-99), `_client_ip_col()` (102-110), `_status_case()`/`_status_where()` (113-140), and others flagged by bandit at lines 179, 768, 775, 863, 895.

All *values* (client IP, domain, timestamps, pattern, IDs, limits/offsets) are passed as bound `?` parameters — confirmed at every `_build_where` call site and in `simulate_pattern`. The f-string-built fragments bandit flags are structural (column/table names, JOIN clauses, hardcoded status-set literals) derived from `detect_schema()` DB introspection or module-level constants, not from HTTP request input — no live injection was found. This is a defense-in-depth flag, not a live vulnerability: if a future change lets `status` or a schema-derived identifier be influenced more directly by request input (e.g. loosening the current identity-comparison validation), this pattern would become exploitable.

**Suggested fix:** No functional change required today; consider an explicit allowlist/raise pattern for `status` and any schema-derived identifiers as defense-in-depth against future regressions.

### 7. [Low] Non-root container execution missing in production Dockerfile
**File:** `server/Dockerfile` (no `USER` directive anywhere in the file)

The container runs as root throughout, including at runtime (`CMD uvicorn ...`). Combined with the SSRF/CSRF findings above, any future RCE-class bug in the request-handling path would execute as root inside the container, increasing blast radius.

**Suggested fix:** Add a non-root user in the final build stage (`RUN useradd -r -u 1000 appuser`, then `USER appuser` before `CMD`), ensuring mounted volumes are writable by that UID. Same applies to `uat/api.Dockerfile` (lower priority — UAT-only, not shipped).

### 8. [Low] Auth credential passed as plain environment variable
**File:** `docker-compose.yml:20-21` (`DNSWATCH_AUTH_PASSWORD: ${DNSWATCH_AUTH_PASSWORD:-}`)

Plain env vars are visible via `docker inspect`, `/proc/<pid>/environ`, and process listings to anyone with host/container access. Likely an acceptable tradeoff for a single-user homelab tool, but worth flagging since it's an auth credential.

**Suggested fix:** Optionally support a `DNSWATCH_AUTH_PASSWORD_FILE` pattern to read from a mounted file/Docker secret for users who want stronger isolation; otherwise document the tradeoff explicitly.

### 9. [Info] Error messages may leak target host on webhook delivery failure
**File:** `server/app/alerts.py:274-275` (`except Exception as e: return False, str(e)`)

`urllib` exceptions can embed the target URL/host (not the secret) in their string representation. Low sensitivity, but confirm this error string isn't forwarded to a shared/less-trusted logging sink beyond the settings UI.

### 10. [Info] No `HEALTHCHECK`, Node version drift between prod build and UAT
**Files:** `server/Dockerfile` (Node 20 build stage) vs `uat/docker-compose.uat.yml`/`uat/api.Dockerfile` (Node 22) — no `HEALTHCHECK` in either Dockerfile.

Not a security issue; noting for build-parity and operational completeness.

## Verified as already handled correctly

- **Pi-hole DB is read-only end-to-end.** Every one of the 20 connection call sites in `server/app/db.py` routes through a single `_connect()` helper using `sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, ...)`. No fallback path, no writable default, no code path bypasses it. Confirmed by direct trace of every call site.
- **Webhook settings endpoint masks the stored secret.** `GET /api/settings` (`server/app/alerts.py:120-136`) returns only `webhook_secret_set: bool`; the raw secret is held by a separate internal-only accessor used solely by delivery/evaluation. `POST /api/settings/test-webhook` only ever echoes back a secret the caller itself supplied — not a leak of the stored value.
- **Redirects are not followed on webhook delivery.** `_NoRedirectHandler.redirect_request` (`alerts.py:211-212`) unconditionally returns `None`; confirmed wired into the actual opener used for delivery.
- **Link-local/cloud-metadata/multicast/reserved SSRF blocking works for its intended cases** (169.254.169.254, `fe80::`, multicast, `0.0.0.0`/`::`) — but see finding #1 for the rebinding gap that bypasses it, and finding #3 for the IPv6-loopback inconsistency.
- **HTTP Basic auth uses a timing-safe comparison.** `server/app/main.py:81` uses `hmac.compare_digest` for both username and password, joined with bitwise `&` (not `and`) specifically to avoid short-circuit timing leakage between the two checks.
- **Auth middleware covers every route**, including all newer endpoints (anomalies, client-activity, heatmap, simulate-blocklist, tail) and the static frontend mount — confirmed by tracing the global Starlette middleware and every registered route. Only `/api/health` and `OPTIONS` are intentionally exempted.
- **No frontend XSS found.** Every render site for client name/hostname/domain (`QueryTable.tsx`, `ClientList.tsx`, `ClientDetailModal.tsx`, `DrilldownModal.tsx`, `HeatmapCellModal.tsx`, `AnomaliesPanel.tsx`, `SimulatorTab.tsx`, `LiveStreamTab.tsx`, `FilterBar.tsx`, `App.tsx`) uses plain JSX text interpolation (auto-escaped). No `dangerouslySetInnerHTML`, no raw DOM/`innerHTML`, no `eval`/`new Function` anywhere in `web/src`. The one dynamic `href` (CSV export) is built from filter state via `URLSearchParams`, not attacker-controlled data.
- **No secrets in frontend storage.** The only `localStorage` usage (`highlightRules.ts`) stores user-defined display rules, not credentials. The webhook secret field is `type="password"`, never fetched back from the server, never logged to console.
- **Docker-level read-only mount matches app-level intent.** `docker-compose.yml` mounts the Pi-hole path `:ro`; same for both services in `uat/docker-compose.uat.yml`.
- **`uat/snapshot-pihole-db.sh` handles the real DB snapshot safely** — runs as the invoking host UID (`--user "$(id -u):$(id -g)"`, non-root), mounts source read-only, works in an ephemeral container-local temp dir, output lands only in the `.gitignore`d `uat/pihole-data/`.
- **`.env.example` contains only placeholder values**, no real secrets.
- **No SQL injection found** in either `server/app/db.py` or `server/app/alerts.py` — all user-supplied values are bound parameters.

## Lint / Code Quality (lower priority)

**Python:**
- `ruff check .`: 1 finding — `F401` unused import `conftest.CLIENTS` in `server/tests/test_alerts.py:57` (trivial, auto-fixable).
- `bandit -r app -q`: 27 findings, 0 High severity. Notable: `B608` (f-string SQL, see finding #6 above), `B107` hardcoded-default-password on `secret: str = ""` params in `alerts.py:251,278` (false-positive — these are optional webhook secrets, not passwords), `B110`/`B112` bare `except: pass`/`continue` in `main.py:34,83` and `alerts.py:449` (appear intentional per inline comments — background scheduler and auth middleware deliberately swallow to avoid crashing the app loop, but worth confirming these can't silently swallow an unexpected auth-bypass condition).
- `pip-audit`: 5 CVEs, all in the container's bundled `pip` tool itself (not a project dependency — `dns-dashboard-server` isn't published to PyPI so its own deps weren't auditable this way; cross-check `pyproject.toml` pins manually if precise dependency-vulnerability data is needed).
- `pytest`: 211 passed, 1 deprecation warning (Starlette `TestClient` usage — cosmetic).

**Frontend:**
- `tsc --noEmit`: clean, exit 0.
- `npm audit --omit=dev`: 0 vulnerabilities in production dependencies.
- `npm audit` (including devDependencies): 2 vulnerabilities (1 moderate, 1 high) — `esbuild <=0.24.2` / `vite <=6.4.2` dev-server request-forgery advisory. Dev-only exposure; not present in the built/shipped bundle. No ESLint config present in `web/` (not added, per audit scope — noting absence only).

**Dependencies:** `server/pyproject.toml` (`fastapi>=0.115`, `uvicorn[standard]>=0.30`) and `web/package.json` (`react@^18.3.1`, `vite@^5.4.0`) are current, reasonably-pinned floors — no abandoned or obviously stale packages found.
