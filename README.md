# DNS Watch — a live per-client DNS dashboard for Pi-hole

A small, self-hosted dashboard that sits **next to** your existing Pi-hole container,
reads its query database directly, and gives you a filterable, live view of which
device is visiting which domain.

Visual style borrows the "ink" dark palette from the Jooce dashboard project (same
CSS variable approach), but this is a fresh, purpose-built app — different data
model entirely (DNS queries/clients, not coding sessions).

```
dns-dashboard/
  docker-compose.yml     <- run this alongside your existing pihole docker-compose
  server/                <- FastAPI backend, reads pihole-FTL.db read-only
  web/                   <- Vite + React + TypeScript frontend
```

## Why DNS Watch, when Pi-hole already has a dashboard?

Pi-hole's built-in admin UI is genuinely good, and DNS Watch is **not a replacement**
for it — you still use Pi-hole's own dashboard to manage blocklists, DHCP, upstream
resolvers, and everything else. DNS Watch is a **focused, read-only lens** for one
job Pi-hole's dashboard doesn't really cover: *watching what each device on your
network is doing, and telling you when something changes.*

What it adds on top of Pi-hole's dashboard:

- **Per-client first.** Pi-hole's dashboard is aggregate-first (totals, then you dig
  for per-device detail). DNS Watch is built the other way around: client is a
  first-class filter, every top client has an activity **sparkline**, and you can
  slice the whole view to a single device instantly.
- **New-device flagging.** Any device whose first-ever query landed in the last 24h
  gets a **NEW** badge. Pi-hole won't tell you a new gadget just joined your network;
  this does — which is exactly when an unexpected device matters most.
- **Proactive alerting Pi-hole simply doesn't have.** Rules for query-volume spikes
  (per-client or overall), new devices, and domain-keyword watches — with optional
  **webhook delivery** to ntfy, Home Assistant, Slack, or Discord. Pi-hole *shows*
  you data; DNS Watch can *notify* you without you having a tab open.
- **Domain drill-down.** Click any top domain to see exactly which clients queried
  it in the current window — a workflow that's clunky in Pi-hole's query log.
- **Works even with Pi-hole's UI locked down.** It reads the FTL database directly,
  so it keeps working if you've hardened or disabled Pi-hole's admin web UI. It also
  never writes to Pi-hole — the database is opened strictly read-only, so there's
  zero risk to DNS resolution.
- **Yours to extend.** It's a small FastAPI + React app — add rule types, panels, or
  exports to fit how *you* watch your network. CSV export of the current filtered
  view is built in.

In short: keep Pi-hole for **controlling** DNS; add DNS Watch for **observing and
being alerted about** per-client activity.

## How it works

- Pi-hole (FTL) already logs every DNS query to a SQLite database at
  `/etc/pihole/pihole-FTL.db` inside its container/volume.
- This app **never touches Pi-hole's DNS resolution path** — it only opens that
  database file **read-only** and serves it up as a filterable API + UI.
- No changes to your Pi-hole container are required. Zero risk of interfering with
  DNS resolution.

## Setup

### 1. Locate your Pi-hole data volume

From your existing `~/pihole/docker-compose.yml`, you're already mounting:
```yaml
volumes:
  - './etc-pihole:/etc/pihole'
```
That `./etc-pihole` folder (on the Ubuntu host) contains `pihole-FTL.db`. Note its
absolute path, e.g. `/home/steve/pihole/etc-pihole`.

### 2. Configure this project

```bash
cd dns-dashboard
cp .env.example .env
# edit .env: set PIHOLE_ETC_PATH to the absolute path from step 1
```

### 3. Run it

```bash
docker compose up -d --build
```

Dashboard: `http://<ubuntu-host-ip>:8090`

### 4. Local dev (optional, hot reload)

```bash
# backend
cd server
pip install -e . --break-system-packages
# DNSWATCH_DB_PATH is where alert rules/events are stored; point it somewhere
# writable in local dev (it defaults to /data/dnswatch.db, the Docker volume).
PIHOLE_DB_PATH=/path/to/pihole-FTL.db DNSWATCH_DB_PATH=./dnswatch.db \
  uvicorn app.main:app --reload --port 8090

# frontend (separate terminal)
cd web
npm install
npm run dev    # http://localhost:5173, proxies /api to :8090
```

## What you get

- **Live query table** — every DNS query, auto-refreshing, with client, domain,
  status (allowed/blocked), and timestamp.
- **Filters** — by client (dropdown of known devices), domain (substring search),
  status (allowed / blocked / all), and time range (15m / 1h / 24h / 7d / custom).
- **Summary cards** — total queries, blocked %, unique clients, unique domains for
  the current filter/time window.
- **Top domains / top clients** — ranked lists for the current filter window.
  Top clients show a per-client activity **sparkline** and a **NEW** badge for
  devices first seen in the last 24h. Click a top domain to open a **drill-down**
  showing which clients queried it, or click a **client** to open its full
  **detail view** (its own volume chart, top domains, query types, first/last seen).
- **Query-volume chart** — a time-series of allowed vs. blocked queries across the
  selected range, bucketed and hoverable.
- **Query-type breakdown** — A / AAAA / HTTPS / PTR / … distribution.
- **CSV export** — download the current filtered query view.
- **Pagination** — the query log is paged with an exact total ("201–400 of 5,000").
- **Alert rules** — watch for query-volume spikes (per-client or overall), new
  devices, specific domain keywords, or a **device going quiet** (an active client
  that suddenly stops querying — offline/unplugged/blocked). Rules are evaluated
  **server-side on a timer** (`ALERT_EVAL_INTERVAL_SECONDS`, default 60), so alerts fire and webhooks
  send even with no dashboard open. Fired alerts show in the Alerts panel.
  Rules and events are stored in DNS Watch's **own** writable SQLite database
  (`DNSWATCH_DB_PATH`, default `/data/dnswatch.db`, mounted as the `dnswatch-data`
  volume) — Pi-hole's database is still only ever opened read-only.
- **Webhook delivery (optional)** — toggle it on in **⚙ Settings** and paste a URL
  to have fired alerts POSTed out (with a "Send test" button to verify). Pick a
  **format** — *Generic JSON* (ntfy / Home Assistant / custom, summary in
  `text`/`content` plus structured `alerts`), *Slack* (top-level `text`), or
  *Discord* (`content`, capped at Discord's limit). An optional **auth token** is
  sent as an `Authorization: Bearer` header (e.g. an ntfy access token) — for
  Slack/Discord the secret is already in the URL, so leave it blank. Delivery runs
  off-thread, so a slow or unreachable endpoint never affects the dashboard.
- **Client naming** — pulls names Pi-hole already knows (from DHCP lease / your
  manual naming in Pi-hole's own UI); no separate naming step needed.
- **Optional login** — set `DNSWATCH_AUTH_PASSWORD` (see `.env.example`) to gate the
  whole app behind HTTP Basic auth. Left unset, it's open on your LAN as before.

## Notes / limitations

- Status classification (allowed vs blocked) is based on Pi-hole FTL's internal
  status codes. The mapping in `server/app/db.py` (`BLOCKED_STATUSES`) covers all
  current Pi-hole versions as of writing, but if you upgrade Pi-hole and see queries
  misclassified, check Pi-hole's FTL changelog for new status codes and adjust that
  set — the raw `status` code is always shown alongside so you can spot mismatches.
- This reads the DB directly rather than going through Pi-hole's API, so it works
  even if you've locked down Pi-hole's admin UI per the hardening guide.
- SQLite read-only connections don't lock the file, so this has effectively zero
  performance impact on Pi-hole/FTL.
- The dashboard exposes who-visited-what and lets you configure webhooks, so treat
  it as sensitive. The optional Basic auth guards access, but it's cleartext over
  HTTP — if DNS Watch is reachable beyond a trusted LAN, front it with a TLS
  reverse proxy (Caddy, nginx, Traefik).
