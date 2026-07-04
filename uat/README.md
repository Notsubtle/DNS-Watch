# DNS Watch — UAT environment

A throwaway environment for **making code changes and visually verifying them**
before they touch production. It reads a **read-only snapshot** of the real
Pi-hole database, so the dashboard shows realistic data without any dependency
on — or risk to — the live Pi-hole or your production DNS Watch state.

Everything lives under `uat/` and nothing here is wired into
`docker-compose.yml` (production). Run all commands from the repo root.

## One-time-ish: seed the data

```bash
./uat/snapshot-pihole-db.sh
```

Copies the live Pi-hole FTL database into `uat/pihole-data/pihole-FTL.db` as a
clean, consolidated, read-only file. The live DB is only ever **read**. Re-run
this whenever you want fresher data. The snapshot is git-ignored (it contains
real DNS history).

> Reads `/media/TempSSD/pihole/etc-pihole` by default. Override with
> `PIHOLE_ETC_PATH=/some/other/etc-pihole ./uat/snapshot-pihole-db.sh`.

## Option 1 — Hot-reload dev stack (fast iteration)

```bash
docker compose -f uat/docker-compose.uat.yml up --build
```

- **Open → http://localhost:5173** (the Vite frontend)
- API is at http://localhost:8091

Edit any file under `web/src/**` and the browser hot-updates in ~1s. Edit any
file under `server/app/**` and the API auto-reloads. This is the loop for
iterating on enhancements.

> Not byte-identical to production (dev server + HMR vs. a built bundle), so use
> Option 2 for final sign-off.

## Option 2 — Prod-like preview (final verification)

```bash
docker compose -f uat/docker-compose.uat.yml --profile prod up --build app
```

- **Open → http://localhost:8092**

Builds the exact single-container image that ships (`server/Dockerfile`:
frontend compiled to static assets, served by FastAPI). What you see here is
what production renders. Re-run with `--build` after changes to rebuild.

## Teardown

```bash
docker compose -f uat/docker-compose.uat.yml --profile prod down        # stop
docker compose -f uat/docker-compose.uat.yml --profile prod down -v     # + wipe the throwaway alert-state volume
```

## Ports

| Service | URL | Purpose |
|---|---|---|
| web (dev) | http://localhost:5173 | Vite frontend, HMR |
| api (dev) | http://localhost:8091 | FastAPI, `--reload` |
| app (prod-like) | http://localhost:8092 | Built image, opt-in via `--profile prod` |

Production (`docker-compose.yml`) uses **8090** and is untouched by any of this.
