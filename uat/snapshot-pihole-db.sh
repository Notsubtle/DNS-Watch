#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Snapshot the live Pi-hole FTL database into the UAT env (read-only seed).
#
#   The live DB runs in WAL mode and Pi-hole writes to it constantly, so we can't
#   just copy pihole-FTL.db — we'd miss the -wal contents or catch a torn write.
#   Instead we copy the db + its -wal/-shm sidecars, then (on the COPY, never the
#   live file) checkpoint the WAL and `VACUUM INTO` a single clean, standalone
#   file with no sidecars — perfect for a read-only bind-mount.
#
#   The live database is only ever READ here. Re-run this any time you want fresh
#   data in UAT.  No sqlite3 CLI needed — the work runs in a python:3.12 container.
#
#   Usage:  ./snapshot-pihole-db.sh   (from the uat/ dir, or anywhere)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# Live Pi-hole etc-pihole folder on Cube1 (post SSD-pool migration).
SRC_DIR="${PIHOLE_ETC_PATH:-/media/TempSSD/pihole/etc-pihole}"
OUT_DIR="$(cd "$(dirname "$0")" && pwd)/pihole-data"

[ -r "$SRC_DIR/pihole-FTL.db" ] || {
  echo "ABORT: cannot read $SRC_DIR/pihole-FTL.db" >&2
  echo "       Set PIHOLE_ETC_PATH to your live etc-pihole folder and retry." >&2
  exit 1
}

mkdir -p "$OUT_DIR"
echo "Snapshotting $SRC_DIR/pihole-FTL.db -> $OUT_DIR/pihole-FTL.db ..."

# Run as the current user so the output file is owned by you, not root.
docker run --rm -i \
  --user "$(id -u):$(id -g)" \
  -v "$SRC_DIR":/src:ro \
  -v "$OUT_DIR":/out \
  python:3.12-slim python - <<'PY'
import os, shutil, sqlite3, tempfile

work = tempfile.mkdtemp()
# Copy the db and any WAL/SHM sidecars (read-only source).
for f in ("pihole-FTL.db", "pihole-FTL.db-wal", "pihole-FTL.db-shm"):
    s = os.path.join("/src", f)
    if os.path.exists(s):
        shutil.copy2(s, os.path.join(work, f))

src = os.path.join(work, "pihole-FTL.db")
out = "/out/pihole-FTL.db"
if os.path.exists(out):
    os.remove(out)  # VACUUM INTO refuses to overwrite

conn = sqlite3.connect(src)
conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # merge WAL into the copy
conn.execute(f"VACUUM INTO '{out}'")             # clean single-file snapshot
conn.close()

mb = os.path.getsize(out) / 1e6
print(f"  wrote snapshot: {mb:.1f} MB")
PY

echo "Done. UAT will read this file read-only."
