#!/bin/sh
# Runs as root (the container's default user) so it can fix ownership of
# /data before dropping to the non-root appuser to actually run the app.
#
# Needed for upgrades: an existing `dnswatch-data` volume created while this
# image still ran as root would contain a root-owned dnswatch.db, which the
# now-non-root appuser couldn't open for writing without this — a silent
# "alert rules stop persisting" regression on upgrade otherwise.
set -e
chown -R appuser:appuser /data 2>/dev/null || true
exec su -s /bin/sh appuser -c 'exec "$0" "$@"' -- "$@"
