#!/usr/bin/env python3
"""Regenerate server/app/data/oui_ma_l.tsv.gz from IEEE's public MA-L registry.

Usage:
    python scripts/build_oui_table.py [path/to/oui.csv]

With no argument, downloads the current registry from
https://standards-oui.ieee.org/oui/oui.csv. Pass a local path to rebuild from
an already-downloaded copy (e.g. in an offline/CI environment).

Output is a gzip-compressed TSV (prefix<TAB>vendor), MA-L entries only
(6 hex chars -> vendor name), sorted by prefix, checked into the repo so the
app never makes a network call to resolve a vendor at runtime. See issue #5
for why MA-L only (not MA-M/MA-S): those are narrower sub-prefixes that need
real longest-prefix matching, which this simple table doesn't do.
"""

from __future__ import annotations

import csv
import gzip
import io
import re
import sys
import urllib.request

SOURCE_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUT_PATH = "app/data/oui_ma_l.tsv.gz"

_HEX_PREFIX = re.compile(r"^[0-9A-Fa-f]{6}$")


def fetch(path: str | None) -> str:
    if path:
        with open(path, encoding="utf-8") as f:
            return f.read()
    with urllib.request.urlopen(SOURCE_URL, timeout=30) as resp:
        return resp.read().decode("utf-8")


def build(csv_text: str) -> list[tuple[str, str]]:
    reader = csv.DictReader(io.StringIO(csv_text))
    entries = []
    for row in reader:
        if row.get("Registry") != "MA-L":
            continue
        prefix = (row.get("Assignment") or "").strip().upper()
        vendor = (row.get("Organization Name") or "").strip()
        if not _HEX_PREFIX.match(prefix) or not vendor:
            continue
        entries.append((prefix, vendor))
    entries.sort()
    return entries


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else None
    entries = build(fetch(path))
    if not entries:
        raise SystemExit("no MA-L entries parsed — source format may have changed")
    with gzip.open(OUT_PATH, "wt", encoding="utf-8") as f:
        for prefix, vendor in entries:
            f.write(f"{prefix}\t{vendor}\n")
    print(f"wrote {len(entries)} MA-L entries to {OUT_PATH}")


if __name__ == "__main__":
    main()
