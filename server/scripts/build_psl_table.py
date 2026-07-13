#!/usr/bin/env python3
"""Regenerate server/app/data/public_suffix_list.dat.gz from the Mozilla-run
Public Suffix List.

Usage:
    python scripts/build_psl_table.py [path/to/public_suffix_list.dat]

With no argument, downloads the current list from
https://publicsuffix.org/list/public_suffix_list.dat. Pass a local path to
rebuild from an already-downloaded copy (e.g. in an offline/CI environment).

Output is a gzip-compressed, comment-stripped copy of the raw rule lines
(one rule per line: a plain suffix, a "*."-prefixed wildcard rule, or a
"!"-prefixed exception rule), checked into the repo so app/psl.py never
makes a network call to compute a domain's registered parent at runtime.
Backs the DNS-tunneling/exfiltration detector (#2 in the feature backlog),
which needs to group a client's queries by registered parent domain --
naive last-two-labels parsing breaks on multi-part suffixes like co.uk.
"""

from __future__ import annotations

import gzip
import sys
import urllib.request

SOURCE_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
OUT_PATH = "app/data/public_suffix_list.dat.gz"


def fetch(path: str | None) -> str:
    if path:
        with open(path, encoding="utf-8") as f:
            return f.read()
    with urllib.request.urlopen(SOURCE_URL, timeout=30) as resp:
        return resp.read().decode("utf-8")


def build(raw_text: str) -> list[str]:
    rules = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        rules.append(line)
    return rules


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else None
    rules = build(fetch(path))
    if not rules:
        raise SystemExit("no rules parsed — source format may have changed")
    with gzip.open(OUT_PATH, "wt", encoding="utf-8") as f:
        for rule in rules:
            f.write(f"{rule}\n")
    print(f"wrote {len(rules)} PSL rules to {OUT_PATH}")


if __name__ == "__main__":
    main()
