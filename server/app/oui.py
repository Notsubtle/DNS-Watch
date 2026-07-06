"""Offline MAC-vendor (OUI) lookup — issue #5.

Fills in vendor names for clients where Pi-hole has a real `hwaddr` but its
own `network.macVendor` is empty. Looks up only against the bundled MA-L
(/24) table in `app/data/oui_ma_l.tsv.gz`, built from IEEE's public registry
by `scripts/build_oui_table.py` — no network call at runtime. MA-M/MA-S
(narrower sub-prefixes) are deliberately out of scope: a naive first-3-octet
match against those would misattribute vendors, and the review that scoped
this feature (see issue #5) recommended MA-L-only as the documented v1
tradeoff.
"""

from __future__ import annotations

import gzip
import os
import re
from functools import lru_cache

_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "oui_ma_l.tsv.gz")

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})")


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    table: dict[str, str] = {}
    try:
        with gzip.open(_DATA_PATH, "rt", encoding="utf-8") as f:
            for line in f:
                prefix, _, vendor = line.rstrip("\n").partition("\t")
                if prefix and vendor:
                    table[prefix] = vendor
    except OSError:
        pass  # missing data file shouldn't break vendor lookups, just no-op them
    return table


def is_locally_administered(hwaddr: str) -> bool:
    """True for randomized/private MACs (common on modern mobile OSes),
    identified by the U/L bit (0x02) in the first octet — these have no
    vendor in any registry by design, not merely an unlisted one."""
    m = _MAC_RE.match(hwaddr)
    if not m:
        return False
    first_octet = int(m.group(1), 16)
    return bool(first_octet & 0x02)


def lookup_vendor(hwaddr: str) -> str | None:
    """MA-L prefix lookup for a real (non-placeholder) hwaddr. Returns None
    for randomized MACs and genuine misses alike — callers distinguish the
    two via `is_locally_administered()` (see db._client_vendor_map)."""
    m = _MAC_RE.match(hwaddr)
    if not m:
        return None
    prefix = f"{m.group(1)}{m.group(2)}{m.group(3)}".upper()
    return _table().get(prefix)
