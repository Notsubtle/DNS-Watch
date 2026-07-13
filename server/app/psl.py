"""Offline Public Suffix List lookup — backs the DNS-tunneling/exfiltration
detector (#2 in the feature backlog).

Classic DNS tunneling (iodine, dnscat2) and some exfiltration tooling show up
as one client emitting a large number of distinct/high-entropy subdomains
under a single REGISTERED parent domain (e.g. "a1b2c3.tunnel.example.com").
Grouping by registered parent needs real Public Suffix List awareness --
naive last-two-labels parsing misidentifies the parent for multi-part
suffixes like "co.uk" (last two labels of "foo.co.uk" is "co.uk" itself, not
"foo.co.uk") and would equally misfire on "*.s3.amazonaws.com"-style private
suffixes shared by many unrelated tenants.

Looks up only against the bundled table in `app/data/public_suffix_list.dat.gz`
(built from https://publicsuffix.org by `scripts/build_psl_table.py`) — no
network call at runtime, matching this codebase's `oui.py` convention.
"""

from __future__ import annotations

import gzip
import os
from functools import lru_cache

_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "public_suffix_list.dat.gz")


@lru_cache(maxsize=1)
def _rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """(plain, wildcard_bases, exceptions) -- see registered_domain()'s
    docstring for how each set is used. wildcard_bases holds the part AFTER
    "*." (e.g. "*.bd" -> "bd"); exceptions hold the full rule text minus its
    leading "!" (e.g. "!city.kawasaki.jp" -> "city.kawasaki.jp")."""
    plain: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()
    try:
        with gzip.open(_DATA_PATH, "rt", encoding="utf-8") as f:
            for line in f:
                rule = line.strip()
                if not rule:
                    continue
                if rule.startswith("!"):
                    exception.add(rule[1:].lower())
                elif rule.startswith("*."):
                    wildcard.add(rule[2:].lower())
                else:
                    plain.add(rule.lower())
    except OSError:
        pass  # missing data file shouldn't break callers, just no-op the lookup
    return frozenset(plain), frozenset(wildcard), frozenset(exception)


def registered_domain(hostname: str) -> str:
    """The registered domain (public suffix + exactly one label) for
    `hostname` -- e.g. "a1b2.tunnel.example.com" -> "example.com",
    "foo.co.uk" -> "foo.co.uk" (co.uk is the public suffix here, so the
    whole thing IS the registered domain), "localhost" -> "localhost"
    (no dot at all -- returned as-is, there's no registrable parent above a
    single label).

    Implements the standard PSL longest-match algorithm (with wildcard and
    exception rule support); falls back to the implicit "*" rule (treat the
    last label alone as the suffix) for anything not covered by the bundled
    list, same as every PSL-consuming library does for unlisted TLDs.
    """
    host = hostname.rstrip(".").lower()
    labels = host.split(".")
    if len(labels) <= 1:
        return host
    plain, wildcard, exception = _rules()

    best_suffix_len = 0  # in labels
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        candidate_len = len(labels) - i
        if candidate in exception:
            # The exception carves the matched candidate itself OUT of the
            # suffix -- the prevailing suffix is one label shorter (drop the
            # leftmost label of the exception match).
            if candidate_len - 1 > best_suffix_len:
                best_suffix_len = candidate_len - 1
            continue
        if candidate in plain:
            if candidate_len > best_suffix_len:
                best_suffix_len = candidate_len
            continue
        rest = ".".join(labels[i + 1:])
        if rest and rest in wildcard and candidate_len > best_suffix_len:
            best_suffix_len = candidate_len

    if best_suffix_len == 0:
        best_suffix_len = 1  # implicit "*" rule: unlisted TLD, last label only

    if best_suffix_len >= len(labels):
        # The whole hostname IS (at most) the public suffix -- no label left
        # above it to be "the registered one"; return it whole rather than
        # fabricating a registrable label that doesn't exist.
        return host
    return ".".join(labels[-(best_suffix_len + 1):])
