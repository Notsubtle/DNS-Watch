#!/usr/bin/env python3
"""On-demand performance harness: view-resolution vs direct-ID aggregates.

This is NOT part of the pytest suite and is deliberately not collected by it
(the filename is `bench_*`, not `test_*`), because it generates large
synthetic Pi-hole-shaped databases (up to ~40M rows / ~0.5 GB) that are far
too slow to build on every commit or in CI. Run it by hand when you want to
re-verify the performance claims behind the id-based aggregate rewrite at
scale. Correctness is covered separately and cheaply by
`tests/test_id_aggregates.py`.

It mirrors the real UAT snapshot schema (verified via PRAGMA):
  query_storage(id PK AUTOINCREMENT, timestamp INT, type INT, status INT,
                domain INT, client INT, ...)   -- domain/client are integer FKs
  domain_by_id(id PK, domain TEXT)
  client_by_id(id PK, ip TEXT, name TEXT)
  queries = VIEW resolving domain/client FKs via a correlated subquery per row.

For each scale it times three approaches per query pattern:
  a_view      -- group/filter through the `queries` view (what DNS Watch did
                 before this rewrite; one correlated subquery per scanned row)
  b_direct    -- group/filter on the raw integer ids, resolve only the result
                 (what DNS Watch does now on the normalized schema)
  c_dir+idx   -- b_direct after CREATE INDEX on query_storage(domain)/(client)
                 (the optional user-side index documented in the README; note
                 it does NOT help every pattern -- see summary_distinct)
and prints EXPLAIN QUERY PLAN evidence that the direct path avoids the
correlated subquery.

Requires numpy (not a runtime dependency of DNS Watch itself; install it into
a throwaway venv/container to run this):
    pip install numpy
    python tests/perf/bench_id_aggregates.py                 # all scales
    python tests/perf/bench_id_aggregates.py 764k            # one scale
    DNSWATCH_BENCH_SCRATCH=/var/tmp/mybench python .../bench_id_aggregates.py

Generated .sqlite files are written under the scratch dir (default: a
`dnswatch-bench` folder under the OS temp dir) and are NEVER committed. They
are reused across runs if already present, so the first run is the slow one.
"""
import os
import statistics
import sqlite3
import sys
import tempfile
import time

import numpy as np

SCRATCH = os.environ.get(
    "DNSWATCH_BENCH_SCRATCH", os.path.join(tempfile.gettempdir(), "dnswatch-bench")
)

# (label, n_rows, n_domains, n_clients, span_days)
SCALES = [
    ("764k_baseline",    764_053,   6_975, 23,   9.17),
    ("7_6M_91day",     7_600_000,  30_000, 23,  91.0),
    ("40M_smallbiz",  40_000_000, 120_000, 75, 365.0),
]

RNG = np.random.default_rng(42)


def zipf_ids(n_rows, n_items, exponent=1.1):
    """Zipfian-ish sample of item ids in [1, n_items]. A few items dominate,
    like real DNS traffic where a handful of domains/clients are very hot."""
    ranks = np.arange(1, n_items + 1)
    weights = 1.0 / np.power(ranks, exponent)
    weights /= weights.sum()
    # shuffle rank->id mapping so 'hot' ids aren't all low ids
    perm = RNG.permutation(n_items) + 1
    idx = RNG.choice(n_items, size=n_rows, p=weights)
    return perm[idx].astype(np.int64)


def build_db(path, n_rows, n_domains, n_clients, span_days):
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    cur = con.cursor()
    cur.execute("PRAGMA journal_mode=OFF")
    cur.execute("PRAGMA synchronous=OFF")
    cur.executescript("""
    CREATE TABLE query_storage (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL,
        type INTEGER NOT NULL, status INTEGER NOT NULL, domain INTEGER NOT NULL, client INTEGER NOT NULL,
        forward INTEGER, additional_info INTEGER, reply_type INTEGER, reply_time REAL, dnssec INTEGER,
        list_id INTEGER, ede INTEGER);
    CREATE TABLE domain_by_id (id INTEGER PRIMARY KEY, domain TEXT NOT NULL);
    CREATE TABLE client_by_id (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, name TEXT);
    """)
    con.executemany("INSERT INTO domain_by_id(id,domain) VALUES(?,?)",
                    [(i, f"domain-{i:06d}.example.net") for i in range(1, n_domains + 1)])
    con.executemany("INSERT INTO client_by_id(id,ip,name) VALUES(?,?,?)",
                    [(i, f"10.{(i >> 8) & 255}.{i & 255}.{i % 254 + 1}", f"device-{i}")
                     for i in range(1, n_clients + 1)])
    # correlated-subquery-resolving view, identical in shape to Pi-hole's
    con.executescript("""
    CREATE VIEW queries AS SELECT id,timestamp,type,status,
      CASE typeof(domain) WHEN 'integer' THEN (SELECT domain FROM domain_by_id d WHERE d.id=q.domain) ELSE domain END domain,
      CASE typeof(client) WHEN 'integer' THEN (SELECT ip FROM client_by_id c WHERE c.id=q.client) ELSE client END client,
      forward,additional_info,reply_type,reply_time,dnssec,list_id,ede
      FROM query_storage q;""")

    now = int(time.time())
    start = now - int(span_days * 86400)
    batch = 1_000_000
    done = 0
    while done < n_rows:
        b = min(batch, n_rows - done)
        ts = RNG.integers(start, now, size=b, dtype=np.int64)
        dom = zipf_ids(b, n_domains)
        cli = zipf_ids(b, n_clients, exponent=0.9)
        typ = RNG.integers(1, 17, size=b, dtype=np.int64)
        # status skewed: mostly forwarded(2)/cached(3), some blocked(1)
        stat = RNG.choice([1, 2, 3], size=b, p=[0.25, 0.45, 0.30]).astype(np.int64)
        rows = zip(ts.tolist(), typ.tolist(), stat.tolist(), dom.tolist(), cli.tolist())
        con.executemany(
            "INSERT INTO query_storage(timestamp,type,status,domain,client) VALUES(?,?,?,?,?)", rows)
        done += b
    cur.execute("CREATE INDEX idx_queries_timestamp ON query_storage(timestamp)")
    con.commit()
    con.close()


def med_time(fn, runs=3):
    ts = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        ts.append(time.perf_counter() - t0)
    return statistics.median(ts), min(ts)


# --- query patterns -------------------------------------------------------
def q_topdom_view(con):
    return con.execute(
        "SELECT q.domain, COUNT(*) n FROM queries q GROUP BY q.domain ORDER BY n DESC LIMIT 15").fetchall()


def q_topdom_direct(con):
    rows = con.execute(
        "SELECT domain, COUNT(*) n FROM query_storage GROUP BY domain ORDER BY n DESC LIMIT 15").fetchall()
    out = []
    for did, n in rows:
        name = con.execute("SELECT domain FROM domain_by_id WHERE id=?", (did,)).fetchone()[0]
        out.append((name, n))
    return out


def q_summary_view(con):
    return con.execute(
        "SELECT COUNT(*), COUNT(DISTINCT q.domain), COUNT(DISTINCT q.client) FROM queries q").fetchone()


def q_summary_direct(con):
    return con.execute(
        "SELECT COUNT(*), COUNT(DISTINCT domain), COUNT(DISTINCT client) FROM query_storage").fetchone()


def q_clientact_view(con):
    return con.execute(
        "SELECT q.client, COUNT(*) n, MAX(q.timestamp) FROM queries q GROUP BY q.client ORDER BY n DESC").fetchall()


def q_clientact_direct(con):
    rows = con.execute(
        "SELECT client, COUNT(*) n, MAX(timestamp) FROM query_storage GROUP BY client ORDER BY n DESC").fetchall()
    out = []
    for cid, n, mx in rows:
        ip = con.execute("SELECT ip FROM client_by_id WHERE id=?", (cid,)).fetchone()[0]
        out.append((ip, n, mx))
    return out


PATTERNS = {
    "top_domains":      (q_topdom_view, q_topdom_direct),
    "summary_distinct": (q_summary_view, q_summary_direct),
    "client_activity":  (q_clientact_view, q_clientact_direct),
}


def eqp(con, sql):
    return [r[3] for r in con.execute("EXPLAIN QUERY PLAN " + sql).fetchall()]


def main():
    os.makedirs(SCRATCH, exist_ok=True)
    only = sys.argv[1] if len(sys.argv) > 1 else None
    results = {}
    for label, nrows, ndom, ncli, span in SCALES:
        if only and only not in label:
            continue
        path = f"{SCRATCH}/db_{label}.sqlite"
        if not os.path.exists(path):
            print(f"[build] {label} rows={nrows:,} dom={ndom:,} cli={ncli} span={span}d", flush=True)
            t0 = time.time()
            build_db(path, nrows, ndom, ncli, span)
            print(f"[build] done in {time.time() - t0:.0f}s size={os.path.getsize(path) / 1e9:.2f}GB",
                  flush=True)

        con = sqlite3.connect(path)
        con.execute("PRAGMA cache_size=-200000")  # ~200MB page cache

        # correctness spot-check on the smallest scale only
        if "764k" in label:
            for pat, (vfn, dfn) in PATTERNS.items():
                ok = vfn(con) == dfn(con)
                print(f"[correctness {label}] {pat}: {'MATCH' if ok else 'MISMATCH'}")

        for pat, (vfn, dfn) in PATTERNS.items():
            tv, _ = med_time(lambda vfn=vfn: vfn(con))
            td, _ = med_time(lambda dfn=dfn: dfn(con))
            results[(label, pat, "a_view")] = tv
            results[(label, pat, "b_direct")] = td

        # (c) add indexes on domain & client, retest the direct approach
        con.execute("CREATE INDEX IF NOT EXISTS idx_qs_domain ON query_storage(domain)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_qs_client ON query_storage(client)")
        for pat, (vfn, dfn) in PATTERNS.items():
            tc, _ = med_time(lambda dfn=dfn: dfn(con))
            results[(label, pat, "c_direct_idx")] = tc

        print(f"\n[EQP {label}]")
        print(" view top_domains :", eqp(con, "SELECT q.domain,COUNT(*) n FROM queries q GROUP BY q.domain ORDER BY n DESC LIMIT 15"))
        print(" direct top_domains(+idx):", eqp(con, "SELECT domain,COUNT(*) n FROM query_storage GROUP BY domain ORDER BY n DESC LIMIT 15"))
        print(" view summary     :", eqp(con, "SELECT COUNT(*),COUNT(DISTINCT q.domain),COUNT(DISTINCT q.client) FROM queries q"))
        print(" direct summary   :", eqp(con, "SELECT COUNT(*),COUNT(DISTINCT domain),COUNT(DISTINCT client) FROM query_storage"))
        con.execute("DROP INDEX idx_qs_domain")
        con.execute("DROP INDEX idx_qs_client")
        con.close()

    print("\n\n===== TIMING TABLE (median of 3 runs, seconds) =====")
    print(f"{'scale':<16}{'pattern':<18}{'a_view':>10}{'b_direct':>12}{'c_dir+idx':>12}")
    seen = []
    for (label, pat, _appr) in results:
        if (label, pat) not in seen:
            seen.append((label, pat))
    for label, pat in seen:
        a = results.get((label, pat, "a_view"))
        b = results.get((label, pat, "b_direct"))
        c = results.get((label, pat, "c_direct_idx"))
        print(f"{label:<16}{pat:<18}{a:>10.3f}{b:>12.3f}{c:>12.3f}")


if __name__ == "__main__":
    main()
