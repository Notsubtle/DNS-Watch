import { useEffect, useState } from "react";
import { api, TunnelingCandidate } from "../api";

const RANGES = [
  { value: "1h", label: "1h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
];

// #2: one client emitting an unusually high number of distinct subdomains
// under a single registered parent domain -- the classic iodine/dnscat2-style
// tunneling signature. Deliberately a passive, on-demand view (not an alert
// rule): CDN/cloud subdomains are also high-cardinality/random-looking, so
// this needs a human reading it, not a page.
export default function TunnelingTab() {
  const [range, setRange] = useState("24h");
  const [minDistinct, setMinDistinct] = useState(20);
  const [entries, setEntries] = useState<TunnelingCandidate[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [debouncedMinDistinct, setDebouncedMinDistinct] = useState(minDistinct);
  useEffect(() => {
    const t = setTimeout(() => setDebouncedMinDistinct(minDistinct), 300);
    return () => clearTimeout(t);
  }, [minDistinct]);

  function load() {
    setLoading(true);
    api
      .tunnelingCandidates(range, debouncedMinDistinct)
      .then((rows) => {
        setEntries(rows);
        setError(null);
      })
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }

  useEffect(load, [range, debouncedMinDistinct]);

  return (
    <div className="tunneling-tab">
      <div className="panel">
        <h2>DNS tunneling / exfiltration detector</h2>
        <p className="modal-sub">
          Devices querying an unusually high number of distinct subdomains under one registered
          parent domain — the signature classic DNS-tunneling tools (iodine, dnscat2) leave
          behind. CDNs and cloud storage buckets can look similar; treat this as a starting point
          for investigation, not a confirmed finding.
        </p>

        <div className="filter-bar">
          {RANGES.map((r) => (
            <button
              key={r.value}
              className={range === r.value ? "active" : ""}
              onClick={() => setRange(r.value)}
            >
              {r.label}
            </button>
          ))}

          <label>
            ≥
            <input
              type="number"
              min={1}
              value={minDistinct}
              onChange={(e) => setMinDistinct(Number(e.target.value))}
            />
            distinct subdomains
          </label>

          <div className="spacer" />
          <button onClick={load}>{loading ? <span className="spinner" /> : "Refresh"}</button>
        </div>

        {error && <div className="error-banner">{error}</div>}

        <ul className="rule-list">
          {entries.map((e, i) => (
            <li key={`${e.ip}-${e.parent_domain}-${i}`}>
              <div className="rule-info">
                <span className="rule-name">
                  {e.name} → {e.parent_domain}
                </span>
                <span className="rule-desc">
                  {e.distinct_subdomains} distinct subdomains, {e.query_count} queries, avg prefix
                  length {e.avg_prefix_length} — e.g. {e.sample_subdomains.join(", ")}
                </span>
              </div>
            </li>
          ))}
          {!loading && entries.length === 0 && (
            <li className="rule-empty">
              No devices matched — try a wider range or a lower distinct-subdomain threshold.
            </li>
          )}
        </ul>
      </div>
    </div>
  );
}
