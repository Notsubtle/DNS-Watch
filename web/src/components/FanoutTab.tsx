import { useEffect, useState } from "react";
import { api, FanoutEntry } from "../api";

const RANGES = [
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
];

function formatTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

// #34: which domains got hit by several distinct clients within the same
// SHORT window -- surfaces synchronized beaconing a per-client view can't
// show. Deliberately a passive, on-demand view (not an alert rule): the
// backend already excludes domains that are merely popular over the whole
// range (see db.domain_fanout's module note) by requiring the clients to
// cluster into one bucket, but this is still exploratory data a human should
// read, not something worth paging someone over.
export default function FanoutTab() {
  const [range, setRange] = useState("1h");
  const [bucketMinutes, setBucketMinutes] = useState(5);
  const [minClients, setMinClients] = useState(3);
  const [entries, setEntries] = useState<FanoutEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function load() {
    setLoading(true);
    api
      .domainFanout(range, bucketMinutes, minClients)
      .then((rows) => {
        setEntries(rows);
        setError(null);
      })
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }

  useEffect(load, [range, bucketMinutes, minClients]);

  return (
    <div className="fanout-tab">
      <div className="panel">
        <h2>Cross-client domain fan-out</h2>
        <p className="modal-sub">
          Domains queried by several different devices within the same short window — the kind of
          synchronized beaconing a per-client view can't show on its own. A domain popular over the
          whole range but spread out over time (a CDN, an ad network) won't show up here; only a
          real cluster in time will.
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
            window
            <input
              type="number"
              min={1}
              max={60}
              value={bucketMinutes}
              onChange={(e) => setBucketMinutes(Number(e.target.value))}
            />
            min
          </label>

          <label>
            ≥
            <input
              type="number"
              min={2}
              value={minClients}
              onChange={(e) => setMinClients(Number(e.target.value))}
            />
            clients
          </label>

          <div className="spacer" />
          <button onClick={load}>{loading ? <span className="spinner" /> : "Refresh"}</button>
        </div>

        {error && <div className="error-banner">{error}</div>}

        <ul className="rule-list">
          {entries.map((e, i) => (
            <li key={`${e.domain}-${e.window_start}-${i}`}>
              <div className="rule-info">
                <span className="rule-name">{e.domain}</span>
                <span className="rule-desc">
                  {e.client_count} clients, {e.query_count} queries between{" "}
                  {formatTime(e.window_start)} and {formatTime(e.window_end)} —{" "}
                  {e.clients.map((c) => c.name).join(", ")}
                </span>
              </div>
            </li>
          ))}
          {!loading && entries.length === 0 && (
            <li className="rule-empty">
              No domains matched — try a wider range, a shorter window, or a lower client
              threshold.
            </li>
          )}
        </ul>
      </div>
    </div>
  );
}
