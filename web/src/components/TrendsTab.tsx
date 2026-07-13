import { useEffect, useMemo, useState } from "react";
import { api, DomainStatusChanges, PeriodComparison, Timeseries } from "../api";

const W = 720;
const H = 140;
const PAD = { top: 12, right: 8, bottom: 20, left: 8 };

function fmtDay(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString([], { month: "short", day: "numeric" });
}

function pct(n: number | undefined): string {
  return n === undefined ? "—" : `${n.toFixed(1)}%`;
}

// Derives a daily block-rate percentage line from the SAME data the main
// dashboard's "All" query-volume chart already fetches (daily_totals via
// /api/timeseries?range=all) -- no new backend endpoint for this half, just
// a different view of allowed/blocked/total per day.
function BlockRateChart({ data }: { data: Timeseries | null }) {
  const [hover, setHover] = useState<number | null>(null);

  const geom = useMemo(() => {
    if (!data || data.series.length === 0) return null;
    const s = data.series.map((p) => ({
      t: p.t,
      pct: p.total > 0 ? (p.blocked / p.total) * 100 : 0,
    }));
    const n = s.length;
    const innerW = W - PAD.left - PAD.right;
    const innerH = H - PAD.top - PAD.bottom;
    const x = (i: number) => PAD.left + (n === 1 ? innerW / 2 : (i / (n - 1)) * innerW);
    const y = (v: number) => PAD.top + innerH - (v / 100) * innerH;
    const line = s.map((p, i) => `${x(i)},${y(p.pct)}`).join(" ");
    return { s, n, x, y, line };
  }, [data]);

  if (!data || !geom) {
    return <div className="chart-empty">Not enough history yet for a trend line.</div>;
  }

  const { s, n, x, line } = geom;
  const hp = hover !== null ? s[hover] : null;

  return (
    <>
      <svg viewBox={`0 0 ${W} ${H}`} className="ts-chart" preserveAspectRatio="none">
        <polyline points={line} className="trend-line" fill="none" />
        {s.map((_, i) => {
          const bw = (W - PAD.left - PAD.right) / n;
          return (
            <rect
              key={i}
              x={x(i) - bw / 2}
              y={PAD.top}
              width={bw}
              height={H - PAD.top - PAD.bottom}
              fill="transparent"
              onMouseEnter={() => setHover(i)}
              onMouseLeave={() => setHover((h) => (h === i ? null : h))}
            />
          );
        })}
        {hover !== null && hp && (
          <line x1={x(hover)} x2={x(hover)} y1={PAD.top} y2={H - PAD.bottom} className="hover-line" />
        )}
        <text x={PAD.left} y={H - 6} className="axis-label" textAnchor="start">
          {fmtDay(data.since)}
        </text>
        <text x={W - PAD.right} y={H - 6} className="axis-label" textAnchor="end">
          {fmtDay(data.until)}
        </text>
      </svg>
      {hp && (
        <div className="chart-tooltip">
          <strong>{fmtDay(hp.t)}</strong> · {hp.pct.toFixed(1)}% blocked
        </div>
      )}
    </>
  );
}

// #NN: retrospective "what changed" trends -- the backward-looking
// complement to the Blocklist Impact Simulator (which is forward-looking:
// "what WOULD this regex block"). Three views, all built from rollup tables
// already maintained for other features -- no new data collection:
//   - block-rate over time (from the same daily_totals-backed series the
//     dashboard's own "All" volume chart already uses)
//   - domains that recently started/stopped being blocked
//   - a current-vs-prior N-day period comparison (block rate, top domain/
//     client shifts, newly-appeared devices)
export default function TrendsTab() {
  const [series, setSeries] = useState<Timeseries | null>(null);
  const [statusChanges, setStatusChanges] = useState<DomainStatusChanges | null>(null);
  const [comparison, setComparison] = useState<PeriodComparison | null>(null);
  const [periodDays, setPeriodDays] = useState(7);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .timeseries({ client: "", tag: "", vendor: "", range: "all" })
      .then(setSeries)
      .catch((e) => setError((e as Error).message));
    api.domainStatusChanges().then(setStatusChanges).catch((e) => setError((e as Error).message));
  }, []);

  useEffect(() => {
    api.periodComparison(periodDays).then(setComparison).catch((e) => setError((e as Error).message));
  }, [periodDays]);

  return (
    <div className="trends-tab">
      {error && <div className="error-banner">{error}</div>}

      <div className="panel chart-panel">
        <div className="panel-head">
          <h2>Block rate over time</h2>
        </div>
        <p className="modal-sub">
          What share of all queries were blocked, per day, across your whole history — the
          retrospective view the Blocklist Impact Simulator's forward-looking "what would this
          regex block" doesn't cover.
        </p>
        <BlockRateChart data={series} />
      </div>

      <div className="panel">
        <div className="panel-head">
          <h2>Recently changed domains</h2>
        </div>
        {!statusChanges?.ready && (
          <div className="chart-empty">Still building history — check back after the rollup catches up.</div>
        )}
        {statusChanges?.ready && (
          <div className="trend-columns">
            <div>
              <h3 className="modal-section">Newly blocked</h3>
              <ul className="rule-list">
                {statusChanges.newly_blocked.map((d) => (
                  <li key={d.domain}>
                    <div className="rule-info">
                      <span className="rule-name">{d.domain}</span>
                      <span className="rule-desc">{d.blocked_count} blocked hits recently</span>
                    </div>
                  </li>
                ))}
                {statusChanges.newly_blocked.length === 0 && (
                  <li className="rule-empty">No domains newly blocked recently.</li>
                )}
              </ul>
            </div>
            <div>
              <h3 className="modal-section">Newly unblocked</h3>
              <ul className="rule-list">
                {statusChanges.newly_unblocked.map((d) => (
                  <li key={d.domain}>
                    <div className="rule-info">
                      <span className="rule-name">{d.domain}</span>
                      <span className="rule-desc">{d.allowed_count} allowed hits recently</span>
                    </div>
                  </li>
                ))}
                {statusChanges.newly_unblocked.length === 0 && (
                  <li className="rule-empty">No domains newly unblocked recently.</li>
                )}
              </ul>
            </div>
          </div>
        )}
      </div>

      <div className="panel">
        <div className="panel-head">
          <h2>What changed</h2>
          <div className="filter-bar">
            {[7, 14, 30].map((d) => (
              <button
                key={d}
                className={periodDays === d ? "active" : ""}
                onClick={() => setPeriodDays(d)}
              >
                {d}d
              </button>
            ))}
          </div>
        </div>

        {!comparison?.ready && (
          <div className="chart-empty">Still building history — check back after the rollup catches up.</div>
        )}
        {comparison?.ready && !comparison.prior_period_available && (
          <div className="chart-empty">
            Not enough history yet for a full {periodDays}-day comparison — check back once DNS
            Watch has been running for at least {periodDays * 2} days.
          </div>
        )}
        {comparison?.ready && comparison.prior_period_available && (
          <>
            <p className="modal-sub">
              Current {periodDays} days ({fmtDay(comparison.current_since!)} – {fmtDay(comparison.current_until!)})
              vs. the {periodDays} days before that.
            </p>
            <div className="drawer-stats">
              <div>
                <span className="drawer-stat-label">Block rate, prior period</span>
                <span className="drawer-stat-value">{pct(comparison.block_rate_prior)}</span>
              </div>
              <div>
                <span className="drawer-stat-label">Block rate, current period</span>
                <span className="drawer-stat-value">{pct(comparison.block_rate_current)}</span>
              </div>
            </div>

            <div className="trend-columns">
              <div>
                <h3 className="modal-section">Biggest domain volume shifts</h3>
                <ul className="rule-list">
                  {comparison.top_domain_shifts?.map((d) => (
                    <li key={d.domain}>
                      <div className="rule-info">
                        <span className="rule-name">{d.domain}</span>
                        <span className="rule-desc">
                          {d.prior.toLocaleString()} → {d.current.toLocaleString()} queries
                          ({d.delta > 0 ? "+" : ""}{d.delta.toLocaleString()})
                        </span>
                      </div>
                    </li>
                  ))}
                  {(comparison.top_domain_shifts?.length ?? 0) === 0 && (
                    <li className="rule-empty">No notable shifts.</li>
                  )}
                </ul>
              </div>
              <div>
                <h3 className="modal-section">Biggest client volume shifts</h3>
                <ul className="rule-list">
                  {comparison.top_client_deltas?.map((c) => (
                    <li key={c.ip}>
                      <div className="rule-info">
                        <span className="rule-name">{c.name}</span>
                        <span className="rule-desc">
                          {c.prior.toLocaleString()} → {c.current.toLocaleString()} queries
                          ({c.delta > 0 ? "+" : ""}{c.delta.toLocaleString()})
                        </span>
                      </div>
                    </li>
                  ))}
                  {(comparison.top_client_deltas?.length ?? 0) === 0 && (
                    <li className="rule-empty">No notable shifts.</li>
                  )}
                </ul>
              </div>
            </div>

            <h3 className="modal-section">New devices this period</h3>
            <ul className="rule-list">
              {comparison.new_devices?.map((d) => (
                <li key={d.ip}>
                  <div className="rule-info">
                    <span className="rule-name">{d.name}</span>
                    <span className="rule-desc">first seen {fmtDay(d.first_seen)}</span>
                  </div>
                </li>
              ))}
              {(comparison.new_devices?.length ?? 0) === 0 && (
                <li className="rule-empty">No new devices this period.</li>
              )}
            </ul>
          </>
        )}
      </div>
    </div>
  );
}
