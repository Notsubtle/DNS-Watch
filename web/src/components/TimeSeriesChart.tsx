import { useMemo, useState } from "react";
import { Timeseries } from "../api";

const W = 720;
const H = 180;
const PAD = { top: 12, right: 8, bottom: 20, left: 8 };

function fmtTime(ts: number, spanSeconds: number): string {
  const d = new Date(ts * 1000);
  // Show date for multi-day spans, otherwise just the clock.
  if (spanSeconds > 2 * 86400) {
    return d.toLocaleDateString([], { month: "short", day: "numeric" });
  }
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}

export default function TimeSeriesChart({ data, loading }: { data: Timeseries | null; loading: boolean }) {
  const [hover, setHover] = useState<number | null>(null);

  const geom = useMemo(() => {
    if (!data || data.series.length === 0) return null;
    const s = data.series;
    const n = s.length;
    const innerW = W - PAD.left - PAD.right;
    const innerH = H - PAD.top - PAD.bottom;
    const maxTotal = Math.max(1, ...s.map((p) => p.total));
    const x = (i: number) => PAD.left + (n === 1 ? innerW / 2 : (i / (n - 1)) * innerW);
    const y = (v: number) => PAD.top + innerH - (v / maxTotal) * innerH;

    // Stacked areas. Allowed sits on the baseline; blocked stacks on top of it.
    // Each polygon: forward along its own upper edge, then back along the edge
    // beneath it (baseline for allowed, the allowed line for blocked).
    const fwd = (edge: (p: (typeof s)[number]) => number) =>
      s.map((p, i) => `${x(i)},${y(edge(p))}`);
    const back = (edge: (p: (typeof s)[number]) => number) =>
      s.map((p, i) => `${x(n - 1 - i)},${y(edge(s[n - 1 - i]))}`);

    const allowedArea = [...fwd((p) => p.allowed), `${x(n - 1)},${y(0)}`, `${x(0)},${y(0)}`].join(" ");
    const blockedArea = [...fwd((p) => p.total), ...back((p) => p.allowed)].join(" ");

    return { s, n, x, y, maxTotal, allowedArea, blockedArea, innerH };
  }, [data]);

  if (!data || !geom) {
    return (
      <div className="panel chart-panel">
        <div className="panel-head">
          <h2>Query volume{loading && <span className="spinner" />}</h2>
        </div>
        <div className="chart-empty">No data in this range.</div>
      </div>
    );
  }

  const { s, n, x, y, allowedArea, blockedArea } = geom;
  const span = data.until - data.since;
  const hp = hover !== null ? s[hover] : null;

  return (
    <div className="panel chart-panel">
      <div className="panel-head">
        <h2>
          Query volume{loading && <span className="spinner" />}
        </h2>
        <div className="chart-legend">
          <span><i className="swatch allowed" /> Allowed</span>
          <span><i className="swatch blocked" /> Blocked</span>
        </div>
      </div>

      <svg viewBox={`0 0 ${W} ${H}`} className="ts-chart" preserveAspectRatio="none">
        <polygon points={allowedArea} className="area-allowed" />
        <polygon points={blockedArea} className="area-blocked" />

        {/* Invisible hover columns for the tooltip */}
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

        {/* x-axis end labels */}
        <text x={PAD.left} y={H - 6} className="axis-label" textAnchor="start">
          {fmtTime(data.since, span)}
        </text>
        <text x={W - PAD.right} y={H - 6} className="axis-label" textAnchor="end">
          {fmtTime(data.until, span)}
        </text>
      </svg>

      {hp && (
        <div className="chart-tooltip">
          <strong>{fmtTime(hp.t, span)}</strong> · {hp.total.toLocaleString()} queries
          <span className="allowed"> {hp.allowed.toLocaleString()} allowed</span> ·
          <span className="blocked"> {hp.blocked.toLocaleString()} blocked</span>
        </div>
      )}
    </div>
  );
}
