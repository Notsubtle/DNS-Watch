import { Fragment, useEffect, useState } from "react";
import { api, ClientInfo, HeatmapResult, Tag } from "../api";
import HeatmapCellModal from "./HeatmapCellModal";

// Monday=0..Sunday=6 — matches the backend's datetime.weekday() convention
// (see db.client_heatmap), not JS's Date.getDay() (which is Sunday=0).
const WEEKDAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const HOUR_LABEL_INTERVAL = 4;

function cellBackground(value: number, max: number): string {
  if (max <= 0 || value <= 0) return "transparent";
  const intensity = value / max;
  // Same RGB as --ink-blue in tokens.css — duplicated here since a CSS
  // custom property can't be alpha-blended from a JS-computed intensity.
  return `rgba(77, 158, 255, ${(0.08 + intensity * 0.82).toFixed(2)})`;
}

interface Props {
  clients: ClientInfo[];
  tags: Tag[];
}

export default function ClientHeatmapTab({ clients, tags }: Props) {
  const [ip, setIp] = useState("");
  // Tag-scoped heatmap (#7) -- mutually exclusive with `ip` above, same
  // "one active scope at a time" pattern the dashboard's own client/tag/
  // vendor filter uses. Picking one clears the other.
  const [tag, setTag] = useState("");
  const [heatmap, setHeatmap] = useState<HeatmapResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cell, setCell] = useState<{ weekday: number; hour: number } | null>(null);

  useEffect(() => {
    if (!ip && !tag) {
      setHeatmap(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    const req = tag ? api.tagHeatmap(tag) : api.clientHeatmap(ip);
    req
      .then((h) => {
        if (cancelled) return;
        setHeatmap(h);
        setError(null);
      })
      .catch((e) => !cancelled && setError((e as Error).message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [ip, tag]);

  const selectedClient = clients.find((c) => c.ip === ip);

  return (
    <div className="heatmap-tab">
      <div className="panel">
        <h2>Client Heatmap</h2>
        <select
          value={ip}
          onChange={(e) => {
            setIp(e.target.value);
            setTag("");
          }}
        >
          <option value="">Select a client…</option>
          {clients.map((c) => (
            <option key={c.ip} value={c.ip}>
              {c.name} ({c.query_count.toLocaleString()})
            </option>
          ))}
        </select>
        {tags.length > 0 && (
          <select
            value={tag}
            onChange={(e) => {
              setTag(e.target.value);
              setIp("");
            }}
            title="Or view a tag's combined activity across all its members"
          >
            <option value="">— or a tag —</option>
            {tags.map((t) => (
              <option key={t.name} value={t.name}>
                🏷 {t.name}
              </option>
            ))}
          </select>
        )}
      </div>

      {!ip && !tag && (
        <div className="tab-placeholder">
          Select a client or a tag to see its weekly activity pattern.
        </div>
      )}
      {loading && <div className="chart-empty">Loading…</div>}
      {error && <div className="error-banner">{error}</div>}

      {heatmap && !loading && !error && (
        <div className="panel">
          <div className="heatmap-grid" style={{ gridTemplateColumns: "44px repeat(24, 1fr)" }}>
            <div className="heatmap-corner" />
            {Array.from({ length: 24 }, (_, hour) => (
              <div key={hour} className="heatmap-hour-label">
                {hour % HOUR_LABEL_INTERVAL === 0 ? String(hour).padStart(2, "0") : ""}
              </div>
            ))}
            {WEEKDAY_LABELS.map((label, weekday) => (
              <Fragment key={weekday}>
                <div className="heatmap-row-label">{label}</div>
                {heatmap.grid[weekday].map((value, hour) => (
                  <div
                    key={hour}
                    className="heatmap-cell"
                    style={{ backgroundColor: cellBackground(value, heatmap.max) }}
                    title={`${label} ${String(hour).padStart(2, "0")}:00 — ${value.toLocaleString()} ${
                      value === 1 ? "query" : "queries"
                    }`}
                    onClick={() => setCell({ weekday, hour })}
                  />
                ))}
              </Fragment>
            ))}
          </div>
        </div>
      )}

      {cell && (ip || tag) && (
        <HeatmapCellModal
          ip={ip || undefined}
          tag={tag || undefined}
          clientName={tag ? `🏷 ${tag}` : selectedClient?.name ?? ip}
          weekday={cell.weekday}
          hour={cell.hour}
          onClose={() => setCell(null)}
        />
      )}
    </div>
  );
}
