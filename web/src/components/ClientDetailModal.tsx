import { useEffect, useState } from "react";
import { api, ClientDetail, DeviceNewDomain } from "../api";
import SummaryCards from "./SummaryCards";
import TimeSeriesChart from "./TimeSeriesChart";
import TopList from "./TopList";
import QueryTypeBreakdown from "./QueryTypeBreakdown";

function fmtDate(ts: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

interface Props {
  ip: string;
  range: string;
  onClose: () => void;
}

// Full per-client profile: its own summary, volume chart, top domains and query
// types over the current range, plus global first/last-seen.
export default function ClientDetailModal({ ip, range, onClose }: Props) {
  const [data, setData] = useState<ClientDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Per-client first-seen-domain (#1) -- fetched separately from clientDetail
  // since it's rollup-backed (may not be ready yet) rather than range-scoped;
  // a failure/not-ready here shouldn't block the rest of the modal from
  // rendering, so it's tracked independently and just renders nothing if unset.
  const [newDomains, setNewDomains] = useState<DeviceNewDomain[] | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api
      .clientDetail(ip, range)
      .then((d) => !cancelled && (setData(d), setError(null)))
      .catch((e) => !cancelled && setError((e as Error).message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [ip, range]);

  useEffect(() => {
    let cancelled = false;
    setNewDomains(null);
    api
      .deviceNewDomains(ip)
      .then((d) => !cancelled && setNewDomains(d.ready ? d.domains : []))
      .catch(() => !cancelled && setNewDomains([]));
    return () => {
      cancelled = true;
    };
  }, [ip]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal modal-wide" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-head">
          <h2 title={ip}>
            {data?.name ?? ip}
            {data && data.name !== ip && <span className="modal-ip"> {ip}</span>}
          </h2>
          <button className="modal-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        {loading && <div className="chart-empty">Loading…</div>}
        {error && <div className="error-banner">{error}</div>}

        {data && !loading && !error && (
          <>
            <div className="modal-sub">
              First seen {fmtDate(data.first_seen)} · last seen {fmtDate(data.last_seen)} · window: {range}
              {data.mac_known && data.vendor && <> · vendor: {data.vendor}</>}
              {data.mac_known && !data.vendor && data.vendor_unknown_reason === "randomized" && (
                <> · vendor: unknown (randomized/private MAC)</>
              )}
              {data.mac_known && !data.vendor && data.vendor_unknown_reason !== "randomized" && (
                <> · vendor: unknown</>
              )}
              {!data.mac_known && <> · vendor: unknown (no MAC observed)</>}
            </div>

            <SummaryCards summary={data.summary} />
            <TimeSeriesChart data={data.timeseries} loading={false} />

            <div className="client-detail-grid">
              <TopList title="Top domains" entries={data.top_domains} />
              <QueryTypeBreakdown entries={data.query_types} />
            </div>

            {newDomains && newDomains.length > 0 && (
              <div className="client-new-domains">
                <h3 className="modal-section">New for this device (last 30d)</h3>
                <ul>
                  {newDomains.map((d) => (
                    <li key={d.domain}>
                      <span className="client-new-domain-name">{d.domain}</span>
                      <span className="client-new-domain-time">{fmtDate(d.first_seen)}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
