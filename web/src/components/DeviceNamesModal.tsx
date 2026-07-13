import { useEffect, useMemo, useState } from "react";
import { api, DeviceNameRow, NameChangeEntry } from "../api";

interface Props {
  onClose: () => void;
  onChange: () => void; // ask App to reload clients/summary after a rename
}

function fmtChangeTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString([], {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function describeChange(e: NameChangeEntry): string {
  const src = e.source === "manual" ? "manual" : "reverse-DNS";
  if (e.old_name === null) return `${src}: set to "${e.new_name}"`;
  if (e.new_name === null) return `${src}: cleared (was "${e.old_name}")`;
  return `${src}: "${e.old_name}" → "${e.new_name}"`;
}

export default function DeviceNamesModal({ onClose, onChange }: Props) {
  const [rows, setRows] = useState<DeviceNameRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  // ip -> in-progress edit text, only while that row is being edited.
  const [editing, setEditing] = useState<Record<string, string>>({});
  const [savingIp, setSavingIp] = useState<string | null>(null);
  // At most one row's history is expanded at a time; fetched on demand
  // (not preloaded for every row) and cached per-ip for this modal session.
  const [historyOpenIp, setHistoryOpenIp] = useState<string | null>(null);
  const [historyByIp, setHistoryByIp] = useState<Record<string, NameChangeEntry[]>>({});
  const [historyLoadingIp, setHistoryLoadingIp] = useState<string | null>(null);

  function toggleHistory(ip: string) {
    if (historyOpenIp === ip) {
      setHistoryOpenIp(null);
      return;
    }
    setHistoryOpenIp(ip);
    if (historyByIp[ip]) return;
    setHistoryLoadingIp(ip);
    api
      .deviceNameHistory(ip)
      .then((h) => setHistoryByIp((m) => ({ ...m, [ip]: h })))
      .catch((e) => setError((e as Error).message))
      .finally(() => setHistoryLoadingIp((id) => (id === ip ? null : id)));
  }

  function load() {
    setLoading(true);
    api
      .deviceNames()
      .then(setRows)
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }
  useEffect(load, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Devices you're currently talking to first, then everything else
  // (including stale manual-only entries) by name/ip so the list is stable.
  const sorted = useMemo(
    () =>
      [...rows].sort((a, b) => {
        if (a.seen !== b.seen) return a.seen ? -1 : 1;
        return b.query_count - a.query_count;
      }),
    [rows]
  );

  async function save(ip: string) {
    const name = (editing[ip] ?? "").trim();
    if (!name) return;
    setSavingIp(ip);
    setError(null);
    try {
      await api.setDeviceName(ip, name);
      setEditing((e) => {
        const next = { ...e };
        delete next[ip];
        return next;
      });
      // Invalidate the cached history so the next expand re-fetches with
      // this change included, rather than showing a stale list.
      setHistoryByIp((m) => {
        const next = { ...m };
        delete next[ip];
        return next;
      });
      load();
      onChange();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSavingIp(null);
    }
  }

  async function clear(ip: string) {
    setSavingIp(ip);
    setError(null);
    try {
      await api.deleteDeviceName(ip);
      setHistoryByIp((m) => {
        const next = { ...m };
        delete next[ip];
        return next;
      });
      load();
      onChange();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSavingIp(null);
    }
  }

  function vendorLabel(r: DeviceNameRow): string {
    if (r.vendor) return r.vendor;
    if (!r.mac_known) return "—";
    if (r.vendor_unknown_reason === "randomized") return "private MAC";
    return "unknown vendor";
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-head">
          <h2>Manage device names</h2>
          <button className="modal-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        <p className="modal-sub">
          A name you set here overrides everything else DNS Watch shows for that IP — Pi-hole's
          own name, DNS Watch's reverse-DNS guess, or the bare address.
        </p>

        {error && <div className="error-banner">{error}</div>}
        {loading && <div className="modal-sub">Loading…</div>}

        <ul className="device-name-list">
          {sorted.map((r) => {
            const isEditing = r.ip in editing;
            const busy = savingIp === r.ip;
            return (
              <li key={r.ip} className={r.seen ? "" : "stale"}>
                <div className="device-name-info">
                  <span className="device-name-ip" title={r.ip}>
                    {r.ip}
                    {!r.seen && <span className="stale-badge">NOT SEEN</span>}
                  </span>
                  <span className="device-name-meta">
                    {r.pihole_name ? `Pi-hole: ${r.pihole_name}` : "no Pi-hole name"}
                    {r.resolved_name && ` · rDNS: ${r.resolved_name}`}
                    {` · ${vendorLabel(r)}`}
                    {r.seen && ` · ${r.query_count.toLocaleString()} queries`}
                  </span>
                </div>

                {isEditing ? (
                  <div className="device-name-edit">
                    <input
                      type="text"
                      autoFocus
                      value={editing[r.ip]}
                      onChange={(e) => setEditing((ed) => ({ ...ed, [r.ip]: e.target.value }))}
                      onKeyDown={(e) => e.key === "Enter" && save(r.ip)}
                      maxLength={100}
                    />
                    <button className="btn-primary btn-small" disabled={busy} onClick={() => save(r.ip)}>
                      Save
                    </button>
                    <button
                      className="btn-small"
                      disabled={busy}
                      onClick={() =>
                        setEditing((ed) => {
                          const next = { ...ed };
                          delete next[r.ip];
                          return next;
                        })
                      }
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <div className="device-name-edit">
                    <span className="device-name-current">{r.manual_name || r.display_name}</span>
                    <button
                      className="btn-small"
                      onClick={() => setEditing((ed) => ({ ...ed, [r.ip]: r.manual_name || "" }))}
                    >
                      {r.manual_name ? "Rename" : "Name it"}
                    </button>
                    {r.manual_name && (
                      <button className="btn-danger btn-small" disabled={busy} onClick={() => clear(r.ip)}>
                        Clear
                      </button>
                    )}
                    <button className="btn-small" onClick={() => toggleHistory(r.ip)}>
                      {historyOpenIp === r.ip ? "Hide history" : "History"}
                    </button>
                  </div>
                )}

                {historyOpenIp === r.ip && (
                  <ul className="name-history-list">
                    {historyLoadingIp === r.ip && <li className="modal-sub">Loading…</li>}
                    {historyLoadingIp !== r.ip && (historyByIp[r.ip]?.length ?? 0) === 0 && (
                      <li className="modal-sub">No recorded changes for this device yet.</li>
                    )}
                    {historyByIp[r.ip]?.map((h, i) => (
                      <li key={`${h.changed_at}-${i}`}>
                        <span className="name-history-time">{fmtChangeTime(h.changed_at)}</span>
                        <span className="name-history-desc">{describeChange(h)}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            );
          })}
          {!loading && sorted.length === 0 && <li className="device-name-empty">No devices seen yet.</li>}
        </ul>
      </div>
    </div>
  );
}
