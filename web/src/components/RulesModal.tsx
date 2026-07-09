import { useEffect, useState } from "react";
import { AlertRule, api, RuleType } from "../api";

const TYPE_LABELS: Record<RuleType, string> = {
  volume_threshold: "Query volume",
  new_device: "New device",
  domain_keyword: "Domain keyword",
  device_quiet: "Device went quiet",
  new_vendor: "Unrecognized/new vendor",
  doh_provider: "Known DoH/DoT provider query",
};

function describe(rule: AlertRule): string {
  const p = rule.params as Record<string, number | string>;
  if (rule.type === "volume_threshold") {
    const who = p.scope === "per_client" ? "any client" : (p.client as string) || "all clients";
    return `≥ ${p.threshold ?? 1000} queries from ${who} in ${p.window_minutes ?? 5}m`;
  }
  if (rule.type === "new_device") {
    return `device first seen within ${p.window_minutes ?? 1440}m`;
  }
  if (rule.type === "new_vendor") {
    return `new device with an unrecognized or first-seen vendor within ${p.window_minutes ?? 1440}m`;
  }
  if (rule.type === "doh_provider") {
    return `a client queries a known DoH/DoT provider domain (setup/fallback lookups, not confirmed bypass) within ${p.window_minutes ?? 60}m`;
  }
  if (rule.type === "device_quiet") {
    return `active client (≥ ${p.min_prior ?? 20} queries) goes silent for ${p.window_minutes ?? 60}m`;
  }
  return `≥ ${p.min_count ?? 1} queries matching "${p.keyword ?? ""}" in ${p.window_minutes ?? 60}m`;
}

interface Props {
  onClose: () => void;
  onChange: () => void; // ask App to re-evaluate alerts after a rule change
}

export default function RulesModal({ onClose, onChange }: Props) {
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Add-form state
  const [type, setType] = useState<RuleType>("volume_threshold");
  const [name, setName] = useState("");
  const [threshold, setThreshold] = useState(1000);
  const [windowMin, setWindowMin] = useState(5);
  const [scope, setScope] = useState<"any" | "per_client">("per_client");
  const [keyword, setKeyword] = useState("");
  const [minCount, setMinCount] = useState(1);
  const [minPrior, setMinPrior] = useState(20);

  function load() {
    api.listRules().then(setRules).catch((e) => setError((e as Error).message));
  }
  useEffect(load, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  function buildParams(): Record<string, unknown> {
    if (type === "volume_threshold") {
      return { scope, threshold, window_minutes: windowMin };
    }
    if (type === "new_device" || type === "new_vendor" || type === "doh_provider") {
      return { window_minutes: windowMin };
    }
    if (type === "device_quiet") {
      return { min_prior: minPrior, window_minutes: windowMin };
    }
    return { keyword, min_count: minCount, window_minutes: windowMin };
  }

  async function add(e: React.FormEvent) {
    e.preventDefault();
    if (type === "domain_keyword" && !keyword.trim()) {
      setError("Keyword is required for a domain rule.");
      return;
    }
    setBusy(true);
    try {
      const label = name.trim() || TYPE_LABELS[type];
      await api.createRule({ name: label, type, params: buildParams() });
      setName("");
      setKeyword("");
      setError(null);
      load();
      onChange();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function toggle(rule: AlertRule) {
    await api.updateRule(rule.id, { enabled: !rule.enabled });
    load();
    onChange();
  }

  async function remove(rule: AlertRule) {
    await api.deleteRule(rule.id);
    load();
    onChange();
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-head">
          <h2>Alert rules</h2>
          <button className="modal-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        {error && <div className="error-banner">{error}</div>}

        <ul className="rule-list">
          {rules.map((r) => (
            <li key={r.id} className={r.enabled ? "" : "disabled"}>
              <div className="rule-info">
                <span className="rule-name">{r.name}</span>
                <span className="rule-desc">{describe(r)}</span>
              </div>
              <label className="rule-toggle">
                <input type="checkbox" checked={r.enabled} onChange={() => toggle(r)} />
                <span>{r.enabled ? "On" : "Off"}</span>
              </label>
              <button className="btn-danger" onClick={() => remove(r)} aria-label="Delete rule">
                Delete
              </button>
            </li>
          ))}
          {rules.length === 0 && <li className="rule-empty">No rules yet.</li>}
        </ul>

        <h3 className="modal-section">Add a rule</h3>
        <form className="rule-form" onSubmit={add}>
          <div className="rule-form-row">
            <select value={type} onChange={(e) => setType(e.target.value as RuleType)}>
              {(Object.keys(TYPE_LABELS) as RuleType[]).map((t) => (
                <option key={t} value={t}>
                  {TYPE_LABELS[t]}
                </option>
              ))}
            </select>
            <input
              type="text"
              placeholder="Rule name (optional)"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          <div className="rule-form-row">
            {type === "volume_threshold" && (
              <>
                <select value={scope} onChange={(e) => setScope(e.target.value as "any" | "per_client")}>
                  <option value="per_client">Per client</option>
                  <option value="any">All clients</option>
                </select>
                <label>
                  ≥
                  <input
                    type="number"
                    min={1}
                    value={threshold}
                    onChange={(e) => setThreshold(Number(e.target.value))}
                  />
                  queries
                </label>
              </>
            )}

            {type === "domain_keyword" && (
              <>
                <input
                  type="text"
                  placeholder="keyword (e.g. tiktok)"
                  value={keyword}
                  onChange={(e) => setKeyword(e.target.value)}
                />
                <label>
                  ≥
                  <input
                    type="number"
                    min={1}
                    value={minCount}
                    onChange={(e) => setMinCount(Number(e.target.value))}
                  />
                  hits
                </label>
              </>
            )}

            {type === "device_quiet" && (
              <label>
                was ≥
                <input
                  type="number"
                  min={1}
                  value={minPrior}
                  onChange={(e) => setMinPrior(Number(e.target.value))}
                />
                queries, now silent
              </label>
            )}

            <label>
              in
              <input
                type="number"
                min={1}
                value={windowMin}
                onChange={(e) => setWindowMin(Number(e.target.value))}
              />
              min
            </label>

            <button type="submit" className="btn-primary" disabled={busy}>
              Add rule
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
