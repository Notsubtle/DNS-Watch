import { Fragment, useEffect, useState } from "react";
import { AlertRule, api, RuleType, Tag } from "../api";

const TYPE_LABELS: Record<RuleType, string> = {
  volume_threshold: "Query volume",
  new_device: "New device",
  domain_keyword: "Domain keyword",
  device_quiet: "Device went quiet",
  new_vendor: "Unrecognized/new vendor",
  doh_provider: "Known DoH/DoT provider query",
  digest: "Periodic digest",
  first_seen_domain: "First-seen domain",
  correlated_new_device_domain: "New device + first-seen domain",
};

const RULE_TYPES = Object.keys(TYPE_LABELS) as RuleType[];

function describe(rule: AlertRule): string {
  const p = rule.params as Record<string, number | string>;
  if (rule.type === "volume_threshold") {
    const who =
      p.scope === "per_client"
        ? "any client"
        : (p.tag && `tag "${p.tag}"`) || (p.client as string) || "all clients";
    return `≥ ${p.threshold ?? 1000} queries from ${who} in ${p.window_minutes ?? 5}m`;
  }
  if (rule.type === "new_device") {
    return `device first seen within ${p.window_minutes ?? 1440}m`;
  }
  if (rule.type === "new_vendor") {
    return `new device with an unrecognized or first-seen vendor within ${p.window_minutes ?? 1440}m`;
  }
  if (rule.type === "first_seen_domain") {
    return `a domain no client has ever queried before, seen within ${p.window_minutes ?? 1440}m`;
  }
  if (rule.type === "correlated_new_device_domain") {
    return `a new device queries a first-seen domain within ${p.window_minutes ?? 15}m of joining`;
  }
  if (rule.type === "doh_provider") {
    return `a client queries a known DoH/DoT provider domain (setup/fallback lookups, not confirmed bypass) within ${p.window_minutes ?? 60}m`;
  }
  if (rule.type === "device_quiet") {
    return `active client (≥ ${p.min_prior ?? 20} queries) goes silent for ${p.window_minutes ?? 60}m`;
  }
  if (rule.type === "digest") {
    return `${p.period === "weekly" ? "weekly" : "daily"} summary of alerts and new devices`;
  }
  const kwWho = p.tag ? ` from tag "${p.tag}"` : "";
  return `≥ ${p.min_count ?? 1} queries matching "${p.keyword ?? ""}"${kwWho} in ${p.window_minutes ?? 60}m`;
}

interface Props {
  onClose: () => void;
  onChange: () => void; // ask App to re-evaluate alerts after a rule change
  tags: Tag[];
}

export default function RulesModal({ onClose, onChange, tags }: Props) {
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [ruleFilter, setRuleFilter] = useState("");

  // Add-form state
  const [type, setType] = useState<RuleType>("volume_threshold");
  const [name, setName] = useState("");
  const [threshold, setThreshold] = useState(1000);
  const [windowMin, setWindowMin] = useState(5);
  const [scope, setScope] = useState<"any" | "per_client">("per_client");
  const [keyword, setKeyword] = useState("");
  const [minCount, setMinCount] = useState(1);
  const [minPrior, setMinPrior] = useState(20);
  // Optional tag scope (#31) for volume_threshold's "any" scope and
  // domain_keyword -- "" means unscoped (all clients), matching prior
  // behavior for anyone who never touches this field.
  const [tagScope, setTagScope] = useState("");
  const [digestPeriod, setDigestPeriod] = useState<"daily" | "weekly">("daily");

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
      const tagParam = scope === "any" && tagScope ? { tag: tagScope } : {};
      return { scope, threshold, window_minutes: windowMin, ...tagParam };
    }
    if (
      type === "new_device" ||
      type === "new_vendor" ||
      type === "doh_provider" ||
      type === "first_seen_domain" ||
      type === "correlated_new_device_domain"
    ) {
      return { window_minutes: windowMin };
    }
    if (type === "device_quiet") {
      return { min_prior: minPrior, window_minutes: windowMin };
    }
    if (type === "digest") {
      return { period: digestPeriod };
    }
    const tagParam = tagScope ? { tag: tagScope } : {};
    return { keyword, min_count: minCount, window_minutes: windowMin, ...tagParam };
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

  const normalizedFilter = ruleFilter.trim().toLowerCase();
  const visibleRules = normalizedFilter
    ? rules.filter((r) => r.name.toLowerCase().includes(normalizedFilter))
    : rules;
  const hasActiveFilter = normalizedFilter.length > 0;

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

        <div className="rule-filter">
          <input
            type="text"
            value={ruleFilter}
            onChange={(e) => setRuleFilter(e.target.value)}
            placeholder="Search rules by name"
            aria-label="Search rules by name"
          />
        </div>

        <ul className="rule-list">
          {RULE_TYPES.map((ruleType) => {
            const groupRules = visibleRules.filter((r) => r.type === ruleType);
            if (groupRules.length === 0) {
              return null;
            }
            return (
              <Fragment key={ruleType}>
                <li className="rule-group-heading">{TYPE_LABELS[ruleType]}</li>
                {groupRules.map((r) => (
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
              </Fragment>
            );
          })}
          {rules.length === 0 && <li className="rule-empty">No rules yet.</li>}
          {rules.length > 0 && hasActiveFilter && visibleRules.length === 0 && (
            <li className="rule-empty">No rules match your search.</li>
          )}
        </ul>

        <h3 className="modal-section">Add a rule</h3>
        <form className="rule-form" onSubmit={add}>
          <div className="rule-form-row">
            <select value={type} onChange={(e) => setType(e.target.value as RuleType)}>
              {RULE_TYPES.map((t) => (
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
                {scope === "any" && tags.length > 0 && (
                  <select
                    value={tagScope}
                    onChange={(e) => setTagScope(e.target.value)}
                    title="Optionally scope to a tag instead of every client"
                  >
                    <option value="">(no tag — every client)</option>
                    {tags.map((t) => (
                      <option key={t.name} value={t.name}>
                        🏷 {t.name}
                      </option>
                    ))}
                  </select>
                )}
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
                {tags.length > 0 && (
                  <select
                    value={tagScope}
                    onChange={(e) => setTagScope(e.target.value)}
                    title="Optionally scope to a tag instead of every client"
                  >
                    <option value="">(no tag — every client)</option>
                    {tags.map((t) => (
                      <option key={t.name} value={t.name}>
                        🏷 {t.name}
                      </option>
                    ))}
                  </select>
                )}
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

            {type === "digest" && (
              <select value={digestPeriod} onChange={(e) => setDigestPeriod(e.target.value as "daily" | "weekly")}>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
              </select>
            )}

            {type !== "digest" && (
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
            )}

            <button type="submit" className="btn-primary" disabled={busy}>
              Add rule
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
