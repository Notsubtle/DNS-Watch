import { useEffect, useState } from "react";
import { HighlightRule, loadHighlightRules, saveHighlightRules } from "../highlightRules";

const DEFAULT_COLOR = "#a855f7"; // purple, matching the spec's Netflix example

// crypto.randomUUID() only exists in secure contexts (HTTPS or localhost).
// DNS Watch's documented deployment is plain HTTP over a LAN IP, where it's
// `undefined` — so calling it directly would throw when adding a rule. These
// ids are local-only (React keys + delete matching), so a non-crypto fallback
// is fine; uniqueness, not unpredictability, is all that's required.
function makeRuleId(): string {
  const c = typeof crypto !== "undefined" ? crypto : undefined;
  if (c && typeof c.randomUUID === "function") return c.randomUUID();
  return `hr-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

interface Props {
  onClose: () => void;
  onChange: (rules: HighlightRule[]) => void;
}

// Same interaction pattern as RulesModal (list, add, delete) but no backend —
// everything is local state persisted straight to localStorage.
export default function HighlightRulesModal({ onClose, onChange }: Props) {
  const [rules, setRules] = useState<HighlightRule[]>(() => loadHighlightRules());
  const [pattern, setPattern] = useState("");
  const [field, setField] = useState<"domain" | "client">("domain");
  const [color, setColor] = useState(DEFAULT_COLOR);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  function persist(next: HighlightRule[]) {
    setRules(next);
    saveHighlightRules(next);
    onChange(next);
  }

  function add(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = pattern.trim();
    if (!trimmed) return; // no-op rule that'd match everything -> don't add it
    const rule: HighlightRule = { id: makeRuleId(), pattern: trimmed, color, field };
    persist([...rules, rule]);
    setPattern("");
  }

  function remove(id: string) {
    persist(rules.filter((r) => r.id !== id));
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-head">
          <h2>Highlight rules</h2>
          <button className="modal-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        <ul className="rule-list">
          {rules.map((r) => (
            <li key={r.id}>
              <div className="rule-info">
                <span className="rule-name">
                  <span className="highlight-swatch" style={{ background: r.color }} />
                  {r.pattern}
                </span>
                <span className="rule-desc">matches {r.field}</span>
              </div>
              <button className="btn-danger" onClick={() => remove(r.id)} aria-label="Delete rule">
                Delete
              </button>
            </li>
          ))}
          {rules.length === 0 && <li className="rule-empty">No highlight rules yet.</li>}
        </ul>

        <h3 className="modal-section">Add a rule</h3>
        <form className="rule-form" onSubmit={add}>
          <div className="rule-form-row">
            <input
              type="text"
              placeholder="e.g. *netflix*"
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
            />
            <select value={field} onChange={(e) => setField(e.target.value as "domain" | "client")}>
              <option value="domain">Domain</option>
              <option value="client">Client</option>
            </select>
            <input
              type="color"
              value={color}
              onChange={(e) => setColor(e.target.value)}
              aria-label="Highlight color"
            />
            <button type="submit" className="btn-primary">
              Add
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
