import { useState } from "react";
import { api, SimulationResult } from "../api";
import TopList from "./TopList";

// Impact percentage above which a client gets the spec's "this rule would
// hit a device pretty hard" warning styling (the SmartFridge example).
const HIGH_IMPACT_PCT = 30;

export default function SimulatorTab() {
  const [pattern, setPattern] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SimulationResult | null>(null);

  async function simulate(e: React.FormEvent) {
    e.preventDefault();
    if (!pattern.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.simulateBlocklist(pattern.trim());
      setResult(res);
    } catch (e) {
      // sendJson() throws `${method} ${url} -> ${status}` — a 400 here can
      // only mean the regex itself was rejected server-side, so show the
      // spec's exact copy rather than a generic network-failure message.
      const message = (e as Error).message;
      setError(
        message.endsWith("-> 400")
          ? "Invalid Regular Expression syntax"
          : "Simulation failed — check the server connection and try again."
      );
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  const highImpactClients = result?.clients.filter((c) => c.pct_of_client_traffic > HIGH_IMPACT_PCT) ?? [];

  return (
    <div className="simulator-tab">
      <div className="panel">
        <h2>Blocklist Impact Simulator</h2>
        <form className="simulator-form" onSubmit={simulate}>
          <textarea
            className="simulator-pattern"
            placeholder="Pi-hole-style regex, e.g. ^(.+[-.])?telemetry[.-]"
            value={pattern}
            onChange={(e) => setPattern(e.target.value)}
            rows={2}
            spellCheck={false}
          />
          <button type="submit" className="btn-primary" disabled={busy || !pattern.trim()}>
            {busy ? <span className="spinner" /> : "Simulate"}
          </button>
        </form>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {result && (
        <>
          <div className="panel simulator-summary">
            <p>
              This rule would have blocked <strong>{result.total_matches.toLocaleString()}</strong>{" "}
              queries across <strong>{result.unique_domains.toLocaleString()}</strong> unique domain
              {result.unique_domains === 1 ? "" : "s"} over the last 7 days. Impact:{" "}
              <strong>{result.clients.length}</strong> client{result.clients.length === 1 ? "" : "s"}{" "}
              affected.
            </p>
            {highImpactClients.map((c) => (
              <p key={c.ip} className="simulator-high-impact">
                This rule would account for <strong>{c.pct_of_client_traffic}%</strong> of{" "}
                <strong>{c.name}</strong>&rsquo;s traffic in this window.
              </p>
            ))}
          </div>

          <div className="main-grid">
            <TopList title="Top matched domains" entries={result.top_domains} />
            <div className="panel">
              <h2>Affected clients</h2>
              <ul className="simulator-client-list">
                {result.clients.map((c) => (
                  <li
                    key={c.ip}
                    className={c.pct_of_client_traffic > HIGH_IMPACT_PCT ? "high-impact" : ""}
                  >
                    <span className="name" title={c.ip}>
                      {c.name}
                    </span>
                    <span className="count">
                      {c.matched_count.toLocaleString()} / {c.total_count.toLocaleString()} (
                      {c.pct_of_client_traffic}%)
                    </span>
                  </li>
                ))}
                {result.clients.length === 0 && <li className="name">No matching traffic</li>}
              </ul>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
