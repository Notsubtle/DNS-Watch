import { useEffect, useState } from "react";
import { api } from "../api";

interface Props {
  onClose: () => void;
}

export default function SettingsModal({ onClose }: Props) {
  const [enabled, setEnabled] = useState(false);
  const [url, setUrl] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; error: string | null } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .getSettings()
      .then((s) => {
        setEnabled(s.webhook_enabled);
        setUrl(s.webhook_url);
      })
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoaded(true));
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Clear the "Saved" pill whenever the user edits again.
  useEffect(() => {
    setSaved(false);
  }, [enabled, url]);

  async function save() {
    setSaving(true);
    try {
      await api.updateSettings({ webhook_enabled: enabled, webhook_url: url.trim() });
      setSaved(true);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function sendTest() {
    setTesting(true);
    setTestResult(null);
    try {
      setTestResult(await api.testWebhook(url.trim()));
    } catch (e) {
      setTestResult({ ok: false, error: (e as Error).message });
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-head">
          <h2>Settings</h2>
          <button className="modal-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        {error && <div className="error-banner">{error}</div>}

        <h3 className="modal-section">Alert delivery — webhook</h3>

        {!loaded ? (
          <div className="chart-empty">Loading…</div>
        ) : (
          <div className="settings-form">
            <label className="settings-toggle">
              <input
                type="checkbox"
                checked={enabled}
                onChange={(e) => setEnabled(e.target.checked)}
              />
              <span>Send fired alerts to a webhook</span>
            </label>

            <input
              type="text"
              className="settings-url"
              placeholder="https://ntfy.sh/my-topic  or  http://homeassistant.local:8123/api/webhook/…"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />

            <p className="settings-hint">
              DNS Watch sends a JSON <code>POST</code> for each batch of new alerts. The summary is
              in the <code>text</code> and <code>content</code> fields (so ntfy, Slack, Discord and
              Home Assistant all work), with structured details under <code>alerts</code>.
            </p>

            <div className="settings-actions">
              <button className="btn-primary" onClick={save} disabled={saving}>
                {saving ? "Saving…" : "Save"}
              </button>
              {saved && <span className="settings-saved">Saved</span>}

              <div className="spacer" />

              <button className="btn-small" onClick={sendTest} disabled={testing || !url.trim()}>
                {testing ? "Sending…" : "Send test"}
              </button>
            </div>

            {testResult && (
              <div className={`settings-test ${testResult.ok ? "ok" : "fail"}`}>
                {testResult.ok
                  ? "Test delivered successfully."
                  : `Test failed: ${testResult.error ?? "unknown error"}`}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
