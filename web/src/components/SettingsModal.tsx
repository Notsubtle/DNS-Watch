import { useEffect, useState } from "react";
import { api, WebhookFormat } from "../api";

interface Props {
  onClose: () => void;
}

const FORMATS: { value: WebhookFormat; label: string }[] = [
  { value: "generic", label: "Generic JSON (ntfy, Home Assistant, custom)" },
  { value: "slack", label: "Slack" },
  { value: "discord", label: "Discord" },
];

export default function SettingsModal({ onClose }: Props) {
  const [enabled, setEnabled] = useState(false);
  const [url, setUrl] = useState("");
  const [format, setFormat] = useState<WebhookFormat>("generic");
  // The server never hands back the real secret — only whether one is set.
  // `secretInput` starts empty and is only sent on save/test if the user
  // actually typed into it (secretTouched), so leaving it alone preserves
  // whatever's already saved instead of blanking it out.
  const [secretSet, setSecretSet] = useState(false);
  const [secretInput, setSecretInput] = useState("");
  const [secretTouched, setSecretTouched] = useState(false);
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
        setFormat(s.webhook_format);
        setSecretSet(s.webhook_secret_set);
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
  }, [enabled, url, format, secretInput]);

  function onSecretChange(v: string) {
    setSecretInput(v);
    setSecretTouched(true);
  }

  async function save() {
    setSaving(true);
    try {
      await api.updateSettings({
        webhook_enabled: enabled,
        webhook_url: url.trim(),
        webhook_format: format,
        // Omit entirely unless the user touched the field, so an untouched
        // field never overwrites (or blanks) whatever secret is already saved.
        ...(secretTouched ? { webhook_secret: secretInput.trim() } : {}),
      });
      setSecretSet(secretTouched ? secretInput.trim().length > 0 : secretSet);
      setSecretTouched(false);
      setSecretInput("");
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
      // Tests whatever's currently typed in the secret field — since the real
      // saved secret is never sent to the browser, testing the already-saved
      // one requires retyping it here first.
      setTestResult(await api.testWebhook(url.trim(), secretInput.trim(), format));
    } catch (e) {
      setTestResult({ ok: false, error: (e as Error).message });
    } finally {
      setTesting(false);
    }
  }

  const secretPlaceholder =
    format === "slack" || format === "discord"
      ? "not used for this format"
      : secretSet
        ? "•••••••• saved — leave blank to keep, or type a new one"
        : "optional";

  const secretHint =
    format === "slack" || format === "discord"
      ? "Slack/Discord put the secret in the webhook URL itself — leave this blank."
      : "Sent as an Authorization: Bearer header (e.g. an ntfy access token). " +
        "For security this is never sent back to the browser once saved — retype it here to change it or to run a test.";

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

            <label className="settings-field">
              <span className="settings-label">Format</span>
              <select value={format} onChange={(e) => setFormat(e.target.value as WebhookFormat)}>
                {FORMATS.map((f) => (
                  <option key={f.value} value={f.value}>
                    {f.label}
                  </option>
                ))}
              </select>
            </label>

            <label className="settings-field">
              <span className="settings-label">Webhook URL</span>
              <input
                type="text"
                className="settings-url"
                placeholder="https://ntfy.sh/my-topic  or  https://discord.com/api/webhooks/…"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            </label>

            <label className="settings-field">
              <span className="settings-label">Auth token / secret</span>
              <input
                type="password"
                className="settings-url"
                placeholder={secretPlaceholder}
                value={secretInput}
                onChange={(e) => onSecretChange(e.target.value)}
                autoComplete="new-password"
              />
              <span className="settings-hint">{secretHint}</span>
            </label>

            <p className="settings-hint">
              {format === "generic"
                ? "Generic sends DNS Watch's own JSON — the summary is in text/content, with structured details under alerts."
                : `${format[0].toUpperCase()}${format.slice(1)} format posts exactly the field that service expects.`}
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
