import { useEffect, useRef, useState } from "react";
import { api, BackupRestoreSummary, StorageStats, WebhookFormat } from "../api";

interface Props {
  onClose: () => void;
}

const FORMATS: { value: WebhookFormat; label: string }[] = [
  { value: "generic", label: "Generic JSON (ntfy, Home Assistant, custom)" },
  { value: "slack", label: "Slack" },
  { value: "discord", label: "Discord" },
];

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

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

  // Config backup/export (#45).
  const [restoring, setRestoring] = useState(false);
  const [restoreSummary, setRestoreSummary] = useState<BackupRestoreSummary | null>(null);
  const [restoreError, setRestoreError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Storage housekeeping (#59).
  const [storageStats, setStorageStats] = useState<StorageStats | null>(null);
  const [storageLoading, setStorageLoading] = useState(false);
  const [storageError, setStorageError] = useState<string | null>(null);
  const [pruneDays, setPruneDays] = useState("90");
  const [pruning, setPruning] = useState(false);
  const [pruneResult, setPruneResult] = useState<string | null>(null);

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
    loadStorageStats();
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

  async function handleRestoreFile(file: File) {
    setRestoring(true);
    setRestoreError(null);
    setRestoreSummary(null);
    try {
      const text = await file.text();
      const data = JSON.parse(text);
      setRestoreSummary(await api.restoreBackup(data));
    } catch (e) {
      setRestoreError(
        e instanceof SyntaxError ? "That file isn't valid JSON." : (e as Error).message
      );
    } finally {
      setRestoring(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }

  async function loadStorageStats() {
    setStorageLoading(true);
    try {
      setStorageStats(await api.storageStats());
      setStorageError(null);
    } catch (e) {
      setStorageError((e as Error).message);
    } finally {
      setStorageLoading(false);
    }
  }

  async function pruneOldEvents() {
    const days = Math.floor(Number(pruneDays));
    if (!Number.isFinite(days) || days < 1) {
      setStorageError("Enter at least 1 day.");
      return;
    }
    setPruning(true);
    setPruneResult(null);
    try {
      const result = await api.pruneEvents(days);
      setPruneResult(`Deleted ${result.deleted} event(s) older than ${days} days.`);
      setStorageError(null);
      await loadStorageStats();
    } catch (e) {
      setStorageError((e as Error).message);
    } finally {
      setPruning(false);
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
  const pruneDaysNumber = Number(pruneDays);
  const pruneDisabled = pruning || !Number.isFinite(pruneDaysNumber) || pruneDaysNumber < 1;

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

            <h3 className="modal-section">Backup &amp; restore</h3>
            <p className="settings-hint">
              A portable snapshot of your tags, alert rules, and device names (webhook settings
              too, minus the secret — that's never sent to the browser, so re-enter it by hand
              after restoring onto a fresh install). Restoring <strong>merges</strong> into
              whatever's already here rather than replacing it — existing tags/rules/names are
              left alone; nothing is deleted.
            </p>
            <div className="settings-actions">
              <a className="btn-small" href={api.backupUrl} download="dnswatch-backup.json">
                Download backup
              </a>
              <button
                className="btn-small"
                onClick={() => fileInputRef.current?.click()}
                disabled={restoring}
              >
                {restoring ? "Restoring…" : "Restore from file…"}
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept="application/json"
                style={{ display: "none" }}
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) handleRestoreFile(file);
                }}
              />
            </div>
            {restoreError && <div className="error-banner">{restoreError}</div>}
            {restoreSummary && (
              <div className="settings-test ok">
                Restored {restoreSummary.tags} tag(s), {restoreSummary.alert_rules} rule(s),{" "}
                {restoreSummary.device_names} device name(s)
                {restoreSummary.settings_restored ? ", and webhook settings" : ""}.
              </div>
            )}

            <h3 className="modal-section">Storage</h3>
            <div className="settings-storage-grid">
              <div>
                <span className="settings-label">Database size</span>
                <strong>{storageStats ? formatBytes(storageStats.db_size_bytes) : "…"}</strong>
              </div>
              <div>
                <span className="settings-label">Alert events</span>
                <strong>
                  {storageStats
                    ? storageStats.alert_events_count.toLocaleString()
                    : storageLoading
                      ? "…"
                      : "0"}
                </strong>
              </div>
            </div>
            <label className="settings-field">
              <span className="settings-label">Delete events older than</span>
              <input
                type="number"
                className="settings-number"
                min={1}
                step={1}
                value={pruneDays}
                onChange={(e) => setPruneDays(e.target.value)}
              />
              <span className="settings-hint">
                Removes fired alert history only. Alert rules, tags, device names, and webhook
                settings are kept.
              </span>
            </label>
            <div className="settings-actions">
              <button
                className="btn-small"
                onClick={pruneOldEvents}
                disabled={pruneDisabled}
              >
                {pruning ? "Pruning…" : "Prune old events"}
              </button>
            </div>
            {storageError && <div className="settings-test fail">{storageError}</div>}
            {pruneResult && <div className="settings-test ok">{pruneResult}</div>}
          </div>
        )}
      </div>
    </div>
  );
}
