import { useEffect, useState } from "react";
import { api, ClientInfo, Tag } from "../api";

interface Props {
  onClose: () => void;
  onChange: () => void; // ask App to reload tags (FilterBar/RulesModal read them)
  clients: ClientInfo[];
}

export default function TagsModal({ onClose, onChange, clients }: Props) {
  const [tagList, setTagList] = useState<Tag[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [newName, setNewName] = useState("");
  // Per-tag "add a member" picker state, keyed by tag id.
  const [addingIp, setAddingIp] = useState<Record<number, string>>({});

  function load() {
    api
      .listTags()
      .then(setTagList)
      .catch((e) => setError((e as Error).message));
  }
  useEffect(load, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function createTag(e: React.FormEvent) {
    e.preventDefault();
    if (!newName.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.createTag(newName.trim());
      setNewName("");
      load();
      onChange();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function removeTag(tag: Tag) {
    setBusy(true);
    try {
      await api.deleteTag(tag.id);
      load();
      onChange();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function addMember(tag: Tag) {
    const ip = addingIp[tag.id];
    if (!ip) return;
    setBusy(true);
    try {
      await api.addTagMember(tag.id, ip);
      setAddingIp((s) => ({ ...s, [tag.id]: "" }));
      load();
      onChange();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function removeMember(tag: Tag, ip: string) {
    setBusy(true);
    try {
      await api.removeTagMember(tag.id, ip);
      load();
      onChange();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-head">
          <h2>Manage tags</h2>
          <button className="modal-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        <p className="modal-sub">
          Group devices under a label (e.g. "kids", "IoT", "guest") so the dashboard filter and
          alert rules can scope to the whole group at once, instead of one device or every device.
        </p>

        {error && <div className="error-banner">{error}</div>}

        <ul className="rule-list">
          {tagList.map((tag) => (
            <li key={tag.id}>
              <div className="rule-info">
                <span className="rule-name">🏷 {tag.name}</span>
                <span className="rule-desc">
                  {tag.ips.length === 0
                    ? "no members yet"
                    : tag.ips
                        .map((ip) => clients.find((c) => c.ip === ip)?.name ?? ip)
                        .join(", ")}
                </span>
              </div>
              <button className="btn-danger" disabled={busy} onClick={() => removeTag(tag)}>
                Delete
              </button>
            </li>
          ))}
          {tagList.length === 0 && <li className="rule-empty">No tags yet.</li>}
        </ul>

        {tagList.length > 0 && (
          <>
            <h3 className="modal-section">Add a member</h3>
            {tagList.map((tag) => (
              <div className="rule-form-row" key={`add-${tag.id}`}>
                <span className="rule-name">🏷 {tag.name}</span>
                <select
                  value={addingIp[tag.id] ?? ""}
                  onChange={(e) => setAddingIp((s) => ({ ...s, [tag.id]: e.target.value }))}
                >
                  <option value="">Pick a device…</option>
                  {clients
                    .filter((c) => !tag.ips.includes(c.ip))
                    .map((c) => (
                      <option key={c.ip} value={c.ip}>
                        {c.name}
                      </option>
                    ))}
                </select>
                <button
                  className="btn-small"
                  disabled={busy || !addingIp[tag.id]}
                  onClick={() => addMember(tag)}
                >
                  Add
                </button>
                {tag.ips.map((ip) => (
                  <button
                    key={ip}
                    className="btn-small"
                    disabled={busy}
                    onClick={() => removeMember(tag, ip)}
                    title={`Remove ${clients.find((c) => c.ip === ip)?.name ?? ip} from ${tag.name}`}
                  >
                    − {clients.find((c) => c.ip === ip)?.name ?? ip}
                  </button>
                ))}
              </div>
            ))}
          </>
        )}

        <h3 className="modal-section">Add a tag</h3>
        <form className="rule-form" onSubmit={createTag}>
          <div className="rule-form-row">
            <input
              type="text"
              placeholder="Tag name (e.g. IoT)"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              maxLength={50}
            />
            <button type="submit" className="btn-primary btn-small" disabled={busy}>
              Add tag
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
