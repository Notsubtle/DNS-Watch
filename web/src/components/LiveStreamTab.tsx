import { useEffect, useMemo, useRef, useState } from "react";
import { List, RowComponentProps, useListRef } from "react-window";
import { api, TailRow } from "../api";
import {
  CompiledRule,
  compileRules,
  HighlightRule,
  loadHighlightRules,
  matchHighlightColor,
} from "../highlightRules";
import HighlightRulesModal from "./HighlightRulesModal";
import { isHighEntropyDomain } from "../entropy";

const POLL_MS = 1500;
const THROTTLED_POLL_MS = 3000;
const BUFFER_CAP = 1500;
const ROW_HEIGHT = 26;
const NEW_ROW_FLASH_MS = 700;
// A single poll returning more rows than this is treated as a flood: render
// only the most recent slice instead of the whole batch, and back the poll
// interval off (see THROTTLED_POLL_MS) so a haywire device doesn't also hammer
// the backend. Ordinary bursts (e.g. a page load firing 20-30 queries) stay
// well under this.
const FLOOD_THRESHOLD = 100;
const FLOOD_DISPLAY_SAMPLE = 50;

function formatTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

interface RowProps {
  rows: TailRow[];
  newIds: Set<number>;
  compiledRules: CompiledRule[];
}

function StreamRow({ index, style, rows, newIds, compiledRules }: RowComponentProps<RowProps>) {
  const r = rows[index];
  if (!r) return null;
  const highlight = matchHighlightColor(compiledRules, r.domain, r.client_name, r.client_ip);
  return (
    <div
      style={{ ...style, backgroundColor: highlight ? `${highlight}33` : undefined }}
      className={`stream-row ${newIds.has(r.id) ? "stream-row-new" : ""}`}
    >
      <span className="stream-time">{formatTime(r.timestamp)}</span>
      <span className="stream-client" title={r.client_ip}>
        {r.client_name}
      </span>
      <span className="stream-domain" title={r.domain}>
        {r.domain}
        {isHighEntropyDomain(r.domain) && (
          <span
            className="entropy-badge"
            title="High lexical entropy -- looks random/algorithmically generated (soft signal, not a confirmed finding)"
          >
            ⚡
          </span>
        )}
      </span>
      <span className={`status-pill ${r.status} mini`}>{r.status}</span>
    </div>
  );
}

// The "Live Stream Console" tab: polls /api/tail every ~1.5s and renders an
// append-only, virtualized console. Per the shared tab shell's unmount-on-
// switch design, leaving this tab and coming back starts a clean buffer —
// matches the spec's "volatile buffer" requirement with no extra code here.
export default function LiveStreamTab() {
  const [rows, setRows] = useState<TailRow[]>([]);
  const [newIds, setNewIds] = useState<Set<number>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [throttled, setThrottled] = useState(false);
  const [highlightRules, setHighlightRules] = useState<HighlightRule[]>(() => loadHighlightRules());
  const [highlightModalOpen, setHighlightModalOpen] = useState(false);
  const cursorRef = useRef({ since: Date.now() / 1000, sinceId: 0 });
  const listRef = useListRef(null);

  // Recompiled only when the rule set changes, not per row/poll.
  const compiledRules = useMemo(() => compileRules(highlightRules), [highlightRules]);

  // Self-scheduling (setTimeout, not setInterval) so the delay between polls
  // can change based on what the LAST poll returned — normal cadence usually,
  // backed off while a flood is in progress.
  useEffect(() => {
    let cancelled = false;
    let timeoutId: ReturnType<typeof setTimeout>;

    async function poll() {
      let nextDelay = POLL_MS;
      try {
        const batch = await api.tail(cursorRef.current.since, cursorRef.current.sinceId);
        if (!cancelled) {
          const isFlood = batch.length > FLOOD_THRESHOLD;
          setThrottled(isFlood);
          nextDelay = isFlood ? THROTTLED_POLL_MS : POLL_MS;

          if (batch.length > 0) {
            const last = batch[batch.length - 1];
            cursorRef.current = { since: last.timestamp, sinceId: last.id };

            // While flooding, only render the tail of the batch — pushing
            // hundreds/thousands of rows through react-window every poll is
            // exactly what this guard exists to avoid.
            const toRender = isFlood ? batch.slice(-FLOOD_DISPLAY_SAMPLE) : batch;
            const incomingIds = new Set(toRender.map((r) => r.id));
            setRows((prev) => {
              const merged = [...toRender, ...prev];
              return merged.length > BUFFER_CAP ? merged.slice(0, BUFFER_CAP) : merged;
            });
            setNewIds(incomingIds);
            setTimeout(() => {
              setNewIds((cur) => {
                const next = new Set(cur);
                incomingIds.forEach((id) => next.delete(id));
                return next;
              });
            }, NEW_ROW_FLASH_MS);
          }
          setError(null);
        }
      } catch (e) {
        if (!cancelled) setError((e as Error).message);
      } finally {
        if (!cancelled) timeoutId = setTimeout(poll, nextDelay);
      }
    }

    poll();
    return () => {
      cancelled = true;
      clearTimeout(timeoutId);
    };
  }, []);


  return (
    <div className="stream-console">
      <div className="stream-head">
        <h2>Live Query Stream</h2>
        <div className="stream-head-actions">
          <span className="stream-count">{rows.length.toLocaleString()} buffered</span>
          <button className="btn-small" onClick={() => setHighlightModalOpen(true)}>
            Highlight rules
          </button>
        </div>
      </div>
      {error && <div className="error-banner">{error}</div>}
      {throttled && (
        <div className="error-banner throttle-banner">
          Streaming throttled due to high volume
        </div>
      )}
      <div className="stream-list-wrap">
        {rows.length === 0 ? (
          <div className="tab-placeholder">Waiting for queries…</div>
        ) : (
          <List
            listRef={listRef}
            rowComponent={StreamRow}
            rowCount={rows.length}
            rowHeight={ROW_HEIGHT}
            rowProps={{ rows, newIds, compiledRules }}
            style={{ height: "100%" }}
          />
        )}
      </div>

      {highlightModalOpen && (
        <HighlightRulesModal
          onClose={() => setHighlightModalOpen(false)}
          onChange={setHighlightRules}
        />
      )}
    </div>
  );
}
