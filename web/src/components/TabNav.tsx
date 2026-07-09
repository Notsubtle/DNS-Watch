export type View = "dashboard" | "stream" | "simulator" | "heatmap" | "fanout";

const TABS: { id: View; label: string }[] = [
  { id: "dashboard", label: "Dashboard" },
  { id: "stream", label: "Live Stream" },
  { id: "simulator", label: "Blocklist Simulator" },
  { id: "heatmap", label: "Client Heatmaps" },
  { id: "fanout", label: "Domain Fan-out" },
];

interface Props {
  view: View;
  onChange: (v: View) => void;
}

export default function TabNav({ view, onChange }: Props) {
  return (
    <div className="tab-nav">
      {TABS.map((t) => (
        <button
          key={t.id}
          className={`tab-nav-btn ${view === t.id ? "active" : ""}`}
          onClick={() => onChange(t.id)}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}
