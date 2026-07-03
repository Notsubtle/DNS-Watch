const W = 80;
const H = 22;

// Tiny inline area sparkline. Normalised to its own max so each client's shape
// is legible regardless of absolute volume.
export default function Sparkline({ data }: { data: number[] }) {
  if (data.length === 0) return <svg width={W} height={H} className="sparkline" />;
  const max = Math.max(1, ...data);
  const n = data.length;
  const x = (i: number) => (n === 1 ? W / 2 : (i / (n - 1)) * W);
  const y = (v: number) => H - 1 - (v / max) * (H - 2);
  const line = data.map((v, i) => `${x(i)},${y(v)}`).join(" ");
  const area = `${line} ${W},${H} 0,${H}`;

  return (
    <svg viewBox={`0 0 ${W} ${H}`} width={W} height={H} className="sparkline" preserveAspectRatio="none">
      <polygon points={area} className="spark-area" />
      <polyline points={line} className="spark-line" fill="none" />
    </svg>
  );
}
