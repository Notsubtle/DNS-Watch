// Client-side approximation of db.domain_entropy (#3 in the feature backlog),
// used only for the live query-log badge -- a lightweight, per-row visual cue,
// not the authoritative score. The backend's per-client "% high-entropy
// domains" metric (ClientDetail.entropy) is PSL-aware (strips the true
// registered parent via app/psl.py); bundling the full Public Suffix List
// into the frontend just for a live-console badge isn't worth the bytes, so
// this uses a naive "drop the last two labels" heuristic instead. That
// breaks on multi-part suffixes (co.uk) the same way naive parsing always
// does, but for a soft visual badge on a live stream, an occasional miss on
// an uncommon TLD is an acceptable tradeoff -- this is never used for
// anything but display.
// keep in sync with DOMAIN_ENTROPY_MIN_LENGTH in server/app/db.py
const HIGH_ENTROPY_MIN_LENGTH = 8;
// keep in sync with DOMAIN_ENTROPY_THRESHOLD in server/app/db.py
const HIGH_ENTROPY_THRESHOLD = 3.3;

function shannonEntropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const n = s.length;
  let entropy = 0;
  for (const c of counts.values()) {
    const p = c / n;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function naivePrefix(domain: string): string {
  const labels = domain.split(".");
  return labels.length > 2 ? labels.slice(0, -2).join("") : "";
}

export function isHighEntropyDomain(domain: string | null | undefined): boolean {
  if (!domain || domain.length < HIGH_ENTROPY_MIN_LENGTH) return false;
  const prefix = naivePrefix(domain);
  if (!prefix) return false;
  return shannonEntropy(prefix) >= HIGH_ENTROPY_THRESHOLD;
}
