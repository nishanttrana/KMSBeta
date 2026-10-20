import { useEffect, useState } from "react";
import { FileBadge, KeyRound, Vault } from "lucide-react";
import type { AuthSession } from "../../lib/auth";
import { searchCertificates } from "../../lib/certs";
import { searchKeys } from "../../lib/keycore";
import { searchSecrets } from "../../lib/secrets";
import { C } from "./theme";

type Hit = { id: string; label: string; sub: string };
type Source = { tab: string; title: string; icon: typeof KeyRound; run: (s: AuthSession, q: string) => Promise<Hit[]> };
type Found = { hits?: Hit[]; error?: string };

// Each source is searched by its service over the whole set, within what the
// caller may see (13.25.0-beta). The filter box still matches module names;
// these are the objects the same text finds.
const SOURCES: Source[] = [
  { tab: "keys", title: "Keys", icon: KeyRound, run: async (s, q) => (await searchKeys(s, q)).map((k) => ({ id: k.id, label: k.name || k.id, sub: k.algorithm || "" })) },
  { tab: "certs/cert-overview", title: "Certificates", icon: FileBadge, run: async (s, q) => (await searchCertificates(s, q)).map((c) => ({ id: c.id, label: c.subject_cn || c.id, sub: c.status || "" })) },
  { tab: "vault", title: "Secrets", icon: Vault, run: async (s, q) => (await searchSecrets(s, q)).map((x) => ({ id: x.id, label: x.name || x.id, sub: x.secret_type || "" })) },
];

export function SidebarSearch({ session, query, visibleTabs, onOpen }: {
  session: AuthSession | null;
  query: string;
  visibleTabs: string[];
  onOpen: (tab: string, text: string) => void;
}) {
  const q = query.trim();
  const sources = SOURCES.filter((s) => visibleTabs.includes(s.tab.split("/")[0]!));
  const [found, setFound] = useState<Record<string, Found>>({});
  useEffect(() => {
    if (!session || q.length < 2) {
      setFound({});
      return undefined;
    }
    let cancelled = false;
    const timer = setTimeout(() => {
      for (const src of sources) {
        src.run(session, q).then(
          (hits) => { if (!cancelled) setFound((prev) => ({ ...prev, [src.tab]: { hits } })); },
          (e: unknown) => { if (!cancelled) setFound((prev) => ({ ...prev, [src.tab]: { error: e instanceof Error ? e.message : String(e) } })); },
        );
      }
    }, 250);
    return () => { cancelled = true; clearTimeout(timer); };
  // eslint-disable-next-line react-hooks/exhaustive-deps -- sources follows visibleTabs, which the shell memoises
  }, [session, q, visibleTabs]);
  if (q.length < 2 || !sources.length) return null;
  return (
    <div data-testid="sidebar-search" style={{ borderTop: `1px solid ${C.border}`, margin: "6px 8px 0", paddingTop: 6 }}>
      {sources.map((src) => {
        const f = found[src.tab];
        return (
          <div key={src.tab} style={{ marginBottom: 6 }}>
            <div style={{ padding: "6px 8px 2px", fontSize: 10.5, fontFamily: "var(--font-mono)", textTransform: "uppercase", letterSpacing: "0.07em", color: C.muted }}>{src.title}</div>
            {!f && <div style={{ padding: "2px 8px", fontSize: 12, color: C.muted }}>Searching…</div>}
            {f?.error && <div style={{ padding: "2px 8px", fontSize: 12, color: C.redFg }} title={f.error}>unavailable</div>}
            {f?.hits && !f.hits.length && <div style={{ padding: "2px 8px", fontSize: 12, color: C.muted }}>No match</div>}
            {f?.hits?.map((h) => (
              <button key={h.id} type="button" className="vk-nav-item" onClick={() => onOpen(src.tab, h.label)} title={h.id}
                style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "5px 8px", border: 0, borderRadius: 3, background: "transparent", cursor: "pointer", textAlign: "left", font: "inherit" }}>
                <src.icon size={13} color={C.muted} style={{ flexShrink: 0 }} />
                <span style={{ fontSize: 12.5, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0 }}>{h.label}</span>
                <span style={{ fontSize: 11, color: C.muted, whiteSpace: "nowrap" }}>{h.sub}</span>
              </button>
            ))}
          </div>
        );
      })}
    </div>
  );
}
