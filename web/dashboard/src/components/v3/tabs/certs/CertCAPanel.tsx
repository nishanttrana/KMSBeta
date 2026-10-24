import { useEffect, useMemo, useState } from "react";
import { Plus } from "lucide-react";
import { Btn, Card } from "../../legacyPrimitives";
import { C } from "../../theme";
import { CertCAClassic } from "./CertCAClassic";
import { CertCADiagram } from "./CertCADiagram";
import { buildCATree } from "./caTree";
import type { CertFilter, ExpiryPolicy } from "./certFilters";
import type { LiveState } from "./useLivePoll";

type View = "diagram" | "classic";
const VIEW_KEY = "vecta_cert_ca_view";
const readView = (): View => { try { return window.localStorage.getItem(VIEW_KEY) === "classic" ? "classic" : "diagram"; } catch { return "diagram"; } };

type Props = {
  cas: any[];
  certs: any[];
  policy: ExpiryPolicy;
  selected: string;
  onSelect: (caID: string) => void;
  onPick: (caID: string, filter: CertFilter) => void;
  onCreate: () => void;
  onCRL: (ca: any) => void;
  onDelete: (ca: any) => void;
  busy: string;
  loading: boolean;
  live: LiveState;
};

// How fresh the hierarchy is: re-read every 15 s while the page is open.
function LiveLabel({ live }: { live: LiveState }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { const id = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(id); }, []);
  if (live.error) {
    return (
      <span data-testid="ca-live" style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, color: C.amberFg }}>
        {`Live updates paused: ${live.error}`}<Btn small onClick={() => void live.retry()}>Retry</Btn>
      </span>
    );
  }
  const secs = Math.max(0, Math.round((now - live.at) / 1000));
  return (
    <span data-testid="ca-live" title="Re-read every 15 seconds while this page is open" style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, color: C.muted }}>
      <span className="vk-live-dot" style={{ width: 7, height: 7, borderRadius: "50%", background: "var(--cls-ontime)" }} />
      {`Live · updated ${secs < 5 ? "just now" : `${secs}s ago`}`}
    </span>
  );
}

// The CA hierarchy, as a diagram or as the classic nested cards.
export function CertCAPanel(p: Props) {
  const [view, setView] = useState<View>(readView);
  const choose = (v: View) => { setView(v); try { window.localStorage.setItem(VIEW_KEY, v); } catch { /* the choice is a convenience */ } };
  // Counted at the time the list arrived (the tiles' rule), not on every render.
  const tree = useMemo(() => buildCATree(p.cas, p.certs, p.policy, Date.now()), [p.cas, p.certs, p.policy]);
  return (
    <Card style={{ padding: 12, marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10, flexWrap: "wrap" }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>CA hierarchy <span className="vk-num" style={{ color: C.muted, fontWeight: 500 }}>{p.cas.length}</span></span>
        <LiveLabel live={p.live} />
        <span style={{ flex: 1 }} />
        <div role="group" aria-label="CA view" style={{ display: "inline-flex", border: `1px solid ${C.border}`, borderRadius: 4, overflow: "hidden" }}>
          {(["diagram", "classic"] as const).map((v) => (
            <button key={v} type="button" aria-pressed={view === v} onClick={() => choose(v)}
              style={{ border: 0, padding: "4px 10px", fontSize: 12, cursor: "pointer", background: view === v ? C.accentDim : "transparent", color: view === v ? C.text : C.muted, fontWeight: view === v ? 600 : 500 }}>
              {v === "diagram" ? "Diagram" : "Classic"}
            </button>
          ))}
        </div>
        <Btn small onClick={p.onCreate}><span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}><Plus size={11} />Create CA</span></Btn>
      </div>
      {!p.cas.length
        ? (p.loading ? null : <div style={{ fontSize: 11, color: C.muted, padding: "8px 4px" }}>No CA yet. Create a root CA to start issuing.</div>)
        : view === "diagram"
          ? <CertCADiagram tree={tree} selected={p.selected} onSelect={p.onSelect} onPick={p.onPick} onCRL={p.onCRL} onDelete={p.onDelete} busy={p.busy} />
          : <CertCAClassic tree={tree} selected={p.selected} onSelect={p.onSelect} onCRL={p.onCRL} onDelete={p.onDelete} busy={p.busy} />}
    </Card>
  );
}
