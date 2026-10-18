import { AlertTriangle, CheckCircle2, Clock, Zap } from "lucide-react";
import { Stat } from "../legacyPrimitives";
import { C } from "../theme";

// The Posture header's count cards. When the posture service did not
// answer they read "unavailable", never "0 · All clear" (13.21.0-beta).
export function PostureCountCards({ loadErr, assessed, open, critical, findings, pending, actions, resolved, statusTotal }: {
  loadErr: string; assessed: boolean; open: number; critical: number; findings: number; pending: number; actions: number; resolved: number; statusTotal: number;
}) {
  if (loadErr) return <>{["Open Findings", "Critical", "Pending Actions", "Resolved"].map((l) => <Stat key={l} l={l} v="—" s="unavailable" c="blue" i={AlertTriangle} />)}</>;
  return <>
    <Stat l="Open Findings" v={open} s={`${findings} total`} c="amber" i={AlertTriangle} />
    <Stat l="Critical" v={critical} s={critical > 0 ? "Action needed" : assessed ? "All clear" : "No scan yet"} c="red" i={Zap} />
    <Stat l="Pending Actions" v={pending} s={`${actions} total`} c="blue" i={Clock} />
    <Stat l="Resolved" v={resolved} s={statusTotal > 0 ? `${Math.round((resolved / statusTotal) * 100)}% resolved` : "No findings"} c="green" i={CheckCircle2} />
  </>;
}

// The Dashboard view's Executive / Operations switch, drawn as a toggle: a
// second tab strip beside the first showed two tabs selected at once.
export function PostureModeToggle({ mode, onChange }: { mode: string; onChange: (m: string) => void }) {
  return (
    <div role="group" aria-label="Dashboard view" style={{ display: "inline-flex", border: `1px solid ${C.border}`, borderRadius: 4, marginBottom: 14, overflow: "hidden" }}>
      {["Executive", "Operations"].map((m) => (
        <button key={m} type="button" aria-pressed={mode === m} onClick={() => onChange(m)}
          style={{ border: 0, padding: "4px 10px", fontSize: 12, cursor: "pointer", background: mode === m ? C.accentDim : "transparent", color: mode === m ? C.text : C.muted, fontWeight: mode === m ? 600 : 500 }}>
          {m}
        </button>
      ))}
    </div>
  );
}
