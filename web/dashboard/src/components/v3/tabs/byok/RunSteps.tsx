import { CheckCircle2, Copy, MinusCircle, XCircle } from "lucide-react";
import type { BYOKRun } from "../../../../lib/byok";
import { B } from "../../legacyPrimitives";
import { C } from "../../theme";
import { MONO, OPERATION_LABEL, fmtAgo } from "./meta";

const copy = (text: string) => { try { void navigator.clipboard.writeText(text); } catch { /* clipboard unavailable */ } };

// One run: each step, the call it made and the command an operator would type.
export function RunSteps({ run, compact = false }: { run: BYOKRun; compact?: boolean }) {
  return (
    <div style={{ display: "grid", gap: 6 }}>
      {!compact && (
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{OPERATION_LABEL[run.operation] ?? run.operation}</span>
          <span style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 10.5, color: C.muted }}>
            {run.actor} · {fmtAgo(run.started_at)} <B c={run.status === "succeeded" ? "green" : "red"}>{run.status}</B>
          </span>
        </div>
      )}
      {run.steps.map((s, i) => {
        const Icon = s.status === "succeeded" ? CheckCircle2 : s.status === "failed" ? XCircle : MinusCircle;
        const color = s.status === "succeeded" ? C.greenFg : s.status === "failed" ? C.redFg : C.muted;
        return (
          <div key={`${run.id}-${i}`} style={{ display: "grid", gridTemplateColumns: "18px 1fr", gap: 8, padding: "6px 8px", background: C.bg, borderRadius: 6 }}>
            <Icon size={14} color={color} style={{ marginTop: 1 }} />
            <div style={{ minWidth: 0 }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8, fontSize: 11 }}>
                <span style={{ color: C.text, fontWeight: 600 }}>{s.name}</span>
                {s.call && <span style={{ color: C.muted, fontFamily: MONO, fontSize: 10 }}>{s.call}</span>}
              </div>
              {s.detail && <div style={{ fontSize: 10.5, color: C.dim, marginTop: 2, overflowWrap: "anywhere" }}>{s.detail}</div>}
              {s.error && <div style={{ fontSize: 10.5, color: C.redFg, marginTop: 2, overflowWrap: "anywhere" }}>{s.error}</div>}
              {s.cli && (
                <div style={{ display: "flex", gap: 6, alignItems: "flex-start", marginTop: 4 }}>
                  <code style={{ flex: 1, fontFamily: MONO, fontSize: 10, color: C.text, background: C.card, border: `1px solid ${C.border}`, borderRadius: 4, padding: "3px 6px", overflowWrap: "anywhere" }}>{s.cli}</code>
                  <button type="button" onClick={() => copy(s.cli || "")} title="Copy the CLI equivalent" style={{ background: "transparent", border: "none", color: C.muted, cursor: "pointer", padding: 2 }}><Copy size={11} /></button>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
