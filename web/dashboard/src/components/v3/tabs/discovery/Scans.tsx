import { useState } from "react";
import { CheckCircle2, Loader2 } from "lucide-react";
import { C } from "../../theme";
import type { DiscoveryScan } from "../../../../lib/discovery";
import { absTime, duration, relTime, sourceMeta } from "./meta";

const STATUS: Record<string, { label: string; color: string }> = {
  running: { label: "Running", color: C.accentFg },
  completed: { label: "Completed", color: C.greenFg },
  completed_with_errors: { label: "With errors", color: C.amberFg },
  failed: { label: "Failed", color: C.redFg },
  interrupted: { label: "Interrupted", color: C.redFg },
};
const statusOf = (s: string) => STATUS[s] ?? { label: s, color: C.muted };

const sourcesOf = (s: DiscoveryScan) => String(s.scan_type || "").split(",").filter(Boolean);
const errorsOf = (s: DiscoveryScan): Record<string, string> => ((s.stats as any)?.errors as Record<string, string>) || {};
const countOf = (s: DiscoveryScan, src: string) => Number((s.stats as any)?.[`${src}_assets`] ?? 0);

// RunningBanner shows a scan in progress, source by source.
export function RunningBanner({ scan }: { scan: DiscoveryScan }) {
  const done: string[] = ((scan.stats as any)?.sources_done as string[]) || [];
  const errs = errorsOf(scan);
  return (
    <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 10, padding: "10px 14px", marginBottom: 14, border: `1px solid ${C.accentFg}`, background: C.accentDim, borderRadius: "var(--radius-md)" }}>
      <Loader2 size={14} color={C.accentFg} style={{ animation: "vecta-spin 1s linear infinite" }} />
      <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>Scanning</span>
      {sourcesOf(scan).map((src) => {
        const finished = done.includes(src);
        return (
          <span key={src} style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 11, color: finished ? (errs[src] ? C.amberFg : C.text) : C.muted }}>
            {finished ? <CheckCircle2 size={12} /> : <Loader2 size={12} style={{ animation: "vecta-spin 1s linear infinite" }} />}
            {sourceMeta(src).label}{finished ? ` · ${countOf(scan, src)}` : ""}
          </span>
        );
      })}
      <span style={{ marginLeft: "auto", fontSize: 10.5, color: C.muted }}>started {relTime(scan.started_at)}</span>
    </div>
  );
}

export function ScansView({ scans }: { scans: DiscoveryScan[] }) {
  const [open, setOpen] = useState("");
  return (
    <div>
      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-sm)" }}>
        {scans.map((s, i) => {
          const st = statusOf(s.status);
          const errs = errorsOf(s);
          const nErr = Object.keys(errs).length;
          const file = (s.stats as any)?.file;
          return (
            <div key={s.id} style={{ borderTop: i ? `1px solid ${C.border}` : "none" }}>
              <div onClick={() => nErr && setOpen(open === s.id ? "" : s.id)}
                style={{ display: "grid", gridTemplateColumns: "110px 1fr auto", gap: 12, alignItems: "center", padding: "10px 14px", cursor: nErr ? "pointer" : "default" }}>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, fontWeight: 600, color: st.color }}>
                  <span style={{ width: 7, height: 7, borderRadius: 4, background: st.color }} />{st.label}
                </span>
                <span style={{ display: "flex", flexWrap: "wrap", gap: 6, minWidth: 0 }}>
                  {sourcesOf(s).map((src) => {
                    const SI = sourceMeta(src).icon;
                    return (
                      <span key={src} title={errs[src] || ""} style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 11, color: errs[src] ? C.amberFg : C.text, border: `1px solid ${errs[src] ? C.amberFg : C.border}`, borderRadius: 12, padding: "2px 9px" }}>
                        <SI size={11} />{sourceMeta(src).label}
                        <b style={{ fontWeight: 600 }}>{countOf(s, src)}</b>
                      </span>
                    );
                  })}
                  {file ? <span style={{ fontSize: 11, color: C.muted, alignSelf: "center" }}>{String(file)}</span> : null}
                </span>
                <span style={{ fontSize: 10.5, color: C.muted, textAlign: "right", whiteSpace: "nowrap" }} title={absTime(s.started_at)}>
                  {relTime(s.started_at)}{duration(s.started_at, s.completed_at) ? ` · ${duration(s.started_at, s.completed_at)}` : ""}{nErr ? ` · ${nErr} error${nErr > 1 ? "s" : ""} ▾` : ""}
                </span>
              </div>
              {open === s.id && (
                <div style={{ padding: "0 14px 12px 136px", display: "grid", gap: 4 }}>
                  {Object.entries(errs).map(([src, msg]) => (
                    <div key={src} style={{ fontSize: 11, color: C.dim, wordBreak: "break-word" }}><b style={{ color: C.amberFg }}>{sourceMeta(src).label}:</b> {msg}</div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
        {!scans.length && <div style={{ textAlign: "center", padding: "28px 0", color: C.muted, fontSize: 11.5 }}>No scans yet.</div>}
      </div>
    </div>
  );
}
