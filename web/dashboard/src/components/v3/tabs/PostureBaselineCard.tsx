import type { PostureBaseline } from "../../../lib/posture";
import { B, Card } from "../legacyPrimitives";
import { C } from "../theme";

const fmtTS = (v?: string) => { const d = new Date(String(v || "")); return Number.isNaN(d.getTime()) ? "-" : d.toLocaleString(); };

// How much history each posture signal has against what it needs
// (docs/SECURITY/POSTURE_BASELINE.md).
export function PostureBaselineCard({ baseline, error }: { baseline: PostureBaseline | null; error: string }) {
  return (
    <Card style={{ padding: "12px 14px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6, gap: 8, flexWrap: "wrap" }}>
        <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Baseline</span>
        {error ? <B c="red">Unavailable</B> : baseline ? (
          <B c={baseline.stable ? "green" : baseline.ready ? "blue" : "amber"}>
            {baseline.stable ? `Stable: ${baseline.days} days` : baseline.ready ? `Ready: ${baseline.days} of ${baseline.stable_days} days` : `Building: ${baseline.days} of ${baseline.required_days} days`}
          </B>
        ) : null}
      </div>
      {error ? <div style={{ fontSize: 10, color: C.red }}>{`Baseline unavailable: ${error}`}</div> : baseline ? <>
        <div style={{ fontSize: 9, color: C.muted, marginBottom: 8, lineHeight: 1.5 }}>
          Each signal is compared with this tenant's own complete days of audit history{baseline.from ? ` since ${fmtTS(baseline.from)}` : ""}. Nothing is judged before {baseline.required_days} days; a failure rate also needs {baseline.signals.find((x: any) => x.kind === "rate")?.required_baseline_events ?? 385} events of its own. A count is unusual when its chance under the baseline is below {baseline.spike_alpha} and it reaches the signal's floor.
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1.6fr 1fr 1.2fr", gap: 8, padding: "4px 0", borderBottom: `1px solid ${C.borderHi}`, fontSize: 9, color: C.muted, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5 }}>
          <span>Signal</span><span>Baseline</span><span>Last 24h</span><span>Status</span>
        </div>
        {baseline.signals.map((sig: any) => (
          <div key={sig.key} style={{ display: "grid", gridTemplateColumns: "2fr 1.6fr 1fr 1.2fr", gap: 8, padding: "5px 0", borderBottom: `1px solid ${C.border}`, fontSize: 10, alignItems: "center" }}>
            <span style={{ color: C.text }}>{sig.label}</span>
            <span style={{ color: C.dim }}>{sig.kind === "rate"
              ? `${(Number(sig.baseline_failure_rate || 0) * 100).toFixed(1)}% over ${Number(sig.baseline_events || 0)} events`
              : `${Number(sig.baseline_daily_mean || 0).toFixed(1)} a day`}</span>
            <span style={{ color: C.dim }}>{sig.kind === "rate" ? `${sig.current_24h} of ${Number(sig.events_24h || 0)}` : sig.current_24h}</span>
            <span>{sig.status === "building" ? <B c="amber">Building</B>
              : sig.status === "needs_events" ? <B c="amber">{`Needs ${Math.max(0, Number(sig.required_baseline_events || 0) - Number(sig.baseline_events || 0))} more events`}</B>
              : sig.unusual ? <B c="red">Unusual</B> : <B c="green">Normal</B>}</span>
          </div>
        ))}
      </> : <div style={{ fontSize: 10, color: C.muted }}>Loading…</div>}
    </Card>
  );
}
