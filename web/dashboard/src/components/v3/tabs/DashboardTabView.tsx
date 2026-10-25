import type { ReactNode } from "react";
import {
  ArrowRight, Bell, CheckCircle2, ClipboardCheck, Cpu, Database, FileText, Gauge, GitBranch, KeyRound,
  Lock, ScrollText, Settings, ShieldCheck, X, Zap, type LucideIcon
} from "lucide-react";
import { B, Btn, Card, Stat } from "../legacyPrimitives";
import { C } from "../theme";

// Status view of Operations: what the platform runs on, the counts other
// views own (each tile opens its home), what waits for the signed-in
// person, and pinned views. Every figure is a service's answer; a source
// that did not answer reads "unavailable", never 0.

const WIDGET_CONF: Record<string, { icon: LucideIcon; label: string }> = {
  keys: { icon: KeyRound, label: "Keys" },
  certs: { icon: FileText, label: "Certificates" },
  vault: { icon: Database, label: "Vault" },
  secrets: { icon: Database, label: "Vault" },
  alerts: { icon: Bell, label: "Alerts" },
  audit: { icon: ScrollText, label: "Audit Log" },
  posture: { icon: Gauge, label: "Posture" },
  compliance: { icon: ClipboardCheck, label: "Compliance" },
  cluster: { icon: GitBranch, label: "Cluster" },
  approvals: { icon: CheckCircle2, label: "Approvals" },
  hsm: { icon: Cpu, label: "HSM" },
  admin: { icon: Settings, label: "Admin" },
};

const title: React.CSSProperties = { fontSize: 10.5, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "var(--font-mono)" };

const nodeTone = (status: string) => {
  const s = status.toLowerCase();
  if (s.includes("online") || s.includes("running") || s.includes("ok") || s.includes("active")) return "green";
  if (s.includes("degraded") || s.includes("warn")) return "amber";
  if (s.includes("down") || s.includes("failed") || s.includes("error")) return "red";
  return "neutral";
};

// A tile that opens the view owning its number.
const Tile = ({ to, onNavigate, children }: { to: string; onNavigate?: (id: string) => void; children: ReactNode }) => (
  <div role="button" tabIndex={0} title="Open" onClick={() => onNavigate?.(to)} onKeyDown={(e) => { if (e.key === "Enter") onNavigate?.(to); }}
    style={{ display: "flex", cursor: "pointer", borderRadius: "var(--radius-md)" }}>{children}</div>
);

const Cell = ({ label, value, note, tone }: { label: string; value: ReactNode; note?: ReactNode; tone?: string }) => (
  <div style={{ minWidth: 0, padding: "12px 16px", borderRight: `1px solid ${C.border}` }}>
    <div style={title}>{label}</div>
    <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginTop: 6, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={typeof value === "string" ? value : undefined}>{value}</div>
    {note && <div style={{ marginTop: 5 }}>{tone ? <B c={tone}>{note}</B> : <span style={{ fontSize: 10.5, color: C.muted }}>{note}</span>}</div>}
  </div>
);

export const DashboardTabView = (props: any) => {
  const {
    homeSummary = {}, homeLoading = false, approvalVoteBusy = "", globalFipsEnabled = false,
    fmtInt = (v: number) => String(v || 0), fmtCompact = (v: number) => String(v || 0),
    clusterNodes = [], clusterSummary = { total_nodes: 0, online_nodes: 0, degraded_nodes: 0, down_nodes: 0 }, clusterLagText = "n/a",
    cryptoLibraryLabel = "", cryptoLibraryValidated = false, homeSystemState = {},
    submitHomeApprovalVote, promptUI, pinnedTabs = [], onNavigate, onUnpinTab,
  } = props || {};

  const s = homeSummary;
  const pending: any[] = Array.isArray(s?.pendingApprovals) ? s.pendingApprovals : [];
  const nodes: any[] = Array.isArray(clusterNodes) ? clusterNodes : [];
  // No nodes reported is not a healthy cluster: it carries no colour.
  const clusterTone = clusterSummary?.unavailable ? "amber" : !Number(clusterSummary?.total_nodes) ? "neutral" : clusterSummary?.down_nodes > 0 ? "red" : clusterSummary?.degraded_nodes > 0 ? "amber" : "green";
  const assessed = Boolean(s?.complianceHasAssessment);
  // A count whose source did not answer is null: shown as a dash, never 0.
  const num = (v: any) => (v == null ? "—" : fmtInt(v));
  const sub = (v: any, text: string) => (v == null ? (homeLoading ? "Loading…" : "Unavailable") : text);
  const pinned: string[] = (Array.isArray(pinnedTabs) ? pinnedTabs : []).filter((id: string) => id !== "home");

  const widget = (id: string): [string, string] => {
    switch (id) {
      case "keys": return [num(s?.keys), sub(s?.keyGrowthWeek, `+${fmtInt(s?.keyGrowthWeek)} this week`)];
      case "certs": return [num(s?.certs), sub(s?.expiring, Number(s?.expiring) > 0 ? `${fmtInt(s.expiring)} expiring` : "None expiring")];
      case "vault": case "secrets": return [num(s?.secrets), "encrypted at rest"];
      case "alerts": return [num(s?.alerts), sub(s?.criticalAlerts, `${fmtInt(s?.criticalAlerts)} critical`)];
      case "compliance": return [assessed ? `${s?.complianceScore || 0}/100` : "Not assessed", assessed ? "latest assessment" : "No score yet"];
      case "cluster": return [clusterSummary?.unavailable ? "unavailable" : `${fmtInt(clusterSummary?.online_nodes || 0)}/${fmtInt(clusterSummary?.total_nodes || 0)}`, `Lag: ${clusterLagText}`];
      case "approvals": return [fmtInt(s?.myPendingApprovals || 0), "pending review"];
      case "audit": return ["—", "Integrity in Checkpoints"];
      case "hsm": return ["—", globalFipsEnabled ? "FIPS strict" : "Standard mode"];
      default: return ["—", ""];
    }
  };

  return (
    <div style={{ display: "grid", gap: 12 }}>
      {/* Runtime: what every operation runs on. */}
      <Card style={{ padding: 0 }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))" }}>
          <Cell label="FIPS mode" value={globalFipsEnabled ? "Strict (FIPS 140-3)" : "Standard"} note={globalFipsEnabled ? "approved algorithms only" : "all algorithms"} />
          <Cell label="Crypto module" value={cryptoLibraryLabel} note={cryptoLibraryValidated ? "validated" : "not validated"} tone={cryptoLibraryValidated ? "green" : "amber"} />
          <Cell label="TLS" value={String(homeSystemState?.fips_tls_profile || "not reported")} />
          <Cell label="RNG" value={String(homeSystemState?.fips_rng_mode || "not reported")} />
          <Cell label="Cluster" value={clusterSummary?.unavailable ? "unavailable" : `${fmtInt(clusterSummary.online_nodes)}/${fmtInt(clusterSummary.total_nodes)} online`}
            note={clusterSummary?.unavailable ? "did not answer" : `lag ${clusterLagText}`} tone={clusterTone} />
        </div>
      </Card>

      {Number(s?.myPendingApprovals || 0) > 0 && (
        <Banner icon={Bell} text={`${fmtInt(s.myPendingApprovals)} approval${Number(s.myPendingApprovals) === 1 ? "" : "s"} waiting for you`}
          action={<Btn small onClick={() => onNavigate?.("approvals")}>Approvals <ArrowRight size={12} /></Btn>} />
      )}
      {Number(s?.expiring || 0) > 0 && (
        <Banner icon={FileText} text={`${fmtInt(s.expiring)} certificate${Number(s.expiring) === 1 ? "" : "s"} expiring within ${fmtInt(s.alertDays || 30)} days`}
          action={<Btn small onClick={() => onNavigate?.("certs/cert-renewals")}>Renewals <ArrowRight size={12} /></Btn>} />
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))", gap: 10 }}>
        <Tile to="ops/inventory" onNavigate={onNavigate}>
          <Stat l="Keys" v={num(s?.keys)} s={sub(s?.keyGrowthWeek, `+${fmtInt(s?.keyGrowthWeek)} created this week`)} i={KeyRound} />
        </Tile>
        <Tile to="ops/metrics" onNavigate={onNavigate}>
          <Stat l="Operations · 24h" v={s?.opsPerDay == null ? "—" : fmtCompact(s.opsPerDay)} s={s?.opsPerDay == null ? (homeLoading ? "Loading…" : "Unavailable") : s?.opsWeekTotal == null ? "last 24 hours" : `${fmtCompact(s.opsWeekTotal)} in 7 days`} i={Zap} />
        </Tile>
        <Tile to="compliance" onNavigate={onNavigate}>
          <Stat l="Compliance" v={assessed ? `${s.complianceScore}/100` : "Not assessed"} s={assessed ? `${s.complianceDeltaWeek >= 0 ? "+" : ""}${fmtInt(s.complianceDeltaWeek)} since the previous assessment` : "no assessment yet"} i={ShieldCheck} />
        </Tile>
        <Tile to="alerts" onNavigate={onNavigate}>
          <Stat l="Open alerts" v={num(s?.alerts)} s={sub(s?.criticalAlerts, `${fmtInt(s?.criticalAlerts)} critical`)} c={Number(s?.criticalAlerts || 0) > 0 ? "red" : Number(s?.alerts || 0) > 0 ? "amber" : "accent"} i={Bell} />
        </Tile>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(320px,1fr))", gap: 12 }}>
        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={title}>Cluster nodes</span>
            <Btn small onClick={() => onNavigate?.("cluster")}>Cluster <ArrowRight size={12} /></Btn>
          </div>
          {clusterSummary?.unavailable ? <div style={{ fontSize: 11, color: C.muted }}>Cluster status unavailable (the cluster service did not answer).</div>
            : !nodes.length ? <div style={{ fontSize: 11, color: C.muted }}>No nodes reported.</div>
              : nodes.map((n: any) => (
                <div key={String(n?.id || n?.name)} style={{ display: "grid", gridTemplateColumns: "1fr auto auto", gap: 8, alignItems: "center", padding: "8px 0", borderBottom: `1px solid ${C.border}` }}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 12, color: C.text, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(n?.name || n?.id || "node")}</div>
                    <div style={{ fontSize: 10.5, color: C.muted, fontFamily: "var(--font-mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(n?.address || n?.endpoint || "n/a")}</div>
                  </div>
                  <B c="neutral">{String(n?.role || "follower")}</B>
                  <B c={nodeTone(String(n?.status || "unknown"))}>{String(n?.status || "unknown")}</B>
                </div>
              ))}
        </Card>

        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
            <span style={title}>Waiting for your approval</span>
            <B c={pending.length ? "amber" : "neutral"}>{fmtInt(s?.myPendingApprovals || 0)}</B>
          </div>
          {!pending.length ? <div style={{ fontSize: 11, color: C.muted }}>Nothing is waiting for you.</div> : pending.slice(0, 4).map((item: any) => {
            const id = String(item?.id || "");
            const busy = approvalVoteBusy === `${id}:approved` || approvalVoteBusy === `${id}:denied` || homeLoading;
            return (
              <div key={id} style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 8, alignItems: "center", padding: "8px 0", borderBottom: `1px solid ${C.border}` }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 12, color: C.text, fontWeight: 600 }}>{String(item?.action || "approval").replace(/^key\./, "").replaceAll("_", " ")}</div>
                  <div style={{ fontSize: 10.5, color: C.muted, fontFamily: "var(--font-mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {`${String(item?.target_id || "-")} · ${Number(item?.current_approvals || 0)}/${Number(item?.required_approvals || 1)} votes`}
                  </div>
                </div>
                <div style={{ display: "flex", gap: 6 }}>
                  <Btn small primary onClick={() => void submitHomeApprovalVote?.(item, "approved")} disabled={busy}>Approve</Btn>
                  <Btn small danger onClick={() => void submitHomeApprovalVote?.(item, "denied")} disabled={busy}>Deny</Btn>
                </div>
              </div>
            );
          })}
        </Card>
      </div>

      {pinned.length > 0 && (
        <div>
          <div style={{ ...title, display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}><Lock size={11} /> Pinned views</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(190px,1fr))", gap: 10 }}>
            {pinned.map((id) => {
              const conf = WIDGET_CONF[id] || { icon: Settings, label: id };
              const Icon = conf.icon;
              const [value, note] = widget(id);
              return (
                <Card key={id}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ ...title, display: "inline-flex", alignItems: "center", gap: 6 }}><Icon size={12} />{conf.label}</span>
                    <button onClick={() => onUnpinTab?.(id)} title={`Unpin ${conf.label}`} aria-label={`Unpin ${conf.label}`}
                      style={{ background: "transparent", border: "none", cursor: "pointer", color: C.muted, padding: 2, display: "flex" }}><X size={12} /></button>
                  </div>
                  <div className="vk-num" style={{ fontSize: 22, fontWeight: 600, color: C.text, marginTop: 6 }}>{value}</div>
                  <div style={{ fontSize: 10.5, color: C.muted, margin: "2px 0 10px" }}>{note}</div>
                  <Btn small onClick={() => onNavigate?.(id)}>Open <ArrowRight size={12} /></Btn>
                </Card>
              );
            })}
          </div>
        </div>
      )}

      {promptUI}
    </div>
  );
};

const Banner = ({ icon: Icon, text, action }: { icon: LucideIcon; text: string; action: ReactNode }) => (
  <div data-keep style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, padding: "10px 14px", borderRadius: "var(--radius-md)", border: `1px solid ${C.border}`, background: C.amberDim }}>
    <span style={{ display: "inline-flex", alignItems: "center", gap: 8, fontSize: 12, fontWeight: 600, color: C.text }}><Icon size={14} color={C.amberFg} />{text}</span>
    {action}
  </div>
);
