// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import {
  ArrowRight, BarChart3, Bell, CheckCircle2, ClipboardCheck, Cloud,
  Cpu, Database, FileText, Gauge, GitBranch, KeyRound, Lock,
  ScrollText, Settings, ShieldCheck, TrendingDown, TrendingUp,
  X, Zap
} from "lucide-react";
import { B, Btn, Card } from "../legacyPrimitives";
import { C } from "../theme";

function statusTone(status: string) {
  const s = String(status || "").toLowerCase();
  if (s.includes("online") || s.includes("running") || s.includes("ok") || s.includes("active")) return "green";
  if (s.includes("degraded") || s.includes("warn")) return "amber";
  if (s.includes("down") || s.includes("failed") || s.includes("error")) return "red";
  return "blue";
}

function statusPill(label: string, tone: string, pulse = false) {
  return <B c={tone as any} pulse={pulse}>{label}</B>;
}

const WIDGET_CONF: Record<string, { icon: any; label: string; color: string }> = {
  keys: { icon: KeyRound, label: "Keys", color: C.accent },
  certs: { icon: FileText, label: "Certificates", color: C.blue },
  vault: { icon: Database, label: "Vault", color: C.purple },
  secrets: { icon: Database, label: "Vault", color: C.purple },
  alerts: { icon: Bell, label: "Alerts", color: C.red },
  audit: { icon: ScrollText, label: "Audit Log", color: C.amber },
  posture: { icon: Gauge, label: "Posture", color: C.green },
  compliance: { icon: ClipboardCheck, label: "Compliance", color: C.blue },
  cluster: { icon: GitBranch, label: "Cluster", color: C.accent },
  approvals: { icon: CheckCircle2, label: "Approvals", color: C.amber },
  governance: { icon: Settings, label: "Governance", color: C.purple },
  reporting: { icon: BarChart3, label: "Reporting", color: C.green },
  hsm: { icon: Cpu, label: "HSM", color: C.accent },
  admin: { icon: Settings, label: "Admin", color: C.muted },
};

export const DashboardTabView = (props: any) => {
  const {
    homeSummary = {},
    homeLoading = false,
    approvalVoteBusy = "",
    globalFipsEnabled = false,
    fmtInt = (v: number) => String(v || 0),
    fmtCompact = (v: number) => String(v || 0),
    clusterNodes = [],
    clusterSummary = { total_nodes: 0, online_nodes: 0, degraded_nodes: 0, down_nodes: 0 },
    clusterLagText = "n/a",
    cryptoLibraryLabel = "",
    cryptoLibraryValidated = false,
    homeSystemState = {},
    networkStatus = "ok",
    modal = null,
    setModal,
    submitHomeApprovalVote,
    promptUI,
    pinnedTabs = [],
    onNavigate,
    onUnpinTab,
  } = props || {};

  const pending = Array.isArray(homeSummary?.pendingApprovals) ? homeSummary.pendingApprovals : [];
  const algos = Array.isArray(homeSummary?.algorithms) ? homeSummary.algorithms : [];
  const nodes = clusterNodes.length
    ? clusterNodes
    : [{ id: "local", name: "vecta-kms-01", status: "online", role: "leader", address: "127.0.0.1" }];
  const auditChainOk = homeSummary?.auditChainOk !== false;
  const complianceHasAssessment = Boolean(homeSummary?.complianceHasAssessment);
  const opsHasBaseline = Boolean(homeSummary?.opsHasBaseline);
  const opsGrowthPos = Number(homeSummary?.opsGrowthPct || 0) >= 0;
  const complianceTrendPos = Number(homeSummary?.complianceDeltaWeek || 0) >= 0;
  const alertTrendPos = Number(homeSummary?.criticalAlerts || 0) === 0;
  const pinnedList = Array.isArray(pinnedTabs) ? pinnedTabs.filter((id: string) => id !== "home") : [];

  const getWidgetPrimary = (tabId: string) => {
    switch (tabId) {
      case "keys": return fmtInt(homeSummary?.keys || 0);
      case "certs": return fmtInt(homeSummary?.certs || 0);
      case "vault": case "secrets": return fmtInt(homeSummary?.secrets || 0);
      case "alerts": return fmtInt(homeSummary?.alerts || 0);
      case "audit": return auditChainOk ? "INTACT" : "BROKEN";
      case "posture": return homeSummary?.postureRisk != null ? `${Number(homeSummary.postureRisk).toFixed(0)}%` : "—";
      case "compliance": return `${homeSummary?.complianceScore || 0}/100`;
      case "cluster": return `${fmtInt(clusterSummary?.online_nodes || 0)}/${fmtInt(clusterSummary?.total_nodes || 0)}`;
      case "approvals": case "governance": return fmtInt(homeSummary?.myPendingApprovals || 0);
      case "hsm": return String(homeSystemState?.hsm_mode || "software");
      case "reporting": return "Live";
      default: return "—";
    }
  };

  const getWidgetSecondary = (tabId: string) => {
    switch (tabId) {
      case "keys": return `+${fmtInt(homeSummary?.keyGrowthWeek || 0)} this week`;
      case "certs": return Number(homeSummary?.expiring) > 0 ? `${fmtInt(homeSummary.expiring)} expiring` : "All valid";
      case "vault": case "secrets": return "encrypted at rest";
      case "alerts": return `${fmtInt(homeSummary?.criticalAlerts || 0)} critical`;
      case "audit": return auditChainOk ? "Chain verified" : "Chain broken!";
      case "posture": return "24h risk score";
      case "compliance": return complianceHasAssessment ? `+${fmtInt(homeSummary?.complianceDeltaWeek || 0)} this week` : "No score yet";
      case "cluster": return `Lag: ${clusterLagText}`;
      case "approvals": case "governance": return "pending review";
      case "hsm": return globalFipsEnabled ? "FIPS strict" : "Standard mode";
      case "reporting": return "analytics ready";
      default: return "";
    }
  };

  const getWidgetPrimaryColor = (tabId: string) => {
    if (tabId === "audit") return auditChainOk ? C.green : C.red;
    if (tabId === "alerts") return Number(homeSummary?.criticalAlerts || 0) > 0 ? C.red : C.amber;
    if (tabId === "approvals" || tabId === "governance") return Number(homeSummary?.myPendingApprovals || 0) > 0 ? C.amber : C.green;
    return (WIDGET_CONF[tabId] || WIDGET_CONF["keys"]).color;
  };

  const Kpi = ({ label, value, icon: KIcon, color, dim, delta, deltaColor, deltaIcon: DIcon, barPct }: any) => (
    <div className="vecta-stat-card" style={{ position: "relative", overflow: "hidden", background: `linear-gradient(160deg, ${C.card} 0%, ${C.surface} 100%)`, border: `1px solid ${C.border}`, borderRadius: "var(--radius-md)", padding: "16px 18px", boxShadow: "var(--shadow-sm)" }}>
      <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, ${color}, transparent 75%)`, opacity: 0.7 }} />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ fontSize: 10, fontWeight: 600, color: C.muted, letterSpacing: 1.1, textTransform: "uppercase" }}>{label}</div>
        <span style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 30, height: 30, borderRadius: 9, background: dim, color }}><KIcon size={15} strokeWidth={2.2} /></span>
      </div>
      <div className="vk-num" style={{ fontSize: 34, fontWeight: 800, color, lineHeight: 1.05, marginTop: 8 }}>{value}</div>
      <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 10.5, color: deltaColor, marginTop: 7, fontWeight: 500 }}>
        {DIcon && <DIcon size={11} strokeWidth={2.2} />}
        {delta}
      </div>
      <div style={{ height: 3, borderRadius: 999, background: C.border, overflow: "hidden", marginTop: 10 }}>
        <div style={{ height: "100%", width: `${barPct}%`, background: `linear-gradient(90deg, ${color}, color-mix(in oklab, ${color} 55%, transparent))`, borderRadius: 999, transition: "width .6s cubic-bezier(.4,0,.2,1)" }} />
      </div>
    </div>
  );

  return (
    <div style={{ display: "grid", gap: 14 }}>
      {/* ── Hero header ── */}
      <div style={{
        position: "relative", overflow: "hidden",
        borderRadius: "var(--radius-lg)", border: `1px solid ${C.border}`,
        background: `linear-gradient(120deg, ${C.surface} 0%, ${C.card} 55%, ${C.surface} 100%)`,
        padding: "20px 24px",
      }}>
        <div style={{ position: "absolute", inset: 0, pointerEvents: "none", background: `radial-gradient(900px 240px at 8% -40%, ${C.glowStrong || "rgba(34,211,238,.18)"}, transparent 60%), radial-gradient(700px 220px at 95% 140%, ${C.glow || "rgba(99,102,241,.14)"}, transparent 60%)` }} />
        <div style={{ position: "relative", display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
          <div>
            <div style={{ fontSize: 20, fontWeight: 800, color: C.text, letterSpacing: -0.4, lineHeight: 1.2 }}>
              Security Operations Overview
            </div>
            <div style={{ fontSize: 11.5, color: C.dim, marginTop: 4 }}>
              {new Date().toLocaleDateString(undefined, { weekday: "long", year: "numeric", month: "long", day: "numeric" })}
              {homeLoading ? "  ·  refreshing…" : ""}
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            <span style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "6px 12px", borderRadius: 999, fontSize: 10.5, fontWeight: 700, color: globalFipsEnabled ? C.greenFg : C.amberFg, background: globalFipsEnabled ? C.greenDim : C.amberDim, border: `1px solid color-mix(in oklab, ${globalFipsEnabled ? C.green : C.amber} 30%, transparent)` }}>
              <ShieldCheck size={12} strokeWidth={2.4} /> {globalFipsEnabled ? "FIPS 140-3 MODE" : "STANDARD MODE"}
            </span>
            <span title={cryptoLibraryLabel} style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "6px 12px", borderRadius: 999, fontSize: 10.5, fontWeight: 700, color: cryptoLibraryValidated ? C.accentFg : C.dim, background: C.accentDim, border: `1px solid color-mix(in oklab, ${C.accent} 25%, transparent)`, maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              <Cpu size={12} strokeWidth={2.4} /> {cryptoLibraryValidated ? "VALIDATED CRYPTO" : (cryptoLibraryLabel || "CRYPTO LIBRARY")}
            </span>
            <span style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "6px 12px", borderRadius: 999, fontSize: 10.5, fontWeight: 700, color: networkStatus === "ok" ? C.greenFg : C.redFg, background: networkStatus === "ok" ? C.greenDim : C.redDim, border: `1px solid color-mix(in oklab, ${networkStatus === "ok" ? C.green : C.red} 30%, transparent)` }}>
              <GitBranch size={12} strokeWidth={2.4} /> {`CLUSTER ${fmtInt(clusterSummary.online_nodes)}/${fmtInt(clusterSummary.total_nodes)}`}
            </span>
          </div>
        </div>
      </div>

      {/* Pending Approvals Banner */}
      {Number(homeSummary?.myPendingApprovals || 0) > 0 && (
        <Card style={{ borderColor: C.amber, background: C.amberDim }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
              <Bell size={14} color={C.amber} />
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 11, color: C.text, fontWeight: 700, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                  {`You have ${fmtInt(homeSummary.myPendingApprovals)} pending approval${Number(homeSummary.myPendingApprovals) === 1 ? "" : "s"}.`}
                </div>
                <div style={{ fontSize: 10, color: C.dim }}>
                  {`Review below or open Governance > Approvals${homeSummary.approverIdentity ? ` as ${homeSummary.approverIdentity}` : ""}.`}
                </div>
              </div>
            </div>
            <B c="amber" pulse={true}>Action Required</B>
          </div>
        </Card>
      )}

      {/* KPI hero cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))", gap: 12 }}>
        <Kpi label="Total Keys" value={fmtInt(homeSummary.keys)} icon={KeyRound}
          color={C.accentFg} dim={C.accentDim} deltaIcon={TrendingUp} deltaColor={C.greenFg}
          delta={`+${fmtInt(homeSummary.keyGrowthWeek)} this week`}
          barPct={Math.min(100, Math.max(4, Number(homeSummary?.keys || 0) / 5))} />
        <Kpi label="Ops / Day" value={fmtCompact(homeSummary.opsPerDay)} icon={Zap}
          color={C.greenFg} dim={C.greenDim}
          deltaIcon={opsHasBaseline ? (opsGrowthPos ? TrendingUp : TrendingDown) : undefined}
          deltaColor={opsHasBaseline ? (opsGrowthPos ? C.greenFg : C.redFg) : C.dim}
          delta={opsHasBaseline ? `${Math.abs(Number(homeSummary.opsGrowthPct || 0)).toFixed(1)}% vs last week` : "No prior-week baseline yet"}
          barPct={62} />
        <Kpi label="Compliance" value={`${homeSummary.complianceScore}`} icon={ShieldCheck}
          color={C.blueFg} dim={C.blueDim}
          deltaIcon={complianceHasAssessment ? (complianceTrendPos ? TrendingUp : TrendingDown) : undefined}
          deltaColor={complianceHasAssessment ? (complianceTrendPos ? C.greenFg : C.redFg) : C.dim}
          delta={complianceHasAssessment ? `${homeSummary.complianceDeltaWeek >= 0 ? "+" : ""}${fmtInt(homeSummary.complianceDeltaWeek)} this week · score /100` : "No assessment yet"}
          barPct={Math.max(0, Math.min(100, Number(homeSummary?.complianceScore || 0)))} />
        <Kpi label="Open Alerts" value={fmtInt(homeSummary.alerts)} icon={Bell}
          color={Number(homeSummary?.criticalAlerts || 0) > 0 ? C.redFg : C.amberFg}
          dim={Number(homeSummary?.criticalAlerts || 0) > 0 ? C.redDim : C.amberDim}
          deltaIcon={alertTrendPos ? TrendingDown : TrendingUp}
          deltaColor={alertTrendPos ? C.greenFg : C.redFg}
          delta={`${fmtInt(homeSummary.criticalAlerts)} critical`}
          barPct={Math.min(100, Math.max(0, Number(homeSummary?.criticalAlerts || 0) * 10))} />
      </div>

      {/* Expiring Certificates Warning */}
      {Number(homeSummary?.expiring || 0) > 0 && (
        <Card style={{ borderColor: C.amber, background: C.amberDim }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <FileText size={14} color={C.amber} />
              <div>
                <div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>
                  {`${fmtInt(homeSummary.expiring)} certificate${Number(homeSummary.expiring) === 1 ? "" : "s"} expiring within ${fmtInt(homeSummary.alertDays || 30)} days`}
                </div>
                <div style={{ fontSize: 10, color: C.dim }}>Renew before expiry to avoid service disruption.</div>
              </div>
            </div>
            <Btn small onClick={() => onNavigate?.("certs")}>View Certificates →</Btn>
          </div>
        </Card>
      )}

      {/* Pinned Tab Widgets */}
      {pinnedList.length > 0 && (
        <div>
          <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 10, display: "flex", alignItems: "center", gap: 6 }}>
            <Lock size={10} color={C.muted} />
            Pinned Views
            <span style={{ marginLeft: "auto", fontSize: 9, color: C.dim }}>{`${pinnedList.length} pinned`}</span>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(190px,1fr))", gap: 10 }}>
            {pinnedList.map((tabId: string) => {
              const conf = WIDGET_CONF[tabId] || { icon: Settings, label: tabId, color: C.muted };
              const TabIcon = conf.icon;
              const primary = getWidgetPrimary(tabId);
              const secondary = getWidgetSecondary(tabId);
              const primaryColor = getWidgetPrimaryColor(tabId);
              return (
                <Card key={`pinned-${tabId}`}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                    <div style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                      <TabIcon size={11} color={conf.color} />
                      <span style={{ fontSize: 10, color: C.muted, letterSpacing: 0.5, textTransform: "uppercase", fontWeight: 600 }}>{conf.label}</span>
                    </div>
                    <button
                      onClick={() => onUnpinTab?.(tabId)}
                      title={`Unpin ${conf.label}`}
                      style={{ background: "transparent", border: "none", cursor: "pointer", color: C.muted, padding: 2, display: "flex", alignItems: "center", borderRadius: 4 }}
                    >
                      <X size={11} strokeWidth={2} />
                    </button>
                  </div>
                  <div style={{ fontSize: 24, fontWeight: 700, color: primaryColor, fontFamily: "'JetBrains Mono',monospace", lineHeight: 1.15, marginBottom: 4 }}>{primary}</div>
                  <div style={{ fontSize: 10, color: C.dim, marginBottom: 12 }}>{secondary}</div>
                  <button
                    onClick={() => onNavigate?.(tabId)}
                    style={{ display: "inline-flex", alignItems: "center", gap: 4, background: "transparent", border: `1px solid ${C.border}`, borderRadius: 6, padding: "4px 10px", cursor: "pointer", color: C.accent, fontSize: 10, fontWeight: 600, transition: "border-color .15s" }}
                  >
                    Open <ArrowRight size={10} strokeWidth={2} />
                  </button>
                </Card>
              );
            })}
          </div>
        </div>
      )}

      {/* Infrastructure Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(280px,1fr))", gap: 10 }}>
        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <div style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, color: C.muted, letterSpacing: 1, textTransform: "uppercase" }}>
              <Lock size={12} color={C.dim} />
              Disk Encryption
            </div>
            {statusPill("ACTIVE", "green", true)}
          </div>
          <div style={{ fontSize: 13, color: C.text, marginBottom: 8, fontFamily: "'JetBrains Mono',monospace" }}>AES-256-XTS | LUKS2 | RSA-4096</div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: C.dim, marginBottom: 6, fontFamily: "'JetBrains Mono',monospace" }}>
            <span>34.2 / 120 GB</span>
            <span>28.5%</span>
          </div>
          <div style={{ height: 7, borderRadius: 999, background: C.border, overflow: "hidden", marginBottom: 8 }}>
            <div style={{ height: "100%", width: "28.5%", background: C.accent, borderRadius: 999 }} />
          </div>
          <div style={{ fontSize: 11, color: C.green }}>Integrity passed | Recovery: 3-of-5</div>
        </Card>

        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <div style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, color: C.muted, letterSpacing: 1, textTransform: "uppercase" }}>
              <ShieldCheck size={12} color={C.dim} />
              FIPS Mode
            </div>
            {statusPill(globalFipsEnabled ? "STRICT" : "STANDARD", globalFipsEnabled ? "green" : "blue", true)}
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div>
              <div style={{ fontSize: 12, color: C.muted, marginBottom: 3 }}>Go Crypto</div>
              <div style={{ fontSize: 11, fontWeight: 700, color: C.text, lineHeight: 1.3, wordBreak: "break-word" }}>{cryptoLibraryLabel}</div>
              <div style={{ fontSize: 10, color: cryptoLibraryValidated ? C.green : C.amber, marginTop: 3 }}>{cryptoLibraryValidated ? "FIPS validated build" : "Non-validated build"}</div>
            </div>
            <div>
              <div style={{ fontSize: 12, color: C.muted, marginBottom: 3 }}>TLS</div>
              <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{String(homeSystemState?.fips_tls_profile || (globalFipsEnabled ? "1.2+ FIPS" : "Standard TLS"))}</div>
            </div>
            <div>
              <div style={{ fontSize: 12, color: C.muted, marginBottom: 3 }}>RNG</div>
              <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{String(homeSystemState?.fips_rng_mode || "CTR_DRBG")}</div>
            </div>
            <div>
              <div style={{ fontSize: 12, color: C.muted, marginBottom: 3 }}>Violations</div>
              <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{`${fmtInt(Number(homeSystemState?.fips_violations_24h || 0))} (24h)`}</div>
            </div>
          </div>
        </Card>

        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <div style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, color: C.muted, letterSpacing: 1, textTransform: "uppercase" }}>
              <Cloud size={12} color={C.dim} />
              Network
            </div>
            {statusPill(networkStatus === "ok" ? "OK" : "DEGRADED", statusTone(networkStatus), networkStatus !== "down")}
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <div><div style={{ fontSize: 12, color: C.muted, marginBottom: 3 }}>Mgmt</div><div style={{ fontSize: 12, fontWeight: 700, color: C.text, fontFamily: "'JetBrains Mono',monospace" }}>{String(homeSystemState?.mgmt_ip || "n/a")}</div></div>
            <div><div style={{ fontSize: 12, color: C.muted, marginBottom: 3 }}>Cluster</div><div style={{ fontSize: 12, fontWeight: 700, color: C.text, fontFamily: "'JetBrains Mono',monospace" }}>{String(homeSystemState?.cluster_ip || "n/a")}</div></div>
            <div><div style={{ fontSize: 12, color: C.muted, marginBottom: 3 }}>TLS</div><div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{String(homeSystemState?.tls_mode || "internal_ca")}</div></div>
            <div><div style={{ fontSize: 12, color: C.muted, marginBottom: 3 }}>HSM</div><div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{String(homeSystemState?.hsm_mode || "software")}</div></div>
          </div>
        </Card>
      </div>

      {/* Algorithm Distribution + Cluster + Approvals */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 10 }}>
        <Card>
          <div style={{ fontSize: 11, color: C.muted, letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>Algorithm Distribution</div>
          <div style={{ display: "grid", gap: 8 }}>
            {(algos.length ? algos : [{ name: "Other", pct: 100, color: C.muted }]).map((item: any) => {
              const pct = Math.max(0, Math.min(100, Number(item?.pct || 0)));
              return (
                <div key={`algo-${String(item?.name || "")}`} style={{ display: "grid", gridTemplateColumns: "130px 1fr 42px", alignItems: "center", gap: 10 }}>
                  <div style={{ fontSize: 11, color: C.text, textAlign: "right" }}>{String(item?.name || "-")}</div>
                  <div style={{ height: 10, borderRadius: 999, background: C.border, overflow: "hidden" }}>
                    <div style={{ height: "100%", width: `${pct}%`, background: String(item?.color || C.accent), borderRadius: 999, transition: "width .4s" }} />
                  </div>
                  <div style={{ fontSize: 11, color: String(item?.color || C.accent), fontWeight: 700, textAlign: "right" }}>{`${pct}%`}</div>
                </div>
              );
            })}
            {!algos.length && <div style={{ fontSize: 10, color: C.muted }}>No key algorithms available for distribution yet.</div>}
          </div>
        </Card>

        <div style={{ display: "grid", gap: 10 }}>
          <Card>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
              <div style={{ fontSize: 11, color: C.muted, letterSpacing: 1, textTransform: "uppercase" }}>Cluster</div>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                {Number(clusterSummary?.degraded_nodes || 0) > 0 && (
                  <span style={{ padding: "2px 6px", borderRadius: 999, background: C.amberDim, color: C.amber, fontSize: 9, fontWeight: 700 }}>
                    {`${fmtInt(clusterSummary.degraded_nodes)} degraded`}
                  </span>
                )}
                <B c={clusterSummary?.down_nodes > 0 ? "red" : clusterSummary?.degraded_nodes > 0 ? "amber" : "green"}>
                  {`${fmtInt(clusterSummary?.online_nodes || 0)}/${fmtInt(clusterSummary?.total_nodes || 0)}`}
                </B>
              </div>
            </div>
            <div style={{ display: "grid", gap: 6 }}>
              {nodes.map((node: any) => {
                const tone = statusTone(String(node?.status || "unknown"));
                const dotColor = (C as any)[tone] || C.blue;
                const pillBg = (C as any)[`${tone}Dim`] || C.blueDim;
                const roleColor = String(node?.role || "") === "leader" ? C.green : C.accent;
                const roleBg = String(node?.role || "") === "leader" ? C.greenDim : C.accentDim;
                return (
                  <div key={`cluster-${String(node?.id || node?.name || "node")}`} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 0", borderBottom: `1px solid ${C.border}` }}>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontSize: 12, color: C.text, display: "inline-flex", alignItems: "center", gap: 8 }}>
                        <span style={{ width: 9, height: 9, borderRadius: 999, background: dotColor, display: "inline-block", flexShrink: 0, animation: tone === "red" ? "none" : "pulse 1.8s infinite" }} />
                        <span style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 130 }}>{String(node?.name || node?.id || "node")}</span>
                        <span style={{ padding: "2px 6px", borderRadius: 999, background: pillBg, color: dotColor, fontSize: 9, fontWeight: 700, textTransform: "uppercase", whiteSpace: "nowrap" }}>{String(node?.status || "unknown")}</span>
                      </div>
                      <div style={{ fontSize: 9, color: C.dim, fontFamily: "'JetBrains Mono',monospace", marginTop: 2, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {String(node?.address || node?.endpoint || "n/a")}
                      </div>
                    </div>
                    <div style={{ padding: "3px 8px", borderRadius: 999, background: roleBg, color: roleColor, fontSize: 10, fontWeight: 700, display: "inline-flex", alignItems: "center", textTransform: "capitalize", whiteSpace: "nowrap", flexShrink: 0, marginLeft: 6 }}>
                      {String(node?.role || "follower")}
                    </div>
                  </div>
                );
              })}
            </div>
            <div style={{ fontSize: 10, color: C.dim, marginTop: 10, fontFamily: "'JetBrains Mono',monospace" }}>
              {`Lag: ${clusterLagText} | Nodes: ${fmtInt(clusterSummary.total_nodes)} | Quorum: ${fmtInt(clusterSummary.online_nodes)}/${fmtInt(clusterSummary.total_nodes)}`}
            </div>
          </Card>

          <Card>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <div style={{ fontSize: 11, color: C.muted, letterSpacing: 1, textTransform: "uppercase" }}>My Pending Approvals</div>
              <B c={Number(homeSummary?.myPendingApprovals || 0) > 0 ? "amber" : "green"} pulse={Number(homeSummary?.myPendingApprovals || 0) > 0}>
                {fmtInt(homeSummary?.myPendingApprovals || 0)}
              </B>
            </div>
            <div style={{ display: "grid", gap: 8 }}>
              {pending.slice(0, 4).map((item: any) => {
                const reqID = String(item?.id || "");
                return (
                  <div key={`home-approval-${reqID}`} style={{ border: `1px solid ${C.border}`, borderRadius: 8, padding: 8 }}>
                    <div style={{ fontSize: 10, color: C.text, fontWeight: 700, marginBottom: 3 }}>
                      {String(item?.action || "approval").replace(/^key\./, "").replaceAll("_", " ")}
                    </div>
                    <div style={{ fontSize: 9, color: C.dim, marginBottom: 6 }}>
                      {`Target: ${String(item?.target_id || "-")} | Votes ${Number(item?.current_approvals || 0)}/${Number(item?.required_approvals || 1)}`}
                    </div>
                    <div style={{ display: "flex", gap: 6 }}>
                      <Btn small primary onClick={() => void submitHomeApprovalVote(item, "approved")} disabled={approvalVoteBusy === `${reqID}:approved` || approvalVoteBusy === `${reqID}:denied` || homeLoading}>Approve</Btn>
                      <Btn small danger onClick={() => void submitHomeApprovalVote(item, "denied")} disabled={approvalVoteBusy === `${reqID}:approved` || approvalVoteBusy === `${reqID}:denied` || homeLoading}>Deny</Btn>
                    </div>
                  </div>
                );
              })}
              {!pending.length && <div style={{ fontSize: 10, color: C.muted }}>No pending approvals assigned to this user.</div>}
            </div>
          </Card>
        </div>
      </div>

      {promptUI}
    </div>
  );
};
