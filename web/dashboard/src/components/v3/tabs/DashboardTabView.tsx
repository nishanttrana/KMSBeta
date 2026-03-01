import { Bell, Cloud, KeyRound, Lock, ShieldCheck, Zap } from "lucide-react";
import { B, Btn, Card, FG, Modal } from "../legacyPrimitives";
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
    promptUI
  } = props || {};

  const pending = Array.isArray(homeSummary?.pendingApprovals) ? homeSummary.pendingApprovals : [];
  const algos = Array.isArray(homeSummary?.algorithms) ? homeSummary.algorithms : [];
  const nodes = clusterNodes.length ? clusterNodes : [{ id: "local", name: "vecta-kms-01", status: "online", role: "leader", address: "127.0.0.1" }];

  return <div style={{ display: "grid", gap: 12 }}>
    {Number(homeSummary?.myPendingApprovals || 0) > 0 && <Card style={{ borderColor: C.amber, background: C.amberDim }}>
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
    </Card>}

    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(210px,1fr))", gap: 10 }}>
      <Card>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ fontSize: 11, color: C.muted, letterSpacing: 1, textTransform: "uppercase" }}>Total Keys</div>
          <KeyRound size={13} color={C.dim} />
        </div>
        <div style={{ fontSize: 30, fontWeight: 700, color: C.accent, lineHeight: 1.08, marginTop: 6, fontFamily: "'JetBrains Mono',monospace" }}>{fmtInt(homeSummary.keys)}</div>
        <div style={{ fontSize: 10, color: C.dim, marginTop: 6 }}>{`+${fmtInt(homeSummary.keyGrowthWeek)} this week`}</div>
      </Card>
      <Card>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ fontSize: 11, color: C.muted, letterSpacing: 1, textTransform: "uppercase" }}>Ops/Day</div>
          <Zap size={13} color={C.dim} />
        </div>
        <div style={{ fontSize: 30, fontWeight: 700, color: C.green, lineHeight: 1.08, marginTop: 6, fontFamily: "'JetBrains Mono',monospace" }}>{fmtCompact(homeSummary.opsPerDay)}</div>
        <div style={{ fontSize: 10, color: C.dim, marginTop: 6 }}>{`${Number(homeSummary.opsGrowthPct || 0).toFixed(1)}%`}</div>
      </Card>
      <Card>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ fontSize: 11, color: C.muted, letterSpacing: 1, textTransform: "uppercase" }}>Compliance</div>
          <ShieldCheck size={13} color={C.dim} />
        </div>
        <div style={{ fontSize: 30, fontWeight: 700, color: C.blue, lineHeight: 1.08, marginTop: 6, fontFamily: "'JetBrains Mono',monospace" }}>{`${homeSummary.complianceScore}/100`}</div>
        <div style={{ fontSize: 10, color: C.dim, marginTop: 6 }}>{`+${fmtInt(homeSummary.complianceDeltaWeek)} this week`}</div>
      </Card>
      <Card>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ fontSize: 11, color: C.muted, letterSpacing: 1, textTransform: "uppercase" }}>Alerts</div>
          <Bell size={13} color={C.dim} />
        </div>
        <div style={{ fontSize: 30, fontWeight: 700, color: C.red, lineHeight: 1.08, marginTop: 6, fontFamily: "'JetBrains Mono',monospace" }}>{fmtInt(homeSummary.alerts)}</div>
        <div style={{ fontSize: 10, color: C.dim, marginTop: 6 }}>{`${fmtInt(homeSummary.criticalAlerts)} critical`}</div>
      </Card>
    </div>

    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(280px,1fr))", gap: 10 }}>
      <Card onClick={() => setModal?.("fde")}>
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
          <div><div style={{ fontSize: 12, color: C.muted, marginBottom: 3 }}>TLS</div><div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{String(homeSystemState?.tls_cert_mode || "internal_ca")}</div></div>
          <div><div style={{ fontSize: 12, color: C.muted, marginBottom: 3 }}>HSM</div><div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{String(homeSystemState?.hsm_mode || "software")}</div></div>
        </div>
      </Card>
    </div>

    <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 10 }}>
      <Card>
        <div style={{ fontSize: 11, color: C.muted, letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>Algorithm Distribution</div>
        <div style={{ display: "grid", gap: 8 }}>
          {(algos.length ? algos : [{ name: "Other", pct: 100, color: C.muted }]).map((item: any) => {
            const pct = Math.max(0, Math.min(100, Number(item?.pct || 0)));
            return <div key={`algo-${String(item?.name || "")}`} style={{ display: "grid", gridTemplateColumns: "130px 1fr 42px", alignItems: "center", gap: 10 }}>
              <div style={{ fontSize: 11, color: C.text, textAlign: "right" }}>{String(item?.name || "-")}</div>
              <div style={{ height: 10, borderRadius: 999, background: C.border, overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${pct}%`, background: String(item?.color || C.accent), borderRadius: 999, transition: "width .3s" }} />
              </div>
              <div style={{ fontSize: 11, color: String(item?.color || C.accent), fontWeight: 700, textAlign: "right" }}>{`${pct}%`}</div>
            </div>;
          })}
          {!algos.length ? <div style={{ fontSize: 10, color: C.muted }}>No key algorithms available for distribution yet.</div> : null}
        </div>
      </Card>

      <div style={{ display: "grid", gap: 10 }}>
        <Card>
          <div style={{ fontSize: 11, color: C.muted, letterSpacing: 1, textTransform: "uppercase", marginBottom: 10 }}>Cluster</div>
          <div style={{ display: "grid", gap: 6 }}>
            {nodes.map((node: any) => {
              const tone = statusTone(String(node?.status || "unknown"));
              const dotColor = (C as any)[tone] || C.blue;
              const pillBg = (C as any)[`${tone}Dim`] || C.blueDim;
              const roleColor = String(node?.role || "") === "leader" ? C.green : C.accent;
              const roleBg = String(node?.role || "") === "leader" ? C.greenDim : C.accentDim;
              return <div key={`cluster-${String(node?.id || node?.name || "node")}`} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 0", borderBottom: `1px solid ${C.border}` }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 12, color: C.text, display: "inline-flex", alignItems: "center", gap: 8 }}>
                    <span style={{ width: 9, height: 9, borderRadius: 999, background: dotColor, display: "inline-block", animation: tone === "red" ? "none" : "pulse 1.8s infinite" }} />
                    <span style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 170 }}>{String(node?.name || node?.id || "node")}</span>
                    <span style={{ padding: "2px 6px", borderRadius: 999, background: pillBg, color: dotColor, fontSize: 9, fontWeight: 700, textTransform: "uppercase" }}>{String(node?.status || "unknown")}</span>
                  </div>
                  <div style={{ fontSize: 9, color: C.dim, fontFamily: "'JetBrains Mono',monospace", marginTop: 2, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                    {String(node?.address || node?.endpoint || "n/a")}
                  </div>
                </div>
                <div style={{ padding: "3px 8px", borderRadius: 999, background: roleBg, color: roleColor, fontSize: 10, fontWeight: 700, display: "inline-flex", alignItems: "center", textTransform: "capitalize" }}>
                  {String(node?.role || "follower")}
                </div>
              </div>;
            })}
          </div>
          <div style={{ fontSize: 10, color: C.dim, marginTop: 10, fontFamily: "'JetBrains Mono',monospace" }}>
            {`Lag: ${clusterLagText} | Nodes: ${fmtInt(clusterSummary.total_nodes)} | Quorum: ${fmtInt(clusterSummary.online_nodes)}/${fmtInt(clusterSummary.total_nodes)}`}
          </div>
        </Card>

        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <div style={{ fontSize: 11, color: C.muted, letterSpacing: 1, textTransform: "uppercase" }}>My Pending Approvals</div>
            <B c={Number(homeSummary?.myPendingApprovals || 0) > 0 ? "amber" : "green"} pulse={Number(homeSummary?.myPendingApprovals || 0) > 0}>{fmtInt(homeSummary?.myPendingApprovals || 0)}</B>
          </div>
          <div style={{ display: "grid", gap: 8 }}>
            {pending.slice(0, 4).map((item: any) => {
              const reqID = String(item?.id || "");
              return <div key={`home-approval-${reqID}`} style={{ border: `1px solid ${C.border}`, borderRadius: 8, padding: 8 }}>
                <div style={{ fontSize: 10, color: C.text, fontWeight: 700, marginBottom: 3 }}>{String(item?.action || "approval").replace(/^key\./, "").replaceAll("_", " ")}</div>
                <div style={{ fontSize: 9, color: C.dim, marginBottom: 6 }}>{`Target: ${String(item?.target_id || "-")} | Votes ${Number(item?.current_approvals || 0)}/${Number(item?.required_approvals || 1)}`}</div>
                <div style={{ display: "flex", gap: 6 }}>
                  <Btn small primary onClick={() => void submitHomeApprovalVote(item, "approved")} disabled={approvalVoteBusy === `${reqID}:approved` || approvalVoteBusy === `${reqID}:denied` || homeLoading}>Approve</Btn>
                  <Btn small danger onClick={() => void submitHomeApprovalVote(item, "denied")} disabled={approvalVoteBusy === `${reqID}:approved` || approvalVoteBusy === `${reqID}:denied` || homeLoading}>Deny</Btn>
                </div>
              </div>;
            })}
            {!pending.length ? <div style={{ fontSize: 10, color: C.muted }}>No pending approvals assigned to this user.</div> : null}
          </div>
        </Card>
      </div>
    </div>

    <Modal open={modal === "fde"} onClose={() => setModal?.(null)} title="Full Disk Encryption Management">
      <FG label="Encryption"><div style={{ fontSize: 11, color: C.green }}>AES-256-XTS via LUKS2 - Active</div></FG>
      <FG label="Actions"><Btn small>Run Integrity Check</Btn><Btn small style={{ marginLeft: 6 }}>Rotate Volume Key</Btn><Btn small style={{ marginLeft: 6 }}>Test Recovery Shares</Btn></FG>
      <FG label="Recovery Shares (Shamir 3-of-5)">
        <div style={{ fontSize: 10, color: C.dim }}>Share 1: Admin A | Share 2: Admin B | Share 3: Escrow | Share 4: Safe | Share 5: DR Site</div>
      </FG>
    </Modal>

    {promptUI}
  </div>;
};
