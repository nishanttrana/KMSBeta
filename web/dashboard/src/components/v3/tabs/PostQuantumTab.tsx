// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { useEffect, useMemo, useState } from "react";
import {
  getPQCInventory,
  getPQCMigrationReport,
  getPQCPolicy,
  runPQCScan,
  updatePQCPolicy
} from "../../../lib/pqc";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, Chk, FG, Inp, Row2, Section, Sel, Stat, Tabs } from "../legacyPrimitives";

const DEFAULT_POLICY = {
  tenant_id: "",
  profile_id: "balanced_hybrid",
  default_kem: "ML-KEM-768",
  default_signature: "ML-DSA-65",
  interface_default_mode: "hybrid",
  certificate_default_mode: "hybrid",
  hqc_backup_enabled: true,
  flag_classical_usage: true,
  flag_classical_certificates: true,
  flag_non_migrated_interfaces: true,
  require_pqc_for_new_keys: false
};

function pctLabel(value: any): string {
  const n = Number(value || 0);
  return `${Math.max(0, Math.min(100, n)).toFixed(1)}%`;
}

function fmtDate(value: any): string {
  const raw = String(value || "").trim();
  if (!raw) return "-";
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return raw;
  return dt.toLocaleString();
}

function topEntries(record: Record<string, number> | undefined, limit = 8): Array<[string, number]> {
  return Object.entries(record || {})
    .sort((a, b) => Number(b[1] || 0) - Number(a[1] || 0))
    .slice(0, limit);
}

export const PostQuantumTab = ({ session, onToast }: any) => {
  const [view, setView] = useState("Overview");
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [policy, setPolicy] = useState<any>(DEFAULT_POLICY);
  const [inventory, setInventory] = useState<any>(null);
  const [report, setReport] = useState<any>(null);

  const refresh = async (silent = false) => {
    if (!session?.token) {
      setPolicy(DEFAULT_POLICY);
      setInventory(null);
      setReport(null);
      return;
    }
    if (!silent) setLoading(true);
    try {
      const [nextPolicy, nextInventory, nextReport] = await Promise.all([
        getPQCPolicy(session),
        getPQCInventory(session),
        getPQCMigrationReport(session)
      ]);
      setPolicy({ ...DEFAULT_POLICY, ...(nextPolicy || {}), tenant_id: session.tenantId });
      setInventory(nextInventory || null);
      setReport(nextReport || null);
    } catch (error) {
      onToast?.(`Post-Quantum Crypto load failed: ${errMsg(error)}`);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    void refresh(false);
  }, [session?.tenantId, session?.token]);

  const summaryCards = [
    { label: "Quantum Readiness", value: `${Number(inventory?.readiness_score || 0)}/100`, sub: pctLabel(inventory?.quantum_readiness_percent || 0), color: "accent" },
    { label: "Keys Migrated", value: `${Number(inventory?.keys?.pqc_only || 0)}`, sub: `${Number(inventory?.keys?.hybrid || 0)} hybrid`, color: "green" },
    { label: "Certificates", value: `${Number(inventory?.certificates?.pqc_only || 0)}`, sub: `${Number(inventory?.non_migrated_certificates?.length || 0)} non-migrated`, color: "blue" },
    { label: "Interfaces", value: `${Number(inventory?.interfaces?.pqc_only || 0)}`, sub: `${Number(inventory?.non_migrated_interfaces?.length || 0)} non-migrated`, color: "purple" },
    { label: "Policy", value: String(policy?.profile_id || "balanced_hybrid").replaceAll("_", " "), sub: String(policy?.default_signature || "ML-DSA-65"), color: "amber" }
  ];

  const savePolicy = async () => {
    if (!session?.token) return;
    setSaving(true);
    try {
      const saved = await updatePQCPolicy(session, {
        ...policy,
        tenant_id: session.tenantId,
        updated_by: session.username
      });
      setPolicy({ ...DEFAULT_POLICY, ...(saved || {}), tenant_id: session.tenantId });
      onToast?.("Post-Quantum Crypto policy saved");
      await refresh(true);
    } catch (error) {
      onToast?.(`PQC policy save failed: ${errMsg(error)}`);
    } finally {
      setSaving(false);
    }
  };

  const scanNow = async () => {
    if (!session?.token) return;
    setScanning(true);
    try {
      await runPQCScan(session, "manual");
      onToast?.("PQC readiness scan completed");
      await refresh(true);
    } catch (error) {
      onToast?.(`PQC scan failed: ${errMsg(error)}`);
    } finally {
      setScanning(false);
    }
  };

  const keyAlgoTop = useMemo(() => topEntries(inventory?.keys?.algorithms), [inventory?.keys?.algorithms]);
  const certAlgoTop = useMemo(() => topEntries(inventory?.certificates?.algorithms), [inventory?.certificates?.algorithms]);

  return <div style={{ display: "grid", gap: 10 }}>
    <Section
      title="Post-Quantum Crypto"
      actions={<div style={{ display: "flex", gap: 8 }}>
        <Btn small onClick={() => void refresh(false)} disabled={loading}>{loading ? "Refreshing..." : "Refresh"}</Btn>
        <Btn small onClick={() => void scanNow()} disabled={scanning}>{scanning ? "Scanning..." : "Run Scan"}</Btn>
        <Btn small primary onClick={() => void savePolicy()} disabled={saving}>{saving ? "Saving..." : "Save Policy"}</Btn>
      </div>}
    >
      <div style={{ fontSize: 11, color: C.dim, marginBottom: 14 }}>
        Production PQC controls for ML-KEM, ML-DSA, SLH-DSA, hybrid TLS posture, migration readiness, and certificate/interface drift. This tab reads live state from the dedicated PQC service and cross-checks key inventory, request-handling interfaces, and certificate classes together.
      </div>

      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 16 }}>
        {summaryCards.map((item) => <Stat key={item.label} l={item.label} v={item.value} s={item.sub} c={item.color} />)}
      </div>

      <Tabs tabs={["Overview", "Policy", "Migration Report"]} active={view} onChange={setView} />

      {view === "Overview" && <div style={{ display: "grid", gap: 10, marginTop: 12 }}>
        <Row2>
          <Card style={{ padding: 12, borderRadius: 10 }}>
            <div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginBottom: 10 }}>Inventory Breakdown</div>
            <div style={{ display: "grid", gap: 8 }}>
              {[
                ["Keys", inventory?.keys],
                ["Certificates", inventory?.certificates],
                ["Interfaces", inventory?.interfaces]
              ].map(([label, item]: any) => (
                <div key={label} style={{ border: `1px solid ${C.border}`, borderRadius: 10, padding: "10px 12px", background: C.bg }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 10, marginBottom: 8 }}>
                    <div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>{label}</div>
                    <div style={{ fontSize: 10, color: C.muted }}>{`${Number(item?.total || 0)} total`}</div>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
                    <div><div style={{ fontSize: 8, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>Classical</div><div style={{ fontSize: 15, color: C.red, fontWeight: 800 }}>{Number(item?.classical || 0)}</div></div>
                    <div><div style={{ fontSize: 8, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>Hybrid</div><div style={{ fontSize: 15, color: C.amber, fontWeight: 800 }}>{Number(item?.hybrid || 0)}</div></div>
                    <div><div style={{ fontSize: 8, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>PQC-Only</div><div style={{ fontSize: 15, color: C.green, fontWeight: 800 }}>{Number(item?.pqc_only || 0)}</div></div>
                  </div>
                </div>
              ))}
            </div>
          </Card>

          <Card style={{ padding: 12, borderRadius: 10 }}>
            <div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginBottom: 10 }}>Top Algorithms Still in Use</div>
            <div style={{ display: "grid", gap: 8 }}>
              <div>
                <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Keys</div>
                {keyAlgoTop.map(([name, count]) => <div key={`k-${name}`} style={{ display: "flex", justifyContent: "space-between", gap: 10, padding: "5px 0", borderBottom: `1px solid ${C.border}` }}><span style={{ fontSize: 10, color: C.text }}>{name}</span><span style={{ fontSize: 10, color: C.muted }}>{count}</span></div>)}
                {!keyAlgoTop.length && <div style={{ fontSize: 10, color: C.muted }}>No key inventory yet.</div>}
              </div>
              <div>
                <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 6 }}>Certificates</div>
                {certAlgoTop.map(([name, count]) => <div key={`c-${name}`} style={{ display: "flex", justifyContent: "space-between", gap: 10, padding: "5px 0", borderBottom: `1px solid ${C.border}` }}><span style={{ fontSize: 10, color: C.text }}>{name}</span><span style={{ fontSize: 10, color: C.muted }}>{count}</span></div>)}
                {!certAlgoTop.length && <div style={{ fontSize: 10, color: C.muted }}>No certificate inventory yet.</div>}
              </div>
            </div>
          </Card>
        </Row2>

        <Card style={{ padding: 12, borderRadius: 10 }}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "center", marginBottom: 10 }}>
            <div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>Where RSA / ECC Is Still Active</div>
            <B c={Number(inventory?.classical_usage?.length || 0) > 0 ? "amber" : "green"}>{`${Number(inventory?.classical_usage?.length || 0)} assets`}</B>
          </div>
          <div style={{ display: "grid", gap: 6 }}>
            {(inventory?.classical_usage || []).slice(0, 12).map((item: any) => (
              <div key={`${item.asset_type}-${item.asset_id}`} style={{ display: "grid", gridTemplateColumns: "1.1fr 0.9fr 0.8fr 0.7fr 1.8fr", gap: 8, padding: "8px 0", borderBottom: `1px solid ${C.border}` }}>
                <div><div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{item.name}</div><div style={{ fontSize: 9, color: C.muted }}>{item.asset_type}</div></div>
                <div style={{ fontSize: 10, color: C.text }}>{item.algorithm}</div>
                <div style={{ fontSize: 10, color: C.muted }}>{item.location}</div>
                <div style={{ fontSize: 10, color: C.amber }}>{Number(item.qsl_score || 0).toFixed(1)}</div>
                <div style={{ fontSize: 10, color: C.dim }}>{item.reason}</div>
              </div>
            ))}
            {!(inventory?.classical_usage || []).length && <div style={{ fontSize: 10, color: C.muted }}>No classical RSA/ECC usage is currently flagged.</div>}
          </div>
        </Card>

        <Row2>
          <Card style={{ padding: 12, borderRadius: 10 }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "center", marginBottom: 10 }}>
              <div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>Non-Migrated Interfaces</div>
              <B c={Number(inventory?.non_migrated_interfaces?.length || 0) > 0 ? "amber" : "green"}>{Number(inventory?.non_migrated_interfaces?.length || 0)}</B>
            </div>
            <div style={{ display: "grid", gap: 6 }}>
              {(inventory?.non_migrated_interfaces || []).slice(0, 8).map((item: any) => (
                <div key={`${item.interface_name}-${item.port}`} style={{ padding: "8px 0", borderBottom: `1px solid ${C.border}` }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                    <span style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{item.interface_name}</span>
                    <span style={{ fontSize: 10, color: C.red }}>{item.effective_pqc_mode}</span>
                  </div>
                  <div style={{ fontSize: 9, color: C.dim, marginTop: 2 }}>{`${item.protocol.toUpperCase()} ${item.bind_address}:${item.port}`}</div>
                </div>
              ))}
              {!(inventory?.non_migrated_interfaces || []).length && <div style={{ fontSize: 10, color: C.muted }}>All exposed interfaces are aligned with the active PQC policy.</div>}
            </div>
          </Card>

          <Card style={{ padding: 12, borderRadius: 10 }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "center", marginBottom: 10 }}>
              <div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>Non-Migrated Certificates</div>
              <B c={Number(inventory?.non_migrated_certificates?.length || 0) > 0 ? "amber" : "green"}>{Number(inventory?.non_migrated_certificates?.length || 0)}</B>
            </div>
            <div style={{ display: "grid", gap: 6 }}>
              {(inventory?.non_migrated_certificates || []).slice(0, 8).map((item: any) => (
                <div key={item.cert_id} style={{ padding: "8px 0", borderBottom: `1px solid ${C.border}` }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                    <span style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{item.subject_cn}</span>
                    <span style={{ fontSize: 10, color: C.red }}>{item.algorithm}</span>
                  </div>
                  <div style={{ fontSize: 9, color: C.dim, marginTop: 2 }}>{`${item.status || "active"}${item.not_after ? ` · exp ${fmtDate(item.not_after)}` : ""}`}</div>
                </div>
              ))}
              {!(inventory?.non_migrated_certificates || []).length && <div style={{ fontSize: 10, color: C.muted }}>Certificate inventory is already hybrid/PQC-classified.</div>}
            </div>
          </Card>
        </Row2>
      </div>}

      {view === "Policy" && <div style={{ display: "grid", gap: 10, marginTop: 12 }}>
        <Row2>
          <FG label="PQC Policy Profile">
            <Sel value={String(policy?.profile_id || "balanced_hybrid")} onChange={(e) => setPolicy((p: any) => ({ ...p, profile_id: String(e.target.value || "balanced_hybrid") }))}>
              <option value="balanced_hybrid">Balanced Hybrid</option>
              <option value="quantum_first">Quantum First</option>
              <option value="signing_first">Signing First</option>
              <option value="compliance_accelerated">Compliance Accelerated</option>
            </Sel>
          </FG>
          <FG label="Default KEM">
            <Sel value={String(policy?.default_kem || "ML-KEM-768")} onChange={(e) => setPolicy((p: any) => ({ ...p, default_kem: String(e.target.value || "ML-KEM-768") }))}>
              <option value="ML-KEM-768">ML-KEM-768</option>
              <option value="ML-KEM-1024">ML-KEM-1024</option>
            </Sel>
          </FG>
        </Row2>
        <Row2>
          <FG label="Default Signature">
            <Sel value={String(policy?.default_signature || "ML-DSA-65")} onChange={(e) => setPolicy((p: any) => ({ ...p, default_signature: String(e.target.value || "ML-DSA-65") }))}>
              <option value="ML-DSA-65">ML-DSA-65</option>
              <option value="ML-DSA-87">ML-DSA-87</option>
              <option value="SLH-DSA-SHAKE-256F">SLH-DSA-SHAKE-256F</option>
            </Sel>
          </FG>
          <FG label="Certificate Default Mode">
            <Sel value={String(policy?.certificate_default_mode || "hybrid")} onChange={(e) => setPolicy((p: any) => ({ ...p, certificate_default_mode: String(e.target.value || "hybrid") }))}>
              <option value="classical">Classical</option>
              <option value="hybrid">Hybrid</option>
              <option value="pqc_only">PQC Only</option>
            </Sel>
          </FG>
        </Row2>
        <Row2>
          <FG label="Interface Default Mode">
            <Sel value={String(policy?.interface_default_mode || "hybrid")} onChange={(e) => setPolicy((p: any) => ({ ...p, interface_default_mode: String(e.target.value || "hybrid") }))}>
              <option value="classical">Classical</option>
              <option value="hybrid">Hybrid</option>
              <option value="pqc_only">PQC Only</option>
            </Sel>
          </FG>
          <FG label="Last Update">
            <Inp value={fmtDate(policy?.updated_at)} readOnly />
          </FG>
        </Row2>
        <Card style={{ padding: 12, borderRadius: 10 }}>
          <div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginBottom: 8 }}>Migration Guardrails</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8 }}>
            <Chk label="Track classical RSA / ECC usage" checked={Boolean(policy?.flag_classical_usage)} onChange={() => setPolicy((p: any) => ({ ...p, flag_classical_usage: !Boolean(p?.flag_classical_usage) }))} />
            <Chk label="Track classical certificates" checked={Boolean(policy?.flag_classical_certificates)} onChange={() => setPolicy((p: any) => ({ ...p, flag_classical_certificates: !Boolean(p?.flag_classical_certificates) }))} />
            <Chk label="Flag non-migrated interfaces" checked={Boolean(policy?.flag_non_migrated_interfaces)} onChange={() => setPolicy((p: any) => ({ ...p, flag_non_migrated_interfaces: !Boolean(p?.flag_non_migrated_interfaces) }))} />
            <Chk label="Require PQC for new keys" checked={Boolean(policy?.require_pqc_for_new_keys)} onChange={() => setPolicy((p: any) => ({ ...p, require_pqc_for_new_keys: !Boolean(p?.require_pqc_for_new_keys) }))} />
            <Chk label="Track HQC backup KEM path" checked={Boolean(policy?.hqc_backup_enabled)} onChange={() => setPolicy((p: any) => ({ ...p, hqc_backup_enabled: !Boolean(p?.hqc_backup_enabled) }))} />
          </div>
          <div style={{ fontSize: 10, color: C.dim, marginTop: 8 }}>
            Interface overrides are configured in Administration -&gt; Interfaces. Choosing `inherit` there causes those listeners to follow the tenant default mode from this policy.
          </div>
        </Card>
      </div>}

      {view === "Migration Report" && <div style={{ display: "grid", gap: 10, marginTop: 12 }}>
        <Row2>
          <Card style={{ padding: 12, borderRadius: 10 }}>
            <div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginBottom: 10 }}>Latest Readiness Scan</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
              <Stat l="Score" v={String(report?.latest_readiness?.readiness_score || 0)} c="accent" />
              <Stat l="Assets" v={String(report?.latest_readiness?.total_assets || 0)} c="blue" />
              <Stat l="Avg QSL" v={String(report?.latest_readiness?.average_qsl || 0)} c="green" />
            </div>
            <div style={{ fontSize: 10, color: C.dim, marginTop: 8 }}>{`Completed ${fmtDate(report?.latest_readiness?.completed_at || report?.generated_at)}`}</div>
          </Card>
          <Card style={{ padding: 12, borderRadius: 10 }}>
            <div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginBottom: 10 }}>Timeline</div>
            <div style={{ display: "grid", gap: 8 }}>
              {(report?.timeline || []).slice(0, 5).map((item: any) => (
                <div key={item.id} style={{ borderBottom: `1px solid ${C.border}`, paddingBottom: 8 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                    <span style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{item.title}</span>
                    <span style={{ fontSize: 10, color: item.status === "on_track" ? C.green : item.status === "in_progress" ? C.accent : C.amber }}>{item.status}</span>
                  </div>
                  <div style={{ fontSize: 9, color: C.dim, marginTop: 2 }}>{`${fmtDate(item.due_date)} · ${Number(item.days_left || 0)} days left`}</div>
                </div>
              ))}
            </div>
          </Card>
        </Row2>

        <Card style={{ padding: 12, borderRadius: 10 }}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "center", marginBottom: 10 }}>
            <div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>Top Migration Risks</div>
            <B c={Number(report?.top_risks?.length || 0) > 0 ? "amber" : "green"}>{Number(report?.top_risks?.length || 0)}</B>
          </div>
          <div style={{ display: "grid", gap: 6 }}>
            {(report?.top_risks || []).map((item: any) => (
              <div key={`${item.asset_type}-${item.asset_id}`} style={{ display: "grid", gridTemplateColumns: "1.1fr 0.9fr 0.6fr 0.9fr 1.3fr", gap: 8, padding: "8px 0", borderBottom: `1px solid ${C.border}` }}>
                <div><div style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{item.name}</div><div style={{ fontSize: 9, color: C.muted }}>{item.asset_type}</div></div>
                <div style={{ fontSize: 10, color: C.text }}>{item.algorithm}</div>
                <div style={{ fontSize: 10, color: C.amber }}>{item.priority}</div>
                <div style={{ fontSize: 10, color: C.blue }}>{item.migration_target}</div>
                <div style={{ fontSize: 10, color: C.dim }}>{item.reason}</div>
              </div>
            ))}
            {!(report?.top_risks || []).length && <div style={{ fontSize: 10, color: C.muted }}>No migration risks are currently reported.</div>}
          </div>
        </Card>

        <Card style={{ padding: 12, borderRadius: 10 }}>
          <div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginBottom: 10 }}>Recommended Next Actions</div>
          <div style={{ display: "grid", gap: 8 }}>
            {(report?.next_actions || []).map((item: any, idx: number) => (
              <div key={`${idx}-${item}`} style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
                <span style={{ fontSize: 10, color: C.accent, marginTop: 1 }}>•</span>
                <span style={{ fontSize: 10, color: C.dim }}>{String(item || "")}</span>
              </div>
            ))}
            {!(report?.next_actions || []).length && <div style={{ fontSize: 10, color: C.muted }}>No next actions generated yet.</div>}
          </div>
        </Card>
      </div>}
    </Section>
  </div>;
};

export default PostQuantumTab;
