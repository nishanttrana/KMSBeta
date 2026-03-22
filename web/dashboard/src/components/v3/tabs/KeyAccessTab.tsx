// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import { B, Btn, Card, Chk, FG, Inp, Row2, Row3, Section, Sel, Stat, Tabs, Txt, usePromptDialog } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  deleteKeyAccessRule,
  getKeyAccessSettings,
  getKeyAccessSummary,
  listKeyAccessDecisions,
  listKeyAccessRules,
  updateKeyAccessSettings,
  upsertKeyAccessRule
} from "../../../lib/keyaccess";

function csvToList(value: any): string[] {
  return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
}

function listToCsv(value: any): string {
  return Array.isArray(value) ? value.map((item) => String(item || "").trim()).filter(Boolean).join(", ") : "";
}

function fmtTS(value: any): string {
  const raw = String(value || "").trim();
  if (!raw) return "-";
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return raw;
  return dt.toLocaleString();
}

const DEFAULT_SETTINGS = {
  enabled: false,
  mode: "enforce",
  default_action: "deny",
  require_justification_code: true,
  require_justification_text: false,
  approval_policy_id: ""
};

const DEFAULT_RULE = {
  id: "",
  code: "",
  label: "",
  description: "",
  action: "deny",
  services_csv: "cloud, ekm, hyok, keycore",
  operations_csv: "wrap, unwrap, sign, decrypt",
  require_text: false,
  approval_policy_id: "",
  enabled: true
};

export const KeyAccessTab = ({ session, onToast }: any) => {
  const promptDialog = usePromptDialog();
  const [tab, setTab] = useState("Overview");
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [summary, setSummary] = useState<any>(null);
  const [settingsDraft, setSettingsDraft] = useState<any>(DEFAULT_SETTINGS);
  const [rules, setRules] = useState<any[]>([]);
  const [ruleDraft, setRuleDraft] = useState<any>(DEFAULT_RULE);
  const [decisions, setDecisions] = useState<any[]>([]);
  const [decisionService, setDecisionService] = useState("");
  const [decisionAction, setDecisionAction] = useState("");

  const load = async (silent = false) => {
    if (!session?.token) {
      setSummary(null);
      setSettingsDraft(DEFAULT_SETTINGS);
      setRules([]);
      setDecisions([]);
      return;
    }
    if (!silent) setLoading(true);
    try {
      const [summaryOut, settingsOut, rulesOut, decisionsOut] = await Promise.all([
        getKeyAccessSummary(session),
        getKeyAccessSettings(session),
        listKeyAccessRules(session),
        listKeyAccessDecisions(session, { service: decisionService, action: decisionAction, limit: 100 })
      ]);
      setSummary(summaryOut || null);
      setSettingsDraft({ ...DEFAULT_SETTINGS, ...(settingsOut || {}) });
      setRules(Array.isArray(rulesOut) ? rulesOut : []);
      setDecisions(Array.isArray(decisionsOut) ? decisionsOut : []);
    } catch (error) {
      onToast?.(`Key access load failed: ${errMsg(error)}`);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => { void load(true); }, [session?.token, session?.tenantId, decisionService, decisionAction]);

  const saveSettings = async () => {
    setBusy(true);
    try {
      await updateKeyAccessSettings(session, { ...settingsDraft, tenant_id: session.tenantId, updated_by: session.username });
      onToast?.("Key access settings saved");
      await load(true);
    } catch (error) {
      onToast?.(`Key access settings save failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const saveRule = async () => {
    setBusy(true);
    try {
      await upsertKeyAccessRule(session, {
        id: ruleDraft?.id || undefined,
        tenant_id: session.tenantId,
        code: String(ruleDraft?.code || "").trim().toUpperCase(),
        label: String(ruleDraft?.label || "").trim(),
        description: String(ruleDraft?.description || "").trim(),
        action: ruleDraft?.action || "deny",
        services: csvToList(ruleDraft?.services_csv),
        operations: csvToList(ruleDraft?.operations_csv),
        require_text: Boolean(ruleDraft?.require_text),
        approval_policy_id: String(ruleDraft?.approval_policy_id || "").trim(),
        enabled: Boolean(ruleDraft?.enabled),
        updated_by: session.username
      });
      onToast?.("Key access rule saved");
      setRuleDraft(DEFAULT_RULE);
      await load(true);
    } catch (error) {
      onToast?.(`Key access rule save failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const editRule = (item: any) => {
    setRuleDraft({
      id: item?.id || "",
      code: item?.code || "",
      label: item?.label || "",
      description: item?.description || "",
      action: item?.action || "deny",
      services_csv: listToCsv(item?.services),
      operations_csv: listToCsv(item?.operations),
      require_text: Boolean(item?.require_text),
      approval_policy_id: item?.approval_policy_id || "",
      enabled: item?.enabled !== false
    });
    setTab("Justifications");
  };

  const removeRule = async (item: any) => {
    const ok = await promptDialog.confirm({ title: "Delete Justification Rule", message: `Delete ${String(item?.code || "").trim()}?`, danger: true, confirmLabel: "Delete" });
    if (!ok) return;
    setBusy(true);
    try {
      await deleteKeyAccessRule(session, String(item?.id || ""));
      onToast?.("Key access rule deleted");
      await load(true);
    } catch (error) {
      onToast?.(`Key access rule delete failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  const serviceRows = useMemo(() => Array.isArray(summary?.services) ? summary.services : [], [summary]);

  return (
    <div>
      {promptDialog.ui}
      <Section title="Key Access Justifications" actions={<div style={{ display: "flex", gap: 8 }}>
        <Btn small onClick={() => void load(false)} disabled={loading || busy}>{loading ? "Refreshing..." : "Refresh"}</Btn>
        <Btn small primary onClick={() => void saveSettings()} disabled={busy}>{busy ? "Saving..." : "Save Settings"}</Btn>
      </div>}>
        <Tabs tabs={["Overview", "Settings", "Justifications", "Decisions"]} active={tab} onChange={setTab} />
      </Section>

      {tab === "Overview" && <>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14 }}>
          <Stat l="Requests / 24h" v={summary?.total_requests_24h || 0} c="accent" />
          <Stat l="Denied" v={summary?.deny_count_24h || 0} c="red" />
          <Stat l="Approval" v={summary?.approval_count_24h || 0} c="amber" />
          <Stat l="Bypass" v={summary?.bypass_count_24h || 0} c="purple" />
          <Stat l="Unjustified" v={summary?.unjustified_count_24h || 0} c="orange" />
          <Stat l="Rules" v={summary?.rule_count || 0} c="blue" />
        </div>
        <Card style={{ padding: 14, marginBottom: 14 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
            <B c={summary?.enabled ? "green" : "amber"}>{summary?.enabled ? "Enabled" : "Disabled"}</B>
            <span style={{ fontSize: 11, color: C.text }}>{`Mode: ${String(summary?.mode || "enforce")}`}</span>
            <span style={{ fontSize: 11, color: C.dim }}>{`Default action: ${String(summary?.default_action || "deny")}`}</span>
          </div>
          <div style={{ fontSize: 11, color: C.dim, lineHeight: 1.6 }}>
            Require per-request justification codes for external wrap, unwrap, sign, and decrypt access. Use approval-backed codes for regulated flows, and watch the recent decision stream to catch bypasses or unsigned operator behavior before those turn into larger posture drift.
          </div>
        </Card>
        <Section title="Service Activity">
          <div style={{ display: "grid", gap: 8 }}>
            {serviceRows.map((item: any) => (
              <Card key={item.service} style={{ padding: 12 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, marginBottom: 8 }}>
                  <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{item.service}</div>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    <B c="blue">{`${item.requests_24h || 0} req`}</B>
                    <B c="red">{`${item.unjustified_count_24h || 0} unjustified`}</B>
                    <B c="amber">{`${item.bypass_count_24h || 0} bypass`}</B>
                  </div>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 8 }}>
                  <div><div style={{ fontSize: 9, color: C.muted }}>Allow</div><div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>{item.allow_count_24h || 0}</div></div>
                  <div><div style={{ fontSize: 9, color: C.muted }}>Deny</div><div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>{item.deny_count_24h || 0}</div></div>
                  <div><div style={{ fontSize: 9, color: C.muted }}>Approval</div><div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>{item.approval_count_24h || 0}</div></div>
                  <div><div style={{ fontSize: 9, color: C.muted }}>Bypass</div><div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>{item.bypass_count_24h || 0}</div></div>
                </div>
              </Card>
            ))}
            {!serviceRows.length ? <Card style={{ padding: 18, textAlign: "center", color: C.muted }}>No recent key access requests yet.</Card> : null}
          </div>
        </Section>
      </>}

      {tab === "Settings" && <Section title="Tenant Policy">
        <Card style={{ padding: 14 }}>
          <Row3>
            <FG label="Enabled"><Chk label="Enable key access justification policy" checked={Boolean(settingsDraft?.enabled)} onChange={() => setSettingsDraft((p: any) => ({ ...p, enabled: !Boolean(p?.enabled) }))} /></FG>
            <FG label="Mode">
              <Sel value={settingsDraft?.mode || "enforce"} onChange={(e) => setSettingsDraft((p: any) => ({ ...p, mode: e.target.value }))}>
                <option value="enforce">Enforce</option>
                <option value="audit">Audit</option>
              </Sel>
            </FG>
            <FG label="Default Action">
              <Sel value={settingsDraft?.default_action || "deny"} onChange={(e) => setSettingsDraft((p: any) => ({ ...p, default_action: e.target.value }))}>
                <option value="deny">Deny</option>
                <option value="allow">Allow</option>
                <option value="approval">Approval</option>
              </Sel>
            </FG>
          </Row3>
          <Row2>
            <Chk label="Require justification code" checked={Boolean(settingsDraft?.require_justification_code)} onChange={() => setSettingsDraft((p: any) => ({ ...p, require_justification_code: !Boolean(p?.require_justification_code) }))} />
            <Chk label="Require justification text" checked={Boolean(settingsDraft?.require_justification_text)} onChange={() => setSettingsDraft((p: any) => ({ ...p, require_justification_text: !Boolean(p?.require_justification_text) }))} />
          </Row2>
          <FG label="Default Approval Policy"><Inp value={settingsDraft?.approval_policy_id || ""} onChange={(e) => setSettingsDraft((p: any) => ({ ...p, approval_policy_id: e.target.value }))} placeholder="policy-high-assurance" /></FG>
        </Card>
      </Section>}

      {tab === "Justifications" && <Section title="Reason Codes" actions={<Btn small primary onClick={() => void saveRule()} disabled={busy}>{busy ? "Saving..." : "Save Rule"}</Btn>}>
        <Card style={{ padding: 14, marginBottom: 12 }}>
          <Row3>
            <FG label="Code"><Inp value={ruleDraft?.code || ""} onChange={(e) => setRuleDraft((p: any) => ({ ...p, code: e.target.value.toUpperCase() }))} placeholder="PAYMENT_ISO20022" /></FG>
            <FG label="Label"><Inp value={ruleDraft?.label || ""} onChange={(e) => setRuleDraft((p: any) => ({ ...p, label: e.target.value }))} placeholder="Payment signing for ISO 20022" /></FG>
            <FG label="Action">
              <Sel value={ruleDraft?.action || "deny"} onChange={(e) => setRuleDraft((p: any) => ({ ...p, action: e.target.value }))}>
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
                <option value="approval">Approval</option>
              </Sel>
            </FG>
          </Row3>
          <FG label="Description"><Txt rows={3} mono={false} value={ruleDraft?.description || ""} onChange={(e) => setRuleDraft((p: any) => ({ ...p, description: e.target.value }))} placeholder="Explain when this code is allowed and which workflow owns it." /></FG>
          <Row2>
            <FG label="Services"><Inp value={ruleDraft?.services_csv || ""} onChange={(e) => setRuleDraft((p: any) => ({ ...p, services_csv: e.target.value }))} placeholder="cloud, ekm, hyok, keycore" /></FG>
            <FG label="Operations"><Inp value={ruleDraft?.operations_csv || ""} onChange={(e) => setRuleDraft((p: any) => ({ ...p, operations_csv: e.target.value }))} placeholder="wrap, unwrap, sign, decrypt" /></FG>
          </Row2>
          <Row2>
            <Chk label="Require free-text explanation" checked={Boolean(ruleDraft?.require_text)} onChange={() => setRuleDraft((p: any) => ({ ...p, require_text: !Boolean(p?.require_text) }))} />
            <Chk label="Enabled" checked={Boolean(ruleDraft?.enabled)} onChange={() => setRuleDraft((p: any) => ({ ...p, enabled: !Boolean(p?.enabled) }))} />
          </Row2>
          <FG label="Approval Policy"><Inp value={ruleDraft?.approval_policy_id || ""} onChange={(e) => setRuleDraft((p: any) => ({ ...p, approval_policy_id: e.target.value }))} placeholder="policy-regulated-signing" /></FG>
        </Card>
        <div style={{ display: "grid", gap: 8 }}>
          {rules.map((item: any) => (
            <Card key={item.id} style={{ padding: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8, marginBottom: 8 }}>
                <div>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{item.code}</span>
                    <B c={item.enabled ? "green" : "red"}>{item.enabled ? "Enabled" : "Disabled"}</B>
                    <B c={item.action === "approval" ? "amber" : item.action === "allow" ? "green" : "red"}>{item.action}</B>
                  </div>
                  <div style={{ fontSize: 10, color: C.muted, marginTop: 4 }}>{item.label}</div>
                  {item.description ? <div style={{ fontSize: 10, color: C.dim, marginTop: 4 }}>{item.description}</div> : null}
                </div>
                <div style={{ display: "flex", gap: 6 }}>
                  <Btn small onClick={() => editRule(item)}>Edit</Btn>
                  <Btn small danger onClick={() => void removeRule(item)}>Delete</Btn>
                </div>
              </div>
              <div style={{ fontSize: 10, color: C.dim }}>{`Services: ${listToCsv(item.services) || "-"} • Operations: ${listToCsv(item.operations) || "-"}`}</div>
            </Card>
          ))}
          {!rules.length ? <Card style={{ padding: 18, textAlign: "center", color: C.muted }}>No justification codes configured yet.</Card> : null}
        </div>
      </Section>}

      {tab === "Decisions" && <Section title="Recent Decisions">
        <Card style={{ padding: 12, marginBottom: 12 }}>
          <Row2>
            <FG label="Service"><Inp value={decisionService} onChange={(e) => setDecisionService(e.target.value)} placeholder="cloud" /></FG>
            <FG label="Decision"><Sel value={decisionAction} onChange={(e) => setDecisionAction(e.target.value)}><option value="">All</option><option value="allow">Allow</option><option value="deny">Deny</option><option value="approval">Approval</option></Sel></FG>
          </Row2>
        </Card>
        <div style={{ display: "grid", gap: 8 }}>
          {decisions.map((item: any) => (
            <Card key={item.id} style={{ padding: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 6 }}>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                  <span style={{ fontSize: 11, fontWeight: 700, color: C.text }}>{item.service}</span>
                  <B c={item.decision === "allow" ? "green" : item.decision === "approval" ? "amber" : "red"}>{item.decision}</B>
                  {item.bypass_detected ? <B c="purple">Bypass</B> : null}
                </div>
                <div style={{ fontSize: 10, color: C.dim }}>{fmtTS(item.created_at)}</div>
              </div>
              <div style={{ fontSize: 10, color: C.dim, lineHeight: 1.6 }}>
                {`${item.operation || "-"} • code ${item.justification_code || "-"} • matched ${item.matched_code || "-"} • key ${item.key_id || "-"} • reason ${item.reason || "-"}`}
              </div>
            </Card>
          ))}
          {!decisions.length ? <Card style={{ padding: 18, textAlign: "center", color: C.muted }}>No decisions found for the current filters.</Card> : null}
        </div>
      </Section>}
    </div>
  );
};
