// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import { Shield, CheckCircle2, XCircle, Clock, AlertTriangle, Settings, Bell, Users, FileText, Eye, ChevronDown, ChevronRight, Send, Slack, MessageSquare } from "lucide-react";
import { Btn, Card, Inp, Sel, Stat, Section, Tabs, Modal, FG, Row2, B, Chk, usePromptDialog } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  getGovernanceSettings,
  updateGovernanceSettings,
  listGovernancePolicies,
  createGovernancePolicy,
  updateGovernancePolicy,
  listGovernanceRequests,
  getGovernanceRequest,
  voteGovernanceRequest,
  testGovernanceSMTP,
  testGovernanceWebhook,
} from "../../../lib/governance";

/* ────── Helpers ────── */

function tone(status: string) {
  const s = String(status || "").toLowerCase();
  if (s === "approved" || s === "active") return C.green;
  if (s === "denied" || s === "rejected" || s === "failed") return C.red;
  if (s === "pending") return C.amber;
  if (s === "expired") return C.muted;
  return C.dim;
}

function badge(status: string) {
  const s = String(status || "").toLowerCase();
  if (s === "approved" || s === "active") return "green";
  if (s === "denied" || s === "rejected") return "red";
  if (s === "pending") return "amber";
  return "dim";
}

function timeAgo(iso: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  const now = Date.now();
  const diff = now - d.getTime();
  if (diff < 60000) return "just now";
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return d.toLocaleDateString();
}

function expiresIn(iso: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  const diff = d.getTime() - Date.now();
  if (diff <= 0) return "Expired";
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m left`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h left`;
  return `${Math.floor(diff / 86400000)}d left`;
}

/* ────── Main Component ────── */

export const GovernanceTab = ({ session, onToast }: any) => {
  const [tab, setTab] = useState("requests");
  const [loading, setLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState("pending");
  const [policies, setPolicies] = useState<any[]>([]);
  const [requests, setRequests] = useState<any[]>([]);
  const [settings, setSettings] = useState<any>(null);
  const [voteBusy, setVoteBusy] = useState("");
  const [filter, setFilter] = useState("");
  const [approver, setApprover] = useState("");
  const [expandedReq, setExpandedReq] = useState<string | null>(null);
  const [reqDetail, setReqDetail] = useState<any>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Policy modal
  const [policyModal, setPolicyModal] = useState(false);
  const [editPolicy, setEditPolicy] = useState<any>(null);
  const [policyName, setPolicyName] = useState("");
  const [policyDesc, setPolicyDesc] = useState("");
  const [policyScope, setPolicyScope] = useState("keys");
  const [policyTriggers, setPolicyTriggers] = useState("");
  const [policyQuorum, setPolicyQuorum] = useState("threshold");
  const [policyRequired, setPolicyRequired] = useState("2");
  const [policyTotal, setPolicyTotal] = useState("3");
  const [policyApprovers, setPolicyApprovers] = useState("");
  const [policyTimeout, setPolicyTimeout] = useState("48");
  const [policyChannels, setPolicyChannels] = useState<string[]>(["dashboard"]);
  const [policySaving, setPolicySaving] = useState(false);

  // Settings modal
  const [settingsModal, setSettingsModal] = useState(false);
  const [settingsSaving, setSettingsSaving] = useState(false);
  const [smtpHost, setSmtpHost] = useState("");
  const [smtpPort, setSmtpPort] = useState("587");
  const [smtpUser, setSmtpUser] = useState("");
  const [smtpPass, setSmtpPass] = useState("");
  const [smtpFrom, setSmtpFrom] = useState("");
  const [smtpStarttls, setSmtpStarttls] = useState(true);
  const [slackUrl, setSlackUrl] = useState("");
  const [teamsUrl, setTeamsUrl] = useState("");
  const [challengeEnabled, setChallengeEnabled] = useState(false);
  const [deliveryMode, setDeliveryMode] = useState("notify");
  const [notifyDashboard, setNotifyDashboard] = useState(true);
  const [notifyEmail, setNotifyEmail] = useState(false);
  const [notifySlack, setNotifySlack] = useState(false);
  const [notifyTeams, setNotifyTeams] = useState(false);

  const prompt = usePromptDialog();

  const refresh = async () => {
    if (!session?.token) return;
    setLoading(true);
    try {
      const [p, r, s] = await Promise.all([
        listGovernancePolicies(session, { status: "active" }).catch(() => []),
        listGovernanceRequests(session, { status: statusFilter === "all" ? undefined : statusFilter }).catch(() => []),
        getGovernanceSettings(session).catch(() => null),
      ]);
      setPolicies(Array.isArray(p) ? p : []);
      setRequests(Array.isArray(r) ? r : []);
      setSettings(s || null);
      if (!approver) {
        const u = String(session?.username || "").trim().toLowerCase();
        setApprover(u.includes("@") ? u : u ? `${u}@vecta.local` : "");
      }
    } catch (error: any) {
      onToast?.(`Governance load failed: ${errMsg(error)}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void refresh(); }, [session?.token, statusFilter]);

  // Stats
  const pendingCount = useMemo(() => requests.filter((r: any) => String(r?.status || "").toLowerCase() === "pending").length, [requests]);
  const approvedCount = useMemo(() => requests.filter((r: any) => String(r?.status || "").toLowerCase() === "approved").length, [requests]);
  const deniedCount = useMemo(() => requests.filter((r: any) => String(r?.status || "").toLowerCase() === "denied").length, [requests]);

  // Filtered items
  const items = useMemo(() => {
    const q = String(filter || "").trim().toLowerCase();
    const src = Array.isArray(requests) ? requests : [];
    if (!q) return src;
    return src.filter((r: any) => {
      const hay = [r?.id, r?.action, r?.target_type, r?.target_id, r?.status, r?.requester_email, r?.policy_id].map((v) => String(v || "").toLowerCase()).join(" ");
      return hay.includes(q);
    });
  }, [requests, filter]);

  // Vote handler
  const doVote = async (row: any, vote: "approved" | "denied") => {
    if (!session?.token) return;
    const id = String(row?.id || "");
    if (!id) return;
    let challenge = "";
    if (Boolean(settings?.challenge_response_enabled)) {
      const entered = await prompt.prompt({
        title: vote === "approved" ? "Approve Request" : "Deny Request",
        message: `Enter your 6-digit governance challenge code to ${vote === "approved" ? "approve" : "deny"} this request.`,
        placeholder: "000000",
        confirmLabel: vote === "approved" ? "Approve" : "Deny",
        danger: vote === "denied",
        validate: (v: string) => /^\d{6}$/.test(String(v || "").trim()) ? "" : "Enter a valid 6-digit code.",
      });
      if (entered === null) return;
      challenge = String(entered || "").trim();
      if (!challenge) return;
    }
    // Optional comment
    const comment = await prompt.prompt({
      title: "Vote Comment (optional)",
      message: "Add a comment for audit trail. Leave empty to skip.",
      placeholder: "Reason for approval/denial...",
      confirmLabel: vote === "approved" ? "Submit Approval" : "Submit Denial",
      danger: vote === "denied",
      validate: () => "",
    });

    setVoteBusy(`${id}:${vote}`);
    try {
      await voteGovernanceRequest(session, id, {
        vote,
        approver_email: String(approver || "").trim(),
        approver_id: String(approver || "").trim(),
        comment: comment || "",
        challenge_code: challenge,
      });
      onToast?.(`Request ${vote === "approved" ? "approved" : "denied"}: ${id.slice(0, 12)}`);
      await refresh();
    } catch (error: any) {
      onToast?.(`Vote failed: ${errMsg(error)}`);
    } finally {
      setVoteBusy("");
    }
  };

  // Expand request detail
  const toggleDetail = async (id: string) => {
    if (expandedReq === id) { setExpandedReq(null); setReqDetail(null); return; }
    setExpandedReq(id);
    setDetailLoading(true);
    try {
      const d = await getGovernanceRequest(session, id);
      setReqDetail(d);
    } catch { setReqDetail(null); }
    finally { setDetailLoading(false); }
  };

  // Save policy
  const savePolicy = async () => {
    setPolicySaving(true);
    try {
      const payload = {
        name: policyName.trim(),
        description: policyDesc.trim(),
        scope: policyScope,
        trigger_actions: policyTriggers.split(",").map((s) => s.trim()).filter(Boolean),
        quorum_mode: policyQuorum,
        required_approvals: Number(policyRequired) || 2,
        total_approvers: Number(policyTotal) || 3,
        approver_users: policyApprovers.split(",").map((s) => s.trim()).filter(Boolean),
        timeout_hours: Number(policyTimeout) || 48,
        notification_channels: policyChannels,
        status: "active",
      };
      if (editPolicy?.id) {
        await updateGovernancePolicy(session, editPolicy.id, payload);
        onToast?.(`Policy "${policyName}" updated.`);
      } else {
        await createGovernancePolicy(session, payload);
        onToast?.(`Policy "${policyName}" created.`);
      }
      setPolicyModal(false);
      await refresh();
    } catch (e: any) { onToast?.(`Policy save failed: ${errMsg(e)}`); }
    finally { setPolicySaving(false); }
  };

  const openPolicyModal = (p?: any) => {
    setEditPolicy(p || null);
    setPolicyName(p?.name || "");
    setPolicyDesc(p?.description || "");
    setPolicyScope(p?.scope || "keys");
    setPolicyTriggers((p?.trigger_actions || []).join(", "));
    setPolicyQuorum(p?.quorum_mode || "threshold");
    setPolicyRequired(String(p?.required_approvals || 2));
    setPolicyTotal(String(p?.total_approvers || 3));
    setPolicyApprovers((p?.approver_users || []).join(", "));
    setPolicyTimeout(String(p?.timeout_hours || 48));
    setPolicyChannels(p?.notification_channels || ["dashboard"]);
    setPolicyModal(true);
  };

  // Save settings
  const saveSettings = async () => {
    setSettingsSaving(true);
    try {
      await updateGovernanceSettings(session, {
        approval_delivery_mode: deliveryMode,
        smtp_host: smtpHost, smtp_port: smtpPort, smtp_username: smtpUser, smtp_password: smtpPass, smtp_from: smtpFrom, smtp_starttls: smtpStarttls,
        notify_dashboard: notifyDashboard, notify_email: notifyEmail, notify_slack: notifySlack, notify_teams: notifyTeams,
        slack_webhook_url: slackUrl, teams_webhook_url: teamsUrl,
        challenge_response_enabled: challengeEnabled,
      });
      onToast?.("Governance settings saved.");
      setSettingsModal(false);
      await refresh();
    } catch (e: any) { onToast?.(`Settings save failed: ${errMsg(e)}`); }
    finally { setSettingsSaving(false); }
  };

  const openSettingsModal = () => {
    if (settings) {
      setSmtpHost(settings.smtp_host || ""); setSmtpPort(settings.smtp_port || "587");
      setSmtpUser(settings.smtp_username || ""); setSmtpPass(""); setSmtpFrom(settings.smtp_from || "");
      setSmtpStarttls(settings.smtp_starttls !== false);
      setSlackUrl(settings.slack_webhook_url || ""); setTeamsUrl(settings.teams_webhook_url || "");
      setChallengeEnabled(Boolean(settings.challenge_response_enabled));
      setDeliveryMode(settings.approval_delivery_mode || "notify");
      setNotifyDashboard(settings.notify_dashboard !== false);
      setNotifyEmail(Boolean(settings.notify_email));
      setNotifySlack(Boolean(settings.notify_slack));
      setNotifyTeams(Boolean(settings.notify_teams));
    }
    setSettingsModal(true);
  };

  /* ════════════ RENDER ════════════ */

  return <div style={{ display: "grid", gap: 14 }}>

    {/* ── Header stats ── */}
    <div style={{ display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: 10 }}>
      <Stat l="Active Policies" v={policies.length} c="accent" i={Shield} />
      <Stat l="Pending" v={statusFilter === "pending" ? items.length : pendingCount} c="amber" i={Clock} />
      <Stat l="Approved" v={statusFilter === "approved" ? items.length : approvedCount} c="green" i={CheckCircle2} />
      <Stat l="Denied" v={statusFilter === "denied" ? items.length : deniedCount} c="red" i={XCircle} />
      <Stat l="Delivery" v={String(settings?.approval_delivery_mode || "notify")} c="blue" i={Send} />
    </div>

    {/* ── Tabs ── */}
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
      <Tabs tabs={["Requests", "Policies", "Settings"]} active={tab === "requests" ? 0 : tab === "policies" ? 1 : 2} onChange={(i) => setTab(["requests", "policies", "settings"][i])} />
      <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
        {tab === "requests" && <>
          <Sel value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} style={{ width: 120 }}>
            <option value="pending">Pending</option>
            <option value="approved">Approved</option>
            <option value="denied">Denied</option>
            <option value="expired">Expired</option>
            <option value="all">All</option>
          </Sel>
          <Inp value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Search..." style={{ width: 180 }} />
        </>}
        {tab === "policies" && <Btn small primary onClick={() => openPolicyModal()}>Create Policy</Btn>}
        {tab === "settings" && <Btn small onClick={openSettingsModal}><Settings size={11} /> Configure</Btn>}
        <Btn small onClick={() => void refresh()} disabled={loading}>{loading ? "..." : "Refresh"}</Btn>
      </div>
    </div>

    {/* ════════════ REQUESTS TAB ════════════ */}
    {tab === "requests" && <>
      {/* Approver identity bar */}
      <Card style={{ padding: "10px 14px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <Users size={14} color={C.accent} />
          <span style={{ fontSize: 11, color: C.dim }}>Approver Identity:</span>
          <Inp value={approver} onChange={(e) => setApprover(e.target.value)} placeholder="your-email@company.com" style={{ width: 280, fontSize: 11 }} />
          {settings?.challenge_response_enabled && <B c="amber">Challenge Required</B>}
          {settings?.notify_slack && <B c="purple">Slack</B>}
          {settings?.notify_teams && <B c="blue">Teams</B>}
          {settings?.notify_email && <B c="green">Email</B>}
        </div>
      </Card>

      {/* Request list */}
      <Card style={{ padding: 0, overflow: "hidden" }}>
        {/* Table header */}
        <div style={{ display: "grid", gridTemplateColumns: "28px 1.5fr 0.8fr 0.6fr 0.6fr 0.5fr 0.7fr auto", padding: "10px 14px", borderBottom: `1px solid ${C.border}`, fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, background: C.surface }}>
          <div></div><div>Action / Target</div><div>Requester</div><div>Required</div><div>Progress</div><div>Status</div><div>Time</div><div style={{ textAlign: "right" }}>Actions</div>
        </div>

        <div style={{ maxHeight: 500, overflowY: "auto" }}>
          {items.map((r: any) => {
            const id = String(r?.id || "");
            const st = String(r?.status || "pending").toLowerCase();
            const pending = st === "pending";
            const expanded = expandedReq === id;
            const approvals = Number(r?.current_approvals || 0);
            const required = Number(r?.required_approvals || 1);
            const denials = Number(r?.current_denials || 0);
            const pct = required > 0 ? Math.min(100, Math.round((approvals / required) * 100)) : 0;

            return <div key={id}>
              {/* Row */}
              <div
                style={{ display: "grid", gridTemplateColumns: "28px 1.5fr 0.8fr 0.6fr 0.6fr 0.5fr 0.7fr auto", padding: "10px 14px", borderBottom: `1px solid ${C.border}`, alignItems: "center", cursor: "pointer", transition: "background 120ms", background: expanded ? C.surface : "transparent" }}
                onClick={() => void toggleDetail(id)}
                onMouseEnter={(e) => { if (!expanded) e.currentTarget.style.background = C.cardHover; }}
                onMouseLeave={(e) => { if (!expanded) e.currentTarget.style.background = "transparent"; }}
              >
                <div>{expanded ? <ChevronDown size={14} color={C.accent} /> : <ChevronRight size={14} color={C.dim} />}</div>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 12, color: C.text, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {String(r?.action || "—")}
                  </div>
                  <div style={{ fontSize: 10, color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {String(r?.target_type || "—")} / {String(r?.target_id || "—").slice(0, 20)}
                  </div>
                </div>
                <div style={{ fontSize: 10, color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(r?.requester_email || r?.requester_id || "—")}</div>
                <div style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{required}</div>
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <div style={{ flex: 1, height: 6, borderRadius: 3, background: C.border, overflow: "hidden" }}>
                    <div style={{ width: `${pct}%`, height: "100%", borderRadius: 3, background: pct >= 100 ? C.green : C.accent, transition: "width 300ms" }} />
                  </div>
                  <span style={{ fontSize: 10, color: C.text, fontWeight: 600, minWidth: 30 }}>{approvals}/{required}</span>
                </div>
                <div><B c={badge(st)}>{st}</B></div>
                <div style={{ fontSize: 10, color: C.dim }}>{timeAgo(r?.created_at)}</div>
                <div style={{ display: "flex", gap: 4, justifyContent: "flex-end" }} onClick={(e) => e.stopPropagation()}>
                  {pending && <>
                    <Btn small primary disabled={voteBusy === `${id}:approved`} onClick={() => void doVote(r, "approved")}>
                      {voteBusy === `${id}:approved` ? "..." : "Approve"}
                    </Btn>
                    <Btn small danger disabled={voteBusy === `${id}:denied`} onClick={() => void doVote(r, "denied")}>
                      {voteBusy === `${id}:denied` ? "..." : "Deny"}
                    </Btn>
                  </>}
                </div>
              </div>

              {/* Expanded detail */}
              {expanded && <div style={{ padding: "12px 14px 14px 42px", borderBottom: `1px solid ${C.border}`, background: C.surface }}>
                {detailLoading ? <div style={{ fontSize: 11, color: C.dim }}>Loading details...</div> : reqDetail ? <div style={{ display: "grid", gap: 10 }}>
                  {/* Meta grid */}
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 8 }}>
                    <MiniField label="Request ID" value={id} mono />
                    <MiniField label="Policy ID" value={reqDetail.request?.policy_id || "—"} mono />
                    <MiniField label="Expires" value={expiresIn(reqDetail.request?.expires_at)} />
                    <MiniField label="Denials" value={String(reqDetail.request?.current_denials || 0)} />
                  </div>

                  {/* Votes */}
                  {reqDetail.votes?.length > 0 && <div>
                    <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>Vote History</div>
                    <div style={{ display: "grid", gap: 4 }}>
                      {reqDetail.votes.map((v: any, i: number) => (
                        <div key={v?.id || i} style={{ display: "grid", gridTemplateColumns: "1fr 0.6fr 0.6fr 1.2fr", gap: 8, padding: "6px 10px", borderRadius: 6, background: C.card, fontSize: 11, alignItems: "center" }}>
                          <div style={{ color: C.text, fontWeight: 500 }}>{v?.approver_email || v?.approver_id || "—"}</div>
                          <div><B c={v?.vote === "approved" ? "green" : "red"}>{v?.vote}</B></div>
                          <div style={{ fontSize: 10, color: C.dim }}>{v?.vote_method || "—"}</div>
                          <div style={{ fontSize: 10, color: C.dim }}>{v?.comment || "—"}</div>
                        </div>
                      ))}
                    </div>
                  </div>}
                  {(!reqDetail.votes || reqDetail.votes.length === 0) && <div style={{ fontSize: 11, color: C.dim }}>No votes recorded yet.</div>}
                </div> : <div style={{ fontSize: 11, color: C.dim }}>Could not load request details.</div>}
              </div>}
            </div>;
          })}

          {!items.length && <div style={{ padding: 24, textAlign: "center", fontSize: 12, color: C.dim }}>
            <Clock size={20} color={C.muted} style={{ margin: "0 auto 8px" }} />
            No {statusFilter === "all" ? "" : statusFilter} requests found.
          </div>}
        </div>
      </Card>
    </>}

    {/* ════════════ POLICIES TAB ════════════ */}
    {tab === "policies" && <Section title="Approval Policies" actions={<Btn small primary onClick={() => openPolicyModal()}>Create Policy</Btn>}>
      <Card style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1.2fr 0.6fr 0.6fr 0.5fr 0.5fr 0.6fr 0.4fr auto", padding: "10px 14px", borderBottom: `1px solid ${C.border}`, fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, background: C.surface }}>
          <div>Policy</div><div>Scope</div><div>Quorum</div><div>Req</div><div>Total</div><div>Timeout</div><div>Status</div><div></div>
        </div>
        <div style={{ maxHeight: 400, overflowY: "auto" }}>
          {policies.map((p: any) => (
            <div key={p.id} style={{ display: "grid", gridTemplateColumns: "1.2fr 0.6fr 0.6fr 0.5fr 0.5fr 0.6fr 0.4fr auto", padding: "10px 14px", borderBottom: `1px solid ${C.border}`, alignItems: "center", fontSize: 11 }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ color: C.text, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.name}</div>
                <div style={{ fontSize: 10, color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{(p.trigger_actions || []).join(", ") || "—"}</div>
              </div>
              <div style={{ color: C.accent }}>{p.scope}</div>
              <div style={{ color: C.text }}>{p.quorum_mode || "threshold"}</div>
              <div style={{ color: C.text, fontWeight: 700 }}>{p.required_approvals}</div>
              <div style={{ color: C.dim }}>{p.total_approvers}</div>
              <div style={{ color: C.dim }}>{p.timeout_hours || 48}h</div>
              <div><B c={badge(p.status)}>{p.status}</B></div>
              <div><Btn small onClick={() => openPolicyModal(p)}>Edit</Btn></div>
            </div>
          ))}
          {!policies.length && <div style={{ padding: 24, textAlign: "center", fontSize: 12, color: C.dim }}>
            <Shield size={20} color={C.muted} style={{ margin: "0 auto 8px" }} />
            No policies configured. Create one to enable approval workflows.
          </div>}
        </div>
      </Card>
    </Section>}

    {/* ════════════ SETTINGS TAB ════════════ */}
    {tab === "settings" && <Section title="Governance Settings" actions={<Btn small primary onClick={openSettingsModal}>Configure</Btn>}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <Card>
          <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 10, display: "flex", alignItems: "center", gap: 6 }}><Bell size={14} color={C.accent} /> Notification Channels</div>
          <div style={{ display: "grid", gap: 6 }}>
            <SettingRow label="Dashboard" value={settings?.notify_dashboard !== false ? "Enabled" : "Disabled"} color={settings?.notify_dashboard !== false ? C.green : C.muted} />
            <SettingRow label="Email (SMTP)" value={settings?.notify_email ? "Enabled" : "Disabled"} color={settings?.notify_email ? C.green : C.muted} />
            <SettingRow label="Slack Webhook" value={settings?.notify_slack ? "Configured" : "Not configured"} color={settings?.notify_slack ? C.green : C.muted} />
            <SettingRow label="Teams Webhook" value={settings?.notify_teams ? "Configured" : "Not configured"} color={settings?.notify_teams ? C.green : C.muted} />
          </div>
        </Card>
        <Card>
          <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 10, display: "flex", alignItems: "center", gap: 6 }}><Shield size={14} color={C.accent} /> Security</div>
          <div style={{ display: "grid", gap: 6 }}>
            <SettingRow label="Delivery Mode" value={settings?.approval_delivery_mode || "notify"} color={C.accent} />
            <SettingRow label="Challenge Response" value={settings?.challenge_response_enabled ? "Required" : "Disabled"} color={settings?.challenge_response_enabled ? C.amber : C.muted} />
            <SettingRow label="SMTP Host" value={settings?.smtp_host || "Not set"} color={settings?.smtp_host ? C.green : C.muted} />
            <SettingRow label="Expiry" value={`${settings?.approval_expiry_minutes || 2880} min`} color={C.dim} />
          </div>
        </Card>
      </div>
    </Section>}

    {/* ════════════ CREATE/EDIT POLICY MODAL ════════════ */}
    <Modal open={policyModal} onClose={() => setPolicyModal(false)} title={editPolicy ? "Edit Approval Policy" : "Create Approval Policy"} wide>
      <Row2>
        <FG label="Policy Name" required>
          <Inp value={policyName} onChange={(e) => setPolicyName(e.target.value)} placeholder="e.g. Key Deletion Approval" />
        </FG>
        <FG label="Scope">
          <Sel value={policyScope} onChange={(e) => setPolicyScope(e.target.value)}>
            <option value="keys">Keys</option>
            <option value="secrets">Secrets</option>
            <option value="certs">Certificates</option>
            <option value="users">Users</option>
            <option value="system">System</option>
            <option value="all">All</option>
          </Sel>
        </FG>
      </Row2>
      <FG label="Description">
        <Inp value={policyDesc} onChange={(e) => setPolicyDesc(e.target.value)} placeholder="What this policy governs" />
      </FG>
      <FG label="Trigger Actions" hint="Comma-separated action patterns, e.g. key.delete, secret.*, user.disable">
        <Inp value={policyTriggers} onChange={(e) => setPolicyTriggers(e.target.value)} placeholder="key.delete, key.export" />
      </FG>
      <Row2>
        <FG label="Quorum Mode">
          <Sel value={policyQuorum} onChange={(e) => setPolicyQuorum(e.target.value)}>
            <option value="threshold">Threshold (M-of-N)</option>
            <option value="and">Unanimous (All must approve)</option>
            <option value="or">Any (Single approver)</option>
          </Sel>
        </FG>
        <FG label="Timeout (hours)">
          <Inp type="number" value={policyTimeout} onChange={(e) => setPolicyTimeout(e.target.value)} placeholder="48" />
        </FG>
      </Row2>
      <Row2>
        <FG label="Required Approvals (M)">
          <Inp type="number" value={policyRequired} onChange={(e) => setPolicyRequired(e.target.value)} placeholder="2" />
        </FG>
        <FG label="Total Approvers (N)">
          <Inp type="number" value={policyTotal} onChange={(e) => setPolicyTotal(e.target.value)} placeholder="3" />
        </FG>
      </Row2>
      <FG label="Approver Emails" hint="Comma-separated email addresses">
        <Inp value={policyApprovers} onChange={(e) => setPolicyApprovers(e.target.value)} placeholder="alice@corp.com, bob@corp.com, carol@corp.com" />
      </FG>
      <FG label="Notification Channels">
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <Chk label="Dashboard" checked={policyChannels.includes("dashboard")} onChange={(v) => setPolicyChannels((prev) => v ? [...prev, "dashboard"] : prev.filter((c) => c !== "dashboard"))} />
          <Chk label="Email" checked={policyChannels.includes("email")} onChange={(v) => setPolicyChannels((prev) => v ? [...prev, "email"] : prev.filter((c) => c !== "email"))} />
          <Chk label="Slack" checked={policyChannels.includes("slack")} onChange={(v) => setPolicyChannels((prev) => v ? [...prev, "slack"] : prev.filter((c) => c !== "slack"))} />
          <Chk label="Teams" checked={policyChannels.includes("teams")} onChange={(v) => setPolicyChannels((prev) => v ? [...prev, "teams"] : prev.filter((c) => c !== "teams"))} />
        </div>
      </FG>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 10 }}>
        <Btn small onClick={() => setPolicyModal(false)}>Cancel</Btn>
        <Btn small primary onClick={savePolicy} disabled={policySaving || !policyName.trim()}>
          {policySaving ? "Saving..." : editPolicy ? "Update Policy" : "Create Policy"}
        </Btn>
      </div>
    </Modal>

    {/* ════════════ SETTINGS MODAL ════════════ */}
    <Modal open={settingsModal} onClose={() => setSettingsModal(false)} title="Governance Settings" wide>
      <FG label="Delivery Mode">
        <Sel value={deliveryMode} onChange={(e) => setDeliveryMode(e.target.value)}>
          <option value="notify">Notify (send notifications)</option>
          <option value="kms_only">KMS Only (dashboard-only approvals)</option>
        </Sel>
      </FG>
      <FG label="Security">
        <Chk label="Require challenge-response code for dashboard votes" checked={challengeEnabled} onChange={setChallengeEnabled} />
      </FG>

      <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginTop: 14, marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}><Bell size={13} color={C.accent} /> Notification Channels</div>
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 12 }}>
        <Chk label="Dashboard" checked={notifyDashboard} onChange={setNotifyDashboard} />
        <Chk label="Email" checked={notifyEmail} onChange={setNotifyEmail} />
        <Chk label="Slack" checked={notifySlack} onChange={setNotifySlack} />
        <Chk label="Teams" checked={notifyTeams} onChange={setNotifyTeams} />
      </div>

      {notifyEmail && <>
        <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginTop: 10, marginBottom: 8 }}>SMTP Configuration</div>
        <Row2>
          <FG label="SMTP Host"><Inp value={smtpHost} onChange={(e) => setSmtpHost(e.target.value)} placeholder="smtp.gmail.com" /></FG>
          <FG label="SMTP Port"><Inp value={smtpPort} onChange={(e) => setSmtpPort(e.target.value)} placeholder="587" /></FG>
        </Row2>
        <Row2>
          <FG label="Username"><Inp value={smtpUser} onChange={(e) => setSmtpUser(e.target.value)} placeholder="noreply@corp.com" /></FG>
          <FG label="Password"><Inp type="password" value={smtpPass} onChange={(e) => setSmtpPass(e.target.value)} placeholder="********" /></FG>
        </Row2>
        <Row2>
          <FG label="From Address"><Inp value={smtpFrom} onChange={(e) => setSmtpFrom(e.target.value)} placeholder="kms@corp.com" /></FG>
          <FG label="TLS"><Chk label="Enable STARTTLS" checked={smtpStarttls} onChange={setSmtpStarttls} /></FG>
        </Row2>
        <Btn small onClick={async () => {
          try { await testGovernanceSMTP(session, approver || "test@example.com"); onToast?.("SMTP test email sent."); }
          catch (e: any) { onToast?.(`SMTP test failed: ${errMsg(e)}`); }
        }}>Test SMTP</Btn>
      </>}

      {notifySlack && <FG label="Slack Webhook URL" hint="Incoming webhook URL for approval notifications">
        <div style={{ display: "flex", gap: 6 }}>
          <Inp value={slackUrl} onChange={(e) => setSlackUrl(e.target.value)} placeholder="https://hooks.slack.com/services/..." />
          <Btn small onClick={async () => {
            try { await testGovernanceWebhook(session, "slack", slackUrl); onToast?.("Slack test sent."); }
            catch (e: any) { onToast?.(`Slack test failed: ${errMsg(e)}`); }
          }}>Test</Btn>
        </div>
      </FG>}

      {notifyTeams && <FG label="Teams Webhook URL" hint="Incoming webhook URL for approval notifications">
        <div style={{ display: "flex", gap: 6 }}>
          <Inp value={teamsUrl} onChange={(e) => setTeamsUrl(e.target.value)} placeholder="https://outlook.office.com/webhook/..." />
          <Btn small onClick={async () => {
            try { await testGovernanceWebhook(session, "teams", teamsUrl); onToast?.("Teams test sent."); }
            catch (e: any) { onToast?.(`Teams test failed: ${errMsg(e)}`); }
          }}>Test</Btn>
        </div>
      </FG>}

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 14 }}>
        <Btn small onClick={() => setSettingsModal(false)}>Cancel</Btn>
        <Btn small primary onClick={saveSettings} disabled={settingsSaving}>
          {settingsSaving ? "Saving..." : "Save Settings"}
        </Btn>
      </div>
    </Modal>

    {prompt.ui}
  </div>;
};

/* ────── Sub-components ────── */

const MiniField = ({ label, value, mono }: { label: string; value: string; mono?: boolean }) => (
  <div>
    <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 2 }}>{label}</div>
    <div style={{ fontSize: 11, color: C.text, fontFamily: mono ? "'JetBrains Mono',monospace" : "inherit", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{value}</div>
  </div>
);

const SettingRow = ({ label, value, color }: { label: string; value: string; color: string }) => (
  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: `1px solid ${C.border}` }}>
    <span style={{ fontSize: 11, color: C.dim }}>{label}</span>
    <span style={{ fontSize: 11, color, fontWeight: 600 }}>{value}</span>
  </div>
);
