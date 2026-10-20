// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { useEffect, useMemo, useState } from "react";
import { Shield, CheckCircle2, XCircle, Clock, Settings, Bell, Users, ChevronDown, ChevronRight, Send } from "lucide-react";
import { Btn, Card, Inp, Sel, Stat, Section, Modal, FG, B, Chk, usePromptDialog } from "../legacyPrimitives";
import { C } from "../theme";
import { CredentialPicker } from "../CredentialPicker";
import { errMsg } from "../runtimeUtils";
import { ApprovalPoliciesPanel } from "./ApprovalPoliciesPanel";
import {
  getGovernanceSettings,
  updateGovernanceSettings,
  listGovernancePolicies,
  listGovernanceRequests,
  getGovernanceRequest,
  voteGovernanceRequest,
  testGovernanceSMTP,
  testGovernanceWebhook,
  listNotifyConnections,
  type NotifyConnection,
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

export const GovernanceTab = ({ session, onToast, onNavigate, subView }: any) => {
  // Requests, Policies and Settings are sidebar sub-options (13.26.0-beta);
  // approval policies have one home here.
  const tab = ["requests", "policies", "settings"].includes(subView) ? subView : "requests";
  const [loading, setLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState("pending");
  const [policies, setPolicies] = useState<any[]>([]);
  const [requests, setRequests] = useState<any[]>([]);
  const [settings, setSettings] = useState<any>(null);
  const [voteBusy, setVoteBusy] = useState("");
  const [filter, setFilter] = useState("");
  const [smtpTestTo, setSmtpTestTo] = useState("");
  const [expandedReq, setExpandedReq] = useState<string | null>(null);
  const [reqDetail, setReqDetail] = useState<any>(null);
  const [detailLoading, setDetailLoading] = useState(false);


  // Settings modal
  const [settingsModal, setSettingsModal] = useState(false);
  const [settingsSaving, setSettingsSaving] = useState(false);
  // The mail relay is an SMTP credential (Playbooks, Credentials).
  const [smtpConn, setSmtpConn] = useState("");
  const [slackConn, setSlackConn] = useState("");
  const [teamsConn, setTeamsConn] = useState("");
  const [notifyConns, setNotifyConns] = useState<NotifyConnection[] | null>(null);
  const [notifyConnsErr, setNotifyConnsErr] = useState("");
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
    } catch (error: any) {
      onToast?.(`Governance load failed: ${errMsg(error)}`);
    } finally {
      setLoading(false);
    }
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: intentional refetch on listed keys / run-once-on-mount; the only omitted dep is a per-render load/refresh closure (wrap in useCallback to drop this suppression). behaviour verified correct.
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

  // Save settings
  const saveSettings = async () => {
    setSettingsSaving(true);
    try {
      await updateGovernanceSettings(session, {
        approval_delivery_mode: deliveryMode,
        smtp_connection_id: smtpConn,
        notify_dashboard: notifyDashboard, notify_email: notifyEmail, notify_slack: notifySlack, notify_teams: notifyTeams,
        slack_connection_id: slackConn, teams_connection_id: teamsConn,
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
      setSmtpConn(settings.smtp_connection_id || "");
      setSlackConn(settings.slack_connection_id || ""); setTeamsConn(settings.teams_connection_id || "");
      listNotifyConnections(session).then((c) => { setNotifyConns(c); setNotifyConnsErr(""); }).catch((e) => { setNotifyConns(null); setNotifyConnsErr(errMsg(e)); });
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
      <Stat l="Notifications" v={settings?.approval_delivery_mode === "kms_only" ? "Dashboard Only" : "External + Dashboard"} c={settings?.approval_delivery_mode === "kms_only" ? "muted" : "blue"} i={Send} />
    </div>

    {/* ── Tabs ── */}
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
      <div />
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
          <span style={{ fontSize: 11, color: C.dim }}>You vote as your signed-in account ({String(session?.username || "")}); only approvers the request was sent to can vote.</span>
          {settings?.challenge_response_enabled && <B c="amber">Challenge Required</B>}
          {settings?.notify_slack && <B c="purple">Slack</B>}
          {settings?.notify_teams && <B c="blue">Teams</B>}
          {settings?.notify_email && <B c="green">Email</B>}
        </div>
      </Card>

      {/* Request list */}
      <Card style={{ padding: 0, overflow: "hidden" }}>
        {/* Table header */}
        <div style={{ display: "grid", gridTemplateColumns: "28px 1.5fr 0.8fr 0.6fr 0.6fr 0.5fr 0.7fr auto", padding: "10px 14px", borderBottom: `1px solid ${C.border}`, fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1, background: C.surface }}>
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
                        <div key={v?.id || i} style={{ display: "grid", gridTemplateColumns: "1fr 0.6fr 0.6fr 1.2fr", gap: 8, padding: "6px 10px", borderRadius: 3, background: C.card, fontSize: 11, alignItems: "center" }}>
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
    {tab === "policies" && <ApprovalPoliciesPanel session={session} onToast={onToast} />}

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
            <SettingRow label="External Notifications" value={settings?.approval_delivery_mode === "kms_only" ? "Disabled (Dashboard Only)" : "Enabled (External + Dashboard)"} color={settings?.approval_delivery_mode === "kms_only" ? C.muted : C.green} />
            <SettingRow label="Challenge Response" value={settings?.challenge_response_enabled ? "Required" : "Disabled"} color={settings?.challenge_response_enabled ? C.amber : C.muted} />
            <SettingRow label="Mail relay" value={settings?.smtp_connection_id ? "Credential set" : settings?.smtp_host ? `${settings.smtp_host} (moving to Credentials)` : "Not set"} color={settings?.smtp_connection_id || settings?.smtp_host ? C.green : C.muted} />
            <SettingRow label="Expiry" value={`${settings?.approval_expiry_minutes || 2880} min`} color={C.dim} />
          </div>
        </Card>
      </div>
    </Section>}

    {/* ════════════ CREATE/EDIT POLICY MODAL ════════════ */}

    {/* ════════════ SETTINGS MODAL ════════════ */}
    <Modal open={settingsModal} onClose={() => setSettingsModal(false)} title="Governance Settings" wide>
      <FG label="External Notifications" hint="When enabled, approval requests are sent to external channels (Email, Slack, Teams). When disabled, approvals are managed through the KMS dashboard only.">
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <div
            onClick={() => setDeliveryMode(deliveryMode === "notify" ? "kms_only" : "notify")}
            style={{ width: 40, height: 22, borderRadius: 11, background: deliveryMode === "notify" ? C.accent : C.border, cursor: "pointer", position: "relative", transition: "background .2s" }}
          >
            <div style={{ width: 16, height: 16, borderRadius: 8, background: C.white, position: "absolute", top: 3, left: deliveryMode === "notify" ? 21 : 3, transition: "left .2s", boxShadow: "0 1px 3px rgba(0,0,0,.3)" }} />
          </div>
          <span style={{ fontSize: 11, color: deliveryMode === "notify" ? C.accentFg : C.dim, fontWeight: 600 }}>
            {deliveryMode === "notify" ? "Enabled — External + Dashboard" : "Disabled — Dashboard Only"}
          </span>
        </div>
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
        <FG label="Mail relay (SMTP credential)" hint={!smtpConn && settings?.smtp_host ? `Now using ${settings.smtp_host}, stored here by an earlier release; it is moved into Credentials automatically.` : "Mail is always sent over TLS."}>
          <CredentialPicker session={session} type="smtp" value={smtpConn} onChange={setSmtpConn} onNavigate={onNavigate} />
        </FG>
        <FG label="Send test email to"><Inp value={smtpTestTo} onChange={(e) => setSmtpTestTo(e.target.value)} placeholder="you@corp.com" /></FG>
        <Btn small onClick={async () => {
          if (!smtpTestTo.trim()) { onToast?.("Enter a recipient for the test email."); return; }
          try { await testGovernanceSMTP(session, smtpTestTo.trim()); onToast?.("SMTP test email sent."); }
          catch (e: any) { onToast?.(`SMTP test failed: ${errMsg(e)}`); }
        }}>Test SMTP</Btn>
      </>}

      {(notifySlack || notifyTeams) && notifyConnsErr && <div style={{ fontSize: 11, color: C.redFg, marginBottom: 8 }}>Connections unavailable: {notifyConnsErr}</div>}
      {([["slack", "Slack", notifySlack, slackConn, setSlackConn], ["teams", "Teams", notifyTeams, teamsConn, setTeamsConn]] as const).map(([ch, label, on, value, set]) => on && (
        <FG key={ch} label={`${label} connection`} hint="Approval notices are sent through this connection; its webhook URL is sealed under Playbooks → Connections">
          <div style={{ display: "flex", gap: 6 }}>
            <Sel value={value} onChange={(e) => set(e.target.value)}>
              <option value="">{(notifyConns || []).some((c) => c.type === ch) ? "choose…" : `no ${label} connection: add one under Playbooks → Connections`}</option>
              {(notifyConns || []).filter((c) => c.type === ch).map((c) => <option key={c.id} value={c.id}>{c.name} ({c.endpoint})</option>)}
            </Sel>
            <Btn small onClick={async () => {
              try { await testGovernanceWebhook(session, ch); onToast?.(`${label} test sent through the saved connection.`); }
              catch (e: any) { onToast?.(`${label} test failed: ${errMsg(e)}`); }
            }}>Test</Btn>
          </div>
        </FG>
      ))}

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
    <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 2 }}>{label}</div>
    <div style={{ fontSize: 11, color: C.text, fontFamily: mono ? "var(--font-mono)" : "inherit", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{value}</div>
  </div>
);

const SettingRow = ({ label, value, color }: { label: string; value: string; color: string }) => (
  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: `1px solid ${C.border}` }}>
    <span style={{ fontSize: 11, color: C.dim }}>{label}</span>
    <span style={{ fontSize: 11, color, fontWeight: 600 }}>{value}</span>
  </div>
);
