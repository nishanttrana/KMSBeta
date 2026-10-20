import { useEffect, useState } from "react";
import { Shield } from "lucide-react";
import type { AuthSession } from "../../../lib/auth";
import { createGovernancePolicy, listGovernancePolicies, updateGovernancePolicy } from "../../../lib/governance";
import { B, Btn, Card, Chk, FG, Inp, Modal, Row2, Section, Sel } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";

// Approval policies: their one home is Approvals → Policies (owner,
// 2026-10-20; 13.26.0-beta). Lists every policy, paused ones included, so a
// paused policy can be enabled again; a failed load says so.

function badge(status: string) {
  const s = String(status || "").toLowerCase();
  if (s === "approved" || s === "active") return "green";
  if (s === "denied" || s === "rejected") return "red";
  if (s === "pending") return "amber";
  return "dim";
}

export function ApprovalPoliciesPanel({ session, onToast }: { session: AuthSession; onToast?: (m: string) => void }) {
  const [policies, setPolicies] = useState<any[]>([]);
  const [error, setError] = useState("");
  const load = async () => {
    if (!session?.token) return;
    try { setPolicies(await listGovernancePolicies(session, {})); setError(""); }
    catch (e: any) { setError(errMsg(e)); }
  };
  // eslint-disable-next-line react-hooks/exhaustive-deps -- load reads only session
  useEffect(() => { void load(); }, [session?.token]);

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
  const [policyRoles, setPolicyRoles] = useState("");
  const [policyTimeout, setPolicyTimeout] = useState("48");
  const [policyChannels, setPolicyChannels] = useState<string[]>(["dashboard"]);
  const [policySaving, setPolicySaving] = useState(false);
  const [policyStatus, setPolicyStatus] = useState("active");
  // Chk passes its click event, which is always truthy: the old handler only
  // ever added a channel (13.26.0-beta).
  const toggleChannel = (ch: string) => setPolicyChannels((prev) => prev.includes(ch) ? prev.filter((c) => c !== ch) : [...prev, ch]);

  // Save policy
  const savePolicy = async () => {
    const triggers = policyTriggers.split(",").map((s) => s.trim()).filter(Boolean);
    const approvers = [...policyApprovers.split(","), ...policyRoles.split(",")].map((s) => s.trim()).filter(Boolean);
    if (!policyName.trim()) { onToast?.("Policy name is required."); return; }
    if (!triggers.length) { onToast?.("Name at least one trigger action."); return; }
    if (!approvers.length) { onToast?.("Name at least one approver or approver role."); return; }
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
        approver_roles: policyRoles.split(",").map((s) => s.trim()).filter(Boolean),
        timeout_hours: Number(policyTimeout) || 48,
        notification_channels: policyChannels,
        // Was always "active": editing a paused policy switched it back on.
        status: policyStatus,
      };
      if (editPolicy?.id) {
        await updateGovernancePolicy(session, editPolicy.id, payload);
        onToast?.(`Policy "${policyName}" updated.`);
      } else {
        await createGovernancePolicy(session, payload);
        onToast?.(`Policy "${policyName}" created.`);
      }
      setPolicyModal(false);
      await load();
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
    setPolicyRoles((p?.approver_roles || []).join(", "));
    setPolicyTimeout(String(p?.timeout_hours || 48));
    setPolicyChannels(p?.notification_channels || ["dashboard"]);
    setPolicyStatus(p?.status || "active");
    setPolicyModal(true);
  };

  return <>
    <Section title="Approval Policies" actions={<Btn small primary onClick={() => openPolicyModal()}>Create Policy</Btn>}>
      <Card style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1.2fr 0.6fr 0.6fr 0.5fr 0.5fr 0.6fr 0.4fr auto", padding: "10px 14px", borderBottom: `1px solid ${C.border}`, fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1, background: C.surface }}>
          <div>Policy</div><div>Scope</div><div>Quorum</div><div>Req</div><div>Total</div><div>Timeout</div><div>Status</div><div></div>
        </div>
        <div style={{ maxHeight: 400, overflowY: "auto" }}>
          {policies.map((p: any) => (
            <div key={p.id} style={{ display: "grid", gridTemplateColumns: "1.2fr 0.6fr 0.6fr 0.5fr 0.5fr 0.6fr 0.4fr auto", padding: "10px 14px", borderBottom: `1px solid ${C.border}`, alignItems: "center", fontSize: 11 }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ color: C.text, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.name}</div>
                <div style={{ fontSize: 10, color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{(p.trigger_actions || []).join(", ") || "—"}</div>
              </div>
              <div style={{ color: C.accentFg }}>{p.scope}</div>
              <div style={{ color: C.text }}>{p.quorum_mode || "threshold"}</div>
              <div style={{ color: C.text, fontWeight: 700 }}>{p.required_approvals}</div>
              <div style={{ color: C.dim }}>{p.total_approvers}</div>
              <div style={{ color: C.dim }}>{p.timeout_hours || 48}h</div>
              <div><B c={badge(p.status)}>{p.status}</B></div>
              <div style={{ display: "flex", gap: 6 }}>
                <Btn small onClick={() => openPolicyModal(p)}>Edit</Btn>
                <Btn small onClick={async () => {
                  const next = p.status === "active" ? "inactive" : "active";
                  // The server replaces the whole policy: send it all with the new status.
                  try { await updateGovernancePolicy(session, p.id, { ...p, status: next }); onToast?.(next === "active" ? "Policy enabled." : "Policy disabled."); await load(); }
                  catch (e: any) { onToast?.(`Policy update failed: ${errMsg(e)}`); }
                }}>{p.status === "active" ? "Disable" : "Enable"}</Btn>
              </div>
            </div>
          ))}
          {error && <div style={{ padding: 24, textAlign: "center", fontSize: 12, color: C.redFg }}>Policies unavailable: {error}</div>}
          {!error && !policies.length && <div style={{ padding: 24, textAlign: "center", fontSize: 12, color: C.dim }}>
            <Shield size={20} color={C.muted} style={{ margin: "0 auto 8px" }} />
            No policies configured. Create one to enable approval workflows.
          </div>}
        </div>
      </Card>
    </Section>

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
      <FG label="Status">
        <Sel value={policyStatus} onChange={(e) => setPolicyStatus(e.target.value)}>
          <option value="active">Active: holds matching operations</option>
          <option value="inactive">Inactive: paused</option>
        </Sel>
      </FG>
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
      <FG label="Approver Roles" hint="Comma-separated roles. Every active user holding one, directly or through a group, becomes an approver when a request opens; the requester never votes on their own request.">
        <Inp value={policyRoles} onChange={(e) => setPolicyRoles(e.target.value)} placeholder="security-officer, admin" />
      </FG>
      <FG label="Notification Channels">
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <Chk label="Dashboard" checked={policyChannels.includes("dashboard")} onChange={() => toggleChannel("dashboard")} />
          <Chk label="Email" checked={policyChannels.includes("email")} onChange={() => toggleChannel("email")} />
          <Chk label="Slack" checked={policyChannels.includes("slack")} onChange={() => toggleChannel("slack")} />
          <Chk label="Teams" checked={policyChannels.includes("teams")} onChange={() => toggleChannel("teams")} />
        </div>
      </FG>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 10 }}>
        <Btn small onClick={() => setPolicyModal(false)}>Cancel</Btn>
        <Btn small primary onClick={savePolicy} disabled={policySaving || !policyName.trim()}>
          {policySaving ? "Saving..." : editPolicy ? "Update Policy" : "Create Policy"}
        </Btn>
      </div>
    </Modal>
  </>;
}
