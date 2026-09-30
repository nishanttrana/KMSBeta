import { useState } from "react";
import type { AuthSession } from "../../../lib/auth";
import { activateAuthClient, registerAuthClient, revokeAuthClient, rotateAuthClientKey } from "../../../lib/authAdmin";
import { B, Btn, FG, Inp } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";

// REST client credential lifecycle: register, approve (issues the API key),
// rotate the key, revoke. Every action is a real auth call, audited by the
// service (audit.auth.client_*). An issued key is shown once, kept only in
// component state until dismissed, and never logged or stored.

type OneTimeKey = { clientID: string; key: string; prefix: string };

const isServiceIdentity = (id: string) => String(id || "").trim().startsWith("kms-");

function OneTimeKeyPanel({ issued, onDismiss }: { issued: OneTimeKey; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false);
  return <div style={{ border: `1px solid ${C.amber}`, background: C.amberDim, borderRadius: 10, padding: "10px 12px", display: "grid", gap: 6 }}>
    <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>API key for {issued.clientID}: shown once</div>
    <div style={{ fontSize: 10, color: C.dim }}>Store it in your CI secret store now. The KMS keeps only its hash; it can't be shown again. Exchange it at POST /svc/auth/auth/client-token (docs/CI_CD_AUTOMATION.md).</div>
    <Inp value={issued.key} readOnly mono onFocus={(e) => e.currentTarget.select()} />
    <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
      <Btn small onClick={() => { void navigator.clipboard.writeText(issued.key).then(() => setCopied(true)); }}>{copied ? "Copied" : "Copy"}</Btn>
      <Btn small primary onClick={onDismiss}>I stored it</Btn>
    </div>
  </div>;
}

export function RestClientRegister({ session, onChanged, onToast }: { session: AuthSession; onChanged: () => void; onToast?: ((m: string) => void) | undefined }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    if (!name.trim()) return;
    setBusy(true);
    try {
      const id = await registerAuthClient(session, { client_name: name.trim(), auth_mode: "api_key" });
      onToast?.(`Client registered (${id}). It stays pending until approved.`);
      setName("");
      onChanged();
    } catch (error) {
      onToast?.(`Register failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };
  return <div style={{ display: "flex", gap: 8, alignItems: "flex-end" }}>
    <div style={{ flex: 1 }}><FG label="Register REST client"><Inp value={name} onChange={(e) => setName(e.target.value)} placeholder="release-pipeline" /></FG></div>
    <Btn small onClick={submit} disabled={busy || !name.trim()}>{busy ? "Registering..." : "Register"}</Btn>
  </div>;
}

export function RestClientLifecycle({ session, client, onChanged, onToast }: { session: AuthSession; client: any; onChanged: () => void; onToast?: ((m: string) => void) | undefined }) {
  const [busy, setBusy] = useState("");
  const [approvalID, setApprovalID] = useState("");
  const [issued, setIssued] = useState<OneTimeKey | null>(null);
  const id = String(client?.id || "");
  const status = String(client?.status || "pending").toLowerCase();

  const run = async (label: string, action: () => Promise<void>) => {
    setBusy(label);
    try {
      await action();
      onChanged();
    } catch (error) {
      onToast?.(`${label} failed: ${errMsg(error)}`);
    } finally {
      setBusy("");
    }
  };
  const approve = () => run("Approve", async () => {
    const out = await activateAuthClient(session, id, approvalID);
    setIssued({ clientID: id, key: String(out?.api_key || ""), prefix: String(out?.api_key_prefix || "") });
    setApprovalID("");
  });
  const rotate = () => {
    if (!window.confirm(`Rotate the API key of "${client?.client_name || id}"? The current key stops working immediately.`)) return;
    void run("Rotate key", async () => {
      const out = await rotateAuthClientKey(session, id);
      setIssued({ clientID: id, key: String(out?.api_key || ""), prefix: String(out?.api_key_prefix || "") });
    });
  };
  const revoke = () => {
    if (!window.confirm(`Revoke "${client?.client_name || id}"? Its API key is deleted and it can no longer get tokens.`)) return;
    void run("Revoke", async () => {
      await revokeAuthClient(session, id);
      setIssued(null);
      onToast?.("Client revoked; its API key is deleted.");
    });
  };

  if (isServiceIdentity(id)) {
    return <div style={{ fontSize: 10, color: C.muted }}>Platform service identity: its key is derived from the bootstrap secret and managed by the platform.</div>;
  }
  return <div style={{ display: "grid", gap: 8 }}>
    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
      <span style={{ fontSize: 10, color: C.muted }}>Credential</span>
      <B c={status === "approved" ? "green" : status === "revoked" ? "red" : "amber"}>{status}</B>
      {client?.api_key_prefix && status === "approved" && <span style={{ fontSize: 10, color: C.dim, fontFamily: "'JetBrains Mono',monospace" }}>{String(client.api_key_prefix)}…</span>}
      <div style={{ flex: 1 }} />
      {status === "pending" && <>
        <Inp value={approvalID} onChange={(e) => setApprovalID(e.target.value)} placeholder="Governance approval ID (if required)" style={{ maxWidth: 240 }} />
        <Btn small primary onClick={() => void approve()} disabled={Boolean(busy)}>{busy === "Approve" ? "Approving..." : "Approve"}</Btn>
      </>}
      {status === "approved" && <Btn small onClick={rotate} disabled={Boolean(busy)}>{busy === "Rotate key" ? "Rotating..." : "Rotate key"}</Btn>}
      {status !== "revoked" && <Btn small danger onClick={revoke} disabled={Boolean(busy)}>{busy === "Revoke" ? "Revoking..." : "Revoke"}</Btn>}
    </div>
    {issued && issued.clientID === id && <OneTimeKeyPanel issued={issued} onDismiss={() => setIssued(null)} />}
  </div>;
}
