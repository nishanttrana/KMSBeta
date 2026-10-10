import { useCallback, useEffect, useState } from "react";
import { Network, Plus, X } from "lucide-react";
import { Btn, Inp } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import { approvePrivateEndpoint, listPrivateEndpoints, withdrawPrivateEndpoint, type PrivateEndpoint } from "../../../lib/privateEndpoints";
import type { AuthSession } from "../../../lib/auth";

// Private address ranges a root administrator approved for a tenant's
// source connections (git, object storage). A connection may name a host
// inside one, and Crypto Discovery sends its credential to a private
// address only inside one. A tenant sees its own ranges; the root tenant
// sees every tenant's and is the only one that can approve or withdraw.
const MONO = "'JetBrains Mono',monospace";

export function PrivateEndpoints({ session }: { session: AuthSession }) {
  const [items, setItems] = useState<PrivateEndpoint[]>([]);
  const [canApprove, setCanApprove] = useState(false);
  const [error, setError] = useState("");
  const [tenant, setTenant] = useState("");
  const [cidr, setCidr] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(""); // why the last approve or withdraw was refused

  const load = useCallback(async () => {
    try {
      const res = await listPrivateEndpoints(session);
      setItems(res.items);
      setCanApprove(res.canApprove);
      setError("");
    } catch (e) {
      setItems([]);
      setError(errMsg(e));
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: reload per tenant session.
  }, [session?.tenantId, session?.token]);

  useEffect(() => { void load(); }, [load]);

  const approve = async () => {
    if (!tenant.trim() || !cidr.trim()) return;
    setBusy(true);
    setFailed("");
    try {
      await approvePrivateEndpoint(session, tenant.trim(), cidr.trim(), note.trim());
      setCidr(""); setNote("");
      await load();
    } catch (e) {
      setFailed(`Range not approved: ${errMsg(e)}`);
    } finally {
      setBusy(false);
    }
  };
  const withdraw = async (e: PrivateEndpoint) => {
    setFailed("");
    try {
      await withdrawPrivateEndpoint(session, e.id);
      await load();
    } catch (err) {
      setFailed(`Approval not withdrawn: ${errMsg(err)}`);
    }
  };

  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, marginTop: 14 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "12px 14px", borderBottom: `1px solid ${C.border}` }}>
        <Network size={14} color={C.accentFg} />
        <span style={{ fontSize: 13, fontWeight: 600, color: C.text }}>Private endpoints</span>
        <span style={{ fontSize: 11, color: C.muted }}>{items.length} approved</span>
        <span style={{ marginLeft: "auto", fontSize: 10.5, color: C.muted }} title="A Git or storage connection may name a host inside an approved range, and its credential is sent to a private address only inside one. Loopback, link-local, metadata and KMS platform addresses can never be approved.">
          For Git and storage connections on your own network
        </span>
      </div>
      {canApprove && (
        <div style={{ display: "grid", gridTemplateColumns: "minmax(120px,1fr) minmax(160px,1.2fr) minmax(160px,2fr) auto", gap: 8, padding: "10px 14px", borderBottom: `1px solid ${C.border}` }}>
          <Inp mono placeholder="tenant" value={tenant} onChange={(e) => setTenant(e.target.value)} />
          <Inp mono placeholder="10.4.0.0/24 or 10.4.0.20" value={cidr} onChange={(e) => setCidr(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void approve(); }} />
          <Inp placeholder="note (what is there)" value={note} onChange={(e) => setNote(e.target.value)} />
          <Btn primary onClick={() => void approve()} disabled={busy || !tenant.trim() || !cidr.trim()}><Plus size={12} />{busy ? "Approving..." : "Approve"}</Btn>
        </div>
      )}
      {failed && <div style={{ padding: "8px 14px", fontSize: 11.5, color: C.redFg, borderBottom: `1px solid ${C.border}` }}>{failed}</div>}
      {error ? (
        <div style={{ padding: 14, fontSize: 11.5, color: C.redFg }}>Private endpoints unavailable: {error}</div>
      ) : items.length ? (
        items.map((e, i) => (
          <div key={e.id} style={{ display: "grid", gridTemplateColumns: "minmax(90px,1fr) minmax(140px,1.2fr) minmax(140px,2fr) auto 28px", alignItems: "center", gap: 10, padding: "8px 14px", borderTop: i ? `1px solid ${C.border}` : "none", fontSize: 11.5 }}>
            <span style={{ fontFamily: MONO, color: C.dim }}>{e.tenant_id}</span>
            <span style={{ fontFamily: MONO, color: C.text, fontWeight: 600 }}>{e.cidr}</span>
            <span style={{ color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.note || "-"}</span>
            <span style={{ fontSize: 10.5, color: C.muted, whiteSpace: "nowrap" }}>{e.created_by} · {new Date(e.created_at).toLocaleDateString()}</span>
            {canApprove ? (
              <button type="button" aria-label={`Withdraw ${e.cidr} for ${e.tenant_id}`} onClick={() => void withdraw(e)} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", display: "inline-flex" }}><X size={13} /></button>
            ) : <span />}
          </div>
        ))
      ) : (
        <div style={{ padding: 18, textAlign: "center", fontSize: 11.5, color: C.muted }}>
          {canApprove ? "No private ranges approved" : "No private ranges approved for this tenant. A root administrator approves them here."}
        </div>
      )}
    </div>
  );
}
