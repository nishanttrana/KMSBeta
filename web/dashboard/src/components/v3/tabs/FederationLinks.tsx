import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../../lib/auth";
import {
  createFederationLink,
  getFederationKeyState,
  linkTone,
  listFederationLinks,
  promoteFederatedKey,
  removeFederationLink,
  syncFederationLink,
  type FederationKeyState,
  type FederationLink,
  type FederationPeer
} from "../../../lib/federation";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Inp, Sel } from "../legacyPrimitives";

// The keys this installation replicates, and a key's federation state
// with failover (promotion) here.

export function FederationLinks({ session, peers }: { session: AuthSession; peers: FederationPeer[] }) {
  const [links, setLinks] = useState<FederationLink[] | null>(null);
  const [keyID, setKeyID] = useState("");
  const [peerID, setPeerID] = useState("");
  const [notice, setNotice] = useState("");
  const peerName = (id: string) => peers.find((p) => p.id === id)?.name ?? id;

  const load = useCallback(async () => {
    try {
      setLinks(await listFederationLinks(session));
    } catch (e) {
      setNotice(errMsg(e));
    }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const act = async (fn: () => Promise<unknown>, msg: string) => {
    try {
      await fn();
      setNotice(msg);
      void load();
    } catch (e) {
      setNotice(errMsg(e));
    }
  };

  return (
    <div style={{ borderTop: `1px solid ${C.border}`, marginTop: 10, paddingTop: 8 }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: C.text, marginBottom: 6 }}>Replicated keys</div>
      <div style={{ display: "grid", gridTemplateColumns: "1.6fr 1fr auto", gap: 6, alignItems: "center", marginBottom: 6 }}>
        <Inp aria-label="Key to replicate" placeholder="key ID (export allowed, not in the HSM)" value={keyID} onChange={(e: any) => setKeyID(e.target.value)} />
        <Sel aria-label="Replicate to" value={peerID} onChange={(e: any) => setPeerID(e.target.value)}>
          <option value="">peer…</option>
          {peers.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </Sel>
        <Btn small primary disabled={!keyID.trim() || !peerID} onClick={() => void act(() => createFederationLink(session, keyID.trim(), peerID), "Replication started.")}>Replicate</Btn>
      </div>
      {notice && <div style={{ fontSize: 11, color: C.dim, marginBottom: 6 }}>{notice}</div>}
      {links === null ? <div style={{ fontSize: 11, color: C.muted }}>Loading…</div>
        : links.length === 0 ? <div style={{ fontSize: 11, color: C.muted }}>No key is replicated.</div>
          : links.map((l) => (
            <div key={l.id} data-testid="federation-link" style={{ borderTop: `1px solid ${C.border}`, padding: "6px 0" }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                <span style={{ fontSize: 11.5, color: C.text, fontFamily: "var(--font-mono)" }}>{`${l.key_id} → ${peerName(l.peer_id)}`}</span>
                <span style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <B c={linkTone(l.status)}>{l.status.replace("_", " ")}</B>
                  <Btn small onClick={() => void act(() => syncFederationLink(session, l.id), "Pushed.")}>Sync now</Btn>
                  <Btn small danger onClick={() => void act(() => removeFederationLink(session, l.id), "Replication stopped; the replica stays on the peer.")}>Stop</Btn>
                </span>
              </div>
              <div style={{ fontSize: 10.5, color: l.last_error ? C.redFg : C.dim, marginTop: 2 }}>
                {l.last_error || (l.last_sync_at ? `Last pushed ${new Date(l.last_sync_at).toLocaleString()}` : "Not pushed yet")}
              </div>
            </div>
          ))}
      <KeyState session={session} />
    </div>
  );
}

function KeyState({ session }: { session: AuthSession }) {
  const [keyID, setKeyID] = useState("");
  const [state, setState] = useState<FederationKeyState | null>(null);
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const look = async () => {
    try {
      setState(await getFederationKeyState(session, keyID.trim()));
      setError("");
    } catch (e) {
      setError(errMsg(e));
    }
  };
  const promote = async () => {
    try {
      await promoteFederatedKey(session, keyID.trim(), reason.trim());
      setReason("");
      void look();
    } catch (e) {
      setError(errMsg(e));
    }
  };
  const role = state?.state.role;
  return (
    <div style={{ borderTop: `1px solid ${C.border}`, marginTop: 10, paddingTop: 8 }}>
      <div style={{ fontSize: 11, color: C.dim, marginBottom: 6 }}>A key's role here, and failover</div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 6 }}>
        <Inp aria-label="Federation key ID" placeholder="key ID" value={keyID} onChange={(e: any) => setKeyID(e.target.value)} />
        <Btn small disabled={!keyID.trim()} onClick={() => void look()}>Show</Btn>
      </div>
      {error && <div style={{ fontSize: 11, color: C.redFg, marginTop: 6 }}>{error}</div>}
      {state && (
        <div data-testid="federation-state" style={{ fontSize: 11, color: C.text, marginTop: 6 }}>
          <B c={role === "primary" ? "green" : role === "none" ? "neutral" : "amber"}>{role}</B>
          {state.state.epoch ? <span style={{ color: C.dim, marginLeft: 6 }}>{`epoch ${state.state.epoch}`}</span> : null}
          <span style={{ color: C.dim, marginLeft: 6 }}>{state.versions.map((v) => `v${v.version} ${v.status} ${v.kcv}`).join(" · ")}</span>
          {(role === "replica" || role === "demoted") && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 6, marginTop: 6 }}>
              <Inp aria-label="Promotion reason" placeholder="why this installation takes over (at least 10 characters)" value={reason} onChange={(e: any) => setReason(e.target.value)} />
              <Btn small danger disabled={reason.trim().length < 10} onClick={() => void promote()}>Promote here</Btn>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
