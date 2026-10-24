import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../../lib/auth";
import {
  addFederationPeer,
  getFederationIdentity,
  listFederationPeers,
  parseIdentity,
  removeFederationPeer,
  type FederationIdentity,
  type FederationPeer
} from "../../../lib/federation";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { Btn, FG, Inp, Row2, Txt } from "../legacyPrimitives";
import { FederationLinks } from "./FederationLinks";

// Key federation (docs/FEDERATION.md): this installation's identity, the
// installations it federates with, the keys it replicates, and failover.

export function FederationPanel({ session }: { session: AuthSession }) {
  const [identity, setIdentity] = useState<FederationIdentity | null>(null);
  const [peers, setPeers] = useState<FederationPeer[] | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [adding, setAdding] = useState(false);

  const load = useCallback(async () => {
    try {
      const [id, ps] = await Promise.all([getFederationIdentity(session), listFederationPeers(session)]);
      setIdentity(id);
      setPeers(ps);
      setError("");
    } catch (e) {
      setError(errMsg(e));
    }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const identityJSON = identity ? JSON.stringify(identity, null, 2) : "";
  const remove = async (p: FederationPeer) => {
    try {
      await removeFederationPeer(session, p.id);
      setNotice(`Peer ${p.name} removed.`);
      void load();
    } catch (e) {
      setNotice(errMsg(e));
    }
  };

  if (error) return <div style={{ fontSize: 11, color: C.redFg }}>{`Federation unavailable: ${error}`}</div>;
  return (
    <div>
      <div style={{ fontSize: 11, color: C.dim, marginBottom: 8 }}>
        Keys replicate to other installations, sealed and signed. A replica serves operations; promote it to fail over.
      </div>
      <div style={{ fontSize: 11, fontWeight: 600, color: C.text }}>This installation</div>
      <div data-testid="federation-fingerprint" style={{ fontSize: 10.5, color: C.dim, fontFamily: "var(--font-mono)", margin: "3px 0 6px" }}>
        {identity ? `Fingerprint ${identity.fingerprint}` : "Loading…"}
      </div>
      {identity && (
        <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
          <Btn small onClick={() => { void navigator.clipboard?.writeText(identityJSON); setNotice("Identity copied: paste it on the other installation, under Add peer."); }}>Copy identity</Btn>
        </div>
      )}
      {notice && <div style={{ fontSize: 11, color: C.dim, marginBottom: 6 }}>{notice}</div>}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderTop: `1px solid ${C.border}`, paddingTop: 8 }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: C.text }}>Peers</span>
        {!adding && <Btn small primary onClick={() => setAdding(true)}>Add peer</Btn>}
      </div>
      {adding && <PeerForm session={session} onDone={(msg) => { setAdding(false); setNotice(msg); void load(); }} onCancel={() => setAdding(false)} />}
      {peers === null ? <div style={{ fontSize: 11, color: C.muted }}>Loading…</div>
        : peers.length === 0 ? <div style={{ fontSize: 11, color: C.muted, padding: "6px 0" }}>No peers.</div>
          : peers.map((p) => (
            <div key={p.id} data-testid="federation-peer" style={{ display: "flex", justifyContent: "space-between", gap: 8, padding: "6px 0", borderTop: `1px solid ${C.border}` }}>
              <span style={{ fontSize: 11.5, color: C.text }}>
                <b>{p.name}</b> <span style={{ color: C.dim }}>{`${p.url} · tenant ${p.peer_tenant_id} · ${p.fingerprint.slice(0, 16)}…`}</span>
              </span>
              <Btn small danger onClick={() => void remove(p)}>Remove</Btn>
            </div>
          ))}
      {peers && <FederationLinks session={session} peers={peers} />}
    </div>
  );
}

function PeerForm({ session, onDone, onCancel }: { session: AuthSession; onDone: (msg: string) => void; onCancel: () => void }) {
  const [name, setName] = useState("");
  const [url, setURL] = useState("https://");
  const [tenant, setTenant] = useState("");
  const [identityText, setIdentityText] = useState("");
  const [caPEM, setCAPEM] = useState("");
  const [clientID, setClientID] = useState("");
  const [apiKey, setAPIKey] = useState("");
  const [error, setError] = useState("");
  const identity = parseIdentity(identityText);
  const save = async () => {
    if (!identity) return;
    try {
      const p = await addFederationPeer(session, { name: name.trim(), url: url.trim(), peer_tenant_id: tenant.trim(), identity, ca_pem: caPEM, client_id: clientID.trim(), api_key: apiKey });
      onDone(`Peer ${p.name} added (${p.fingerprint.slice(0, 16)}…). Confirm the fingerprint with its administrator.`);
    } catch (e) {
      setError(errMsg(e));
    }
  };
  return (
    <div style={{ border: `1px solid ${C.border}`, borderRadius: 6, padding: 10, margin: "8px 0" }}>
      <Row2>
        <FG label="Name" required><Inp aria-label="Peer name" value={name} onChange={(e: any) => setName(e.target.value)} placeholder="dr-site" /></FG>
        <FG label="Address" required hint="The other installation's edge."><Inp aria-label="Peer URL" value={url} onChange={(e: any) => setURL(e.target.value)} /></FG>
      </Row2>
      <FG label="Its identity" required hint="Copy identity, on the other installation's Federation dialog."><Txt aria-label="Peer identity" rows={4} value={identityText} onChange={(e: any) => setIdentityText(e.target.value)} /></FG>
      <Row2>
        <FG label="REST client there" required hint="A client with key.federation.receive."><Inp aria-label="Peer client ID" value={clientID} onChange={(e: any) => setClientID(e.target.value)} /></FG>
        <FG label="Its API key" required><Inp aria-label="Peer API key" type="password" value={apiKey} onChange={(e: any) => setAPIKey(e.target.value)} /></FG>
      </Row2>
      <Row2>
        <FG label="Tenant there" hint="Default: the identity's tenant."><Inp aria-label="Peer tenant" value={tenant} onChange={(e: any) => setTenant(e.target.value)} /></FG>
        <FG label="Its CA (PEM)" hint="When its certificate comes from its own CA."><Txt aria-label="Peer CA" rows={2} value={caPEM} onChange={(e: any) => setCAPEM(e.target.value)} /></FG>
      </Row2>
      {error && <div style={{ fontSize: 11, color: C.redFg, marginBottom: 6 }}>{error}</div>}
      <div style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
        <Btn small onClick={onCancel}>Cancel</Btn>
        <Btn small primary disabled={!name.trim() || !identity || !clientID.trim() || !apiKey} onClick={() => void save()}>Add peer</Btn>
      </div>
    </div>
  );
}
