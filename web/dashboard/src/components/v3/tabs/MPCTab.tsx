// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import { KeyRound, PenTool, Lock } from "lucide-react";
import { listAuthUsers } from "../../../lib/authAdmin";
import {
  contributeMPCDecrypt,
  contributeMPCDKG,
  contributeMPCSign,
  getMPCDecryptResult,
  getMPCSignResult,
  initiateMPCDecrypt,
  initiateMPCDKG,
  initiateMPCSign,
  listMPCKeys
} from "../../../lib/mpc";
import {
  B,
  Btn,
  Card,
  Chk,
  FG,
  Inp,
  Modal,
  Row2,
  Row3,
  Section,
  Sel,
  Txt
} from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";

export const MPCTab = ({ session, onToast }: any) => {
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState("");
  const [modal, setModal] = useState<"dkg" | "sign" | "decrypt" | null>(null);
  const [keys, setKeys] = useState<any[]>([]);
  const [users, setUsers] = useState<any[]>([]);
  const [lastResult, setLastResult] = useState<any>(null);

  const [dkgName, setDKGName] = useState("custody-distributed");
  const [dkgThreshold, setDKGThreshold] = useState(3);
  const [dkgTotal, setDKGTotal] = useState(5);
  const [dkgAlgorithm, setDKGAlgorithm] = useState("ECDSA_P256_GG20");
  const [dkgTimeout, setDKGTimeout] = useState("30 minutes");
  const [dkgPurpose, setDKGPurpose] = useState("Threshold signing");
  const [dkgParticipants, setDKGParticipants] = useState<string[]>(["node-1", "node-2", "node-3"]);

  const [signKeyID, setSignKeyID] = useState("");
  const [signInput, setSignInput] = useState("deadbeef");
  const [signParticipants, setSignParticipants] = useState<string[]>([]);

  const [decryptKeyID, setDecryptKeyID] = useState("");
  const [decryptCiphertext, setDecryptCiphertext] = useState("");
  const [decryptParticipants, setDecryptParticipants] = useState<string[]>([]);

  const algorithmOptions = [
    { v: "ECDSA_P256_GG20", l: "ECDSA-P256 (GG20)" },
    { v: "ECDSA_P384_GG20", l: "ECDSA-P384 (GG20)" },
    { v: "ED25519_FROST", l: "EdDSA-Ed25519 (FROST)" },
    { v: "SCHNORR_FROST", l: "Schnorr (FROST)" }
  ];

  const participantOptions = useMemo(() => {
    const base = [
      { id: "node-1", label: "Admin A (alice@bank.com)" },
      { id: "node-2", label: "Admin B (bob@bank.com)" },
      { id: "node-3", label: "HSM Partition (automated)" },
      { id: "node-4", label: "Escrow Agent" },
      { id: "node-5", label: "DR Site" }
    ];
    const dynamic = (Array.isArray(users) ? users : [])
      .filter((u) => String(u?.status || "").toLowerCase() === "active")
      .map((u) => ({
        id: String(u?.username || "").trim(),
        label: `${String(u?.username || "").trim()} (${String(u?.email || "-")})`
      }))
      .filter((u) => u.id);

    const byID = new Map<string, any>();
    [...base, ...dynamic].forEach((item) => {
      if (!byID.has(item.id)) {
        byID.set(item.id, item);
      }
    });
    return Array.from(byID.values());
  }, [users]);

  const refresh = async (silent = false) => {
    if (!session?.token) {
      setKeys([]);
      return;
    }
    if (!silent) setLoading(true);
    try {
      const [keyItems, userItems] = await Promise.all([
        listMPCKeys(session, { limit: 200 }),
        listAuthUsers(session).catch(() => [])
      ]);
      setKeys(Array.isArray(keyItems) ? keyItems : []);
      setUsers(Array.isArray(userItems) ? userItems : []);
      if (!signKeyID && keyItems?.[0]?.id) setSignKeyID(String(keyItems[0].id));
      if (!decryptKeyID && keyItems?.[0]?.id) setDecryptKeyID(String(keyItems[0].id));
    } catch (error) {
      onToast?.(`MPC load failed: ${errMsg(error)}`);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    if (!session?.token) {
      setKeys([]);
      setUsers([]);
      return;
    }
    void refresh();
  }, [session?.token, session?.tenantId]);

  const selectedSignKey = useMemo(
    () => keys.find((k) => String(k?.id || "") === String(signKeyID || "")) || null,
    [keys, signKeyID]
  );
  const selectedDecryptKey = useMemo(
    () => keys.find((k) => String(k?.id || "") === String(decryptKeyID || "")) || null,
    [keys, decryptKeyID]
  );

  useEffect(() => {
    if (selectedSignKey) {
      const parts = Array.isArray(selectedSignKey.participants) ? selectedSignKey.participants : [];
      if (parts.length) {
        setSignParticipants((prev) => (prev.length ? prev : parts.slice(0, Number(selectedSignKey.threshold || 2))));
      }
    }
  }, [selectedSignKey?.id]);

  useEffect(() => {
    if (selectedDecryptKey) {
      const parts = Array.isArray(selectedDecryptKey.participants) ? selectedDecryptKey.participants : [];
      if (parts.length) {
        setDecryptParticipants((prev) => (prev.length ? prev : parts.slice(0, Number(selectedDecryptKey.threshold || 2))));
      }
    }
  }, [selectedDecryptKey?.id]);

  const toggle = (items: string[], id: string) =>
    items.includes(id) ? items.filter((x) => x !== id) : [...items, id];

  const nowIso = () => new Date().toISOString();

  const normalizeProtocol = (algorithm: string) => {
    const a = String(algorithm || "").toUpperCase();
    if (a.includes("FROST") || a.includes("ED25519") || a.includes("SCHNORR")) return "FROST";
    if (a.includes("SHAMIR")) return "Shamir";
    return "Feldman VSS";
  };

  const fmtAgo = (value: string) => {
    const ts = new Date(String(value || ""));
    if (Number.isNaN(ts.getTime())) return "Never used";
    const sec = Math.max(1, Math.floor((Date.now() - ts.getTime()) / 1000));
    if (sec < 60) return `${sec}s ago`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
    if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
    return `${Math.floor(sec / 86400)}d ago`;
  };

  const availableCounts = (key: any) => {
    const active = Number(key?.metadata?.active_share_count || 0);
    const total = Math.max(1, Number(key?.participant_count || key?.participantCount || 0));
    return { active, total };
  };

  const autoContribute = async (type: "dkg" | "sign" | "decrypt", ceremonyID: string, parties: string[]) => {
    for (const partyID of parties) {
      if (type === "dkg") {
        await contributeMPCDKG(session, ceremonyID, { party_id: partyID, payload: { auto: true, submitted_at: nowIso() } });
      } else if (type === "sign") {
        await contributeMPCSign(session, ceremonyID, { party_id: partyID });
      } else {
        await contributeMPCDecrypt(session, ceremonyID, { party_id: partyID });
      }
    }
  };

  const submitDKG = async () => {
    const threshold = Math.max(2, Math.trunc(Number(dkgThreshold || 0)));
    const requestedTotal = Math.max(threshold, Math.trunc(Number(dkgTotal || 0)) || threshold);
    const allIDs = participantOptions.map((p) => p.id);
    let chosen = dkgParticipants.filter((id) => allIDs.includes(id));
    if (!chosen.length) chosen = allIDs.slice(0, requestedTotal);
    if (chosen.length < requestedTotal) {
      const extras = allIDs.filter((id) => !chosen.includes(id)).slice(0, requestedTotal - chosen.length);
      chosen = [...chosen, ...extras];
    }
    chosen = chosen.slice(0, requestedTotal);
    if (chosen.length < threshold) {
      onToast?.("Select enough participants to satisfy threshold.");
      return;
    }

    setBusy("dkg");
    try {
      const ceremony = await initiateMPCDKG(session, {
        key_name: String(dkgName || "mpc-key").trim() || "mpc-key",
        algorithm: dkgAlgorithm,
        threshold,
        participants: chosen,
        created_by: String(session?.username || "system")
      });
      await autoContribute("dkg", String(ceremony.id || ""), chosen.slice(0, threshold));
      await refresh(true);
      setModal(null);
      onToast?.(`DKG completed: ${String(ceremony.key_id || "").slice(0, 16)}...`);
    } catch (error) {
      onToast?.(`DKG failed: ${errMsg(error)}`);
    } finally {
      setBusy("");
    }
  };

  const submitSign = async () => {
    const key = selectedSignKey;
    if (!key) {
      onToast?.("Select an MPC key for threshold signing.");
      return;
    }
    const threshold = Math.max(2, Number(key?.threshold || 2));
    const parties = (signParticipants.length ? signParticipants : Array.isArray(key.participants) ? key.participants : []).slice(
      0,
      Math.max(threshold, signParticipants.length || 0)
    );
    if (parties.length < threshold) {
      onToast?.("Selected participants do not satisfy key threshold.");
      return;
    }
    if (!String(signInput || "").trim()) {
      onToast?.("Message hash/input is required.");
      return;
    }

    setBusy("sign");
    try {
      const ceremony = await initiateMPCSign(session, {
        key_id: String(key.id),
        message_hash: String(signInput || "").trim(),
        participants: parties,
        created_by: String(session?.username || "system")
      });
      await autoContribute("sign", String(ceremony.id || ""), parties.slice(0, threshold));
      const result = await getMPCSignResult(session, String(ceremony.id || ""));
      setLastResult({ type: "sign", key: key.name, at: new Date().toISOString(), result });
      await refresh(true);
      setModal(null);
      onToast?.(`Threshold signature complete: ${String(result?.signature_b64 || result?.signature || "").slice(0, 20)}...`);
    } catch (error) {
      onToast?.(`Threshold sign failed: ${errMsg(error)}`);
    } finally {
      setBusy("");
    }
  };

  const submitDecrypt = async () => {
    const key = selectedDecryptKey;
    if (!key) {
      onToast?.("Select an MPC key for threshold decryption.");
      return;
    }
    const threshold = Math.max(2, Number(key?.threshold || 2));
    const parties = (
      decryptParticipants.length ? decryptParticipants : Array.isArray(key.participants) ? key.participants : []
    ).slice(0, Math.max(threshold, decryptParticipants.length || 0));
    if (parties.length < threshold) {
      onToast?.("Selected participants do not satisfy key threshold.");
      return;
    }
    if (!String(decryptCiphertext || "").trim()) {
      onToast?.("Ciphertext is required.");
      return;
    }

    setBusy("decrypt");
    try {
      const ceremony = await initiateMPCDecrypt(session, {
        key_id: String(key.id),
        ciphertext: String(decryptCiphertext || "").trim(),
        participants: parties,
        created_by: String(session?.username || "system")
      });
      await autoContribute("decrypt", String(ceremony.id || ""), parties.slice(0, threshold));
      const result = await getMPCDecryptResult(session, String(ceremony.id || ""));
      setLastResult({ type: "decrypt", key: key.name, at: new Date().toISOString(), result });
      await refresh(true);
      setModal(null);
      onToast?.("Threshold decrypt completed.");
    } catch (error) {
      onToast?.(`Threshold decrypt failed: ${errMsg(error)}`);
    } finally {
      setBusy("");
    }
  };

  return (
    <div>
      <Section
        title="MPC Engine"
        actions={
          <Btn small onClick={() => void refresh()} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh"}
          </Btn>
        }
      >
        <Row3>
          <Card>
            <div style={{ display: "inline-flex", padding: "3px 7px", borderRadius: 999, background: C.purpleDim, color: C.purple, fontSize: 9, fontWeight: 700, marginBottom: 8 }}>Feldman VSS</div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <KeyRound size={18} color={C.accent} />
              <div style={{ fontSize: 20, color: C.text, fontWeight: 700, lineHeight: 1.1 }}>Distributed Key Gen</div>
            </div>
            <div style={{ fontSize: 11, color: C.dim, marginTop: 6 }}>No single node holds the full key.</div>
            <div style={{ marginTop: 12 }}><Btn primary onClick={() => setModal("dkg")}>Initiate</Btn></div>
          </Card>
          <Card>
            <div style={{ display: "inline-flex", padding: "3px 7px", borderRadius: 999, background: C.purpleDim, color: C.purple, fontSize: 9, fontWeight: 700, marginBottom: 8 }}>GG20 / FROST</div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <PenTool size={18} color={C.accent} />
              <div style={{ fontSize: 20, color: C.text, fontWeight: 700, lineHeight: 1.1 }}>Threshold Signing</div>
            </div>
            <div style={{ fontSize: 11, color: C.dim, marginTop: 6 }}>T-of-N sign without reconstructing key externally.</div>
            <div style={{ marginTop: 12 }}><Btn primary onClick={() => setModal("sign")} disabled={!keys.length}>Initiate</Btn></div>
          </Card>
          <Card>
            <div style={{ display: "inline-flex", padding: "3px 7px", borderRadius: 999, background: C.purpleDim, color: C.purple, fontSize: 9, fontWeight: 700, marginBottom: 8 }}>Shamir SSS</div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Lock size={18} color={C.accent} />
              <div style={{ fontSize: 20, color: C.text, fontWeight: 700, lineHeight: 1.1 }}>Threshold Decryption</div>
            </div>
            <div style={{ fontSize: 11, color: C.dim, marginTop: 6 }}>T-of-N decrypt cooperatively with active shares.</div>
            <div style={{ marginTop: 12 }}><Btn primary onClick={() => setModal("decrypt")} disabled={!keys.length}>Initiate</Btn></div>
          </Card>
        </Row3>
      </Section>

      <Section title="Active MPC Keys">
        <Card style={{ padding: 0, overflow: "hidden" }}>
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr .8fr .8fr 1fr", padding: "10px 14px", borderBottom: `1px solid ${C.border}`, fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>
            <div>Key</div>
            <div>Protocol</div>
            <div>Threshold</div>
            <div>Shares</div>
            <div style={{ textAlign: "right" }}>Last Action</div>
          </div>
          <div style={{ maxHeight: 280, overflowY: "auto" }}>
            {keys.map((key: any) => {
              const counts = availableCounts(key);
              return (
                <div key={String(key.id)} style={{ display: "grid", gridTemplateColumns: "2fr 1fr .8fr .8fr 1fr", padding: "11px 14px", borderBottom: `1px solid ${C.border}`, alignItems: "center" }}>
                  <div>
                    <div style={{ fontSize: 12, color: C.text, fontWeight: 700 }}>{String(key.name || key.id)}</div>
                    <div style={{ fontSize: 10, color: C.muted, fontFamily: "'JetBrains Mono',monospace" }}>{String(key.algorithm || "-")}</div>
                  </div>
                  <div><B c="purple">{normalizeProtocol(String(key.algorithm || ""))}</B></div>
                  <div style={{ fontSize: 11, color: C.accent, fontFamily: "'JetBrains Mono',monospace" }}>{`${Number(key.threshold || 0)}-of-${Number(key.participant_count || 0)}`}</div>
                  <div style={{ fontSize: 11, color: counts.active >= Number(key.threshold || 0) ? C.green : C.amber }}>{`${counts.active}/${counts.total}`} {counts.active >= Number(key.threshold || 0) ? "ready" : "below"}</div>
                  <div style={{ fontSize: 10, color: C.dim, textAlign: "right" }}>{String(key.status || "").toLowerCase() === "active" ? `Ready (${fmtAgo(String(key.updated_at || key.created_at || ""))})` : String(key.status || "")}</div>
                </div>
              );
            })}
            {!keys.length && <div style={{ padding: "12px 14px", fontSize: 11, color: C.dim }}>{loading ? "Loading MPC keys..." : "No MPC keys created yet."}</div>}
          </div>
        </Card>

        {lastResult && (
          <Card style={{ marginTop: 10 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
              <div style={{ fontSize: 12, color: C.text, fontWeight: 700 }}>Last MPC Result</div>
              <B c={String(lastResult.type) === "sign" ? "blue" : "green"}>{String(lastResult.type || "").toUpperCase()}</B>
            </div>
            <div style={{ fontSize: 10, color: C.muted, marginBottom: 6 }}>{`${String(lastResult.key || "-")} | ${new Date(String(lastResult.at || Date.now())).toLocaleString()}`}</div>
            <Txt rows={5} value={JSON.stringify(lastResult.result || {}, null, 2)} readOnly />
          </Card>
        )}
      </Section>

      <Modal open={modal === "dkg"} onClose={() => setModal(null)} title="Start DKG Ceremony" wide>
        <Row2>
          <FG label="Threshold (T)" required><Inp type="number" min={2} value={String(dkgThreshold)} onChange={(e) => setDKGThreshold(Math.max(2, Number(e.target.value || 2)))} /></FG>
          <FG label="Total Parties (N)" required><Inp type="number" min={2} value={String(dkgTotal)} onChange={(e) => setDKGTotal(Math.max(2, Number(e.target.value || 2)))} /></FG>
        </Row2>
        <FG label="Key Name" required><Inp value={dkgName} onChange={(e) => setDKGName(e.target.value)} placeholder="custody-distributed" /></FG>
        <FG label="Key Algorithm"><Sel value={dkgAlgorithm} onChange={(e) => setDKGAlgorithm(e.target.value)}>{algorithmOptions.map((item) => <option key={item.v} value={item.v}>{item.l}</option>)}</Sel></FG>
        <FG label="Participants">{(participantOptions || []).map((p) => <Chk key={p.id} label={p.label} checked={dkgParticipants.includes(p.id)} onChange={() => setDKGParticipants((prev) => toggle(prev, p.id))} />)}</FG>
        <Row2>
          <FG label="Timeout"><Sel value={dkgTimeout} onChange={(e) => setDKGTimeout(e.target.value)}><option>30 minutes</option><option>1 hour</option><option>4 hours</option><option>24 hours</option></Sel></FG>
          <FG label="Purpose"><Inp value={dkgPurpose} onChange={(e) => setDKGPurpose(e.target.value)} placeholder="Threshold signing" /></FG>
        </Row2>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
          <Btn onClick={() => setModal(null)} disabled={busy === "dkg"}>Cancel</Btn>
          <Btn primary onClick={() => void submitDKG()} disabled={busy === "dkg"}>{busy === "dkg" ? "Initiating..." : "Initiate DKG"}</Btn>
        </div>
      </Modal>

      <Modal open={modal === "sign"} onClose={() => setModal(null)} title="Start Threshold Signing" wide>
        <FG label="MPC Key" required>
          <Sel value={signKeyID} onChange={(e) => setSignKeyID(e.target.value)}>
            {(keys || []).map((k) => <option key={k.id} value={k.id}>{`${k.name} (${k.algorithm})`}</option>)}
            {!keys.length && <option value="">No MPC keys available</option>}
          </Sel>
        </FG>
        <FG label="Message Hash / Input" required hint="Hex, Base64, or UTF-8 input accepted.">
          <Txt rows={4} value={signInput} onChange={(e) => setSignInput(e.target.value)} placeholder="deadbeef" />
        </FG>
        <FG label="Participants">{(Array.isArray(selectedSignKey?.participants) ? selectedSignKey.participants : []).map((id: string) => <Chk key={id} label={id} checked={signParticipants.includes(id)} onChange={() => setSignParticipants((prev) => toggle(prev, id))} />)}</FG>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
          <Btn onClick={() => setModal(null)} disabled={busy === "sign"}>Cancel</Btn>
          <Btn primary onClick={() => void submitSign()} disabled={busy === "sign" || !selectedSignKey}>{busy === "sign" ? "Signing..." : "Initiate Sign"}</Btn>
        </div>
      </Modal>

      <Modal open={modal === "decrypt"} onClose={() => setModal(null)} title="Start Threshold Decryption" wide>
        <FG label="MPC Key" required>
          <Sel value={decryptKeyID} onChange={(e) => setDecryptKeyID(e.target.value)}>
            {(keys || []).map((k) => <option key={k.id} value={k.id}>{`${k.name} (${k.algorithm})`}</option>)}
            {!keys.length && <option value="">No MPC keys available</option>}
          </Sel>
        </FG>
        <FG label="Ciphertext" required hint='Accepted formats: JSON {"nonce","ciphertext","aad"}, nonce:ciphertext, or packed (12-byte nonce + ciphertext).'>
          <Txt rows={5} value={decryptCiphertext} onChange={(e) => setDecryptCiphertext(e.target.value)} placeholder='{"nonce":"...","ciphertext":"...","aad":"..."}' />
        </FG>
        <FG label="Participants">{(Array.isArray(selectedDecryptKey?.participants) ? selectedDecryptKey.participants : []).map((id: string) => <Chk key={id} label={id} checked={decryptParticipants.includes(id)} onChange={() => setDecryptParticipants((prev) => toggle(prev, id))} />)}</FG>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
          <Btn onClick={() => setModal(null)} disabled={busy === "decrypt"}>Cancel</Btn>
          <Btn primary onClick={() => void submitDecrypt()} disabled={busy === "decrypt" || !selectedDecryptKey}>{busy === "decrypt" ? "Decrypting..." : "Initiate Decrypt"}</Btn>
        </div>
      </Modal>
    </div>
  );
};

