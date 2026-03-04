import { useEffect, useMemo, useState } from "react";
import { KeyRound, PenTool, Lock, Users, Shield, Activity, Plus, Trash2, Edit3, Ban, FolderOpen } from "lucide-react";
import { listAuthUsers } from "../../../lib/authAdmin";
import type { MPCKey, MPCCeremony, MPCParticipant, MPCPolicy, MPCOverview, MPCOverviewStats } from "../../../lib/mpc";
import {
  contributeMPCDecrypt,
  contributeMPCDKG,
  contributeMPCSign,
  getMPCDecryptResult,
  getMPCSignResult,
  initiateMPCDecrypt,
  initiateMPCDKG,
  initiateMPCSign,
  listMPCKeys,
  getMPCOverview,
  listMPCCeremonies,
  createMPCParticipant,
  listMPCParticipants,
  updateMPCParticipant,
  deleteMPCParticipant,
  createMPCPolicy,
  listMPCPolicies,
  updateMPCPolicy,
  deleteMPCPolicy,
  revokeMPCKey,
  setMPCKeyGroup
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
  Stat,
  Tabs,
  Txt
} from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";

/* ── helpers ──────────────────────────────────────────────── */

const fmtAgo = (v: string | undefined) => {
  const ts = new Date(String(v || ""));
  if (Number.isNaN(ts.getTime())) return "—";
  const sec = Math.max(1, Math.floor((Date.now() - ts.getTime()) / 1000));
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
};

const statusColor = (s: string) => {
  const l = String(s || "").toLowerCase();
  if (l === "active" || l === "completed" || l === "ready") return "green";
  if (l === "pending" || l === "in_progress") return "amber";
  if (l === "revoked" || l === "failed" || l === "suspended") return "red";
  if (l === "inactive" || l === "expired") return "muted";
  return "accent";
};

const typeColor = (t: string) => {
  const l = String(t || "").toLowerCase();
  if (l === "dkg") return "purple";
  if (l === "sign") return "blue";
  if (l === "decrypt") return "green";
  return "accent";
};

const gridHeader = (cols: string, labels: string[]) => (
  <div style={{ display: "grid", gridTemplateColumns: cols, padding: "10px 14px", borderBottom: `1px solid ${C.border}`, fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>
    {labels.map((l, i) => <div key={i} style={i === labels.length - 1 ? { textAlign: "right" } : undefined}>{l}</div>)}
  </div>
);

const gridRow = (cols: string, children: React.ReactNode, key: string) => (
  <div key={key} style={{ display: "grid", gridTemplateColumns: cols, padding: "11px 14px", borderBottom: `1px solid ${C.border}`, alignItems: "center" }}>
    {children}
  </div>
);

const emptyRow = (msg: string) => (
  <div style={{ padding: "16px 14px", fontSize: 11, color: C.dim, textAlign: "center" }}>{msg}</div>
);

const nowIso = () => new Date().toISOString();

/* ── component ────────────────────────────────────────────── */

export const MPCTab = ({ session, onToast }: any) => {
  const [tab, setTab] = useState("Overview");
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState("");
  const [modal, setModal] = useState<string | null>(null);

  // Data
  const [overview, setOverview] = useState<MPCOverview | null>(null);
  const [keys, setKeys] = useState<MPCKey[]>([]);
  const [ceremonies, setCeremonies] = useState<MPCCeremony[]>([]);
  const [participants, setParticipants] = useState<MPCParticipant[]>([]);
  const [policies, setPolicies] = useState<MPCPolicy[]>([]);
  const [users, setUsers] = useState<any[]>([]);

  // Filters
  const [keyGroupFilter, setKeyGroupFilter] = useState("");
  const [keyStatusFilter, setKeyStatusFilter] = useState("");
  const [ceremonyTypeFilter, setCeremonyTypeFilter] = useState("");
  const [ceremonyStatusFilter, setCeremonyStatusFilter] = useState("");

  // DKG form
  const [dkgName, setDKGName] = useState("custody-distributed");
  const [dkgThreshold, setDKGThreshold] = useState(3);
  const [dkgTotal, setDKGTotal] = useState(5);
  const [dkgAlgorithm, setDKGAlgorithm] = useState("ECDSA_P256_GG20");
  const [dkgParticipants, setDKGParticipants] = useState<string[]>(["node-1", "node-2", "node-3"]);

  // Sign form
  const [signKeyID, setSignKeyID] = useState("");
  const [signInput, setSignInput] = useState("deadbeef");
  const [signParticipants, setSignParticipants] = useState<string[]>([]);

  // Decrypt form
  const [decryptKeyID, setDecryptKeyID] = useState("");
  const [decryptCiphertext, setDecryptCiphertext] = useState("");
  const [decryptParticipants, setDecryptParticipants] = useState<string[]>([]);

  // Participant form
  const [pName, setPName] = useState("");
  const [pEndpoint, setPEndpoint] = useState("");
  const [pPubKey, setPPubKey] = useState("");
  const [editingParticipant, setEditingParticipant] = useState<MPCParticipant | null>(null);

  // Policy form
  const [polName, setPolName] = useState("");
  const [polDesc, setPolDesc] = useState("");
  const [polKeyIds, setPolKeyIds] = useState("");
  const [polEnabled, setPolEnabled] = useState(true);
  const [polRules, setPolRules] = useState<{ rule_type: string; params: string }[]>([]);
  const [editingPolicy, setEditingPolicy] = useState<MPCPolicy | null>(null);

  // Revoke / Group modals
  const [revokeKeyId, setRevokeKeyId] = useState("");
  const [revokeReason, setRevokeReason] = useState("");
  const [groupKeyId, setGroupKeyId] = useState("");
  const [groupName, setGroupName] = useState("");

  const [lastResult, setLastResult] = useState<any>(null);

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
      if (!byID.has(item.id)) byID.set(item.id, item);
    });
    return Array.from(byID.values());
  }, [users]);

  /* ── data loading ─────────────────────────────────────── */

  const refresh = async (silent = false) => {
    if (!session?.token) return;
    if (!silent) setLoading(true);
    try {
      const [ov, keyItems, cerItems, partItems, polItems, userItems] = await Promise.all([
        getMPCOverview(session).catch(() => null),
        listMPCKeys(session, { limit: 200 }),
        listMPCCeremonies(session, { limit: 50 }),
        listMPCParticipants(session).catch(() => []),
        listMPCPolicies(session).catch(() => []),
        listAuthUsers(session).catch(() => [])
      ]);
      setOverview(ov);
      setKeys(Array.isArray(keyItems) ? keyItems : []);
      setCeremonies(Array.isArray(cerItems) ? cerItems : []);
      setParticipants(Array.isArray(partItems) ? partItems : []);
      setPolicies(Array.isArray(polItems) ? polItems : []);
      setUsers(Array.isArray(userItems) ? userItems : []);
      if (!signKeyID && keyItems?.[0]?.id) setSignKeyID(keyItems[0].id);
      if (!decryptKeyID && keyItems?.[0]?.id) setDecryptKeyID(keyItems[0].id);
    } catch (error) {
      onToast?.(`MPC load failed: ${errMsg(error)}`);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    if (!session?.token) {
      setKeys([]); setCeremonies([]); setParticipants([]); setPolicies([]);
      return;
    }
    void refresh();
  }, [session?.token, session?.tenantId]);

  const stats: MPCOverviewStats = overview?.stats || {
    total_keys: keys.length, active_keys: keys.filter(k => !k.revoked_at).length,
    revoked_keys: keys.filter(k => k.revoked_at).length,
    total_ceremonies: ceremonies.length, pending_ceremonies: ceremonies.filter(c => c.status === "pending").length,
    completed_ceremonies: ceremonies.filter(c => c.status === "completed").length,
    failed_ceremonies: ceremonies.filter(c => c.status === "failed").length,
    active_participants: participants.filter(p => p.status === "active").length,
    total_participants: participants.length, active_policies: policies.filter(p => p.enabled).length
  };

  const selectedSignKey = useMemo(
    () => keys.find((k) => k.id === signKeyID) || null,
    [keys, signKeyID]
  );
  const selectedDecryptKey = useMemo(
    () => keys.find((k) => k.id === decryptKeyID) || null,
    [keys, decryptKeyID]
  );

  useEffect(() => {
    if (selectedSignKey?.participants?.length) {
      setSignParticipants(prev => prev.length ? prev : selectedSignKey.participants.slice(0, selectedSignKey.threshold || 2));
    }
  }, [selectedSignKey?.id]);

  useEffect(() => {
    if (selectedDecryptKey?.participants?.length) {
      setDecryptParticipants(prev => prev.length ? prev : selectedDecryptKey.participants.slice(0, selectedDecryptKey.threshold || 2));
    }
  }, [selectedDecryptKey?.id]);

  const toggle = (items: string[], id: string) =>
    items.includes(id) ? items.filter(x => x !== id) : [...items, id];

  /* ── ceremony actions ─────────────────────────────────── */

  const autoContribute = async (type: "dkg" | "sign" | "decrypt", ceremonyID: string, parties: string[]) => {
    for (const partyID of parties) {
      if (type === "dkg") await contributeMPCDKG(session, ceremonyID, { party_id: partyID, payload: { auto: true, submitted_at: nowIso() } });
      else if (type === "sign") await contributeMPCSign(session, ceremonyID, { party_id: partyID });
      else await contributeMPCDecrypt(session, ceremonyID, { party_id: partyID });
    }
  };

  const submitDKG = async () => {
    const threshold = Math.max(2, Math.trunc(dkgThreshold));
    const requestedTotal = Math.max(threshold, Math.trunc(dkgTotal) || threshold);
    const allIDs = participantOptions.map(p => p.id);
    let chosen = dkgParticipants.filter(id => allIDs.includes(id));
    if (!chosen.length) chosen = allIDs.slice(0, requestedTotal);
    if (chosen.length < requestedTotal) {
      const extras = allIDs.filter(id => !chosen.includes(id)).slice(0, requestedTotal - chosen.length);
      chosen = [...chosen, ...extras];
    }
    chosen = chosen.slice(0, requestedTotal);
    if (chosen.length < threshold) { onToast?.("Select enough participants to satisfy threshold."); return; }

    setBusy("dkg");
    try {
      const ceremony = await initiateMPCDKG(session, {
        key_name: String(dkgName || "mpc-key").trim() || "mpc-key",
        algorithm: dkgAlgorithm, threshold, participants: chosen,
        created_by: String(session?.username || "system")
      });
      await autoContribute("dkg", ceremony.id, chosen.slice(0, threshold));
      await refresh(true);
      setModal(null);
      onToast?.(`DKG completed: ${ceremony.key_id?.slice(0, 16)}...`);
    } catch (error) { onToast?.(`DKG failed: ${errMsg(error)}`); }
    finally { setBusy(""); }
  };

  const submitSign = async () => {
    const key = selectedSignKey;
    if (!key) { onToast?.("Select an MPC key for threshold signing."); return; }
    const threshold = Math.max(2, key.threshold || 2);
    const parties = (signParticipants.length ? signParticipants : key.participants || []).slice(0, Math.max(threshold, signParticipants.length));
    if (parties.length < threshold) { onToast?.("Selected participants do not satisfy key threshold."); return; }
    if (!signInput.trim()) { onToast?.("Message hash/input is required."); return; }

    setBusy("sign");
    try {
      const ceremony = await initiateMPCSign(session, {
        key_id: key.id, message_hash: signInput.trim(), participants: parties,
        created_by: String(session?.username || "system")
      });
      await autoContribute("sign", ceremony.id, parties.slice(0, threshold));
      const result = await getMPCSignResult(session, ceremony.id);
      setLastResult({ type: "sign", key: key.name, at: nowIso(), result });
      await refresh(true); setModal(null);
      onToast?.(`Threshold signature complete`);
    } catch (error) { onToast?.(`Threshold sign failed: ${errMsg(error)}`); }
    finally { setBusy(""); }
  };

  const submitDecrypt = async () => {
    const key = selectedDecryptKey;
    if (!key) { onToast?.("Select an MPC key for threshold decryption."); return; }
    const threshold = Math.max(2, key.threshold || 2);
    const parties = (decryptParticipants.length ? decryptParticipants : key.participants || []).slice(0, Math.max(threshold, decryptParticipants.length));
    if (parties.length < threshold) { onToast?.("Selected participants do not satisfy key threshold."); return; }
    if (!decryptCiphertext.trim()) { onToast?.("Ciphertext is required."); return; }

    setBusy("decrypt");
    try {
      const ceremony = await initiateMPCDecrypt(session, {
        key_id: key.id, ciphertext: decryptCiphertext.trim(), participants: parties,
        created_by: String(session?.username || "system")
      });
      await autoContribute("decrypt", ceremony.id, parties.slice(0, threshold));
      const result = await getMPCDecryptResult(session, ceremony.id);
      setLastResult({ type: "decrypt", key: key.name, at: nowIso(), result });
      await refresh(true); setModal(null);
      onToast?.("Threshold decrypt completed.");
    } catch (error) { onToast?.(`Threshold decrypt failed: ${errMsg(error)}`); }
    finally { setBusy(""); }
  };

  /* ── participant actions ──────────────────────────────── */

  const submitParticipant = async () => {
    if (!pName.trim()) { onToast?.("Participant name is required."); return; }
    setBusy("participant");
    try {
      if (editingParticipant) {
        await updateMPCParticipant(session, editingParticipant.id, { name: pName.trim(), endpoint: pEndpoint.trim(), public_key: pPubKey.trim() });
        onToast?.("Participant updated.");
      } else {
        await createMPCParticipant(session, { name: pName.trim(), endpoint: pEndpoint.trim(), public_key: pPubKey.trim() });
        onToast?.("Participant registered.");
      }
      await refresh(true); setModal(null); resetParticipantForm();
    } catch (error) { onToast?.(`Participant error: ${errMsg(error)}`); }
    finally { setBusy(""); }
  };

  const removeParticipant = async (id: string) => {
    setBusy("delpart");
    try {
      await deleteMPCParticipant(session, id);
      await refresh(true); onToast?.("Participant removed.");
    } catch (error) { onToast?.(`Remove failed: ${errMsg(error)}`); }
    finally { setBusy(""); }
  };

  const toggleParticipantStatus = async (p: MPCParticipant) => {
    setBusy("togpart");
    try {
      const next = p.status === "active" ? "suspended" : "active";
      await updateMPCParticipant(session, p.id, { status: next });
      await refresh(true); onToast?.(`Participant ${next}.`);
    } catch (error) { onToast?.(`Status update failed: ${errMsg(error)}`); }
    finally { setBusy(""); }
  };

  const resetParticipantForm = () => { setPName(""); setPEndpoint(""); setPPubKey(""); setEditingParticipant(null); };

  const openEditParticipant = (p: MPCParticipant) => {
    setEditingParticipant(p); setPName(p.name); setPEndpoint(p.endpoint); setPPubKey(p.public_key); setModal("participant");
  };

  /* ── policy actions ───────────────────────────────────── */

  const submitPolicy = async () => {
    if (!polName.trim()) { onToast?.("Policy name is required."); return; }
    setBusy("policy");
    try {
      if (editingPolicy) {
        await updateMPCPolicy(session, editingPolicy.id, { name: polName.trim(), description: polDesc.trim(), key_ids: polKeyIds.trim(), enabled: polEnabled, rules: polRules });
        onToast?.("Policy updated.");
      } else {
        await createMPCPolicy(session, { name: polName.trim(), description: polDesc.trim(), key_ids: polKeyIds.trim(), enabled: polEnabled, rules: polRules });
        onToast?.("Policy created.");
      }
      await refresh(true); setModal(null); resetPolicyForm();
    } catch (error) { onToast?.(`Policy error: ${errMsg(error)}`); }
    finally { setBusy(""); }
  };

  const removePolicy = async (id: string) => {
    setBusy("delpol");
    try {
      await deleteMPCPolicy(session, id);
      await refresh(true); onToast?.("Policy deleted.");
    } catch (error) { onToast?.(`Delete failed: ${errMsg(error)}`); }
    finally { setBusy(""); }
  };

  const resetPolicyForm = () => { setPolName(""); setPolDesc(""); setPolKeyIds(""); setPolEnabled(true); setPolRules([]); setEditingPolicy(null); };

  const openEditPolicy = (p: MPCPolicy) => {
    setEditingPolicy(p); setPolName(p.name); setPolDesc(p.description); setPolKeyIds(p.key_ids);
    setPolEnabled(p.enabled); setPolRules(p.rules?.map(r => ({ rule_type: r.rule_type, params: r.params })) || []);
    setModal("policy");
  };

  const addPolicyRule = () => setPolRules(prev => [...prev, { rule_type: "quorum_override", params: '{"min_signers":3}' }]);
  const removePolicyRule = (i: number) => setPolRules(prev => prev.filter((_, idx) => idx !== i));

  /* ── key lifecycle ────────────────────────────────────── */

  const submitRevoke = async () => {
    if (!revokeReason.trim()) { onToast?.("Revocation reason is required."); return; }
    setBusy("revoke");
    try {
      await revokeMPCKey(session, revokeKeyId, revokeReason.trim());
      await refresh(true); setModal(null); setRevokeKeyId(""); setRevokeReason("");
      onToast?.("Key revoked.");
    } catch (error) { onToast?.(`Revoke failed: ${errMsg(error)}`); }
    finally { setBusy(""); }
  };

  const submitGroup = async () => {
    setBusy("group");
    try {
      await setMPCKeyGroup(session, groupKeyId, groupName.trim());
      await refresh(true); setModal(null); setGroupKeyId(""); setGroupName("");
      onToast?.("Key group updated.");
    } catch (error) { onToast?.(`Group update failed: ${errMsg(error)}`); }
    finally { setBusy(""); }
  };

  /* ── filtered data ────────────────────────────────────── */

  const filteredKeys = useMemo(() => {
    let out = keys;
    if (keyGroupFilter) out = out.filter(k => k.key_group === keyGroupFilter);
    if (keyStatusFilter === "active") out = out.filter(k => !k.revoked_at && (!k.expires_at || new Date(k.expires_at) > new Date()));
    else if (keyStatusFilter === "revoked") out = out.filter(k => k.revoked_at);
    else if (keyStatusFilter === "expired") out = out.filter(k => k.expires_at && new Date(k.expires_at) <= new Date());
    return out;
  }, [keys, keyGroupFilter, keyStatusFilter]);

  const filteredCeremonies = useMemo(() => {
    let out = ceremonies;
    if (ceremonyTypeFilter) out = out.filter(c => c.type === ceremonyTypeFilter);
    if (ceremonyStatusFilter) out = out.filter(c => c.status === ceremonyStatusFilter);
    return out;
  }, [ceremonies, ceremonyTypeFilter, ceremonyStatusFilter]);

  const keyGroups = useMemo(() => [...new Set(keys.map(k => k.key_group).filter(Boolean))], [keys]);

  const keyCols = "2fr 1fr .7fr .7fr .7fr 1.2fr";
  const cerCols = "1.5fr .7fr 1.2fr .7fr .7fr 1fr";
  const partCols = "1.5fr 1.5fr 1.2fr .7fr .7fr 1.2fr";
  const polCols = "1.5fr 2fr .6fr .6fr .6fr 1.2fr";

  /* ── render ───────────────────────────────────────────── */

  return (
    <div>
      <Section title="MPC Engine" actions={
        <Btn small onClick={() => void refresh()} disabled={loading}>{loading ? "Refreshing..." : "Refresh"}</Btn>
      }>
        <Tabs tabs={["Overview", "Keys", "Ceremonies", "Policies", "Participants"]} active={tab} onChange={setTab} />
      </Section>

      {/* ═══ OVERVIEW TAB ═══ */}
      {tab === "Overview" && <>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10, marginBottom: 14 }}>
          <Stat l="Active Keys" v={stats.active_keys} s={`${stats.revoked_keys} revoked`} c="accent" i={KeyRound} />
          <Stat l="Pending Ceremonies" v={stats.pending_ceremonies} s={`${stats.completed_ceremonies} completed`} c="amber" i={Activity} />
          <Stat l="Participants" v={stats.active_participants} s={`${stats.total_participants} total`} c="blue" i={Users} />
          <Stat l="Active Policies" v={stats.active_policies} c="purple" i={Shield} />
        </div>

        <Row3>
          <Card onClick={() => { setModal("dkg"); }} style={{ cursor: "pointer" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <KeyRound size={16} color={C.accent} />
              <div style={{ fontSize: 13, color: C.text, fontWeight: 700 }}>New DKG Ceremony</div>
            </div>
            <div style={{ fontSize: 10, color: C.dim }}>Generate a new distributed key with Feldman VSS</div>
          </Card>
          <Card onClick={() => { resetParticipantForm(); setModal("participant"); }} style={{ cursor: "pointer" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <Users size={16} color={C.blue} />
              <div style={{ fontSize: 13, color: C.text, fontWeight: 700 }}>Register Participant</div>
            </div>
            <div style={{ fontSize: 10, color: C.dim }}>Add an MPC compute node to the network</div>
          </Card>
          <Card onClick={() => { resetPolicyForm(); setModal("policy"); }} style={{ cursor: "pointer" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <Shield size={16} color={C.purple} />
              <div style={{ fontSize: 13, color: C.text, fontWeight: 700 }}>Create Policy</div>
            </div>
            <div style={{ fontSize: 10, color: C.dim }}>Define signing policy rules for MPC keys</div>
          </Card>
        </Row3>

        <Section title="Recent Ceremonies">
          <Card style={{ padding: 0, overflow: "hidden" }}>
            {gridHeader("1.5fr .7fr 1.5fr .7fr 1fr", ["Ceremony", "Type", "Key", "Status", "Created"])}
            <div style={{ maxHeight: 240, overflowY: "auto" }}>
              {(overview?.recent_ceremonies || ceremonies.slice(0, 10)).map(c => (
                gridRow("1.5fr .7fr 1.5fr .7fr 1fr", <>
                  <div style={{ fontSize: 11, color: C.text, fontFamily: "'JetBrains Mono',monospace" }}>{c.id?.slice(0, 12)}...</div>
                  <div><B c={typeColor(c.type)}>{c.type.toUpperCase()}</B></div>
                  <div style={{ fontSize: 10, color: C.muted, fontFamily: "'JetBrains Mono',monospace" }}>{c.key_id?.slice(0, 16)}...</div>
                  <div><B c={statusColor(c.status)}>{c.status}</B></div>
                  <div style={{ fontSize: 10, color: C.dim, textAlign: "right" }}>{fmtAgo(c.created_at)}</div>
                </>, c.id)
              ))}
              {!ceremonies.length && emptyRow("No ceremonies yet.")}
            </div>
          </Card>
        </Section>

        <Section title="Participant Health">
          <Card style={{ padding: 0, overflow: "hidden" }}>
            {gridHeader("2fr 1fr 1fr", ["Name", "Status", "Last Seen"])}
            <div style={{ maxHeight: 180, overflowY: "auto" }}>
              {(overview?.participants || participants).map(p => (
                gridRow("2fr 1fr 1fr", <>
                  <div style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{p.name}</div>
                  <div><B c={statusColor(p.status)}>{p.status}</B></div>
                  <div style={{ fontSize: 10, color: C.dim, textAlign: "right" }}>{fmtAgo(p.last_seen_at)}</div>
                </>, p.id)
              ))}
              {!participants.length && emptyRow("No participants registered.")}
            </div>
          </Card>
        </Section>
      </>}

      {/* ═══ KEYS TAB ═══ */}
      {tab === "Keys" && <>
        <Section title="MPC Keys" actions={
          <Btn small primary onClick={() => setModal("dkg")}><Plus size={12} /> Generate Key (DKG)</Btn>
        }>
          <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
            <Sel w={160} value={keyGroupFilter} onChange={e => setKeyGroupFilter(e.target.value)}>
              <option value="">All Groups</option>
              {keyGroups.map(g => <option key={g} value={g}>{g}</option>)}
            </Sel>
            <Sel w={140} value={keyStatusFilter} onChange={e => setKeyStatusFilter(e.target.value)}>
              <option value="">All Status</option>
              <option value="active">Active</option>
              <option value="revoked">Revoked</option>
              <option value="expired">Expired</option>
            </Sel>
          </div>
          <Card style={{ padding: 0, overflow: "hidden" }}>
            {gridHeader(keyCols, ["Key", "Algorithm", "Threshold", "Group", "Status", "Actions"])}
            <div style={{ maxHeight: 400, overflowY: "auto" }}>
              {filteredKeys.map(k => {
                const revoked = Boolean(k.revoked_at);
                const kStatus = revoked ? "revoked" : (k.expires_at && new Date(k.expires_at) <= new Date()) ? "expired" : "active";
                return gridRow(keyCols, <>
                  <div>
                    <div style={{ fontSize: 12, color: C.text, fontWeight: 700 }}>{k.name || k.id}</div>
                    <div style={{ fontSize: 9, color: C.muted, fontFamily: "'JetBrains Mono',monospace" }}>{k.id?.slice(0, 20)}...</div>
                  </div>
                  <div style={{ fontSize: 11, color: C.dim }}>{k.algorithm}</div>
                  <div style={{ fontSize: 11, color: C.accent, fontFamily: "'JetBrains Mono',monospace" }}>{k.threshold}-of-{k.participant_count}</div>
                  <div>{k.key_group ? <B c="purple">{k.key_group}</B> : <span style={{ fontSize: 10, color: C.muted }}>—</span>}</div>
                  <div><B c={statusColor(kStatus)}>{kStatus}</B></div>
                  <div style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}>
                    {!revoked && <Btn small onClick={() => { setRevokeKeyId(k.id); setRevokeReason(""); setModal("revoke"); }}><Ban size={10} /> Revoke</Btn>}
                    <Btn small onClick={() => { setGroupKeyId(k.id); setGroupName(k.key_group || ""); setModal("group"); }}><FolderOpen size={10} /> Group</Btn>
                  </div>
                </>, k.id);
              })}
              {!filteredKeys.length && emptyRow(loading ? "Loading keys..." : "No MPC keys match filters.")}
            </div>
          </Card>
        </Section>

        {lastResult && (
          <Card style={{ marginTop: 10 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
              <div style={{ fontSize: 12, color: C.text, fontWeight: 700 }}>Last MPC Result</div>
              <B c={lastResult.type === "sign" ? "blue" : "green"}>{String(lastResult.type || "").toUpperCase()}</B>
            </div>
            <div style={{ fontSize: 10, color: C.muted, marginBottom: 6 }}>{lastResult.key} | {new Date(lastResult.at).toLocaleString()}</div>
            <Txt rows={4} value={JSON.stringify(lastResult.result || {}, null, 2)} readOnly />
          </Card>
        )}
      </>}

      {/* ═══ CEREMONIES TAB ═══ */}
      {tab === "Ceremonies" && <>
        <Section title="Ceremonies" actions={
          <div style={{ display: "flex", gap: 4 }}>
            <Btn small primary onClick={() => setModal("dkg")}>New DKG</Btn>
            <Btn small onClick={() => setModal("sign")} disabled={!keys.length}>New Sign</Btn>
            <Btn small onClick={() => setModal("decrypt")} disabled={!keys.length}>New Decrypt</Btn>
          </div>
        }>
          <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
            <Sel w={140} value={ceremonyTypeFilter} onChange={e => setCeremonyTypeFilter(e.target.value)}>
              <option value="">All Types</option>
              <option value="dkg">DKG</option>
              <option value="sign">Sign</option>
              <option value="decrypt">Decrypt</option>
            </Sel>
            <Sel w={140} value={ceremonyStatusFilter} onChange={e => setCeremonyStatusFilter(e.target.value)}>
              <option value="">All Status</option>
              <option value="pending">Pending</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
            </Sel>
          </div>
          <Card style={{ padding: 0, overflow: "hidden" }}>
            {gridHeader(cerCols, ["Ceremony", "Type", "Key", "Threshold", "Status", "Created"])}
            <div style={{ maxHeight: 460, overflowY: "auto" }}>
              {filteredCeremonies.map(c => (
                gridRow(cerCols, <>
                  <div>
                    <div style={{ fontSize: 11, color: C.text, fontFamily: "'JetBrains Mono',monospace" }}>{c.id?.slice(0, 16)}...</div>
                    {c.created_by && <div style={{ fontSize: 9, color: C.muted }}>by {c.created_by}</div>}
                  </div>
                  <div><B c={typeColor(c.type)}>{c.type.toUpperCase()}</B></div>
                  <div style={{ fontSize: 10, color: C.muted, fontFamily: "'JetBrains Mono',monospace" }}>{c.key_id?.slice(0, 16)}...</div>
                  <div style={{ fontSize: 11, color: C.accent }}>{c.threshold}-of-{c.participant_count}</div>
                  <div><B c={statusColor(c.status)}>{c.status}</B></div>
                  <div style={{ fontSize: 10, color: C.dim, textAlign: "right" }}>{fmtAgo(c.created_at)}</div>
                </>, c.id)
              ))}
              {!filteredCeremonies.length && emptyRow("No ceremonies match filters.")}
            </div>
          </Card>
        </Section>
      </>}

      {/* ═══ POLICIES TAB ═══ */}
      {tab === "Policies" && <>
        <Section title="Signing Policies" actions={
          <Btn small primary onClick={() => { resetPolicyForm(); setModal("policy"); }}><Plus size={12} /> Create Policy</Btn>
        }>
          <Card style={{ padding: 0, overflow: "hidden" }}>
            {gridHeader(polCols, ["Name", "Description", "Rules", "Enabled", "Scope", "Actions"])}
            <div style={{ maxHeight: 400, overflowY: "auto" }}>
              {policies.map(p => (
                gridRow(polCols, <>
                  <div style={{ fontSize: 12, color: C.text, fontWeight: 700 }}>{p.name}</div>
                  <div style={{ fontSize: 10, color: C.dim }}>{p.description || "—"}</div>
                  <div><B c="accent">{p.rules?.length || 0}</B></div>
                  <div><B c={p.enabled ? "green" : "muted"}>{p.enabled ? "ON" : "OFF"}</B></div>
                  <div style={{ fontSize: 10, color: C.muted }}>{p.key_ids ? `${p.key_ids.split(",").length} keys` : "All keys"}</div>
                  <div style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}>
                    <Btn small onClick={() => openEditPolicy(p)}><Edit3 size={10} /> Edit</Btn>
                    <Btn small onClick={() => void removePolicy(p.id)} disabled={busy === "delpol"}><Trash2 size={10} /></Btn>
                  </div>
                </>, p.id)
              ))}
              {!policies.length && emptyRow("No policies defined.")}
            </div>
          </Card>
        </Section>
      </>}

      {/* ═══ PARTICIPANTS TAB ═══ */}
      {tab === "Participants" && <>
        <Section title="MPC Participants" actions={
          <Btn small primary onClick={() => { resetParticipantForm(); setModal("participant"); }}><Plus size={12} /> Register</Btn>
        }>
          <Card style={{ padding: 0, overflow: "hidden" }}>
            {gridHeader(partCols, ["Name", "Endpoint", "Public Key", "Status", "Last Seen", "Actions"])}
            <div style={{ maxHeight: 400, overflowY: "auto" }}>
              {participants.map(p => (
                gridRow(partCols, <>
                  <div style={{ fontSize: 12, color: C.text, fontWeight: 700 }}>{p.name}</div>
                  <div style={{ fontSize: 10, color: C.dim, fontFamily: "'JetBrains Mono',monospace" }}>{p.endpoint || "—"}</div>
                  <div style={{ fontSize: 10, color: C.muted, fontFamily: "'JetBrains Mono',monospace" }}>{p.public_key ? `${p.public_key.slice(0, 16)}...` : "—"}</div>
                  <div><B c={statusColor(p.status)}>{p.status}</B></div>
                  <div style={{ fontSize: 10, color: C.dim }}>{fmtAgo(p.last_seen_at)}</div>
                  <div style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}>
                    <Btn small onClick={() => openEditParticipant(p)}><Edit3 size={10} /></Btn>
                    <Btn small onClick={() => void toggleParticipantStatus(p)} disabled={busy === "togpart"}>
                      {p.status === "active" ? "Suspend" : "Activate"}
                    </Btn>
                    <Btn small onClick={() => void removeParticipant(p.id)} disabled={busy === "delpart"}><Trash2 size={10} /></Btn>
                  </div>
                </>, p.id)
              ))}
              {!participants.length && emptyRow("No participants registered.")}
            </div>
          </Card>
        </Section>
      </>}

      {/* ═══ MODALS ═══ */}

      {/* DKG Modal */}
      <Modal open={modal === "dkg"} onClose={() => setModal(null)} title="Start DKG Ceremony" wide>
        <Row2>
          <FG label="Threshold (T)" required><Inp type="number" min={2} value={String(dkgThreshold)} onChange={e => setDKGThreshold(Math.max(2, Number(e.target.value || 2)))} /></FG>
          <FG label="Total Parties (N)" required><Inp type="number" min={2} value={String(dkgTotal)} onChange={e => setDKGTotal(Math.max(2, Number(e.target.value || 2)))} /></FG>
        </Row2>
        <FG label="Key Name" required><Inp value={dkgName} onChange={e => setDKGName(e.target.value)} placeholder="custody-distributed" /></FG>
        <FG label="Key Algorithm"><Sel value={dkgAlgorithm} onChange={e => setDKGAlgorithm(e.target.value)}>{algorithmOptions.map(o => <option key={o.v} value={o.v}>{o.l}</option>)}</Sel></FG>
        <FG label="Participants">{participantOptions.map(p => <Chk key={p.id} label={p.label} checked={dkgParticipants.includes(p.id)} onChange={() => setDKGParticipants(prev => toggle(prev, p.id))} />)}</FG>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
          <Btn onClick={() => setModal(null)} disabled={busy === "dkg"}>Cancel</Btn>
          <Btn primary onClick={() => void submitDKG()} disabled={busy === "dkg"}>{busy === "dkg" ? "Initiating..." : "Initiate DKG"}</Btn>
        </div>
      </Modal>

      {/* Sign Modal */}
      <Modal open={modal === "sign"} onClose={() => setModal(null)} title="Start Threshold Signing" wide>
        <FG label="MPC Key" required>
          <Sel value={signKeyID} onChange={e => setSignKeyID(e.target.value)}>
            {keys.map(k => <option key={k.id} value={k.id}>{k.name} ({k.algorithm})</option>)}
            {!keys.length && <option value="">No MPC keys available</option>}
          </Sel>
        </FG>
        <FG label="Message Hash / Input" required hint="Hex, Base64, or UTF-8 input accepted.">
          <Txt rows={4} value={signInput} onChange={e => setSignInput(e.target.value)} placeholder="deadbeef" />
        </FG>
        <FG label="Participants">{(selectedSignKey?.participants || []).map((id: string) => <Chk key={id} label={id} checked={signParticipants.includes(id)} onChange={() => setSignParticipants(prev => toggle(prev, id))} />)}</FG>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
          <Btn onClick={() => setModal(null)} disabled={busy === "sign"}>Cancel</Btn>
          <Btn primary onClick={() => void submitSign()} disabled={busy === "sign" || !selectedSignKey}>{busy === "sign" ? "Signing..." : "Initiate Sign"}</Btn>
        </div>
      </Modal>

      {/* Decrypt Modal */}
      <Modal open={modal === "decrypt"} onClose={() => setModal(null)} title="Start Threshold Decryption" wide>
        <FG label="MPC Key" required>
          <Sel value={decryptKeyID} onChange={e => setDecryptKeyID(e.target.value)}>
            {keys.map(k => <option key={k.id} value={k.id}>{k.name} ({k.algorithm})</option>)}
            {!keys.length && <option value="">No MPC keys available</option>}
          </Sel>
        </FG>
        <FG label="Ciphertext" required>
          <Txt rows={5} value={decryptCiphertext} onChange={e => setDecryptCiphertext(e.target.value)} placeholder='{"nonce":"...","ciphertext":"...","aad":"..."}' />
        </FG>
        <FG label="Participants">{(selectedDecryptKey?.participants || []).map((id: string) => <Chk key={id} label={id} checked={decryptParticipants.includes(id)} onChange={() => setDecryptParticipants(prev => toggle(prev, id))} />)}</FG>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
          <Btn onClick={() => setModal(null)} disabled={busy === "decrypt"}>Cancel</Btn>
          <Btn primary onClick={() => void submitDecrypt()} disabled={busy === "decrypt" || !selectedDecryptKey}>{busy === "decrypt" ? "Decrypting..." : "Initiate Decrypt"}</Btn>
        </div>
      </Modal>

      {/* Participant Modal */}
      <Modal open={modal === "participant"} onClose={() => { setModal(null); resetParticipantForm(); }} title={editingParticipant ? "Edit Participant" : "Register Participant"}>
        <FG label="Name" required><Inp value={pName} onChange={e => setPName(e.target.value)} placeholder="mpc-node-east-1" /></FG>
        <FG label="Endpoint URL"><Inp value={pEndpoint} onChange={e => setPEndpoint(e.target.value)} placeholder="https://mpc-node.example.com:8443" /></FG>
        <FG label="Public Key"><Txt rows={3} value={pPubKey} onChange={e => setPPubKey(e.target.value)} placeholder="Base64-encoded public key" /></FG>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
          <Btn onClick={() => { setModal(null); resetParticipantForm(); }}>Cancel</Btn>
          <Btn primary onClick={() => void submitParticipant()} disabled={busy === "participant"}>{busy === "participant" ? "Saving..." : editingParticipant ? "Update" : "Register"}</Btn>
        </div>
      </Modal>

      {/* Policy Modal */}
      <Modal open={modal === "policy"} onClose={() => { setModal(null); resetPolicyForm(); }} title={editingPolicy ? "Edit Policy" : "Create Policy"} wide>
        <Row2>
          <FG label="Name" required><Inp value={polName} onChange={e => setPolName(e.target.value)} placeholder="velocity-limit-production" /></FG>
          <FG label="Key Scope" hint="Comma-separated key IDs, or blank for all keys"><Inp value={polKeyIds} onChange={e => setPolKeyIds(e.target.value)} placeholder="All keys" /></FG>
        </Row2>
        <FG label="Description"><Inp value={polDesc} onChange={e => setPolDesc(e.target.value)} placeholder="Limit signing to 10 per hour during business hours" /></FG>
        <div style={{ marginBottom: 12 }}>
          <Chk label="Policy Enabled" checked={polEnabled} onChange={() => setPolEnabled(p => !p)} />
        </div>

        <Section title="Rules" actions={<Btn small onClick={addPolicyRule}><Plus size={10} /> Add Rule</Btn>}>
          {polRules.map((r, i) => (
            <Card key={i} style={{ marginBottom: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <Sel w={200} value={r.rule_type} onChange={e => {
                  const updated = [...polRules];
                  updated[i] = { ...r, rule_type: e.target.value };
                  setPolRules(updated);
                }}>
                  <option value="quorum_override">Quorum Override</option>
                  <option value="velocity_limit">Velocity Limit</option>
                  <option value="time_window">Time Window</option>
                  <option value="whitelist">Whitelist</option>
                </Sel>
                <Btn small onClick={() => removePolicyRule(i)}><Trash2 size={10} /></Btn>
              </div>
              <FG label="Parameters (JSON)">
                <Inp mono value={r.params} onChange={e => {
                  const updated = [...polRules];
                  updated[i] = { ...r, params: e.target.value };
                  setPolRules(updated);
                }} placeholder={
                  r.rule_type === "quorum_override" ? '{"min_signers":3}' :
                  r.rule_type === "velocity_limit" ? '{"max_per_hour":10}' :
                  r.rule_type === "time_window" ? '{"allowed_hours":"09:00-17:00","timezone":"UTC"}' :
                  '{"allowed_addresses":["0x..."]}'
                } />
              </FG>
            </Card>
          ))}
          {!polRules.length && <div style={{ fontSize: 10, color: C.dim, padding: "8px 0" }}>No rules added. Click "Add Rule" to define policy constraints.</div>}
        </Section>

        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
          <Btn onClick={() => { setModal(null); resetPolicyForm(); }}>Cancel</Btn>
          <Btn primary onClick={() => void submitPolicy()} disabled={busy === "policy"}>{busy === "policy" ? "Saving..." : editingPolicy ? "Update Policy" : "Create Policy"}</Btn>
        </div>
      </Modal>

      {/* Revoke Key Modal */}
      <Modal open={modal === "revoke"} onClose={() => setModal(null)} title="Revoke MPC Key">
        <div style={{ fontSize: 11, color: C.dim, marginBottom: 12 }}>This action is irreversible. The key will be marked as revoked and can no longer be used for signing or decryption.</div>
        <FG label="Key ID"><Inp value={revokeKeyId} readOnly mono /></FG>
        <FG label="Revocation Reason" required><Txt rows={3} value={revokeReason} onChange={e => setRevokeReason(e.target.value)} placeholder="Key compromise suspected" mono={false} /></FG>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
          <Btn onClick={() => setModal(null)}>Cancel</Btn>
          <Btn danger onClick={() => void submitRevoke()} disabled={busy === "revoke"}>{busy === "revoke" ? "Revoking..." : "Revoke Key"}</Btn>
        </div>
      </Modal>

      {/* Set Key Group Modal */}
      <Modal open={modal === "group"} onClose={() => setModal(null)} title="Set Key Group">
        <FG label="Key ID"><Inp value={groupKeyId} readOnly mono /></FG>
        <FG label="Group Name"><Inp value={groupName} onChange={e => setGroupName(e.target.value)} placeholder="production, staging, custody..." /></FG>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
          <Btn onClick={() => setModal(null)}>Cancel</Btn>
          <Btn primary onClick={() => void submitGroup()} disabled={busy === "group"}>{busy === "group" ? "Updating..." : "Set Group"}</Btn>
        </div>
      </Modal>
    </div>
  );
};
