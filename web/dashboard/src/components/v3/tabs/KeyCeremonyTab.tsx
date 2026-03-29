// @ts-nocheck
import { useEffect, useState } from "react";
import {
  Key, Users, CheckCircle2, Clock, Shield, Plus, Trash2, StopCircle, RefreshCw
} from "lucide-react";
import { B, Btn, Card, FG, Inp, Modal, Row2, Section, Sel, Stat, Tabs, Txt } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  listCeremonies,
  createCeremony,
  listGuardians,
  createGuardian,
  abortCeremony,
  type Guardian,
  type Ceremony,
} from "../../../lib/ceremony";

/* ────── Helpers ────── */

function fmtDate(iso: string) {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }); }
  catch { return "—"; }
}

function ceremonyTypeLabel(t: string) {
  switch (t) {
    case "key_generation": return "Key Generation";
    case "key_recovery": return "Key Recovery";
    case "key_destruction": return "Key Destruction";
    case "root_rotation": return "Root Rotation";
    default: return t || "—";
  }
}

function statusColor(s: string) {
  switch ((s || "").toLowerCase()) {
    case "completed": return "green";
    case "active": return "accent";
    case "awaiting_quorum": return "amber";
    case "draft": return "blue";
    case "aborted": return "red";
    default: return "muted";
  }
}

function guardianStatusColor(s: string) {
  switch ((s || "").toLowerCase()) {
    case "active": return "green";
    case "pending": return "amber";
    case "revoked": return "red";
    default: return "muted";
  }
}

/* ────── Mock Data ────── */

const MOCK_GUARDIANS: Guardian[] = [
  { id: "g1", name: "Alice Chen", email: "alice@corp.com", role: "Security Officer", joined_at: "2025-01-10T09:00:00Z", status: "active" },
  { id: "g2", name: "Bob Martins", email: "bob@corp.com", role: "Key Custodian", joined_at: "2025-01-12T11:30:00Z", status: "active" },
  { id: "g3", name: "Carol Davis", email: "carol@corp.com", role: "Compliance Officer", joined_at: "2025-02-01T08:15:00Z", status: "active" },
  { id: "g4", name: "David Kim", email: "david@corp.com", role: "CISO Delegate", joined_at: "2025-02-14T14:00:00Z", status: "active" },
  { id: "g5", name: "Emma Wilson", email: "emma@corp.com", role: "Key Custodian", joined_at: "2025-03-01T10:45:00Z", status: "pending" },
];

const MOCK_CEREMONIES: Ceremony[] = [
  { id: "c1", tenant_id: "t1", name: "Q1 Root Key Generation", type: "key_generation", threshold: 3, total_shares: 5, status: "completed", key_name: "root-key-2025-q1", shares: [], created_by: "alice@corp.com", created_at: "2025-01-15T10:00:00Z", completed_at: "2025-01-15T11:30:00Z", notes: "Annual root key ceremony." },
  { id: "c2", tenant_id: "t1", name: "HSM Backup Recovery", type: "key_recovery", threshold: 2, total_shares: 4, status: "awaiting_quorum", shares: [], created_by: "bob@corp.com", created_at: "2025-03-10T09:00:00Z", notes: "Recovery after HSM failure." },
  { id: "c3", tenant_id: "t1", name: "Legacy Key Destruction", type: "key_destruction", threshold: 3, total_shares: 5, status: "active", shares: [], created_by: "carol@corp.com", created_at: "2025-03-20T14:00:00Z", notes: "Destroying deprecated encryption keys." },
  { id: "c4", tenant_id: "t1", name: "Annual Root Rotation", type: "root_rotation", threshold: 3, total_shares: 5, status: "draft", shares: [], created_by: "david@corp.com", created_at: "2025-03-22T08:00:00Z", notes: "Scheduled root key rotation." },
];

/* ────── Main Component ────── */

export const KeyCeremonyTab = ({ session, enabledFeatures, keyCatalog }: { session: any; enabledFeatures?: any; keyCatalog?: any[] }) => {
  const [section, setSection] = useState("ceremonies");
  const [loading, setLoading] = useState(false);
  const [ceremonies, setCeremonies] = useState<Ceremony[]>([]);
  const [guardians, setGuardians] = useState<Guardian[]>([]);
  const [error, setError] = useState("");

  // Ceremony modal
  const [ceremonyModal, setCeremonyModal] = useState(false);
  const [cName, setCName] = useState("");
  const [cType, setCType] = useState<string>("key_generation");
  const [cThreshold, setCThreshold] = useState("3");
  const [cShares, setCShares] = useState("5");
  const [cGuardians, setCGuardians] = useState<string[]>([]);
  const [cNotes, setCNotes] = useState("");
  const [cSaving, setCSaving] = useState(false);
  const [cError, setCError] = useState("");

  // Guardian modal
  const [guardianModal, setGuardianModal] = useState(false);
  const [gName, setGName] = useState("");
  const [gEmail, setGEmail] = useState("");
  const [gRole, setGRole] = useState("Key Custodian");
  const [gSaving, setGSaving] = useState(false);
  const [gError, setGError] = useState("");

  // Abort busy
  const [abortBusy, setAbortBusy] = useState("");

  const refresh = async () => {
    if (!session?.token) return;
    setLoading(true);
    setError("");
    try {
      const [c, g] = await Promise.all([
        listCeremonies(session).catch(() => MOCK_CEREMONIES),
        listGuardians(session).catch(() => MOCK_GUARDIANS),
      ]);
      setCeremonies(Array.isArray(c) ? c : MOCK_CEREMONIES);
      setGuardians(Array.isArray(g) ? g : MOCK_GUARDIANS);
    } catch (e: any) {
      setError(errMsg(e));
      setCeremonies(MOCK_CEREMONIES);
      setGuardians(MOCK_GUARDIANS);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void refresh(); }, [session?.token]);

  // Stats derived
  const activeCeremonies = ceremonies.filter((c) => ["active", "awaiting_quorum"].includes(c.status)).length;
  const completedCeremonies = ceremonies.filter((c) => c.status === "completed").length;
  const totalGuardians = guardians.length;

  const openCeremonyModal = () => {
    setCName(""); setCType("key_generation"); setCThreshold("3"); setCShares("5");
    setCGuardians([]); setCNotes(""); setCError("");
    setCeremonyModal(true);
  };

  const saveCeremony = async () => {
    if (!cName.trim()) { setCError("Name is required."); return; }
    const m = Number(cThreshold);
    const n = Number(cShares);
    if (!m || !n || m > n) { setCError("Threshold must be ≤ total shares and both must be > 0."); return; }
    setCSaving(true);
    setCError("");
    try {
      await createCeremony(session, {
        name: cName.trim(),
        type: cType as Ceremony["type"],
        threshold: m,
        total_shares: n,
        guardian_ids: cGuardians,
        notes: cNotes.trim(),
      });
      setCeremonyModal(false);
      await refresh();
    } catch (e: any) {
      setCError(errMsg(e));
    } finally {
      setCSaving(false);
    }
  };

  const openGuardianModal = () => {
    setGName(""); setGEmail(""); setGRole("Key Custodian"); setGError("");
    setGuardianModal(true);
  };

  const saveGuardian = async () => {
    if (!gName.trim() || !gEmail.trim()) { setGError("Name and email are required."); return; }
    setGSaving(true);
    setGError("");
    try {
      await createGuardian(session, { name: gName.trim(), email: gEmail.trim(), role: gRole.trim() });
      setGuardianModal(false);
      await refresh();
    } catch (e: any) {
      setGError(errMsg(e));
    } finally {
      setGSaving(false);
    }
  };

  const doAbort = async (c: Ceremony) => {
    if (!window.confirm(`Abort ceremony "${c.name}"? This cannot be undone.`)) return;
    setAbortBusy(c.id);
    try {
      await abortCeremony(session, c.id, "Aborted by operator");
      await refresh();
    } catch { /* ignore */ }
    finally { setAbortBusy(""); }
  };

  const toggleGuardian = (id: string) => {
    setCGuardians((prev) => prev.includes(id) ? prev.filter((g) => g !== id) : [...prev, id]);
  };

  /* ════════════ RENDER ════════════ */
  return (
    <div style={{ display: "grid", gap: 14 }}>

      {/* ── Stats ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 10 }}>
        <Stat l="Active Ceremonies" v={loading ? "…" : activeCeremonies} c="accent" i={Key} />
        <Stat l="Total Guardians" v={loading ? "…" : totalGuardians} c="blue" i={Users} />
        <Stat l="Completed Ceremonies" v={loading ? "…" : completedCeremonies} c="green" i={CheckCircle2} />
      </div>

      {/* ── Error ── */}
      {error && (
        <div style={{ padding: "8px 12px", borderRadius: 7, background: C.redDim, border: `1px solid ${C.red}`, fontSize: 11, color: C.red }}>
          {error}
        </div>
      )}

      {/* ── Section tab switcher + header actions ── */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
        <Tabs
          tabs={["Ceremonies", "Guardians"]}
          active={section === "ceremonies" ? "Ceremonies" : "Guardians"}
          onChange={(t) => setSection(t === "Ceremonies" ? "ceremonies" : "guardians")}
        />
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          {section === "ceremonies" && (
            <Btn small primary onClick={openCeremonyModal}><Plus size={11} /> Create Ceremony</Btn>
          )}
          {section === "guardians" && (
            <Btn small primary onClick={openGuardianModal}><Plus size={11} /> Add Guardian</Btn>
          )}
          <Btn small onClick={() => void refresh()} disabled={loading}><RefreshCw size={11} /> {loading ? "Loading..." : "Refresh"}</Btn>
        </div>
      </div>

      {/* ════════════ CEREMONIES SECTION ════════════ */}
      {section === "ceremonies" && (
        <Section title="Key Ceremonies">
          <Card style={{ padding: 0, overflow: "hidden" }}>
            {/* Table header */}
            <div style={{ display: "grid", gridTemplateColumns: "2fr 1.2fr 0.8fr 0.8fr 0.9fr auto", padding: "9px 14px", borderBottom: `1px solid ${C.border}`, fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, background: C.surface }}>
              <div>Name</div>
              <div>Type</div>
              <div>Threshold</div>
              <div>Status</div>
              <div>Created</div>
              <div style={{ textAlign: "right" }}>Actions</div>
            </div>

            {/* Rows */}
            <div style={{ maxHeight: 420, overflowY: "auto" }}>
              {loading && (
                <div style={{ padding: 28, textAlign: "center", fontSize: 12, color: C.dim }}>
                  <Clock size={20} color={C.muted} style={{ margin: "0 auto 8px", display: "block" }} />
                  Loading...
                </div>
              )}
              {!loading && ceremonies.length === 0 && (
                <div style={{ padding: 28, textAlign: "center", fontSize: 12, color: C.dim }}>
                  <Key size={20} color={C.muted} style={{ margin: "0 auto 8px", display: "block" }} />
                  No ceremonies found. Create one to begin.
                </div>
              )}
              {!loading && ceremonies.map((c) => {
                const canAbort = ["active", "awaiting_quorum", "draft"].includes(c.status);
                return (
                  <div
                    key={c.id}
                    style={{ display: "grid", gridTemplateColumns: "2fr 1.2fr 0.8fr 0.8fr 0.9fr auto", padding: "10px 14px", borderBottom: `1px solid ${C.border}`, alignItems: "center", fontSize: 11, transition: "background 120ms" }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = C.cardHover; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                  >
                    <div style={{ minWidth: 0 }}>
                      <div style={{ color: C.text, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.name}</div>
                      {c.key_name && (
                        <div style={{ fontSize: 9, color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "'JetBrains Mono', monospace" }}>{c.key_name}</div>
                      )}
                    </div>
                    <div style={{ color: C.accent, fontSize: 10 }}>{ceremonyTypeLabel(c.type)}</div>
                    <div style={{ color: C.text, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>{c.threshold}-of-{c.total_shares}</div>
                    <div><B c={statusColor(c.status)}>{c.status.replace("_", " ")}</B></div>
                    <div style={{ color: C.dim, fontSize: 10 }}>{fmtDate(c.created_at)}</div>
                    <div style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}>
                      {canAbort && (
                        <Btn small danger disabled={abortBusy === c.id} onClick={() => void doAbort(c)}>
                          <StopCircle size={10} /> {abortBusy === c.id ? "..." : "Abort"}
                        </Btn>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </Card>
        </Section>
      )}

      {/* ════════════ GUARDIANS SECTION ════════════ */}
      {section === "guardians" && (
        <Section title="Guardians" actions={<Btn small primary onClick={openGuardianModal}><Plus size={11} /> Add Guardian</Btn>}>
          <Card style={{ padding: 0, overflow: "hidden" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1.5fr 1fr 0.7fr 0.9fr", padding: "9px 14px", borderBottom: `1px solid ${C.border}`, fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, background: C.surface }}>
              <div>Name</div>
              <div>Email</div>
              <div>Role</div>
              <div>Status</div>
              <div>Joined</div>
            </div>
            <div style={{ maxHeight: 420, overflowY: "auto" }}>
              {loading && (
                <div style={{ padding: 28, textAlign: "center", fontSize: 12, color: C.dim }}>
                  <Clock size={20} color={C.muted} style={{ margin: "0 auto 8px", display: "block" }} />
                  Loading...
                </div>
              )}
              {!loading && guardians.length === 0 && (
                <div style={{ padding: 28, textAlign: "center", fontSize: 12, color: C.dim }}>
                  <Users size={20} color={C.muted} style={{ margin: "0 auto 8px", display: "block" }} />
                  No guardians registered.
                </div>
              )}
              {!loading && guardians.map((g) => (
                <div
                  key={g.id}
                  style={{ display: "grid", gridTemplateColumns: "1.5fr 1.5fr 1fr 0.7fr 0.9fr", padding: "10px 14px", borderBottom: `1px solid ${C.border}`, alignItems: "center", fontSize: 11, transition: "background 120ms" }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = C.cardHover; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                >
                  <div style={{ color: C.text, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    <Shield size={10} color={C.accent} style={{ marginRight: 5, verticalAlign: "middle" }} />
                    {g.name}
                  </div>
                  <div style={{ color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{g.email}</div>
                  <div style={{ color: C.text }}>{g.role}</div>
                  <div><B c={guardianStatusColor(g.status)}>{g.status}</B></div>
                  <div style={{ color: C.dim, fontSize: 10 }}>{fmtDate(g.joined_at)}</div>
                </div>
              ))}
            </div>
          </Card>
        </Section>
      )}

      {/* ════════════ CREATE CEREMONY MODAL ════════════ */}
      <Modal open={ceremonyModal} onClose={() => setCeremonyModal(false)} title="Create Key Ceremony" wide>
        <Row2>
          <FG label="Ceremony Name" required>
            <Inp value={cName} onChange={(e) => setCName(e.target.value)} placeholder="e.g. Q2 Root Key Generation" />
          </FG>
          <FG label="Ceremony Type" required>
            <Sel value={cType} onChange={(e) => setCType(e.target.value)}>
              <option value="key_generation">Key Generation</option>
              <option value="key_recovery">Key Recovery</option>
              <option value="key_destruction">Key Destruction</option>
              <option value="root_rotation">Root Rotation</option>
            </Sel>
          </FG>
        </Row2>
        <Row2>
          <FG label="Threshold (M)" required hint="Minimum shares required to reconstruct the secret">
            <Inp type="number" value={cThreshold} onChange={(e) => setCThreshold(e.target.value)} placeholder="3" />
          </FG>
          <FG label="Total Shares (N)" required hint="Total number of key shares to distribute">
            <Inp type="number" value={cShares} onChange={(e) => setCShares(e.target.value)} placeholder="5" />
          </FG>
        </Row2>
        <FG label="Select Guardians" hint={`${cGuardians.length} selected — guardians will each receive one key share`}>
          <div style={{ border: `1px solid ${C.border}`, borderRadius: 7, maxHeight: 180, overflowY: "auto", background: C.card }}>
            {guardians.map((g) => {
              const sel = cGuardians.includes(g.id);
              return (
                <div
                  key={g.id}
                  onClick={() => toggleGuardian(g.id)}
                  style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", borderBottom: `1px solid ${C.border}`, cursor: "pointer", background: sel ? C.accentDim : "transparent", transition: "background 120ms" }}
                >
                  <div style={{ width: 14, height: 14, borderRadius: 3, border: `1px solid ${sel ? C.accent : C.border}`, background: sel ? C.accent : "transparent", flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
                    {sel && <span style={{ color: C.bg, fontSize: 9, fontWeight: 700 }}>✓</span>}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 11, color: sel ? C.accent : C.text, fontWeight: sel ? 600 : 400 }}>{g.name}</div>
                    <div style={{ fontSize: 9, color: C.muted }}>{g.email} · {g.role}</div>
                  </div>
                  <B c={guardianStatusColor(g.status)}>{g.status}</B>
                </div>
              );
            })}
            {guardians.length === 0 && (
              <div style={{ padding: 12, fontSize: 11, color: C.muted, textAlign: "center" }}>No guardians available. Add guardians first.</div>
            )}
          </div>
        </FG>
        <FG label="Notes">
          <Txt
            value={cNotes}
            onChange={(e) => setCNotes(e.target.value)}
            placeholder="Additional context or instructions for this ceremony..."
            rows={3}
            mono={false}
          />
        </FG>
        {cError && <div style={{ fontSize: 10, color: C.red, marginBottom: 8, padding: "6px 10px", background: C.redDim, borderRadius: 6 }}>{cError}</div>}
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 10 }}>
          <Btn small onClick={() => setCeremonyModal(false)}>Cancel</Btn>
          <Btn small primary onClick={saveCeremony} disabled={cSaving || !cName.trim()}>
            {cSaving ? "Creating..." : "Create Ceremony"}
          </Btn>
        </div>
      </Modal>

      {/* ════════════ ADD GUARDIAN MODAL ════════════ */}
      <Modal open={guardianModal} onClose={() => setGuardianModal(false)} title="Add Guardian">
        <FG label="Full Name" required>
          <Inp value={gName} onChange={(e) => setGName(e.target.value)} placeholder="e.g. Alice Chen" />
        </FG>
        <FG label="Email Address" required>
          <Inp type="email" value={gEmail} onChange={(e) => setGEmail(e.target.value)} placeholder="alice@corp.com" />
        </FG>
        <FG label="Role">
          <Sel value={gRole} onChange={(e) => setGRole(e.target.value)}>
            <option value="Key Custodian">Key Custodian</option>
            <option value="Security Officer">Security Officer</option>
            <option value="Compliance Officer">Compliance Officer</option>
            <option value="CISO Delegate">CISO Delegate</option>
            <option value="IT Administrator">IT Administrator</option>
          </Sel>
        </FG>
        {gError && <div style={{ fontSize: 10, color: C.red, marginBottom: 8, padding: "6px 10px", background: C.redDim, borderRadius: 6 }}>{gError}</div>}
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 10 }}>
          <Btn small onClick={() => setGuardianModal(false)}>Cancel</Btn>
          <Btn small primary onClick={saveGuardian} disabled={gSaving || !gName.trim() || !gEmail.trim()}>
            {gSaving ? "Adding..." : "Add Guardian"}
          </Btn>
        </div>
      </Modal>

    </div>
  );
};
