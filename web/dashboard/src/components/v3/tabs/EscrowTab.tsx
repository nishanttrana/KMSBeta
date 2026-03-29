// @ts-nocheck
import { useEffect, useState } from "react";
import {
  Shield, Key, Users, FileText, CheckCircle2, XCircle, Clock, AlertTriangle,
  Plus, RefreshCcw, User, Building2, Mail, ToggleLeft, ToggleRight, Lock,
  Unlock, ChevronDown
} from "lucide-react";
import {
  listGuardians,
  addGuardian,
  listPolicies,
  createPolicy,
  listEscrowedKeys,
  escrowKey,
  listRecoveryRequests,
  createRecoveryRequest,
  approveRecovery,
  denyRecovery,
  type EscrowGuardian,
  type EscrowPolicy,
  type EscrowedKey,
  type RecoveryRequest,
} from "../../../lib/escrow";
import { listKeys, type KeyItem } from "../../../lib/keycore";
import { C } from "../../v3/theme";

/* ─── Helpers ─── */
function fmt(iso?: string) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}
function fmtFull(iso?: string) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" });
}
function recoveryStatusColor(s: string) {
  if (s === "approved" || s === "completed") return C.green;
  if (s === "denied") return C.red;
  if (s === "pending") return C.amber;
  return C.muted;
}
function escrowStatusColor(s: string) {
  if (s === "active") return C.green;
  if (s === "under_recovery") return C.amber;
  if (s === "recovered") return C.blue;
  if (s === "destroyed") return C.red;
  return C.muted;
}

/* ─── Shared Primitives ─── */
const TH = ({ children }: any) => (
  <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}`, whiteSpace: "nowrap" }}>{children}</th>
);
const TD = ({ children, mono }: any) => (
  <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{children}</td>
);
const Badge = ({ color, children }: any) => (
  <span style={{ display: "inline-flex", alignItems: "center", gap: 3, padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600, textTransform: "capitalize", letterSpacing: 0.3 }}>{children}</span>
);
const Btn = ({ onClick, children, variant = "default", disabled = false, small = false }: any) => {
  const base: any = { display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: small ? 11 : 12, fontWeight: 600, cursor: disabled ? "not-allowed" : "pointer", border: "none", transition: "opacity .15s", opacity: disabled ? 0.5 : 1 };
  const styles: any = {
    default: { background: C.accent, color: C.bg },
    ghost: { background: `rgba(255,255,255,.06)`, color: C.dim, border: `1px solid ${C.border}` },
    danger: { background: C.redDim, color: C.red, border: `1px solid ${C.red}33` },
    success: { background: C.greenDim, color: C.green, border: `1px solid ${C.green}33` },
  };
  return <button onClick={disabled ? undefined : onClick} style={{ ...base, ...styles[variant] }}>{children}</button>;
};
const Inp = ({ label, ...props }: any) => (
  <div style={{ marginBottom: 12 }}>
    {label && <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>{label}</div>}
    <input {...props} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box", ...props.style }} />
  </div>
);
const StatCard = ({ icon, label, value, color = C.accent, tint }: any) => (
  <div style={{ flex: 1, minWidth: 140, background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "14px 16px", display: "flex", flexDirection: "column", gap: 8, backgroundImage: tint ? `linear-gradient(135deg, ${tint}, transparent)` : undefined }}>
    <div style={{ display: "flex", alignItems: "center", gap: 6, color }}>
      {icon}
      <span style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, fontWeight: 600 }}>{label}</span>
    </div>
    <div style={{ fontSize: 26, fontWeight: 800, color, lineHeight: 1 }}>{value}</div>
  </div>
);
const SubTab = ({ active, onClick, children }: any) => (
  <button onClick={onClick} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", border: "none", background: active ? C.accent : "transparent", color: active ? C.bg : C.dim, transition: "all .15s" }}>{children}</button>
);
const EmptyState = ({ icon, message }: any) => (
  <div style={{ padding: "40px 0", textAlign: "center", color: C.muted }}>
    <div style={{ marginBottom: 10, opacity: 0.4 }}>{icon}</div>
    <div style={{ fontSize: 13 }}>{message}</div>
  </div>
);

/* ─── Create Policy Modal ─── */
const CreatePolicyModal = ({ open, onClose, onSubmit, busy, guardians }: any) => {
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [keyFilter, setKeyFilter] = useState("");
  const [threshold, setThreshold] = useState("2");
  const [selectedGuardians, setSelectedGuardians] = useState<string[]>([]);
  const [jurisdiction, setJurisdiction] = useState("US-Federal");
  const [legalHold, setLegalHold] = useState(false);

  function reset() { setName(""); setDesc(""); setKeyFilter(""); setThreshold("2"); setSelectedGuardians([]); setJurisdiction("US-Federal"); setLegalHold(false); }
  function handleClose() { reset(); onClose(); }
  function toggleGuardian(id: string) {
    setSelectedGuardians(prev => prev.includes(id) ? prev.filter(g => g !== id) : [...prev, id]);
  }
  function handleSubmit() {
    if (!name.trim() || !keyFilter.trim() || selectedGuardians.length === 0) return;
    onSubmit({ name: name.trim(), description: desc.trim(), key_filter: keyFilter.trim(), threshold: Number(threshold) || 2, guardian_ids: selectedGuardians, jurisdiction, legal_hold: legalHold, enabled: true });
    reset();
  }

  if (!open) return null;
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }} onClick={handleClose}>
      <div style={{ position: "absolute", inset: 0, background: "rgba(0,0,0,.7)", backdropFilter: "blur(4px)" }} />
      <div onClick={e => e.stopPropagation()} style={{ position: "relative", background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 14, width: 560, maxHeight: "88vh", overflow: "auto", boxShadow: "0 24px 60px rgba(0,0,0,.5)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 20px", borderBottom: `1px solid ${C.border}`, position: "sticky", top: 0, background: C.surface, zIndex: 1, borderRadius: "14px 14px 0 0" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Shield size={15} color={C.accent} />
            <span style={{ fontSize: 15, fontWeight: 700, color: C.text }}>Create Escrow Policy</span>
          </div>
          <button onClick={handleClose} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 18, lineHeight: 1 }}>✕</button>
        </div>
        <div style={{ padding: "20px" }}>
          <Inp label="Policy Name" placeholder="e.g. PCI-DSS Payment Keys" value={name} onChange={e => setName(e.target.value)} />
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Description</div>
            <textarea value={desc} onChange={e => setDesc(e.target.value)} placeholder="Describe the purpose and legal basis for this escrow policy…" style={{ width: "100%", minHeight: 70, background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", resize: "vertical", boxSizing: "border-box" }} />
          </div>
          <Inp label="Key Filter (tag or name pattern)" placeholder="tag:payment OR name:pmt-*" value={keyFilter} onChange={e => setKeyFilter(e.target.value)} />
          <div style={{ display: "flex", gap: 12, marginBottom: 12 }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Required Approvals (M)</div>
              <input type="number" min="1" value={threshold} onChange={e => setThreshold(e.target.value)} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", boxSizing: "border-box" }} />
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Total Guardians (N)</div>
              <input type="number" min="1" value={guardians.length || "0"} readOnly style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.muted, fontSize: 12, outline: "none", boxSizing: "border-box" }} />
            </div>
          </div>

          {/* Guardian multi-select */}
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, color: C.dim, marginBottom: 6, fontWeight: 500 }}>Select Guardians</div>
            {guardians.length === 0 ? (
              <div style={{ padding: "12px", background: C.card, borderRadius: 7, border: `1px solid ${C.border}`, fontSize: 11, color: C.muted, textAlign: "center" }}>
                No guardians available — add guardians first
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {guardians.map((g: EscrowGuardian) => {
                  const sel = selectedGuardians.includes(g.id);
                  return (
                    <div key={g.id} onClick={() => toggleGuardian(g.id)} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", background: sel ? C.accentDim : C.card, border: `1px solid ${sel ? C.accent : C.border}`, borderRadius: 7, cursor: "pointer", transition: "all .15s" }}>
                      <div style={{ width: 16, height: 16, borderRadius: 4, border: `2px solid ${sel ? C.accent : C.muted}`, background: sel ? C.accent : "transparent", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                        {sel && <span style={{ color: C.bg, fontSize: 10, fontWeight: 800 }}>✓</span>}
                      </div>
                      <User size={12} color={sel ? C.accent : C.muted} />
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{g.name}</div>
                        <div style={{ fontSize: 10, color: C.muted }}>{g.organization}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Jurisdiction</div>
            <select value={jurisdiction} onChange={e => setJurisdiction(e.target.value)} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none" }}>
              {["US-Federal", "US-HIPAA", "EU-GDPR", "UK-ICO", "APAC-MAS", "Global"].map(j => <option key={j} value={j}>{j}</option>)}
            </select>
          </div>

          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16, padding: "10px 12px", background: C.card, borderRadius: 7, border: `1px solid ${C.border}` }}>
            <div>
              <div style={{ fontSize: 12, color: C.text, fontWeight: 500 }}>Legal Hold</div>
              <div style={{ fontSize: 10, color: C.muted }}>Prevents destruction of escrowed material</div>
            </div>
            <button onClick={() => setLegalHold(v => !v)} style={{ background: "none", border: "none", cursor: "pointer", color: legalHold ? C.amber : C.muted, display: "flex", alignItems: "center" }}>
              {legalHold ? <ToggleRight size={22} /> : <ToggleLeft size={22} />}
            </button>
          </div>

          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <Btn variant="ghost" onClick={handleClose}>Cancel</Btn>
            <Btn onClick={handleSubmit} disabled={busy || !name.trim() || !keyFilter.trim() || selectedGuardians.length === 0}>{busy ? "Creating…" : "Create Policy"}</Btn>
          </div>
        </div>
      </div>
    </div>
  );
};

/* ─── Escrow Key Modal ─── */
const EscrowKeyModal = ({ open, onClose, onSubmit, busy, policies, guardians, session }: any) => {
  const [keys, setKeys] = useState<KeyItem[]>([]);
  const [loadingKeys, setLoadingKeys] = useState(false);
  const [selectedKey, setSelectedKey] = useState("");
  const [selectedPolicy, setSelectedPolicy] = useState("");
  const [escrowedBy, setEscrowedBy] = useState("admin");

  useEffect(() => {
    if (!open || !session) return;
    setLoadingKeys(true);
    listKeys(session, { limit: 200 }).then(ks => setKeys(ks)).catch(() => setKeys([])).finally(() => setLoadingKeys(false));
  }, [open, session]);

  function reset() { setSelectedKey(""); setSelectedPolicy(""); setEscrowedBy("admin"); }
  function handleClose() { reset(); onClose(); }
  function handleSubmit() {
    const key = keys.find(k => k.id === selectedKey);
    const policy = policies.find((p: EscrowPolicy) => p.id === selectedPolicy);
    if (!key || !policy) return;
    onSubmit({
      policy_id: policy.id,
      policy_name: policy.name,
      key_id: key.id,
      key_name: key.name,
      algorithm: key.algorithm,
      guardian_ids: policy.guardian_ids ?? [],
      escrowed_by: escrowedBy.trim() || "admin",
    });
    reset();
  }

  if (!open) return null;
  const enabledPolicies = (policies as EscrowPolicy[]).filter(p => p.enabled);
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }} onClick={handleClose}>
      <div style={{ position: "absolute", inset: 0, background: "rgba(0,0,0,.7)", backdropFilter: "blur(4px)" }} />
      <div onClick={e => e.stopPropagation()} style={{ position: "relative", background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 14, width: 520, maxHeight: "88vh", overflow: "auto", boxShadow: "0 24px 60px rgba(0,0,0,.5)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 20px", borderBottom: `1px solid ${C.border}`, position: "sticky", top: 0, background: C.surface, zIndex: 1, borderRadius: "14px 14px 0 0" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Key size={15} color={C.accent} />
            <span style={{ fontSize: 15, fontWeight: 700, color: C.text }}>Escrow a Key</span>
          </div>
          <button onClick={handleClose} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 18, lineHeight: 1 }}>✕</button>
        </div>
        <div style={{ padding: "20px" }}>
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Select Key</div>
            {loadingKeys ? (
              <div style={{ padding: "10px 12px", background: C.card, borderRadius: 6, border: `1px solid ${C.border}`, fontSize: 11, color: C.muted }}>Loading keys…</div>
            ) : keys.length === 0 ? (
              <div style={{ padding: "10px 12px", background: C.card, borderRadius: 6, border: `1px solid ${C.border}`, fontSize: 11, color: C.muted }}>No keys found in key catalog</div>
            ) : (
              <select value={selectedKey} onChange={e => setSelectedKey(e.target.value)} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: selectedKey ? C.text : C.muted, fontSize: 12, outline: "none" }}>
                <option value="">Select a key…</option>
                {keys.filter(k => k.status === "active").map(k => (
                  <option key={k.id} value={k.id}>{k.name} — {k.algorithm} ({k.key_type})</option>
                ))}
              </select>
            )}
          </div>
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Escrow Policy</div>
            {enabledPolicies.length === 0 ? (
              <div style={{ padding: "10px 12px", background: C.card, borderRadius: 6, border: `1px solid ${C.border}`, fontSize: 11, color: C.muted }}>No enabled escrow policies — create a policy first</div>
            ) : (
              <select value={selectedPolicy} onChange={e => setSelectedPolicy(e.target.value)} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: selectedPolicy ? C.text : C.muted, fontSize: 12, outline: "none" }}>
                <option value="">Select a policy…</option>
                {enabledPolicies.map((p: EscrowPolicy) => (
                  <option key={p.id} value={p.id}>{p.name} ({p.threshold}-of-{p.guardian_ids?.length ?? 0}, {p.jurisdiction})</option>
                ))}
              </select>
            )}
          </div>
          <Inp label="Escrowed By" placeholder="admin" value={escrowedBy} onChange={e => setEscrowedBy(e.target.value)} />
          <div style={{ padding: "10px 12px", background: C.accentDim, border: `1px solid ${C.accent}33`, borderRadius: 7, marginBottom: 16, display: "flex", gap: 8, alignItems: "flex-start" }}>
            <Shield size={13} color={C.accent} style={{ flexShrink: 0, marginTop: 1 }} />
            <span style={{ fontSize: 11, color: C.accent, lineHeight: 1.5 }}>The key will be placed under the selected policy's guardian threshold. Recovery requires {selectedPolicy ? (policies.find((p: EscrowPolicy) => p.id === selectedPolicy)?.threshold ?? "N") : "N"} guardian approvals.</span>
          </div>
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <Btn variant="ghost" onClick={handleClose}>Cancel</Btn>
            <Btn onClick={handleSubmit} disabled={busy || !selectedKey || !selectedPolicy}>{busy ? "Escrowing…" : "Escrow Key"}</Btn>
          </div>
        </div>
      </div>
    </div>
  );
};

/* ─── Create Recovery Request Modal ─── */
const CreateRecoveryModal = ({ open, onClose, onSubmit, busy, escrowedKeys }: any) => {
  const [escrowId, setEscrowId] = useState("");
  const [requestor, setRequestor] = useState("");
  const [reason, setReason] = useState("");
  const [legalRef, setLegalRef] = useState("");

  function reset() { setEscrowId(""); setRequestor(""); setReason(""); setLegalRef(""); }
  function handleClose() { reset(); onClose(); }
  function handleSubmit() {
    if (!escrowId || !reason.trim() || !requestor.trim()) return;
    onSubmit({ escrow_id: escrowId, requestor: requestor.trim(), reason: reason.trim(), legal_reference: legalRef.trim() || undefined });
    reset();
  }

  if (!open) return null;
  const activeKeys = escrowedKeys.filter((k: EscrowedKey) => k.status === "active");
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }} onClick={handleClose}>
      <div style={{ position: "absolute", inset: 0, background: "rgba(0,0,0,.7)", backdropFilter: "blur(4px)" }} />
      <div onClick={e => e.stopPropagation()} style={{ position: "relative", background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 14, width: 520, maxHeight: "88vh", overflow: "auto", boxShadow: "0 24px 60px rgba(0,0,0,.5)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 20px", borderBottom: `1px solid ${C.border}`, position: "sticky", top: 0, background: C.surface, zIndex: 1, borderRadius: "14px 14px 0 0" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Unlock size={15} color={C.amber} />
            <span style={{ fontSize: 15, fontWeight: 700, color: C.text }}>Create Recovery Request</span>
          </div>
          <button onClick={handleClose} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 18, lineHeight: 1 }}>✕</button>
        </div>
        <div style={{ padding: "20px" }}>
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Escrowed Key</div>
            {activeKeys.length === 0 ? (
              <div style={{ padding: "10px 12px", background: C.card, borderRadius: 6, border: `1px solid ${C.border}`, fontSize: 11, color: C.muted }}>
                No active escrowed keys — escrow a key first
              </div>
            ) : (
              <select value={escrowId} onChange={e => setEscrowId(e.target.value)} style={{ width: "100%", background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: escrowId ? C.text : C.muted, fontSize: 12, outline: "none" }}>
                <option value="">Select an escrowed key…</option>
                {activeKeys.map((k: EscrowedKey) => (
                  <option key={k.id} value={k.id}>{k.key_name} ({k.policy_name})</option>
                ))}
              </select>
            )}
          </div>
          <Inp label="Requestor (your name / email)" placeholder="e.g. alice@company.com" value={requestor} onChange={e => setRequestor(e.target.value)} />
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 11, color: C.dim, marginBottom: 4, fontWeight: 500 }}>Reason for Recovery</div>
            <textarea value={reason} onChange={e => setReason(e.target.value)} placeholder="Provide a detailed justification for accessing the escrowed key material…" style={{ width: "100%", minHeight: 90, background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "7px 10px", color: C.text, fontSize: 12, outline: "none", resize: "vertical", boxSizing: "border-box" }} />
          </div>
          <Inp label="Legal Reference (optional)" placeholder="e.g. 18 U.S.C. § 2703 / Court Order #2026-12345" value={legalRef} onChange={e => setLegalRef(e.target.value)} />
          <div style={{ padding: "10px 12px", background: C.amberDim, border: `1px solid ${C.amber}33`, borderRadius: 7, marginBottom: 16, display: "flex", gap: 8, alignItems: "flex-start" }}>
            <AlertTriangle size={13} color={C.amber} style={{ flexShrink: 0, marginTop: 1 }} />
            <span style={{ fontSize: 11, color: C.amber, lineHeight: 1.5 }}>Recovery requests require guardian approval according to the policy threshold. All activity is immutably logged.</span>
          </div>
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <Btn variant="ghost" onClick={handleClose}>Cancel</Btn>
            <Btn onClick={handleSubmit} disabled={busy || !escrowId || !reason.trim() || !requestor.trim() || activeKeys.length === 0}>{busy ? "Submitting…" : "Submit Request"}</Btn>
          </div>
        </div>
      </div>
    </div>
  );
};

/* ─── Add Guardian Modal ─── */
const AddGuardianModal = ({ open, onClose, onSubmit, busy }: any) => {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [org, setOrg] = useState("");

  function reset() { setName(""); setEmail(""); setOrg(""); }
  function handleClose() { reset(); onClose(); }
  function handleSubmit() {
    if (!name.trim() || !email.trim() || !org.trim()) return;
    onSubmit({ name: name.trim(), email: email.trim(), organization: org.trim() });
    reset();
  }

  if (!open) return null;
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }} onClick={handleClose}>
      <div style={{ position: "absolute", inset: 0, background: "rgba(0,0,0,.7)", backdropFilter: "blur(4px)" }} />
      <div onClick={e => e.stopPropagation()} style={{ position: "relative", background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 14, width: 460, maxHeight: "88vh", overflow: "auto", boxShadow: "0 24px 60px rgba(0,0,0,.5)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 20px", borderBottom: `1px solid ${C.border}`, position: "sticky", top: 0, background: C.surface, zIndex: 1, borderRadius: "14px 14px 0 0" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Users size={15} color={C.accent} />
            <span style={{ fontSize: 15, fontWeight: 700, color: C.text }}>Add Guardian</span>
          </div>
          <button onClick={handleClose} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 18, lineHeight: 1 }}>✕</button>
        </div>
        <div style={{ padding: "20px" }}>
          <Inp label="Full Name" placeholder="e.g. Alice Mercer" value={name} onChange={e => setName(e.target.value)} />
          <Inp label="Email Address" type="email" placeholder="guardian@organization.com" value={email} onChange={e => setEmail(e.target.value)} />
          <Inp label="Organization" placeholder="e.g. Crane & Associates LLP" value={org} onChange={e => setOrg(e.target.value)} />
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 4 }}>
            <Btn variant="ghost" onClick={handleClose}>Cancel</Btn>
            <Btn onClick={handleSubmit} disabled={busy || !name.trim() || !email.trim() || !org.trim()}>{busy ? "Adding…" : "Add Guardian"}</Btn>
          </div>
        </div>
      </div>
    </div>
  );
};

/* ─── Main Component ─── */
export const EscrowTab = ({ session, enabledFeatures, keyCatalog }: { session: any; enabledFeatures?: any; keyCatalog?: any[] }) => {
  const [section, setSection] = useState<"policies" | "keys" | "recovery" | "guardians">("policies");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [guardians, setGuardians] = useState<EscrowGuardian[]>([]);
  const [policies, setPolicies] = useState<EscrowPolicy[]>([]);
  const [escrowedKeys, setEscrowedKeys] = useState<EscrowedKey[]>([]);
  const [recoveryRequests, setRecoveryRequests] = useState<RecoveryRequest[]>([]);

  const [policyModal, setPolicyModal] = useState(false);
  const [recoveryModal, setRecoveryModal] = useState(false);
  const [guardianModal, setGuardianModal] = useState(false);
  const [escrowKeyModal, setEscrowKeyModal] = useState(false);
  const [policyBusy, setPolicyBusy] = useState(false);
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const [guardianBusy, setGuardianBusy] = useState(false);
  const [escrowKeyBusy, setEscrowKeyBusy] = useState(false);
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const [gs, ps, eks, rrs] = await Promise.all([
        listGuardians(session),
        listPolicies(session),
        listEscrowedKeys(session),
        listRecoveryRequests(session),
      ]);
      setGuardians(gs);
      setPolicies(ps);
      setEscrowedKeys(eks);
      setRecoveryRequests(rrs);
    } catch (e: any) {
      setError(e?.message || "Failed to load escrow data");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function handleCreatePolicy(data: any) {
    setPolicyBusy(true);
    try {
      const pol = await createPolicy(session, data);
      setPolicies(prev => [pol, ...prev]);
      setPolicyModal(false);
    } catch (e: any) {
      setActionError(e?.message || "Failed to create policy");
    } finally {
      setPolicyBusy(false);
    }
  }

  async function handleCreateRecovery(data: any) {
    setRecoveryBusy(true);
    try {
      const rr = await createRecoveryRequest(session, data);
      setRecoveryRequests(prev => [rr, ...prev]);
      setRecoveryModal(false);
    } catch (e: any) {
      setActionError(e?.message || "Failed to submit recovery request");
    } finally {
      setRecoveryBusy(false);
    }
  }

  async function handleEscrowKey(data: any) {
    setEscrowKeyBusy(true);
    try {
      const ek = await escrowKey(session, data);
      setEscrowedKeys(prev => [ek, ...prev]);
      // Refresh policies so escrow_count updates
      listPolicies(session).then(ps => setPolicies(ps)).catch(() => {});
      setEscrowKeyModal(false);
    } catch (e: any) {
      setActionError(e?.message || "Failed to escrow key");
    } finally {
      setEscrowKeyBusy(false);
    }
  }

  async function handleAddGuardian(data: any) {
    setGuardianBusy(true);
    try {
      const g = await addGuardian(session, data);
      setGuardians(prev => [...prev, g]);
      setGuardianModal(false);
    } catch (e: any) {
      setActionError(e?.message || "Failed to add guardian");
    } finally {
      setGuardianBusy(false);
    }
  }

  async function handleApprove(id: string) {
    setActionBusy(id);
    setActionError(null);
    try {
      const updated = await approveRecovery(session, id);
      setRecoveryRequests(prev => prev.map(r => r.id === id ? updated : r));
    } catch (e: any) {
      setActionError(e?.message || "Failed to approve request");
    } finally {
      setActionBusy(null);
    }
  }

  async function handleDeny(id: string) {
    setActionBusy(id + "-deny");
    setActionError(null);
    try {
      const updated = await denyRecovery(session, id, "Denied by administrator");
      setRecoveryRequests(prev => prev.map(r => r.id === id ? updated : r));
    } catch (e: any) {
      setActionError(e?.message || "Failed to deny request");
    } finally {
      setActionBusy(null);
    }
  }

  /* Stat counts */
  const activeEscrows = escrowedKeys.filter(k => k.status === "active").length;
  const enabledPolicies = policies.filter(p => p.enabled).length;
  const pendingRecovery = recoveryRequests.filter(r => r.status === "pending").length;

  return (
    <div style={{ padding: "20px 24px", display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
            <Lock size={18} color={C.accent} />
            <span style={{ fontSize: 17, fontWeight: 800, color: C.text, letterSpacing: -0.4 }}>Key Escrow</span>
          </div>
          <div style={{ fontSize: 12, color: C.muted }}>Formal key escrow with guardian management and governed recovery workflow</div>
        </div>
        <Btn onClick={load} variant="ghost" small><RefreshCcw size={13} />Refresh</Btn>
      </div>

      {/* Stat Cards */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        <StatCard icon={<Key size={14} />} label="Escrowed Keys" value={loading ? "—" : escrowedKeys.length} color={C.accent} tint={C.accentTint} />
        <StatCard icon={<Shield size={14} />} label="Active Policies" value={loading ? "—" : enabledPolicies} color={C.green} tint={C.greenTint} />
        <StatCard icon={<AlertTriangle size={14} />} label="Pending Recovery" value={loading ? "—" : pendingRecovery} color={C.amber} tint={C.amberTint} />
        <StatCard icon={<Users size={14} />} label="Guardians" value={loading ? "—" : guardians.length} color={C.purple} tint={C.purpleTint} />
      </div>

      {/* Error banner */}
      {(error || actionError) && (
        <div style={{ padding: "10px 14px", background: C.redDim, border: `1px solid ${C.red}33`, borderRadius: 8, display: "flex", alignItems: "center", gap: 8 }}>
          <XCircle size={14} color={C.red} />
          <span style={{ fontSize: 12, color: C.red }}>{error || actionError}</span>
          <button onClick={() => { setError(null); setActionError(null); }} style={{ marginLeft: "auto", background: "none", border: "none", color: C.red, cursor: "pointer", fontSize: 14 }}>✕</button>
        </div>
      )}

      {loading && (
        <div style={{ textAlign: "center", padding: "40px 0", color: C.muted, fontSize: 13 }}>
          <RefreshCcw size={20} style={{ display: "block", margin: "0 auto 10px", opacity: 0.5 }} />Loading escrow data…
        </div>
      )}

      {!loading && (
        <>
          {/* Section Tabs */}
          <div style={{ display: "flex", gap: 4, background: C.card, padding: 4, borderRadius: 8, width: "fit-content", border: `1px solid ${C.border}` }}>
            <SubTab active={section === "policies"} onClick={() => setSection("policies")}>Policies {policies.length > 0 && `(${policies.length})`}</SubTab>
            <SubTab active={section === "keys"} onClick={() => setSection("keys")}>Escrowed Keys {escrowedKeys.length > 0 && `(${escrowedKeys.length})`}</SubTab>
            <SubTab active={section === "recovery"} onClick={() => setSection("recovery")}>
              Recovery Requests {pendingRecovery > 0 && <span style={{ background: C.amber, color: C.bg, borderRadius: 10, padding: "0 5px", fontSize: 9, fontWeight: 800, marginLeft: 3 }}>{pendingRecovery}</span>}
            </SubTab>
            <SubTab active={section === "guardians"} onClick={() => setSection("guardians")}>Guardians {guardians.length > 0 && `(${guardians.length})`}</SubTab>
          </div>

          {/* ── Policies Section ── */}
          {section === "policies" && (
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", borderBottom: `1px solid ${C.border}` }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>Escrow Policies</span>
                <Btn small onClick={() => setPolicyModal(true)}><Plus size={12} />Create Policy</Btn>
              </div>
              {policies.length === 0 ? (
                <EmptyState icon={<Shield size={32} />} message="No escrow policies yet — create one to start protecting keys" />
              ) : (
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ background: "rgba(0,0,0,.2)" }}>
                        <TH>Policy Name</TH>
                        <TH>Key Filter</TH>
                        <TH>Threshold</TH>
                        <TH>Legal Hold</TH>
                        <TH>Jurisdiction</TH>
                        <TH>Status</TH>
                        <TH>Escrowed</TH>
                      </tr>
                    </thead>
                    <tbody>
                      {policies.map(pol => (
                        <tr key={pol.id} onMouseEnter={e => (e.currentTarget.style.background = C.cardHover)} onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                          <TD>
                            <div style={{ fontWeight: 600 }}>{pol.name}</div>
                            <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{pol.description?.slice(0, 52)}{pol.description?.length > 52 ? "…" : ""}</div>
                          </TD>
                          <TD mono><span style={{ fontSize: 10, color: C.cyan }}>{pol.key_filter}</span></TD>
                          <TD><Badge color={C.accent}>{pol.threshold}-of-{pol.guardian_ids?.length ?? 0}</Badge></TD>
                          <TD>{pol.legal_hold ? <Badge color={C.amber}>Legal Hold</Badge> : <span style={{ color: C.muted, fontSize: 11 }}>—</span>}</TD>
                          <TD><Badge color={C.blue}>{pol.jurisdiction}</Badge></TD>
                          <TD>{pol.enabled ? <Badge color={C.green}>Enabled</Badge> : <Badge color={C.muted}>Disabled</Badge>}</TD>
                          <TD><Badge color={C.purple}>{pol.escrow_count ?? 0}</Badge></TD>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* ── Escrowed Keys Section ── */}
          {section === "keys" && (
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", borderBottom: `1px solid ${C.border}` }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>Escrowed Keys</span>
                <div style={{ display: "flex", gap: 6 }}>
                  <Btn small variant="ghost" onClick={() => setRecoveryModal(true)}><Unlock size={12} />Recovery Request</Btn>
                  <Btn small onClick={() => setEscrowKeyModal(true)}><Key size={12} />Escrow a Key</Btn>
                </div>
              </div>
              {escrowedKeys.length === 0 ? (
                <EmptyState icon={<Key size={32} />} message="No keys have been escrowed yet" />
              ) : (
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ background: "rgba(0,0,0,.2)" }}>
                        <TH>Key Name</TH>
                        <TH>Algorithm</TH>
                        <TH>Policy</TH>
                        <TH>Escrowed At</TH>
                        <TH>Guardians</TH>
                        <TH>Status</TH>
                      </tr>
                    </thead>
                    <tbody>
                      {escrowedKeys.map(ek => {
                        const sc = escrowStatusColor(ek.status);
                        return (
                          <tr key={ek.id} onMouseEnter={e => (e.currentTarget.style.background = C.cardHover)} onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                            <TD><div style={{ display: "flex", alignItems: "center", gap: 6 }}><Key size={12} color={C.accent} /><span style={{ fontWeight: 600 }}>{ek.key_name}</span></div></TD>
                            <TD mono>{ek.algorithm}</TD>
                            <TD><Badge color={C.blue}>{ek.policy_name}</Badge></TD>
                            <TD>{fmtFull(ek.escrowed_at)}</TD>
                            <TD><Badge color={C.purple}>{ek.guardian_ids?.length ?? 0} guardians</Badge></TD>
                            <TD><Badge color={sc}>{ek.status.replace(/_/g, " ")}</Badge></TD>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* ── Recovery Requests Section ── */}
          {section === "recovery" && (
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", borderBottom: `1px solid ${C.border}` }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>Recovery Requests</span>
                <Btn small onClick={() => setRecoveryModal(true)}><Plus size={12} />New Request</Btn>
              </div>
              {recoveryRequests.length === 0 ? (
                <EmptyState icon={<Unlock size={32} />} message="No recovery requests have been submitted" />
              ) : (
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ background: "rgba(0,0,0,.2)" }}>
                        <TH>Key Name</TH>
                        <TH>Requestor</TH>
                        <TH>Reason</TH>
                        <TH>Legal Reference</TH>
                        <TH>Approvals</TH>
                        <TH>Status</TH>
                        <TH>Created</TH>
                        <TH>Actions</TH>
                      </tr>
                    </thead>
                    <tbody>
                      {recoveryRequests.map(rr => {
                        const sc = recoveryStatusColor(rr.status);
                        const isPending = rr.status === "pending";
                        return (
                          <tr key={rr.id} onMouseEnter={e => (e.currentTarget.style.background = C.cardHover)} onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                            <TD><div style={{ display: "flex", alignItems: "center", gap: 6 }}><Key size={11} color={C.accent} /><span style={{ fontWeight: 600 }}>{rr.key_name}</span></div></TD>
                            <TD><span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }}>{rr.requestor}</span></TD>
                            <TD><span title={rr.reason} style={{ color: C.dim }}>{rr.reason?.slice(0, 48)}{rr.reason?.length > 48 ? "…" : ""}</span></TD>
                            <TD mono><span style={{ fontSize: 10 }}>{rr.legal_reference || "—"}</span></TD>
                            <TD><Badge color={C.blue}>{rr.approvals?.length ?? 0}/{rr.required_approvals}</Badge></TD>
                            <TD><Badge color={sc}>{rr.status}</Badge></TD>
                            <TD>{fmt(rr.created_at)}</TD>
                            <TD>
                              {isPending ? (
                                <div style={{ display: "flex", gap: 5 }}>
                                  <Btn small variant="success" onClick={() => handleApprove(rr.id)} disabled={actionBusy === rr.id}><CheckCircle2 size={11} />{actionBusy === rr.id ? "…" : "Approve"}</Btn>
                                  <Btn small variant="danger" onClick={() => handleDeny(rr.id)} disabled={actionBusy === rr.id + "-deny"}><XCircle size={11} />{actionBusy === rr.id + "-deny" ? "…" : "Deny"}</Btn>
                                </div>
                              ) : <span style={{ fontSize: 10, color: C.muted }}>—</span>}
                            </TD>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* ── Guardians Section ── */}
          {section === "guardians" && (
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 16px", borderBottom: `1px solid ${C.border}` }}>
                <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                  <Users size={14} color={C.accent} />
                  <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>Escrow Guardians</span>
                </div>
                <Btn small onClick={() => setGuardianModal(true)}><Plus size={12} />Add Guardian</Btn>
              </div>
              {guardians.length === 0 ? (
                <EmptyState icon={<Users size={32} />} message="No guardians registered — add guardians to enable key escrow" />
              ) : (
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ background: "rgba(0,0,0,.2)" }}>
                        <TH>Name</TH>
                        <TH>Email</TH>
                        <TH>Organization</TH>
                        <TH>Status</TH>
                        <TH>Added</TH>
                      </tr>
                    </thead>
                    <tbody>
                      {guardians.map(g => (
                        <tr key={g.id} onMouseEnter={e => (e.currentTarget.style.background = C.cardHover)} onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                          <TD><div style={{ display: "flex", alignItems: "center", gap: 7 }}><div style={{ width: 28, height: 28, borderRadius: 14, background: C.accentDim, border: `1px solid ${C.accent}33`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}><User size={13} color={C.accent} /></div><span style={{ fontWeight: 600 }}>{g.name}</span></div></TD>
                          <TD><div style={{ display: "flex", alignItems: "center", gap: 5 }}><Mail size={11} color={C.muted} /><span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }}>{g.email}</span></div></TD>
                          <TD><div style={{ display: "flex", alignItems: "center", gap: 5 }}><Building2 size={11} color={C.muted} />{g.organization}</div></TD>
                          <TD><Badge color={g.status === "active" ? C.green : C.red}>{g.status}</Badge></TD>
                          <TD>{fmt(g.added_at)}</TD>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Modals */}
      <CreatePolicyModal open={policyModal} onClose={() => setPolicyModal(false)} onSubmit={handleCreatePolicy} busy={policyBusy} guardians={guardians} />
      <CreateRecoveryModal open={recoveryModal} onClose={() => setRecoveryModal(false)} onSubmit={handleCreateRecovery} busy={recoveryBusy} escrowedKeys={escrowedKeys} />
      <AddGuardianModal open={guardianModal} onClose={() => setGuardianModal(false)} onSubmit={handleAddGuardian} busy={guardianBusy} />
      <EscrowKeyModal open={escrowKeyModal} onClose={() => setEscrowKeyModal(false)} onSubmit={handleEscrowKey} busy={escrowKeyBusy} policies={policies} guardians={guardians} session={session} />
    </div>
  );
};
