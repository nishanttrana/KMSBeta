import { Plus, Trash2, UserCheck, UserX } from "lucide-react";
import { useState } from "react";
import type { AuthSession } from "../../../../lib/auth";
import { ACCESS_CAPABILITIES, ACCESS_SUBJECT_TYPES, createAccessRule, deleteAccessRule, type AccessRule } from "../../../../lib/secrets";
import { B, Btn, Chk, FG, Inp, Modal, Row2, Sel } from "../../legacyPrimitives";
import { errMsg } from "../../runtimeUtils";
import { C } from "../../theme";

const MONO = "'JetBrains Mono',ui-monospace,monospace";

// What each capability lets the named callers do (services/secrets/access.go).
export const CAPABILITY_HINT: Record<string, string> = {
  read: "See it: metadata, versions, history",
  value: "Read the value",
  write: "Create, edit, rotate, roll back, restore",
  delete: "Delete and destroy",
};

export const RuleRow = ({ rule, onDelete }: { rule: AccessRule; onDelete?: (() => void) | undefined }) => {
  const deny = rule.effect === "deny";
  const Icon = deny ? UserX : UserCheck;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "70px minmax(120px,1.4fr) minmax(120px,1.2fr) minmax(160px,1.6fr) 28px", gap: 10, alignItems: "center", padding: "8px 4px", borderBottom: `1px solid ${C.border}`, fontSize: 11 }}>
      <span style={{ display: "inline-flex", alignItems: "center", gap: 5, color: deny ? C.redFg : C.greenFg, fontWeight: 600 }}><Icon size={12} />{deny ? "Deny" : "Allow"}</span>
      <code style={{ fontFamily: MONO, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={rule.path}>{rule.path}</code>
      <span style={{ color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={`${rule.subject_type}: ${rule.subject_id}`}>
        <span style={{ color: C.muted }}>{rule.subject_type} </span>{rule.subject_id}
      </span>
      <span style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>{rule.capabilities.map((c) => <B key={c} c={deny ? "red" : "accent"}>{c}</B>)}</span>
      {onDelete ? <button type="button" title="Delete rule" onClick={onDelete} style={{ background: "none", border: "none", color: C.redFg, cursor: "pointer", padding: 2 }}><Trash2 size={13} /></button> : <span />}
    </div>
  );
};

type Props = {
  session: AuthSession;
  rules: AccessRule[] | null;
  error: string;
  restricted: number;
  total: number;
  confirm: (opts: Record<string, unknown>) => Promise<boolean>;
  onChanged: () => void;
  onToast?: ((m: string) => void) | undefined;
};

export function AccessRules({ session, rules, error, restricted, total, confirm, onChanged, onToast }: Props) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [path, setPath] = useState("");
  const [subjectType, setSubjectType] = useState<string>("role");
  const [subjectId, setSubjectId] = useState("");
  const [caps, setCaps] = useState<string[]>([...ACCESS_CAPABILITIES]);
  const [effect, setEffect] = useState("allow");

  const save = async () => {
    setBusy(true);
    try {
      await createAccessRule(session, { path: path.trim(), subject_type: subjectType, subject_id: subjectId.trim(), capabilities: caps, effect });
      onToast?.("Access rule created.");
      setOpen(false); setPath(""); setSubjectId("");
      onChanged();
    } catch (e) { onToast?.(`Rule refused: ${errMsg(e)}`); } finally { setBusy(false); }
  };

  const remove = async (rule: AccessRule) => {
    const ok = await confirm({ title: "Delete access rule", message: `Delete the ${rule.effect} rule on ${rule.path} for ${rule.subject_type} ${rule.subject_id}? If it was the only allow rule there, those secrets open to everyone with the secrets permission.`, confirmLabel: "Delete", danger: true });
    if (!ok) return;
    try { await deleteAccessRule(session, rule.id); onToast?.("Access rule deleted."); onChanged(); } catch (e) { onToast?.(`Delete failed: ${errMsg(e)}`); }
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, marginBottom: 10, flexWrap: "wrap" }}>
        <span style={{ fontSize: 11, color: C.muted }}>
          {rules ? `${rules.length} rule${rules.length === 1 ? "" : "s"} · ${restricted} of ${total} secrets restricted · a path with no allow rule is open to the secrets permission` : ""}
        </span>
        <Btn small primary onClick={() => setOpen(true)}><Plus size={12} />Add rule</Btn>
      </div>
      {error ? <div style={{ fontSize: 11.5, color: C.redFg }}>Access rules unavailable: {error}</div>
        : rules && rules.length === 0 ? <div style={{ fontSize: 12, color: C.muted, textAlign: "center", padding: "28px 0" }}>No access rules. Every secret is open to callers with the secrets permission.</div>
        : (rules || []).map((r) => <RuleRow key={r.id} rule={r} onDelete={() => void remove(r)} />)}

      <Modal open={open} onClose={() => setOpen(false)} title="Add access rule">
        <FG label="Path" required hint="One secret (/finance/prod/ledger-db) or everything under a folder (/finance/*)">
          <Inp mono placeholder="/finance/*" value={path} onChange={(e) => setPath(e.target.value)} />
        </FG>
        <Row2>
          <FG label="Who" required>
            <Sel value={subjectType} onChange={(e) => setSubjectType(e.target.value)}>
              {ACCESS_SUBJECT_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </Sel>
          </FG>
          <FG label={subjectType === "role" ? "Role name" : subjectType === "workload" ? "Workload identity" : `${subjectType} ID`} required>
            <Inp value={subjectId} onChange={(e) => setSubjectId(e.target.value)} placeholder={subjectType === "role" ? "finance-admin" : subjectType === "workload" ? "spiffe://..." : ""} />
          </FG>
        </Row2>
        <FG label="Effect" hint={effect === "allow" ? "Only the callers allow rules name may do this on the path" : "Refuses this caller, even where an allow rule names them"}>
          <Sel value={effect} onChange={(e) => setEffect(e.target.value)}>
            <option value="allow">Allow (and restrict to those named)</option>
            <option value="deny">Deny</option>
          </Sel>
        </FG>
        <FG label="Capabilities" required>
          {ACCESS_CAPABILITIES.map((c) => {
            const toggle = () => setCaps((cur) => cur.includes(c) ? cur.filter((x) => x !== c) : ACCESS_CAPABILITIES.filter((x) => x === c || cur.includes(x)));
            return <Chk key={c} checked={caps.includes(c)} onChange={toggle}
              label={<span onClick={toggle}><b style={{ color: C.text }}>{c}</b> <span style={{ color: C.muted }}>{CAPABILITY_HINT[c]}</span></span>} />;
          })}
        </FG>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 14 }}>
          <Btn onClick={() => setOpen(false)} disabled={busy}>Cancel</Btn>
          <Btn primary onClick={() => void save()} disabled={busy || !path.trim() || !subjectId.trim() || caps.length === 0}>{busy ? "Saving..." : "Add rule"}</Btn>
        </div>
      </Modal>
    </div>
  );
}
