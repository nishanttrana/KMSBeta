import { Plus, Trash2, UserCheck, UserX } from "lucide-react";
import { useEffect, useState } from "react";
import type { AuthSession } from "../../../../lib/auth";
import { ACCESS_CAPABILITIES, ACCESS_SUBJECT_TYPES, createAccessRule, deleteAccessRule, putVaultSettings, type AccessRule, type VaultSettings } from "../../../../lib/secrets";
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

// Access groups by ID, for showing a group rule by its name.
export type GroupNames = Record<string, string>;

export const RuleRow = ({ rule, groups, onDelete }: { rule: AccessRule; groups?: GroupNames | undefined; onDelete?: (() => void) | undefined }) => {
  const deny = rule.effect === "deny";
  const who = rule.subject_type === "group" ? groups?.[rule.subject_id] || rule.subject_id : rule.subject_id;
  const Icon = deny ? UserX : UserCheck;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "70px minmax(120px,1.4fr) minmax(120px,1.2fr) minmax(160px,1.6fr) 28px", gap: 10, alignItems: "center", padding: "8px 4px", borderBottom: `1px solid ${C.border}`, fontSize: 11 }}>
      <span style={{ display: "inline-flex", alignItems: "center", gap: 5, color: deny ? C.redFg : C.greenFg, fontWeight: 600 }}><Icon size={12} />{deny ? "Deny" : "Allow"}</span>
      <code style={{ fontFamily: MONO, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={rule.path}>{rule.path}</code>
      <span style={{ color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={`${rule.subject_type}: ${rule.subject_id}`}>
        <span style={{ color: C.muted }}>{rule.subject_type} </span>{who}
      </span>
      <span style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>{rule.capabilities.map((c) => <B key={c} c={deny ? "red" : "accent"}>{c}</B>)}</span>
      {onDelete ? <button type="button" title="Delete rule" onClick={onDelete} style={{ background: "none", border: "none", color: C.redFg, cursor: "pointer", padding: 2 }}><Trash2 size={13} /></button> : <span />}
    </div>
  );
};

type SettingsProps = {
  session: AuthSession;
  settings: VaultSettings | null;
  error: string;
  // Active secrets no allow rule covers; null under deny by default, when
  // they are hidden from everyone and cannot be counted here.
  uncovered: number | null;
  confirm: (opts: Record<string, unknown>) => Promise<boolean>;
  onChanged: () => void;
  onToast?: ((m: string) => void) | undefined;
};

// The tenant's vault-wide choices: what happens on a path no rule covers,
// how many versions are kept, and how long a deleted secret is kept.
export function VaultSettingsCard({ session, settings, error, uncovered, confirm, onChanged, onToast }: SettingsProps) {
  const [deny, setDeny] = useState(false);
  const [versions, setVersions] = useState("0");
  const [days, setDays] = useState("0");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!settings) return;
    setDeny(settings.default_deny); setVersions(String(settings.max_versions)); setDays(String(settings.deleted_retention_days));
  }, [settings]);

  if (!settings) return <div style={{ fontSize: 11.5, color: C.redFg, marginBottom: 14 }}>Vault settings unavailable: {error || "no answer"}</div>;
  const next = { default_deny: deny, max_versions: Math.trunc(Number(versions) || 0), deleted_retention_days: Math.trunc(Number(days) || 0) };
  const dirty = next.default_deny !== settings.default_deny || next.max_versions !== settings.max_versions || next.deleted_retention_days !== settings.deleted_retention_days;

  const save = async () => {
    if (next.default_deny && !settings.default_deny && uncovered !== null && uncovered > 0) {
      const ok = await confirm({ title: "Deny by default", message: `${uncovered} secret${uncovered === 1 ? " has" : "s have"} no allow rule. Under deny by default nobody can list, read or change ${uncovered === 1 ? "it" : "them"} until a rule covers ${uncovered === 1 ? "it" : "them"}. Rules can still be added.`, confirmLabel: "Deny by default", danger: true });
      if (!ok) return;
    }
    setBusy(true);
    try { await putVaultSettings(session, next); onToast?.("Vault settings saved."); onChanged(); }
    catch (e) { onToast?.(`Settings refused: ${errMsg(e)}`); } finally { setBusy(false); }
  };

  const cell = { background: C.card, border: `1px solid ${C.border}`, borderRadius: "var(--radius-md)", padding: "12px 14px", minWidth: 0 } as const;
  const title = { fontSize: 11, fontWeight: 600, color: C.text, marginBottom: 8 } as const;
  const hint = { fontSize: 10.5, color: C.muted, marginTop: 6 } as const;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr)) auto", gap: 10, marginBottom: 16, alignItems: "stretch" }}>
      <div style={cell}>
        <div style={title}>Paths with no rule</div>
        <Sel value={deny ? "deny" : "open"} onChange={(e) => setDeny(e.target.value === "deny")}>
          <option value="open">Open to the secrets permission</option>
          <option value="deny">Denied</option>
        </Sel>
        <div style={hint}>{uncovered === null ? "secrets with no allow rule are hidden from everyone" : `${uncovered} secret${uncovered === 1 ? "" : "s"} with no allow rule`}</div>
      </div>
      <div style={cell}>
        <div style={title}>Versions kept per secret</div>
        <Inp type="number" min="0" max="1000" aria-label="Versions kept per secret" value={versions} onChange={(e) => setVersions(e.target.value)} />
        <div style={hint}>{next.max_versions > 0 ? "older versions go at the next write" : "0: every version is kept"}</div>
      </div>
      <div style={cell}>
        <div style={title}>Days a deleted secret is kept</div>
        <Inp type="number" min="0" max="3650" aria-label="Days a deleted secret is kept" value={days} onChange={(e) => setDays(e.target.value)} />
        <div style={hint}>{next.deleted_retention_days > 0 ? "then destroyed, and audited" : "0: kept until someone destroys it"}</div>
      </div>
      <div style={{ display: "flex", alignItems: "center" }}><Btn primary disabled={busy || !dirty} onClick={() => void save()}>{busy ? "Saving..." : "Save"}</Btn></div>
    </div>
  );
}

type Props = {
  session: AuthSession;
  rules: AccessRule[] | null;
  // Access groups for group rules; null when they could not be loaded.
  groups: GroupNames | null;
  error: string;
  restricted: number;
  total: number;
  confirm: (opts: Record<string, unknown>) => Promise<boolean>;
  onChanged: () => void;
  onToast?: ((m: string) => void) | undefined;
};

export function AccessRules({ session, rules, groups, error, restricted, total, confirm, onChanged, onToast }: Props) {
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
    const ok = await confirm({ title: "Delete access rule", message: `Delete the ${rule.effect} rule on ${rule.path} for ${rule.subject_type} ${(rule.subject_type === "group" && groups?.[rule.subject_id]) || rule.subject_id}? If it was the only allow rule there, those secrets open to everyone with the secrets permission.`, confirmLabel: "Delete", danger: true });
    if (!ok) return;
    try { await deleteAccessRule(session, rule.id); onToast?.("Access rule deleted."); onChanged(); } catch (e) { onToast?.(`Delete failed: ${errMsg(e)}`); }
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, marginBottom: 10, flexWrap: "wrap" }}>
        <span style={{ fontSize: 11, color: C.muted }}>
          {rules ? `${rules.length} rule${rules.length === 1 ? "" : "s"} · ${restricted} of ${total} secrets restricted` : ""}
        </span>
        <Btn small primary onClick={() => setOpen(true)}><Plus size={12} />Add rule</Btn>
      </div>
      {error ? <div style={{ fontSize: 11.5, color: C.redFg }}>Access rules unavailable: {error}</div>
        : rules && rules.length === 0 ? <div style={{ fontSize: 12, color: C.muted, textAlign: "center", padding: "28px 0" }}>No access rules.</div>
        : (rules || []).map((r) => <RuleRow key={r.id} rule={r} groups={groups || undefined} onDelete={() => void remove(r)} />)}

      <Modal open={open} onClose={() => setOpen(false)} title="Add access rule">
        <FG label="Path" required hint="One secret (/finance/prod/ledger-db) or everything under a folder (/finance/*)">
          <Inp mono placeholder="/finance/*" value={path} onChange={(e) => setPath(e.target.value)} />
        </FG>
        <Row2>
          <FG label="Who" required>
            <Sel value={subjectType} onChange={(e) => { setSubjectType(e.target.value); setSubjectId(""); }}>
              {ACCESS_SUBJECT_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </Sel>
          </FG>
          <FG label={subjectType === "role" ? "Role name" : subjectType === "group" ? "Access group" : subjectType === "workload" ? "Workload identity" : `${subjectType} ID`} required
            hint={subjectType === "group" ? (groups ? "Groups are managed in Key Management, Access groups" : "Access groups unavailable: enter the group ID") : undefined}>
            {subjectType === "group" && groups
              ? <Sel value={subjectId} onChange={(e) => setSubjectId(e.target.value)}>
                <option value="">{Object.keys(groups).length ? "Choose a group" : "No access groups yet"}</option>
                {Object.entries(groups).map(([id, name]) => <option key={id} value={id}>{name}</option>)}
              </Sel>
              : <Inp value={subjectId} onChange={(e) => setSubjectId(e.target.value)} placeholder={subjectType === "role" ? "finance-admin" : subjectType === "workload" ? "spiffe://..." : ""} />}
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
