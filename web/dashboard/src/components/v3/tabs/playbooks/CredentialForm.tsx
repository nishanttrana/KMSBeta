import { useState } from "react";
import type { AuthSession } from "../../../../lib/auth";
import { saveCredential, testCredential, type Credential, type CredentialType } from "../../../../lib/credentials";
import { Btn, FG, Inp, Modal, Row2, Sel, Txt } from "../../legacyPrimitives";
import { errMsg } from "../../runtimeUtils";
import { C } from "../../theme";
import { CATEGORIES, FIELD_HINTS, MULTILINE } from "./credentialMeta";

const KEEP = "********";

type Props = {
  session: AuthSession;
  types: CredentialType[];
  // The credential being edited, or the type a new one starts as.
  editing?: Credential | undefined;
  startType?: string | undefined;
  onClose: () => void;
  onSaved: (message: string) => void;
};

type FieldEvent = { target: { value: string } };

// Add or edit a credential. Saving seals it and then runs its real test, so
// the list shows at once whether it works.
export function CredentialForm({ session, types, editing, startType, onClose, onSaved }: Props) {
  const [name, setName] = useState(editing?.name ?? "");
  const [type, setType] = useState(editing?.type ?? startType ?? types[0]?.type ?? "");
  const [fields, setFields] = useState<Record<string, string>>(() =>
    Object.fromEntries((editing?.fields_set ?? []).map((f) => [f, editing?.attributes?.[f] ?? KEEP])));
  const [expires, setExpires] = useState(editing?.expires_at ? editing.expires_at.slice(0, 10) : "");
  const [rotate, setRotate] = useState(String(editing?.rotate_after_days || ""));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const spec = types.find((t) => t.type === type);

  const save = async () => {
    setBusy(true);
    setError("");
    try {
      const saved = await saveCredential(session, editing?.id, {
        name, type, fields: Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== "")),
        expires_at: expires ? new Date(`${expires}T00:00:00Z`).toISOString() : null,
        rotate_after_days: Number(rotate) || 0,
      });
      try {
        await testCredential(session, saved.id);
        onSaved(`${saved.name} saved and tested.`);
      } catch (e) {
        // Saved, but it does not work (or is tested where it is used).
        onSaved(`${saved.name} saved. Test: ${errMsg(e)}`);
      }
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal open onClose={onClose} title={editing ? `Edit ${editing.name}` : "Add credential"} width={560}>
      <FG label="Name" required><Inp value={name} placeholder="what it is for" onChange={(e: FieldEvent) => setName(e.target.value)} /></FG>
      <FG label="Type" required>
        <Sel value={type} disabled={Boolean(editing)} onChange={(e: FieldEvent) => { setType(e.target.value); setFields({}); }}>
          {CATEGORIES.map((cat) => (
            <optgroup key={cat.id} label={cat.label}>
              {types.filter((t) => t.category === cat.id).map((t) => <option key={t.type} value={t.type}>{t.label}</option>)}
            </optgroup>
          ))}
        </Sel>
      </FG>
      {spec?.use ? <div style={{ fontSize: 10.5, color: C.muted, margin: "-6px 0 10px" }}>Used by: {spec.use}</div> : null}
      {[...(spec?.fields ?? []), ...(spec?.optional ?? [])].map((f) => {
        const required = (spec?.fields ?? []).includes(f);
        const secret = (spec?.secrets ?? []).includes(f);
        const set = (v: string) => setFields((p) => ({ ...p, [f]: v }));
        const value = fields[f] ?? "";
        const choices = spec?.choices?.[f];
        return (
          <FG key={f} label={f} required={required} hint={editing && secret ? "leave ******** to keep the stored value" : undefined}>
            {choices
              ? <Sel value={value} onChange={(e: FieldEvent) => set(e.target.value)}><option value="">-</option>{choices.map((c) => <option key={c} value={c}>{c}</option>)}</Sel>
              : MULTILINE.has(f)
                ? <Txt rows={f === "headers" || f === "options_json" ? 2 : 4} value={value} placeholder={FIELD_HINTS[f] ?? ""} onChange={(e: FieldEvent) => set(e.target.value)} />
                : <Inp type={secret ? "password" : "text"} autoComplete="off" value={value} placeholder={FIELD_HINTS[f] ?? ""} onChange={(e: FieldEvent) => set(e.target.value)} />}
          </FG>
        );
      })}
      <Row2>
        <FG label="Expires on" hint="the secret's own expiry, if it has one"><Inp type="date" value={expires} onChange={(e: FieldEvent) => setExpires(e.target.value)} /></FG>
        <FG label="Rotate after (days)" hint="reminder after the secret's last change"><Inp type="number" min={0} value={rotate} placeholder="0 = no reminder" onChange={(e: FieldEvent) => setRotate(e.target.value)} /></FG>
      </Row2>
      {error ? <div style={{ fontSize: 11, color: C.redFg, marginBottom: 10 }}>Save refused: {error}</div> : null}
      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
        <Btn onClick={onClose}>Cancel</Btn>
        <Btn primary disabled={busy || !name.trim() || !type} onClick={save}>{busy ? "Saving…" : "Save and test"}</Btn>
      </div>
    </Modal>
  );
}
