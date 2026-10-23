import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../../lib/auth";
import {
  deleteMetadataProfile,
  listMetadataProfiles,
  metadataProfileViolations,
  saveMetadataProfile,
  toInput,
  type MetadataLabelRule,
  type MetadataProfile,
  type MetadataProfileInput,
  type MetadataViolation
} from "../../../lib/metadataProfiles";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Chk, FG, Inp, Row2 } from "../legacyPrimitives";

// Metadata profiles (docs/KEYS.md "Metadata profiles"): what a tenant's keys
// must carry. Keys that don't meet an active profile are refused when
// created, imported or updated; existing keys are listed, never changed.

const empty = (): MetadataProfileInput => ({
  name: "", purposes: [], status: "active", require_owner: false, require_description: false, labels: [], required_tags: []
});

const list = (text: string) => text.split(",").map((s) => s.trim()).filter(Boolean);

export function MetadataProfilesPanel({ session }: { session: AuthSession }) {
  const [items, setItems] = useState<MetadataProfile[] | null>(null);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState<{ id?: string; p: MetadataProfileInput } | null>(null);
  const [report, setReport] = useState<{ id: string; items: MetadataViolation[]; checked: number } | null>(null);
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      setItems(await listMetadataProfiles(session));
      setError("");
    } catch (e) {
      setError(errMsg(e));
    }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const save = async () => {
    if (!editing) return;
    try {
      await saveMetadataProfile(session, editing.p, editing.id);
      setEditing(null);
      setNotice("Profile saved. New and updated keys are checked against it.");
      void load();
    } catch (e) {
      setNotice(errMsg(e));
    }
  };
  const remove = async (p: MetadataProfile) => {
    try {
      await deleteMetadataProfile(session, p.id);
      setNotice(`Profile ${p.name} deleted.`);
      void load();
    } catch (e) {
      setNotice(errMsg(e));
    }
  };
  const check = async (p: MetadataProfile) => {
    try {
      setReport({ id: p.id, ...(await metadataProfileViolations(session, p.id)) });
    } catch (e) {
      setNotice(errMsg(e));
    }
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
        <span style={{ fontSize: 11, color: C.dim }}>Keys that don't meet an active profile are refused.</span>
        {!editing && <Btn small primary onClick={() => setEditing({ p: empty() })}>New profile</Btn>}
      </div>
      {notice && <div style={{ fontSize: 11, color: C.dim, marginBottom: 6 }}>{notice}</div>}
      {editing && <ProfileForm value={editing.p} onChange={(p) => setEditing({ ...editing, p })} onSave={() => void save()} onCancel={() => setEditing(null)} />}
      {error ? <div style={{ fontSize: 11, color: C.redFg }}>{`Profiles unavailable: ${error}`}</div>
        : items === null ? <div style={{ fontSize: 11, color: C.muted }}>Loading…</div>
          : items.length === 0 ? <div style={{ fontSize: 11, color: C.muted }}>No metadata profiles.</div>
            : items.map((p) => (
              <div key={p.id} data-testid="metadata-profile-row" style={{ borderTop: `1px solid ${C.border}`, padding: "8px 0" }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{p.name}</span>
                  <span style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <B c={p.status === "active" ? "green" : "neutral"}>{p.status}</B>
                    <Btn small onClick={() => void check(p)}>Check keys</Btn>
                    <Btn small onClick={() => setEditing({ id: p.id, p: toInput(p) })}>Edit</Btn>
                    <Btn small danger onClick={() => void remove(p)}>Delete</Btn>
                  </span>
                </div>
                <div style={{ fontSize: 10.5, color: C.dim, marginTop: 3 }}>{summary(p)}</div>
                {report?.id === p.id && (
                  <div data-testid="metadata-violations" style={{ fontSize: 10.5, marginTop: 6 }}>
                    <div style={{ color: C.dim }}>{`${report.items.length} of ${report.checked} keys don't comply.`}</div>
                    {report.items.map((v) => <div key={v.key_id} style={{ color: C.text }}>{`${v.name}: ${v.problems.join("; ")}`}</div>)}
                  </div>
                )}
              </div>
            ))}
    </div>
  );
}

function summary(p: MetadataProfile) {
  const parts = [p.purposes.length ? `${p.purposes.join(", ")} keys` : "every key"];
  if (p.require_owner) parts.push("owner");
  if (p.require_description) parts.push("description");
  for (const l of p.labels) parts.push(`${l.key}${l.required ? " (required)" : ""}${l.allowed?.length ? ` ∈ ${l.allowed.join("|")}` : ""}${l.default ? ` = ${l.default} by default` : ""}`);
  if (p.required_tags.length) parts.push(`tags ${p.required_tags.join(", ")}`);
  return parts.join(" · ");
}

function ProfileForm({ value, onChange, onSave, onCancel }: { value: MetadataProfileInput; onChange: (p: MetadataProfileInput) => void; onSave: () => void; onCancel: () => void }) {
  const set = (patch: Partial<MetadataProfileInput>) => onChange({ ...value, ...patch });
  const setLabel = (i: number, patch: Partial<MetadataLabelRule>) => set({ labels: value.labels.map((l, j) => (j === i ? { ...l, ...patch } : l)) });
  return (
    <div style={{ border: `1px solid ${C.border}`, borderRadius: 6, padding: 10, marginBottom: 10 }}>
      <Row2>
        <FG label="Name" required><Inp aria-label="Profile name" value={value.name} onChange={(e: any) => set({ name: e.target.value })} /></FG>
        <FG label="Key purposes" hint="Comma-separated, e.g. encrypt, sign. Empty applies to every key.">
          <Inp aria-label="Profile purposes" value={value.purposes.join(", ")} onChange={(e: any) => set({ purposes: list(e.target.value) })} />
        </FG>
      </Row2>
      <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
        <Chk label="Owner required" checked={value.require_owner} onChange={() => set({ require_owner: !value.require_owner })} />
        <Chk label="Description required" checked={value.require_description} onChange={() => set({ require_description: !value.require_description })} />
        <Chk label="Active" checked={value.status === "active"} onChange={() => set({ status: value.status === "active" ? "disabled" : "active" })} />
      </div>
      <FG label="Required tags" hint="Comma-separated."><Inp aria-label="Profile required tags" value={value.required_tags.join(", ")} onChange={(e: any) => set({ required_tags: list(e.target.value) })} /></FG>
      <div style={{ fontSize: 11, color: C.dim, margin: "6px 0" }}>Labels</div>
      {value.labels.map((l, i) => (
        <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 1.4fr 1fr 1fr auto auto", gap: 6, alignItems: "center", marginBottom: 4 }}>
          <Inp aria-label={`Label ${i + 1} key`} placeholder="key" value={l.key} onChange={(e: any) => setLabel(i, { key: e.target.value })} />
          <Inp aria-label={`Label ${i + 1} allowed values`} placeholder="allowed: prod, dev" value={(l.allowed || []).join(", ")} onChange={(e: any) => setLabel(i, { allowed: list(e.target.value) })} />
          <Inp aria-label={`Label ${i + 1} pattern`} placeholder="pattern" value={l.pattern || ""} onChange={(e: any) => setLabel(i, { pattern: e.target.value })} />
          <Inp aria-label={`Label ${i + 1} default`} placeholder="default" value={l.default || ""} onChange={(e: any) => setLabel(i, { default: e.target.value })} />
          <Chk label="Required" checked={l.required} onChange={() => setLabel(i, { required: !l.required })} />
          <Btn small onClick={() => set({ labels: value.labels.filter((_, j) => j !== i) })}>Remove</Btn>
        </div>
      ))}
      <div style={{ display: "flex", gap: 6, marginTop: 6 }}>
        <Btn small onClick={() => set({ labels: [...value.labels, { key: "", required: true }] })}>Add label</Btn>
        <span style={{ flex: 1 }} />
        <Btn small onClick={onCancel}>Cancel</Btn>
        <Btn small primary disabled={!value.name.trim()} onClick={onSave}>Save profile</Btn>
      </div>
    </div>
  );
}
