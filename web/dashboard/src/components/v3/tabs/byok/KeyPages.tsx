import { useCallback, useEffect, useState, type ReactNode } from "react";
import type { AuthSession } from "../../../../lib/auth";
import type { BYOKKey } from "../../../../lib/byok";
import { B, Btn, Inp, usePromptDialog } from "../../legacyPrimitives";
import { C } from "../../theme";
import { MONO, cloudLabel } from "./meta";
import { toB64, useConsole } from "./useConsole";

// The cloud key's own settings, as its cloud has them: state, policy,
// grants, aliases, tags and a "try it" panel. Every action is a console
// operation (audited as audit.cloud.console_<op>); a tab appears only when
// the cloud has its operations.

type Tab = "state" | "policy" | "grants" | "aliases" | "tags" | "try";

const TABS: { id: Tab; label: string; op: string }[] = [
  { id: "state", label: "State", op: "describe-key" },
  { id: "policy", label: "Policy", op: "get-key-policy" },
  { id: "grants", label: "Grants", op: "list-grants" },
  { id: "aliases", label: "Aliases", op: "list-aliases" },
  { id: "tags", label: "Tags", op: "list-tags" },
  { id: "try", label: "Try it", op: "encrypt" },
];

const Pre = ({ v }: { v: unknown }) => (
  <pre style={{ fontFamily: MONO, fontSize: 10.5, color: C.text, background: C.bg, borderRadius: 6, padding: 8, maxHeight: 260, overflow: "auto", margin: 0, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
    {typeof v === "string" ? v : JSON.stringify(v, null, 2)}
  </pre>
);

const Row = ({ children }: { children: ReactNode }) => <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>{children}</div>;

export function KeyPages({ session, k }: { session: AuthSession; k: BYOKKey }) {
  const con = useConsole(session, k.account_id);
  const prompt = usePromptDialog();
  const [tab, setTab] = useState<Tab>("state");
  const [data, setData] = useState<unknown>(null);
  const [form, setForm] = useState<Record<string, string>>({});
  const [output, setOutput] = useState<unknown>(null);
  const key = k.cloud_key_id;
  const set = (name: string, v: string) => setForm((f) => ({ ...f, [name]: v }));
  const tabs = TABS.filter((t) => con.supported(t.op) || (t.id === "try" && (con.supported("sign") || con.supported("generate-mac"))));

  const load = useCallback(async () => {
    setOutput(null);
    const op = { state: "describe-key", policy: "get-key-policy", grants: "list-grants", aliases: "list-aliases", tags: "list-tags", try: "" }[tab];
    if (!op) return;
    const out = await con.run(op, { key });
    setData(out ?? null);
    if (tab === "policy" && out) {
      const p = (out as { policy?: string }).policy;
      set("policy", p ? JSON.stringify(JSON.parse(p), null, 2) : JSON.stringify(out, null, 2));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- con.run is stable per account
  }, [tab, key]);
  useEffect(() => { if (con.ops.length) void load(); }, [load, con.ops.length]);

  const act = async (op: string, params?: Record<string, string>, confirm?: string) => {
    if (confirm && !(await prompt.confirm({ title: `${cloudLabel(k.provider)}: ${op}`, message: confirm, confirmLabel: "Run", danger: true }))) return;
    const out = await con.run(op, { key, ...(params ? { params } : {}) });
    if (out !== undefined) {
      if (tab !== "try") return void (await load());
      setOutput(out);
      const r = out as Record<string, string>;
      if (r.ciphertext_b64) set("ciphertext", r.ciphertext_b64);
      if (r.signature_b64) set("signature", r.signature_b64);
      if (r.mac_b64) set("mac", r.mac_b64);
    }
  };
  const btn = (op: string, label: string, params?: Record<string, string>, confirm?: string) =>
    con.supported(op) ? <Btn key={op} small danger={!!confirm} disabled={!!con.busy} onClick={() => void act(op, params, confirm)}>{con.busy === op ? `${label}…` : label}</Btn> : null;

  if (con.opsError) return <div style={{ fontSize: 11, color: C.redFg }}>Console unavailable: {con.opsError}</div>;
  if (!tabs.length) return <div style={{ fontSize: 11, color: C.muted }}>{cloudLabel(k.provider)} has no key settings the KMS can manage.</div>;

  const tags = (data && typeof data === "object" && !Array.isArray(data) ? data : {}) as Record<string, string>;
  const list = (Array.isArray(data) ? data : []) as Record<string, unknown>[];
  const spec = k.key_spec;

  return (
    <div style={{ display: "grid", gap: 10 }}>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {tabs.map((t) => <Btn key={t.id} small primary={tab === t.id} onClick={() => { setTab(t.id); setForm({}); }}>{t.label}</Btn>)}
      </div>

      {tab === "state" && <>
        <Row>
          {btn("enable-key", "Enable")}
          {btn("disable-key", "Disable", undefined, "Applications using this key in the cloud stop working until it is enabled again.")}
          {btn("cancel-key-deletion", "Cancel deletion")}
          {con.supported("schedule-key-deletion") && <>
            <Inp w="80px" value={form.pending_days ?? ""} onChange={(e) => set("pending_days", e.target.value.replace(/\D/g, ""))} placeholder="days" />
            {btn("schedule-key-deletion", "Schedule deletion", form.pending_days ? { pending_days: form.pending_days } : {}, "The cloud deletes this key after the waiting period. Data it encrypted can't be decrypted afterwards, unless the deletion is cancelled in time.")}
          </>}
        </Row>
        {con.supported("get-rotation-status") && <Row>
          <span style={{ fontSize: 11, color: C.muted }}>Cloud's automatic rotation (keys the cloud generated):</span>
          {btn("get-rotation-status", "Status")}
          {btn("enable-rotation", "Turn on")}
          {btn("disable-rotation", "Turn off")}
        </Row>}
        {data !== null && <Pre v={data} />}
      </>}

      {tab === "policy" && <>
        <textarea value={form.policy ?? ""} onChange={(e) => set("policy", e.target.value)} rows={12}
          style={{ width: "100%", fontFamily: MONO, fontSize: 10.5, background: C.card, color: C.text, border: `1px solid ${C.border}`, borderRadius: 7, padding: 8, boxSizing: "border-box" }} />
        <Row>{btn("put-key-policy", "Save policy", { policy: form.policy ?? "" }, "The whole policy is replaced. A policy that removes your own access can lock the key; the cloud checks what it can.")}</Row>
      </>}

      {tab === "grants" && <>
        {list.map((g) => (
          <div key={String(g.GrantId)} style={{ display: "grid", gridTemplateColumns: "1fr 1.5fr 1.5fr auto", gap: 8, fontSize: 11, alignItems: "center", borderBottom: `1px solid ${C.border}`, padding: "4px 0" }}>
            <span style={{ fontFamily: MONO }}>{String(g.GrantId)}</span>
            <span style={{ fontFamily: MONO, overflowWrap: "anywhere" }}>{String(g.GranteePrincipal ?? "")}</span>
            <span>{Array.isArray(g.Operations) ? g.Operations.join(", ") : ""}</span>
            {btn("revoke-grant", "Revoke", { grant_id: String(g.GrantId) }, "The grantee loses these operations on the key.")}
          </div>
        ))}
        {!list.length && <div style={{ fontSize: 11, color: C.muted }}>No grants.</div>}
        <Row>
          <Inp w="260px" mono value={form.grantee ?? ""} onChange={(e) => set("grantee", e.target.value)} placeholder="grantee principal ARN" />
          <Inp w="200px" value={form.operations ?? ""} onChange={(e) => set("operations", e.target.value)} placeholder="Encrypt,Decrypt" />
          {btn("create-grant", "Create grant", { grantee: form.grantee ?? "", operations: form.operations ?? "" })}
        </Row>
      </>}

      {tab === "aliases" && <>
        {list.map((a) => (
          <Row key={String(a.AliasName)}>
            <span style={{ fontFamily: MONO, fontSize: 11 }}>{String(a.AliasName)}</span>
            {btn("delete-alias", "Delete", { alias: String(a.AliasName) }, "Applications that use this alias can no longer find the key by it.")}
          </Row>
        ))}
        {!list.length && <div style={{ fontSize: 11, color: C.muted }}>No aliases.</div>}
        <Row>
          <Inp w="240px" mono value={form.alias ?? ""} onChange={(e) => set("alias", e.target.value)} placeholder="alias/orders-db" />
          {btn("create-alias", "Create alias", { alias: form.alias ?? "" })}
        </Row>
      </>}

      {tab === "tags" && <>
        {Object.entries(tags).map(([tk, tv]) => (
          <Row key={tk}>
            <B c="blue">{tk}</B><span style={{ fontSize: 11, color: C.text }}>{String(tv)}</span>
            {btn("untag-key", "Remove", { tag_key: tk })}
          </Row>
        ))}
        {!Object.keys(tags).length && <div style={{ fontSize: 11, color: C.muted }}>No tags.</div>}
        <Row>
          <Inp w="160px" value={form.tag_key ?? ""} onChange={(e) => set("tag_key", e.target.value)} placeholder="key" />
          <Inp w="200px" value={form.tag_value ?? ""} onChange={(e) => set("tag_value", e.target.value)} placeholder="value" />
          {btn("tag-key", "Set tag", { tag_key: form.tag_key ?? "", tag_value: form.tag_value ?? "" })}
        </Row>
      </>}

      {tab === "try" && <>
        <Inp value={form.text ?? ""} onChange={(e) => set("text", e.target.value)} placeholder="a message (text)" />
        <Row>
          {(spec === "AES-256" || k.usage === "encrypt") && <>
            {btn("encrypt", "Encrypt", { plaintext_b64: toB64(form.text ?? "") })}
            <Inp w="320px" mono value={form.ciphertext ?? ""} onChange={(e) => set("ciphertext", e.target.value)} placeholder="ciphertext (base64)" />
            {btn("decrypt", "Decrypt", { ciphertext_b64: form.ciphertext ?? "" })}
          </>}
          {spec === "HMAC-256" && <>
            {btn("generate-mac", "Generate MAC", { message_b64: toB64(form.text ?? "") })}
            <Inp w="320px" mono value={form.mac ?? ""} onChange={(e) => set("mac", e.target.value)} placeholder="MAC (base64)" />
            {btn("verify-mac", "Verify MAC", { message_b64: toB64(form.text ?? ""), mac_b64: form.mac ?? "" })}
          </>}
          {spec !== "AES-256" && spec !== "HMAC-256" && k.usage !== "encrypt" && <>
            {btn("sign", "Sign", { message_b64: toB64(form.text ?? "") })}
            <Inp w="320px" mono value={form.signature ?? ""} onChange={(e) => set("signature", e.target.value)} placeholder="signature (base64)" />
            {btn("verify", "Verify", { message_b64: toB64(form.text ?? ""), signature_b64: form.signature ?? "" })}
          </>}
        </Row>
        {output !== null && <Pre v={output} />}
      </>}

      {con.error && <div style={{ fontSize: 11, color: C.redFg }}>{con.error}</div>}
      {con.cli && <div style={{ fontSize: 10, color: C.muted }}>CLI equivalent: <code style={{ fontFamily: MONO, color: C.text }}>{con.cli}</code></div>}
      {prompt.ui}
    </div>
  );
}
