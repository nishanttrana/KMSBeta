import { useMemo, useState } from "react";
import type { AuthSession } from "../../../../lib/auth";
import type { CloudAccount } from "../../../../lib/cloud";
import { B, Btn, FG, Inp, Modal, Row2, Sel, usePromptDialog } from "../../legacyPrimitives";
import { C } from "../../theme";
import { MONO, cloudLabel } from "./meta";
import { toB64, useConsole } from "./useConsole";

type Entry = { at: string; op: string; key: string; ok: boolean; cli: string; result: unknown; error: string };

// The structured console: a cloud account, one of the catalogue's
// operations its cloud supports, and that operation's typed parameters.
// Nothing else can be sent; each call is audited under its own action.
export function CloudConsole({ session, accounts, onClose }: { session: AuthSession; accounts: CloudAccount[]; onClose: () => void }) {
  const [accountId, setAccountId] = useState(accounts[0]?.id ?? "");
  const con = useConsole(session, accountId);
  const [opName, setOpName] = useState("list-keys");
  const [key, setKey] = useState("");
  const [version, setVersion] = useState("");
  const [params, setParams] = useState<Record<string, string>>({});
  const [textMode, setTextMode] = useState<Record<string, boolean>>({});
  const [history, setHistory] = useState<Entry[]>([]);
  const prompt = usePromptDialog();
  const account = accounts.find((a) => a.id === accountId);
  const supported = con.ops.filter((o) => o.supported);
  const op = supported.find((o) => o.name === opName) ?? supported[0];
  const groups = useMemo(() => Array.from(new Set(supported.map((o) => o.group))), [supported]);

  const run = async () => {
    if (!op) return;
    if (op.danger && !(await prompt.confirm({ title: op.label, message: `${op.label} on ${key || "the account"} in ${cloudLabel(account?.provider ?? "")}?`, confirmLabel: "Run", danger: true }))) return;
    const sent: Record<string, string> = {};
    for (const p of op.params ?? []) {
      const v = params[p.name] ?? "";
      if (v) sent[p.name] = p.type === "base64" && textMode[p.name] ? toB64(v) : v;
    }
    const result = await con.run(op.name, { key, version, params: sent });
    setHistory((h) => [{ at: new Date().toISOString(), op: op.name, key, ok: result !== undefined, cli: "", result, error: "" }, ...h].slice(0, 50));
  };
  // The hook sets cli/error after the call; attach them to the newest entry.
  const shown = history.map((h, i) => (i === 0 ? { ...h, cli: con.cli, error: h.ok ? "" : con.error } : h));

  const exportScript = () => {
    const lines = ["#!/bin/sh", "# Cloud console calls made through the KMS, as CLI equivalents. Values the KMS sent are not included.", ""];
    for (const h of [...shown].reverse()) if (h.cli) lines.push(h.ok ? h.cli : `# (failed) ${h.cli}`);
    const url = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/x-sh" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "vecta-cloud-console.sh";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Modal open onClose={onClose} title="Cloud console" width={980}>
      <div style={{ padding: 20, display: "grid", gap: 12 }}>
        <Row2>
          <FG label="Cloud account">
            <Sel value={accountId} onChange={(e) => { setAccountId(e.target.value); setParams({}); }}>
              {accounts.map((a) => <option key={a.id} value={a.id}>{`${cloudLabel(a.provider)} · ${a.name}`}</option>)}
            </Sel>
          </FG>
          <FG label="Operation">
            <Sel value={op?.name ?? ""} onChange={(e) => { setOpName(e.target.value); setParams({}); }}>
              {groups.flatMap((g) => supported.filter((o) => o.group === g).map((o) => <option key={o.name} value={o.name}>{`${g} · ${o.label}`}</option>))}
            </Sel>
          </FG>
        </Row2>
        {con.opsError && <div style={{ fontSize: 11, color: C.redFg }}>Operations unavailable: {con.opsError}</div>}
        {op && <>
          <Row2>
            <FG label={op.needs_key ? "Key (required)" : "Key (optional)"} hint="ARN, key ID, resource name or key URL, as the cloud names it">
              <Inp mono value={key} onChange={(e) => setKey(e.target.value)} />
            </FG>
            <FG label="Version" hint="Optional: a key version or material ID">
              <Inp mono value={version} onChange={(e) => setVersion(e.target.value)} />
            </FG>
          </Row2>
          {(op.params ?? []).map((p) => (
            <FG key={p.name} label={`${p.name}${p.required ? " (required)" : ""}`} hint={p.help}>
              {p.type === "json" ? (
                <textarea rows={8} value={params[p.name] ?? ""} onChange={(e) => setParams({ ...params, [p.name]: e.target.value })}
                  style={{ width: "100%", fontFamily: MONO, fontSize: 10.5, background: C.card, color: C.text, border: `1px solid ${C.border}`, borderRadius: 7, padding: 8, boxSizing: "border-box" }} />
              ) : (
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <Inp mono value={params[p.name] ?? ""} onChange={(e) => setParams({ ...params, [p.name]: e.target.value })} />
                  {p.type === "base64" && <label style={{ fontSize: 10.5, color: C.muted, whiteSpace: "nowrap" }}>
                    <input type="checkbox" checked={!!textMode[p.name]} onChange={() => setTextMode({ ...textMode, [p.name]: !textMode[p.name] })} /> text
                  </label>}
                </div>
              )}
            </FG>
          ))}
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <Btn primary danger={!!op.danger} disabled={!!con.busy || (op.needs_key && !key)} onClick={() => void run()}>{con.busy ? "Running…" : `Run ${op.label}`}</Btn>
            {op.mutating && <B c="amber">changes the cloud</B>}
            <span style={{ flex: 1 }} />
            <Btn small disabled={!history.length} onClick={exportScript}>Export as script</Btn>
          </div>
        </>}
        <div style={{ display: "grid", gap: 8 }}>
          {shown.map((h, i) => (
            <div key={`${h.at}-${i}`} style={{ border: `1px solid ${C.border}`, borderRadius: 8, padding: 8 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11 }}>
                <span style={{ color: C.text }}>{h.op} {h.key && <code style={{ fontFamily: MONO, color: C.muted }}>{h.key}</code>}</span>
                <B c={h.ok ? "green" : "red"}>{h.ok ? "done" : "failed"}</B>
              </div>
              {h.cli && <code style={{ display: "block", fontFamily: MONO, fontSize: 10, color: C.muted, marginTop: 4, overflowWrap: "anywhere" }}>{h.cli}</code>}
              {h.error && <div style={{ fontSize: 10.5, color: C.redFg, marginTop: 4 }}>{h.error}</div>}
              {h.ok && <pre style={{ fontFamily: MONO, fontSize: 10.5, color: C.text, background: C.bg, borderRadius: 6, padding: 8, maxHeight: 220, overflow: "auto", margin: "6px 0 0", whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
                {JSON.stringify(h.result, null, 2)}
              </pre>}
            </div>
          ))}
        </div>
      </div>
      {prompt.ui}
    </Modal>
  );
}
