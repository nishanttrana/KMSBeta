import { useEffect, useState } from "react";
import { Copy, Plus, X } from "lucide-react";
import type { AuthSession } from "../../../lib/auth";
import { configureHYOKEndpoint, type HYOKEndpoint } from "../../../lib/hyok";
import { CredentialPicker } from "../CredentialPicker";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { Btn, Chk, FG, Inp, Modal, Row2, Sel } from "../legacyPrimitives";

// AWS KMS external key store (services/hyok/aws_xks.go). AWS KMS signs each
// call with an aws_xks credential from Playbooks → Credentials; a second one
// lets the customer rotate. Each external key ID maps to an AES-256 key.

type KeyChoice = { id: string; name: string; algo?: string };
type KeyRow = { name: string; keyId: string };

function parseMeta(raw: string | undefined): { prefix: string; creds: string[]; rows: KeyRow[] } {
  try {
    const m = JSON.parse(String(raw || "{}"));
    const keys = m && typeof m.keys === "object" && m.keys ? m.keys : {};
    return {
      prefix: String(m?.path_prefix || ""),
      creds: Array.isArray(m?.credential_ids) ? m.credential_ids.map(String) : [],
      rows: Object.keys(keys).sort().map((name) => ({ name, keyId: String(keys[name]) })),
    };
  } catch {
    return { prefix: "", creds: [], rows: [] };
  }
}

// The XksProxyUriPath given to AWS: the edge routes /svc/hyok/ to the service.
export function xksURIPath(prefix: string): string {
  return `/svc/hyok/xks/${prefix.replace(/^\/+|\/+$/g, "")}`;
}

export function HYOKXKSConfig({ open, session, endpoint, keyChoices, onClose, onSaved, onNavigate }: {
  open: boolean;
  session: AuthSession;
  endpoint?: HYOKEndpoint;
  keyChoices: KeyChoice[];
  onClose: () => void;
  onSaved: (message: string) => void;
  onNavigate?: (target: string) => void;
}) {
  const [enabled, setEnabled] = useState(true);
  const [prefix, setPrefix] = useState("");
  const [cred1, setCred1] = useState("");
  const [cred2, setCred2] = useState("");
  const [policyID, setPolicyID] = useState("");
  const [rows, setRows] = useState<KeyRow[]>([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    const m = parseMeta(endpoint?.metadata_json);
    setEnabled(endpoint ? Boolean(endpoint.enabled) : true);
    setPrefix(m.prefix);
    setCred1(m.creds[0] || "");
    setCred2(m.creds[1] || "");
    setRows(m.rows.length ? m.rows : [{ name: "", keyId: "" }]);
    setPolicyID(String(endpoint?.policy_id || ""));
    setError("");
  }, [open, endpoint]);

  const setRow = (i: number, patch: Partial<KeyRow>) => setRows((cur) => cur.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const aesKeys = keyChoices.filter((k) => /^AES-256(-GCM)?$/i.test(String(k.algo || "")));

  const save = async () => {
    const keys: Record<string, string> = {};
    for (const r of rows) {
      if (!r.name.trim() && !r.keyId) continue;
      keys[r.name.trim()] = r.keyId;
    }
    setSaving(true);
    setError("");
    try {
      await configureHYOKEndpoint(session, "aws_xks", {
        enabled,
        auth_mode: "sigv4",
        policy_id: policyID.trim(),
        governance_required: false,
        metadata_json: JSON.stringify({ path_prefix: prefix.trim(), credential_ids: [cred1, cred2].filter(Boolean), keys }),
      });
      onSaved("AWS XKS saved.");
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setSaving(false);
    }
  };

  const uriPath = prefix.trim() ? xksURIPath(prefix.trim()) : "";
  return (
    <Modal open={open} onClose={onClose} title="AWS XKS" wide>
      <FG label="Path prefix" required hint="Unique across tenants; AWS calls under it.">
        <Inp value={prefix} onChange={(e) => setPrefix(e.target.value)} placeholder="contoso/xks" mono />
      </FG>
      <Row2>
        <FG label="XKS credential" required hint="Access key ID and secret AWS signs with.">
          <CredentialPicker session={session} type="aws_xks" value={cred1} onChange={setCred1} onNavigate={onNavigate} />
        </FG>
        <FG label="Second credential (rotation)">
          <CredentialPicker session={session} type="aws_xks" value={cred2} onChange={setCred2} onNavigate={onNavigate} />
        </FG>
      </Row2>
      <FG label="Keys" hint="External key ID in AWS → Vecta AES-256 key.">
        <div style={{ display: "grid", gap: 6 }}>
          {rows.map((r, i) => (
            <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 1.4fr 28px", gap: 6, alignItems: "center" }}>
              <Inp value={r.name} onChange={(e) => setRow(i, { name: e.target.value })} placeholder="external-key-id" mono aria-label="External key ID" />
              <Sel value={r.keyId} onChange={(e) => setRow(i, { keyId: e.target.value })} aria-label="Vecta key">
                <option value="">Choose an AES-256 key</option>
                {aesKeys.map((k) => <option key={k.id} value={k.id}>{k.name}</option>)}
              </Sel>
              <button type="button" title="Remove" onClick={() => setRows((cur) => cur.filter((_, j) => j !== i))} style={{ background: "transparent", border: "none", color: C.dim, cursor: "pointer" }}><X size={14} /></button>
            </div>
          ))}
          <div><Btn small onClick={() => setRows((cur) => [...cur, { name: "", keyId: "" }])}><Plus size={12} /> Add key</Btn></div>
        </div>
      </FG>
      <Row2>
        <FG label="Policy ID" hint="Optional policy evaluated on every encrypt and decrypt.">
          <Inp value={policyID} onChange={(e) => setPolicyID(e.target.value)} placeholder="hyok.aws_xks.*" mono />
        </FG>
        <FG label="Endpoint">
          <Chk label="Enabled" checked={enabled} onChange={() => setEnabled((v) => !v)} />
        </FG>
      </Row2>
      {uriPath && (
        <div data-testid="xks-uri-path" style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, padding: "6px 8px", background: C.bg, borderRadius: "var(--radius-md)", marginBottom: 10 }}>
          <span style={{ color: C.muted }}>XksProxyUriPath</span>
          <code style={{ color: C.accentFg, fontFamily: "var(--font-mono)", flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>{uriPath}</code>
          <button type="button" title="Copy" onClick={() => { try { void navigator.clipboard.writeText(uriPath); } catch { /* clipboard unavailable */ } }} style={{ background: "transparent", border: "none", color: C.dim, cursor: "pointer" }}><Copy size={12} /></button>
        </div>
      )}
      {error && <div role="alert" style={{ fontSize: 11, color: C.redFg, marginBottom: 8 }}>{error}</div>}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <Btn onClick={onClose}>Cancel</Btn>
        <Btn primary onClick={() => void save()} disabled={saving}>{saving ? "Saving…" : "Save"}</Btn>
      </div>
    </Modal>
  );
}
