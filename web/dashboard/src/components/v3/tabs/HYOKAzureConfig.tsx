import { useEffect, useState } from "react";
import { Copy, Plus, X } from "lucide-react";
import type { AuthSession } from "../../../lib/auth";
import { configureHYOKEndpoint, type HYOKEndpoint } from "../../../lib/hyok";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { Btn, Chk, FG, Inp, Modal, Row2, Sel, Txt } from "../legacyPrimitives";

// Azure Managed HSM external key management: the endpoint's settings
// (services/hyok/azure_ekm.go). Managed HSM reaches its own listener on port
// 8443, proves itself with a client certificate from the CA set here, and
// names keys by the key names mapped here.

type KeyChoice = { id: string; name: string; algo?: string };
type KeyRow = { name: string; keyId: string };

export const AZURE_EKM_PORT = 8443;

function parseMeta(raw: string | undefined): { prefix: string; cn: string; ca: string; rows: KeyRow[] } {
  try {
    const m = JSON.parse(String(raw || "{}"));
    const keys = m && typeof m.keys === "object" && m.keys ? m.keys : {};
    return {
      prefix: String(m?.path_prefix || ""),
      cn: String(m?.client_subject_cn || ""),
      ca: String(m?.client_ca_pem || ""),
      rows: Object.keys(keys).sort().map((name) => ({ name, keyId: String(keys[name]) })),
    };
  } catch {
    return { prefix: "", cn: "", ca: "", rows: [] };
  }
}

export function azureProxyURL(prefix: string): string {
  return `https://${window.location.hostname}:${AZURE_EKM_PORT}/${prefix.replace(/^\/+|\/+$/g, "")}`;
}

export function HYOKAzureConfig({ open, session, endpoint, keyChoices, onClose, onSaved }: {
  open: boolean;
  session: AuthSession;
  endpoint?: HYOKEndpoint;
  keyChoices: KeyChoice[];
  onClose: () => void;
  onSaved: (message: string) => void;
}) {
  const [enabled, setEnabled] = useState(true);
  const [prefix, setPrefix] = useState("");
  const [cn, setCN] = useState("");
  const [ca, setCA] = useState("");
  const [policyID, setPolicyID] = useState("");
  const [rows, setRows] = useState<KeyRow[]>([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    const m = parseMeta(endpoint?.metadata_json);
    setEnabled(endpoint ? Boolean(endpoint.enabled) : true);
    setPrefix(m.prefix);
    setCN(m.cn);
    setCA(m.ca);
    setRows(m.rows.length ? m.rows : [{ name: "", keyId: "" }]);
    setPolicyID(String(endpoint?.policy_id || ""));
    setError("");
  }, [open, endpoint]);

  const setRow = (i: number, patch: Partial<KeyRow>) => setRows((cur) => cur.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  const save = async () => {
    const keys: Record<string, string> = {};
    for (const r of rows) {
      if (!r.name.trim() && !r.keyId) continue;
      keys[r.name.trim()] = r.keyId;
    }
    setSaving(true);
    setError("");
    try {
      await configureHYOKEndpoint(session, "azure", {
        enabled,
        auth_mode: "mtls",
        policy_id: policyID.trim(),
        governance_required: false,
        metadata_json: JSON.stringify({ path_prefix: prefix.trim(), client_ca_pem: ca.trim(), client_subject_cn: cn.trim(), keys }),
      });
      onSaved("Azure EKM saved.");
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setSaving(false);
    }
  };

  const url = prefix.trim() ? azureProxyURL(prefix.trim()) : "";
  return (
    <Modal open={open} onClose={onClose} title="Azure EKM" wide>
      <Row2>
        <FG label="Path prefix" required hint="Managed HSM puts it before every call; unique across tenants.">
          <Inp value={prefix} onChange={(e) => setPrefix(e.target.value)} placeholder="contoso/mhsm-pool-1" mono />
        </FG>
        <FG label="Client certificate subject CN" required>
          <Inp value={cn} onChange={(e) => setCN(e.target.value)} placeholder="Managed HSM client certificate CN" mono />
        </FG>
      </Row2>
      <FG label="Client CA (PEM)" required hint="The CA that issues Managed HSM's client certificate.">
        <Txt rows={4} value={ca} onChange={(e) => setCA(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
      </FG>
      <FG label="Keys" hint="Key name in Managed HSM → Vecta key (AES-256 or RSA).">
        <div style={{ display: "grid", gap: 6 }}>
          {rows.map((r, i) => (
            <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 1.4fr 28px", gap: 6, alignItems: "center" }}>
              <Inp value={r.name} onChange={(e) => setRow(i, { name: e.target.value })} placeholder="key-name" mono aria-label="Key name" />
              <Sel value={r.keyId} onChange={(e) => setRow(i, { keyId: e.target.value })} aria-label="Vecta key">
                <option value="">Choose a key</option>
                {keyChoices.map((k) => <option key={k.id} value={k.id}>{k.name}{k.algo ? ` (${k.algo})` : ""}</option>)}
              </Sel>
              <button type="button" title="Remove" onClick={() => setRows((cur) => cur.filter((_, j) => j !== i))} style={{ background: "transparent", border: "none", color: C.dim, cursor: "pointer" }}><X size={14} /></button>
            </div>
          ))}
          <div><Btn small onClick={() => setRows((cur) => [...cur, { name: "", keyId: "" }])}><Plus size={12} /> Add key</Btn></div>
        </div>
      </FG>
      <Row2>
        <FG label="Policy ID" hint="Optional policy evaluated on every wrap and unwrap.">
          <Inp value={policyID} onChange={(e) => setPolicyID(e.target.value)} placeholder="hyok.azure.*" mono />
        </FG>
        <FG label="Endpoint">
          <Chk label="Enabled" checked={enabled} onChange={() => setEnabled((v) => !v)} />
        </FG>
      </Row2>
      {url && (
        <div data-testid="azure-proxy-url" style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, padding: "6px 8px", background: C.bg, borderRadius: "var(--radius-md)", marginBottom: 10 }}>
          <span style={{ color: C.muted }}>EKM connection URL</span>
          <code style={{ color: C.accentFg, fontFamily: "var(--font-mono)", flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>{url}</code>
          <button type="button" title="Copy" onClick={() => { try { void navigator.clipboard.writeText(url); } catch { /* clipboard unavailable */ } }} style={{ background: "transparent", border: "none", color: C.dim, cursor: "pointer" }}><Copy size={12} /></button>
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
