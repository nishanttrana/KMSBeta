import { useEffect, useState } from "react";
import { Copy, Plus, X } from "lucide-react";
import type { AuthSession } from "../../../lib/auth";
import { configureHYOKEndpoint, type HYOKEndpoint } from "../../../lib/hyok";
import { CredentialPicker } from "../CredentialPicker";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { Btn, Chk, FG, Inp, Modal, Row2, Sel } from "../legacyPrimitives";

// OCI External KMS (services/hyok/oci_ekm.go). OCI KMS calls with an access
// token from the customer's identity domain; the KMS verifies it against the
// domain's JWKS, the resource app's audience and the allowed client IDs.
// Each external key ID maps to an AES key.

type KeyChoice = { id: string; name: string; algo?: string };
type KeyRow = { name: string; keyId: string };
type Meta = { prefix: string; vault: string; issuer: string; jwks: string; audience: string; clients: string; cred: string; rows: KeyRow[] };

const DEFAULT_ISSUER = "https://identity.oraclecloud.com/";

function parseMeta(raw: string | undefined): Meta {
  try {
    const m = JSON.parse(String(raw || "{}"));
    const keys = m && typeof m.keys === "object" && m.keys ? m.keys : {};
    return {
      prefix: String(m?.path_prefix || ""), vault: String(m?.vault_id || ""), issuer: String(m?.issuer || DEFAULT_ISSUER),
      jwks: String(m?.jwks_url || ""), audience: String(m?.audience || ""), cred: String(m?.jwks_credential_id || ""),
      clients: Array.isArray(m?.client_ids) ? m.client_ids.map(String).join(", ") : "",
      rows: Object.keys(keys).sort().map((name) => ({ name, keyId: String(keys[name]) })),
    };
  } catch {
    return { prefix: "", vault: "", issuer: DEFAULT_ISSUER, jwks: "", audience: "", clients: "", cred: "", rows: [] };
  }
}

// The external key manager URL given to OCI: the edge routes /svc/hyok/ to the service.
export function ociBasePath(prefix: string): string {
  return `/svc/hyok/oci/${prefix.replace(/^\/+|\/+$/g, "")}`;
}

export function HYOKOCIConfig({ open, session, endpoint, keyChoices, onClose, onSaved, onNavigate }: {
  open: boolean;
  session: AuthSession;
  endpoint?: HYOKEndpoint;
  keyChoices: KeyChoice[];
  onClose: () => void;
  onSaved: (message: string) => void;
  onNavigate?: (target: string) => void;
}) {
  const [enabled, setEnabled] = useState(true);
  const [m, setM] = useState<Meta>(parseMeta(undefined));
  const [policyID, setPolicyID] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    const parsed = parseMeta(endpoint?.metadata_json);
    setM({ ...parsed, rows: parsed.rows.length ? parsed.rows : [{ name: "", keyId: "" }] });
    setEnabled(endpoint ? Boolean(endpoint.enabled) : true);
    setPolicyID(String(endpoint?.policy_id || ""));
    setError("");
  }, [open, endpoint]);

  const set = (patch: Partial<Meta>) => setM((cur) => ({ ...cur, ...patch }));
  const setRow = (i: number, patch: Partial<KeyRow>) => set({ rows: m.rows.map((r, j) => (j === i ? { ...r, ...patch } : r)) });
  const aesKeys = keyChoices.filter((k) => /^AES-(128|192|256)(-GCM)?$/i.test(String(k.algo || "")));

  const save = async () => {
    const keys: Record<string, string> = {};
    for (const r of m.rows) {
      if (!r.name.trim() && !r.keyId) continue;
      keys[r.name.trim()] = r.keyId;
    }
    setSaving(true);
    setError("");
    try {
      await configureHYOKEndpoint(session, "oci_ekm", {
        enabled, auth_mode: "oci_jwt", policy_id: policyID.trim(), governance_required: false,
        metadata_json: JSON.stringify({
          path_prefix: m.prefix.trim(), vault_id: m.vault.trim(), issuer: m.issuer.trim(), jwks_url: m.jwks.trim(), audience: m.audience.trim(),
          client_ids: m.clients.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean), ...(m.cred ? { jwks_credential_id: m.cred } : {}), keys,
        }),
      });
      onSaved("OCI External KMS saved.");
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setSaving(false);
    }
  };

  const base = m.prefix.trim() ? ociBasePath(m.prefix.trim()) : "";
  return (
    <Modal open={open} onClose={onClose} title="OCI External KMS" wide>
      <Row2>
        <FG label="Path prefix" required hint="Unique across tenants; OCI calls under it.">
          <Inp value={m.prefix} onChange={(e) => set({ prefix: e.target.value })} placeholder="contoso" mono />
        </FG>
        <FG label="Vault ID" required hint="The vault ID you give OCI for the external vault.">
          <Inp value={m.vault} onChange={(e) => set({ vault: e.target.value })} placeholder="vecta-vault-1" mono />
        </FG>
      </Row2>
      <Row2>
        <FG label="JWKS URL" required hint="From <identity domain>/.well-known/idcs-configuration.">
          <Inp value={m.jwks} onChange={(e) => set({ jwks: e.target.value })} placeholder="https://idcs-….identity.oraclecloud.com/admin/v1/SigningCert/jwk" mono />
        </FG>
        <FG label="Issuer" required>
          <Inp value={m.issuer} onChange={(e) => set({ issuer: e.target.value })} mono />
        </FG>
      </Row2>
      <Row2>
        <FG label="Audience" required hint="The resource app's primary audience.">
          <Inp value={m.audience} onChange={(e) => set({ audience: e.target.value })} placeholder="https://10.0.0.5/" mono />
        </FG>
        <FG label="Allowed client IDs" required hint="The confidential app OCI KMS uses; separate several with commas.">
          <Inp value={m.clients} onChange={(e) => set({ clients: e.target.value })} placeholder="client ID" mono aria-label="Allowed client IDs" />
        </FG>
      </Row2>
      <FG label="JWKS credential" hint="Only if the domain's signing certificate is not public: the resource app's client ID and secret.">
        <CredentialPicker session={session} type="oci_identity_domain" value={m.cred} onChange={(v) => set({ cred: v })} onNavigate={onNavigate} />
      </FG>
      <FG label="Keys" hint="External key ID in OCI → Vecta AES key.">
        <div style={{ display: "grid", gap: 6 }}>
          {m.rows.map((r, i) => (
            <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 1.4fr 28px", gap: 6, alignItems: "center" }}>
              <Inp value={r.name} onChange={(e) => setRow(i, { name: e.target.value })} placeholder="external-key-id" mono aria-label="External key ID" />
              <Sel value={r.keyId} onChange={(e) => setRow(i, { keyId: e.target.value })} aria-label="Vecta key">
                <option value="">Choose an AES key</option>
                {aesKeys.map((k) => <option key={k.id} value={k.id}>{k.name}</option>)}
              </Sel>
              <button type="button" title="Remove" onClick={() => set({ rows: m.rows.filter((_, j) => j !== i) })} style={{ background: "transparent", border: "none", color: C.dim, cursor: "pointer" }}><X size={14} /></button>
            </div>
          ))}
          <div><Btn small onClick={() => set({ rows: [...m.rows, { name: "", keyId: "" }] })}><Plus size={12} /> Add key</Btn></div>
        </div>
      </FG>
      <Row2>
        <FG label="Policy ID" hint="Optional policy evaluated on every encrypt and decrypt.">
          <Inp value={policyID} onChange={(e) => setPolicyID(e.target.value)} placeholder="hyok.oci_ekm.*" mono />
        </FG>
        <FG label="Endpoint">
          <Chk label="Enabled" checked={enabled} onChange={() => setEnabled((v) => !v)} />
        </FG>
      </Row2>
      {base && (
        <div data-testid="oci-base-path" style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, padding: "6px 8px", background: C.bg, borderRadius: "var(--radius-md)", marginBottom: 10 }}>
          <span style={{ color: C.muted }}>External key manager path</span>
          <code style={{ color: C.accentFg, fontFamily: "var(--font-mono)", flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>{base}</code>
          <button type="button" title="Copy" onClick={() => { try { void navigator.clipboard.writeText(base); } catch { /* clipboard unavailable */ } }} style={{ background: "transparent", border: "none", color: C.dim, cursor: "pointer" }}><Copy size={12} /></button>
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
