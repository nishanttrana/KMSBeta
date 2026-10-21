import { useEffect, useMemo, useState } from "react";
import { Copy } from "lucide-react";
import type { AuthSession } from "../../../../lib/auth";
import { listAuthClients, type AuthClientRegistration } from "../../../../lib/authAdmin";
import { errMsg } from "../../runtimeUtils";
import { C } from "../../theme";
import { B, Card, FG, Row2, Section, Sel, Stat } from "../../legacyPrimitives";

// Kubernetes KMS v2 (services/k8s-kms-plugin, docs/KUBERNETES_KMS.md): the
// plugin on each control-plane node wraps kube-apiserver's data keys with a
// Vecta AES-256 key, as an API client. This view builds its configuration
// from the tenant's real keys and API clients.

type KeyItem = { id: string; name: string; algo?: string; state?: string; __raw?: { current_version?: number } };

const SOCKET = "/var/run/vecta-kms/kms.sock";

function Snippet({ title, text, testid }: { title: string; text: string; testid: string }) {
  return (
    <Card style={{ padding: 0, overflow: "hidden" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 12px", borderBottom: `1px solid ${C.border}` }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{title}</span>
        <button type="button" title="Copy" onClick={() => { try { void navigator.clipboard.writeText(text); } catch { /* clipboard unavailable */ } }} style={{ background: "transparent", border: "none", color: C.dim, cursor: "pointer" }}><Copy size={13} /></button>
      </div>
      <pre data-testid={testid} style={{ margin: 0, padding: 12, fontSize: 11.5, fontFamily: "var(--font-mono)", color: C.text, overflowX: "auto" }}>{text}</pre>
    </Card>
  );
}

export function Kubernetes({ session, keyCatalog, onNavigate }: { session: AuthSession; keyCatalog: KeyItem[]; onNavigate?: (target: string) => void }) {
  const [clients, setClients] = useState<AuthClientRegistration[] | null>(null);
  const [error, setError] = useState("");
  const [keyID, setKeyID] = useState("");
  const [clientID, setClientID] = useState("");

  useEffect(() => {
    let live = true;
    listAuthClients(session).then((c) => { if (live) setClients(c); }).catch((e) => { if (live) setError(errMsg(e)); });
    return () => { live = false; };
  }, [session]);

  const keys = useMemo(() => (Array.isArray(keyCatalog) ? keyCatalog : []).filter((k) => /^AES-256(-GCM)?$/i.test(String(k.algo || "")) && String(k.state || "").toLowerCase() === "active"), [keyCatalog]);
  const apiClients = useMemo(() => (clients || []).filter((c) => String(c.auth_mode || "api_key") === "api_key" && ["approved", "active"].includes(String(c.status || "").toLowerCase())), [clients]);
  const key = keys.find((k) => k.id === keyID);
  const version = Number(key?.__raw?.current_version || 0);

  const pluginConfig = JSON.stringify({
    server: window.location.origin, tenant_id: session.tenantId, key_id: keyID || "<key id>", client_id: clientID || "<api client id>",
    api_key_file: "/etc/vecta-kms/api-key", ca_file: "/etc/vecta-kms/ca.pem", socket: SOCKET,
  }, null, 2);
  const encryptionConfig = `apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - kms:
          apiVersion: v2
          name: vecta-kms
          endpoint: unix://${SOCKET}
          timeout: 3s
      - identity: {}`;

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 10, marginBottom: 16 }}>
        <Stat l="AES-256 keys" v={keys.length} />
        <Stat l="API clients" v={clients ? apiClients.length : "unavailable"} c={error ? "amber" : "accent"} />
        <Stat l="Key ID Kubernetes sees" v={key && version ? `${keyID}:v${version}` : "choose a key"} />
      </div>
      {error && <div role="alert" style={{ fontSize: 11, color: C.redFg, marginBottom: 10 }}>API clients unavailable: {error}</div>}
      <Section title="Kubernetes KMS v2 plugin">
        <Row2>
          <FG label="Key" hint="An active AES-256 key; rotating it makes the cluster re-wrap.">
            <Sel value={keyID} onChange={(e) => setKeyID(e.target.value)} aria-label="Key">
              <option value="">Choose a key</option>
              {keys.map((k) => <option key={k.id} value={k.id}>{k.name}</option>)}
            </Sel>
          </FG>
          <FG label="API client" hint="Its key goes in /etc/vecta-kms/api-key on each node (mode 0600).">
            <Sel value={clientID} onChange={(e) => setClientID(e.target.value)} aria-label="API client" disabled={!apiClients.length}>
              <option value="">{apiClients.length ? "Choose an API client" : "No approved API client"}</option>
              {apiClients.map((c) => <option key={c.id} value={c.id}>{c.client_name}</option>)}
            </Sel>
          </FG>
        </Row2>
        {keyID && clientID && (
          <div style={{ fontSize: 11, color: C.muted, marginBottom: 10, display: "flex", gap: 6, alignItems: "center" }}>
            <B c="amber">Access</B>
            <span>The client needs encrypt and decrypt on this key:</span>
            <span role="link" tabIndex={0} onClick={() => onNavigate?.("keys")} style={{ color: C.accentFg, cursor: "pointer" }}>Key Management → key → Access</span>
          </div>
        )}
        <div style={{ display: "grid", gap: 10 }}>
          <Snippet title="/etc/vecta-kms/k8s-kms-plugin.json" text={pluginConfig} testid="k8s-plugin-config" />
          <Snippet title="kube-apiserver --encryption-provider-config" text={encryptionConfig} testid="k8s-encryption-config" />
        </div>
      </Section>
    </div>
  );
}
