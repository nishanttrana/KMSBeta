import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../../lib/auth";
import { getAuditAnchor, saveAuditAnchor, type AuditAnchorSettings } from "../../../lib/audit";
import { CredentialPicker } from "../CredentialPicker";
import { B, Btn, Card } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";

// Audit Log → Checkpoints: where signed checkpoints are timestamped (an
// RFC 3161 authority, a "tsa" credential). Turning it on takes a real token
// first (services/audit/anchor.go; docs/SECURITY/AUDIT_INTEGRITY.md).
export function AnchorSettings({ session, onNavigate, onToast }: {
  session: AuthSession;
  onNavigate?: (tab: string) => void;
  onToast?: (m: string) => void;
}) {
  const [saved, setSaved] = useState<AuditAnchorSettings | null>(null);
  const [error, setError] = useState("");
  const [conn, setConn] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const a = await getAuditAnchor(session);
      setSaved(a);
      setConn(a.connection_id);
      setError("");
    } catch (e) {
      setSaved(null);
      setError(errMsg(e));
    }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const save = async (enabled: boolean) => {
    setBusy(true);
    try {
      const a = await saveAuditAnchor(session, { enabled, connection_id: conn });
      setSaved(a);
      onToast?.(enabled ? "Timestamping is on: the authority issued a test token." : "Timestamping is off.");
    } catch (e) {
      onToast?.(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card style={{ marginBottom: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: C.text }} title="Each new checkpoint's signature is timestamped by an outside authority, so a history rewritten later can only get a later time.">
          Timestamping (RFC 3161)
        </span>
        {saved && <B c={saved.enabled ? "green" : "neutral"}>{saved.enabled ? "on" : "off"}</B>}
      </div>
      {error ? <div style={{ fontSize: 11, color: C.redFg, marginTop: 6 }}>{`Anchoring unavailable: ${error}`}</div> : saved && (
        <div style={{ display: "flex", gap: 8, alignItems: "flex-end", flexWrap: "wrap", marginTop: 8 }}>
          <div style={{ minWidth: 260, flex: "1 1 260px" }}>
            <CredentialPicker session={session} type="tsa" value={conn} onChange={setConn} onNavigate={onNavigate} disabled={busy} />
          </div>
          {saved.enabled
            ? <>
              {conn !== saved.connection_id && <Btn small primary disabled={busy || !conn} onClick={() => void save(true)}>Use this authority</Btn>}
              <Btn small disabled={busy} onClick={() => void save(false)}>Turn off</Btn>
            </>
            : <Btn small primary disabled={busy || !conn} onClick={() => void save(true)}>{busy ? "Testing..." : "Turn on"}</Btn>}
        </div>
      )}
      {!error && saved && !saved.enabled && (
        <div style={{ fontSize: 11, color: C.muted, marginTop: 6 }}>
          Add the authority's root certificate (trust_pem) to the credential; system roots rarely include it.
        </div>
      )}
    </Card>
  );
}
