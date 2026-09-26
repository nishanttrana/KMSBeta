import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../lib/auth";
import { getHSMOverview, updateHSMSettings, type HSMOverview } from "../../lib/keycore";
import { Btn, Card, Chk } from "../../components/v3/legacyPrimitives";
import { errMsg } from "../../components/v3/runtimeUtils";
import { C } from "../../components/v3/theme";

// How this tenant's keys use its HSM (docs/SECURITY/HSM_INTEGRATION.md).
// The status is what the hsm-connector reports after loading the tenant's
// PKCS#11 library and logging in; nothing here is assumed.
export function HSMIntegrationCard({ session, onToast }: { session: AuthSession | null; onToast?: (msg: string) => void }) {
  const [overview, setOverview] = useState<HSMOverview | null>(null);
  const [tenantKey, setTenantKey] = useState(false);
  const [hsmKeys, setHsmKeys] = useState(false);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    if (!session) return;
    setLoading(true);
    try {
      const out = await getHSMOverview(session);
      setOverview(out);
      setTenantKey(Boolean(out.settings?.tenant_key_enabled));
      setHsmKeys(Boolean(out.settings?.hsm_keys_enabled));
    } catch (e) {
      onToast?.(`HSM status failed: ${errMsg(e)}`);
    } finally {
      setLoading(false);
    }
  }, [session, onToast]);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async () => {
    if (!session) return;
    setSaving(true);
    try {
      await updateHSMSettings(session, { tenant_key_enabled: tenantKey, hsm_keys_enabled: hsmKeys });
      onToast?.("HSM integration saved.");
      await load();
    } catch (e) {
      onToast?.(`HSM integration not saved: ${errMsg(e)}`);
    } finally {
      setSaving(false);
    }
  };

  const hsm = overview?.hsm;
  const settings = overview?.settings;
  const dirty = settings ? tenantKey !== settings.tenant_key_enabled || hsmKeys !== settings.hsm_keys_enabled : false;
  let state = "Checking...";
  let tone: string = C.muted;
  if (overview && !overview.connector) {
    state = "HSM connector not running on this platform (install with HSM mode hardware)";
    tone = C.red;
  } else if (hsm && !hsm.configured) {
    state = "No enabled HSM profile for this tenant: save and enable one below";
    tone = C.amber;
  } else if (hsm && !hsm.connected) {
    state = `Configured, not connected: ${hsm.error || "unknown error"}`;
    tone = C.red;
  } else if (hsm?.connected) {
    state = `Connected: ${[hsm.manufacturer, hsm.model].filter(Boolean).join(" ")} token "${hsm.token_label || "-"}"${hsm.firmware ? `, firmware ${hsm.firmware}` : ""}`;
    tone = C.green;
  }

  return (
    <Card style={{ padding: 12, marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", marginBottom: 8 }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>KMS integration</div>
        <div style={{ marginLeft: "auto" }}>
          <Btn small onClick={() => void load()} disabled={loading}>{loading ? "Checking..." : "Test connection"}</Btn>
        </div>
      </div>
      <div style={{ fontSize: 10, color: tone, marginBottom: 10 }}>{state}</div>
      <Chk
        label="Tenant key in HSM: this tenant gets its own AES-256 key inside the HSM, and every new key's material is encrypted by it (keys created before keep the KMS master key)"
        checked={tenantKey}
        onChange={() => setTenantKey(!tenantKey)}
      />
      {settings?.tenant_key_label && (
        <div style={{ fontSize: 9, color: C.muted, margin: "2px 0 6px 22px", fontFamily: "'JetBrains Mono',monospace" }}>
          {settings.tenant_key_label}{hsm?.tenant_key_ready ? " (present in HSM)" : ""}
        </div>
      )}
      <Chk
        label="HSM keys: offer 'Create in HSM' when creating a key. Such a key is generated inside the HSM, never leaves it, and its encrypt, decrypt, sign and verify run in the HSM"
        checked={hsmKeys}
        onChange={() => setHsmKeys(!hsmKeys)}
      />
      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 8 }}>
        <Btn small primary onClick={() => void save()} disabled={saving || !dirty}>{saving ? "Saving..." : "Save"}</Btn>
      </div>
    </Card>
  );
}
