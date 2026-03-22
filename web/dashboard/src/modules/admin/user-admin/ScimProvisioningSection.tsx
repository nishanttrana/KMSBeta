import { useEffect, useState } from "react";
import { B, Btn, Card, FG, Row2, Section, Sel } from "../../../components/v3/legacyPrimitives";
import { C } from "../../../components/v3/theme";
import {
  getAuthSCIMSettings,
  getAuthSCIMSummary,
  listAuthSCIMGroups,
  listAuthSCIMUsers,
  rotateAuthSCIMToken,
  updateAuthSCIMSettings,
  type SCIMGroup,
  type SCIMSettings,
  type SCIMSummary,
  type SCIMUser
} from "../../../lib/authAdmin";
import { errMsg } from "../../../components/v3/runtimeUtils";
import type { AuthSession } from "../../../lib/auth";

type Props = {
  session: AuthSession | null;
  onToast: (message: string) => void;
  tenantID: string;
};

const DEFAULT_SETTINGS: SCIMSettings = {
  tenant_id: "",
  enabled: false,
  default_role: "readonly",
  default_status: "active",
  default_must_change_password: false,
  deprovision_mode: "disable",
  group_role_mappings_enabled: true
};

export function ScimProvisioningSection({ session, onToast, tenantID }: Props) {
  const [settings, setSettings] = useState<SCIMSettings>(DEFAULT_SETTINGS);
  const [summary, setSummary] = useState<SCIMSummary | null>(null);
  const [users, setUsers] = useState<SCIMUser[]>([]);
  const [groups, setGroups] = useState<SCIMGroup[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [bearerToken, setBearerToken] = useState("");

  useEffect(() => {
    if (!session?.token || !String(tenantID || "").trim()) {
      setSettings({ ...DEFAULT_SETTINGS, tenant_id: String(tenantID || "").trim() });
      setSummary(null);
      setUsers([]);
      setGroups([]);
      setBearerToken("");
      return;
    }
    let cancelled = false;
    setLoading(true);
    void Promise.all([
      getAuthSCIMSettings(session, tenantID).catch(() => ({ ...DEFAULT_SETTINGS, tenant_id: tenantID })),
      getAuthSCIMSummary(session, tenantID).catch(() => null),
      listAuthSCIMUsers(session, tenantID).catch(() => []),
      listAuthSCIMGroups(session, tenantID).catch(() => [])
    ])
      .then(([settingsOut, summaryOut, userRows, groupRows]) => {
        if (cancelled) {
          return;
        }
        setSettings(settingsOut || { ...DEFAULT_SETTINGS, tenant_id: tenantID });
        setSummary(summaryOut);
        setUsers(Array.isArray(userRows) ? userRows : []);
        setGroups(Array.isArray(groupRows) ? groupRows : []);
      })
      .catch((error) => {
        if (!cancelled) {
          onToast(`SCIM provisioning load failed: ${errMsg(error)}`);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [onToast, session, tenantID]);

  const save = async () => {
    if (!session?.token || !String(tenantID || "").trim()) {
      return;
    }
    setSaving(true);
    try {
      const updated = await updateAuthSCIMSettings(session, { ...settings, tenant_id: tenantID });
      setSettings(updated || { ...settings, tenant_id: tenantID });
      const [summaryOut, userRows, groupRows] = await Promise.all([
        getAuthSCIMSummary(session, tenantID).catch(() => null),
        listAuthSCIMUsers(session, tenantID).catch(() => users),
        listAuthSCIMGroups(session, tenantID).catch(() => groups)
      ]);
      setSummary(summaryOut);
      setUsers(Array.isArray(userRows) ? userRows : []);
      setGroups(Array.isArray(groupRows) ? groupRows : []);
      onToast("SCIM provisioning settings saved.");
    } catch (error) {
      onToast(`SCIM settings update failed: ${errMsg(error)}`);
    } finally {
      setSaving(false);
    }
  };

  const rotateToken = async () => {
    if (!session?.token || !String(tenantID || "").trim()) {
      return;
    }
    setRotating(true);
    try {
      const out = await rotateAuthSCIMToken(session, tenantID);
      if (out?.settings) {
        setSettings(out.settings);
      }
      setBearerToken(String(out?.bearer_token || ""));
      const summaryOut = await getAuthSCIMSummary(session, tenantID).catch(() => null);
      setSummary(summaryOut);
      onToast("SCIM bearer token rotated. Copy it now; it is only shown once.");
    } catch (error) {
      onToast(`SCIM token rotation failed: ${errMsg(error)}`);
    } finally {
      setRotating(false);
    }
  };

  return (
    <Section
      title="SCIM Provisioning"
      actions={
        <div style={{ display: "flex", gap: 8 }}>
          <Btn small onClick={() => void rotateToken()} disabled={rotating || !String(tenantID || "").trim()}>
            {rotating ? "Rotating..." : "Rotate Bearer Token"}
          </Btn>
          <Btn small primary onClick={() => void save()} disabled={saving || !String(tenantID || "").trim()}>
            {saving ? "Saving..." : "Save SCIM"}
          </Btn>
        </div>
      }
    >
      <Row2>
        <FG label="Provisioning">
          <Sel
            value={settings.enabled ? "enabled" : "disabled"}
            onChange={(event) => setSettings((prev) => ({ ...prev, tenant_id: tenantID, enabled: event.target.value === "enabled" }))}
          >
            <option value="disabled">Disabled</option>
            <option value="enabled">Enabled</option>
          </Sel>
        </FG>
        <FG label="Deprovision Mode">
          <Sel
            value={String(settings.deprovision_mode || "disable")}
            onChange={(event) => setSettings((prev) => ({ ...prev, tenant_id: tenantID, deprovision_mode: event.target.value }))}
          >
            <option value="disable">Disable User</option>
            <option value="delete">Delete User</option>
          </Sel>
        </FG>
      </Row2>
      <Row2>
        <FG label="Default Role">
          <Sel
            value={String(settings.default_role || "readonly")}
            onChange={(event) => setSettings((prev) => ({ ...prev, tenant_id: tenantID, default_role: event.target.value }))}
          >
            {["readonly", "viewer", "operator", "tenant-admin", "security-admin", "app-service"].map((role) => (
              <option key={role} value={role}>{role}</option>
            ))}
          </Sel>
        </FG>
        <FG label="Default Status">
          <Sel
            value={String(settings.default_status || "active")}
            onChange={(event) => setSettings((prev) => ({ ...prev, tenant_id: tenantID, default_status: event.target.value }))}
          >
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
          </Sel>
        </FG>
      </Row2>
      <Row2>
        <FG label="Password Rotation on First Login">
          <Sel
            value={settings.default_must_change_password ? "yes" : "no"}
            onChange={(event) =>
              setSettings((prev) => ({
                ...prev,
                tenant_id: tenantID,
                default_must_change_password: event.target.value === "yes"
              }))
            }
          >
            <option value="no">No forced change</option>
            <option value="yes">Must change on first local login</option>
          </Sel>
        </FG>
        <FG label="Group Role Mapping">
          <Sel
            value={settings.group_role_mappings_enabled ? "enabled" : "disabled"}
            onChange={(event) =>
              setSettings((prev) => ({
                ...prev,
                tenant_id: tenantID,
                group_role_mappings_enabled: event.target.value === "enabled"
              }))
            }
          >
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
          </Sel>
        </FG>
      </Row2>

      <Card>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, minmax(0, 1fr))", gap: 10 }}>
          <MetricCard label="Managed Users" value={String(Number(summary?.managed_users || 0))} tone="blue" />
          <MetricCard label="Managed Groups" value={String(Number(summary?.managed_groups || 0))} tone="green" />
          <MetricCard label="Memberships" value={String(Number(summary?.managed_memberships || 0))} tone="blue" />
          <MetricCard label="Disabled Users" value={String(Number(summary?.disabled_users || 0))} tone={Number(summary?.disabled_users || 0) > 0 ? "amber" : "green"} />
          <MetricCard label="Role-Mapped Groups" value={String(Number(summary?.role_mapped_groups || 0))} tone="green" />
        </div>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 12, fontSize: 11, color: C.dim }}>
          <span>{summary?.token_configured ? `Provisioning token ready (${summary?.token_prefix || "configured"})` : "No SCIM bearer token rotated yet"}</span>
          <span>{summary?.last_provisioned_at ? `Last provisioned ${new Date(summary.last_provisioned_at).toLocaleString()}` : "No SCIM user provisioned yet"}</span>
          <span>{summary?.last_deprovisioned_at ? `Last deprovisioned ${new Date(summary.last_deprovisioned_at).toLocaleString()}` : "No SCIM deprovision event yet"}</span>
        </div>
      </Card>

      {bearerToken ? (
        <Card>
          <div style={{ fontSize: 12, color: C.text, fontWeight: 700, marginBottom: 8 }}>One-Time SCIM Bearer Token</div>
          <div style={{ fontSize: 11, color: C.dim, marginBottom: 8 }}>
            Copy this into Okta, Microsoft Entra ID, or another SCIM client now. The hash is stored server-side; the raw token is only shown after rotation.
          </div>
          <div
            style={{
              fontFamily: "monospace",
              fontSize: 11,
              color: C.text,
              padding: 10,
              borderRadius: 12,
              border: `1px solid ${C.border}`,
              background: "rgba(4,10,20,0.7)",
              wordBreak: "break-all"
            }}
          >
            {bearerToken}
          </div>
        </Card>
      ) : null}

      <Row2>
        <Card>
          <div style={{ fontSize: 12, color: C.text, fontWeight: 700, marginBottom: 8 }}>Provisioned Users</div>
          <div style={{ display: "grid", gap: 8 }}>
            {users.slice(0, 8).map((user) => (
              <div key={user.id} style={{ display: "flex", justifyContent: "space-between", gap: 8, fontSize: 11 }}>
                <div>
                  <div style={{ color: C.text, fontWeight: 600 }}>{user.display_name || user.username}</div>
                  <div style={{ color: C.dim }}>{user.email}</div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <B c={String(user.status || "").toLowerCase() === "active" ? "green" : "amber"}>{user.status || "unknown"}</B>
                  <div style={{ color: C.dim }}>{user.external_id || "no external id"}</div>
                </div>
              </div>
            ))}
            {!users.length ? <div style={{ fontSize: 10, color: C.muted }}>{loading ? "Loading..." : "No SCIM-managed users yet."}</div> : null}
          </div>
        </Card>
        <Card>
          <div style={{ fontSize: 12, color: C.text, fontWeight: 700, marginBottom: 8 }}>Provisioned Groups</div>
          <div style={{ display: "grid", gap: 8 }}>
            {groups.slice(0, 8).map((group) => (
              <div key={group.id} style={{ display: "flex", justifyContent: "space-between", gap: 8, fontSize: 11 }}>
                <div>
                  <div style={{ color: C.text, fontWeight: 600 }}>{group.display_name}</div>
                  <div style={{ color: C.dim }}>{group.external_id || "no external id"}</div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <B c={group.active ? "green" : "amber"}>{group.active ? "active" : "disabled"}</B>
                  <div style={{ color: C.dim }}>{`${Number(group.member_count || 0)} members`}</div>
                </div>
              </div>
            ))}
            {!groups.length ? <div style={{ fontSize: 10, color: C.muted }}>{loading ? "Loading..." : "No SCIM-managed groups yet."}</div> : null}
          </div>
        </Card>
      </Row2>
    </Section>
  );
}

function MetricCard({ label, value, tone }: { label: string; value: string; tone: "green" | "amber" | "blue" }) {
  return (
    <div style={{ border: `1px solid ${C.border}`, borderRadius: 14, padding: 12, background: "rgba(15, 24, 40, 0.75)" }}>
      <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>{label}</div>
      <B c={tone}>{value}</B>
    </div>
  );
}
