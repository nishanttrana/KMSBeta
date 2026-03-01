import { useCallback, useEffect, useMemo, useState } from "react";
import {
  createAuthTenant,
  deleteAuthTenant,
  disableAuthTenant,
  getAuthTenantDeleteReadiness,
  listAuthTenants,
  type AuthTenant,
  type TenantDeleteReadiness
} from "../../lib/authAdmin";
import { B, Btn, Card, FG, Inp, Row2, Section, Sel } from "../../components/v3/legacyPrimitives";
import { errMsg } from "../../components/v3/runtimeUtils";
import { C } from "../../components/v3/theme";
import type { AdminTabProps } from "./types";

const readinessDefaults = (tenantID: string): TenantDeleteReadiness => ({
  tenant_id: tenantID,
  tenant_status: "unknown",
  can_disable: false,
  can_delete: false,
  blockers: []
});

export const TenantAdminTab = ({ session, onToast }: AdminTabProps) => {
  const [tenants, setTenants] = useState<AuthTenant[]>([]);
  const [selectedTenant, setSelectedTenant] = useState("");
  const [readiness, setReadiness] = useState<TenantDeleteReadiness>(readinessDefaults(""));
  const [loading, setLoading] = useState(false);
  const [readinessLoading, setReadinessLoading] = useState(false);
  const [createBusy, setCreateBusy] = useState(false);
  const [disableBusy, setDisableBusy] = useState(false);
  const [deleteBusy, setDeleteBusy] = useState(false);

  const [disableApprovalID, setDisableApprovalID] = useState("");
  const [deleteApprovalID, setDeleteApprovalID] = useState("");

  const [createTenantID, setCreateTenantID] = useState("");
  const [createTenantName, setCreateTenantName] = useState("");
  const [createTenantStatus, setCreateTenantStatus] = useState("active");
  const [createAdminUsername, setCreateAdminUsername] = useState("admin");
  const [createAdminEmail, setCreateAdminEmail] = useState("");
  const [createAdminPassword, setCreateAdminPassword] = useState("");
  const [createAdminRole, setCreateAdminRole] = useState("tenant-admin");
  const [createAdminMustChange, setCreateAdminMustChange] = useState(true);

  const loadTenants = useCallback(async () => {
    if (!session?.token) {
      setTenants([]);
      setSelectedTenant("");
      return;
    }
    setLoading(true);
    try {
      const items = await listAuthTenants(session);
      const next = Array.isArray(items) ? items : [];
      setTenants(next);
      if (!next.some((tenant) => String(tenant.id) === String(selectedTenant))) {
        setSelectedTenant(next[0]?.id || "");
      }
    } catch (error) {
      onToast(`Tenant list load failed: ${errMsg(error)}`);
    } finally {
      setLoading(false);
    }
  }, [onToast, selectedTenant, session]);

  const loadReadiness = useCallback(async () => {
    const tenantID = String(selectedTenant || "").trim();
    if (!session?.token || !tenantID) {
      setReadiness(readinessDefaults(tenantID));
      return;
    }
    setReadinessLoading(true);
    try {
      const out = await getAuthTenantDeleteReadiness(session, tenantID);
      setReadiness(out || readinessDefaults(tenantID));
    } catch (error) {
      onToast(`Tenant readiness load failed: ${errMsg(error)}`);
      setReadiness(readinessDefaults(tenantID));
    } finally {
      setReadinessLoading(false);
    }
  }, [onToast, selectedTenant, session]);

  useEffect(() => {
    void loadTenants();
  }, [loadTenants]);

  useEffect(() => {
    void loadReadiness();
  }, [loadReadiness]);

  const createTenant = useCallback(async () => {
    if (!session?.token) {
      return;
    }
    if (!String(createTenantID || "").trim() || !String(createTenantName || "").trim()) {
      onToast("Tenant ID and name are required.");
      return;
    }
    if (!String(createAdminEmail || "").trim() || !String(createAdminPassword || "").trim()) {
      onToast("Tenant admin email and password are required.");
      return;
    }
    setCreateBusy(true);
    try {
      await createAuthTenant(session, {
        id: String(createTenantID || "").trim(),
        name: String(createTenantName || "").trim(),
        status: createTenantStatus,
        admin_username: String(createAdminUsername || "").trim(),
        admin_email: String(createAdminEmail || "").trim(),
        admin_password: String(createAdminPassword || ""),
        admin_role: createAdminRole,
        admin_must_change_password: createAdminMustChange
      });
      onToast("Tenant created.");
      setCreateTenantID("");
      setCreateTenantName("");
      setCreateAdminEmail("");
      setCreateAdminPassword("");
      await loadTenants();
    } catch (error) {
      onToast(`Tenant create failed: ${errMsg(error)}`);
    } finally {
      setCreateBusy(false);
    }
  }, [
    createAdminEmail,
    createAdminMustChange,
    createAdminPassword,
    createAdminRole,
    createAdminUsername,
    createTenantID,
    createTenantName,
    createTenantStatus,
    loadTenants,
    onToast,
    session
  ]);

  const disableTenant = useCallback(async () => {
    const tenantID = String(selectedTenant || "").trim();
    if (!session?.token || !tenantID) {
      return;
    }
    setDisableBusy(true);
    try {
      const next = await disableAuthTenant(session, tenantID, String(disableApprovalID || "").trim());
      setReadiness(next || readinessDefaults(tenantID));
      onToast("Tenant disabled.");
      await loadTenants();
    } catch (error) {
      onToast(`Tenant disable failed: ${errMsg(error)}`);
    } finally {
      setDisableBusy(false);
    }
  }, [disableApprovalID, loadTenants, onToast, selectedTenant, session]);

  const deleteTenant = useCallback(async () => {
    const tenantID = String(selectedTenant || "").trim();
    if (!session?.token || !tenantID) {
      return;
    }
    setDeleteBusy(true);
    try {
      await deleteAuthTenant(session, tenantID, String(deleteApprovalID || "").trim());
      onToast("Tenant deleted.");
      setSelectedTenant("");
      await loadTenants();
    } catch (error) {
      onToast(`Tenant delete failed: ${errMsg(error)}`);
    } finally {
      setDeleteBusy(false);
    }
  }, [deleteApprovalID, loadTenants, onToast, selectedTenant, session]);

  const blockerRows = useMemo(() => (Array.isArray(readiness.blockers) ? readiness.blockers : []), [readiness.blockers]);

  return (
    <div>
      <Section title="Tenant Administration" actions={<Btn small onClick={() => void loadTenants()}>{loading ? "Refreshing..." : "Refresh"}</Btn>}>
        <Row2>
          <FG label="Tenant">
            <Sel value={selectedTenant} onChange={(event) => setSelectedTenant(event.target.value)}>
              {tenants.map((tenant) => (
                <option key={tenant.id} value={tenant.id}>{`${tenant.id} (${tenant.name})`}</option>
              ))}
            </Sel>
          </FG>
          <FG label="Status">
            <Inp value={String(readiness.tenant_status || "unknown")} readOnly />
          </FG>
        </Row2>
        <Row2>
          <Card>
            <div style={{ fontSize: 10, color: C.muted }}>UI Sessions</div>
            <div style={{ fontSize: 24, color: C.text, fontWeight: 700 }}>{Number(readiness.active_ui_session_count || 0)}</div>
          </Card>
          <Card>
            <div style={{ fontSize: 10, color: C.muted }}>Service Links</div>
            <div style={{ fontSize: 24, color: C.text, fontWeight: 700 }}>{Number(readiness.active_service_link_count || 0)}</div>
          </Card>
        </Row2>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 10 }}>
          <B c={readiness.can_disable ? "green" : "amber"}>{`can disable: ${readiness.can_disable ? "yes" : "no"}`}</B>
          <B c={readiness.can_delete ? "green" : "red"}>{`can delete: ${readiness.can_delete ? "yes" : "no"}`}</B>
          <B c="blue">{`blockers: ${blockerRows.length}`}</B>
        </div>
        <FG label="Disable Approval Request ID (optional)">
          <Inp value={disableApprovalID} onChange={(event) => setDisableApprovalID(event.target.value)} placeholder="approval-request-id" />
        </FG>
        <FG label="Delete Approval Request ID (optional)">
          <Inp value={deleteApprovalID} onChange={(event) => setDeleteApprovalID(event.target.value)} placeholder="approval-request-id" />
        </FG>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn small onClick={() => void loadReadiness()} disabled={readinessLoading}>{readinessLoading ? "Checking..." : "Check Readiness"}</Btn>
          <Btn small danger onClick={() => void disableTenant()} disabled={disableBusy || !selectedTenant || !readiness.can_disable}>{disableBusy ? "Disabling..." : "Disable Tenant"}</Btn>
          <Btn small danger onClick={() => void deleteTenant()} disabled={deleteBusy || !selectedTenant || !readiness.can_delete}>{deleteBusy ? "Deleting..." : "Delete Tenant"}</Btn>
        </div>

        <Card style={{ marginTop: 10 }}>
          <div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginBottom: 8 }}>Delete Blockers</div>
          <div style={{ display: "grid", gap: 8 }}>
            {blockerRows.map((blocker) => (
              <div key={String(blocker.code || Math.random())} style={{ borderBottom: `1px solid ${C.border}`, paddingBottom: 8 }}>
                <div style={{ fontSize: 11, color: C.text }}>{`${String(blocker.label || blocker.code || "blocker")} (${Number(blocker.count || 0)})`}</div>
                <div style={{ fontSize: 10, color: C.dim }}>{String(blocker.remediation || "")}</div>
              </div>
            ))}
            {!blockerRows.length ? <div style={{ fontSize: 10, color: C.muted }}>No blockers detected.</div> : null}
          </div>
        </Card>
      </Section>

      <Section title="Create Tenant">
        <Row2>
          <FG label="Tenant ID" required>
            <Inp value={createTenantID} onChange={(event) => setCreateTenantID(event.target.value)} placeholder="tenant-id" />
          </FG>
          <FG label="Tenant Name" required>
            <Inp value={createTenantName} onChange={(event) => setCreateTenantName(event.target.value)} placeholder="Tenant Name" />
          </FG>
        </Row2>
        <Row2>
          <FG label="Tenant Status">
            <Sel value={createTenantStatus} onChange={(event) => setCreateTenantStatus(event.target.value)}>
              <option value="active">active</option>
              <option value="disabled">disabled</option>
            </Sel>
          </FG>
          <FG label="Admin Role">
            <Sel value={createAdminRole} onChange={(event) => setCreateAdminRole(event.target.value)}>
              <option value="tenant-admin">tenant-admin</option>
              <option value="admin">admin</option>
            </Sel>
          </FG>
        </Row2>
        <Row2>
          <FG label="Admin Username" required>
            <Inp value={createAdminUsername} onChange={(event) => setCreateAdminUsername(event.target.value)} placeholder="admin" />
          </FG>
          <FG label="Admin Email" required>
            <Inp value={createAdminEmail} onChange={(event) => setCreateAdminEmail(event.target.value)} placeholder="admin@tenant.local" />
          </FG>
        </Row2>
        <FG label="Admin Password" required>
          <Inp type="password" value={createAdminPassword} onChange={(event) => setCreateAdminPassword(event.target.value)} />
        </FG>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <B c={createAdminMustChange ? "amber" : "blue"}>{createAdminMustChange ? "Password reset required on first login" : "No forced password change"}</B>
          <Btn small onClick={() => setCreateAdminMustChange((prev) => !prev)}>Toggle First-Login Reset</Btn>
        </div>
        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10 }}>
          <Btn primary onClick={() => void createTenant()} disabled={createBusy}>{createBusy ? "Creating..." : "Create Tenant"}</Btn>
        </div>
      </Section>
    </div>
  );
};
