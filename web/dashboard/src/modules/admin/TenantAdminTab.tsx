import { useCallback, useEffect, useMemo, useState } from "react";
import {
  createAuthTenant,
  deleteAuthTenant,
  disableAuthTenant,
  getAuthPasswordPolicy,
  getAuthSecurityPolicy,
  getAuthTenantDeleteReadiness,
  listAuthTenants,
  listAuthUsers,
  updateAuthPasswordPolicy,
  updateAuthSecurityPolicy,
  updateAuthTenant,
  type AuthTenant,
  type AuthUser,
  type PasswordPolicy,
  type SecurityPolicy,
  type TenantDeleteReadiness
} from "../../lib/authAdmin";
import {
  createGovernanceBackup,
  deleteGovernanceBackup,
  downloadGovernanceBackupArtifact,
  downloadGovernanceBackupKey,
  governanceBackupKeyRetained,
  listGovernanceBackups,
  type GovernanceBackupJob
} from "../../lib/governance";
import { B, Btn, Card, Chk, FG, Inp, Modal, Row2, Sel, Stat } from "../../components/v3/legacyPrimitives";
import { errMsg } from "../../components/v3/runtimeUtils";
import { C } from "../../components/v3/theme";
import type { AdminTabProps } from "./types";
import { ExposurePanel } from "./ExposurePanel";

// A tenant's HSM (its root of trust) is set by that tenant's administrators
// in the HSM module.
const INTERNAL_TABS = ["Overview", "Security", "Backup", "Lifecycle"] as const;

// The platform tenant can't be disabled or deleted (auth refuses it).
const PLATFORM_TENANT = "root";
type InternalTab = (typeof INTERNAL_TABS)[number];

const readinessDefaults = (tenantID: string): TenantDeleteReadiness => ({
  tenant_id: tenantID,
  tenant_status: "unknown",
  can_disable: false,
  can_delete: false,
  blockers: []
});

const defaultPasswordPolicy = (): PasswordPolicy => ({
  tenant_id: "",
  min_length: 8,
  max_length: 128,
  require_upper: true,
  require_lower: true,
  require_digit: true,
  require_special: true,
  require_no_whitespace: true,
  deny_username: true,
  deny_email_local_part: true,
  min_unique_chars: 4
});

const defaultSecurityPolicy = (): SecurityPolicy => ({
  tenant_id: "",
  max_failed_attempts: 5,
  lockout_minutes: 15,
  idle_timeout_minutes: 30
});

function relativeTime(iso: string): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 0) return "just now";
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

function formatBytes(bytes: number): string {
  if (bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

function saveBackupFile(file: { file_name?: string; content_type?: string; content_base64?: string }, fallbackName: string, fallbackType: string): void {
  const blob = new Blob([atob(String(file?.content_base64 || ""))], { type: file?.content_type || fallbackType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = file?.file_name || fallbackName; a.click();
  URL.revokeObjectURL(url);
}

export const TenantAdminTab = ({ session, onToast }: AdminTabProps) => {
  const [activeTab, setActiveTab] = useState<InternalTab>("Overview");
  const [tenants, setTenants] = useState<AuthTenant[]>([]);
  const [selectedTenantId, setSelectedTenantId] = useState("");
  const [loading, setLoading] = useState(false);
  // Why the tenant list could not be read: only a platform (root)
  // administrator may read it.
  const [tenantsError, setTenantsError] = useState("");

  // Overview state
  const [tenantUsers, setTenantUsers] = useState<AuthUser[]>([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [usersError, setUsersError] = useState("");

  // Create tenant modal
  const [createOpen, setCreateOpen] = useState(false);
  const [createTenantID, setCreateTenantID] = useState("");
  const [createTenantName, setCreateTenantName] = useState("");
  const [createAdminUsername, setCreateAdminUsername] = useState("admin");
  const [createAdminEmail, setCreateAdminEmail] = useState("");
  const [createAdminPassword, setCreateAdminPassword] = useState("");
  const [createAdminRole, setCreateAdminRole] = useState("tenant-admin");
  const [createAdminMustChange, setCreateAdminMustChange] = useState(true);
  const [createBusy, setCreateBusy] = useState(false);

  // Security state
  const [passwordPolicy, setPasswordPolicy] = useState<PasswordPolicy>(defaultPasswordPolicy());
  const [securityPolicy, setSecurityPolicy] = useState<SecurityPolicy>(defaultSecurityPolicy());
  const [policyLoading, setPolicyLoading] = useState(false);
  const [policyError, setPolicyError] = useState("");
  const [policySaving, setPolicySaving] = useState(false);

  // Backup state
  const [backups, setBackups] = useState<GovernanceBackupJob[]>([]);
  const [backupsLoading, setBackupsLoading] = useState(false);
  const [backupCreating, setBackupCreating] = useState(false);

  // Lifecycle state
  const [readiness, setReadiness] = useState<TenantDeleteReadiness>(readinessDefaults(""));
  const [readinessLoading, setReadinessLoading] = useState(false);
  const [readinessError, setReadinessError] = useState("");
  const [disableBusy, setDisableBusy] = useState(false);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [disableApprovalID, setDisableApprovalID] = useState("");
  const [deleteApprovalID, setDeleteApprovalID] = useState("");
  const [enableBusy, setEnableBusy] = useState(false);

  const selectedTenant = useMemo(() => tenants.find((t) => t.id === selectedTenantId), [tenants, selectedTenantId]);

  // ── Load tenants ──
  const loadTenants = useCallback(async () => {
    if (!session?.token) { setTenants([]); return; }
    setLoading(true);
    try {
      const items = await listAuthTenants(session);
      const next = Array.isArray(items) ? items : [];
      setTenants(next);
      setTenantsError("");
      setSelectedTenantId((current) => (next.some((t) => t.id === current) ? current : next[0]?.id || ""));
    } catch (e) { setTenants([]); setTenantsError(errMsg(e)); }
    finally { setLoading(false); }
  }, [session]);

  useEffect(() => { void loadTenants(); }, [loadTenants]);

  // ── Load users for selected tenant ──
  const loadUsers = useCallback(async () => {
    if (!session?.token || !selectedTenantId) { setTenantUsers([]); return; }
    setUsersLoading(true);
    try {
      const items = await listAuthUsers(session, selectedTenantId);
      setTenantUsers(Array.isArray(items) ? items : []);
      setUsersError("");
    } catch (e) { setTenantUsers([]); setUsersError(errMsg(e)); }
    finally { setUsersLoading(false); }
  }, [session, selectedTenantId]);

  useEffect(() => { void loadUsers(); }, [loadUsers]);

  // ── Load policies ──
  const loadPolicies = useCallback(async () => {
    if (!session?.token || !selectedTenantId) return;
    setPolicyLoading(true);
    try {
      const [pp, sp] = await Promise.all([
        getAuthPasswordPolicy(session, selectedTenantId),
        getAuthSecurityPolicy(session, selectedTenantId)
      ]);
      setPasswordPolicy(pp || defaultPasswordPolicy());
      setSecurityPolicy(sp || defaultSecurityPolicy());
      setPolicyError("");
    } catch (e) { setPolicyError(errMsg(e)); }
    finally { setPolicyLoading(false); }
  }, [session, selectedTenantId]);

  useEffect(() => { if (activeTab === "Security") void loadPolicies(); }, [activeTab, loadPolicies]);

  // ── Load backups ──
  // Backups are a root administrator's (governance system administration),
  // so they are read and made with the signed-in session, naming the tenant.
  const loadBackups = useCallback(async () => {
    if (!session?.token) return;
    setBackupsLoading(true);
    try {
      const items = await listGovernanceBackups(session, { scope: "tenant", limit: 200 });
      setBackups(Array.isArray(items) ? items : []);
    } catch (e) { setBackups([]); onToast(`Backups unavailable: ${errMsg(e)}`); }
    finally { setBackupsLoading(false); }
  }, [session, onToast]);

  useEffect(() => { if (activeTab === "Backup") void loadBackups(); }, [activeTab, loadBackups]);

  // ── Load readiness ──
  const loadReadiness = useCallback(async () => {
    if (!session?.token || !selectedTenantId) { setReadiness(readinessDefaults("")); return; }
    setReadinessLoading(true);
    try {
      const out = await getAuthTenantDeleteReadiness(session, selectedTenantId);
      setReadiness(out || readinessDefaults(selectedTenantId));
      setReadinessError("");
    } catch (e) { setReadiness(readinessDefaults(selectedTenantId)); setReadinessError(errMsg(e)); }
    finally { setReadinessLoading(false); }
  }, [session, selectedTenantId]);

  useEffect(() => { if (activeTab === "Lifecycle") void loadReadiness(); }, [activeTab, loadReadiness]);

  // ── Actions ──
  const createTenant = useCallback(async () => {
    if (!session?.token) return;
    if (!createTenantID.trim() || !createTenantName.trim()) { onToast("Tenant ID and name are required."); return; }
    if (!createAdminEmail.trim() || !createAdminPassword.trim()) { onToast("Admin email and password are required."); return; }
    setCreateBusy(true);
    try {
      await createAuthTenant(session, {
        id: createTenantID.trim(),
        name: createTenantName.trim(),
        admin_username: createAdminUsername.trim(),
        admin_email: createAdminEmail.trim(),
        admin_password: createAdminPassword,
        admin_role: createAdminRole,
        admin_must_change_password: createAdminMustChange
      });
      onToast("Tenant created successfully.");
      setCreateOpen(false);
      setCreateTenantID(""); setCreateTenantName("");
      setCreateAdminEmail(""); setCreateAdminPassword("");
      await loadTenants();
    } catch (e) { onToast(`Create failed: ${errMsg(e)}`); }
    finally { setCreateBusy(false); }
  }, [createAdminEmail, createAdminMustChange, createAdminPassword, createAdminRole, createAdminUsername, createTenantID, createTenantName, loadTenants, onToast, session]);

  const savePolicies = useCallback(async () => {
    if (!session?.token || !selectedTenantId) return;
    setPolicySaving(true);
    try {
      const [pp, sp] = await Promise.all([
        updateAuthPasswordPolicy(session, passwordPolicy, selectedTenantId),
        updateAuthSecurityPolicy(session, securityPolicy, selectedTenantId)
      ]);
      if (pp) setPasswordPolicy(pp);
      if (sp) setSecurityPolicy(sp);
      onToast(`Security policies saved for ${selectedTenantId}.`);
    } catch (e) { onToast(`Save failed: ${errMsg(e)}`); }
    finally { setPolicySaving(false); }
  }, [session, selectedTenantId, passwordPolicy, securityPolicy, onToast]);

  const handleCreateBackup = useCallback(async () => {
    if (!session?.token || !selectedTenantId) return;
    setBackupCreating(true);
    try {
      const { job, key_file } = await createGovernanceBackup(session, {
        scope: "tenant",
        target_tenant_id: selectedTenantId
      });
      if (key_file) saveBackupFile(key_file, `backup-${job.id}.key.json`, "application/json");
      onToast(governanceBackupKeyRetained(job)
        ? "Backup created. Its key file was saved."
        : "Backup created. Its key file was saved: keep it safe, the platform does not keep a copy.");
      await loadBackups();
    } catch (e) { onToast(`Backup failed: ${errMsg(e)}`); }
    finally { setBackupCreating(false); }
  }, [session, selectedTenantId, onToast, loadBackups]);

  const handleDownloadArtifact = useCallback(async (backupId: string) => {
    if (!session?.token) return;
    try {
      const art = await downloadGovernanceBackupArtifact(session, backupId);
      saveBackupFile(art, `backup-${backupId}.vbk`, "application/octet-stream");
    } catch (e) { onToast(`Download failed: ${errMsg(e)}`); }
  }, [session, onToast]);

  const handleDownloadKey = useCallback(async (backupId: string) => {
    if (!session?.token) return;
    try {
      const key = await downloadGovernanceBackupKey(session, backupId);
      saveBackupFile(key, `backup-${backupId}.key.json`, "application/json");
    } catch (e) { onToast(`Key download failed: ${errMsg(e)}`); }
  }, [session, onToast]);

  const handleDeleteBackup = useCallback(async (backupId: string) => {
    if (!session?.token) return;
    try {
      await deleteGovernanceBackup(session, backupId);
      onToast("Backup deleted.");
      await loadBackups();
    } catch (e) { onToast(`Delete failed: ${errMsg(e)}`); }
  }, [session, onToast, loadBackups]);

  const handleDisable = useCallback(async () => {
    if (!session?.token || !selectedTenantId) return;
    setDisableBusy(true);
    try {
      const out = await disableAuthTenant(session, selectedTenantId, disableApprovalID.trim());
      setReadiness(out || readinessDefaults(selectedTenantId));
      onToast("Tenant disabled.");
      await loadTenants();
    } catch (e) { onToast(`Disable failed: ${errMsg(e)}`); }
    finally { setDisableBusy(false); }
  }, [disableApprovalID, loadTenants, onToast, selectedTenantId, session]);

  const handleDelete = useCallback(async () => {
    if (!session?.token || !selectedTenantId) return;
    setDeleteBusy(true);
    try {
      await deleteAuthTenant(session, selectedTenantId, deleteApprovalID.trim());
      onToast("Tenant deleted.");
      setSelectedTenantId("");
      await loadTenants();
    } catch (e) { onToast(`Delete failed: ${errMsg(e)}`); }
    finally { setDeleteBusy(false); }
  }, [deleteApprovalID, loadTenants, onToast, selectedTenantId, session]);

  const handleEnable = useCallback(async () => {
    if (!session?.token || !selectedTenantId) return;
    setEnableBusy(true);
    try {
      await updateAuthTenant(session, selectedTenantId, { status: "active" });
      onToast("Tenant re-enabled.");
      await loadTenants();
      await loadReadiness();
    } catch (e) { onToast(`Enable failed: ${errMsg(e)}`); }
    finally { setEnableBusy(false); }
  }, [session, selectedTenantId, onToast, loadTenants, loadReadiness]);

  // ── Computed ──
  const activeTenants = tenants.filter((t) => t.status === "active").length;
  const disabledTenants = tenants.filter((t) => t.status === "disabled").length;
  const blockerRows = useMemo(() => (Array.isArray(readiness.blockers) ? readiness.blockers : []), [readiness.blockers]);
  const tenantBackups = useMemo(() => backups.filter((b) => b.scope === "tenant" && b.target_tenant_id === selectedTenantId), [backups, selectedTenantId]);
  // The platform tenant, and the tenant this session belongs to, are never
  // disabled or deleted from here.
  const lifecycleProtected = selectedTenantId === PLATFORM_TENANT || selectedTenantId === session?.tenantId;

  // ── Tab Bar ──
  const tabBar = (
    <div style={{ display: "flex", gap: 2, marginBottom: 18, flexWrap: "wrap" }}>
      {INTERNAL_TABS.map((t) => (
        <button
          key={t}
          onClick={() => setActiveTab(t)}
          style={{
            background: activeTab === t ? C.accentDim : "transparent",
            color: activeTab === t ? C.accentFg : C.muted,
            border: `1px solid ${activeTab === t ? C.accent : C.border}`,
            borderRadius: 3,
            padding: "6px 14px",
            fontSize: 10,
            fontWeight: activeTab === t ? 700 : 500,
            cursor: "pointer",
            letterSpacing: 0.3,
            transition: "all .15s"
          }}
        >{t}</button>
      ))}
    </div>
  );

  // ── Tenant Selector ──
  const tenantSelector = (
    <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
      <div style={{ flex: 1 }}>
        <Sel value={selectedTenantId} onChange={(e) => setSelectedTenantId(e.target.value)} style={{ height: 36, fontSize: 12, borderRadius: 8 }}>
          {tenants.map((t) => (
            <option key={t.id} value={t.id}>{`${t.name} (${t.id}) — ${t.status}`}</option>
          ))}
        </Sel>
      </div>
      <Btn small onClick={() => void loadTenants()} disabled={loading}>{loading ? "..." : "Refresh"}</Btn>
      <Btn small primary onClick={() => setCreateOpen(true)}>+ Create Tenant</Btn>
    </div>
  );

  // ── VIEW: Overview ──
  const overviewView = (
    <div>
      <div style={{ display: "flex", gap: 10, marginBottom: 18, flexWrap: "wrap" }}>
        <Stat l="Total Tenants" v={tenants.length} c="accent" />
        <Stat l="Active" v={activeTenants} c="green" />
        <Stat l="Disabled" v={disabledTenants} c="orange" />
        <Stat l="Users" v={usersError ? "—" : tenantUsers.length} s={usersError ? `unavailable: ${usersError}` : usersLoading ? "Loading..." : `in ${selectedTenant?.name || "—"}`} c="blue" />
      </div>

      {/* Tenant Cards Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 12, marginBottom: 18 }}>
        {tenants.map((t) => {
          const isSelected = t.id === selectedTenantId;
          return (
            <div
              key={t.id}
              onClick={() => setSelectedTenantId(t.id)}
              style={{
                background: isSelected ? C.card : C.surface,
                border: `1px solid ${isSelected ? C.accent : C.border}`,
                borderRadius: 4,
                padding: "14px 16px",
                cursor: "pointer",
                transition: "all .15s",
                boxShadow: isSelected ? `0 0 16px ${C.glow}` : "none"
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: C.text, letterSpacing: -0.2 }}>{t.name}</span>
                <B c={t.status === "active" ? "green" : t.status === "disabled" ? "orange" : "blue"}>{t.status}</B>
              </div>
              <div style={{ fontSize: 10, color: C.muted, fontFamily: "var(--font-mono)", marginBottom: 6 }}>{t.id}</div>
              {t.created_at && <div style={{ fontSize: 10, color: C.muted }}>Created {relativeTime(t.created_at)}</div>}
            </div>
          );
        })}
      </div>

      {/* Selected Tenant Detail Card */}
      {selectedTenant && (
        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <div>
              <div style={{ fontSize: 15, fontWeight: 700, color: C.text }}>{selectedTenant.name}</div>
              <div style={{ fontSize: 10, color: C.muted, fontFamily: "var(--font-mono)", marginTop: 2 }}>{selectedTenant.id}</div>
            </div>
            <B c={selectedTenant.status === "active" ? "green" : "orange"} pulse={selectedTenant.status === "active"}>{selectedTenant.status.toUpperCase()}</B>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
            <div style={{ background: C.surface, borderRadius: 4, padding: "10px 12px", border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>Users</div>
              <div style={{ fontSize: 20, fontWeight: 700, color: C.text, marginTop: 2 }}>{usersError ? "—" : tenantUsers.length}</div>
            </div>
            <div style={{ background: C.surface, borderRadius: 4, padding: "10px 12px", border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>Active Users</div>
              <div style={{ fontSize: 20, fontWeight: 700, color: C.text, marginTop: 2 }}>{usersError ? "—" : tenantUsers.filter((u) => u.status === "active").length}</div>
            </div>
            <div style={{ background: C.surface, borderRadius: 4, padding: "10px 12px", border: `1px solid ${C.border}` }}>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>Admin Users</div>
              <div style={{ fontSize: 20, fontWeight: 700, color: C.text, marginTop: 2 }}>{usersError ? "—" : tenantUsers.filter((u) => u.role?.includes("admin")).length}</div>
            </div>
          </div>

          {/* User List Preview */}
          {tenantUsers.length > 0 && (
            <div style={{ marginTop: 14 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: C.dim, textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 8 }}>Tenant Users</div>
              <div style={{ display: "grid", gap: 4, maxHeight: 200, overflowY: "auto" }}>
                {tenantUsers.slice(0, 20).map((u) => (
                  <div key={u.id} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", background: C.surface, borderRadius: 3, border: `1px solid ${C.border}` }}>
                    <div style={{ width: 24, height: 24, borderRadius: 3, background: C.accentDim, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700, color: C.accentFg, flexShrink: 0 }}>
                      {(u.username || "?").slice(0, 2).toUpperCase()}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 11, color: C.text, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{u.username}</div>
                      <div style={{ fontSize: 10, color: C.muted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{u.email}</div>
                    </div>
                    <B c={u.role?.includes("admin") ? "purple" : "blue"}>{u.role}</B>
                    <B c={u.status === "active" ? "green" : "orange"}>{u.status}</B>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Card>
      )}
    </div>
  );

  // ── VIEW: Security ──
  const securityView = (
    <div>
      {/* The exposure register is read from each service as the signed-in tenant. */}
      {selectedTenantId === session?.tenantId && <div style={{ marginBottom: 12 }}><ExposurePanel session={session} onToast={onToast}/></div>}
      {policyLoading && <div style={{ fontSize: 10, color: C.muted, marginBottom: 10 }}>Loading policies...</div>}
      {policyError && <div style={{ fontSize: 11, color: C.amberFg, marginBottom: 10 }}>{`Policies unavailable: ${policyError}`}</div>}
      {!policyError && <>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {/* Password Policy */}
        <Card style={{ borderTop: `2px solid ${C.blue}` }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 14 }}>Password Policy</div>
          <Row2>
            <FG label="Min Length">
              <Inp type="number" value={passwordPolicy.min_length} onChange={(e) => setPasswordPolicy((p) => ({ ...p, min_length: Number(e.target.value) }))} />
            </FG>
            <FG label="Max Length">
              <Inp type="number" value={passwordPolicy.max_length} onChange={(e) => setPasswordPolicy((p) => ({ ...p, max_length: Number(e.target.value) }))} />
            </FG>
          </Row2>
          <FG label="Min Unique Characters">
            <Inp type="number" value={passwordPolicy.min_unique_chars} onChange={(e) => setPasswordPolicy((p) => ({ ...p, min_unique_chars: Number(e.target.value) }))} />
          </FG>
          <div style={{ display: "grid", gap: 6, marginTop: 8 }}>
            <Chk label="Require uppercase" checked={passwordPolicy.require_upper} onChange={() => setPasswordPolicy((p) => ({ ...p, require_upper: !p.require_upper }))} />
            <Chk label="Require lowercase" checked={passwordPolicy.require_lower} onChange={() => setPasswordPolicy((p) => ({ ...p, require_lower: !p.require_lower }))} />
            <Chk label="Require digit" checked={passwordPolicy.require_digit} onChange={() => setPasswordPolicy((p) => ({ ...p, require_digit: !p.require_digit }))} />
            <Chk label="Require special character" checked={passwordPolicy.require_special} onChange={() => setPasswordPolicy((p) => ({ ...p, require_special: !p.require_special }))} />
            <Chk label="No whitespace" checked={passwordPolicy.require_no_whitespace} onChange={() => setPasswordPolicy((p) => ({ ...p, require_no_whitespace: !p.require_no_whitespace }))} />
            <Chk label="Deny username in password" checked={passwordPolicy.deny_username} onChange={() => setPasswordPolicy((p) => ({ ...p, deny_username: !p.deny_username }))} />
            <Chk label="Deny email local part" checked={passwordPolicy.deny_email_local_part} onChange={() => setPasswordPolicy((p) => ({ ...p, deny_email_local_part: !p.deny_email_local_part }))} />
          </div>
          {passwordPolicy.updated_at && <div style={{ fontSize: 10, color: C.muted, marginTop: 10 }}>Last updated: {relativeTime(passwordPolicy.updated_at)}{passwordPolicy.updated_by ? ` by ${passwordPolicy.updated_by}` : ""}</div>}
        </Card>

        {/* Security / Lockout Policy */}
        <Card style={{ borderTop: `2px solid ${C.purple}` }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 14 }}>Lockout &amp; Session Policy</div>
          <FG label="Max Failed Login Attempts">
            <Inp type="number" value={securityPolicy.max_failed_attempts} onChange={(e) => setSecurityPolicy((p) => ({ ...p, max_failed_attempts: Number(e.target.value) }))} />
          </FG>
          <FG label="Lockout Duration (minutes)">
            <Inp type="number" value={securityPolicy.lockout_minutes} onChange={(e) => setSecurityPolicy((p) => ({ ...p, lockout_minutes: Number(e.target.value) }))} />
          </FG>
          <FG label="Idle Session Timeout (minutes)">
            <Inp type="number" value={securityPolicy.idle_timeout_minutes} onChange={(e) => setSecurityPolicy((p) => ({ ...p, idle_timeout_minutes: Number(e.target.value) }))} />
          </FG>

          {/* Visual Policy Summary */}
          <div style={{ marginTop: 14, padding: "10px 12px", background: C.surface, borderRadius: 4, border: `1px solid ${C.border}` }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: C.dim, marginBottom: 8 }}>Policy Summary</div>
            <div style={{ display: "grid", gap: 6 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10 }}>
                <span style={{ color: C.dim }}>Lockout after</span>
                <span style={{ color: C.text, fontWeight: 600 }}>{securityPolicy.max_failed_attempts} failed attempts</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10 }}>
                <span style={{ color: C.dim }}>Locked for</span>
                <span style={{ color: C.amberFg, fontWeight: 600 }}>{securityPolicy.lockout_minutes} min</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10 }}>
                <span style={{ color: C.dim }}>Idle timeout</span>
                <span style={{ color: C.blueFg, fontWeight: 600 }}>{securityPolicy.idle_timeout_minutes} min</span>
              </div>
            </div>
          </div>
          {securityPolicy.updated_at && <div style={{ fontSize: 10, color: C.muted, marginTop: 10 }}>Last updated: {relativeTime(securityPolicy.updated_at)}{securityPolicy.updated_by ? ` by ${securityPolicy.updated_by}` : ""}</div>}
        </Card>
      </div>

      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14, gap: 8 }}>
        <Btn small onClick={() => void loadPolicies()} disabled={policyLoading}>{policyLoading ? "Loading..." : "Reload"}</Btn>
        <Btn small primary onClick={() => void savePolicies()} disabled={policySaving || policyLoading}>{policySaving ? "Saving..." : "Save Policies"}</Btn>
      </div>
      </>}
    </div>
  );

  // ── VIEW: Backup ──
  const backupView = (
    <div>
      <div>
      <div style={{ display: "flex", gap: 10, marginBottom: 18, flexWrap: "wrap" }}>
        <Stat l="Total Backups" v={tenantBackups.length} c="accent" />
        <Stat l="Completed" v={tenantBackups.filter((b) => b.status === "completed").length} c="green" />
        <Stat l="HSM Bound" v={tenantBackups.filter((b) => b.hsm_bound).length} c="purple" />
        <Stat l="Total Size" v={formatBytes(tenantBackups.reduce((s, b) => s + (b.artifact_size_bytes || 0), 0))} c="blue" />
      </div>

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Tenant Backups</div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn small onClick={() => void loadBackups()} disabled={backupsLoading}>{backupsLoading ? "..." : "Refresh"}</Btn>
          <Btn small primary onClick={() => void handleCreateBackup()} disabled={backupCreating || !selectedTenantId}>
            {backupCreating ? "Creating..." : "Create Backup"}
          </Btn>
        </div>
      </div>

      <div style={{ display: "grid", gap: 8 }}>
        {tenantBackups.length === 0 && !backupsLoading && (
          <div style={{ padding: "24px 16px", textAlign: "center", color: C.muted, fontSize: 11, background: C.surface, borderRadius: 4, border: `1px solid ${C.border}` }}>
            No backups found for this tenant. Create one to get started.
          </div>
        )}
        {tenantBackups.map((b) => (
          <Card key={b.id} style={{ borderLeft: `3px solid ${b.status === "completed" ? C.green : b.status === "failed" ? C.red : C.amber}` }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: 11, fontWeight: 700, color: C.text, fontFamily: "var(--font-mono)" }}>{b.id}</span>
                  <B c={b.status === "completed" ? "green" : b.status === "failed" ? "red" : "amber"}>{b.status}</B>
                  {b.hsm_bound && <B c="purple">HSM</B>}
                </div>
                <div style={{ display: "flex", gap: 16, fontSize: 10, color: C.muted }}>
                  <span>Scope: {b.scope}</span>
                  <span>Rows: {b.row_count_total || 0}</span>
                  <span>Tables: {b.table_count || 0}</span>
                  <span>Size: {formatBytes(b.artifact_size_bytes || 0)}</span>
                  <span>Encryption: {b.encryption_algorithm || "AES-256-GCM"}</span>
                </div>
                {b.created_at && <div style={{ fontSize: 10, color: C.muted, marginTop: 4 }}>Created: {relativeTime(b.created_at)}{b.created_by ? ` by ${b.created_by}` : ""}</div>}
              </div>
              <div style={{ display: "flex", gap: 4, flexShrink: 0 }}>
                {b.status === "completed" && (
                  <>
                    <Btn small onClick={() => void handleDownloadArtifact(b.id)}>Artifact</Btn>
                    {governanceBackupKeyRetained(b) && <Btn small onClick={() => void handleDownloadKey(b.id)}>Key</Btn>}
                  </>
                )}
                <Btn small danger onClick={() => void handleDeleteBackup(b.id)}>Delete</Btn>
              </div>
            </div>
          </Card>
        ))}
      </div>
      </div>
    </div>
  );

  // ── VIEW: Lifecycle ──
  const lifecycleView = (
    <div>
      {readinessLoading && <div style={{ fontSize: 10, color: C.muted, marginBottom: 10 }}>Checking readiness...</div>}
      {readinessError && <div style={{ fontSize: 11, color: C.amberFg, marginBottom: 10 }}>{`Readiness unavailable: ${readinessError}`}</div>}

      {/* Status Card */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10, marginBottom: 18 }}>
        <div style={{ background: C.card, borderRadius: 4, border: `1px solid ${C.border}`, padding: "12px 14px" }}>
          <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>Tenant Status</div>
          <div style={{ fontSize: 16, fontWeight: 700, color: C.text, marginTop: 4 }}>{readiness.tenant_status?.toUpperCase() || "UNKNOWN"}</div>
        </div>
        <div style={{ background: C.card, borderRadius: 4, border: `1px solid ${C.border}`, padding: "12px 14px" }}>
          <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>UI Sessions</div>
          <div style={{ fontSize: 20, fontWeight: 700, color: C.text, marginTop: 4 }}>{Number(readiness.active_ui_session_count || 0)}</div>
        </div>
        <div style={{ background: C.card, borderRadius: 4, border: `1px solid ${C.border}`, padding: "12px 14px" }}>
          <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>Service Links</div>
          <div style={{ fontSize: 20, fontWeight: 700, color: C.text, marginTop: 4 }}>{Number(readiness.active_service_link_count || 0)}</div>
        </div>
        <div style={{ background: C.card, borderRadius: 4, border: `1px solid ${C.border}`, padding: "12px 14px" }}>
          <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>Blockers</div>
          <div style={{ fontSize: 20, fontWeight: 700, color: blockerRows.length > 0 ? C.redFg : C.text, marginTop: 4 }}>{blockerRows.length}</div>
        </div>
      </div>

      {/* Readiness Indicators */}
      <div style={{ display: "flex", gap: 10, marginBottom: 18 }}>
        <Card style={{ flex: 1 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>Disable Ready</div>
              <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>Tenant can be safely disabled</div>
            </div>
            <B c={readiness.can_disable ? "green" : "amber"} pulse={Boolean(readiness.can_disable)}>{readiness.can_disable ? "YES" : "NO"}</B>
          </div>
        </Card>
        <Card style={{ flex: 1 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>Delete Ready</div>
              <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>Tenant can be permanently removed</div>
            </div>
            <B c={readiness.can_delete ? "green" : "red"} pulse={Boolean(readiness.can_delete)}>{readiness.can_delete ? "YES" : "NO"}</B>
          </div>
        </Card>
      </div>

      {/* Blockers */}
      <Card style={{ marginBottom: 18 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 10 }}>Delete Blockers</div>
        {blockerRows.length === 0 ? (
          <div style={{ fontSize: 10, color: C.muted, padding: "8px 0" }}>No blockers detected. Tenant is clear for lifecycle operations.</div>
        ) : (
          <div style={{ display: "grid", gap: 8 }}>
            {blockerRows.map((blocker) => (
              <div key={String(blocker.code || Math.random())} style={{ padding: "10px 12px", background: C.surface, borderRadius: 4, border: `1px solid ${C.border}` }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{String(blocker.label || blocker.code || "Blocker")}</span>
                  <B c="red">{Number(blocker.count || 0)} active</B>
                </div>
                {blocker.remediation && <div style={{ fontSize: 10, color: C.dim, marginTop: 4 }}>{blocker.remediation}</div>}
                {Array.isArray(blocker.details) && blocker.details.length > 0 && (
                  <div style={{ fontSize: 10, color: C.muted, marginTop: 4, fontFamily: "var(--font-mono)" }}>
                    {blocker.details.slice(0, 5).join(", ")}
                    {blocker.details.length > 5 && ` +${blocker.details.length - 5} more`}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Actions */}
      <Card>
        <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 14 }}>Lifecycle Actions</div>

        {selectedTenant?.status === "disabled" && (
          <div style={{ marginBottom: 14, padding: "10px 12px", background: C.surface, borderRadius: 4, border: `1px solid ${C.border}` }}>
            <div style={{ fontSize: 11, color: C.greenFg, fontWeight: 600, marginBottom: 4 }}>Re-enable Tenant</div>
            <div style={{ fontSize: 10, color: C.dim, marginBottom: 8 }}>Restore this tenant to active status.</div>
            <Btn small onClick={() => void handleEnable()} disabled={enableBusy}>{enableBusy ? "Enabling..." : "Enable Tenant"}</Btn>
          </div>
        )}

        {lifecycleProtected ? (
          <div style={{ fontSize: 11, color: C.dim }}>
            {selectedTenantId === PLATFORM_TENANT ? "The platform tenant is never disabled or deleted." : "The tenant you are signed in to is disabled or deleted from another tenant's session."}
          </div>
        ) : <>
        <Row2>
          <FG label="Disable Approval Request ID (optional)">
            <Inp value={disableApprovalID} onChange={(e) => setDisableApprovalID(e.target.value)} placeholder="governance-approval-id" />
          </FG>
          <FG label="Delete Approval Request ID (optional)">
            <Inp value={deleteApprovalID} onChange={(e) => setDeleteApprovalID(e.target.value)} placeholder="governance-approval-id" />
          </FG>
        </Row2>
        <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
          <Btn small onClick={() => void loadReadiness()} disabled={readinessLoading}>{readinessLoading ? "Checking..." : "Check Readiness"}</Btn>
          <Btn small danger onClick={() => void handleDisable()} disabled={disableBusy || !selectedTenantId || !readiness.can_disable}>
            {disableBusy ? "Disabling..." : "Disable Tenant"}
          </Btn>
          <Btn small danger onClick={() => void handleDelete()} disabled={deleteBusy || !selectedTenantId || !readiness.can_delete}>
            {deleteBusy ? "Deleting..." : "Delete Tenant"}
          </Btn>
        </div>
        </>}
      </Card>
    </div>
  );

  // ── Create Tenant Modal ──
  const createModal = (
    <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="Create New Tenant" wide>
      <div style={{ display: "grid", gap: 12 }}>
        <div style={{ padding: "10px 12px", background: C.surface, borderRadius: 4, border: `1px solid ${C.border}`, marginBottom: 4 }}>
          <div style={{ fontSize: 10, color: C.accentFg, fontWeight: 600 }}>New Tenant Setup</div>
          <div style={{ fontSize: 10, color: C.dim, marginTop: 2 }}>Creates an isolated tenant with its own data segregation, admin user, and security policies.</div>
        </div>

        <div style={{ fontSize: 11, fontWeight: 700, color: C.dim, textTransform: "uppercase", letterSpacing: 0.8 }}>Tenant Details</div>
        <Row2>
          <FG label="Tenant ID" required>
            <Inp value={createTenantID} onChange={(e) => setCreateTenantID(e.target.value)} placeholder="my-tenant" />
          </FG>
          <FG label="Tenant Name" required>
            <Inp value={createTenantName} onChange={(e) => setCreateTenantName(e.target.value)} placeholder="My Tenant" />
          </FG>
        </Row2>
        <Row2>
          <FG label="Admin Role">
            <Sel value={createAdminRole} onChange={(e) => setCreateAdminRole(e.target.value)}>
              <option value="tenant-admin">Tenant Admin</option>
              <option value="admin">Admin</option>
            </Sel>
          </FG>
          <div />
        </Row2>

        <div style={{ fontSize: 11, fontWeight: 700, color: C.dim, textTransform: "uppercase", letterSpacing: 0.8, marginTop: 4 }}>Initial Admin User</div>
        <Row2>
          <FG label="Admin Username" required>
            <Inp value={createAdminUsername} onChange={(e) => setCreateAdminUsername(e.target.value)} placeholder="admin" />
          </FG>
          <FG label="Admin Email" required>
            <Inp value={createAdminEmail} onChange={(e) => setCreateAdminEmail(e.target.value)} placeholder="admin@tenant.local" />
          </FG>
        </Row2>
        <FG label="Admin Password" required>
          <Inp type="password" value={createAdminPassword} onChange={(e) => setCreateAdminPassword(e.target.value)} placeholder="Strong password" />
        </FG>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <Chk label="Require password change on first login" checked={createAdminMustChange} onChange={() => setCreateAdminMustChange((p) => !p)} />
        </div>

        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 8 }}>
          <Btn onClick={() => setCreateOpen(false)}>Cancel</Btn>
          <Btn primary onClick={() => void createTenant()} disabled={createBusy}>{createBusy ? "Creating..." : "Create Tenant"}</Btn>
        </div>
      </div>
    </Modal>
  );

  // ── Main Render ──
  return (
    <div>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 700, color: C.text, letterSpacing: -0.3 }}>Tenant Administration</div>
          <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>Tenants, their security policies, backups and lifecycle</div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {selectedTenant && <B c={selectedTenant.status === "active" ? "green" : "orange"}>{selectedTenant.name}</B>}
        </div>
      </div>

      {tenantsError ? (
        <Card>
          <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Tenants unavailable</div>
          <div style={{ fontSize: 11, color: C.dim, marginTop: 4 }}>{tenantsError}</div>
        </Card>
      ) : <>
      {tenantSelector}
      {tabBar}

      {activeTab === "Overview" && overviewView}
      {activeTab === "Security" && securityView}
      {activeTab === "Backup" && backupView}
      {activeTab === "Lifecycle" && lifecycleView}
      </>}

      {createModal}
    </div>
  );
};
