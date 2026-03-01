import { useCallback, useEffect, useMemo, useState, type Dispatch, type SetStateAction } from "react";
import {
  createAuthUser,
  deleteAuthGroupRoleBinding,
  importAuthIdentityUsers,
  getAuthPasswordPolicy,
  listAuthIdentityProviderGroupMembers,
  listAuthIdentityProviderGroups,
  listAuthIdentityProviderUsers,
  listAuthIdentityProviders,
  getAuthSecurityPolicy,
  listAuthGroupRoleBindings,
  listAuthTenants,
  listAuthUsers,
  resetAuthUserPassword,
  testAuthIdentityProviderConfig,
  updateAuthPasswordPolicy,
  updateAuthSecurityPolicy,
  updateAuthUserRole,
  updateAuthUserStatus,
  upsertAuthIdentityProviderConfig,
  upsertAuthGroupRoleBinding,
  type AuthTenant,
  type AuthUser,
  type ExternalDirectoryGroup,
  type ExternalDirectoryUser,
  type GroupRoleBinding,
  type IdentityProviderConfigView,
  type IdentityProviderName,
  type PasswordPolicy,
  type SecurityPolicy
} from "../../../lib/authAdmin";
import { errMsg } from "../../../components/v3/runtimeUtils";
import type { AdminTabProps } from "../types";
import { defaultPasswordPolicy, defaultSecurityPolicy, parseJsonObject, prettyJson } from "./constants";

type SetState<T> = Dispatch<SetStateAction<T>>;

export type UserAdminModel = {
  tenants: AuthTenant[];
  selectedTenant: string;
  setSelectedTenant: SetState<string>;
  users: AuthUser[];
  bindings: GroupRoleBinding[];
  passwordPolicy: PasswordPolicy;
  setPasswordPolicy: SetState<PasswordPolicy>;
  securityPolicy: SecurityPolicy;
  setSecurityPolicy: SetState<SecurityPolicy>;

  loading: boolean;
  savingPolicy: boolean;
  createBusy: boolean;
  updateBusy: string;
  bindingBusy: boolean;

  newUsername: string;
  setNewUsername: SetState<string>;
  newEmail: string;
  setNewEmail: SetState<string>;
  newPassword: string;
  setNewPassword: SetState<string>;
  newRole: string;
  setNewRole: SetState<string>;
  newStatus: string;
  setNewStatus: SetState<string>;

  resetUserID: string;
  setResetUserID: SetState<string>;
  resetPasswordValue: string;
  setResetPasswordValue: SetState<string>;
  resetMustChange: boolean;
  setResetMustChange: SetState<boolean>;

  groupID: string;
  setGroupID: SetState<string>;
  groupRole: string;
  setGroupRole: SetState<string>;

  idpProvider: IdentityProviderName;
  setIdpProvider: SetState<IdentityProviderName>;
  idpEnabled: boolean;
  setIdpEnabled: SetState<boolean>;
  idpConfigJson: string;
  setIdpConfigJson: SetState<string>;
  idpSecretsJson: string;
  setIdpSecretsJson: SetState<string>;
  idpSaving: boolean;
  idpTesting: boolean;
  idpUsersLoading: boolean;
  idpGroupsLoading: boolean;
  idpMembersLoading: boolean;
  idpImporting: boolean;
  idpQuery: string;
  setIdpQuery: SetState<string>;
  idpSelectedGroupID: string;
  setIdpSelectedGroupID: SetState<string>;
  idpUsers: ExternalDirectoryUser[];
  idpGroups: ExternalDirectoryGroup[];
  idpMembers: ExternalDirectoryUser[];
  idpSelectedUserIDs: string[];
  idpImportRole: string;
  setIdpImportRole: SetState<string>;
  idpImportStatus: string;
  setIdpImportStatus: SetState<string>;
  idpImportMustChange: boolean;
  setIdpImportMustChange: SetState<boolean>;

  usersByStatus: {
    active: number;
    disabled: number;
  };

  loadUsers: () => Promise<void>;
  createUser: () => Promise<void>;
  updateRole: (user: AuthUser, role: string) => Promise<void>;
  updateStatus: (user: AuthUser, status: string) => Promise<void>;
  resetPassword: () => Promise<void>;
  savePolicies: () => Promise<void>;
  upsertBinding: () => Promise<void>;
  removeBinding: (binding: GroupRoleBinding) => Promise<void>;
  loadIdpConfig: () => Promise<void>;
  saveIdpConfig: () => Promise<void>;
  testIdpConfig: () => Promise<void>;
  discoverIdpUsers: () => Promise<void>;
  discoverIdpGroups: () => Promise<void>;
  discoverIdpMembers: () => Promise<void>;
  toggleIdpUserSelection: (externalID: string) => void;
  importIdpUsers: () => Promise<void>;
};

export function useUserAdminModel({ session, onToast }: Pick<AdminTabProps, "session" | "onToast">): UserAdminModel {
  const [tenants, setTenants] = useState<AuthTenant[]>([]);
  const [selectedTenant, setSelectedTenant] = useState("");
  const [users, setUsers] = useState<AuthUser[]>([]);
  const [bindings, setBindings] = useState<GroupRoleBinding[]>([]);
  const [passwordPolicy, setPasswordPolicy] = useState<PasswordPolicy>(defaultPasswordPolicy);
  const [securityPolicy, setSecurityPolicy] = useState<SecurityPolicy>(defaultSecurityPolicy);

  const [loading, setLoading] = useState(false);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [createBusy, setCreateBusy] = useState(false);
  const [updateBusy, setUpdateBusy] = useState("");
  const [bindingBusy, setBindingBusy] = useState(false);

  const [newUsername, setNewUsername] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("viewer");
  const [newStatus, setNewStatus] = useState("active");

  const [resetUserID, setResetUserID] = useState("");
  const [resetPasswordValue, setResetPasswordValue] = useState("");
  const [resetMustChange, setResetMustChange] = useState(true);

  const [groupID, setGroupID] = useState("");
  const [groupRole, setGroupRole] = useState("viewer");

  const [idpProvider, setIdpProvider] = useState<IdentityProviderName>("ad");
  const [idpEnabled, setIdpEnabled] = useState(false);
  const [idpConfigJson, setIdpConfigJson] = useState("{}");
  const [idpSecretsJson, setIdpSecretsJson] = useState("{}");
  const [idpSaving, setIdpSaving] = useState(false);
  const [idpTesting, setIdpTesting] = useState(false);
  const [idpUsersLoading, setIdpUsersLoading] = useState(false);
  const [idpGroupsLoading, setIdpGroupsLoading] = useState(false);
  const [idpMembersLoading, setIdpMembersLoading] = useState(false);
  const [idpImporting, setIdpImporting] = useState(false);
  const [idpQuery, setIdpQuery] = useState("");
  const [idpSelectedGroupID, setIdpSelectedGroupID] = useState("");
  const [idpUsers, setIdpUsers] = useState<ExternalDirectoryUser[]>([]);
  const [idpGroups, setIdpGroups] = useState<ExternalDirectoryGroup[]>([]);
  const [idpMembers, setIdpMembers] = useState<ExternalDirectoryUser[]>([]);
  const [idpSelectedUserIDs, setIdpSelectedUserIDs] = useState<string[]>([]);
  const [idpImportRole, setIdpImportRole] = useState("viewer");
  const [idpImportStatus, setIdpImportStatus] = useState("active");
  const [idpImportMustChange, setIdpImportMustChange] = useState(true);

  const loadTenants = useCallback(async () => {
    if (!session?.token) {
      setTenants([]);
      setSelectedTenant("");
      return;
    }
    try {
      const items = await listAuthTenants(session);
      const next = Array.isArray(items) ? items : [];
      setTenants(next);
      if (!next.some((tenant) => String(tenant.id) === String(selectedTenant))) {
        setSelectedTenant(next[0]?.id || "");
      }
    } catch (error) {
      onToast(`Tenant list load failed: ${errMsg(error)}`);
    }
  }, [onToast, selectedTenant, session]);

  const loadUsers = useCallback(async () => {
    const tenantID = String(selectedTenant || "").trim();
    if (!session?.token || !tenantID) {
      setUsers([]);
      setBindings([]);
      return;
    }
    setLoading(true);
    try {
      const [userRows, bindingRows] = await Promise.all([
        listAuthUsers(session, tenantID),
        listAuthGroupRoleBindings(session, tenantID)
      ]);
      setUsers(Array.isArray(userRows) ? userRows : []);
      setBindings(Array.isArray(bindingRows) ? bindingRows : []);
    } catch (error) {
      onToast(`User inventory load failed: ${errMsg(error)}`);
    } finally {
      setLoading(false);
    }
  }, [onToast, selectedTenant, session]);

  const loadPolicies = useCallback(async () => {
    if (!session?.token) {
      setPasswordPolicy(defaultPasswordPolicy);
      setSecurityPolicy(defaultSecurityPolicy);
      return;
    }
    try {
      const [pwd, sec] = await Promise.all([getAuthPasswordPolicy(session), getAuthSecurityPolicy(session)]);
      setPasswordPolicy(pwd || defaultPasswordPolicy);
      setSecurityPolicy(sec || defaultSecurityPolicy);
    } catch (error) {
      onToast(`Policy load failed: ${errMsg(error)}`);
    }
  }, [onToast, session]);

  const createUser = useCallback(async () => {
    const tenantID = String(selectedTenant || "").trim();
    if (!session?.token || !tenantID) {
      return;
    }
    if (!String(newUsername || "").trim() || !String(newEmail || "").trim() || !String(newPassword || "").trim()) {
      onToast("Username, email, and password are required.");
      return;
    }
    setCreateBusy(true);
    try {
      await createAuthUser(session, {
        tenant_id: tenantID,
        username: newUsername,
        email: newEmail,
        password: newPassword,
        role: newRole,
        status: newStatus,
        must_change_password: true
      });
      onToast("User created.");
      setNewUsername("");
      setNewEmail("");
      setNewPassword("");
      await loadUsers();
    } catch (error) {
      onToast(`User create failed: ${errMsg(error)}`);
    } finally {
      setCreateBusy(false);
    }
  }, [loadUsers, newEmail, newPassword, newRole, newStatus, newUsername, onToast, selectedTenant, session]);

  const updateRole = useCallback(
    async (user: AuthUser, role: string) => {
      const userID = String(user.id || "").trim();
      if (!session?.token || !userID) {
        return;
      }
      setUpdateBusy(`${userID}:role`);
      try {
        await updateAuthUserRole(session, userID, role, selectedTenant);
        onToast("User role updated.");
        await loadUsers();
      } catch (error) {
        onToast(`Role update failed: ${errMsg(error)}`);
      } finally {
        setUpdateBusy("");
      }
    },
    [loadUsers, onToast, selectedTenant, session]
  );

  const updateStatus = useCallback(
    async (user: AuthUser, status: string) => {
      const userID = String(user.id || "").trim();
      if (!session?.token || !userID) {
        return;
      }
      setUpdateBusy(`${userID}:status`);
      try {
        await updateAuthUserStatus(session, userID, status, selectedTenant);
        onToast("User status updated.");
        await loadUsers();
      } catch (error) {
        onToast(`Status update failed: ${errMsg(error)}`);
      } finally {
        setUpdateBusy("");
      }
    },
    [loadUsers, onToast, selectedTenant, session]
  );

  const resetPassword = useCallback(async () => {
    const userID = String(resetUserID || "").trim();
    if (!session?.token || !userID) {
      onToast("Select a user for reset.");
      return;
    }
    if (!String(resetPasswordValue || "").trim()) {
      onToast("Provide new password.");
      return;
    }
    setUpdateBusy(`${userID}:reset`);
    try {
      await resetAuthUserPassword(session, userID, {
        new_password: resetPasswordValue,
        must_change_password: resetMustChange,
        tenant_id: selectedTenant
      });
      onToast("Password reset completed.");
      setResetPasswordValue("");
      await loadUsers();
    } catch (error) {
      onToast(`Password reset failed: ${errMsg(error)}`);
    } finally {
      setUpdateBusy("");
    }
  }, [loadUsers, onToast, resetMustChange, resetPasswordValue, resetUserID, selectedTenant, session]);

  const savePolicies = useCallback(async () => {
    if (!session?.token) {
      return;
    }
    setSavingPolicy(true);
    try {
      await Promise.all([
        updateAuthPasswordPolicy(session, {
          ...passwordPolicy,
          min_length: Math.max(8, Math.trunc(Number(passwordPolicy.min_length || 12))),
          max_length: Math.max(32, Math.trunc(Number(passwordPolicy.max_length || 128))),
          min_unique_chars: Math.max(1, Math.trunc(Number(passwordPolicy.min_unique_chars || 6)))
        }),
        updateAuthSecurityPolicy(session, {
          ...securityPolicy,
          max_failed_attempts: Math.max(1, Math.trunc(Number(securityPolicy.max_failed_attempts || 5))),
          lockout_minutes: Math.max(1, Math.trunc(Number(securityPolicy.lockout_minutes || 15))),
          idle_timeout_minutes: Math.max(1, Math.trunc(Number(securityPolicy.idle_timeout_minutes || 30)))
        })
      ]);
      onToast("Auth policies updated.");
      await loadPolicies();
    } catch (error) {
      onToast(`Policy save failed: ${errMsg(error)}`);
    } finally {
      setSavingPolicy(false);
    }
  }, [loadPolicies, onToast, passwordPolicy, securityPolicy, session]);

  const upsertBinding = useCallback(async () => {
    const tenantID = String(selectedTenant || "").trim();
    if (!session?.token || !tenantID) {
      return;
    }
    if (!String(groupID || "").trim() || !String(groupRole || "").trim()) {
      onToast("Group ID and role are required.");
      return;
    }
    setBindingBusy(true);
    try {
      await upsertAuthGroupRoleBinding(session, String(groupID || "").trim(), String(groupRole || "").trim(), tenantID);
      onToast("Group role binding upserted.");
      setGroupID("");
      await loadUsers();
    } catch (error) {
      onToast(`Group role binding failed: ${errMsg(error)}`);
    } finally {
      setBindingBusy(false);
    }
  }, [groupID, groupRole, loadUsers, onToast, selectedTenant, session]);

  const removeBinding = useCallback(
    async (binding: GroupRoleBinding) => {
      const tenantID = String(binding.tenant_id || selectedTenant || "").trim();
      const group = String(binding.group_id || "").trim();
      if (!session?.token || !tenantID || !group) {
        return;
      }
      setBindingBusy(true);
      try {
        await deleteAuthGroupRoleBinding(session, group, tenantID);
        onToast("Group role binding deleted.");
        await loadUsers();
      } catch (error) {
        onToast(`Binding delete failed: ${errMsg(error)}`);
      } finally {
        setBindingBusy(false);
      }
    },
    [loadUsers, onToast, selectedTenant, session]
  );

  const loadIdpConfig = useCallback(async () => {
    if (!session?.token) {
      setIdpEnabled(false);
      setIdpConfigJson("{}");
      setIdpSecretsJson("{}");
      return;
    }
    try {
      const configs = await listAuthIdentityProviders(session, selectedTenant);
      const found = (Array.isArray(configs) ? configs : []).find((item: IdentityProviderConfigView) => item.provider === idpProvider);
      setIdpEnabled(Boolean(found?.enabled));
      setIdpConfigJson(prettyJson(found?.config || {}));
      setIdpSecretsJson("{}");
    } catch (error) {
      onToast(`Identity provider load failed: ${errMsg(error)}`);
    }
  }, [idpProvider, onToast, selectedTenant, session]);

  const saveIdpConfig = useCallback(async () => {
    if (!session?.token) {
      return;
    }
    setIdpSaving(true);
    try {
      const config = parseJsonObject(idpConfigJson, "Identity configuration");
      const secrets = parseJsonObject(idpSecretsJson, "Identity secrets");
      await upsertAuthIdentityProviderConfig(session, idpProvider, {
        tenant_id: selectedTenant,
        enabled: idpEnabled,
        config,
        secrets
      });
      onToast("Identity provider configuration saved.");
      await loadIdpConfig();
    } catch (error) {
      onToast(`Identity provider save failed: ${errMsg(error)}`);
    } finally {
      setIdpSaving(false);
    }
  }, [idpConfigJson, idpEnabled, idpProvider, idpSecretsJson, loadIdpConfig, onToast, selectedTenant, session]);

  const testIdpConfig = useCallback(async () => {
    if (!session?.token) {
      return;
    }
    setIdpTesting(true);
    try {
      const config = parseJsonObject(idpConfigJson, "Identity configuration");
      const secrets = parseJsonObject(idpSecretsJson, "Identity secrets");
      await testAuthIdentityProviderConfig(session, idpProvider, {
        tenant_id: selectedTenant,
        enabled: idpEnabled,
        config,
        secrets
      });
      onToast("Identity provider connectivity test passed.");
    } catch (error) {
      onToast(`Identity provider test failed: ${errMsg(error)}`);
    } finally {
      setIdpTesting(false);
    }
  }, [idpConfigJson, idpEnabled, idpProvider, idpSecretsJson, onToast, selectedTenant, session]);

  const discoverIdpUsers = useCallback(async () => {
    if (!session?.token) {
      return;
    }
    setIdpUsersLoading(true);
    try {
      const rows = await listAuthIdentityProviderUsers(session, idpProvider, {
        tenant_id: selectedTenant,
        query: idpQuery,
        limit: 100
      });
      setIdpUsers(Array.isArray(rows) ? rows : []);
      setIdpSelectedUserIDs([]);
      onToast("Directory users fetched.");
    } catch (error) {
      onToast(`Directory user lookup failed: ${errMsg(error)}`);
    } finally {
      setIdpUsersLoading(false);
    }
  }, [idpProvider, idpQuery, onToast, selectedTenant, session]);

  const discoverIdpGroups = useCallback(async () => {
    if (!session?.token) {
      return;
    }
    setIdpGroupsLoading(true);
    try {
      const rows = await listAuthIdentityProviderGroups(session, idpProvider, {
        tenant_id: selectedTenant,
        query: idpQuery,
        limit: 100
      });
      setIdpGroups(Array.isArray(rows) ? rows : []);
      onToast("Directory groups fetched.");
    } catch (error) {
      onToast(`Directory group lookup failed: ${errMsg(error)}`);
    } finally {
      setIdpGroupsLoading(false);
    }
  }, [idpProvider, idpQuery, onToast, selectedTenant, session]);

  const discoverIdpMembers = useCallback(async () => {
    if (!session?.token || !String(idpSelectedGroupID || "").trim()) {
      return;
    }
    setIdpMembersLoading(true);
    try {
      const rows = await listAuthIdentityProviderGroupMembers(session, idpProvider, idpSelectedGroupID, {
        tenant_id: selectedTenant,
        limit: 500
      });
      const normalized = Array.isArray(rows) ? rows : [];
      setIdpMembers(normalized);
      setIdpSelectedUserIDs(normalized.map((item) => String(item.external_id || "").trim()).filter(Boolean));
      onToast("Group members fetched.");
    } catch (error) {
      onToast(`Group member lookup failed: ${errMsg(error)}`);
    } finally {
      setIdpMembersLoading(false);
    }
  }, [idpProvider, idpSelectedGroupID, onToast, selectedTenant, session]);

  const toggleIdpUserSelection = useCallback((externalID: string) => {
    const id = String(externalID || "").trim();
    if (!id) {
      return;
    }
    setIdpSelectedUserIDs((prev) => (prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]));
  }, []);

  const importIdpUsers = useCallback(async () => {
    if (!session?.token) {
      return;
    }
    const pool = (idpMembers.length ? idpMembers : idpUsers).filter((row) => idpSelectedUserIDs.includes(String(row.external_id || "").trim()));
    if (!pool.length) {
      onToast("Select directory users to import.");
      return;
    }
    setIdpImporting(true);
    try {
      await importAuthIdentityUsers(session, {
        tenant_id: selectedTenant,
        provider: idpProvider,
        group_id: String(idpSelectedGroupID || "").trim(),
        role: idpImportRole,
        status: idpImportStatus,
        must_change_password: idpImportMustChange,
        users: pool
      });
      onToast("Directory users imported.");
      await loadUsers();
    } catch (error) {
      onToast(`Directory import failed: ${errMsg(error)}`);
    } finally {
      setIdpImporting(false);
    }
  }, [
    idpImportMustChange,
    idpImportRole,
    idpImportStatus,
    idpMembers,
    idpProvider,
    idpSelectedGroupID,
    idpSelectedUserIDs,
    idpUsers,
    loadUsers,
    onToast,
    selectedTenant,
    session
  ]);

  useEffect(() => {
    void loadTenants();
    void loadPolicies();
  }, [loadPolicies, loadTenants]);

  useEffect(() => {
    void loadUsers();
  }, [loadUsers]);

  useEffect(() => {
    void loadIdpConfig();
  }, [loadIdpConfig]);

  const usersByStatus = useMemo(() => {
    const active = users.filter((user) => String(user.status || "").toLowerCase() === "active").length;
    const disabled = users.filter((user) => String(user.status || "").toLowerCase() !== "active").length;
    return { active, disabled };
  }, [users]);

  return {
    tenants,
    selectedTenant,
    setSelectedTenant,
    users,
    bindings,
    passwordPolicy,
    setPasswordPolicy,
    securityPolicy,
    setSecurityPolicy,
    loading,
    savingPolicy,
    createBusy,
    updateBusy,
    bindingBusy,
    newUsername,
    setNewUsername,
    newEmail,
    setNewEmail,
    newPassword,
    setNewPassword,
    newRole,
    setNewRole,
    newStatus,
    setNewStatus,
    resetUserID,
    setResetUserID,
    resetPasswordValue,
    setResetPasswordValue,
    resetMustChange,
    setResetMustChange,
    groupID,
    setGroupID,
    groupRole,
    setGroupRole,
    idpProvider,
    setIdpProvider,
    idpEnabled,
    setIdpEnabled,
    idpConfigJson,
    setIdpConfigJson,
    idpSecretsJson,
    setIdpSecretsJson,
    idpSaving,
    idpTesting,
    idpUsersLoading,
    idpGroupsLoading,
    idpMembersLoading,
    idpImporting,
    idpQuery,
    setIdpQuery,
    idpSelectedGroupID,
    setIdpSelectedGroupID,
    idpUsers,
    idpGroups,
    idpMembers,
    idpSelectedUserIDs,
    idpImportRole,
    setIdpImportRole,
    idpImportStatus,
    setIdpImportStatus,
    idpImportMustChange,
    setIdpImportMustChange,
    usersByStatus,
    loadUsers,
    createUser,
    updateRole,
    updateStatus,
    resetPassword,
    savePolicies,
    upsertBinding,
    removeBinding,
    loadIdpConfig,
    saveIdpConfig,
    testIdpConfig,
    discoverIdpUsers,
    discoverIdpGroups,
    discoverIdpMembers,
    toggleIdpUserSelection,
    importIdpUsers
  };
}
