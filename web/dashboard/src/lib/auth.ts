import { trackedFetch } from "./serviceApi";

export type UIAuthConfig = {
  tenant_id: string;
  admin_username: string;
  admin_password: string;
  force_password_change: boolean;
  prefer_backend_auth: boolean;
  allow_local_fallback: boolean;
};

export type AuthSession = {
  tenantId: string;
  username: string;
  token: string;
  mode: "backend" | "local";
  mustChangePassword: boolean;
  role?: string | undefined;
  permissions?: string[] | undefined;
  idleTimeoutMinutes?: number | undefined;
  expiresAt?: string | undefined;
};

const defaultUIAuth: UIAuthConfig = {
  tenant_id: "root",
  admin_username: "admin",
  admin_password: "",
  force_password_change: true,
  prefer_backend_auth: true,
  allow_local_fallback: false
};

const AUTH_CONFIG_URL = "/config/ui-auth.json";
const CHANGED_PASS_KEY = "vecta_ui_password_changed";
const SESSION_KEY = "vecta_ui_session";

// In-memory session cache — primary store; localStorage is write-through
// for page-refresh persistence only. Reduces XSS read-surface.
let _sessionCache: AuthSession | null = null;

// In-memory only — never persisted to localStorage
let _localAdminPassword: string | null = null;

// Session hardening: logout flag prevents refresh race from restoring a cleared session
let _loggedOut = false;
let _refreshAbortController: AbortController | null = null;

export function isLoggedOut(): boolean {
  return _loggedOut;
}

export function resetLogoutFlag(): void {
  _loggedOut = false;
}

export function getRefreshAbortSignal(): AbortSignal {
  _refreshAbortController = new AbortController();
  return _refreshAbortController.signal;
}

export function abortPendingRefresh(): void {
  if (_refreshAbortController) {
    _refreshAbortController.abort();
    _refreshAbortController = null;
  }
}

export async function loadUIAuthConfig(): Promise<UIAuthConfig> {
  try {
    const response = await trackedFetch(AUTH_CONFIG_URL, { cache: "no-store" });
    if (!response.ok) {
      return defaultUIAuth;
    }
    const parsed = (await response.json()) as Partial<UIAuthConfig>;
    return {
      tenant_id: parsed.tenant_id ?? defaultUIAuth.tenant_id,
      admin_username: parsed.admin_username ?? defaultUIAuth.admin_username,
      admin_password: parsed.admin_password ?? defaultUIAuth.admin_password,
      force_password_change: parsed.force_password_change ?? defaultUIAuth.force_password_change,
      prefer_backend_auth: parsed.prefer_backend_auth ?? defaultUIAuth.prefer_backend_auth,
      allow_local_fallback: parsed.allow_local_fallback ?? defaultUIAuth.allow_local_fallback
    };
  } catch {
    return defaultUIAuth;
  }
}

export function getSession(): AuthSession | null {
  try {
    if (_loggedOut) return null;
    // Return in-memory cache first to avoid redundant localStorage reads
    if (_sessionCache) return _sessionCache;
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as AuthSession;
    if (!parsed?.token || !parsed?.username) {
      return null;
    }
    // Reject expired tokens
    const expiresAt = String(parsed.expiresAt || "").trim();
    if (expiresAt) {
      const expMs = new Date(expiresAt).getTime();
      if (Number.isFinite(expMs) && expMs <= Date.now()) {
        sessionStorage.removeItem(SESSION_KEY);
        return null;
      }
    }
    const session = {
      ...parsed,
      mustChangePassword: Boolean(parsed.mustChangePassword),
      role: String(parsed.role || "").trim() || undefined,
      permissions: normalizePermissionList(parsed.permissions),
      idleTimeoutMinutes:
        Number.isFinite(Number(parsed.idleTimeoutMinutes)) && Number(parsed.idleTimeoutMinutes) > 0
          ? Math.trunc(Number(parsed.idleTimeoutMinutes))
          : undefined,
      expiresAt: expiresAt || undefined
    };
    _sessionCache = session;
    return session;
  } catch {
    return null;
  }
}

export function saveSession(session: AuthSession): void {
  if (_loggedOut) return;
  _sessionCache = session;
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function clearSession(): void {
  _loggedOut = true;
  _sessionCache = null;
  _localAdminPassword = null;
  // Clear session from sessionStorage (tab-scoped — cleared on tab close)
  sessionStorage.removeItem(SESSION_KEY);
  // Clear remaining auth artifacts from localStorage
  [CHANGED_PASS_KEY, "vecta_pinned_tabs", "vecta_key_table_columns", "vecta_system_admin_open_cli"]
    .forEach((k) => localStorage.removeItem(k));
}

export async function logoutSession(session: AuthSession): Promise<void> {
  if (!session || session.mode !== "backend") return;
  try {
    await trackedFetch("/auth/logout", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${session.token}`
      }
    });
  } catch {
    // Best-effort — don't block UI logout on network failure
  }
}

export function mustForcePasswordChange(config: UIAuthConfig): boolean {
  if (!config.force_password_change) {
    return false;
  }
  return localStorage.getItem(CHANGED_PASS_KEY) !== "true";
}

export function markPasswordChanged(): void {
  localStorage.setItem(CHANGED_PASS_KEY, "true");
}

export function updateLocalAdminPassword(password: string): void {
  // Stored in memory only — never written to localStorage to avoid
  // plaintext credential exposure to XSS attacks.
  _localAdminPassword = password;
}

function effectiveLocalPassword(config: UIAuthConfig): string {
  return _localAdminPassword ?? config.admin_password;
}

export async function login(
  username: string,
  password: string,
  config: UIAuthConfig,
  tenantOverride?: string
): Promise<AuthSession> {
  const tenantId = String(tenantOverride || config.tenant_id || "").trim() || config.tenant_id;
  if (config.prefer_backend_auth) {
    try {
      const response = await trackedFetch("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_id: tenantId,
          username,
          password
        })
      });
      if (response.ok) {
        const data = (await response.json()) as {
          access_token?: string;
          must_change_password?: boolean;
          security_policy?: { idle_timeout_minutes?: number };
          expires_at?: string;
        };
        if (data.access_token) {
          const authz = deriveSessionAuthFromToken(data.access_token);
          const idleTimeoutMinutes = Number(data.security_policy?.idle_timeout_minutes || 0);
          return {
            tenantId,
            username,
            token: data.access_token,
            mode: "backend",
            mustChangePassword: Boolean(data.must_change_password),
            role: authz.role,
            permissions: authz.permissions,
            idleTimeoutMinutes: Number.isFinite(idleTimeoutMinutes) && idleTimeoutMinutes > 0 ? Math.trunc(idleTimeoutMinutes) : undefined,
            expiresAt: String(data.expires_at || "").trim() || undefined
          };
        }
      }
      const payload = (await response.json().catch(() => ({}))) as { error?: { message?: string } };
      const backendError = readErrorMessage(payload, "Authentication failed");
      if (!config.allow_local_fallback) {
        throw new Error(backendError);
      }
    } catch (error) {
      if (!config.allow_local_fallback) {
        if (error instanceof Error) {
          throw error;
        }
        throw new Error("Authentication failed");
      }
      // fallback allowed below
    }
  }

  if (!config.allow_local_fallback) {
    throw new Error("Authentication failed");
  }
  if (username !== config.admin_username || password !== effectiveLocalPassword(config)) {
    throw new Error("Invalid username or password");
  }
  return {
    tenantId,
    username,
    token: `local-${Date.now()}`,
    mode: "local",
    mustChangePassword: mustForcePasswordChange(config),
    role: "admin",
    permissions: ["*"],
    idleTimeoutMinutes: undefined
  };
}

function readErrorMessage(data: unknown, fallback: string): string {
  if (typeof data !== "object" || data === null) {
    return fallback;
  }
  const error = (data as { error?: { message?: string } }).error;
  if (error?.message) {
    return error.message;
  }
  return fallback;
}

export async function changePassword(
  session: AuthSession,
  currentPassword: string,
  newPassword: string,
  config: UIAuthConfig
): Promise<AuthSession> {
  if (newPassword.length < 12) {
    throw new Error("New password must be at least 12 characters");
  }
  if (session.mode === "backend") {
    const response = await trackedFetch("/auth/change-password", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${session.token}`
      },
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword
      })
    });
    const payload = (await response.json().catch(() => ({}))) as {
      access_token?: string;
      must_change_password?: boolean;
      expires_at?: string;
      error?: { message?: string };
    };
    if (!response.ok) {
      throw new Error(readErrorMessage(payload, "Password update failed"));
    }
    const nextToken = String(payload.access_token || session.token);
    const authz = deriveSessionAuthFromToken(nextToken, session);
    return {
      ...session,
      token: nextToken,
      mustChangePassword: Boolean(payload.must_change_password),
      role: authz.role,
      permissions: authz.permissions,
      expiresAt: String(payload.expires_at || "").trim() || session.expiresAt
    };
  }

  updateLocalAdminPassword(newPassword);
  if (config.force_password_change) {
    markPasswordChanged();
  }
  return {
    ...session,
    mustChangePassword: false
  };
}

export async function refreshSession(session: AuthSession, signal?: AbortSignal): Promise<AuthSession> {
  if (_loggedOut) throw new Error("Session logged out");
  if (!session || session.mode !== "backend") {
    return session;
  }
  const response = await trackedFetch("/auth/refresh", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${session.token}`
    },
    signal: signal ?? null
  });
  if (_loggedOut) throw new Error("Session logged out");
  const payload = (await response.json().catch(() => ({}))) as {
    access_token?: string;
    expires_at?: string;
    error?: { message?: string };
  };
  if (!response.ok) {
    throw new Error(readErrorMessage(payload, "Session refresh failed"));
  }
  const nextToken = String(payload.access_token || session.token);
  const authz = deriveSessionAuthFromToken(nextToken, session);
  return {
    ...session,
    token: nextToken,
    role: authz.role,
    permissions: authz.permissions,
    expiresAt: String(payload.expires_at || "").trim() || session.expiresAt
  };
}

type TokenClaims = {
  role?: unknown;
  permissions?: unknown;
};

function normalizePermissionList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const dedup = new Set<string>();
  value.forEach((item) => {
    const token = String(item || "").trim();
    if (!token) {
      return;
    }
    dedup.add(token);
  });
  return Array.from(dedup);
}

function decodeTokenClaims(token: string): TokenClaims | null {
  const raw = String(token || "").trim();
  if (!raw) {
    return null;
  }
  const parts = raw.split(".");
  if (parts.length < 2) {
    return null;
  }
  try {
    const payload = (parts[1] || "").replace(/-/g, "+").replace(/_/g, "/");
    const padded = payload.padEnd(Math.ceil(payload.length / 4) * 4, "=");
    const json = atob(padded);
    const parsed = JSON.parse(json) as TokenClaims;
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function deriveSessionAuthFromToken(
  token: string,
  fallback?: Pick<AuthSession, "role" | "permissions">
): Pick<AuthSession, "role" | "permissions"> {
  const claims = decodeTokenClaims(token);
  const role = String(claims?.role || fallback?.role || "").trim() || undefined;
  const nextPermissions = normalizePermissionList(claims?.permissions);
  const permissions = nextPermissions.length ? nextPermissions : normalizePermissionList(fallback?.permissions);
  return {
    role,
    permissions
  };
}

// --- SSO callback helpers ---

export type SSOParams = {
  provider: string;
  token: string;
  tenantId: string;
};

export function extractSSOParams(): SSOParams | null {
  const params = new URLSearchParams(window.location.search);
  const provider = params.get("sso_provider");
  const token = params.get("sso_token");
  const tenantId = params.get("sso_tenant");
  if (!provider || !token || !tenantId) return null;
  // Clean SSO params from URL
  params.delete("sso_provider");
  params.delete("sso_token");
  params.delete("sso_tenant");
  const remaining = params.toString();
  const cleanURL = window.location.pathname + (remaining ? `?${remaining}` : "");
  window.history.replaceState({}, "", cleanURL);
  return { provider, token, tenantId };
}

export function createSSOSession(ssoParams: SSOParams): AuthSession {
  const authz = deriveSessionAuthFromToken(ssoParams.token);
  const claims = decodeTokenClaims(ssoParams.token);
  const username = String((claims as Record<string, unknown>)?.user_id || ssoParams.provider).trim();
  return {
    tenantId: ssoParams.tenantId,
    username,
    token: ssoParams.token,
    mode: "backend",
    mustChangePassword: false,
    role: authz.role,
    permissions: authz.permissions,
    idleTimeoutMinutes: undefined,
    expiresAt: undefined
  };
}
