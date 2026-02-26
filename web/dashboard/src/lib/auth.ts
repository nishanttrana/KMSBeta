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
  role?: string;
  permissions?: string[];
  idleTimeoutMinutes?: number;
  expiresAt?: string;
};

const defaultUIAuth: UIAuthConfig = {
  tenant_id: "root",
  admin_username: "admin",
  admin_password: "VectaAdmin@2026",
  force_password_change: true,
  prefer_backend_auth: true,
  allow_local_fallback: false
};

const AUTH_CONFIG_URL = "/config/ui-auth.json";
const LOCAL_PASS_KEY = "vecta_ui_local_admin_password";
const CHANGED_PASS_KEY = "vecta_ui_password_changed";
const SESSION_KEY = "vecta_ui_session";

export async function loadUIAuthConfig(): Promise<UIAuthConfig> {
  try {
    const response = await fetch(AUTH_CONFIG_URL, { cache: "no-store" });
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
    const raw = localStorage.getItem(SESSION_KEY);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as AuthSession;
    if (!parsed?.token || !parsed?.username) {
      return null;
    }
    return {
      ...parsed,
      mustChangePassword: Boolean(parsed.mustChangePassword),
      role: String(parsed.role || "").trim() || undefined,
      permissions: normalizePermissionList(parsed.permissions),
      idleTimeoutMinutes:
        Number.isFinite(Number(parsed.idleTimeoutMinutes)) && Number(parsed.idleTimeoutMinutes) > 0
          ? Math.trunc(Number(parsed.idleTimeoutMinutes))
          : undefined,
      expiresAt: String(parsed.expiresAt || "").trim() || undefined
    };
  } catch {
    return null;
  }
}

export function saveSession(session: AuthSession): void {
  localStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function clearSession(): void {
  localStorage.removeItem(SESSION_KEY);
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
  localStorage.setItem(LOCAL_PASS_KEY, password);
}

function effectiveLocalPassword(config: UIAuthConfig): string {
  return localStorage.getItem(LOCAL_PASS_KEY) ?? config.admin_password;
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
      const response = await fetch("/auth/login", {
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
    const response = await fetch("/auth/change-password", {
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

export async function refreshSession(session: AuthSession): Promise<AuthSession> {
  if (!session || session.mode !== "backend") {
    return session;
  }
  const response = await fetch("/auth/refresh", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${session.token}`
    }
  });
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
    const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
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
