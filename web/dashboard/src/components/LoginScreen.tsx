import { ArrowRight, Check, Info, KeyRound, Lock, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { AuthSession, UIAuthConfig } from "../lib/auth";
import { changePassword, login } from "../lib/auth";
import type { SSOProviderInfo } from "../lib/authAdmin";
import { getSSOLoginURL, listSSOProviders } from "../lib/authAdmin";

/* ────────────────────────────────────────────────────────────────────
   Static brand mark — shield + keyhole. No animation; a single subtle
   gradient stroke for depth ("better graphics" without motion).
   ──────────────────────────────────────────────────────────────────── */

function BrandMark({ size = 56 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <defs>
        <linearGradient id="vk-shield" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="var(--s-accent)" />
          <stop offset="100%" stopColor="var(--s-purple)" />
        </linearGradient>
      </defs>
      {/* Shield body */}
      <path
        d="M32 6 L54 15 L54 33 C54 46 44 55 32 59 C20 55 10 46 10 33 L10 15 Z"
        fill="var(--s-accent-dim)"
        stroke="url(#vk-shield)"
        strokeWidth="2.5"
        strokeLinejoin="round"
      />
      {/* Keyhole */}
      <circle cx="32" cy="29" r="7" fill="none" stroke="var(--s-accent)" strokeWidth="2.5" />
      <path
        d="M32 35 L32 44"
        stroke="var(--s-accent)"
        strokeWidth="3"
        strokeLinecap="round"
      />
    </svg>
  );
}

/* ────────────────────────────────────────────────────────────────────
   Simple labelled input (no floating-label motion)
   ──────────────────────────────────────────────────────────────────── */

function Field(props: {
  id?: string;
  value: string;
  onChange: (v: string) => void;
  label?: string;
  placeholder?: string;
  type?: "text" | "password";
  autoComplete?: string;
}) {
  const { id, value, onChange, label, placeholder, type = "text", autoComplete } = props;
  return (
    <label className="block space-y-1.5">
      {label && (
        <span className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
          {label}
        </span>
      )}
      <input
        id={id}
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        autoComplete={autoComplete}
        className="w-full rounded-lg border border-cyber-border bg-cyber-panel/60 px-3.5 py-2.5 text-sm text-cyber-text outline-none transition-colors duration-150 placeholder:text-cyber-muted/40 focus:border-cyber-accent/60 focus:shadow-[0_0_0_3px_var(--s-accent-dim)]"
      />
    </label>
  );
}

/* ────────────────────────────────────────────────────────────────────
   Password Policy Checklist
   ──────────────────────────────────────────────────────────────────── */

type PolicyChecks = {
  minLength: boolean;
  hasUpper: boolean;
  hasLower: boolean;
  hasDigit: boolean;
  hasSpecial: boolean;
  noWhitespace: boolean;
  matchesConfirm: boolean;
};

const POLICY_RULES: { key: keyof PolicyChecks; label: string }[] = [
  { key: "minLength",     label: "At least 12 characters" },
  { key: "hasUpper",      label: "One uppercase letter (A–Z)" },
  { key: "hasLower",      label: "One lowercase letter (a–z)" },
  { key: "hasDigit",      label: "One digit (0–9)" },
  { key: "hasSpecial",    label: "One special character (!@#$...)" },
  { key: "noWhitespace",  label: "No spaces or whitespace" },
];

function PasswordPolicyChecklist({ checks }: { checks: PolicyChecks }) {
  return (
    <div className="rounded-lg border border-cyber-border bg-cyber-elevated/60 p-3">
      <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-cyber-muted">
        Password Requirements
      </p>
      <ul className="space-y-1">
        {POLICY_RULES.map(({ key, label }) => {
          const passed = checks[key];
          return (
            <li key={key} className="flex items-center gap-2 text-xs">
              {passed ? (
                <Check size={12} className="shrink-0 text-emerald-400" />
              ) : (
                <X size={12} className="shrink-0 text-cyber-muted/50" />
              )}
              <span className={passed ? "text-emerald-400" : "text-cyber-muted"}>{label}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
   Login Screen — centered minimal card
   ──────────────────────────────────────────────────────────────────── */

type LoginScreenProps = {
  config: UIAuthConfig;
  onAuthenticated: (session: AuthSession) => void;
};

export function LoginScreen(props: LoginScreenProps) {
  const { config, onAuthenticated } = props;
  const ROOT_TENANT_ID = "root";
  const [username, setUsername] = useState(config.admin_username);
  const [password, setPassword] = useState(config.admin_password);
  const [useRootTenant, setUseRootTenant] = useState(true);
  const [tenantInput, setTenantInput] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [authError, setAuthError] = useState<string | null>(null);
  const [session, setSession] = useState<AuthSession | null>(null);
  const [loading, setLoading] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);
  const [showPolicyHint, setShowPolicyHint] = useState(false);
  const [ssoProviders, setSsoProviders] = useState<SSOProviderInfo[]>([]);
  const [ssoLoading, setSsoLoading] = useState<string | null>(null);

  // Fetch SSO providers when tenant changes
  const activeTenantId = useRootTenant ? ROOT_TENANT_ID : tenantInput.trim();
  useEffect(() => {
    if (!activeTenantId) {
      setSsoProviders([]);
      return;
    }
    let cancelled = false;
    listSSOProviders(activeTenantId)
      .then((providers) => {
        if (!cancelled) setSsoProviders(providers);
      })
      .catch(() => {
        if (!cancelled) setSsoProviders([]);
      });
    return () => {
      cancelled = true;
    };
  }, [activeTenantId]);

  const handleSSOLogin = async (provider: string) => {
    if (!activeTenantId) {
      setAuthError("Tenant is required for SSO login.");
      return;
    }
    setSsoLoading(provider);
    setAuthError(null);
    try {
      const redirectURL = await getSSOLoginURL(provider, activeTenantId);
      // Validate redirect URL to prevent open redirect attacks
      try {
        const parsed = new URL(redirectURL);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
          throw new Error('Invalid redirect URL protocol');
        }
        window.location.href = redirectURL;
      } catch {
        setAuthError('SSO redirect URL is invalid');
        setSsoLoading(null);
      }
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "SSO login failed");
      setSsoLoading(null);
    }
  };

  const passwordChecks = useMemo(() => {
    const pw = newPassword;
    return {
      minLength:      pw.length >= 12,
      hasUpper:       /[A-Z]/.test(pw),
      hasLower:       /[a-z]/.test(pw),
      hasDigit:       /\d/.test(pw),
      hasSpecial:     /[^A-Za-z0-9\s]/.test(pw),
      noWhitespace:   !/\s/.test(pw),
      matchesConfirm: pw.length > 0 && pw === confirmPassword,
    };
  }, [newPassword, confirmPassword]);

  const allChecksPassed = useMemo(
    () => Object.values(passwordChecks).every(Boolean),
    [passwordChecks]
  );

  const canChangePassword = allChecksPassed;

  const handleLogin = async () => {
    const tenantId = useRootTenant ? ROOT_TENANT_ID : tenantInput.trim();
    if (!tenantId) {
      setAuthError("Tenant name is required when root tenant is not selected.");
      return;
    }
    // Tenant ID format validation: alphanumeric, hyphens, underscores, max 64 chars
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(tenantId)) {
      setAuthError("Tenant ID must be 1-64 characters and contain only letters, digits, hyphens, or underscores.");
      return;
    }
    if (!username.trim()) {
      setAuthError("Username is required.");
      return;
    }
    if (!password) {
      setAuthError("Password is required.");
      return;
    }
    setLoading(true);
    setAuthError(null);
    try {
      const next = await login(username.trim(), password, config, tenantId);
      if (next.mustChangePassword) {
        setSession(next);
      } else {
        onAuthenticated(next);
      }
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Authentication failed");
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordChange = async () => {
    if (!session || !canChangePassword) return;
    setSavingPassword(true);
    setAuthError(null);
    try {
      const updated = await changePassword(session, password, newPassword, config);
      onAuthenticated(updated);
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Password update failed");
    } finally {
      setSavingPassword(false);
    }
  };

  // Submit on Enter from any field in the login form
  const onFormKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== "Enter") return;
    e.preventDefault();
    if (session) {
      if (canChangePassword && !savingPassword) handlePasswordChange();
    } else if (!loading) {
      handleLogin();
    }
  };

  return (
    <main
      className="relative flex min-h-screen items-center justify-center px-4 py-10"
      style={{
        background:
          "radial-gradient(ellipse 70% 55% at 50% 0%, var(--s-accent-dim) 0%, transparent 60%), var(--c-bg)",
      }}
    >
      <section
        onKeyDown={onFormKeyDown}
        className="w-full max-w-[420px] animate-fadeIn rounded-2xl border border-cyber-border bg-cyber-card p-8 shadow-lg"
      >
        {/* Brand */}
        <div className="mb-7 flex flex-col items-center text-center">
          <BrandMark />
          <h1 className="mt-3 font-heading text-2xl font-bold tracking-widest text-cyber-text">
            Vecta KMS
          </h1>
          <p className="mt-1 text-[10px] font-semibold uppercase tracking-[0.28em] text-cyber-accent">
            Enterprise Key Management
          </p>
        </div>

        <h2 className="mb-1 text-center font-heading text-base font-semibold text-cyber-text">
          {session ? "Set a new password" : "Sign in"}
        </h2>
        <p className="mb-6 text-center text-xs text-cyber-muted">
          {session
            ? "A new administrator password is required before dashboard access."
            : "Authenticate with tenant administrator credentials."}
        </p>

        {!session ? (
          <div className="space-y-4">
            {/* Tenant selector */}
            <div className="rounded-lg border border-cyber-border bg-cyber-panel/40 p-3">
              <label className="flex cursor-pointer items-center gap-2.5 text-sm text-cyber-text">
                <input
                  type="checkbox"
                  checked={useRootTenant}
                  onChange={(e) => setUseRootTenant(e.target.checked)}
                  className="h-4 w-4 rounded border-cyber-border bg-cyber-panel accent-cyber-accent"
                />
                <span>
                  Use root tenant{" "}
                  <code className="ml-1 rounded bg-cyber-accent/10 px-1.5 py-0.5 text-[11px] text-cyber-accent">
                    {ROOT_TENANT_ID}
                  </code>
                </span>
              </label>
              {!useRootTenant && (
                <div className="mt-3">
                  <Field
                    value={tenantInput}
                    onChange={setTenantInput}
                    placeholder="Enter tenant ID"
                    autoComplete="organization"
                  />
                </div>
              )}
            </div>

            <Field
              id="login-username"
              value={username}
              onChange={setUsername}
              label="Username"
              placeholder="administrator"
              autoComplete="username"
            />
            <Field
              id="login-password"
              value={password}
              onChange={setPassword}
              label="Password"
              type="password"
              placeholder="••••••••••••"
              autoComplete="current-password"
            />

            {authError && (
              <div className="flex items-start gap-2.5 rounded-lg border border-red-500/25 bg-red-500/[0.08] px-3.5 py-2.5 text-sm text-red-400">
                <X size={14} className="mt-0.5 shrink-0" />
                <span>{authError}</span>
              </div>
            )}

            <button
              type="button"
              onClick={handleLogin}
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-cyber-accent py-2.5 text-sm font-bold tracking-wide text-cyber-bg transition-opacity duration-150 hover:opacity-90 disabled:opacity-60"
            >
              {loading ? (
                <>
                  <span className="h-4 w-4 animate-spin rounded-full border-2 border-cyber-bg/30 border-t-cyber-bg" />
                  Authenticating…
                </>
              ) : (
                <>
                  Sign In
                  <ArrowRight size={15} />
                </>
              )}
            </button>

            <p className="text-center text-[10px] text-cyber-muted/60">
              Default admin: <strong className="text-cyber-muted">{config.admin_username}</strong>.
              Password configured in{" "}
              <code className="rounded bg-cyber-accent/10 px-1 text-cyber-accent/70">ui-auth.json</code>.
            </p>

            {/* SSO providers */}
            {ssoProviders.length > 0 && (
              <div className="space-y-3 pt-1">
                <div className="flex items-center gap-3">
                  <div className="h-px flex-1 bg-cyber-border" />
                  <span className="text-[10px] font-medium uppercase tracking-wider text-cyber-muted/60">
                    or sign in with
                  </span>
                  <div className="h-px flex-1 bg-cyber-border" />
                </div>
                {ssoProviders.map((sp) => (
                  <button
                    key={sp.provider}
                    type="button"
                    onClick={() => handleSSOLogin(sp.provider)}
                    disabled={ssoLoading === sp.provider}
                    className="w-full rounded-lg border border-cyber-border bg-cyber-panel/40 px-4 py-2.5 text-sm font-medium text-cyber-text transition-colors duration-150 hover:border-cyber-accent/40 hover:bg-cyber-accent/[0.06] disabled:opacity-60"
                  >
                    {ssoLoading === sp.provider ? "Redirecting…" : sp.display_name}
                  </button>
                ))}
              </div>
            )}
          </div>
        ) : (
          /* ── Password change view ── */
          <div className="space-y-4">
            <div
              className="rounded-lg border p-3.5 text-sm"
              style={{
                background: "var(--s-amber-dim, rgba(246,186,58,0.08))",
                borderColor: "rgba(246,186,58,0.3)",
                color: "#f6ba3a",
              }}
            >
              <div className="mb-1 flex items-center gap-2 font-semibold">
                <KeyRound size={14} />
                Password Rotation Required
              </div>
              <span className="text-xs opacity-80">
                First-login security policy blocks dashboard access until the temporary admin password is changed.
              </span>
            </div>

            <label className="block space-y-1.5">
              <span className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
                New Password
                <button
                  type="button"
                  onClick={() => setShowPolicyHint((v) => !v)}
                  className="text-cyber-accent transition-colors hover:text-cyber-accent/80"
                  title="Password requirements"
                >
                  <Info size={14} />
                </button>
              </span>
              <Field value={newPassword} onChange={setNewPassword} placeholder="Enter new password" type="password" autoComplete="new-password" />
            </label>

            {showPolicyHint && <PasswordPolicyChecklist checks={passwordChecks} />}
            {!showPolicyHint && newPassword.length > 0 && !allChecksPassed && (
              <PasswordPolicyChecklist checks={passwordChecks} />
            )}

            <Field value={confirmPassword} onChange={setConfirmPassword} label="Confirm Password" placeholder="Repeat password" type="password" autoComplete="new-password" />

            {confirmPassword.length > 0 && !passwordChecks.matchesConfirm && (
              <p className="flex items-center gap-1.5 text-xs text-red-400">
                <X size={12} /> Passwords do not match
              </p>
            )}

            {authError && (
              <div className="flex items-start gap-2.5 rounded-lg border border-red-500/25 bg-red-500/[0.08] px-3.5 py-2.5 text-sm text-red-400">
                <X size={14} className="mt-0.5 shrink-0" />
                <span>{authError}</span>
              </div>
            )}

            <button
              type="button"
              onClick={handlePasswordChange}
              disabled={!canChangePassword || savingPassword}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-cyber-accent py-2.5 text-sm font-bold tracking-wide text-cyber-bg transition-opacity duration-150 hover:opacity-90 disabled:opacity-60"
            >
              {savingPassword ? (
                <>
                  <span className="h-4 w-4 animate-spin rounded-full border-2 border-cyber-bg/30 border-t-cyber-bg" />
                  Applying…
                </>
              ) : (
                <>
                  Update Password and Continue
                  <ArrowRight size={15} />
                </>
              )}
            </button>
          </div>
        )}

        {/* Footer */}
        <div className="mt-7 flex items-center justify-center gap-2 border-t border-cyber-border pt-5 text-center">
          <Lock size={10} className="text-cyber-muted/40" />
          <p className="text-[10px] text-cyber-muted/40">
            256-bit AES-GCM &nbsp;&middot;&nbsp; FIPS 140-3 &nbsp;&middot;&nbsp; TLS 1.3
          </p>
        </div>
      </section>
    </main>
  );
}
