import { Check, Info, KeyRound, Lock, ShieldCheck, UserRound, X, Zap } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { AuthSession, UIAuthConfig } from "../lib/auth";
import { changePassword, login } from "../lib/auth";
import type { SSOProviderInfo } from "../lib/authAdmin";
import { getSSOLoginURL, listSSOProviders } from "../lib/authAdmin";

/* ────────────────────────────────────────────────────────────────────
   Animated Network Grid — circuit-board-like grid with glowing data
   packets traveling along paths. Pure SVG + CSS animations.
   ──────────────────────────────────────────────────────────────────── */

const GRID_H = [80, 160, 240, 320, 400];
const GRID_V = [60, 120, 180, 240, 300, 360, 420, 480, 540];

const NODES: [number, number][] = [
  [120, 80], [300, 80], [480, 80],
  [60, 160], [180, 160], [360, 160], [480, 160],
  [120, 240], [240, 240], [420, 240],
  [180, 320], [300, 320], [480, 320],
  [60, 400], [240, 400], [360, 400], [540, 400],
];

const HUBS: [number, number][] = [
  [300, 200], [180, 320], [420, 160], [120, 400],
];

const PACKETS = [
  { id: "p1", d: "M0,80 L120,80 L120,200 L300,200 L300,320 L500,320", dur: "10s", delay: "0s", color: "#06d6e0" },
  { id: "p2", d: "M600,120 L400,120 L400,240 L200,240 L200,400 L60,400", dur: "13s", delay: "2s", color: "#06d6e0" },
  { id: "p3", d: "M300,0 L300,80 L180,80 L180,280 L360,280 L360,500", dur: "9s", delay: "4s", color: "#a78bfa" },
  { id: "p4", d: "M0,320 L180,320 L180,160 L420,160 L420,400 L600,400", dur: "12s", delay: "1s", color: "#2dd4a0" },
  { id: "p5", d: "M480,0 L480,160 L360,160 L360,360 L120,360 L120,500", dur: "11s", delay: "3s", color: "#06d6e0" },
];

function NetworkGrid() {
  const reducedMotion =
    typeof window !== "undefined" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  return (
    <svg
      className="h-full w-full"
      viewBox="0 0 600 500"
      preserveAspectRatio="xMidYMid slice"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <defs>
        <filter id="pktGlow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <filter id="nodeGlow" x="-100%" y="-100%" width="300%" height="300%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="2" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <linearGradient id="gridFadeH" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="#1a2944" stopOpacity="0" />
          <stop offset="15%" stopColor="#1a2944" stopOpacity="0.4" />
          <stop offset="85%" stopColor="#1a2944" stopOpacity="0.4" />
          <stop offset="100%" stopColor="#1a2944" stopOpacity="0" />
        </linearGradient>
        <linearGradient id="gridFadeV" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#1a2944" stopOpacity="0" />
          <stop offset="15%" stopColor="#1a2944" stopOpacity="0.4" />
          <stop offset="85%" stopColor="#1a2944" stopOpacity="0.4" />
          <stop offset="100%" stopColor="#1a2944" stopOpacity="0" />
        </linearGradient>
        {PACKETS.map((p) => (
          <path key={p.id} id={p.id} d={p.d} fill="none" stroke="none" />
        ))}
      </defs>

      {/* Grid lines */}
      {GRID_H.map((y) => (
        <line key={`h${y}`} x1="0" y1={y} x2="600" y2={y} stroke="url(#gridFadeH)" strokeWidth="0.5" />
      ))}
      {GRID_V.map((x) => (
        <line key={`v${x}`} x1={x} y1="0" x2={x} y2="500" stroke="url(#gridFadeV)" strokeWidth="0.5" />
      ))}

      {/* Intersection nodes */}
      {NODES.map(([cx, cy], i) => (
        <circle key={`n${i}`} cx={cx} cy={cy} r="2" fill="#06d6e0" opacity="0.15" filter="url(#nodeGlow)" />
      ))}

      {/* Hub nodes with glow pulse */}
      {HUBS.map(([cx, cy], i) => (
        <circle
          key={`hub${i}`}
          cx={cx}
          cy={cy}
          r="4"
          fill="#06d6e0"
          opacity="0.3"
          filter="url(#nodeGlow)"
          style={reducedMotion ? undefined : { animation: `vecta-node-glow 3s ease-in-out ${i * 0.8}s infinite`, transformOrigin: `${cx}px ${cy}px` }}
        />
      ))}

      {/* Traveling data packets */}
      {!reducedMotion &&
        PACKETS.map((p, i) => (
          <circle key={`pkt${i}`} r="3" fill={p.color} filter="url(#pktGlow)">
            <animateMotion dur={p.dur} repeatCount="indefinite" begin={p.delay}>
              <mpath href={`#${p.id}`} />
            </animateMotion>
          </circle>
        ))}
    </svg>
  );
}

/* ────────────────────────────────────────────────────────────────────
   Feature Highlight Row
   ──────────────────────────────────────────────────────────────────── */

function FeatureHighlight({ icon: Icon, title, desc }: { icon: React.ComponentType<any>; title: string; desc: string }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-white/[0.06] bg-white/[0.03] p-3 backdrop-blur-sm transition-colors hover:bg-white/[0.05]">
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-cyber-accent/10 text-cyber-accent">
        <Icon size={16} />
      </div>
      <div>
        <p className="text-[13px] font-semibold text-cyber-text">{title}</p>
        <p className="text-[11px] leading-relaxed text-cyber-muted">{desc}</p>
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
   Login Input (enhanced focus glow, login-page-specific)
   ──────────────────────────────────────────────────────────────────── */

function LoginInput(props: { value: string; onChange: (v: string) => void; placeholder?: string; type?: "text" | "password" }) {
  const { value, onChange, placeholder, type = "text" } = props;
  return (
    <input
      type={type}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className="w-full rounded-lg border border-cyber-border bg-cyber-panel/80 px-4 py-2.5 text-sm text-cyber-text outline-none transition-all duration-150 placeholder:text-cyber-muted/40 focus:border-cyber-accent/50 focus:shadow-[0_0_0_3px_rgba(6,214,224,0.1)]"
    />
  );
}

/* ────────────────────────────────────────────────────────────────────
   Login Screen
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
    listSSOProviders(activeTenantId).then((providers) => {
      if (!cancelled) setSsoProviders(providers);
    }).catch(() => {
      if (!cancelled) setSsoProviders([]);
    });
    return () => { cancelled = true; };
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
      window.location.href = redirectURL;
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "SSO login failed");
      setSsoLoading(null);
    }
  };

  const passwordChecks = useMemo(() => {
    const pw = newPassword;
    return {
      minLength: pw.length >= 12,
      hasUpper: /[A-Z]/.test(pw),
      hasLower: /[a-z]/.test(pw),
      hasDigit: /\d/.test(pw),
      hasSpecial: /[^A-Za-z0-9\s]/.test(pw),
      noWhitespace: !/\s/.test(pw),
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
    if (!session || !canChangePassword) {
      return;
    }
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

  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden px-4 py-10">
      {/* Background gradients — more dramatic */}
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_10%_20%,rgba(6,214,224,0.18),transparent_50%),radial-gradient(ellipse_at_90%_80%,rgba(167,139,250,0.12),transparent_50%),radial-gradient(ellipse_at_50%_50%,rgba(6,214,224,0.04),transparent_70%),linear-gradient(160deg,#030810,#060a11_30%,#0a1020_60%,#060a11)]" />

      {/* Mobile brand header */}
      <div className="absolute left-0 right-0 top-8 z-20 text-center lg:hidden">
        <div className="mx-auto flex w-fit items-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-cyber-accent to-[#a78bfa] shadow-lg shadow-cyan-500/20">
            <Lock size={18} className="text-[#060a11]" />
          </div>
          <div className="text-left">
            <h1 className="font-heading text-xl font-bold tracking-wide text-cyber-text">Vecta KMS</h1>
            <p className="text-[9px] font-medium uppercase tracking-[0.2em] text-cyber-accent">Enterprise Key Management</p>
          </div>
        </div>
      </div>

      {/* Main grid */}
      <div className="relative z-10 grid w-full max-w-6xl gap-8 lg:grid-cols-[1.3fr_1fr]">

        {/* ═══ Left Panel — animated grid + branding ═══ */}
        <section className="relative hidden min-h-[560px] overflow-hidden rounded-2xl border border-cyber-border/40 shadow-2xl shadow-black/50 lg:flex lg:flex-col">
          {/* Animated grid background */}
          <div className="absolute inset-0">
            <NetworkGrid />
          </div>

          {/* Gradient overlay for text readability */}
          <div className="absolute inset-0 bg-gradient-to-t from-[#060a11] via-[#060a11]/80 to-[#060a11]/20" />

          {/* Content */}
          <div className="relative z-10 flex flex-1 flex-col justify-end p-8">
            {/* Brand mark */}
            <div className="mb-6 flex items-center gap-3.5">
              <div className="flex h-14 w-14 items-center justify-center rounded-xl bg-gradient-to-br from-cyber-accent to-[#a78bfa] shadow-lg shadow-cyan-500/25">
                <Lock size={28} className="text-[#060a11]" />
              </div>
              <div>
                <h1 className="font-heading text-[34px] font-bold leading-none tracking-wide text-cyber-text">
                  Vecta KMS
                </h1>
                <p className="mt-0.5 text-[10px] font-semibold uppercase tracking-[0.25em] text-cyber-accent">
                  Enterprise Key Management
                </p>
              </div>
            </div>

            {/* Tagline */}
            <p className="mb-8 max-w-md text-[13px] leading-relaxed text-cyber-muted">
              Unified cryptographic command center for key lifecycle, compliance governance,
              and continuous security posture monitoring across your entire infrastructure.
            </p>

            {/* Feature highlights */}
            <div className="space-y-2.5">
              <FeatureHighlight
                icon={ShieldCheck}
                title="AI/GenAI Data Protection"
                desc="DLP scan & redact PII from LLM prompts/completions before transmission"
              />
              <FeatureHighlight
                icon={Zap}
                title="Full Data Lineage"
                desc="Source traceability, key impact analysis and real-time activity monitoring"
              />
              <FeatureHighlight
                icon={KeyRound}
                title="FIPS 140-3 · TDE · TFE · DSPM"
                desc="Transparent DB/file encryption, posture management, and compliance evidence export"
              />
            </div>
          </div>
        </section>

        {/* ═══ Right Panel — login form ═══ */}
        <section className="mt-20 self-center rounded-2xl border border-cyber-border/60 bg-cyber-card/90 p-6 shadow-2xl shadow-black/40 backdrop-blur-sm animate-fadeIn lg:mt-0">
          <div className="mb-5">
            <h3 className="font-heading text-xl font-bold tracking-wide text-cyber-text">
              {session ? "Force Password Change" : "Administrator Login"}
            </h3>
            <p className="mt-1 text-xs text-cyber-muted">
              {session
                ? "A new administrator password is required before dashboard access."
                : "Authenticate with tenant administrator credentials."}
            </p>
          </div>

          {!session ? (
            <div className="space-y-4">
              {/* Tenant selector */}
              <label className="block space-y-1">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Tenant</span>
                <div className="space-y-2 rounded-lg border border-cyber-border bg-cyber-elevated/50 p-3">
                  <label className="flex items-center gap-2 text-xs text-cyber-text">
                    <input
                      type="checkbox"
                      checked={useRootTenant}
                      onChange={(event) => setUseRootTenant(event.target.checked)}
                      className="h-3.5 w-3.5 rounded border-cyber-border bg-cyber-panel accent-cyber-accent"
                    />
                    Use root tenant ({ROOT_TENANT_ID})
                  </label>
                  {!useRootTenant ? (
                    <LoginInput value={tenantInput} onChange={setTenantInput} placeholder="Enter tenant ID" />
                  ) : null}
                </div>
              </label>

              {/* Username */}
              <label className="block space-y-1.5">
                <span className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
                  <UserRound size={12} />
                  Username
                </span>
                <LoginInput value={username} onChange={setUsername} placeholder="admin" />
              </label>

              {/* Password */}
              <label className="block space-y-1.5">
                <span className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
                  <Lock size={12} />
                  Password
                </span>
                <LoginInput value={password} onChange={setPassword} placeholder="Enter password" type="password" />
              </label>

              {authError ? (
                <p className="rounded-lg border border-cyber-danger/40 bg-cyber-danger/10 px-3 py-2 text-sm text-cyber-danger">{authError}</p>
              ) : null}

              {/* Sign In button — gradient + glow */}
              <button
                type="button"
                onClick={handleLogin}
                className="w-full rounded-lg border border-cyber-accent/80 bg-gradient-to-r from-cyber-accent to-[#05b8c1] px-4 py-2.5 text-sm font-bold text-[#060a11] shadow-lg shadow-cyan-500/20 transition-all duration-150 hover:shadow-cyan-500/30 hover:brightness-110 active:scale-[0.98] disabled:opacity-60"
                disabled={loading}
              >
                {loading ? "Signing in..." : "Sign In"}
              </button>

              <p className="text-[10px] text-cyber-muted/60">
                Default admin: <strong className="text-cyber-muted">{config.admin_username}</strong>. Password configured in{" "}
                <code className="rounded bg-cyber-elevated px-1 text-cyber-accent/60">ui-auth.json</code>.
              </p>

              {/* SSO provider buttons */}
              {ssoProviders.length > 0 && (
                <div className="space-y-3 pt-1">
                  <div className="flex items-center gap-3">
                    <div className="h-px flex-1 bg-cyber-border/40" />
                    <span className="text-[10px] font-medium uppercase tracking-wider text-cyber-muted/60">or sign in with</span>
                    <div className="h-px flex-1 bg-cyber-border/40" />
                  </div>
                  {ssoProviders.map((sp) => (
                    <button
                      key={sp.provider}
                      type="button"
                      onClick={() => handleSSOLogin(sp.provider)}
                      disabled={ssoLoading === sp.provider}
                      className="w-full rounded-lg border border-cyber-border bg-cyber-elevated/60 px-4 py-2.5 text-sm font-medium text-cyber-text transition-all duration-150 hover:border-cyber-accent/40 hover:bg-cyber-elevated active:scale-[0.98] disabled:opacity-60"
                    >
                      {ssoLoading === sp.provider ? "Redirecting..." : sp.display_name}
                    </button>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <div className="rounded-lg border border-cyber-warning/35 bg-cyber-warning/10 p-3 text-sm text-cyber-warning">
                <div className="mb-1 flex items-center gap-2 font-semibold">
                  <KeyRound size={14} />
                  Password Rotation Required
                </div>
                First-login security policy blocks dashboard access until the temporary admin password is changed.
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
                <LoginInput value={newPassword} onChange={setNewPassword} placeholder="Enter new password" type="password" />
              </label>

              {showPolicyHint && <PasswordPolicyChecklist checks={passwordChecks} />}
              {!showPolicyHint && newPassword.length > 0 && !allChecksPassed && (
                <PasswordPolicyChecklist checks={passwordChecks} />
              )}

              <label className="block space-y-1.5">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">Confirm Password</span>
                <LoginInput value={confirmPassword} onChange={setConfirmPassword} placeholder="Repeat password" type="password" />
              </label>

              {confirmPassword.length > 0 && !passwordChecks.matchesConfirm && (
                <p className="flex items-center gap-1.5 text-xs text-cyber-danger">
                  <X size={12} /> Passwords do not match
                </p>
              )}

              {authError ? (
                <p className="rounded-lg border border-cyber-danger/40 bg-cyber-danger/10 px-3 py-2 text-sm text-cyber-danger">{authError}</p>
              ) : null}

              <button
                type="button"
                onClick={handlePasswordChange}
                className="w-full rounded-lg border border-cyber-accent/80 bg-gradient-to-r from-cyber-accent to-[#05b8c1] px-4 py-2.5 text-sm font-bold text-[#060a11] shadow-lg shadow-cyan-500/20 transition-all duration-150 hover:shadow-cyan-500/30 hover:brightness-110 active:scale-[0.98] disabled:opacity-60"
                disabled={!canChangePassword || savingPassword}
              >
                {savingPassword ? "Applying..." : "Update Password and Continue"}
              </button>
            </div>
          )}

          {/* Footer */}
          <div className="mt-6 border-t border-cyber-border/30 pt-4 text-center">
            <p className="text-[10px] text-cyber-muted/40">
              Vecta KMS v3.0 &middot; Secure Session &middot; TLS Encrypted
            </p>
          </div>
        </section>
      </div>
    </main>
  );
}

/* ────────────────────────────────────────────────────────────────────
   Password Policy Checklist (preserved from original)
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
  { key: "minLength", label: "At least 12 characters" },
  { key: "hasUpper", label: "One uppercase letter (A\u2013Z)" },
  { key: "hasLower", label: "One lowercase letter (a\u2013z)" },
  { key: "hasDigit", label: "One digit (0\u20139)" },
  { key: "hasSpecial", label: "One special character (!@#$...)" },
  { key: "noWhitespace", label: "No spaces or whitespace" },
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
              <span className={passed ? "text-emerald-400" : "text-cyber-muted"}>
                {label}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
