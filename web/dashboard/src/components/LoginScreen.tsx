import { ArrowRight, Check, Info, KeyRound, Lock, ShieldCheck, UserRound, X, Zap } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { AuthSession, UIAuthConfig } from "../lib/auth";
import { changePassword, login } from "../lib/auth";
import type { SSOProviderInfo } from "../lib/authAdmin";
import { getSSOLoginURL, listSSOProviders } from "../lib/authAdmin";

/* ────────────────────────────────────────────────────────────────────
   Inline CSS animations — injected once at module level
   ──────────────────────────────────────────────────────────────────── */

const ANIMATION_STYLES = `
  @keyframes floatParticle {
    0%   { opacity: 0; transform: translateY(0) scale(0.8); }
    10%  { opacity: 0.6; }
    90%  { opacity: 0.3; }
    100% { opacity: 0; transform: translateY(-120px) scale(1.1); }
  }
  @keyframes scanline {
    0%   { top: -2px; opacity: 0.6; }
    95%  { opacity: 0.3; }
    100% { top: 100%; opacity: 0; }
  }
  @keyframes glowPulse {
    0%, 100% { filter: drop-shadow(0 0 8px rgba(6,214,224,0.5)); }
    50%       { filter: drop-shadow(0 0 20px rgba(6,214,224,0.9)) drop-shadow(0 0 40px rgba(6,214,224,0.4)); }
  }
  @keyframes spinRingCW {
    from { transform: rotate(0deg); }
    to   { transform: rotate(360deg); }
  }
  @keyframes spinRingCCW {
    from { transform: rotate(0deg); }
    to   { transform: rotate(-360deg); }
  }
  @keyframes orbitDot {
    from { transform: rotate(0deg) translateX(72px) rotate(0deg); }
    to   { transform: rotate(360deg) translateX(72px) rotate(-360deg); }
  }
  @keyframes orbitDot2 {
    from { transform: rotate(120deg) translateX(96px) rotate(-120deg); }
    to   { transform: rotate(480deg) translateX(96px) rotate(-480deg); }
  }
  @keyframes shimmerBtn {
    0%   { background-position: -200% center; }
    100% { background-position: 200% center; }
  }
  @keyframes slideUp {
    0%   { opacity: 0; transform: translateY(20px); }
    100% { opacity: 1; transform: translateY(0); }
  }
  @keyframes labelFloat {
    0%   { top: 50%; transform: translateY(-50%); font-size: 14px; color: rgba(148,163,184,0.6); }
    100% { top: 4px; transform: translateY(0);    font-size: 10px; color: rgba(6,214,224,0.8); }
  }
  @keyframes borderGlow {
    0%, 100% { box-shadow: 0 1px 0 0 rgba(6,214,224,0.4); }
    50%       { box-shadow: 0 1px 0 0 rgba(6,214,224,0.9), 0 0 12px rgba(6,214,224,0.15); }
  }
  @keyframes orbPulse {
    0%, 100% { transform: scale(1); opacity: 0.18; }
    50%       { transform: scale(1.08); opacity: 0.24; }
  }
  .login-shimmer-btn {
    background: linear-gradient(90deg, #06d6e0 0%, #05b8c1 40%, #a0f0f5 50%, #05b8c1 60%, #06d6e0 100%);
    background-size: 200% auto;
  }
  .login-shimmer-btn:hover {
    animation: shimmerBtn 2.5s linear infinite;
  }
  .login-card-entrance {
    animation: slideUp 0.6s ease-out forwards;
  }
  .float-label-input:focus ~ .float-label,
  .float-label-input:not(:placeholder-shown) ~ .float-label {
    top: 4px;
    font-size: 10px;
    color: rgba(6,214,224,0.8);
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }
  .float-label {
    position: absolute;
    left: 0;
    top: 50%;
    transform: translateY(-50%);
    font-size: 14px;
    color: rgba(148,163,184,0.5);
    pointer-events: none;
    transition: top 0.2s ease, font-size 0.2s ease, color 0.2s ease, transform 0.2s ease, letter-spacing 0.2s ease;
  }
  .float-label-input:focus ~ .float-label {
    transform: translateY(0);
  }
  .float-label-input:not(:placeholder-shown) ~ .float-label {
    transform: translateY(0);
  }
  .login-input-line {
    border-bottom: 2px solid rgba(26,41,68,0.8);
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
  }
  .login-input-line:focus {
    outline: none;
    border-bottom-color: rgba(6,214,224,0.7);
    box-shadow: 0 1px 0 0 rgba(6,214,224,0.3);
  }
  .orb-pulse { animation: orbPulse 6s ease-in-out infinite; }
  .orb-pulse-delay { animation: orbPulse 6s ease-in-out 2s infinite; }
  .orb-pulse-delay2 { animation: orbPulse 6s ease-in-out 4s infinite; }
`;

/* ────────────────────────────────────────────────────────────────────
   Floating hex particles
   ──────────────────────────────────────────────────────────────────── */

const HEX_CHARS = ["0x1F", "0xA3", "0x7E", "0xB2", "0x4C", "0xFF", "0x08", "0x3D", "0x91", "0xC6", "0x55", "0x2A", "0xE0", "0x69", "0x17", "0xF4", "0x0B", "0x88", "0xD1", "0x3C", "0xAA", "0x76", "0x5F", "0x22", "0xCC", "0x49", "0x8E", "0x13", "0xB7", "0x60"];

function FloatingParticles() {
  const particles = useMemo(() => {
    return Array.from({ length: 36 }, (_, i) => ({
      id: i,
      char: HEX_CHARS[i % HEX_CHARS.length],
      left: `${(i * 2.8 + Math.sin(i * 1.3) * 5 + 2) % 98}%`,
      bottom: `${(i * 3.1 + 2) % 88}%`,
      duration: `${8 + (i % 7) * 1.8}s`,
      delay: `${(i * 0.6) % 12}s`,
      size: i % 4 === 0 ? "11px" : i % 3 === 0 ? "9px" : "8px",
      opacity: i % 5 === 0 ? 0.55 : 0.35,
    }));
  }, []);

  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden" aria-hidden="true">
      {particles.map((p) => (
        <span
          key={p.id}
          className="absolute font-mono text-cyber-accent"
          style={{
            left: p.left,
            bottom: p.bottom,
            fontSize: p.size,
            opacity: 0,
            animation: `floatParticle ${p.duration} ease-in-out ${p.delay} infinite`,
            color: p.id % 5 === 0 ? "#a78bfa" : p.id % 7 === 0 ? "#2dd4a0" : "#06d6e0",
          }}
        >
          {p.char}
        </span>
      ))}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
   Scan line
   ──────────────────────────────────────────────────────────────────── */

function ScanLine() {
  return (
    <div
      className="pointer-events-none absolute inset-x-0 z-10 h-px"
      aria-hidden="true"
      style={{
        background: "linear-gradient(90deg, transparent 0%, rgba(6,214,224,0.5) 30%, rgba(6,214,224,0.8) 50%, rgba(6,214,224,0.5) 70%, transparent 100%)",
        animation: "scanline 8s linear infinite",
      }}
    />
  );
}

/* ────────────────────────────────────────────────────────────────────
   Animated Crypto Vault SVG
   ──────────────────────────────────────────────────────────────────── */

function CryptoVaultSVG() {
  return (
    <div className="relative flex items-center justify-center" style={{ width: 280, height: 280 }}>
      {/* Radial glow background */}
      <div
        className="absolute inset-0 rounded-full"
        style={{
          background: "radial-gradient(circle at center, rgba(6,214,224,0.12) 0%, rgba(6,214,224,0.04) 40%, transparent 70%)",
        }}
      />

      <svg
        width="280"
        height="280"
        viewBox="0 0 280 280"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden="true"
      >
        <defs>
          <radialGradient id="vaultBg" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="rgba(6,214,224,0.08)" />
            <stop offset="100%" stopColor="transparent" />
          </radialGradient>
          <filter id="vaultGlow" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur in="SourceGraphic" stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter id="strongGlow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur in="SourceGraphic" stdDeviation="6" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Background circle */}
        <circle cx="140" cy="140" r="130" fill="url(#vaultBg)" />

        {/* Outer ring — slow clockwise */}
        <g style={{ transformOrigin: "140px 140px", animation: "spinRingCW 20s linear infinite" }}>
          <circle cx="140" cy="140" r="122" fill="none" stroke="rgba(6,214,224,0.15)" strokeWidth="1" strokeDasharray="4 8" />
          {/* Nodes on outer ring */}
          {[0, 45, 90, 135, 180, 225, 270, 315].map((angle, i) => {
            const rad = (angle * Math.PI) / 180;
            const x = 140 + 122 * Math.cos(rad);
            const y = 140 + 122 * Math.sin(rad);
            return (
              <circle
                key={i}
                cx={x}
                cy={y}
                r={i % 2 === 0 ? 3 : 2}
                fill={i % 3 === 0 ? "#06d6e0" : "#a78bfa"}
                opacity={i % 2 === 0 ? 0.7 : 0.4}
                filter="url(#vaultGlow)"
              />
            );
          })}
          {/* Orbiting dot on outer ring */}
          <circle cx="262" cy="140" r="4" fill="#06d6e0" opacity="0.9" filter="url(#vaultGlow)" />
        </g>

        {/* Middle ring — medium counter-clockwise */}
        <g style={{ transformOrigin: "140px 140px", animation: "spinRingCCW 15s linear infinite" }}>
          <circle cx="140" cy="140" r="90" fill="none" stroke="rgba(167,139,250,0.2)" strokeWidth="1.5" strokeDasharray="6 10" />
          {[30, 90, 150, 210, 270, 330].map((angle, i) => {
            const rad = (angle * Math.PI) / 180;
            const x = 140 + 90 * Math.cos(rad);
            const y = 140 + 90 * Math.sin(rad);
            return (
              <circle
                key={i}
                cx={x}
                cy={y}
                r="2.5"
                fill={i % 2 === 0 ? "#a78bfa" : "#06d6e0"}
                opacity="0.6"
                filter="url(#vaultGlow)"
              />
            );
          })}
          {/* Orbiting dot on middle ring */}
          <circle cx="230" cy="140" r="5" fill="#a78bfa" opacity="0.85" filter="url(#strongGlow)" />
        </g>

        {/* Inner ring — faster clockwise */}
        <g style={{ transformOrigin: "140px 140px", animation: "spinRingCW 8s linear infinite" }}>
          <circle cx="140" cy="140" r="62" fill="none" stroke="rgba(45,212,160,0.25)" strokeWidth="1" strokeDasharray="3 6" />
          {[0, 60, 120, 180, 240, 300].map((angle, i) => {
            const rad = (angle * Math.PI) / 180;
            const x = 140 + 62 * Math.cos(rad);
            const y = 140 + 62 * Math.sin(rad);
            return (
              <circle key={i} cx={x} cy={y} r="2" fill="#2dd4a0" opacity="0.5" filter="url(#vaultGlow)" />
            );
          })}
        </g>

        {/* Shield body */}
        <g style={{ animation: "glowPulse 3s ease-in-out infinite" }}>
          <path
            d="M140 105 L165 115 L165 138 C165 153 152 165 140 170 C128 165 115 153 115 138 L115 115 Z"
            fill="rgba(6,214,224,0.08)"
            stroke="#06d6e0"
            strokeWidth="2"
            strokeLinejoin="round"
            filter="url(#vaultGlow)"
          />
          {/* Shield inner highlight */}
          <path
            d="M140 109 L161 118 L161 138 C161 151 149 162 140 166 C131 162 119 151 119 138 L119 118 Z"
            fill="rgba(6,214,224,0.05)"
            stroke="rgba(6,214,224,0.3)"
            strokeWidth="0.5"
          />

          {/* Key icon inside shield */}
          {/* Key head (circle) */}
          <circle cx="136" cy="130" r="7" fill="none" stroke="#06d6e0" strokeWidth="2" filter="url(#vaultGlow)" />
          <circle cx="136" cy="130" r="3.5" fill="rgba(6,214,224,0.4)" />
          {/* Key shaft */}
          <line x1="141" y1="133" x2="152" y2="144" stroke="#06d6e0" strokeWidth="2" strokeLinecap="round" filter="url(#vaultGlow)" />
          {/* Key teeth */}
          <line x1="148" y1="141" x2="148" y2="145" stroke="#06d6e0" strokeWidth="1.5" strokeLinecap="round" />
          <line x1="152" y1="144" x2="152" y2="148" stroke="#06d6e0" strokeWidth="1.5" strokeLinecap="round" />
        </g>

        {/* Center glow */}
        <circle cx="140" cy="140" r="30" fill="rgba(6,214,224,0.03)" />
      </svg>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
   Feature Highlight (left panel)
   ──────────────────────────────────────────────────────────────────── */

function FeatureHighlight({ icon: Icon, title, desc }: { icon: React.ComponentType<any>; title: string; desc: string }) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-white/[0.07] bg-white/[0.03] p-3.5 backdrop-blur-sm transition-all duration-200 hover:border-cyber-accent/20 hover:bg-white/[0.06]">
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-cyber-accent/10 text-cyber-accent ring-1 ring-cyber-accent/20">
        <Icon size={16} />
      </div>
      <div>
        <p className="text-[13px] font-semibold text-cyber-text">{title}</p>
        <p className="mt-0.5 text-[11px] leading-relaxed text-cyber-muted">{desc}</p>
      </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
   Floating Label Input
   ──────────────────────────────────────────────────────────────────── */

function FloatingLabelInput(props: {
  value: string;
  onChange: (v: string) => void;
  label: string;
  type?: "text" | "password";
  id: string;
}) {
  const { value, onChange, label, type = "text", id } = props;
  return (
    <div className="relative pt-5 pb-1">
      <input
        id={id}
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder=" "
        autoComplete={type === "password" ? "current-password" : "username"}
        className="float-label-input login-input-line w-full bg-transparent px-0 pb-1.5 pt-1 text-sm text-cyber-text caret-cyber-accent"
        style={{ outline: "none" }}
      />
      <label htmlFor={id} className="float-label">
        {label}
      </label>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
   Simple login input (for change-password view / tenant)
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
    <div className="rounded-xl border border-cyber-border bg-cyber-elevated/60 p-3">
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
      window.location.href = redirectURL;
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

  return (
    <>
      {/* Inject keyframe animations */}
      <style>{ANIMATION_STYLES}</style>

      <main
        className="relative flex min-h-screen items-center justify-center overflow-hidden px-4 py-10"
        style={{ background: "#060a11" }}
      >
        {/* ── Background: deep dark base ── */}
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            background:
              "radial-gradient(ellipse 80% 60% at 10% 15%, rgba(6,214,224,0.07) 0%, transparent 55%), radial-gradient(ellipse 70% 55% at 92% 85%, rgba(167,139,250,0.07) 0%, transparent 55%), radial-gradient(ellipse 60% 50% at 50% 50%, rgba(6,214,224,0.025) 0%, transparent 65%), linear-gradient(160deg, #030810 0%, #060a11 30%, #09101e 60%, #060a11 100%)",
          }}
          aria-hidden="true"
        />

        {/* ── Glowing orbs ── */}
        <div
          className="pointer-events-none absolute orb-pulse"
          aria-hidden="true"
          style={{
            top: "-10%",
            left: "-8%",
            width: 520,
            height: 520,
            borderRadius: "50%",
            background: "radial-gradient(circle, rgba(6,214,224,0.22) 0%, transparent 65%)",
            filter: "blur(60px)",
          }}
        />
        <div
          className="pointer-events-none absolute orb-pulse-delay"
          aria-hidden="true"
          style={{
            bottom: "-12%",
            right: "-8%",
            width: 480,
            height: 480,
            borderRadius: "50%",
            background: "radial-gradient(circle, rgba(167,139,250,0.18) 0%, transparent 65%)",
            filter: "blur(70px)",
          }}
        />
        <div
          className="pointer-events-none absolute orb-pulse-delay2"
          aria-hidden="true"
          style={{
            top: "40%",
            left: "40%",
            width: 360,
            height: 360,
            borderRadius: "50%",
            background: "radial-gradient(circle, rgba(45,212,160,0.12) 0%, transparent 65%)",
            filter: "blur(80px)",
          }}
        />

        {/* ── Floating hex particles ── */}
        <FloatingParticles />

        {/* ── Scan line ── */}
        <ScanLine />

        {/* ── Mobile header ── */}
        <div className="absolute left-0 right-0 top-6 z-20 text-center lg:hidden" aria-hidden="true">
          <div className="mx-auto flex w-fit items-center gap-2.5">
            <div
              className="flex h-9 w-9 items-center justify-center rounded-lg"
              style={{ background: "linear-gradient(135deg, #06d6e0 0%, #a78bfa 100%)", boxShadow: "0 4px 14px rgba(6,214,224,0.3)" }}
            >
              <Lock size={18} style={{ color: "#060a11" }} />
            </div>
            <div className="text-left">
              <h1 className="font-heading text-xl font-bold tracking-wide text-cyber-text">Vecta KMS</h1>
              <p className="text-[9px] font-semibold uppercase tracking-[0.2em] text-cyber-accent">Enterprise Key Management</p>
            </div>
          </div>
        </div>

        {/* ── Main two-column layout ── */}
        <div className="relative z-10 grid w-full max-w-6xl items-center gap-6 lg:grid-cols-[1.25fr_1fr]">

          {/* ═══════════════════════════════════════════
              LEFT PANEL — Crypto vault + branding
              ═══════════════════════════════════════════ */}
          <section
            className="relative hidden min-h-[620px] overflow-hidden rounded-2xl lg:flex lg:flex-col"
            style={{
              background: "linear-gradient(145deg, rgba(15,21,33,0.85) 0%, rgba(9,14,24,0.90) 100%)",
              border: "1px solid rgba(26,41,68,0.6)",
              backdropFilter: "blur(20px)",
              boxShadow: "0 25px 60px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.04)",
            }}
          >
            {/* Subtle inner glow at top */}
            <div
              className="pointer-events-none absolute inset-x-0 top-0 h-px"
              style={{ background: "linear-gradient(90deg, transparent, rgba(6,214,224,0.4), transparent)" }}
              aria-hidden="true"
            />

            <div className="relative z-10 flex flex-1 flex-col items-center justify-between p-8">
              {/* Top: Brand */}
              <div className="flex w-full items-center gap-3.5">
                <div
                  className="flex h-12 w-12 items-center justify-center rounded-xl"
                  style={{
                    background: "linear-gradient(135deg, #06d6e0 0%, #a78bfa 100%)",
                    boxShadow: "0 6px 20px rgba(6,214,224,0.35)",
                  }}
                >
                  <Lock size={24} style={{ color: "#060a11" }} />
                </div>
                <div>
                  <h1 className="font-heading text-3xl font-bold leading-none tracking-widest text-cyber-text">
                    Vecta KMS
                  </h1>
                  <p className="mt-0.5 text-[9px] font-semibold uppercase tracking-[0.28em] text-cyber-accent">
                    Enterprise Key Management
                  </p>
                </div>
              </div>

              {/* Center: Animated vault SVG */}
              <div className="flex flex-col items-center gap-3">
                <CryptoVaultSVG />
                <p className="text-center text-[13px] leading-relaxed text-cyber-muted" style={{ maxWidth: 300 }}>
                  Unified cryptographic command center for key lifecycle, compliance governance,
                  and continuous security posture monitoring.
                </p>
              </div>

              {/* Feature cards */}
              <div className="w-full space-y-2.5">
                <FeatureHighlight
                  icon={ShieldCheck}
                  title="Zero-Trust Segmentation"
                  desc="Tenant-isolated key stores with policy-enforced access boundaries"
                />
                <FeatureHighlight
                  icon={Zap}
                  title="Live Telemetry"
                  desc="Real-time audit logging, alerting, and compliance drift detection"
                />
                <FeatureHighlight
                  icon={KeyRound}
                  title="FIPS 140-3 Governance"
                  desc="Hardware-rooted key ceremonies with multi-party approval workflows"
                />
              </div>

              {/* Bottom stats bar */}
              <div
                className="flex w-full items-center justify-around rounded-xl px-4 py-3"
                style={{
                  background: "rgba(255,255,255,0.025)",
                  border: "1px solid rgba(255,255,255,0.07)",
                }}
              >
                {[
                  { value: "27", label: "Services" },
                  { value: "FIPS 140-3", label: "Certified" },
                  { value: "Zero Trust", label: "Architecture" },
                ].map((stat, i) => (
                  <div key={i} className="flex flex-col items-center gap-0.5">
                    <span className="font-heading text-sm font-bold tracking-wide text-cyber-accent">
                      {stat.value}
                    </span>
                    <span className="text-[9px] font-medium uppercase tracking-widest text-cyber-muted">
                      {stat.label}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* ═══════════════════════════════════════════
              RIGHT PANEL — Login form
              ═══════════════════════════════════════════ */}
          <section
            className="login-card-entrance mt-16 self-center rounded-2xl p-8 lg:mt-0"
            style={{
              background: "rgba(255,255,255,0.028)",
              backdropFilter: "blur(24px)",
              WebkitBackdropFilter: "blur(24px)",
              border: "1px solid rgba(255,255,255,0.09)",
              boxShadow: "0 30px 70px rgba(0,0,0,0.55), 0 1px 0 rgba(255,255,255,0.06) inset, 0 0 40px rgba(6,214,224,0.04)",
            }}
          >
            {/* Top badge */}
            <div className="mb-6 flex items-center gap-3">
              <div
                className="flex h-10 w-10 items-center justify-center rounded-xl"
                style={{
                  background: "linear-gradient(135deg, rgba(6,214,224,0.15) 0%, rgba(167,139,250,0.15) 100%)",
                  border: "1px solid rgba(6,214,224,0.25)",
                  boxShadow: "0 0 16px rgba(6,214,224,0.12)",
                }}
              >
                <Lock size={18} className="text-cyber-accent" />
              </div>
              <div>
                <p className="text-[9px] font-semibold uppercase tracking-[0.25em] text-cyber-accent">
                  Secure Access
                </p>
                <h2 className="font-heading text-xl font-bold tracking-wide text-cyber-text">
                  {session ? "Force Password Change" : "Administrator Login"}
                </h2>
              </div>
            </div>

            {/* Top accent line */}
            <div
              className="mb-6 h-px w-full"
              style={{ background: "linear-gradient(90deg, rgba(6,214,224,0.5), rgba(167,139,250,0.3), transparent)" }}
            />

            <p className="mb-6 text-xs text-cyber-muted">
              {session
                ? "A new administrator password is required before dashboard access."
                : "Authenticate with tenant administrator credentials to access the KMS dashboard."}
            </p>

            {!session ? (
              <div className="space-y-5">
                {/* Tenant selector */}
                <div>
                  <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
                    Tenant
                  </p>
                  <div
                    className="space-y-3 rounded-xl p-3.5"
                    style={{
                      background: "rgba(255,255,255,0.025)",
                      border: "1px solid rgba(255,255,255,0.07)",
                    }}
                  >
                    <label className="flex cursor-pointer items-center gap-2.5 text-sm text-cyber-text">
                      <input
                        type="checkbox"
                        checked={useRootTenant}
                        onChange={(e) => setUseRootTenant(e.target.checked)}
                        className="h-4 w-4 rounded border-cyber-border bg-cyber-panel accent-cyber-accent"
                      />
                      <span>
                        Use root tenant{" "}
                        <code
                          className="ml-1 rounded px-1.5 py-0.5 text-[11px] text-cyber-accent"
                          style={{ background: "rgba(6,214,224,0.08)", border: "1px solid rgba(6,214,224,0.15)" }}
                        >
                          {ROOT_TENANT_ID}
                        </code>
                      </span>
                    </label>
                    {!useRootTenant && (
                      <LoginInput value={tenantInput} onChange={setTenantInput} placeholder="Enter tenant ID" />
                    )}
                  </div>
                </div>

                {/* Username — floating label */}
                <div
                  className="rounded-xl px-4"
                  style={{
                    background: "rgba(255,255,255,0.02)",
                    border: "1px solid rgba(255,255,255,0.07)",
                  }}
                >
                  <div className="flex items-end gap-2.5">
                    <UserRound size={14} className="mb-2.5 shrink-0 text-cyber-muted/60" />
                    <div className="flex-1">
                      <FloatingLabelInput
                        id="login-username"
                        value={username}
                        onChange={setUsername}
                        label="Username"
                        type="text"
                      />
                    </div>
                  </div>
                </div>

                {/* Password — floating label */}
                <div
                  className="rounded-xl px-4"
                  style={{
                    background: "rgba(255,255,255,0.02)",
                    border: "1px solid rgba(255,255,255,0.07)",
                  }}
                >
                  <div className="flex items-end gap-2.5">
                    <Lock size={14} className="mb-2.5 shrink-0 text-cyber-muted/60" />
                    <div className="flex-1">
                      <FloatingLabelInput
                        id="login-password"
                        value={password}
                        onChange={setPassword}
                        label="Password"
                        type="password"
                      />
                    </div>
                  </div>
                </div>

                {/* Auth error */}
                {authError && (
                  <div
                    className="flex items-start gap-2.5 rounded-xl px-4 py-3 text-sm text-red-400"
                    style={{
                      background: "rgba(239,68,68,0.08)",
                      border: "1px solid rgba(239,68,68,0.25)",
                    }}
                  >
                    <X size={14} className="mt-0.5 shrink-0" />
                    <span>{authError}</span>
                  </div>
                )}

                {/* Sign In button */}
                <button
                  type="button"
                  onClick={handleLogin}
                  disabled={loading}
                  className="login-shimmer-btn relative w-full overflow-hidden rounded-xl py-3 text-sm font-bold tracking-wide disabled:opacity-60"
                  style={{
                    color: "#060a11",
                    boxShadow: loading ? "none" : "0 4px 20px rgba(6,214,224,0.35), 0 0 0 1px rgba(6,214,224,0.5)",
                    transition: "box-shadow 0.2s ease, opacity 0.2s ease",
                  }}
                >
                  <span className="relative z-10 flex items-center justify-center gap-2">
                    {loading ? (
                      <>
                        <span
                          className="h-4 w-4 rounded-full border-2 border-[#060a11]/30 border-t-[#060a11]"
                          style={{ animation: "spinRingCW 0.8s linear infinite", display: "inline-block" }}
                        />
                        Authenticating...
                      </>
                    ) : (
                      <>
                        Sign In
                        <ArrowRight size={15} />
                      </>
                    )}
                  </span>
                </button>

                {/* Helper hint */}
                <p className="text-[10px] text-cyber-muted/50">
                  Default admin:{" "}
                  <strong className="text-cyber-muted">{config.admin_username}</strong>. Password configured in{" "}
                  <code
                    className="rounded px-1 text-cyber-accent/60"
                    style={{ background: "rgba(6,214,224,0.07)" }}
                  >
                    ui-auth.json
                  </code>
                  .
                </p>

                {/* SSO providers */}
                {ssoProviders.length > 0 && (
                  <div className="space-y-3 pt-1">
                    <div className="flex items-center gap-3">
                      <div className="h-px flex-1" style={{ background: "rgba(26,41,68,0.6)" }} />
                      <span className="text-[10px] font-medium uppercase tracking-wider text-cyber-muted/60">
                        or sign in with
                      </span>
                      <div className="h-px flex-1" style={{ background: "rgba(26,41,68,0.6)" }} />
                    </div>
                    {ssoProviders.map((sp) => (
                      <button
                        key={sp.provider}
                        type="button"
                        onClick={() => handleSSOLogin(sp.provider)}
                        disabled={ssoLoading === sp.provider}
                        className="w-full rounded-xl px-4 py-2.5 text-sm font-medium text-cyber-text transition-all duration-150 disabled:opacity-60"
                        style={{
                          background: "rgba(255,255,255,0.03)",
                          border: "1px solid rgba(255,255,255,0.08)",
                        }}
                        onMouseEnter={(e) => {
                          (e.currentTarget as HTMLElement).style.borderColor = "rgba(6,214,224,0.3)";
                          (e.currentTarget as HTMLElement).style.background = "rgba(6,214,224,0.05)";
                        }}
                        onMouseLeave={(e) => {
                          (e.currentTarget as HTMLElement).style.borderColor = "rgba(255,255,255,0.08)";
                          (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.03)";
                        }}
                      >
                        {ssoLoading === sp.provider ? "Redirecting..." : sp.display_name}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              /* ── Password change view ── */
              <div className="space-y-4">
                <div
                  className="rounded-xl p-3.5 text-sm"
                  style={{
                    background: "rgba(246,186,58,0.08)",
                    border: "1px solid rgba(246,186,58,0.3)",
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
                  <LoginInput value={newPassword} onChange={setNewPassword} placeholder="Enter new password" type="password" />
                </label>

                {showPolicyHint && <PasswordPolicyChecklist checks={passwordChecks} />}
                {!showPolicyHint && newPassword.length > 0 && !allChecksPassed && (
                  <PasswordPolicyChecklist checks={passwordChecks} />
                )}

                <label className="block space-y-1.5">
                  <span className="text-[10px] font-semibold uppercase tracking-wider text-cyber-muted">
                    Confirm Password
                  </span>
                  <LoginInput value={confirmPassword} onChange={setConfirmPassword} placeholder="Repeat password" type="password" />
                </label>

                {confirmPassword.length > 0 && !passwordChecks.matchesConfirm && (
                  <p className="flex items-center gap-1.5 text-xs text-red-400">
                    <X size={12} /> Passwords do not match
                  </p>
                )}

                {authError && (
                  <div
                    className="flex items-start gap-2.5 rounded-xl px-4 py-3 text-sm text-red-400"
                    style={{ background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.25)" }}
                  >
                    <X size={14} className="mt-0.5 shrink-0" />
                    <span>{authError}</span>
                  </div>
                )}

                <button
                  type="button"
                  onClick={handlePasswordChange}
                  disabled={!canChangePassword || savingPassword}
                  className="login-shimmer-btn relative w-full overflow-hidden rounded-xl py-3 text-sm font-bold tracking-wide disabled:opacity-60"
                  style={{
                    color: "#060a11",
                    boxShadow: canChangePassword && !savingPassword ? "0 4px 20px rgba(6,214,224,0.35), 0 0 0 1px rgba(6,214,224,0.5)" : "none",
                    transition: "box-shadow 0.2s ease, opacity 0.2s ease",
                  }}
                >
                  <span className="relative z-10 flex items-center justify-center gap-2">
                    {savingPassword ? (
                      <>
                        <span
                          className="h-4 w-4 rounded-full border-2 border-[#060a11]/30 border-t-[#060a11]"
                          style={{ animation: "spinRingCW 0.8s linear infinite", display: "inline-block" }}
                        />
                        Applying...
                      </>
                    ) : (
                      <>
                        Update Password and Continue
                        <ArrowRight size={15} />
                      </>
                    )}
                  </span>
                </button>
              </div>
            )}

            {/* Footer */}
            <div
              className="mt-7 flex items-center justify-center gap-2 border-t pt-5 text-center"
              style={{ borderColor: "rgba(255,255,255,0.06)" }}
            >
              <Lock size={10} className="text-cyber-muted/40" />
              <p className="text-[10px] text-cyber-muted/40">
                256-bit AES-GCM &nbsp;&middot;&nbsp; FIPS 140-3 &nbsp;&middot;&nbsp; TLS 1.3
              </p>
            </div>
          </section>
        </div>
      </main>
    </>
  );
}
