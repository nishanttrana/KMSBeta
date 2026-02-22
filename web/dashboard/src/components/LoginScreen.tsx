import { KeyRound, Lock, UserRound } from "lucide-react";
import { useMemo, useState } from "react";
import vectaLogo from "../assets/vecta-logo.svg";
import type { AuthSession, UIAuthConfig } from "../lib/auth";
import { changePassword, login } from "../lib/auth";
import { Button, Panel, TextInput } from "./primitives";

type LoginScreenProps = {
  config: UIAuthConfig;
  onAuthenticated: (session: AuthSession) => void;
};

export function LoginScreen(props: LoginScreenProps) {
  const { config, onAuthenticated } = props;
  const [username, setUsername] = useState(config.admin_username);
  const [password, setPassword] = useState(config.admin_password);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [authError, setAuthError] = useState<string | null>(null);
  const [session, setSession] = useState<AuthSession | null>(null);
  const [loading, setLoading] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);

  const canChangePassword = useMemo(() => {
    return newPassword.length >= 12 && newPassword === confirmPassword;
  }, [newPassword, confirmPassword]);

  const handleLogin = async () => {
    setLoading(true);
    setAuthError(null);
    try {
      const next = await login(username.trim(), password, config);
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
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_15%_15%,rgba(24,210,255,0.25),transparent_40%),radial-gradient(circle_at_80%_0%,rgba(36,214,139,0.15),transparent_34%),linear-gradient(145deg,#040a11,#081321_45%,#05101a)]" />

      <div className="relative z-10 grid w-full max-w-5xl gap-6 lg:grid-cols-[1.2fr_1fr]">
        <section className="rounded-2xl border border-cyber-border bg-cyber-panel/80 p-6 shadow-2xl shadow-black/40 backdrop-blur">
          <img src={vectaLogo} alt="Vecta logo" className="h-auto w-full rounded-xl border border-cyber-border/60" />
          <div className="mt-6 space-y-3">
            <h1 className="font-heading text-4xl font-bold tracking-wide text-cyber-text">Vecta KMS</h1>
            <p className="max-w-2xl text-cyber-muted">
              Secure control plane for key lifecycle, compliance posture, cryptographic workflows, and continuous operational monitoring.
            </p>
            <div className="grid gap-3 text-sm text-cyber-muted md:grid-cols-3">
              <div className="rounded-lg border border-cyber-border bg-cyber-elevated p-3">Zero-trust tenant segmentation</div>
              <div className="rounded-lg border border-cyber-border bg-cyber-elevated p-3">Live audit and alert telemetry</div>
              <div className="rounded-lg border border-cyber-border bg-cyber-elevated p-3">Policy and FIPS governance orchestration</div>
            </div>
          </div>
        </section>

        <Panel
          title={session ? "Force Password Change" : "Administrator Login"}
          subtitle={
            session
              ? "A new administrator password is required before dashboard access."
              : "Authenticate with tenant administrator credentials."
          }
          className="self-center"
        >
          {!session ? (
            <div className="space-y-4">
              <label className="block space-y-1">
                <span className="text-xs uppercase tracking-wide text-cyber-muted">Tenant</span>
                <div className="rounded-md border border-cyber-border bg-cyber-elevated px-3 py-2 text-sm text-cyber-text">{config.tenant_id}</div>
              </label>
              <label className="block space-y-1">
                <span className="flex items-center gap-2 text-xs uppercase tracking-wide text-cyber-muted">
                  <UserRound size={12} />
                  Username
                </span>
                <TextInput value={username} onChange={setUsername} placeholder="admin" />
              </label>
              <label className="block space-y-1">
                <span className="flex items-center gap-2 text-xs uppercase tracking-wide text-cyber-muted">
                  <Lock size={12} />
                  Password
                </span>
                <TextInput value={password} onChange={setPassword} placeholder="Enter password" type="password" />
              </label>
              {authError ? <p className="rounded-md border border-cyber-danger/40 bg-cyber-danger/10 px-3 py-2 text-sm text-cyber-danger">{authError}</p> : null}
              <Button onClick={handleLogin} className="w-full" kind="primary">
                {loading ? "Signing in..." : "Sign In"}
              </Button>
              <p className="text-xs text-cyber-muted">
                Default admin username: <strong>{config.admin_username}</strong>. Default password configured in
                <code className="ml-1 rounded bg-cyber-elevated px-1">public/config/ui-auth.json</code>.
              </p>
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
              <label className="block space-y-1">
                <span className="text-xs uppercase tracking-wide text-cyber-muted">New Password</span>
                <TextInput value={newPassword} onChange={setNewPassword} placeholder="At least 12 characters" type="password" />
              </label>
              <label className="block space-y-1">
                <span className="text-xs uppercase tracking-wide text-cyber-muted">Confirm Password</span>
                <TextInput value={confirmPassword} onChange={setConfirmPassword} placeholder="Repeat password" type="password" />
              </label>
              {authError ? <p className="rounded-md border border-cyber-danger/40 bg-cyber-danger/10 px-3 py-2 text-sm text-cyber-danger">{authError}</p> : null}
              <Button onClick={handlePasswordChange} className="w-full" kind="primary">
                {savingPassword ? "Applying..." : "Update Password and Continue"}
              </Button>
            </div>
          )}
        </Panel>
      </div>
    </main>
  );
}
