// @ts-nocheck
import { useCallback, useState } from "react";
import {
  Check, Lock, Loader2, ChevronRight, Sparkles,
  KeyRound, FileText, ShieldCheck, Cloud, Database, Cpu,
  GitBranch, Bell, CreditCard, Atom, Layers, Bot, Shield, BarChart3
} from "lucide-react";
import type { AuthSession } from "../lib/auth";
import { Btn, Card } from "./v3/legacyPrimitives";
import { C } from "./v3/theme";

type FeatureTile = {
  key: string;
  label: string;
  description: string;
  icon: any;
  category: string;
  recommended: boolean;
};

const CORE_FEATURES = ["auth", "keycore", "audit", "policy"];

const FEATURE_TILES: FeatureTile[] = [
  { key: "secrets", label: "Secrets Vault", description: "Universal secret store for passwords, SSH keys, tokens", icon: Lock, category: "core_services", recommended: true },
  { key: "certs", label: "Certificates / PKI", description: "Full CA hierarchy with ACME, EST, SCEP, OCSP", icon: FileText, category: "core_services", recommended: true },
  { key: "governance", label: "Governance", description: "Multi-quorum approval workflows for sensitive operations", icon: ShieldCheck, category: "governance", recommended: true },
  { key: "reporting_alerting", label: "Reporting & Alerts", description: "Alerting channels, incident management, dashboards", icon: Bell, category: "governance", recommended: true },
  { key: "data_protection", label: "Data Protection", description: "Tokenization, masking, FPE, envelope encryption", icon: Shield, category: "data_protection", recommended: true },
  { key: "cloud_byok", label: "Cloud BYOK", description: "Bring-your-own-key for AWS, Azure, GCP", icon: Cloud, category: "cloud", recommended: false },
  { key: "hyok_proxy", label: "HYOK Proxy", description: "Hold-your-own-key with DKE and EKM flows", icon: Cloud, category: "cloud", recommended: false },
  { key: "kmip_server", label: "KMIP Server", description: "OASIS KMIP 2.x protocol server", icon: Database, category: "cloud", recommended: false },
  { key: "ekm_database", label: "EKM for Databases", description: "TDE agent management for MSSQL, Oracle", icon: Database, category: "cloud", recommended: false },
  { key: "payment_crypto", label: "Payment Crypto", description: "TR-31, PIN blocks, CVV, MAC operations", icon: CreditCard, category: "data_protection", recommended: false },
  { key: "compliance_dashboard", label: "Compliance", description: "Posture scoring and framework gap analysis", icon: BarChart3, category: "governance", recommended: false },
  { key: "sbom_cbom", label: "SBOM / CBOM", description: "Software and cryptographic bill of materials", icon: BarChart3, category: "governance", recommended: false },
  { key: "ai_llm", label: "AI Assistant", description: "Natural-language queries and AI security analysis", icon: Bot, category: "infrastructure", recommended: false },
  { key: "qkd_interface", label: "QKD Interface", description: "Quantum key distribution endpoint", icon: GitBranch, category: "infrastructure", recommended: false },
  { key: "pqc_migration", label: "PQC Migration", description: "Post-quantum cryptography migration planning", icon: Atom, category: "infrastructure", recommended: false },
  { key: "mpc_engine", label: "MPC Engine", description: "Distributed key generation and threshold signing", icon: Cpu, category: "infrastructure", recommended: false },
  { key: "crypto_discovery", label: "Crypto Discovery", description: "Scan cloud providers for crypto asset inventory", icon: Shield, category: "governance", recommended: false },
  { key: "clustering", label: "Clustering", description: "Multi-node cluster topology and HA", icon: Layers, category: "infrastructure", recommended: false },
];

const CATEGORIES = [
  { id: "core_services", label: "Core Services" },
  { id: "data_protection", label: "Data Protection" },
  { id: "cloud", label: "Cloud & Integration" },
  { id: "governance", label: "Governance & Compliance" },
  { id: "infrastructure", label: "Infrastructure" },
];

type WizardStep = "welcome" | "features" | "deploying" | "complete";

type Props = {
  session: AuthSession;
  onComplete: () => void;
};

type RuntimeApplyResult = {
  enabled?: boolean;
  executed?: boolean;
  start_ok?: boolean;
  health_checked?: boolean;
  healthy?: boolean;
  profiles?: string[];
  services?: string[];
  start_logs?: string[];
  health_logs?: string[];
  message?: string;
  manual_steps?: string[];
};

type FeaturesApplyResponse = {
  status?: string;
  runtime_status?: string;
  features?: Record<string, boolean>;
  runtime_apply?: RuntimeApplyResult;
};

export function FeatureOnboardingWizard({ session, onComplete }: Props) {
  const [step, setStep] = useState<WizardStep>("welcome");
  const [selected, setSelected] = useState<Set<string>>(() =>
    new Set(FEATURE_TILES.filter((t) => t.recommended).map((t) => t.key))
  );
  const [deployLog, setDeployLog] = useState<string[]>([]);
  const [deployError, setDeployError] = useState("");
  const [deployResult, setDeployResult] = useState<RuntimeApplyResult | null>(null);

  const toggleFeature = useCallback((key: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const selectPreset = useCallback((preset: "minimal" | "recommended" | "all") => {
    if (preset === "minimal") setSelected(new Set());
    else if (preset === "recommended") setSelected(new Set(FEATURE_TILES.filter((t) => t.recommended).map((t) => t.key)));
    else setSelected(new Set(FEATURE_TILES.map((t) => t.key)));
  }, []);

  const handleDeploy = useCallback(async () => {
    setStep("deploying");
    setDeployLog(["Applying feature configuration..."]);
    setDeployError("");
    setDeployResult(null);
    try {
      const features: Record<string, boolean> = {};
      FEATURE_TILES.forEach((tile) => { features[tile.key] = selected.has(tile.key); });

      const response = await fetch("/svc/firstboot/api/v1/firstboot/features/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${session.token}` },
        body: JSON.stringify({ metadata: {}, spec: { features } }),
      });

      const payload = await response.json().catch(() => ({} as FeaturesApplyResponse)) as FeaturesApplyResponse;
      const runtimeApply = payload?.runtime_apply || {};
      const nextLog = [
        payload?.status === "applied" ? "Feature configuration saved." : "Feature configuration update returned an unexpected status.",
        ...(runtimeApply?.message ? [runtimeApply.message] : []),
        ...(Array.isArray(runtimeApply?.start_logs) ? runtimeApply.start_logs : []),
        ...(Array.isArray(runtimeApply?.health_logs) ? runtimeApply.health_logs : []),
        ...(Array.isArray(runtimeApply?.manual_steps) ? runtimeApply.manual_steps : []),
      ].filter(Boolean);
      setDeployResult(runtimeApply);
      setDeployLog(nextLog.length ? nextLog : ["Feature configuration processed."]);

      if (!response.ok) {
        const runtimeMessage = String(runtimeApply?.message || "").trim();
        throw new Error(runtimeMessage || `Deployment API returned ${response.status}`);
      }

      setStep("complete");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setDeployError(message);
      setDeployLog((p) => [...p, `Error: ${message}`]);
    }
  }, [selected, session]);

  const handleFinish = useCallback(() => {
    localStorage.setItem("vecta_onboarding_complete", "true");
    onComplete();
  }, [onComplete]);

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: C.bg, padding: 40 }}>
      <div style={{ maxWidth: 900, width: "100%", animation: "vecta-fade-in .4s ease" }}>

        {step === "welcome" && (
          <div style={{ textAlign: "center" }}>
            <div style={{ display: "flex", justifyContent: "center", marginBottom: 24 }}>
              <div style={{ width: 80, height: 80, borderRadius: "50%", background: `${C.accent}22`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Sparkles size={40} color={C.accent} />
              </div>
            </div>
            <h1 style={{ fontSize: 28, fontWeight: 800, color: C.text, margin: "0 0 12px", letterSpacing: -0.5 }}>Welcome to Vecta KMS</h1>
            <p style={{ fontSize: 14, color: C.dim, maxWidth: 500, margin: "0 auto 32px", lineHeight: 1.6 }}>
              Your KMS core services are running. Let's configure which additional features you'd like to enable. You can always change these later from Administration.
            </p>
            <Btn small primary onClick={() => setStep("features")} style={{ padding: "10px 28px", fontSize: 14 }}>
              Get Started <ChevronRight size={16} style={{ marginLeft: 4 }} />
            </Btn>
          </div>
        )}

        {step === "features" && (
          <div>
            <div style={{ textAlign: "center", marginBottom: 24 }}>
              <h2 style={{ fontSize: 22, fontWeight: 700, color: C.text, margin: "0 0 8px" }}>Select Features</h2>
              <p style={{ fontSize: 12, color: C.dim, margin: 0 }}>
                {selected.size} of {FEATURE_TILES.length} features selected · Core services are always enabled
              </p>
            </div>

            {/* Presets */}
            <div style={{ display: "flex", justifyContent: "center", gap: 8, marginBottom: 20 }}>
              <Btn small onClick={() => selectPreset("minimal")}>Minimal</Btn>
              <Btn small primary onClick={() => selectPreset("recommended")}>Recommended</Btn>
              <Btn small onClick={() => selectPreset("all")}>Full</Btn>
            </div>

            {/* Core features */}
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>Core (Always Enabled)</div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(180px,1fr))", gap: 8 }}>
                {CORE_FEATURES.map((key) => (
                  <div key={key} style={{ padding: "10px 14px", borderRadius: 8, background: `${C.green}11`, border: `1px solid ${C.green}33`, opacity: 0.7 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <Lock size={12} color={C.green} />
                      <span style={{ fontSize: 11, color: C.green, fontWeight: 600, textTransform: "capitalize" }}>{key}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Feature categories */}
            {CATEGORIES.map((cat) => {
              const tiles = FEATURE_TILES.filter((t) => t.category === cat.id);
              if (!tiles.length) return null;
              return (
                <div key={cat.id} style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>{cat.label}</div>
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(200px,1fr))", gap: 8 }}>
                    {tiles.map((tile, idx) => {
                      const isSelected = selected.has(tile.key);
                      const Icon = tile.icon;
                      return (
                        <Card
                          key={tile.key}
                          onClick={() => toggleFeature(tile.key)}
                          style={{
                            padding: "12px 14px",
                            cursor: "pointer",
                            border: `1px solid ${isSelected ? C.accent : C.border}`,
                            background: isSelected ? `${C.accent}11` : C.surface,
                            transition: "all .15s ease",
                            animation: `vecta-tile-appear .3s ease ${idx * 0.05}s both`,
                          }}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                              <Icon size={14} color={isSelected ? C.accent : C.dim} />
                              <span style={{ fontSize: 11, fontWeight: 700, color: C.text }}>{tile.label}</span>
                            </div>
                            {isSelected && (
                              <div style={{ width: 18, height: 18, borderRadius: "50%", background: C.accent, display: "flex", alignItems: "center", justifyContent: "center", animation: "vecta-check-pop .25s ease" }}>
                                <Check size={12} color="#000" strokeWidth={3} />
                              </div>
                            )}
                          </div>
                          <div style={{ fontSize: 10, color: C.dim, lineHeight: 1.4 }}>{tile.description}</div>
                          {tile.recommended && <div style={{ fontSize: 9, color: C.green, marginTop: 4, fontWeight: 600 }}>Recommended</div>}
                        </Card>
                      );
                    })}
                  </div>
                </div>
              );
            })}

            {/* Deploy button */}
            <div style={{ display: "flex", justifyContent: "center", marginTop: 24, gap: 12 }}>
              <Btn small onClick={() => setStep("welcome")}>Back</Btn>
              <Btn small primary onClick={() => void handleDeploy()} style={{ padding: "10px 28px", fontSize: 14 }}>
                Deploy {selected.size} Feature{selected.size !== 1 ? "s" : ""} <ChevronRight size={16} style={{ marginLeft: 4 }} />
              </Btn>
            </div>
          </div>
        )}

        {step === "deploying" && (
          <div style={{ textAlign: "center" }}>
            <div style={{ display: "flex", justifyContent: "center", marginBottom: 24 }}>
              <Loader2 size={48} color={C.accent} className="vecta-spin" />
            </div>
            <h2 style={{ fontSize: 22, fontWeight: 700, color: C.text, margin: "0 0 16px" }}>Deploying Features</h2>
            <div style={{ maxWidth: 500, margin: "0 auto", textAlign: "left" }}>
              {deployLog.map((line, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 0", animation: `vecta-fade-in .3s ease ${i * 0.1}s both` }}>
                  <Check size={12} color={C.green} />
                  <span style={{ fontSize: 11, color: C.dim }}>{line}</span>
                </div>
              ))}
            </div>
            {deployError && (
              <div style={{ marginTop: 16, padding: "8px 14px", borderRadius: 8, background: `${C.red}11`, border: `1px solid ${C.red}33`, fontSize: 11, color: C.red }}>
                {deployError}
              </div>
            )}
          </div>
        )}

        {step === "complete" && (
          <div style={{ textAlign: "center", animation: "vecta-fade-in .5s ease" }}>
            <div style={{ display: "flex", justifyContent: "center", marginBottom: 24 }}>
              <div style={{ width: 80, height: 80, borderRadius: "50%", background: `${C.green}22`, display: "flex", alignItems: "center", justifyContent: "center", animation: "vecta-check-pop .4s ease" }}>
                <Check size={40} color={C.green} strokeWidth={3} />
              </div>
            </div>
            <h2 style={{ fontSize: 24, fontWeight: 800, color: C.text, margin: "0 0 12px" }}>All Set!</h2>
            <p style={{ fontSize: 13, color: C.dim, maxWidth: 450, margin: "0 auto 28px", lineHeight: 1.6 }}>
              {deployResult?.executed
                ? deployResult?.healthy
                  ? "Your selected features are deployed and healthy."
                  : "Your feature configuration was applied. Review the deployment details below."
                : "Your feature configuration was applied. Complete the remaining startup steps below if needed."}
            </p>
            {deployResult?.services?.length ? (
              <div style={{ margin: "0 auto 20px", maxWidth: 560, textAlign: "left", padding: "12px 14px", borderRadius: 10, border: `1px solid ${C.border}`, background: C.surface }}>
                <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>Services</div>
                <div style={{ fontSize: 11, color: C.text, lineHeight: 1.6 }}>{deployResult.services.join(", ")}</div>
              </div>
            ) : null}
            {deployResult?.manual_steps?.length ? (
              <div style={{ margin: "0 auto 20px", maxWidth: 560, textAlign: "left", padding: "12px 14px", borderRadius: 10, border: `1px solid ${C.border}`, background: C.surface }}>
                <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>Next Steps</div>
                {deployResult.manual_steps.map((line, index) => (
                  <div key={index} style={{ fontSize: 11, color: C.text, lineHeight: 1.6 }}>{line}</div>
                ))}
              </div>
            ) : null}
            <Btn small primary onClick={handleFinish} style={{ padding: "10px 28px", fontSize: 14 }}>
              Go to Dashboard <ChevronRight size={16} style={{ marginLeft: 4 }} />
            </Btn>
          </div>
        )}
      </div>
    </div>
  );
}
