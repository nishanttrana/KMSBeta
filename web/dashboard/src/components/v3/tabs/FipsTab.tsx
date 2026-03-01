import { useCallback, useEffect, useMemo, useState } from "react";
import type { AuthSession } from "../../../lib/auth";
import { getGovernanceSystemState, patchGovernanceSystemState } from "../../../lib/governance";
import { B, Btn, Card, FG, Section, Sel } from "../legacyPrimitives";
import { errMsg, isFipsModeEnabled, normalizeFipsModeValue } from "../runtimeUtils";
import { C } from "../theme";

type FipsTabProps = {
  session: AuthSession | null;
  fipsMode?: string;
  onFipsModeChange?: (value: "enabled" | "disabled") => void;
  onToast?: (message: string) => void;
};

export const FipsTab = ({ session, fipsMode = "disabled", onFipsModeChange, onToast }: FipsTabProps) => {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [state, setState] = useState<any>(null);
  const [draft, setDraft] = useState({
    fips_mode_policy: "strict",
    fips_tls_profile: "tls12_fips_suites",
    fips_rng_mode: "ctr_drbg"
  });

  const load = useCallback(async () => {
    if (!session?.token) {
      setState(null);
      return;
    }
    setLoading(true);
    try {
      const out = await getGovernanceSystemState(session);
      const current = out?.state || {};
      setState(current);
      setDraft({
        fips_mode_policy: String(current?.fips_mode_policy || "strict").toLowerCase() === "standard" ? "standard" : "strict",
        fips_tls_profile: String(current?.fips_tls_profile || "tls12_fips_suites").toLowerCase() === "tls13_only" ? "tls13_only" : "tls12_fips_suites",
        fips_rng_mode: (() => {
          const raw = String(current?.fips_rng_mode || "ctr_drbg").toLowerCase();
          if (raw === "hmac_drbg") return "hmac_drbg";
          if (raw === "hsm_trng") return "hsm_trng";
          return "ctr_drbg";
        })()
      });
      setError("");
    } catch (loadError) {
      const message = errMsg(loadError);
      setError(message);
      onToast?.(`FIPS state load failed: ${message}`);
    } finally {
      setLoading(false);
    }
  }, [onToast, session]);

  useEffect(() => {
    void load();
  }, [load]);

  const apply = async () => {
    if (!session?.token) {
      onToast?.("Login is required to update FIPS settings.");
      return;
    }
    setSaving(true);
    try {
      const payload = {
        fips_mode_policy: draft.fips_mode_policy === "standard" ? "standard" : "strict",
        fips_mode: draft.fips_mode_policy === "standard" ? "disabled" : "enabled",
        fips_tls_profile: draft.fips_tls_profile === "tls13_only" ? "tls13_only" : "tls12_fips_suites",
        fips_rng_mode: ["ctr_drbg", "hmac_drbg", "hsm_trng"].includes(draft.fips_rng_mode) ? draft.fips_rng_mode : "ctr_drbg"
      };
      const out = await patchGovernanceSystemState(session, payload);
      const next = out?.state || payload;
      setState(next);
      onFipsModeChange?.(normalizeFipsModeValue(String(next?.fips_mode || payload.fips_mode || "disabled")));
      onToast?.("FIPS settings updated.");
      setError("");
    } catch (applyError) {
      const message = errMsg(applyError);
      setError(message);
      onToast?.(`FIPS settings update failed: ${message}`);
    } finally {
      setSaving(false);
    }
  };

  const runtimeEnabled = useMemo(() => {
    return Boolean(state?.fips_runtime_enabled ?? false);
  }, [state]);

  const modeEnabled = useMemo(() => {
    return isFipsModeEnabled(String(state?.fips_mode || fipsMode || "disabled"));
  }, [state?.fips_mode, fipsMode]);

  const libraryLabel = String(state?.fips_crypto_library || "go-boringcrypto");
  const entropyHealth = String(state?.fips_entropy_health || "unknown").toLowerCase();

  return <div>
    <Section title="FIPS Compliance Mode" actions={<div style={{ display: "flex", gap: 8 }}>
      <Btn small onClick={() => void load()} disabled={loading}>{loading ? "Refreshing..." : "Refresh"}</Btn>
      <Btn small primary onClick={() => void apply()} disabled={saving}>{saving ? "Applying..." : "Apply"}</Btn>
    </div>}>
      <Card style={{ padding: 12 }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 8, marginBottom: 10 }}>
          <Card><div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>Mode</div><div style={{ marginTop: 4 }}><B c={modeEnabled ? "green" : "blue"}>{modeEnabled ? "Strict" : "Standard"}</B></div></Card>
          <Card><div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>Library</div><div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginTop: 4 }}>{libraryLabel}</div></Card>
          <Card><div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>Runtime</div><div style={{ marginTop: 4 }}><B c={runtimeEnabled ? "green" : "amber"}>{runtimeEnabled ? "Enabled" : "Disabled"}</B></div></Card>
          <Card><div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>Entropy Health</div><div style={{ marginTop: 4 }}><B c={entropyHealth === "ok" ? "green" : entropyHealth === "degraded" ? "amber" : "red"}>{String(state?.fips_entropy_health || "UNKNOWN")}</B></div></Card>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          <FG label="Mode">
            <Sel value={draft.fips_mode_policy} onChange={(e) => setDraft((prev) => ({ ...prev, fips_mode_policy: e.target.value === "standard" ? "standard" : "strict" }))}>
              <option value="strict" disabled={!runtimeEnabled}>Strict FIPS (non-approved algos blocked)</option>
              <option value="standard">Standard (all algos, violations logged)</option>
            </Sel>
          </FG>
          <FG label="TLS">
            <Sel value={draft.fips_tls_profile} onChange={(e) => setDraft((prev) => ({ ...prev, fips_tls_profile: e.target.value === "tls13_only" ? "tls13_only" : "tls12_fips_suites" }))}>
              <option value="tls12_fips_suites">TLS 1.2+ FIPS suites only</option>
              <option value="tls13_only">TLS 1.3 only</option>
            </Sel>
          </FG>
          <FG label="RNG">
            <Sel value={draft.fips_rng_mode} onChange={(e) => setDraft((prev) => ({ ...prev, fips_rng_mode: e.target.value }))}>
              <option value="ctr_drbg">CTR_DRBG (FIPS)</option>
              <option value="hmac_drbg">HMAC_DRBG</option>
              <option value="hsm_trng">HSM TRNG</option>
            </Sel>
          </FG>
        </div>

        {error ? <div style={{ fontSize: 10, color: C.red, marginTop: 8 }}>{error}</div> : null}
      </Card>
    </Section>
  </div>;
};
