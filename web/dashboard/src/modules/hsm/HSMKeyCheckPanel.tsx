import { useState } from "react";
import type { AuthSession } from "../../lib/auth";
import { inspectHSMKey, type HSMKeyCheck } from "../../lib/keycore";
import { Btn } from "../../components/v3/legacyPrimitives";
import { errMsg } from "../../components/v3/runtimeUtils";
import { C } from "../../components/v3/theme";

const yes = (v: boolean | undefined) => v === true;

// "Verify in HSM": reads the key's objects back from the HSM and shows what
// the HSM itself reports: the label, that the key was generated on the token
// (CKA_LOCAL), is sensitive and was never extractable, and whether the HSM now
// configured is the device the key was created on.
export function HSMKeyCheckPanel({ session, keyID }: { session: AuthSession | null; keyID: string }) {
  const [check, setCheck] = useState<HSMKeyCheck | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const run = async () => {
    if (!session) return;
    setLoading(true);
    setError("");
    try {
      setCheck(await inspectHSMKey(session, keyID));
    } catch (e) {
      setCheck(null);
      setError(errMsg(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ marginTop: 10, padding: 10, border: `1px solid ${C.border}`, borderRadius: 6 }}>
      <div style={{ display: "flex", alignItems: "center" }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>HSM</div>
        <div style={{ marginLeft: "auto" }}>
          <Btn small onClick={() => void run()} disabled={loading}>{loading ? "Reading HSM..." : "Verify in HSM"}</Btn>
        </div>
      </div>
      {error && <div style={{ fontSize: 10, color: C.red, marginTop: 6 }}>{error}</div>}
      {check && (
        <div style={{ fontSize: 10, color: C.text, marginTop: 6 }}>
          <div style={{ color: check.same_device ? C.green : C.red, marginBottom: 4 }}>
            {check.same_device
              ? `On the HSM it was created on${check.current_hsm.serial_number ? ` (serial ${check.current_hsm.serial_number}, token "${check.current_hsm.token_label}")` : ""}.`
              : `Created on HSM serial ${check.recorded_hsm.serial_number}, but the tenant's profile now points at serial ${check.current_hsm.serial_number || "unknown"}.`}
          </div>
          {check.versions.map((v) => (
            <div key={v.version} style={{ marginBottom: 6 }}>
              <div style={{ fontFamily: "'JetBrains Mono',monospace", color: C.muted }}>v{v.version} {v.protection === "tenant_hsm" ? "(material under the tenant key)" : ""} {v.label}</div>
              {v.error && <div style={{ color: C.red }}>{v.error}</div>}
              {(v.objects || []).map((o, i) => {
                const secret = o.class !== "public_key";
                const ok = yes(o.local) && (!secret || (yes(o.sensitive) && o.extractable === false && yes(o.never_extractable)));
                return (
                  <div key={i} style={{ color: ok ? C.green : C.amber }}>
                    {o.class.replace("_", " ")} {o.key_type}{o.curve ? ` ${o.curve}` : o.size_bits ? ` ${o.size_bits}-bit` : ""}: generated in HSM {yes(o.local) ? "yes" : "no"}
                    {secret && `, sensitive ${yes(o.sensitive) ? "yes" : "no"}, extractable ${o.extractable ? "yes" : "no"}, never extractable ${yes(o.never_extractable) ? "yes" : "no"}`}
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
