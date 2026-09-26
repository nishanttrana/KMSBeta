import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../lib/auth";
import { listHSMObjects, type HSMIdentity, type HSMObjectInfo } from "../../lib/keycore";
import { Btn, Card } from "../../components/v3/legacyPrimitives";
import { errMsg } from "../../components/v3/runtimeUtils";
import { C } from "../../components/v3/theme";

const flag = (v: boolean | undefined) => (v === undefined ? "-" : v ? "yes" : "no");

// The keys or certificates in the tenant's HSM partition, as the HSM reports
// them: objects the KMS created for this tenant ("KMS") and objects that were
// already there ("found in HSM"). Read-only; key values are never read.
export function HSMPartitionTable({ session, kind, onToast }: { session: AuthSession | null; kind: "keys" | "certificates"; onToast?: (msg: string) => void }) {
  const [objects, setObjects] = useState<HSMObjectInfo[]>([]);
  const [hsm, setHsm] = useState<HSMIdentity>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    if (!session) return;
    setLoading(true);
    setError("");
    try {
      const out = await listHSMObjects(session);
      setObjects(out.objects.filter((o) => (kind === "certificates" ? o.class === "certificate" : o.class !== "certificate")));
      setHsm(out.hsm);
    } catch (e) {
      setError(errMsg(e));
      onToast?.(`HSM partition failed: ${errMsg(e)}`);
    } finally {
      setLoading(false);
    }
  }, [session, kind, onToast]);

  useEffect(() => {
    void load();
  }, [load]);

  const th = { padding: "4px 6px", textAlign: "left" as const, color: C.muted, fontWeight: 600 };
  const td = { padding: "4px 6px", borderTop: `1px solid ${C.border}`, color: C.text };
  return (
    <Card style={{ padding: 12, marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", marginBottom: 6 }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>
          HSM partition {kind}{hsm.token_label ? `: token "${hsm.token_label}"` : ""}{hsm.model ? ` (${[hsm.manufacturer, hsm.model].filter(Boolean).join(" ")}${hsm.serial_number ? `, serial ${hsm.serial_number}` : ""})` : ""}
        </div>
        <div style={{ marginLeft: "auto" }}>
          <Btn small onClick={() => void load()} disabled={loading}>{loading ? "Reading HSM..." : "Refresh"}</Btn>
        </div>
      </div>
      {error && <div style={{ fontSize: 10, color: C.red, marginBottom: 6 }}>{error}</div>}
      {!error && objects.length === 0 && <div style={{ fontSize: 10, color: C.muted }}>{loading ? "Reading HSM..." : `No ${kind} in the partition.`}</div>}
      {objects.length > 0 && (
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 10 }}>
          <thead>
            {kind === "certificates" ? (
              <tr><th style={th}>Label</th><th style={th}>Subject</th><th style={th}>Issuer</th><th style={th}>Serial</th><th style={th}>Expires</th><th style={th}>Source</th></tr>
            ) : (
              <tr><th style={th}>Label</th><th style={th}>Class</th><th style={th}>Type</th><th style={th}>Generated in HSM</th><th style={th}>Sensitive</th><th style={th}>Extractable</th><th style={th}>Source</th></tr>
            )}
          </thead>
          <tbody>
            {objects.map((o, i) => (
              <tr key={`${o.label}-${o.class}-${i}`}>
                <td style={{ ...td, fontFamily: "'JetBrains Mono',monospace", maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={o.label}>{o.label || "(no label)"}</td>
                {kind === "certificates" ? (
                  <>
                    <td style={td}>{o.certificate?.subject || "-"}</td>
                    <td style={td}>{o.certificate?.issuer || "-"}</td>
                    <td style={{ ...td, fontFamily: "'JetBrains Mono',monospace" }}>{o.certificate?.serial || "-"}</td>
                    <td style={td}>{o.certificate?.not_after ? new Date(o.certificate.not_after).toLocaleDateString() : "-"}</td>
                  </>
                ) : (
                  <>
                    <td style={td}>{o.class.replace("_", " ")}</td>
                    <td style={td}>{[o.key_type, o.curve || (o.size_bits ? `${o.size_bits}-bit` : "")].filter(Boolean).join(" ") || "-"}</td>
                    <td style={td}>{flag(o.local)}</td>
                    <td style={td}>{flag(o.sensitive)}</td>
                    <td style={{ ...td, color: o.extractable ? C.amber : C.text }}>{flag(o.extractable)}</td>
                  </>
                )}
                <td style={{ ...td, color: o.managed ? C.accent : C.muted }}>
                  {o.managed ? (o.kms_role === "tenant_key" ? "KMS tenant key" : o.key_id ? `KMS key ${o.key_id} v${o.version}` : "KMS") : "found in HSM"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}
