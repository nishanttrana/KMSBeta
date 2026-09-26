import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../lib/auth";
import { listAuditEvents, type AuditEvent } from "../../lib/audit";
import { Btn, Card } from "../../components/v3/legacyPrimitives";
import { errMsg } from "../../components/v3/runtimeUtils";
import { C } from "../../components/v3/theme";

// Every HSM operation and refusal is audited (docs/SECURITY/HSM_INTEGRATION.md):
// the connector's audit.hsm.* events (generate, encrypt, decrypt, sign,
// verify, destroy, inspect, list) and keycore's audit.key.hsm_* decisions.
// This lists them from the tamper-evident audit log for this tenant.
const HSM_ACTION_PREFIXES = ["audit.hsm.", "audit.key.hsm_"];

export function HSMActivityPanel({ session, onToast }: { session: AuthSession | null; onToast?: (msg: string) => void }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    if (!session) return;
    setLoading(true);
    try {
      setEvents(await listAuditEvents(session, { action_prefix: HSM_ACTION_PREFIXES, limit: 50 }));
    } catch (e) {
      onToast?.(`HSM activity failed: ${errMsg(e)}`);
    } finally {
      setLoading(false);
    }
  }, [session, onToast]);

  useEffect(() => {
    void load();
  }, [load]);

  const tone = (r: string) => (r === "success" ? C.green : r === "refused" ? C.amber : C.red);
  return (
    <Card style={{ padding: 12, marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", marginBottom: 8 }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>HSM activity (audit log)</div>
        <div style={{ marginLeft: "auto" }}>
          <Btn small onClick={() => void load()} disabled={loading}>{loading ? "Loading..." : "Refresh"}</Btn>
        </div>
      </div>
      {events.length === 0 ? (
        <div style={{ fontSize: 10, color: C.muted }}>{loading ? "Loading..." : "No HSM activity recorded for this tenant yet."}</div>
      ) : (
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 10 }}>
          <thead>
            <tr style={{ color: C.muted, textAlign: "left" }}>
              <th style={{ padding: "4px 6px" }}>Time</th>
              <th style={{ padding: "4px 6px" }}>Action</th>
              <th style={{ padding: "4px 6px" }}>Caller</th>
              <th style={{ padding: "4px 6px" }}>Object</th>
              <th style={{ padding: "4px 6px" }}>Result</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => {
              const reason = String((e.details as Record<string, unknown> | undefined)?.reason || "");
              return (
                <tr key={e.id} style={{ borderTop: `1px solid ${C.border}`, color: C.text }}>
                  <td style={{ padding: "4px 6px", whiteSpace: "nowrap" }}>{new Date(e.timestamp).toLocaleString()}</td>
                  <td style={{ padding: "4px 6px", fontFamily: "'JetBrains Mono',monospace" }}>{e.action.replace(/^audit\./, "")}</td>
                  <td style={{ padding: "4px 6px" }}>{e.actor_id || "-"}</td>
                  <td style={{ padding: "4px 6px", fontFamily: "'JetBrains Mono',monospace", maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={e.target_id}>{e.target_id || "-"}</td>
                  <td style={{ padding: "4px 6px", color: tone(e.result) }}>{e.result}{reason ? `: ${reason}` : ""}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </Card>
  );
}
