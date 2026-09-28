import { useEffect, useState } from "react";
import type { AuthSession } from "../../lib/auth";
import { getAuditTimeline, verifyTargetIntegrity, type AuditEvent, type AuditEventIntegrity, type AuditTargetIntegrity } from "../../lib/audit";
import { getKeyConsumers, type KeyConsumers } from "../../lib/keyConsumers";
import { Btn } from "../../components/v3/legacyPrimitives";
import { errMsg } from "../../components/v3/runtimeUtils";
import { C } from "../../components/v3/theme";

const when = (ts?: string) => (ts ? new Date(ts).toLocaleString() : "-");
const shortAction = (a: string) => String(a || "").replace(/^audit\./, "");

// One event's integrity as a short line: what failed, or how far it is proven.
function integrityNote(r: AuditEventIntegrity | undefined): { text: string; color: string } | null {
  if (!r) return null;
  if (r.failures?.length) return { text: `FAILED: ${r.failures.join(", ")}`, color: C.red };
  const sig = r.signature === "verified" ? "HMAC ok" : r.signature === "unsigned" ? "unsigned" : "HMAC not checked";
  const seal = r.seal === "sealed" ? `covered by signed checkpoint at #${r.checkpoint_sequence}` : "awaiting next signed checkpoint";
  return { text: `chain ok, ${sig}, ${seal}`, color: r.seal === "sealed" && r.signature === "verified" ? C.green : C.amber };
}

// "History & usage" on a key: its audit timeline with a real integrity proof
// (GET /audit/targets/{id}/integrity), the callers seen in keycore's usage
// trail, and what a rotation or deletion would affect. Nothing here is
// inferred: a section that can't load says so with the error.
export function KeyHistoryPanel({ session, keyID }: { session: AuthSession | null; keyID: string }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [eventsError, setEventsError] = useState("");
  const [usage, setUsage] = useState<KeyConsumers | null>(null);
  const [usageError, setUsageError] = useState("");
  const [proof, setProof] = useState<AuditTargetIntegrity | null>(null);
  const [proofError, setProofError] = useState("");
  const [verifying, setVerifying] = useState(false);

  useEffect(() => {
    if (!session || !keyID) return;
    let live = true;
    setProof(null);
    setProofError("");
    getAuditTimeline(session, keyID, { limit: 100 })
      .then((items) => { if (live) { setEvents(items); setEventsError(""); } })
      .catch((e) => { if (live) { setEvents([]); setEventsError(errMsg(e)); } });
    getKeyConsumers(session, keyID)
      .then((out) => { if (live) { setUsage(out); setUsageError(""); } })
      .catch((e) => { if (live) { setUsage(null); setUsageError(errMsg(e)); } });
    return () => { live = false; };
  }, [session, keyID]);

  const verify = async () => {
    if (!session) return;
    setVerifying(true);
    setProofError("");
    try {
      setProof(await verifyTargetIntegrity(session, keyID));
    } catch (e) {
      setProof(null);
      setProofError(errMsg(e));
    } finally {
      setVerifying(false);
    }
  };

  const byEvent = new Map((proof?.events || []).map((r) => [r.event_id, r]));
  const impact = usage?.impact;
  const versions = Object.entries(impact?.versions_by_status || {}).map(([s, n]) => `${n} ${s}`).join(", ");
  const box = { marginTop: 10, padding: 10, border: `1px solid ${C.border}`, borderRadius: 6 };
  const h = { fontSize: 11, fontWeight: 700, color: C.text };
  const line = { fontSize: 10, color: C.dim, padding: "3px 0" };

  return (
    <div style={box}>
      <div style={{ ...h, fontSize: 12 }}>History &amp; usage</div>

      <div style={{ display: "flex", alignItems: "center", marginTop: 8 }}>
        <div style={h}>Timeline</div>
        <div style={{ marginLeft: "auto" }}>
          <Btn small onClick={() => void verify()} disabled={verifying || !events.length}>{verifying ? "Verifying..." : "Verify integrity"}</Btn>
        </div>
      </div>
      {proofError && <div style={{ fontSize: 10, color: C.red, marginTop: 4 }}>Verification unavailable: {proofError}</div>}
      {proof && (
        <div style={{ fontSize: 10, marginTop: 4, color: proof.verdict === "tampered" ? C.red : C.green }}>
          {proof.verdict === "tampered"
            ? `Tampering detected: ${proof.failed} of ${proof.events_checked} events failed verification. A critical chain_broken audit event was raised.`
            : proof.verdict === "no_events"
              ? "No audit events name this key."
              : `Intact: ${proof.events_checked} events recomputed from storage and chained; ${proof.sealed} proven against signed checkpoints, ${proof.pending} awaiting the next checkpoint.`}
          {!proof.signing_key_configured && <span style={{ color: C.amber }}> HMAC signatures not checked: this node holds no audit signing key.</span>}
          {proof.unsigned > 0 && <span style={{ color: C.amber }}> {proof.unsigned} events carry no HMAC.</span>}
          {proof.truncated && <span style={{ color: C.amber }}> Only the newest {proof.events_checked} events were checked.</span>}
        </div>
      )}
      {eventsError && <div style={{ fontSize: 10, color: C.red, marginTop: 4 }}>Timeline unavailable: {eventsError}</div>}
      <div style={{ maxHeight: 220, overflowY: "auto", marginTop: 4 }}>
        {events.map((e) => {
          const note = integrityNote(byEvent.get(e.id));
          return (
            <div key={e.id} style={{ ...line, borderBottom: `1px solid ${C.border}` }}>
              <span style={{ fontFamily: "'JetBrains Mono',monospace", color: C.muted }}>{when(e.timestamp)}</span>{" "}
              <span style={{ color: C.text }}>{shortAction(e.action)}</span>{" "}
              by {e.actor_id || "-"}{" "}
              <span style={{ color: e.result === "success" ? C.green : e.result === "refused" ? C.amber : C.red }}>{e.result}</span>
              {note && <div style={{ color: note.color }}>{note.text}</div>}
            </div>
          );
        })}
        {!eventsError && !events.length && <div style={line}>No audit events name this key.</div>}
      </div>

      <div style={{ ...h, marginTop: 12 }}>Used by</div>
      {usageError && <div style={{ fontSize: 10, color: C.red, marginTop: 4 }}>Usage unavailable: {usageError}</div>}
      {usage && (
        <>
          <div style={{ fontSize: 9, color: C.muted, marginTop: 2 }}>
            Crypto operations recorded on this node in the last {usage.window_days} days.
          </div>
          {usage.consumers.map((c) => (
            <div key={`${c.actor_id}|${c.interface}`} style={{ ...line, borderBottom: `1px solid ${C.border}` }}>
              <span style={{ color: C.text }}>{c.actor_id || "unknown actor"}</span>
              {c.interface && <span style={{ color: C.muted }}> via {c.interface}</span>}
              {" - "}
              {Object.entries(c.operations).map(([op, n]) => `${op} ${n}`).join(", ")}
              <span style={{ color: C.muted }}> - last {when(c.last_seen)}</span>
            </div>
          ))}
          {!usage.consumers.length && <div style={line}>No crypto operations on this key in that window.</div>}
        </>
      )}

      <div style={{ ...h, marginTop: 12 }}>Before you rotate or delete</div>
      {impact && (
        <div style={{ fontSize: 10, color: C.text, marginTop: 4, display: "grid", gap: 4 }}>
          <div>
            {impact.active_callers
              ? `${impact.active_callers} caller${impact.active_callers === 1 ? "" : "s"} used this key in the last ${usage?.window_days} days${impact.interfaces.length ? ` (${impact.interfaces.join(", ")})` : ""}; last use ${when(impact.last_used_at)}.`
              : `No recorded callers in the last ${usage?.window_days} days on this node.`}
          </div>
          <div>
            Rotate: new operations use v{impact.current_version + 1}. By default v{impact.current_version} is deactivated; the rotate dialog can keep it active or destroy it.
          </div>
          <div style={{ color: impact.active_callers ? C.amber : C.text }}>
            Delete: {impact.active_callers ? "every caller above loses this key." : "no recorded caller is affected on this node; other nodes keep their own usage trail."}
          </div>
          {versions && <div style={{ color: C.muted }}>Versions: {versions}.</div>}
          {impact.approval_required && <div style={{ color: C.muted }}>Crypto operations on this key require governance approval.</div>}
        </div>
      )}
      {!impact && !usageError && <div style={line}>Loading...</div>}
      {!impact && usageError && <div style={{ ...line, color: C.muted }}>Impact needs the usage data above.</div>}
    </div>
  );
}
