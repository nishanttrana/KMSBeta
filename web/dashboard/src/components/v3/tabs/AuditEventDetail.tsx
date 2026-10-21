import type { ReactNode } from "react";
import type { AuditEvent, InvestigateDimension, InvestigatePivots } from "../../../lib/audit";
import { B, Btn, Modal } from "../legacyPrimitives";
import { C } from "../theme";
import { DIMENSION_LABEL, eventOrigin, fmtTS, formatAction, resultTone, shortService } from "./auditFormat";

// One audit event as who, what, on what, when, from where and how, with a
// link from each to everything else it shares (the Investigate view).
const label: React.CSSProperties = { fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6 };
const value: React.CSSProperties = { fontSize: 11, color: C.text, wordBreak: "break-all" };
const mono: React.CSSProperties = { ...value, fontFamily: "var(--font-mono)", fontSize: 10 };

function Part({ title, rows }: { title: string; rows: Array<[string, ReactNode]> }) {
  const shown = rows.filter(([, v]) => v !== "" && v !== null && v !== undefined);
  return (
    <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, padding: "8px 10px" }}>
      <div style={{ ...label, fontWeight: 700, color: C.dim, marginBottom: 6 }}>{title}</div>
      {shown.length === 0 ? <div style={{ fontSize: 10, color: C.muted }}>Not recorded</div> : shown.map(([k, v]) => (
        <div key={k} style={{ marginBottom: 4 }}>
          <div style={label}>{k}</div>
          <div style={value}>{v}</div>
        </div>
      ))}
    </div>
  );
}

export function AuditEventDetail({ event, onClose, onInvestigate }: {
  event: AuditEvent | null;
  onClose: () => void;
  onInvestigate?: (pivots: InvestigatePivots) => void;
}) {
  if (!event) return null;
  const ev = event;
  const d = (ev.details || {}) as Record<string, unknown>;
  const reason = typeof d.reason === "string" ? d.reason : "";
  const origin = eventOrigin(ev);
  const pivots: Array<[InvestigateDimension, string, string]> = [
    ["actor_id", ev.actor_id, `Everything by ${ev.actor_id}`],
    ["target_id", ev.target_id, `Everything on ${ev.target_id}`],
    ["source_ip", ev.source_ip, `Everything from ${ev.source_ip}`],
    ["session_id", ev.session_id, "This sign-in session"],
    ["correlation_id", ev.correlation_id, "This request, every service"],
  ];
  return (
    <Modal open onClose={onClose} title="Audit Event" wide>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 12 }}>
        <span style={{ fontSize: 14, fontWeight: 700, color: C.text }}>{formatAction(ev.action)}</span>
        <B c={resultTone(ev.result)}>{ev.result}</B>
        <span style={{ fontSize: 10, color: C.muted }}>{fmtTS(ev.timestamp)}</span>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 8, marginBottom: 12 }}>
        <Part title={DIMENSION_LABEL.actor_id} rows={[
          ["Actor", ev.actor_id ? `${ev.actor_id}${ev.actor_type ? ` (${ev.actor_type})` : ""}` : ""],
          ["Sign-in session", ev.session_id ? <span style={mono}>{ev.session_id}</span> : ""],
          ["Origin", origin.origin === "agent" ? `agent ${origin.agentId}`.trim() : ""],
        ]} />
        <Part title={DIMENSION_LABEL.action} rows={[
          ["Action", <span style={mono}>{ev.action}</span>],
          ["Outcome", ev.result],
          ["Reason", reason || ev.error_message],
          ["Approval", ev.approval_id],
        ]} />
        <Part title={DIMENSION_LABEL.target_id} rows={[
          ["Object", ev.target_id ? `${ev.target_id}${ev.target_type ? ` (${ev.target_type})` : ""}` : ""],
        ]} />
        <Part title="When" rows={[
          ["Time", fmtTS(ev.timestamp)],
          ["Took", ev.duration_ms ? `${ev.duration_ms} ms` : ""],
        ]} />
        <Part title="Where from" rows={[
          ["Address", ev.source_ip],
          ["Service", shortService(ev.service)],
          ["Node", ev.node_id],
        ]} />
        <Part title="How" rows={[
          ["Request", ev.method || ev.endpoint ? <span style={mono}>{`${ev.method} ${ev.endpoint}`.trim()}</span> : ""],
          ["Client", ev.user_agent],
          ["Status", ev.status_code ? String(ev.status_code) : ""],
          ["FIPS", ev.fips_compliant ? "approved algorithms" : ""],
        ]} />
      </div>

      {onInvestigate && (
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
          {pivots.filter(([, v]) => v).map(([dim, v, text]) => (
            <Btn key={dim} small onClick={() => { onClose(); onInvestigate({ [dim]: v }); }}>{text}</Btn>
          ))}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 8, marginBottom: 10 }}>
        <Part title="Integrity" rows={[
          ["Sequence", String(ev.sequence)],
          ["Chain hash", <span style={mono}>{ev.chain_hash}</span>],
          ["Previous hash", <span style={mono}>{ev.previous_hash}</span>],
          ["Event ID", <span style={mono}>{ev.id}</span>],
          ["Request", ev.correlation_id ? <span style={mono}>{ev.correlation_id}</span> : ""],
        ]} />
      </div>

      {Object.keys(d).length > 0 && (
        <>
          <div style={{ ...label, marginBottom: 4 }}>Details</div>
          <pre style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 3, padding: 10, fontSize: 10, color: C.dim, overflow: "auto", maxHeight: 160, fontFamily: "var(--font-mono)" }}>
            {JSON.stringify(d, null, 2)}
          </pre>
        </>
      )}
      {Array.isArray(ev.tags) && ev.tags.length > 0 && (
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 8 }}>
          {ev.tags.map((t) => <B key={t} c="neutral">{t}</B>)}
        </div>
      )}
    </Modal>
  );
}
