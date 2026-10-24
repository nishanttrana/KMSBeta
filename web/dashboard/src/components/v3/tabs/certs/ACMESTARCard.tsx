import { Clock } from "lucide-react";
import { B, Btn, Card } from "../../legacyPrimitives";
import { C } from "../../theme";

type Props = {
  star: any;
  renewal: any;
  refreshing: boolean;
  busy: string;
  onRefresh: () => void;
  onNew: () => void;
  onRenew: (item: any) => void;
  onDelete: (item: any) => void;
};

const when = (v: unknown) => { const t = new Date(String(v || "")); return Number.isNaN(t.getTime()) ? "-" : t.toLocaleString(); };
const statusTone = (s: string) => s === "active" ? "green" : s === "error" ? "red" : "amber";

// ACME STAR (short-term, automatically renewed) subscriptions, beside the
// ACME protocol that serves them in Certificates → Enrollment Protocols.
export function ACMESTARCard({ star, renewal, refreshing, busy, onRefresh, onNew, onRenew, onDelete }: Props) {
  const subs: any[] = Array.isArray(star?.subscriptions) ? star.subscriptions : [];
  const risks: any[] = Array.isArray(star?.mass_rollout_risks) ? star.mass_rollout_risks : [];
  const n = (k: string, alt: string) => Number(star?.[k] || renewal?.[alt] || 0);
  return (
    <div data-testid="acme-star" style={{ marginTop: 10 }}><Card style={{ padding: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, marginBottom: 6 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Clock size={14} color={star?.enabled === false ? C.red : C.accent} />
          <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>ACME STAR subscriptions</span>
          {star?.enabled === false ? <B c="red">disabled in ACME policy</B> : null}
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          <Btn small onClick={onRefresh} disabled={refreshing}>{refreshing ? "Refreshing…" : "Refresh"}</Btn>
          <Btn small primary onClick={onNew}>New</Btn>
        </div>
      </div>
      {star?.enabled !== false ? (
        <div style={{ fontSize: 10, color: C.muted, marginBottom: 8 }}>
          {`Subscriptions ${n("subscription_count", "star_subscription_count")} • Delegated ${n("delegated_count", "star_delegated_count")} • Due soon ${n("due_soon_count", "star_due_soon_count")}`}
        </div>
      ) : null}
      <div style={{ display: "grid", gap: 8 }}>
        {subs.map((item) => {
          const status = String(item.status || "active").toLowerCase();
          return (
            <div key={item.id} style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center", borderBottom: `1px solid ${C.border}`, paddingBottom: 6 }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 11, color: C.text, fontWeight: 700, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(item.name || item.subject_cn || item.id)}</div>
                <div style={{ fontSize: 10, color: C.dim, marginTop: 3 }}>
                  {`${String(item.subject_cn || "-")} • ${item.validity_hours || 24}h • ${item.delegated_subscriber ? `delegated to ${item.delegated_subscriber}` : "tenant-managed"} • next ${when(item.next_renewal_at)}`}
                </div>
                {item.last_error ? <div style={{ fontSize: 10, color: C.redFg, marginTop: 3 }}>{String(item.last_error)}</div> : null}
              </div>
              <div style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                <B c={statusTone(status)}>{status}</B>
                <Btn small onClick={() => onRenew(item)} disabled={busy === `star-refresh-${item.id}`}>Renew</Btn>
                <Btn small danger onClick={() => onDelete(item)} disabled={busy === `star-delete-${item.id}`}>Delete</Btn>
              </div>
            </div>
          );
        })}
        {!subs.length ? <div style={{ fontSize: 10, color: C.muted }}>No STAR subscriptions yet.</div> : null}
        {risks.map((risk) => (
          <div key={`star-risk-${risk.rollout_group}`} style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center", borderTop: `1px dashed ${C.border}`, paddingTop: 6 }}>
            <span style={{ fontSize: 10, color: C.text, fontWeight: 700 }}>{`Rollout ${String(risk.rollout_group || "-")} • ${when(risk.scheduled_start)} → ${when(risk.scheduled_end)}`}</span>
            <B c={String(risk.risk_level || "medium").toLowerCase() === "high" ? "red" : "amber"}>{`${risk.count} subs`}</B>
          </div>
        ))}
      </div>
    </Card></div>
  );
}
