import { CheckCircle2, Circle, CircleDashed } from "lucide-react";
import type { ControlCheck, PlatformSnapshot } from "../../../lib/recommendations";
import { C } from "../theme";

export type SetupStep = { id: string; label: string; status: "done" | "todo" | "unknown"; action: { tab: string; label: string } };

const fromCheck = (checks: ControlCheck[], id: string): SetupStep["status"] => {
  const status = checks.find((c) => c.id === id)?.status;
  return status === "pass" ? "done" : status === "fail" ? "todo" : "unknown";
};

// A new tenant's first steps, in order (13.25.0-beta). Each state comes from
// the snapshot or a control check the Command Center already evaluates, so
// no rule is kept twice; "unknown" means the source could not be read.
export function setupSteps(snapshot: PlatformSnapshot | null, checks: ControlCheck[]): SetupStep[] {
  const users = snapshot?.users;
  const defaultAdmin = users?.find((u) => u.username === "admin" && u.must_change_password);
  return [
    { id: "admin-password", label: "Change the default admin password", status: !users ? "unknown" : defaultAdmin ? "todo" : "done", action: { tab: "admin/users", label: "Users" } },
    { id: "first-key", label: "Create your first key", status: !snapshot?.keys ? "unknown" : snapshot.keys.length ? "done" : "todo", action: { tab: "keys", label: "Create key" } },
    { id: "quorum", label: "Require approval to destroy or export keys", status: fromCheck(checks, "quorum"), action: { tab: "approvals/policies", label: "Approvals" } },
    { id: "backup", label: "Take an encrypted backup", status: fromCheck(checks, "backup"), action: { tab: "backup/encrypted", label: "Backup" } },
    { id: "rotation", label: "Turn on automatic key rotation", status: fromCheck(checks, "rotation-policy"), action: { tab: "rotation", label: "Rotation" } },
  ];
}

const ICON = {
  done: { icon: CheckCircle2, color: C.greenFg, text: "done" },
  todo: { icon: Circle, color: C.amberFg, text: "to do" },
  unknown: { icon: CircleDashed, color: C.muted, text: "not assessed" },
};

// Shown until every step is done.
export function SetupChecklist({ steps, onNavigate }: { steps: SetupStep[]; onNavigate?: ((tab: string) => void) | undefined }) {
  const done = steps.filter((s) => s.status === "done").length;
  if (done === steps.length) return null;
  return (
    <div data-testid="setup-checklist" style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 6, padding: "12px 16px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 8 }}>
        <span style={{ fontSize: 14, fontWeight: 600 }}>First steps</span>
        <span style={{ fontSize: 12, color: C.muted }}>{done} of {steps.length} done</span>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 8 }}>
        {steps.map((s) => {
          const look = ICON[s.status];
          return (
            <div key={s.id} data-step={s.id} data-status={s.status} style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: 4, minWidth: 0 }}>
              <look.icon size={15} color={look.color} aria-label={look.text} style={{ flexShrink: 0 }} />
              <span style={{ fontSize: 12.5, color: s.status === "done" ? C.muted : C.text, flex: 1, minWidth: 0, textDecoration: s.status === "done" ? "line-through" : "none" }}>{s.label}</span>
              {s.status !== "done" && onNavigate && (
                <button type="button" onClick={() => onNavigate(s.action.tab)} style={{ fontSize: 12, fontWeight: 600, color: C.accentFg, background: "none", border: 0, cursor: "pointer", whiteSpace: "nowrap" }}>{s.action.label} →</button>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
