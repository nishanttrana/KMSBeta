import { APPROVAL_ACTIONS } from "../../../lib/approvalActions";
import { Chk } from "../legacyPrimitives";
import { C } from "../theme";

const split = (value: string) => value.split(",").map((s) => s.trim()).filter(Boolean);
const norm = (s: string) => s.toLowerCase().replace(/_/g, "-");

// Checkboxes for the actions services really submit for approval, kept in
// step with the comma-separated pattern box (13.27.0-beta). Ticking adds an
// action, unticking removes it; patterns typed by hand stay as they are.
export function ApprovalTriggerPicker({ value, onChange }: { value: string; onChange: (next: string) => void }) {
  const chosen = split(value);
  const has = (action: string) => chosen.some((c) => norm(c) === action);
  const toggle = (action: string) =>
    onChange((has(action) ? chosen.filter((c) => norm(c) !== action) : [...chosen, action]).join(", "));
  return (
    <div data-testid="approval-trigger-picker" style={{ display: "grid", gap: 8, marginTop: 6 }}>
      {APPROVAL_ACTIONS.map((g) => (
        <div key={g.group}>
          <div style={{ fontSize: 11, fontWeight: 600, color: C.text }} title={`Used when ${g.when}`}>{g.group}</div>
          <div style={{ fontSize: 10, color: C.muted, marginBottom: 4 }}>when {g.when}</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(190px, 1fr))", gap: "0 10px" }}>
            {g.actions.map((a) => <Chk key={a.action} label={a.label} checked={has(a.action)} onChange={() => toggle(a.action)} />)}
          </div>
        </div>
      ))}
    </div>
  );
}
