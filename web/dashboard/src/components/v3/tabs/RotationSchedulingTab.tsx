// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
// Merged "Rotation & Scheduling" tab: the mature rotation-policy scheduler and
// the generic maintenance-job scheduler under one nav entry. Rotation is owned
// by the Rotation Policies view; the Scheduled Jobs view covers non-rotation
// maintenance (verify/backup/archive), so the two no longer overlap.
import { useState } from "react";
import { Repeat, CalendarClock } from "lucide-react";
import { C } from "../../v3/theme";
import { RotationSchedulerTab } from "./RotationSchedulerTab";
import { KeySchedulingTab } from "./KeySchedulingTab";

export function RotationSchedulingTab({ session }: any) {
  const [view, setView] = useState<"rotation" | "jobs">("rotation");
  const tabs = [
    { id: "rotation", label: "Rotation Policies", icon: Repeat },
    { id: "jobs", label: "Scheduled Jobs", icon: CalendarClock },
  ] as const;
  return (
    <div>
      <div style={{ display: "flex", gap: 8, padding: "16px 24px 0" }}>
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setView(id)}
            style={{
              display: "inline-flex", alignItems: "center", gap: 6, padding: "6px 14px",
              borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer",
              border: `1px solid ${C.border}`,
              background: view === id ? C.accent : "transparent",
              color: view === id ? C.bg : C.dim,
            }}
          >
            <Icon size={13} /> {label}
          </button>
        ))}
      </div>
      {view === "rotation"
        ? <RotationSchedulerTab session={session} />
        : <KeySchedulingTab session={session} />}
    </div>
  );
}
