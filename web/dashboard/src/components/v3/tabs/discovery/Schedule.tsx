import { useEffect, useState } from "react";
import { Btn, Modal } from "../../legacyPrimitives";
import { C } from "../../theme";
import { errMsg } from "../../runtimeUtils";
import { saveDiscoverySchedule, type DiscoverySchedule, type DiscoverySource } from "../../../../lib/discovery";
import type { AuthSession } from "../../../../lib/auth";
import { SCANNABLE, absTime, relTime, sourceMeta } from "./meta";

const INTERVALS = [[6, "Every 6 hours"], [12, "Every 12 hours"], [24, "Daily"], [168, "Weekly"]] as const;

// scheduleLabel is the header button's text for a schedule.
export function scheduleLabel(s: DiscoverySchedule | null): string {
  if (!s || !s.enabled) return "Schedule";
  if (s.paused_reason) return "Schedule paused";
  return INTERVALS.find(([h]) => h === s.interval_hours)?.[1] ?? `Every ${s.interval_hours}h`;
}

type Props = {
  open: boolean;
  onClose: () => void;
  session: AuthSession;
  schedule: DiscoverySchedule | null;
  sources: DiscoverySource[];
  onSaved: (s: DiscoverySchedule) => void;
  onToast?: (msg: string) => void;
};

export function ScheduleModal({ open, onClose, session, schedule, sources, onSaved, onToast }: Props) {
  const [enabled, setEnabled] = useState(false);
  const [hours, setHours] = useState(24);
  const [picked, setPicked] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const configured = (id: string) => !!sources.find((s) => s.id === id)?.configured;

  useEffect(() => {
    if (!open) return;
    setEnabled(!!schedule?.enabled);
    setHours(schedule?.interval_hours || 24);
    setPicked(schedule?.sources?.length ? schedule.sources : SCANNABLE.filter(configured));
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: reset the form when the dialog opens.
  }, [open]);

  const save = async () => {
    setBusy(true);
    try {
      const saved = await saveDiscoverySchedule(session, { enabled, interval_hours: hours, sources: picked });
      onSaved(saved);
      onToast?.(saved.enabled ? `Scheduled: ${scheduleLabel(saved).toLowerCase()}, next ${absTime(saved.next_run_at)}` : "Schedule turned off");
      onClose();
    } catch (e) {
      onToast?.(`Schedule not saved: ${errMsg(e)}`);
    } finally {
      setBusy(false);
    }
  };
  const pill = (on: boolean) => ({
    border: `1px solid ${on ? C.accentFg : C.border}`, background: on ? C.accentDim : "transparent", color: on ? C.accentFg : C.muted,
    borderRadius: 7, padding: "6px 12px", fontSize: 11, fontWeight: 600, cursor: "pointer",
  });

  return (
    <Modal open={open} onClose={onClose} title="Scan schedule">
      {schedule?.paused_reason && (
        <div style={{ fontSize: 11.5, color: C.amberFg, border: `1px solid ${C.amberFg}`, borderRadius: 8, padding: "8px 10px", marginBottom: 12 }}>
          Paused: {schedule.paused_reason}
        </div>
      )}
      <div style={{ display: "flex", gap: 6, marginBottom: 14 }}>
        <button type="button" style={pill(!enabled)} onClick={() => setEnabled(false)}>Off</button>
        <button type="button" style={pill(enabled)} onClick={() => setEnabled(true)}>On</button>
      </div>
      <div style={{ opacity: enabled ? 1 : 0.5, pointerEvents: enabled ? "auto" : "none" }}>
        <div style={{ fontSize: 11, color: C.muted, marginBottom: 6 }}>How often</div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 14 }}>
          {INTERVALS.map(([h, label]) => <button key={h} type="button" style={pill(hours === h)} onClick={() => setHours(h)}>{label}</button>)}
        </div>
        <div style={{ fontSize: 11, color: C.muted, marginBottom: 6 }}>Sources</div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 14 }}>
          {SCANNABLE.map((id) => {
            const on = picked.includes(id);
            const M = sourceMeta(id);
            const Icon = M.icon;
            return (
              <button key={id} type="button" title={configured(id) ? "" : "Not set up yet: it will report an error until it is"}
                style={{ ...pill(on), display: "inline-flex", alignItems: "center", gap: 6, opacity: configured(id) ? 1 : 0.6 }}
                onClick={() => setPicked(on ? picked.filter((p) => p !== id) : [...picked, id])}>
                <Icon size={12} />{M.label}
              </button>
            );
          })}
        </div>
      </div>
      {schedule?.enabled && !schedule.paused_reason && (
        <div style={{ fontSize: 11, color: C.muted, marginBottom: 12 }}>
          Next run {absTime(schedule.next_run_at)}{relTime(schedule.last_run_at) !== "-" ? ` · last run ${relTime(schedule.last_run_at)}` : ""} · saved by {schedule.authorized_by}
        </div>
      )}
      <div style={{ fontSize: 10.5, color: C.muted, marginBottom: 12 }}>Runs on your permission to scan, which is checked again before each run.</div>
      <Btn primary onClick={() => void save()} disabled={busy || (enabled && !picked.length)}>{busy ? "Saving..." : "Save"}</Btn>
    </Modal>
  );
}
