import type { AuthSession } from "../../lib/auth";
import { createPolicy } from "../../lib/rotationScheduler";
import { FG, Inp, Sel } from "../../components/v3/legacyPrimitives";

// A rotation schedule set while creating a key. It is one of keycore's
// rotation policies with the filter id:<key id> and auto_rotate on, so it
// runs, is listed and is audited like any other (Rotation & Scheduling).
// Creating it needs key.rotation.write; the field is not shown without it.

export const NO_ROTATION = "";
const PRESETS = [30, 90, 180, 365];
const MAX_DAYS = 3650;

// rotationDays reads the field's value: 0 for none, NaN when not 1-3650.
export function rotationDays(value: string): number {
  if (value === NO_ROTATION) return 0;
  const n = Number(value);
  return Number.isInteger(n) && n >= 1 && n <= MAX_DAYS ? n : Number.NaN;
}

export function mayScheduleRotation(session: AuthSession | null): boolean {
  return (session?.permissions || []).some((p) => p === "*" || p === "key.*" || p === "key.rotation.*" || p === "key.rotation.write");
}

export async function scheduleRotation(session: AuthSession, keyId: string, keyName: string, days: number): Promise<void> {
  await createPolicy(session, { name: keyName, target_filter: `id:${keyId}`, interval_days: days, auto_rotate: true });
}

type Props = { value: string; onChange: (value: string) => void };

export function RotationScheduleField({ value, onChange }: Props) {
  const custom = value !== NO_ROTATION && !PRESETS.includes(Number(value));
  return (
    <FG label="Rotation">
      <div style={{ display: "grid", gridTemplateColumns: custom ? "1fr 1fr" : "1fr", gap: 10 }}>
        <Sel aria-label="Rotation schedule" value={custom ? "custom" : value} onChange={(e) => onChange(e.target.value === "custom" ? "60" : e.target.value)}>
          <option value={NO_ROTATION}>No schedule</option>
          {PRESETS.map((d) => <option key={d} value={String(d)}>{`Every ${d} days`}</option>)}
          <option value="custom">Other interval (days)</option>
        </Sel>
        {custom && <Inp aria-label="Rotation interval in days" type="number" min={1} max={MAX_DAYS} placeholder="Days (1-3650)" value={value} onChange={(e) => onChange(e.target.value)} />}
      </div>
    </FG>
  );
}
