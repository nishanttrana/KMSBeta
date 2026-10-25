import type { AuthSession } from "../../lib/auth";
import { RotationSchedulerTab } from "../../components/v3/tabs/RotationSchedulerTab";
import { CryptoperiodPanel } from "../../components/v3/tabs/CryptoperiodPanel";
import { BackupSchedulesPanel } from "../backup/BackupSchedulesPanel";
import { KeyIntegrityView } from "./KeyIntegrityView";
import { ReportsView } from "./ReportsView";
import { ScansView } from "./ScansView";
import { SchedulingOverview } from "./SchedulingOverview";
import { SecretRotationView } from "./SecretRotationView";

// Scheduling (13.66.0-beta): the one home of every schedule in the platform
// (owner, 2026-10-25: "all the scheduling for keys, backup, reporting etc
// anything in the scheduling and secrets schedule should be under
// scheduling"). Each view edits schedules the owning service runs; nothing
// here schedules work a service would not do.

type Props = { session: AuthSession | null; subView?: string; onToast?: (m: string) => void; onNavigate?: (target: string) => void };

export function SchedulingModule({ session, subView, onToast, onNavigate }: Props) {
  if (!session) return null;
  const toast = onToast ?? (() => undefined);
  switch (subView) {
    case "keys": return <RotationSchedulerTab session={session} />;
    case "integrity": return <KeyIntegrityView session={session} onToast={toast} />;
    case "secrets": return <SecretRotationView session={session} onToast={toast} />;
    case "reports": return <ReportsView session={session} onToast={toast} onNavigate={onNavigate} />;
    case "scans": return <ScansView session={session} onToast={toast} />;
    case "backups": return <BackupSchedulesPanel session={session} onToast={toast} />;
    case "cryptoperiods": return <CryptoperiodPanel session={session} />;
    default: return <SchedulingOverview session={session} onOpen={(sub) => onNavigate?.(`scheduling/${sub}`)} />;
  }
}
