import type { AuthSession } from "../../lib/auth";
import { EncryptedBackupsPanel } from "./EncryptedBackupsPanel";

// Backup & Restore is the one home for backups (owner, 2026-10-20), root
// administrators only. Backup schedules moved to Scheduling → Backups
// (13.66.0-beta), the home of every schedule.
export function BackupModule({ session, onToast, onLogout }: {
  session: AuthSession | null;
  onToast: (message: string) => void;
  onLogout: () => void;
  subView?: string;
}) {
  return <EncryptedBackupsPanel session={session} onToast={onToast} onLogout={onLogout} />;
}
