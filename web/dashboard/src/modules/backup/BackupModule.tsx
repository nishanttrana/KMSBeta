import type { AuthSession } from "../../lib/auth";
import { BackupSchedulesPanel } from "./BackupSchedulesPanel";
import { EncryptedBackupsPanel } from "./EncryptedBackupsPanel";

// Backup & Restore is the one home for backups (owner, 2026-10-20). Its
// sub-options: Encrypted Backups and Schedules (13.43.0-beta: real
// scheduled backups replaced the preview), both root administrators only.
export function BackupModule({ session, onToast, onLogout, subView }: {
  session: AuthSession | null;
  onToast: (message: string) => void;
  onLogout: () => void;
  subView?: string;
}) {
  if (subView === "schedules") return <BackupSchedulesPanel session={session} onToast={onToast} />;
  return <EncryptedBackupsPanel session={session} onToast={onToast} onLogout={onLogout} />;
}
