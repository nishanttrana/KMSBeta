import { BackupTab } from "../../components/v3/tabs/BackupTab";
import type { AuthSession } from "../../lib/auth";
import { EncryptedBackupsPanel } from "./EncryptedBackupsPanel";

// Backup & Restore is the one home for backups (owner, 2026-10-20). Its
// sub-options: Encrypted Backups (real, root administrators only) and
// Schedules (the labelled preview scheduler).
export function BackupModule({ session, onToast, onLogout, subView }: {
  session: AuthSession | null;
  onToast: (message: string) => void;
  onLogout: () => void;
  subView?: string;
}) {
  if (subView === "encrypted") return <EncryptedBackupsPanel session={session} onToast={onToast} onLogout={onLogout} />;
  return <BackupTab session={session} />;
}
