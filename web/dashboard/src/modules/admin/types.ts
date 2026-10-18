import type { AuthSession } from "../../lib/auth";

// "tenant", "users", or a System Administration section (SystemAdminTab).
export type AdminSubView = string;

export type AdminTabProps = {
  session: AuthSession | null;
  tagCatalog: unknown[];
  setTagCatalog: (next: unknown[]) => void;
  onToast: (message: string) => void;
  onLogout: () => void;
  fipsMode: "enabled" | "disabled";
  onFipsModeChange: (mode: "enabled" | "disabled") => void;
  subView?: string;
};
