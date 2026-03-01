import type { AuthSession } from "../../lib/auth";

export type AdminSubView = "system" | "tenant" | "users" | "docs";

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
