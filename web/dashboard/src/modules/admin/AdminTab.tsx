import type { AdminSubView, AdminTabProps } from "./types";
import { DocsTab } from "./DocsTab";
import { SystemAdminTab } from "./SystemAdminTab";
import { TenantAdminTab } from "./TenantAdminTab";
import { UserAdminTab } from "./UserAdminTab";

const normalizeAdminView = (value: unknown): AdminSubView => {
  const raw = String(value || "system").trim().toLowerCase();
  if (raw === "tenant") return "tenant";
  if (raw === "users") return "users";
  if (raw === "docs") return "docs";
  return "system";
};

export const AdminTab = (props: AdminTabProps) => {
  const view = normalizeAdminView(props.subView);
  if (view === "tenant") {
    return <TenantAdminTab {...props} />;
  }
  if (view === "users") {
    return <UserAdminTab {...props} />;
  }
  if (view === "docs") {
    return <DocsTab />;
  }
  return <SystemAdminTab {...props} />;
};
