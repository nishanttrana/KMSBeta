import { isSystemAdminSession } from "../../config/moduleRegistry";
import type { AdminSubView, AdminTabProps } from "./types";
import { SystemAdminTab } from "./SystemAdminTab";
import { TenantAdminTab } from "./TenantAdminTab";
import { UserAdminTab } from "./UserAdminTab";

const normalizeAdminView = (value: unknown): AdminSubView => {
  const raw = String(value || "system").trim().toLowerCase();
  if (raw === "tenant") return "tenant";
  if (raw === "users") return "users";
  return "system";
};

export const AdminTab = (props: AdminTabProps) => {
  // Outside the platform tenant only User Management is offered.
  const view = isSystemAdminSession(props.session) ? normalizeAdminView(props.subView) : "users";
  if (view === "tenant") {
    return <TenantAdminTab {...props} />;
  }
  if (view === "users") {
    return <UserAdminTab {...props} />;
  }
  return <SystemAdminTab {...props} />;
};
