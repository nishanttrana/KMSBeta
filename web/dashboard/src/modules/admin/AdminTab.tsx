import { isSystemAdminSession } from "../../config/moduleRegistry";
import type { AdminTabProps } from "./types";
import { SystemAdminTab } from "./SystemAdminTab";
import { TenantAdminTab } from "./TenantAdminTab";
import { UserAdminTab } from "./UserAdminTab";

export const AdminTab = (props: AdminTabProps) => {
  // Outside the platform tenant only User Management is offered. Any other
  // sub-option is a System Administration section; an unknown one (an old
  // "#admin/system" link) opens Health.
  const view = isSystemAdminSession(props.session) ? String(props.subView || "health") : "users";
  if (view === "tenant") {
    return <TenantAdminTab {...props} />;
  }
  if (view === "users") {
    return <UserAdminTab {...props} />;
  }
  return <SystemAdminTab {...props} />;
};
