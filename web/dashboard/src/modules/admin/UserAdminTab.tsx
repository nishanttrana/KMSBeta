import type { AdminTabProps } from "./types";
import { GroupBindingsSection } from "./user-admin/GroupBindingsSection";
import { IdentityProvidersSection } from "./user-admin/IdentityProvidersSection";
import { PoliciesSection } from "./user-admin/PoliciesSection";
import { UserManagementSection } from "./user-admin/UserManagementSection";
import { useUserAdminModel } from "./user-admin/useUserAdminModel";

export const UserAdminTab = ({ session, onToast }: AdminTabProps) => {
  const model = useUserAdminModel({ session, onToast });

  return (
    <div>
      <UserManagementSection model={model} />
      <GroupBindingsSection model={model} />
      <IdentityProvidersSection model={model} />
      <PoliciesSection model={model} />
    </div>
  );
};
