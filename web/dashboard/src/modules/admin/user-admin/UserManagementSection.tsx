import { B, Btn, Card, Chk, FG, Inp, Row2, Section, Sel } from "../../../components/v3/legacyPrimitives";
import { C } from "../../../components/v3/theme";
import { STATUS_OPTIONS } from "./constants";
import { selectOptions } from "./roleOptions";
import type { UserAdminModel } from "./useUserAdminModel";

type Props = {
  model: UserAdminModel;
};

export function UserManagementSection({ model }: Props) {
  return (
    <>
      <Section title="User Management" actions={<Btn small onClick={() => void model.loadUsers()}>{model.loading ? "Refreshing..." : "Refresh"}</Btn>}>
        <Row2>
          {/* Only a platform (root) administrator manages more than one tenant. */}
          {model.tenants.length > 1 ? (
            <FG label="Tenant">
              <Sel value={model.selectedTenant} onChange={(event) => model.setSelectedTenant(event.target.value)}>
                {model.tenants.map((tenant) => (
                  <option key={tenant.id} value={tenant.id}>{`${tenant.id} (${tenant.name})`}</option>
                ))}
              </Sel>
            </FG>
          ) : <div />}
          <FG label="Inventory">
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <B c="green">{`${model.usersByStatus.active} active`}</B>
              <B c="amber">{`${model.usersByStatus.inactive} inactive`}</B>
              <B c="blue">{`${model.users.length} total`}</B>
            </div>
          </FG>
        </Row2>

        <Card>
          <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1.4fr 0.9fr 0.9fr 1.2fr", gap: 8, borderBottom: `1px solid ${C.border}`, paddingBottom: 8 }}>
            {["User", "Email", "Role", "Status", "Actions"].map((header) => (
              <div key={header} style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>{header}</div>
            ))}
          </div>
          {model.users.map((user) => {
            const userID = String(user.id || "");
            const self = model.isSelf(user);
            const roleBusy = model.updateBusy === `${userID}:role`;
            const statusBusy = model.updateBusy === `${userID}:status`;
            return (
              <div key={userID} style={{ display: "grid", gridTemplateColumns: "1.5fr 1.4fr 0.9fr 0.9fr 1.2fr", gap: 8, alignItems: "center", borderBottom: `1px solid ${C.border}`, padding: "8px 0" }}>
                <div style={{ fontSize: 12, color: C.text, fontWeight: 600 }}>{String(user.username || "-")}</div>
                <div style={{ fontSize: 11, color: C.dim }}>{String(user.email || "-")}</div>
                <Sel value={String(user.role || "")} onChange={(event) => void model.updateRole(user, event.target.value)} disabled={roleBusy || self} title={self ? "Another administrator changes your role" : undefined}>
                  {selectOptions(model.roles, String(user.role || ""))}
                </Sel>
                <Sel value={String(user.status || "")} onChange={(event) => void model.updateStatus(user, event.target.value)} disabled={statusBusy || self} title={self ? "Another administrator changes your status" : undefined}>
                  {selectOptions(STATUS_OPTIONS, String(user.status || ""))}
                </Sel>
                <Btn
                  small
                  onClick={() => {
                    model.setResetUserID(userID);
                    model.setResetPasswordValue("");
                  }}
                >
                  Reset Password
                </Btn>
              </div>
            );
          })}
          {!model.users.length ? <div style={{ fontSize: 10, color: C.muted, paddingTop: 10 }}>No users found for selected tenant.</div> : null}
        </Card>
      </Section>

      <Section title="Create User">
        <Row2>
          <FG label="Username" required>
            <Inp value={model.newUsername} onChange={(event) => model.setNewUsername(event.target.value)} />
          </FG>
          <FG label="Email" required>
            <Inp value={model.newEmail} onChange={(event) => model.setNewEmail(event.target.value)} />
          </FG>
        </Row2>
        <Row2>
          <FG label="Password" required>
            <Inp type="password" value={model.newPassword} onChange={(event) => model.setNewPassword(event.target.value)} />
          </FG>
          <FG label="Role">
            <Sel value={model.newRole} onChange={(event) => model.setNewRole(event.target.value)}>
              {selectOptions(model.roles)}
            </Sel>
          </FG>
        </Row2>
        <Row2>
          <FG label="Status">
            <Sel value={model.newStatus} onChange={(event) => model.setNewStatus(event.target.value)}>
              {selectOptions(STATUS_OPTIONS)}
            </Sel>
          </FG>
          <div />
        </Row2>
        <div style={{ display: "flex", justifyContent: "flex-end" }}>
          <Btn primary onClick={() => void model.createUser()} disabled={model.createBusy}>{model.createBusy ? "Creating..." : "Create User"}</Btn>
        </div>
      </Section>

      <Section title="Reset Password">
        <Row2>
          <FG label="User">
            <Sel value={model.resetUserID} onChange={(event) => model.setResetUserID(event.target.value)}>
              <option value="">Select user</option>
              {model.users.map((user) => (
                <option key={user.id} value={user.id}>{`${user.username} (${user.email})`}</option>
              ))}
            </Sel>
          </FG>
          <FG label="New Password">
            <Inp type="password" value={model.resetPasswordValue} onChange={(event) => model.setResetPasswordValue(event.target.value)} />
          </FG>
        </Row2>
        <Chk label="Must change on next sign-in" checked={model.resetMustChange} onChange={() => model.setResetMustChange((prev) => !prev)} />
        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 8 }}>
          <Btn primary onClick={() => void model.resetPassword()} disabled={model.updateBusy.endsWith(":reset")}>{model.updateBusy.endsWith(":reset") ? "Applying..." : "Apply Reset"}</Btn>
        </div>
      </Section>
    </>
  );
}
