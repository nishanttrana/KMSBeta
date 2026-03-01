import { B, Btn, Card, FG, Inp, Row2, Section, Sel } from "../../../components/v3/legacyPrimitives";
import { C } from "../../../components/v3/theme";
import { ROLE_OPTIONS, STATUS_OPTIONS } from "./constants";
import type { UserAdminModel } from "./useUserAdminModel";

type Props = {
  model: UserAdminModel;
};

export function UserManagementSection({ model }: Props) {
  return (
    <>
      <Section title="User Management" actions={<Btn small onClick={() => void model.loadUsers()}>{model.loading ? "Refreshing..." : "Refresh"}</Btn>}>
        <Row2>
          <FG label="Tenant Scope">
            <Sel value={model.selectedTenant} onChange={(event) => model.setSelectedTenant(event.target.value)}>
              {model.tenants.map((tenant) => (
                <option key={tenant.id} value={tenant.id}>{`${tenant.id} (${tenant.name})`}</option>
              ))}
            </Sel>
          </FG>
          <FG label="Inventory">
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <B c="green">{`${model.usersByStatus.active} active`}</B>
              <B c="amber">{`${model.usersByStatus.disabled} non-active`}</B>
              <B c="blue">{`${model.users.length} total`}</B>
            </div>
          </FG>
        </Row2>

        <Card>
          <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1.4fr 0.9fr 0.9fr 1.2fr", gap: 8, borderBottom: `1px solid ${C.border}`, paddingBottom: 8 }}>
            {["User", "Email", "Role", "Status", "Actions"].map((header) => (
              <div key={header} style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>{header}</div>
            ))}
          </div>
          {model.users.map((user) => {
            const userID = String(user.id || "");
            const roleBusy = model.updateBusy === `${userID}:role`;
            const statusBusy = model.updateBusy === `${userID}:status`;
            return (
              <div key={userID} style={{ display: "grid", gridTemplateColumns: "1.5fr 1.4fr 0.9fr 0.9fr 1.2fr", gap: 8, alignItems: "center", borderBottom: `1px solid ${C.border}`, padding: "8px 0" }}>
                <div style={{ fontSize: 12, color: C.text, fontWeight: 600 }}>{String(user.username || "-")}</div>
                <div style={{ fontSize: 11, color: C.dim }}>{String(user.email || "-")}</div>
                <Sel value={String(user.role || "viewer")} onChange={(event) => void model.updateRole(user, event.target.value)} disabled={roleBusy}>
                  {ROLE_OPTIONS.map((role) => (
                    <option key={role} value={role}>{role}</option>
                  ))}
                </Sel>
                <Sel value={String(user.status || "active")} onChange={(event) => void model.updateStatus(user, event.target.value)} disabled={statusBusy}>
                  {STATUS_OPTIONS.map((status) => (
                    <option key={status} value={status}>{status}</option>
                  ))}
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
              {ROLE_OPTIONS.map((role) => (
                <option key={role} value={role}>{role}</option>
              ))}
            </Sel>
          </FG>
        </Row2>
        <Row2>
          <FG label="Status">
            <Sel value={model.newStatus} onChange={(event) => model.setNewStatus(event.target.value)}>
              {STATUS_OPTIONS.map((status) => (
                <option key={status} value={status}>{status}</option>
              ))}
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
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <B c={model.resetMustChange ? "amber" : "blue"}>{model.resetMustChange ? "Must change on next login" : "No forced change"}</B>
          <Btn small onClick={() => model.setResetMustChange((prev) => !prev)}>Toggle</Btn>
        </div>
        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 8 }}>
          <Btn primary onClick={() => void model.resetPassword()} disabled={model.updateBusy.endsWith(":reset")}>{model.updateBusy.endsWith(":reset") ? "Applying..." : "Apply Reset"}</Btn>
        </div>
      </Section>
    </>
  );
}
