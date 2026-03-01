import { B, Btn, Card, Chk, FG, Inp, Row2, Section, Sel, Txt } from "../../../components/v3/legacyPrimitives";
import { C } from "../../../components/v3/theme";
import { ROLE_OPTIONS, STATUS_OPTIONS } from "./constants";
import type { UserAdminModel } from "./useUserAdminModel";
import type { IdentityProviderName } from "../../../lib/authAdmin";

type Props = {
  model: UserAdminModel;
};

export function IdentityProvidersSection({ model }: Props) {
  return (
    <Section title="Identity Providers (AD / Entra ID)">
      <Row2>
        <FG label="Provider">
          <Sel value={model.idpProvider} onChange={(event) => model.setIdpProvider(event.target.value as IdentityProviderName)}>
            <option value="ad">Microsoft Active Directory</option>
            <option value="entra">Microsoft Entra ID</option>
          </Sel>
        </FG>
        <FG label="Directory Query">
          <Inp value={model.idpQuery} onChange={(event) => model.setIdpQuery(event.target.value)} placeholder="user/group search term" />
        </FG>
      </Row2>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8, marginBottom: 8 }}>
        <Chk label="Provider enabled" checked={model.idpEnabled} onChange={() => model.setIdpEnabled((prev) => !prev)} />
        <Chk label="Imported users must change password" checked={model.idpImportMustChange} onChange={() => model.setIdpImportMustChange((prev) => !prev)} />
      </div>
      <Row2>
        <FG label="Configuration JSON">
          <Txt rows={8} value={model.idpConfigJson} onChange={(event) => model.setIdpConfigJson(event.target.value)} mono />
        </FG>
        <FG label="Secrets JSON">
          <Txt rows={8} value={model.idpSecretsJson} onChange={(event) => model.setIdpSecretsJson(event.target.value)} mono />
        </FG>
      </Row2>
      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginBottom: 10 }}>
        <Btn small onClick={() => void model.loadIdpConfig()}>Reload</Btn>
        <Btn small onClick={() => void model.testIdpConfig()} disabled={model.idpTesting}>{model.idpTesting ? "Testing..." : "Test"}</Btn>
        <Btn small primary onClick={() => void model.saveIdpConfig()} disabled={model.idpSaving}>{model.idpSaving ? "Saving..." : "Save"}</Btn>
      </div>

      <Card>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>Directory Discovery</div>
          <div style={{ display: "flex", gap: 8 }}>
            <Btn small onClick={() => void model.discoverIdpUsers()} disabled={model.idpUsersLoading}>{model.idpUsersLoading ? "Users..." : "Fetch Users"}</Btn>
            <Btn small onClick={() => void model.discoverIdpGroups()} disabled={model.idpGroupsLoading}>{model.idpGroupsLoading ? "Groups..." : "Fetch Groups"}</Btn>
          </div>
        </div>
        <Row2>
          <Card>
            <div style={{ fontSize: 10, color: C.muted, marginBottom: 8 }}>Groups</div>
            <div style={{ maxHeight: 180, overflowY: "auto", display: "grid", gap: 6 }}>
              {model.idpGroups.map((group) => {
                const groupID = String(group.external_id || "").trim();
                const selected = groupID === model.idpSelectedGroupID;
                return (
                  <div key={groupID} style={{ border: `1px solid ${selected ? C.accent : C.border}`, borderRadius: 8, padding: "8px 10px" }}>
                    <div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>{String(group.name || groupID)}</div>
                    <div style={{ fontSize: 9, color: C.dim }}>{groupID}</div>
                    <div style={{ display: "flex", justifyContent: "space-between", marginTop: 6 }}>
                      <B c="blue">{`${Number(group.member_count || 0)} members`}</B>
                      <Btn
                        small
                        onClick={() => {
                          model.setIdpSelectedGroupID(groupID);
                        }}
                      >
                        Select
                      </Btn>
                    </div>
                  </div>
                );
              })}
              {!model.idpGroups.length ? <div style={{ fontSize: 10, color: C.muted }}>No groups loaded.</div> : null}
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 8 }}>
              <Btn small onClick={() => void model.discoverIdpMembers()} disabled={model.idpMembersLoading || !String(model.idpSelectedGroupID || "").trim()}>
                {model.idpMembersLoading ? "Loading..." : "Load Group Members"}
              </Btn>
            </div>
          </Card>

          <Card>
            <div style={{ fontSize: 10, color: C.muted, marginBottom: 8 }}>Users</div>
            <div style={{ maxHeight: 180, overflowY: "auto", display: "grid", gap: 6 }}>
              {(model.idpMembers.length ? model.idpMembers : model.idpUsers).map((user) => {
                const userID = String(user.external_id || "").trim();
                const selected = model.idpSelectedUserIDs.includes(userID);
                return (
                  <div key={userID} style={{ border: `1px solid ${selected ? C.accent : C.border}`, borderRadius: 8, padding: "8px 10px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                      <div>
                        <div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>{String(user.display_name || user.username || userID)}</div>
                        <div style={{ fontSize: 9, color: C.dim }}>{String(user.email || user.username || userID)}</div>
                      </div>
                      <Chk label="" checked={selected} onChange={() => model.toggleIdpUserSelection(userID)} />
                    </div>
                  </div>
                );
              })}
              {!model.idpUsers.length && !model.idpMembers.length ? <div style={{ fontSize: 10, color: C.muted }}>No users loaded.</div> : null}
            </div>
          </Card>
        </Row2>
        <Row2>
          <FG label="Import Role">
            <Sel value={model.idpImportRole} onChange={(event) => model.setIdpImportRole(event.target.value)}>
              {ROLE_OPTIONS.map((role) => (
                <option key={role} value={role}>{role}</option>
              ))}
            </Sel>
          </FG>
          <FG label="Import Status">
            <Sel value={model.idpImportStatus} onChange={(event) => model.setIdpImportStatus(event.target.value)}>
              {STATUS_OPTIONS.map((status) => (
                <option key={status} value={status}>{status}</option>
              ))}
            </Sel>
          </FG>
        </Row2>
        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 6 }}>
          <Btn primary onClick={() => void model.importIdpUsers()} disabled={model.idpImporting}>
            {model.idpImporting ? "Importing..." : `Import Selected (${model.idpSelectedUserIDs.length})`}
          </Btn>
        </div>
      </Card>
    </Section>
  );
}
