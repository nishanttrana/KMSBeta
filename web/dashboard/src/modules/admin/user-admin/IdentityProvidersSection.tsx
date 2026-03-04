import { B, Btn, Card, Chk, FG, Inp, Row2, Section, Sel, Txt } from "../../../components/v3/legacyPrimitives";
import { C } from "../../../components/v3/theme";
import { ROLE_OPTIONS, STATUS_OPTIONS } from "./constants";
import type { UserAdminModel } from "./useUserAdminModel";
import type { IdentityProviderName } from "../../../lib/authAdmin";

type Props = {
  model: UserAdminModel;
};

// Helpers to read/write specific config keys from the JSON textareas
function parseJsonSafe(raw: string): Record<string, unknown> {
  try { return JSON.parse(raw) || {}; } catch { return {}; }
}

function setConfigKey(model: UserAdminModel, key: string, value: unknown) {
  const obj = parseJsonSafe(model.idpConfigJson);
  obj[key] = value;
  model.setIdpConfigJson(JSON.stringify(obj, null, 2));
}

function getConfigKey(model: UserAdminModel, key: string, defaultVal = ""): string {
  const obj = parseJsonSafe(model.idpConfigJson);
  return String(obj[key] ?? defaultVal);
}

function setSecretKey(model: UserAdminModel, key: string, value: string) {
  const obj = parseJsonSafe(model.idpSecretsJson);
  obj[key] = value;
  model.setIdpSecretsJson(JSON.stringify(obj, null, 2));
}

function getSecretKey(model: UserAdminModel, key: string): string {
  const obj = parseJsonSafe(model.idpSecretsJson);
  return String(obj[key] ?? "");
}

function ConfigInput({ model, configKey, label, placeholder }: { model: UserAdminModel; configKey: string; label: string; placeholder?: string }) {
  return (
    <FG label={label}>
      <Inp
        value={getConfigKey(model, configKey)}
        onChange={(e) => setConfigKey(model, configKey, e.target.value)}
        placeholder={placeholder}
      />
    </FG>
  );
}

function SecretInput({ model, secretKey, label, placeholder }: { model: UserAdminModel; secretKey: string; label: string; placeholder?: string }) {
  return (
    <FG label={label}>
      <Inp
        type="password"
        value={getSecretKey(model, secretKey)}
        onChange={(e) => setSecretKey(model, secretKey, e.target.value)}
        placeholder={placeholder || "Enter value (hidden)"}
      />
    </FG>
  );
}

function ConfigCheckbox({ model, configKey, label }: { model: UserAdminModel; configKey: string; label: string }) {
  const val = getConfigKey(model, configKey, "false");
  return (
    <Chk
      label={label}
      checked={val === "true"}
      onChange={() => setConfigKey(model, configKey, val === "true" ? "false" : "true")}
    />
  );
}

function SAMLForm({ model }: { model: UserAdminModel }) {
  return (
    <>
      <Row2>
        <ConfigInput model={model} configKey="sp_entity_id" label="SP Entity ID" placeholder="https://your-app.com/saml/metadata" />
        <ConfigInput model={model} configKey="acs_url" label="ACS URL (Assertion Consumer)" placeholder="https://your-app.com/auth/sso/saml/callback" />
      </Row2>
      <Row2>
        <ConfigInput model={model} configKey="idp_metadata_url" label="IdP Metadata URL" placeholder="https://idp.example.com/metadata" />
        <ConfigInput model={model} configKey="idp_sso_url" label="IdP SSO URL" placeholder="https://idp.example.com/sso" />
      </Row2>
      <Row2>
        <FG label="Name ID Format">
          <Sel value={getConfigKey(model, "name_id_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")} onChange={(e) => setConfigKey(model, "name_id_format", e.target.value)}>
            <option value="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">Email Address</option>
            <option value="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">Unspecified</option>
            <option value="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">Persistent</option>
            <option value="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">Transient</option>
          </Sel>
        </FG>
        <ConfigInput model={model} configKey="display_name" label="Display Name (Login Button)" placeholder="SAML SSO" />
      </Row2>
      <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, marginTop: 8, marginBottom: 4 }}>Attribute Mapping</div>
      <Row2>
        <ConfigInput model={model} configKey="attr_username" label="Username Attribute" placeholder="preferred_username" />
        <ConfigInput model={model} configKey="attr_email" label="Email Attribute" placeholder="email" />
      </Row2>
      <Row2>
        <ConfigInput model={model} configKey="attr_display_name" label="Display Name Attribute" placeholder="name" />
        <FG label="Default Role (Auto-Created Users)">
          <Sel value={getConfigKey(model, "default_role", "viewer")} onChange={(e) => setConfigKey(model, "default_role", e.target.value)}>
            {ROLE_OPTIONS.map((r) => <option key={r} value={r}>{r}</option>)}
          </Sel>
        </FG>
      </Row2>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8, marginTop: 8 }}>
        <ConfigCheckbox model={model} configKey="sign_requests" label="Sign AuthnRequests" />
        <ConfigCheckbox model={model} configKey="auto_create_users" label="Auto-create users on first login" />
      </div>
      <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, marginTop: 12, marginBottom: 4 }}>Certificates</div>
      <Row2>
        <FG label="IdP Certificate (PEM)">
          <Txt rows={4} value={getSecretKey(model, "idp_certificate")} onChange={(e) => setSecretKey(model, "idp_certificate", e.target.value)} mono />
        </FG>
        <FG label="SP Private Key (PEM)">
          <Txt rows={4} value={getSecretKey(model, "sp_private_key")} onChange={(e) => setSecretKey(model, "sp_private_key", e.target.value)} mono />
        </FG>
      </Row2>
    </>
  );
}

function OIDCForm({ model }: { model: UserAdminModel }) {
  return (
    <>
      <Row2>
        <ConfigInput model={model} configKey="issuer_url" label="Issuer URL" placeholder="https://accounts.google.com" />
        <ConfigInput model={model} configKey="client_id" label="Client ID" placeholder="your-client-id" />
      </Row2>
      <Row2>
        <ConfigInput model={model} configKey="redirect_uri" label="Redirect URI" placeholder="https://your-app.com/auth/sso/oidc/callback" />
        <SecretInput model={model} secretKey="client_secret" label="Client Secret" />
      </Row2>
      <Row2>
        <ConfigInput model={model} configKey="scopes" label="Scopes" placeholder="openid profile email" />
        <ConfigInput model={model} configKey="response_type" label="Response Type" placeholder="code" />
      </Row2>
      <Row2>
        <ConfigInput model={model} configKey="display_name" label="Display Name (Login Button)" placeholder="OpenID Connect" />
        <FG label="Default Role (Auto-Created Users)">
          <Sel value={getConfigKey(model, "default_role", "viewer")} onChange={(e) => setConfigKey(model, "default_role", e.target.value)}>
            {ROLE_OPTIONS.map((r) => <option key={r} value={r}>{r}</option>)}
          </Sel>
        </FG>
      </Row2>
      <div style={{ fontSize: 10, fontWeight: 700, color: C.muted, marginTop: 8, marginBottom: 4 }}>Attribute Mapping</div>
      <Row2>
        <ConfigInput model={model} configKey="attr_username" label="Username Claim" placeholder="preferred_username" />
        <ConfigInput model={model} configKey="attr_email" label="Email Claim" placeholder="email" />
      </Row2>
      <Row2>
        <ConfigInput model={model} configKey="attr_display_name" label="Display Name Claim" placeholder="name" />
        <div />
      </Row2>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8, marginTop: 8 }}>
        <ConfigCheckbox model={model} configKey="auto_create_users" label="Auto-create users on first login" />
      </div>
    </>
  );
}

function LDAPForm({ model }: { model: UserAdminModel }) {
  return (
    <>
      <Row2>
        <ConfigInput model={model} configKey="server_url" label="Server URL" placeholder="ldap://ldap.example.com:389" />
        <ConfigInput model={model} configKey="base_dn" label="Base DN" placeholder="dc=example,dc=com" />
      </Row2>
      <Row2>
        <ConfigInput model={model} configKey="bind_dn" label="Bind DN (Service Account)" placeholder="cn=admin,dc=example,dc=com" />
        <SecretInput model={model} secretKey="bind_password" label="Bind Password" />
      </Row2>
      <Row2>
        <ConfigInput model={model} configKey="user_search_filter" label="User Search Filter" placeholder="(objectClass=inetOrgPerson)" />
        <ConfigInput model={model} configKey="user_login_attr" label="Login Attribute" placeholder="uid" />
      </Row2>
      <Row2>
        <ConfigInput model={model} configKey="user_email_attr" label="Email Attribute" placeholder="mail" />
        <ConfigInput model={model} configKey="user_display_attr" label="Display Name Attribute" placeholder="displayName" />
      </Row2>
      <Row2>
        <ConfigInput model={model} configKey="group_search_filter" label="Group Search Filter" placeholder="(objectClass=groupOfNames)" />
        <ConfigInput model={model} configKey="group_name_attr" label="Group Name Attribute" placeholder="cn" />
      </Row2>
      <Row2>
        <ConfigInput model={model} configKey="timeout_sec" label="Timeout (seconds)" placeholder="10" />
        <FG label="Default Role (Auto-Created Users)">
          <Sel value={getConfigKey(model, "default_role", "viewer")} onChange={(e) => setConfigKey(model, "default_role", e.target.value)}>
            {ROLE_OPTIONS.map((r) => <option key={r} value={r}>{r}</option>)}
          </Sel>
        </FG>
      </Row2>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8, marginTop: 8 }}>
        <ConfigCheckbox model={model} configKey="use_start_tls" label="Use StartTLS" />
        <ConfigCheckbox model={model} configKey="insecure_skip_verify" label="Skip TLS Verification" />
        <ConfigCheckbox model={model} configKey="auto_create_users" label="Auto-create users on LDAP login" />
      </div>
    </>
  );
}

function ADEntraForm({ model }: { model: UserAdminModel }) {
  return (
    <Row2>
      <FG label="Configuration JSON">
        <Txt rows={8} value={model.idpConfigJson} onChange={(event) => model.setIdpConfigJson(event.target.value)} mono />
      </FG>
      <FG label="Secrets JSON">
        <Txt rows={8} value={model.idpSecretsJson} onChange={(event) => model.setIdpSecretsJson(event.target.value)} mono />
      </FG>
    </Row2>
  );
}

// Providers that support directory discovery
const DIRECTORY_PROVIDERS: IdentityProviderName[] = ["ad", "entra", "ldap"];

export function IdentityProvidersSection({ model }: Props) {
  const showDirectoryDiscovery = DIRECTORY_PROVIDERS.includes(model.idpProvider);

  return (
    <Section title="Identity Providers (AD / Entra / SAML / OIDC / LDAP)">
      <Row2>
        <FG label="Provider">
          <Sel value={model.idpProvider} onChange={(event) => model.setIdpProvider(event.target.value as IdentityProviderName)}>
            <option value="ad">Microsoft Active Directory</option>
            <option value="entra">Microsoft Entra ID</option>
            <option value="saml">SAML 2.0</option>
            <option value="oidc">OpenID Connect (OIDC)</option>
            <option value="ldap">Generic LDAP</option>
          </Sel>
        </FG>
        {showDirectoryDiscovery && (
          <FG label="Directory Query">
            <Inp value={model.idpQuery} onChange={(event) => model.setIdpQuery(event.target.value)} placeholder="user/group search term" />
          </FG>
        )}
      </Row2>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8, marginBottom: 8 }}>
        <Chk label="Provider enabled" checked={model.idpEnabled} onChange={() => model.setIdpEnabled((prev) => !prev)} />
        {showDirectoryDiscovery && (
          <Chk label="Imported users must change password" checked={model.idpImportMustChange} onChange={() => model.setIdpImportMustChange((prev) => !prev)} />
        )}
      </div>

      {/* Provider-specific configuration forms */}
      {model.idpProvider === "saml" && <SAMLForm model={model} />}
      {model.idpProvider === "oidc" && <OIDCForm model={model} />}
      {model.idpProvider === "ldap" && <LDAPForm model={model} />}
      {(model.idpProvider === "ad" || model.idpProvider === "entra") && <ADEntraForm model={model} />}

      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 10, marginBottom: 10 }}>
        <Btn small onClick={() => void model.loadIdpConfig()}>Reload</Btn>
        <Btn small onClick={() => void model.testIdpConfig()} disabled={model.idpTesting}>{model.idpTesting ? "Testing..." : "Test"}</Btn>
        <Btn small primary onClick={() => void model.saveIdpConfig()} disabled={model.idpSaving}>{model.idpSaving ? "Saving..." : "Save"}</Btn>
      </div>

      {/* Directory Discovery — only for AD, Entra, LDAP */}
      {showDirectoryDiscovery && (
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
      )}
    </Section>
  );
}
