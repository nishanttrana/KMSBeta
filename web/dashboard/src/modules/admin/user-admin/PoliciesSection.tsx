import { Btn, Card, Chk, FG, Inp, Row2, Section } from "../../../components/v3/legacyPrimitives";
import { C } from "../../../components/v3/theme";
import type { UserAdminModel } from "./useUserAdminModel";

type Props = {
  model: UserAdminModel;
};

export function PoliciesSection({ model }: Props) {
  return (
    <Section title="Authentication Policies" actions={<Btn small primary onClick={() => void model.savePolicies()} disabled={model.savingPolicy}>{model.savingPolicy ? "Saving..." : "Save"}</Btn>}>
      <Row2>
        <Card>
          <div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginBottom: 8 }}>Password Policy</div>
          <FG label="Min Length">
            <Inp
              type="number"
              value={String(model.passwordPolicy.min_length)}
              onChange={(event) => model.setPasswordPolicy((prev) => ({ ...prev, min_length: Number(event.target.value || 12) }))}
            />
          </FG>
          <FG label="Max Length">
            <Inp
              type="number"
              value={String(model.passwordPolicy.max_length)}
              onChange={(event) => model.setPasswordPolicy((prev) => ({ ...prev, max_length: Number(event.target.value || 128) }))}
            />
          </FG>
          <FG label="Min Unique Characters">
            <Inp
              type="number"
              value={String(model.passwordPolicy.min_unique_chars)}
              onChange={(event) => model.setPasswordPolicy((prev) => ({ ...prev, min_unique_chars: Number(event.target.value || 6) }))}
            />
          </FG>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8 }}>
            <Chk
              label="Require uppercase letters"
              checked={Boolean(model.passwordPolicy.require_upper)}
              onChange={() => model.setPasswordPolicy((prev) => ({ ...prev, require_upper: !prev.require_upper }))}
            />
            <Chk
              label="Require lowercase letters"
              checked={Boolean(model.passwordPolicy.require_lower)}
              onChange={() => model.setPasswordPolicy((prev) => ({ ...prev, require_lower: !prev.require_lower }))}
            />
            <Chk
              label="Require digits"
              checked={Boolean(model.passwordPolicy.require_digit)}
              onChange={() => model.setPasswordPolicy((prev) => ({ ...prev, require_digit: !prev.require_digit }))}
            />
            <Chk
              label="Require special characters"
              checked={Boolean(model.passwordPolicy.require_special)}
              onChange={() => model.setPasswordPolicy((prev) => ({ ...prev, require_special: !prev.require_special }))}
            />
            <Chk
              label="Disallow whitespace"
              checked={Boolean(model.passwordPolicy.require_no_whitespace)}
              onChange={() => model.setPasswordPolicy((prev) => ({ ...prev, require_no_whitespace: !prev.require_no_whitespace }))}
            />
            <Chk
              label="Disallow username in password"
              checked={Boolean(model.passwordPolicy.deny_username)}
              onChange={() => model.setPasswordPolicy((prev) => ({ ...prev, deny_username: !prev.deny_username }))}
            />
            <Chk
              label="Disallow email local-part in password"
              checked={Boolean(model.passwordPolicy.deny_email_local_part)}
              onChange={() => model.setPasswordPolicy((prev) => ({ ...prev, deny_email_local_part: !prev.deny_email_local_part }))}
            />
          </div>
        </Card>

        <Card>
          <div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginBottom: 8 }}>Security Policy</div>
          <FG label="Max Failed Attempts">
            <Inp
              type="number"
              value={String(model.securityPolicy.max_failed_attempts)}
              onChange={(event) => model.setSecurityPolicy((prev) => ({ ...prev, max_failed_attempts: Number(event.target.value || 5) }))}
            />
          </FG>
          <FG label="Lockout Minutes">
            <Inp
              type="number"
              value={String(model.securityPolicy.lockout_minutes)}
              onChange={(event) => model.setSecurityPolicy((prev) => ({ ...prev, lockout_minutes: Number(event.target.value || 15) }))}
            />
          </FG>
          <FG label="Idle Timeout Minutes">
            <Inp
              type="number"
              value={String(model.securityPolicy.idle_timeout_minutes)}
              onChange={(event) => model.setSecurityPolicy((prev) => ({ ...prev, idle_timeout_minutes: Number(event.target.value || 30) }))}
            />
          </FG>
        </Card>
      </Row2>
    </Section>
  );
}
