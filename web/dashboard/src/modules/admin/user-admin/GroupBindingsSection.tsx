import { Btn, Card, FG, Inp, Row2, Section, Sel } from "../../../components/v3/legacyPrimitives";
import { C } from "../../../components/v3/theme";
import { ROLE_OPTIONS } from "./constants";
import type { UserAdminModel } from "./useUserAdminModel";

type Props = {
  model: UserAdminModel;
};

export function GroupBindingsSection({ model }: Props) {
  return (
    <Section title="Group Role Bindings">
      <Row2>
        <FG label="Group ID">
          <Inp value={model.groupID} onChange={(event) => model.setGroupID(event.target.value)} placeholder="group-id" />
        </FG>
        <FG label="Role">
          <Sel value={model.groupRole} onChange={(event) => model.setGroupRole(event.target.value)}>
            {ROLE_OPTIONS.map((role) => (
              <option key={role} value={role}>{role}</option>
            ))}
          </Sel>
        </FG>
      </Row2>
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 8 }}>
        <Btn primary onClick={() => void model.upsertBinding()} disabled={model.bindingBusy}>{model.bindingBusy ? "Saving..." : "Upsert Binding"}</Btn>
      </div>
      <Card>
        <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr 110px", gap: 8, borderBottom: `1px solid ${C.border}`, paddingBottom: 8 }}>
          {["Group", "Role", "Actions"].map((header) => (
            <div key={header} style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>{header}</div>
          ))}
        </div>
        {model.bindings.map((binding) => (
          <div key={`${binding.group_id}:${binding.role_name}`} style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr 110px", gap: 8, borderBottom: `1px solid ${C.border}`, padding: "8px 0", alignItems: "center" }}>
            <div style={{ fontSize: 12, color: C.text }}>{binding.group_id}</div>
            <div style={{ fontSize: 11, color: C.dim }}>{binding.role_name}</div>
            <Btn small danger onClick={() => void model.removeBinding(binding)} disabled={model.bindingBusy}>Delete</Btn>
          </div>
        ))}
        {!model.bindings.length ? <div style={{ fontSize: 10, color: C.muted, paddingTop: 10 }}>No group role bindings found.</div> : null}
      </Card>
    </Section>
  );
}
