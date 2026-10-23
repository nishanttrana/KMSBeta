import { Sel } from "../legacyPrimitives";

// Who a key grant names: a user, a group, or a REST client (13.53.0-beta,
// docs/SECURITY/KEY_ACCESS_MODEL.md). Kept out of KeysTab, which may not grow.

export type GrantSubjectType = "user" | "group" | "client";

export const grantSubjectType = (v: unknown): GrantSubjectType => {
  const t = String(v || "user");
  return t === "group" || t === "client" ? t : "user";
};

type Lists = { users: any[]; groups: any[]; clients: any[] };

const arr = (v: unknown): any[] => (Array.isArray(v) ? v : []);

export function grantSubjectLabel(type: GrantSubjectType, id: string, { users, groups, clients }: Lists): string {
  if (type === "group") return arr(groups).find((g) => String(g?.id || "") === id)?.name || id;
  if (type === "client") return `REST client: ${arr(clients).find((c) => String(c?.id || "") === id)?.client_name || id}`;
  return arr(users).find((u) => String(u?.id || "") === id)?.username || id;
}

export function GrantSubjectPicker({ type, id, onType, onId, users, groups, clients }: Lists & {
  type: GrantSubjectType; id: string; onType: (t: GrantSubjectType) => void; onId: (id: string) => void;
}) {
  return (
    <>
      <Sel value={type} onChange={(e: any) => { onType(grantSubjectType(e.target.value)); onId(""); }}>
        <option value="user">User</option>
        <option value="group">Group</option>
        <option value="client">REST client</option>
      </Sel>
      <Sel value={id} onChange={(e: any) => onId(String(e.target.value))}>
        <option value="">{type === "group" ? "Select group" : type === "client" ? "Select client" : "Select user"}</option>
        {type === "group"
          ? arr(groups).map((g) => <option key={g.id} value={g.id}>{`${g.name}${Number(g.member_count || 0) > 0 ? ` (${g.member_count})` : ""}`}</option>)
          : type === "client"
            ? arr(clients).map((c) => <option key={c.id} value={c.id}>{String(c.client_name || c.id)}</option>)
            : arr(users).map((u) => <option key={u.id} value={u.id}>{`${u.username} (${u.role})`}</option>)}
      </Sel>
    </>
  );
}
