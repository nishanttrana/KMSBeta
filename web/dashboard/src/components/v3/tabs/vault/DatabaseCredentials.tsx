import { useCallback, useEffect, useMemo, useState } from "react";
import { Copy, Database, KeyRound, Timer, TriangleAlert } from "lucide-react";
import type { AuthSession } from "../../../../lib/auth";
import { deleteDBRole, issueDBCreds, listDBLeases, listDBRoles, putDBRole, renewDBLease, revokeDBLease, type DBLease, type DBRole } from "../../../../lib/secretsDatabase";
import { CredentialPicker } from "../../CredentialPicker";
import { errMsg } from "../../runtimeUtils";
import { C } from "../../theme";
import { B, Btn, Card, FG, Inp, Modal, Row2, Section, Stat, Txt } from "../../legacyPrimitives";

// Secret Vault → Database credentials: short-lived PostgreSQL logins
// (services/secrets/dbengine.go). A role's admin credential lives in
// Playbooks → Credentials; a generated password is shown once.

type RoleRow = { role: DBRole; active_leases: number };
type Defaults = { creation_statements: string[]; revocation_statements: string[] };

const when = (v?: string) => (v ? new Date(v).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "-");
const stateTone: Record<string, string> = { active: "blue", revoked: "neutral", expired: "neutral", revoke_failed: "red" };

function RoleDialog({ session, editing, defaults, onClose, onSaved, onNavigate }: {
  session: AuthSession; editing: DBRole | null; defaults: Defaults; onClose: () => void; onSaved: (m: string) => void; onNavigate?: ((t: string) => void) | undefined;
}) {
  const [name, setName] = useState(editing?.name || "");
  const [conn, setConn] = useState(editing?.connection_id || "");
  const [ttl, setTTL] = useState(String(editing?.default_ttl_seconds ?? 3600));
  const [max, setMax] = useState(String(editing?.max_ttl_seconds ?? 86400));
  const [creation, setCreation] = useState((editing?.creation_statements || defaults.creation_statements).join("\n"));
  const [revocation, setRevocation] = useState((editing?.revocation_statements || defaults.revocation_statements).join("\n"));
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const lines = (s: string) => s.split("\n").map((l) => l.trim()).filter(Boolean);
  const save = async () => {
    setSaving(true);
    setError("");
    try {
      await putDBRole(session, name.trim(), {
        connection_id: conn, creation_statements: lines(creation), revocation_statements: lines(revocation),
        default_ttl_seconds: Number(ttl), max_ttl_seconds: Number(max),
      });
      onSaved(`Role ${name.trim()} saved.`);
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setSaving(false);
    }
  };
  return (
    <Modal open onClose={onClose} title={editing ? `Role ${editing.name}` : "New database role"} wide>
      <Row2>
        <FG label="Name" required hint="Lowercase letters, digits, '-' and '_'.">
          <Inp value={name} onChange={(e) => setName(e.target.value)} placeholder="orders-readers" mono disabled={Boolean(editing)} />
        </FG>
        <FG label="Database credential" required hint="A PostgreSQL administrator, checked by connecting.">
          <CredentialPicker session={session} type="database" value={conn} onChange={setConn} onNavigate={onNavigate} />
        </FG>
      </Row2>
      <Row2>
        <FG label="Default TTL (seconds)"><Inp value={ttl} onChange={(e) => setTTL(e.target.value)} mono /></FG>
        <FG label="Maximum TTL (seconds)" hint="Renewal never goes past it."><Inp value={max} onChange={(e) => setMax(e.target.value)} mono /></FG>
      </Row2>
      <FG label="Creation statements" hint="One per line. {{name}} {{password}} {{expiration}} {{username}}.">
        <Txt rows={4} value={creation} onChange={(e) => setCreation(e.target.value)} aria-label="Creation statements" />
      </FG>
      <FG label="Revocation statements" hint="One per line.">
        <Txt rows={4} value={revocation} onChange={(e) => setRevocation(e.target.value)} aria-label="Revocation statements" />
      </FG>
      {error && <div role="alert" style={{ fontSize: 11, color: C.redFg, marginBottom: 8 }}>{error}</div>}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
        <Btn onClick={onClose}>Cancel</Btn>
        <Btn primary onClick={() => void save()} disabled={saving || !name.trim() || !conn}>{saving ? "Saving…" : "Save"}</Btn>
      </div>
    </Modal>
  );
}

export function DatabaseCredentials({ session, onToast, onNavigate }: { session: AuthSession; onToast?: ((m: string) => void) | undefined; onNavigate?: ((t: string) => void) | undefined }) {
  const [roles, setRoles] = useState<RoleRow[] | null>(null);
  const [defaults, setDefaults] = useState<Defaults>({ creation_statements: [], revocation_statements: [] });
  const [leases, setLeases] = useState<DBLease[] | null>(null);
  const [error, setError] = useState("");
  const [dialog, setDialog] = useState<null | { role: DBRole | null }>(null);
  const [issued, setIssued] = useState<null | { username: string; password: string; expires_at: string }>(null);
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    try {
      const [r, l] = await Promise.all([listDBRoles(session), listDBLeases(session)]);
      setRoles(r.items);
      setDefaults(r.defaults);
      setLeases(l);
      setError("");
    } catch (e) {
      setError(errMsg(e));
    }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const act = async (key: string, fn: () => Promise<unknown>, done: string) => {
    setBusy(key);
    try {
      await fn();
      onToast?.(done);
      await load();
    } catch (e) {
      onToast?.(errMsg(e));
    } finally {
      setBusy("");
    }
  };
  const active = useMemo(() => (leases || []).filter((l) => l.state === "active"), [leases]);
  const soon = active.filter((l) => new Date(l.expires_at).getTime() - Date.now() < 3600_000).length;
  const failed = (leases || []).filter((l) => l.state === "revoke_failed").length;

  return (
    <div>
      {error && <Card style={{ marginBottom: 12 }}><div role="alert" style={{ fontSize: 12, color: C.redFg }}>Database credentials unavailable: {error}</div></Card>}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))", gap: 10, marginBottom: 16 }}>
        <Stat l="Roles" v={roles ? roles.length : "unavailable"} i={Database} />
        <Stat l="Active leases" v={leases ? active.length : "unavailable"} i={KeyRound} />
        <Stat l="Ending within 1h" v={leases ? soon : "unavailable"} c={soon > 0 ? "amber" : "accent"} i={Timer} />
        <Stat l="Revocation failed" v={leases ? failed : "unavailable"} c={failed > 0 ? "red" : "accent"} i={TriangleAlert} />
      </div>

      <Section title="Roles" actions={<Btn small primary onClick={() => setDialog({ role: null })} disabled={!roles}>New role</Btn>}>
        <Card style={{ padding: 0, overflow: "hidden" }}>
          {roles && roles.length === 0 && <div style={{ padding: 16, fontSize: 12, color: C.dim }}>No roles yet.</div>}
          {(roles || []).map(({ role, active_leases }) => (
            <div key={role.name} data-testid={`db-role-${role.name}`} style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr 1fr 0.7fr auto", gap: 10, alignItems: "center", padding: "10px 14px", borderBottom: `1px solid ${C.border}`, fontSize: 12 }}>
              <span style={{ fontWeight: 600, color: C.text, fontFamily: "var(--font-mono)" }}>{role.name}</span>
              <span style={{ color: C.dim, fontFamily: "var(--font-mono)" }}>{role.connection_id}</span>
              <span style={{ color: C.dim }}>{Math.round(role.default_ttl_seconds / 60)} min, up to {Math.round(role.max_ttl_seconds / 3600)} h</span>
              <span style={{ color: C.dim }}>{active_leases} active</span>
              <span style={{ display: "flex", gap: 6 }}>
                <Btn small primary disabled={busy !== ""} onClick={() => void (async () => {
                  setBusy("issue-" + role.name);
                  try {
                    const out = await issueDBCreds(session, role.name);
                    setIssued({ username: out.username, password: out.password, expires_at: out.lease.expires_at });
                    await load();
                  } catch (e) {
                    onToast?.(errMsg(e));
                  } finally {
                    setBusy("");
                  }
                })()}>Generate</Btn>
                <Btn small onClick={() => setDialog({ role })}>Edit</Btn>
                <Btn small danger disabled={active_leases > 0 || busy !== ""} title={active_leases > 0 ? "Revoke its leases first" : ""} onClick={() => void act("del-" + role.name, () => deleteDBRole(session, role.name), `Role ${role.name} deleted.`)}>Delete</Btn>
              </span>
            </div>
          ))}
        </Card>
      </Section>

      <Section title="Leases">
        <Card style={{ padding: 0, overflow: "hidden" }}>
          {leases && leases.length === 0 && <div style={{ padding: 16, fontSize: 12, color: C.dim }}>No credentials issued yet.</div>}
          {(leases || []).map((l) => (
            <div key={l.id} data-testid={`db-lease-${l.id}`} style={{ display: "grid", gridTemplateColumns: "1.6fr 1fr 0.8fr 1fr 1fr auto", gap: 10, alignItems: "center", padding: "9px 14px", borderBottom: `1px solid ${C.border}`, fontSize: 12 }}>
              <span style={{ fontFamily: "var(--font-mono)", color: C.text }} title={l.last_error || ""}>{l.username}</span>
              <span style={{ color: C.dim }}>{l.role_name}</span>
              <span><B c={stateTone[l.state] || "neutral"}>{l.state.replace("_", " ")}</B></span>
              <span style={{ color: C.dim }}>{when(l.created_at)}</span>
              <span style={{ color: C.dim }}>{l.state === "active" ? `until ${when(l.expires_at)}` : when(l.ended_at)}</span>
              <span style={{ display: "flex", gap: 6 }}>
                {l.state === "active" && <Btn small disabled={busy !== ""} onClick={() => void act("renew-" + l.id, () => renewDBLease(session, l.id), "Lease renewed.")}>Renew</Btn>}
                {(l.state === "active" || l.state === "revoke_failed") && <Btn small danger disabled={busy !== ""} onClick={() => void act("revoke-" + l.id, () => revokeDBLease(session, l.id), "Login dropped.")}>Revoke</Btn>}
              </span>
            </div>
          ))}
        </Card>
      </Section>

      {dialog && <RoleDialog session={session} editing={dialog.role} defaults={defaults} onClose={() => setDialog(null)} onNavigate={onNavigate} onSaved={(m) => { setDialog(null); onToast?.(m); void load(); }} />}
      {issued && (
        <Modal open onClose={() => setIssued(null)} title="Database login">
          <div data-keep style={{ fontSize: 12, color: C.amberFg, marginBottom: 10 }}>The password is shown once.</div>
          {([["Username", issued.username], ["Password", issued.password]] as const).map(([label, value]) => (
            <FG key={label} label={label}>
              <div style={{ display: "flex", gap: 6 }}>
                <Inp value={value} readOnly mono aria-label={label} />
                <Btn small title="Copy" onClick={() => { try { void navigator.clipboard.writeText(value); } catch { /* clipboard unavailable */ } }}><Copy size={12} /></Btn>
              </div>
            </FG>
          ))}
          <div style={{ fontSize: 11, color: C.dim }}>Valid until {when(issued.expires_at)}.</div>
          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10 }}><Btn onClick={() => setIssued(null)}>Done</Btn></div>
        </Modal>
      )}
    </div>
  );
}
