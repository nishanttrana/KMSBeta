// @ts-nocheck
import { useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Database,
  KeyRound,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  XCircle,
} from "lucide-react";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import {
  B,
  Btn,
  Card,
  FG,
  Inp,
  Row2,
  Row3,
  Section,
  Sel,
  Stat,
  Txt,
} from "../legacyPrimitives";
import {
  getTDEStatus,
  listTDEDatabases,
  provisionTDEKey,
  registerTDEDatabase,
  revokeTDEKey,
} from "../../../lib/tde";

type Props = { session: any };
type View = "overview" | "databases" | "register";

// ── constants ──────────────────────────────────────────────────────

const ENGINE_OPTS = ["oracle", "sqlserver", "postgresql", "mysql", "db2"];
const TDE_MODES = ["auto", "manual", "managed"];
const ROTATION_OPTS = ["none", "30d", "90d", "180d", "365d"];

const ENGINE_COLORS: Record<string, string> = {
  oracle: "orange",
  sqlserver: "blue",
  db2: "purple",
  mysql: "amber",
  postgresql: "teal",
};

const EMPTY_FORM = {
  name: "", engine: "postgresql", host: "", port: "5432", db_name: "",
  tde_mode: "auto", rotation_policy: "90d", notes: "",
};

// ── helpers ────────────────────────────────────────────────────────

const TH: React.CSSProperties = {
  padding: "8px 12px", fontSize: 10, fontWeight: 700, color: C.muted,
  textTransform: "uppercase", letterSpacing: "0.08em", textAlign: "left",
  background: C.card, borderBottom: `1px solid ${C.border}`,
};
const TD = (i: number): React.CSSProperties => ({
  padding: "9px 12px", color: C.dim, fontSize: 11, verticalAlign: "middle",
  background: i % 2 === 0 ? C.card : "#0f1824",
  borderBottom: `1px solid ${C.border}22`,
});

function tdeStatusBadgeColor(s: string): string {
  if (s === "key_provisioned") return "green";
  if (s === "registered") return "amber";
  if (s === "revoked") return "red";
  return "blue";
}

function tdeStatusIcon(s: string) {
  if (s === "key_provisioned") return <CheckCircle2 size={11} color={C.green} />;
  if (s === "revoked") return <XCircle size={11} color={C.red} />;
  return <ShieldAlert size={11} color={C.amber} />;
}

function fmtDate(s?: string): string {
  if (!s) return "—";
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleDateString();
}

// ── component ──────────────────────────────────────────────────────

export function TDETab({ session }: Props) {
  const [view, setView] = useState<View>("overview");
  const [databases, setDatabases] = useState<any[]>([]);
  const [status, setStatus] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  // Register form
  const [form, setForm] = useState({ ...EMPTY_FORM });
  const [formErr, setFormErr] = useState("");
  const [formBusy, setFormBusy] = useState(false);
  const [formSuccess, setFormSuccess] = useState(false);

  // Databases filter
  const [filterEngine, setFilterEngine] = useState("");
  const [filterStatus, setFilterStatus] = useState("");

  async function load() {
    setLoading(true);
    setErr("");
    try {
      const [dbs, st] = await Promise.all([
        listTDEDatabases(session),
        getTDEStatus(session),
      ]);
      setDatabases(dbs);
      setStatus(st);
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function doProvision(id: string) {
    setBusy(id + ":provision");
    try {
      const updated = await provisionTDEKey(session, id);
      setDatabases(dbs => dbs.map(d => d.id === id ? updated : d));
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(null);
    }
  }

  async function doRevoke(id: string) {
    if (!confirm("Revoke this TDE key? The database will lose access to its encryption key.")) return;
    setBusy(id + ":revoke");
    try {
      const updated = await revokeTDEKey(session, id);
      setDatabases(dbs => dbs.map(d => d.id === id ? updated : d));
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(null);
    }
  }

  async function doRegister() {
    setFormErr(""); setFormSuccess(false);
    if (!form.name.trim()) { setFormErr("Name is required"); return; }
    if (!form.host.trim()) { setFormErr("Host is required"); return; }
    if (!form.db_name.trim()) { setFormErr("Database name is required"); return; }
    const port = parseInt(form.port, 10);
    if (isNaN(port) || port < 1 || port > 65535) { setFormErr("Invalid port"); return; }
    setFormBusy(true);
    try {
      const db = await registerTDEDatabase(session, {
        name: form.name.trim(),
        engine: form.engine,
        host: form.host.trim(),
        port,
        db_name: form.db_name.trim(),
        tde_mode: form.tde_mode,
        rotation_policy: form.rotation_policy,
        notes: form.notes.trim(),
      });
      setDatabases(dbs => [db, ...dbs]);
      setFormSuccess(true);
      setForm({ ...EMPTY_FORM });
    } catch (e) {
      setFormErr(errMsg(e));
    } finally {
      setFormBusy(false);
    }
  }

  // ── derived ─────────────────────────────────────────────────────

  const provisioned = databases.filter(d => d.status === "key_provisioned").length;
  const rotationDue = status?.rotation_due_soon ?? 0;

  const filteredDatabases = databases.filter(d => {
    if (filterEngine && d.engine !== filterEngine) return false;
    if (filterStatus && d.status !== filterStatus) return false;
    return true;
  });

  const attentionDbs = databases.filter(d => d.status !== "key_provisioned");

  const VIEWS = ["overview", "databases", "register"];
  const VIEW_LABELS = ["Overview", `Databases (${databases.length})`, "Register"];

  return (
    <div style={{ padding: 24, fontFamily: '"IBM Plex Sans", sans-serif', color: C.text, minHeight: "100%" }}>

      {/* ── Header ── */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
            <Database size={18} color={C.accent} strokeWidth={2} />
            <span style={{ fontSize: 16, fontWeight: 700, color: C.text, letterSpacing: -0.3 }}>Database TDE Key Management</span>
            <B c="green" pulse>Live</B>
          </div>
          <div style={{ fontSize: 11, color: C.muted }}>Provision and manage transparent data encryption keys for registered databases</div>
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          <Btn small primary onClick={() => setView("register")}>
            <Plus size={11} /> Register Database
          </Btn>
          <Btn small onClick={load} disabled={loading}>
            <RefreshCw size={11} /> Refresh
          </Btn>
        </div>
      </div>

      {/* ── Error banner ── */}
      {err && (
        <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 11, marginBottom: 14, display: "flex", alignItems: "center", gap: 8 }}>
          <AlertTriangle size={13} /> {err}
        </div>
      )}

      {/* ── Stats row ── */}
      <div style={{ display: "flex", gap: 10, marginBottom: 20 }}>
        <Stat l="Total Databases" v={loading ? "—" : String(status?.total ?? 0)} s="registered" c="accent" i={Database} />
        <Stat l="Keys Provisioned" v={loading ? "—" : String(provisioned)} s="databases encrypted" c="green" i={ShieldCheck} />
        <Stat l="Rotation Due Soon" v={loading ? "—" : String(rotationDue)} s="keys need rotation" c={rotationDue > 0 ? "amber" : "green"} i={KeyRound} />
        <Stat l="Engines Supported" v={String(ENGINE_OPTS.length)} s="oracle, sql server, db2…" c="blue" i={Database} />
      </div>

      {/* ── View tabs ── */}
      <div style={{ display: "flex", gap: 2, marginBottom: 18, borderBottom: `1px solid ${C.border}` }}>
        {VIEWS.map((key, idx) => (
          <button key={key} onClick={() => setView(key as View)} style={{
            padding: "8px 16px", border: "none", background: "transparent", cursor: "pointer",
            fontSize: 11, fontWeight: view === key ? 700 : 400,
            color: view === key ? C.accent : C.muted,
            borderBottom: view === key ? `2px solid ${C.accent}` : "2px solid transparent",
            marginBottom: -1, letterSpacing: 0.1,
          }}>{VIEW_LABELS[idx]}</button>
        ))}
      </div>

      {/* ════════════════════════════════════════════════════════════
          OVERVIEW
      ════════════════════════════════════════════════════════════ */}
      {view === "overview" && (
        <>
          {/* Engine breakdown */}
          {status && Object.keys(status.by_engine ?? {}).length > 0 && (
            <Section title="TDE Status by Engine">
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                {["oracle", "sqlserver", "db2", "mysql", "postgresql"].map(eng => {
                  const cnt = status.by_engine?.[eng];
                  if (cnt === undefined && cnt !== 0) return null;
                  const color = ENGINE_COLORS[eng] ?? "accent";
                  return (
                    <Card key={eng} style={{ flex: "1 1 140px", minWidth: 140 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                        <Database size={14} color={C[color] ?? C.accent} />
                        <B c={color}>{eng}</B>
                      </div>
                      <div style={{ fontSize: 22, fontWeight: 700, color: C[color] ?? C.accent }}>{cnt ?? 0}</div>
                      <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>databases</div>
                    </Card>
                  );
                })}
              </div>
            </Section>
          )}

          {/* Databases needing attention */}
          <Section title="Databases Needing Attention" actions={
            <Btn small onClick={() => setView("databases")}>View All</Btn>
          }>
            <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
              {loading ? (
                <div style={{ padding: "32px 20px", textAlign: "center", color: C.muted, fontSize: 11 }}>Loading…</div>
              ) : attentionDbs.length === 0 ? (
                <div style={{ padding: "36px 20px", textAlign: "center" }}>
                  <ShieldCheck size={26} color={C.green} style={{ marginBottom: 8 }} />
                  <div style={{ color: C.green, fontSize: 12, fontWeight: 600 }}>All databases have keys provisioned</div>
                  <div style={{ color: C.muted, fontSize: 10, marginTop: 4 }}>No attention required at this time.</div>
                </div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["Database", "Engine", "Host", "Status", "Last Rotated", "Actions"].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {attentionDbs.map((db, i) => (
                      <tr key={db.id}
                        onMouseEnter={e => e.currentTarget.style.filter = "brightness(1.07)"}
                        onMouseLeave={e => e.currentTarget.style.filter = ""}>
                        <td style={{ ...TD(i), color: C.text, fontWeight: 600 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                            <Database size={12} color={C.muted} />
                            {db.name}
                          </div>
                        </td>
                        <td style={TD(i)}><B c={ENGINE_COLORS[db.engine] ?? "accent"}>{db.engine}</B></td>
                        <td style={{ ...TD(i), fontFamily: "monospace", fontSize: 10 }}>{db.host}:{db.port}</td>
                        <td style={TD(i)}>
                          <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                            {tdeStatusIcon(db.status)}
                            <B c={tdeStatusBadgeColor(db.status)}>{db.status.replace(/_/g, " ")}</B>
                          </div>
                        </td>
                        <td style={{ ...TD(i), fontSize: 10 }}>{fmtDate(db.last_rotated)}</td>
                        <td style={TD(i)}>
                          <Btn small primary onClick={() => doProvision(db.id)} disabled={busy === db.id + ":provision"}>
                            <KeyRound size={10} /> {busy === db.id + ":provision" ? "…" : "Provision Key"}
                          </Btn>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </Section>
        </>
      )}

      {/* ════════════════════════════════════════════════════════════
          DATABASES
      ════════════════════════════════════════════════════════════ */}
      {view === "databases" && (
        <>
          <Section title="Filter" actions={null}>
            <div style={{ display: "flex", gap: 10, marginBottom: 14 }}>
              <div style={{ width: 180 }}>
                <Sel value={filterEngine} onChange={e => setFilterEngine(e.target.value)}>
                  <option value="">All Engines</option>
                  {ENGINE_OPTS.map(e => <option key={e} value={e}>{e}</option>)}
                </Sel>
              </div>
              <div style={{ width: 200 }}>
                <Sel value={filterStatus} onChange={e => setFilterStatus(e.target.value)}>
                  <option value="">All Statuses</option>
                  <option value="registered">Registered</option>
                  <option value="key_provisioned">Key Provisioned</option>
                  <option value="revoked">Revoked</option>
                </Sel>
              </div>
            </div>
          </Section>

          <Section title={`Databases (${filteredDatabases.length})`}>
            <div style={{ background: C.card, borderRadius: 10, border: `1px solid ${C.border}`, overflow: "hidden" }}>
              {loading && databases.length === 0 ? (
                <div style={{ padding: "32px 20px", textAlign: "center", color: C.muted, fontSize: 11 }}>Loading…</div>
              ) : filteredDatabases.length === 0 ? (
                <div style={{ padding: "36px 20px", textAlign: "center" }}>
                  <Database size={26} color={C.border} style={{ marginBottom: 8 }} />
                  <div style={{ color: C.muted, fontSize: 11 }}>No databases match this filter.</div>
                </div>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      {["Database Name", "Engine", "Host", "Status", "Key Status", "Last Rotated", "Actions"].map(h => <th key={h} style={TH}>{h}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredDatabases.map((db, i) => (
                      <tr key={db.id}
                        onMouseEnter={e => e.currentTarget.style.filter = "brightness(1.07)"}
                        onMouseLeave={e => e.currentTarget.style.filter = ""}>
                        <td style={{ ...TD(i), color: C.text, fontWeight: 600 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                            <Database size={12} color={C.muted} />
                            {db.name}
                          </div>
                          <div style={{ fontSize: 10, color: C.muted, marginTop: 1 }}>{db.db_name}</div>
                        </td>
                        <td style={TD(i)}><B c={ENGINE_COLORS[db.engine] ?? "accent"}>{db.engine}</B></td>
                        <td style={{ ...TD(i), fontFamily: "monospace", fontSize: 10 }}>{db.host}:{db.port}</td>
                        <td style={TD(i)}>
                          <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                            {tdeStatusIcon(db.status)}
                            <B c={tdeStatusBadgeColor(db.status)}>{db.status.replace(/_/g, " ")}</B>
                          </div>
                        </td>
                        <td style={TD(i)}><B c={db.key_algorithm ? "blue" : "amber"}>{db.key_algorithm || "Not assigned"}</B></td>
                        <td style={{ ...TD(i), fontSize: 10 }}>{fmtDate(db.last_rotated)}</td>
                        <td style={TD(i)}>
                          <div style={{ display: "flex", gap: 5 }}>
                            {db.status !== "revoked" && (
                              <Btn small primary onClick={() => doProvision(db.id)} disabled={busy === db.id + ":provision"}>
                                <KeyRound size={10} /> {busy === db.id + ":provision" ? "…" : db.status === "key_provisioned" ? "Rotate" : "Provision"}
                              </Btn>
                            )}
                            {db.status === "key_provisioned" && (
                              <Btn small danger onClick={() => doRevoke(db.id)} disabled={busy === db.id + ":revoke"}>
                                <Trash2 size={10} /> {busy === db.id + ":revoke" ? "…" : "Revoke"}
                              </Btn>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </Section>
        </>
      )}

      {/* ════════════════════════════════════════════════════════════
          REGISTER
      ════════════════════════════════════════════════════════════ */}
      {view === "register" && (
        <Section title="Register New Database">
          <Card style={{ maxWidth: 700 }}>
            {formSuccess && (
              <div style={{ display: "flex", alignItems: "center", gap: 8, background: C.greenDim, border: `1px solid ${C.green}`, borderRadius: 8, padding: "10px 14px", marginBottom: 16, color: C.green, fontSize: 11 }}>
                <CheckCircle2 size={14} /> Database registered successfully.
              </div>
            )}

            <Row2>
              <FG label="Display Name" required>
                <Inp
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="prod-oracle-hr"
                />
              </FG>
              <FG label="Engine" required>
                <Sel value={form.engine} onChange={e => setForm(f => ({ ...f, engine: e.target.value }))}>
                  {ENGINE_OPTS.map(e => <option key={e} value={e}>{e}</option>)}
                </Sel>
              </FG>
            </Row2>

            <Row2>
              <FG label="Host" required>
                <Inp
                  value={form.host}
                  onChange={e => setForm(f => ({ ...f, host: e.target.value }))}
                  placeholder="db.example.com"
                  mono
                />
              </FG>
              <FG label="Port" required>
                <Inp
                  value={form.port}
                  onChange={e => setForm(f => ({ ...f, port: e.target.value }))}
                  placeholder="5432"
                />
              </FG>
            </Row2>

            <FG label="Database Name" required>
              <Inp
                value={form.db_name}
                onChange={e => setForm(f => ({ ...f, db_name: e.target.value }))}
                placeholder="hrdb"
                mono
              />
            </FG>

            <Row2>
              <FG label="TDE Mode">
                <Sel value={form.tde_mode} onChange={e => setForm(f => ({ ...f, tde_mode: e.target.value }))}>
                  {TDE_MODES.map(m => <option key={m} value={m}>{m}</option>)}
                </Sel>
              </FG>
              <FG label="Rotation Policy">
                <Sel value={form.rotation_policy} onChange={e => setForm(f => ({ ...f, rotation_policy: e.target.value }))}>
                  {ROTATION_OPTS.map(r => <option key={r} value={r}>{r === "none" ? "No rotation" : `Every ${r}`}</option>)}
                </Sel>
              </FG>
            </Row2>

            <FG label="Notes">
              <Txt
                rows={3}
                mono={false}
                value={form.notes}
                onChange={e => setForm(f => ({ ...f, notes: e.target.value }))}
                placeholder="Optional notes about this database registration…"
              />
            </FG>

            {formErr && (
              <div style={{ background: C.redDim, border: `1px solid ${C.red}`, borderRadius: 6, padding: "7px 10px", color: C.red, fontSize: 11, marginBottom: 12 }}>
                {formErr}
              </div>
            )}

            <div style={{ display: "flex", gap: 8 }}>
              <Btn primary onClick={doRegister} disabled={formBusy}>
                <Plus size={12} /> {formBusy ? "Registering…" : "Register Database"}
              </Btn>
              <Btn onClick={() => { setForm({ ...EMPTY_FORM }); setFormErr(""); setFormSuccess(false); }}>
                Reset
              </Btn>
            </div>
          </Card>
        </Section>
      )}
    </div>
  );
}
