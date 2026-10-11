import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowRight, Check, Plus, RefreshCcw, X } from "lucide-react";
import type { AuthSession } from "../../../../lib/auth";
import { listEKMClients, type EKMClient, type EKMClientList } from "../../../../lib/ekmClients";
import { clickable } from "../../chartDrill";
import { Btn, Card, Inp, Stat, usePromptDialog } from "../../legacyPrimitives";
import { errMsg } from "../../runtimeUtils";
import { C } from "../../theme";
import { AddClientWizard } from "./AddClientWizard";
import { ClientDrawer } from "./ClientDrawer";
import { HEALTH, MONO, ageNow, ago, engineLabel, tiles, type ClientDrill } from "./meta";

type Props = {
  session: AuthSession;
  onToast?: ((msg: string) => void) | undefined;
  // Called after a client is added, enrolled or removed.
  onChanged?: (() => void) | undefined;
};

const th = { padding: "9px 14px", textAlign: "left" as const, fontSize: 11, fontWeight: 600, color: C.muted };
const td = { padding: "10px 14px", fontSize: 12.5, color: C.text, verticalAlign: "middle" as const };
const cut = { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" as const };

const Pill = ({ health }: { health: EKMClient["health"] }) => {
  const h = HEALTH[health];
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "2px 9px", borderRadius: 10, fontSize: 11.5, fontWeight: 600, color: h.fg, background: h.bg, whiteSpace: "nowrap" }}>
      <span style={{ width: 6, height: 6, borderRadius: 3, background: "currentColor" }} />{h.label}
    </span>
  );
};

// EKM for DBs: every database client, whether its agent has registered, and
// how long ago it last checked in. Tiles filter the table to the clients
// they count; a row opens the client's health.
export function EKMClients({ session, onToast, onChanged }: Props) {
  const [list, setList] = useState<EKMClientList | null>(null);
  const [error, setError] = useState("");
  const [fetchedAt, setFetchedAt] = useState(0);
  const [now, setNow] = useState(() => Date.now());
  const [loading, setLoading] = useState(false);
  const [drill, setDrill] = useState<ClientDrill | null>(null);
  const [search, setSearch] = useState("");
  const [openId, setOpenId] = useState("");
  const [wizard, setWizard] = useState<{ resume: EKMClient | null } | null>(null);
  const prompt = usePromptDialog();

  const load = useCallback(async (quiet: boolean) => {
    if (!quiet) setLoading(true);
    try {
      setList(await listEKMClients(session, quiet));
      setFetchedAt(Date.now());
      setError("");
    } catch (e) {
      setError(errMsg(e));
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [session]);

  useEffect(() => {
    void load(false);
    const poll = setInterval(() => void load(true), 10000);
    const tick = setInterval(() => setNow(Date.now()), 1000);
    return () => { clearInterval(poll); clearInterval(tick); };
  }, [load]);

  const changed = useCallback(() => { void load(true); onChanged?.(); }, [load, onChanged]);
  const closeDrawer = useCallback(() => setOpenId(""), []);

  const rows = useMemo(() => list?.items ?? [], [list]);
  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    return rows.filter((c) => (!drill || drill.match(c)) && (!q || [c.name, c.host, c.id, c.db_engine].some((v) => v.toLowerCase().includes(q))));
  }, [rows, drill, search]);
  const open = (c: EKMClient) => (c.registration === "pending" ? setWizard({ resume: c }) : setOpenId(c.id));
  const pick = (d: ClientDrill) => setDrill(drill?.key === d.key ? null : d);

  return (
    <div data-testid="ekm-clients">
      <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap", alignItems: "center" }}>
        <Inp placeholder="Search clients..." value={search} onChange={(e) => setSearch(e.target.value)} style={{ flex: 1, minWidth: 180, maxWidth: 320 }} />
        <span style={{ flex: 1 }} />
        <Btn onClick={() => void load(false)} disabled={loading} aria-label="Refresh"><RefreshCcw size={14} className={loading ? "vecta-spin" : undefined} /></Btn>
        <Btn primary onClick={() => setWizard({ resume: null })}><Plus size={14} />Add client</Btn>
      </div>

      {!list ? (
        <Card><div data-keep="" style={{ fontSize: 12, color: error ? C.redFg : C.muted, textAlign: "center", padding: 20 }}>{error ? `Clients unavailable: ${error}` : "Loading clients…"}</div></Card>
      ) : (<>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: 12, marginBottom: 16 }}>
          {tiles(list.thresholds).map((t) => {
            const n = rows.filter(t.match).length;
            return (
              <div key={t.key} role="button" tabIndex={0} data-testid={`ekm-tile-${t.key}`} aria-pressed={drill?.key === t.key} title={`List: ${t.label}`} onClick={() => pick(t)} onKeyDown={(e) => { if (e.key === "Enter") pick(t); }}
                style={{ ...clickable, display: "flex", borderRadius: "var(--radius-md)", outline: drill?.key === t.key ? `2px solid ${C.accentFg}` : "none" }}>
                <Stat l={t.label} v={n.toLocaleString()} s={t.hint} c={n > 0 && t.attention ? t.attention : "accent"} i={t.icon} />
              </div>
            );
          })}
        </div>

        {error && <div data-keep="" style={{ fontSize: 12, color: C.redFg, marginBottom: 8 }}>Not refreshed: {error}</div>}

        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: "var(--radius-md)", overflow: "hidden" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "12px 14px", borderBottom: `1px solid ${C.border}` }}>
            <span style={{ fontSize: 14, fontWeight: 600, color: C.text }}>Clients</span>
            {drill && (
              <button type="button" onClick={() => setDrill(null)} data-testid="ekm-drill" style={{ ...clickable, display: "inline-flex", alignItems: "center", gap: 5, background: C.accentDim, color: C.accentFg, border: "none", borderRadius: 10, padding: "2px 9px", fontSize: 11.5, fontWeight: 600 }}>
                {drill.label} · {rows.filter(drill.match).length.toLocaleString()}<X size={11} />
              </button>
            )}
          </div>
          {shown.length === 0 ? (
            <div style={{ padding: 32, textAlign: "center", fontSize: 12.5, color: C.muted }}>
              {rows.length === 0 ? "No database clients yet." : "No client matches."}
              {rows.length === 0 && <div style={{ marginTop: 10 }}><Btn primary onClick={() => setWizard({ resume: null })}><Plus size={14} />Add client</Btn></div>}
            </div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%" }}>
                <thead><tr style={{ background: C.surface }}><th style={th}>Client</th><th style={th}>Database</th><th style={th}>Registration</th><th style={th} title="Time since the client's last check-in">Health</th><th style={th}>Last check-in</th><th style={th} /></tr></thead>
                <tbody>
                  {shown.map((c) => (
                    <tr key={c.id} data-testid="ekm-client-row" data-health={c.health} onClick={() => open(c)} style={clickable}>
                      <td style={{ ...td, maxWidth: 340 }} title={`${c.name}${c.host ? ` · ${c.host}` : ""}`}>
                        <div style={{ ...cut, fontWeight: 600 }}>{c.name}</div>
                        <div style={{ ...cut, fontSize: 11.5, color: C.muted, fontFamily: MONO }}>{c.host || c.id}</div>
                      </td>
                      <td style={td}>{engineLabel(c.db_engine)}</td>
                      <td style={td}>
                        {c.registration === "registered"
                          ? <span style={{ display: "inline-flex", alignItems: "center", gap: 5, border: `1px solid ${C.border}`, borderRadius: 10, padding: "2px 9px", fontSize: 11.5 }}><Check size={11} />Registered</span>
                          : <span style={{ fontSize: 11.5, color: C.blueFg }}>Pending</span>}
                      </td>
                      <td style={td}><Pill health={c.health} /></td>
                      <td style={{ ...td, color: C.dim }} className="vk-num">{c.registration === "registered" ? ago(ageNow(c, fetchedAt, now)) : "Never"}</td>
                      <td style={{ ...td, textAlign: "right" }}>
                        <Btn small onClick={(e) => { e.stopPropagation(); open(c); }}>{c.registration === "registered" ? <>Health<ArrowRight size={12} /></> : "Continue setup"}</Btn>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </>)}

      {openId && <ClientDrawer session={session} clientId={openId} onClose={closeDrawer} onChanged={changed} confirm={prompt.confirm} onToast={onToast} onReenrol={(c) => { setOpenId(""); setWizard({ resume: c }); }} />}
      {wizard && <AddClientWizard session={session} resume={wizard.resume} existingNames={rows.map((c) => c.name)} onClose={() => { setWizard(null); void load(true); }} onChanged={changed} />}
      {prompt.ui}
    </div>
  );
}
