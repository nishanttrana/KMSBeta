import { useCallback, useEffect, useState, type ReactNode } from "react";
import { ArrowRight, X } from "lucide-react";
import type { AuthSession } from "../../../../lib/auth";
import { deleteEKMAgent, listEKMAgentLogs, rotateEKMAgentKey, type EKMAccessLog } from "../../../../lib/ekm";
import { getEKMClient, type EKMClient, type EKMClientDetail } from "../../../../lib/ekmClients";
import { Btn } from "../../legacyPrimitives";
import { errMsg } from "../../runtimeUtils";
import { C } from "../../theme";
import { CheckInStrip } from "./CheckInStrip";
import { HEALTH, MONO, ageNow, ago, engineLabel, fmtTime, span } from "./meta";

type Props = {
  session: AuthSession;
  clientId: string;
  onClose: () => void;
  onChanged: () => void;
  onReenrol: (client: EKMClient) => void;
  confirm: (opts: Record<string, unknown>) => Promise<boolean>;
  onToast?: ((msg: string) => void) | undefined;
};

const Section = ({ title, children }: { title: string; children: ReactNode }) => (
  <div style={{ marginTop: 18 }}>
    <div style={{ fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 8 }}>{title}</div>
    {children}
  </div>
);

const Row = ({ k, children, mono = false }: { k: string; children: ReactNode; mono?: boolean }) => (
  <div style={{ display: "flex", justifyContent: "space-between", gap: 12, padding: "5px 0", fontSize: 12 }}>
    <span style={{ color: C.muted, flexShrink: 0 }}>{k}</span>
    <span style={{ color: C.text, textAlign: "right", overflowWrap: "anywhere", fontFamily: mono ? MONO : "inherit" }}>{children}</span>
  </div>
);

const Node = ({ children }: { children: ReactNode }) => (
  <span style={{ border: `1px solid ${C.border}`, background: C.card, borderRadius: "var(--radius-md)", padding: "5px 9px", fontSize: 12, color: C.text }}>{children}</span>
);

// Health of one client: the verdict, the path to the KMS, every recent
// check-in, and what the agent last reported. Refreshed while open.
export function ClientDrawer({ session, clientId, onClose, onChanged, onReenrol, confirm, onToast }: Props) {
  const [detail, setDetail] = useState<EKMClientDetail | null>(null);
  const [error, setError] = useState("");
  const [fetchedAt, setFetchedAt] = useState(0);
  const [now, setNow] = useState(() => Date.now());
  const [logs, setLogs] = useState<EKMAccessLog[] | null>(null);
  const [busy, setBusy] = useState("");

  const load = useCallback(async (quiet: boolean) => {
    try {
      const d = await getEKMClient(session, clientId, quiet);
      setDetail(d);
      setFetchedAt(Date.now());
      setError("");
    } catch (e) {
      setError(errMsg(e));
    }
  }, [session, clientId]);

  useEffect(() => {
    void load(false);
    const poll = setInterval(() => void load(true), 5000);
    const tick = setInterval(() => setNow(Date.now()), 1000);
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", esc);
    return () => { clearInterval(poll); clearInterval(tick); window.removeEventListener("keydown", esc); };
  }, [load, onClose]);

  const c = detail?.client;
  const h = c ? HEALTH[c.health] : null;
  const age = c ? ageNow(c, fetchedAt, now) : undefined;
  const last = detail?.check_ins[detail.check_ins.length - 1];

  const act = async (name: string, fn: () => Promise<void>) => {
    setBusy(name);
    try { await fn(); } catch (e) { onToast?.(`${name} failed: ${errMsg(e)}`); } finally { setBusy(""); }
  };

  const rotate = () => act("Rotate key", async () => {
    if (!c || !(await confirm({ title: "Rotate TDE key", message: `Create a new version of the TDE key of ${c.name}? The database must then be re-keyed on the host.`, confirmLabel: "Rotate key" }))) return;
    await rotateEKMAgentKey(session, c.id, "manual-dashboard");
    onToast?.(`New key version created for ${c.name}.`);
    await load(true);
    onChanged();
  });

  const remove = () => act("Remove", async () => {
    if (!c || !(await confirm({ title: "Remove client", message: `Remove ${c.name}? Its agent can no longer check in, and its databases, TDE keys and key request log are deleted. This can't be undone.`, confirmLabel: "Remove client", danger: true }))) return;
    await deleteEKMAgent(session, c.id, "manual-dashboard-delete");
    onToast?.(`${c.name} removed.`);
    onChanged();
    onClose();
  });

  const summary = () => {
    if (!c) return "";
    const since = ago(age).replace(" ago", "").toLowerCase();
    if (c.health === "pending") return "Waiting for the agent to present its registration token.";
    if (age === undefined) return "No check-in on record.";
    if (c.health === "healthy") return `Checked in ${ago(age).toLowerCase()}.`;
    return `No check-in for ${since}.`;
  };

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 900 }}>
      <div onClick={onClose} style={{ position: "absolute", inset: 0, background: "var(--c-scrim)" }} />
      <aside role="dialog" aria-label="Client health" data-testid="ekm-client-drawer" style={{ position: "absolute", top: 0, right: 0, bottom: 0, width: "min(460px, 100vw)", background: C.surface, borderLeft: `1px solid ${C.borderHi}`, boxShadow: "var(--shadow-lg)", display: "flex", flexDirection: "column" }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 12, padding: "16px 20px", borderBottom: `1px solid ${C.border}` }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 15, fontWeight: 600, color: C.text, overflowWrap: "anywhere" }}>{c?.name ?? "Client"}</div>
            {c && <div style={{ fontSize: 12, color: C.muted, marginTop: 3 }}>{engineLabel(c.db_engine)}{c.host ? ` · ${c.host}` : ""}</div>}
          </div>
          <button onClick={onClose} aria-label="Close" style={{ background: "transparent", border: `1px solid ${C.border}`, borderRadius: "var(--radius-md)", color: C.muted, cursor: "pointer", padding: 6, display: "inline-flex" }}><X size={14} /></button>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: "16px 20px 20px" }}>
          {error && <div data-keep="" style={{ fontSize: 12, color: C.redFg, marginBottom: 12 }}>Unavailable: {error}</div>}
          {!detail && !error && <div style={{ fontSize: 12, color: C.muted }}>Loading…</div>}
          {c && h && detail && (<>
            <div data-testid="ekm-client-health" style={{ display: "flex", gap: 12, alignItems: "center", background: h.bg, border: `1px solid ${h.bg}`, borderRadius: "var(--radius-md)", padding: "12px 14px" }}>
              <span style={{ width: 34, height: 34, borderRadius: 17, background: C.card, color: h.fg, display: "inline-flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}><h.icon size={16} /></span>
              <div>
                <div style={{ fontSize: 14, fontWeight: 600, color: h.fg }}>{h.label}</div>
                <div data-keep="" style={{ fontSize: 12, color: C.dim, marginTop: 2 }}>{summary()}</div>
              </div>
            </div>

            <Section title="Connection path">
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <Node>{c.name}</Node>
                {c.health === "offline" || c.health === "pending" ? <X size={14} style={{ color: c.health === "offline" ? C.redFg : C.muted }} aria-label="Not connected" /> : <ArrowRight size={14} style={{ color: C.muted }} />}
                <Node>Vecta KMS</Node>
                <ArrowRight size={14} style={{ color: C.muted }} />
                <Node>{detail.key ? `Key · ${detail.key.name}` : "No TDE key"}</Node>
              </div>
            </Section>

            <Section title="Check-ins">
              <CheckInStrip checkIns={detail.check_ins} intervalSec={c.heartbeat_interval_sec} serverTime={detail.server_time} />
            </Section>

            <Section title="Details">
              <Row k="Last check-in">{ago(age)}</Row>
              <Row k="Agent">{c.version || "not reported"}{last?.status ? ` · reported ${last.status}` : ""}</Row>
              <Row k="Checks in every">{c.heartbeat_interval_sec}s</Row>
              <Row k="Host">{c.host || "-"}</Row>
              <Row k="Source IP">{c.source_ip || "-"}</Row>
              <Row k="Registered">{fmtTime(c.registered_at)}</Row>
              <Row k="Credential">{c.credential === "client_key" ? "Client key" : c.credential === "service_token" ? "Service token" : "None yet"}</Row>
              <Row k="TDE state (reported)">{c.registration === "pending" ? "-" : c.tde_state}</Row>
              <Row k="TDE key" mono>{detail.key ? `${detail.key.name} · ${detail.key.algorithm} ${detail.key.version}` : "none"}</Row>
              <Row k="Last key request">{detail.last_key_request ? `${detail.last_key_request.operation} · ${detail.last_key_request.status} · ${fmtTime(detail.last_key_request.at)}` : "none recorded"}</Row>
              {detail.databases !== undefined && <Row k="Databases">{detail.databases} ({detail.tde_enabled_databases ?? 0} with TDE)</Row>}
              <Row k="Client ID" mono>{c.id}</Row>
            </Section>

            {detail.metrics && (
              <Section title="Host (as reported)">
                {([["CPU", detail.metrics.cpu_usage_pct], ["Memory", detail.metrics.memory_usage_pct], ["Disk", detail.metrics.disk_usage_pct]] as const).map(([k, v]) => (
                  <div key={k} style={{ display: "grid", gridTemplateColumns: "70px 1fr 46px", alignItems: "center", gap: 8, fontSize: 12, padding: "4px 0" }}>
                    <span style={{ color: C.muted }}>{k}</span>
                    <span style={{ height: 6, borderRadius: 3, background: C.border, overflow: "hidden" }}><span style={{ display: "block", height: "100%", width: `${Math.max(0, Math.min(100, v))}%`, background: v >= 90 ? "var(--cls-missed)" : "var(--cls-ontime)" }} /></span>
                    <span className="vk-num" style={{ color: C.text, textAlign: "right" }}>{v.toFixed(0)}%</span>
                  </div>
                ))}
              </Section>
            )}

            <Section title="Health thresholds">
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
                {([["healthy", `up to ${span(detail.thresholds.healthy_within_sec)}`], ["degraded", `${span(detail.thresholds.healthy_within_sec)} to ${span(detail.thresholds.degraded_within_sec)}`], ["offline", `over ${span(detail.thresholds.degraded_within_sec)}`]] as const).map(([k, v]) => (
                  <div key={k} style={{ background: HEALTH[k].bg, borderRadius: "var(--radius-md)", padding: "8px 10px", fontSize: 12 }}>
                    <div style={{ color: HEALTH[k].fg, fontWeight: 600 }}>{HEALTH[k].label}</div>
                    <div style={{ color: C.dim, marginTop: 2 }}>{v}</div>
                  </div>
                ))}
              </div>
            </Section>

            <Section title="Key requests">
              {logs === null ? (
                <Btn small onClick={() => act("Key requests", async () => setLogs(await listEKMAgentLogs(session, c.id, 20)))} disabled={busy === "Key requests"}>Show recent</Btn>
              ) : logs.length === 0 ? (
                <div style={{ fontSize: 12, color: C.muted }}>None recorded.</div>
              ) : logs.map((l) => (
                <div key={l.id} style={{ display: "grid", gridTemplateColumns: "1fr 70px 1.4fr", gap: 8, fontSize: 11.5, padding: "4px 0", borderBottom: `1px solid ${C.border}` }}>
                  <span style={{ color: C.text }}>{l.operation}</span>
                  <span style={{ color: l.status === "success" ? C.greenFg : C.redFg }}>{l.status}</span>
                  <span style={{ color: C.muted, textAlign: "right" }}>{fmtTime(l.created_at)}</span>
                </div>
              ))}
            </Section>
          </>)}
        </div>

        {c && (
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", padding: "12px 20px", borderTop: `1px solid ${C.border}` }}>
            <Btn small onClick={rotate} disabled={!detail?.key || busy !== ""}>Rotate key</Btn>
            <Btn small onClick={() => onReenrol(c)} disabled={busy !== ""}>New registration token</Btn>
            <Btn small danger onClick={remove} disabled={busy !== ""} style={{ marginLeft: "auto" }}>Remove</Btn>
          </div>
        )}
      </aside>
    </div>
  );
}
