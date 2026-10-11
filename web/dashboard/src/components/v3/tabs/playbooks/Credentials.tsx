import { AlertTriangle, CheckCircle2, Clock, KeyRound, Plus, RefreshCcw, RotateCcw, ShieldAlert, XCircle } from "lucide-react";
import { type ReactNode, useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../../../lib/auth";
import { deleteCredential, listCredentials, testCredential, type Credential, type CredentialType } from "../../../../lib/credentials";
import { DrillPanel, clickable } from "../../chartDrill";
import { B, Btn, Stat } from "../../legacyPrimitives";
import { errMsg } from "../../runtimeUtils";
import { C } from "../../theme";
import { BarRow, ChartCard, Swatch, solid } from "../discovery/Charts";
import { PrivateEndpoints } from "../PrivateEndpoints";
import { CredentialDetail } from "./CredentialDetail";
import { CredentialForm } from "./CredentialForm";
import {
  AGE, CATEGORIES, EXPIRY, EXPOSED_FILL, HEALTH, SERIES_FILL, ageBucket, ageDays, ageDrill, allDrill, categoryDrill, expiringDrill,
  expiryBucket, expiryDrill, exposedDrill, fmtDate, health, healthDrill, rotationDrill, rotationDue, typeDrill, type CredentialDrill,
} from "./credentialMeta";

type Props = {
  session: AuthSession;
  // Open exposure-register items by credential ID (stored in plaintext by an
  // earlier release); exposureError when the register can't be read.
  exposed: Record<string, { exposed_since?: string }>;
  exposureError?: string;
  onToast: (message: string) => void;
  onNavigate?: ((tab: string) => void) | undefined;
  // Tells the Playbooks tab its connection list changed.
  onChanged?: (() => void) | undefined;
};

const HealthBadge = ({ c }: { c: Credential }) => {
  const h = health(c);
  return h === "ok" ? <B c="green">Test passed</B> : h === "failing" ? <B c="red">Test failed</B> : <B c="blue">Not tested</B>;
};

// Playbooks → Credentials: the one place a credential for an external
// system is added, before any feature can use it.
export function Credentials({ session, exposed, exposureError, onToast, onNavigate, onChanged }: Props) {
  const [items, setItems] = useState<Credential[]>([]);
  const [types, setTypes] = useState<CredentialType[]>([]);
  const [error, setError] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [drill, setDrill] = useState<CredentialDrill | null>(null);
  const [form, setForm] = useState<{ editing?: Credential; startType?: string } | null>(null);
  const [openId, setOpenId] = useState("");
  const [busy, setBusy] = useState("");
  // The moment the list was read: ages and expiry are counted from it.
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(async () => {
    try {
      const res = await listCredentials(session);
      setItems(res.items);
      setTypes(res.types);
      setNow(Date.now());
      setError("");
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setLoaded(true);
    }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const changed = () => { void load(); onChanged?.(); };
  const typeOf = (t: string) => types.find((x) => x.type === t);
  const count = (d: CredentialDrill) => items.filter(d.match).length;
  const toggle = (d: CredentialDrill) => setDrill((cur) => (cur?.key === d.key ? null : d));
  const active = drill?.key ?? "";
  const dim = (key: string) => Boolean(active) && active !== key;
  const max = (rows: { n: number }[]) => Math.max(0, ...rows.map((r) => r.n));
  const total = items.length;
  const tip = (label: string, n: number) => `${label}: ${n} of ${total}`;

  const test = async (c: Credential) => {
    setBusy(c.id);
    try {
      await testCredential(session, c.id);
      onToast(`${c.name}: test passed.`);
    } catch (e) {
      onToast(`${c.name}: ${errMsg(e)}`);
    } finally {
      setBusy("");
      void load();
    }
  };
  const remove = async (c: Credential) => {
    if (!window.confirm(`Delete credential "${c.name}"?`)) return;
    try {
      await deleteCredential(session, c.id);
      onToast(`${c.name} deleted.`);
      setOpenId("");
    } catch (e) {
      onToast(`Delete refused: ${errMsg(e)}`);
    }
    changed();
  };

  const tile = (d: CredentialDrill, node: ReactNode) => (
    <div role="button" tabIndex={0} title={`List: ${d.label}`} onClick={() => toggle(d)} onKeyDown={(e) => { if (e.key === "Enter") toggle(d); }}
      style={{ ...clickable, display: "flex", borderRadius: "var(--radius-md)", outline: active === d.key ? `2px solid ${C.accentFg}` : "none" }}>{node}</div>
  );
  const byCategory = CATEGORIES.map((cat) => ({ cat, d: categoryDrill(types, cat.id), n: 0 })).map((r) => ({ ...r, n: count(r.d) }));
  const byType = types.map((t) => ({ t, d: typeDrill(t.type, t.label), n: 0 })).map((r) => ({ ...r, n: count(r.d) })).filter((r) => r.n > 0).sort((a, b) => b.n - a.n);
  const byHealth = HEALTH.map((h) => ({ h, d: healthDrill(h.id), n: items.filter((c) => health(c) === h.id).length }));
  const byExpiry = EXPIRY.map((b) => ({ b, d: expiryDrill(b.id, now), n: items.filter((c) => expiryBucket(c, now) === b.id).length }));
  const byAge = AGE.map((b) => ({ b, d: ageDrill(b.id, now), n: items.filter((c) => ageBucket(c, now) === b.id).length }));
  const exposedD = exposedDrill(exposed);
  const shown = drill ? items.filter(drill.match) : items;
  const open = items.find((c) => c.id === openId);

  const row = (c: Credential) => (
    <div key={c.id} onClick={() => setOpenId(c.id)}
      style={{ ...clickable, display: "grid", gridTemplateColumns: "2fr 1.4fr 1.3fr 110px 1.1fr 90px", gap: 10, alignItems: "center", padding: "8px 6px", borderBottom: `1px solid ${C.border}`, fontSize: 11 }}
      onMouseEnter={(e) => { e.currentTarget.style.background = C.cardHover; }} onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}>
      <span style={{ fontWeight: 600, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {c.name}{exposed[c.id] ? <span style={{ marginLeft: 6 }}><B c="red">Rotate</B></span> : null}
      </span>
      <span style={{ color: C.dim }}>{typeOf(c.type)?.label ?? c.type}</span>
      <span style={{ color: C.dim, fontFamily: "'JetBrains Mono',ui-monospace,monospace", fontSize: 10.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.endpoint || "-"}</span>
      <span><HealthBadge c={c} /></span>
      <span style={{ color: rotationDue(c, now) || ["expired", "7d"].includes(expiryBucket(c, now)) ? C.amberFg : C.dim }}>
        {c.expires_at ? `expires ${fmtDate(c.expires_at)}` : `secret ${ageDays(c, now)}d old`}
      </span>
      <span style={{ textAlign: "right" }} onClick={(e) => e.stopPropagation()}>
        <Btn small disabled={busy === c.id} onClick={() => void test(c)}>{busy === c.id ? "…" : "Test"}</Btn>
      </span>
    </div>
  );

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, gap: 8, flexWrap: "wrap" }}>
        <span style={{ fontSize: 11, color: C.muted }}>Add a credential here first; cloud accounts, HSM keys, mail, playbooks, event streams and scans then pick it. Values are sealed and never shown again.</span>
        <span style={{ display: "flex", gap: 8 }}>
          <Btn small onClick={() => void load()}><RefreshCcw size={11} /></Btn>
          <Btn small primary disabled={types.length === 0} onClick={() => setForm({})}><Plus size={11} /> Add credential</Btn>
        </span>
      </div>
      {error ? <div style={{ padding: 12, marginBottom: 12, border: `1px solid ${C.redFg}`, borderRadius: 8, color: C.redFg, fontSize: 11 }}>Credentials unavailable: {error}</div> : null}
      {exposureError ? <div style={{ fontSize: 11, color: C.amberFg, marginBottom: 10 }}>Exposure register unavailable; which credentials need rotating is not assessed: {exposureError}</div> : null}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))", gap: 10, marginBottom: 12 }}>
        {tile(allDrill(), <Stat l="Credentials" v={loaded && !error ? total : "-"} s={`${new Set(items.map((c) => c.type)).size} types`} c="accent" i={KeyRound} />)}
        {tile(healthDrill("ok"), <Stat l="Test passed" v={byHealth[0]?.n ?? 0} s="last real test" c="green" i={CheckCircle2} />)}
        {tile(healthDrill("failing"), <Stat l="Test failed" v={byHealth[1]?.n ?? 0} s="not working now" c="red" i={XCircle} />)}
        {tile(healthDrill("untested"), <Stat l="Not tested" v={byHealth[2]?.n ?? 0} s="since the secret changed" c="blue" i={AlertTriangle} />)}
        {tile(expiringDrill(now), <Stat l="Expiring" v={count(expiringDrill(now))} s="expired or within 30 days" c="amber" i={Clock} />)}
        {tile(rotationDrill(now), <Stat l="Rotation due" v={count(rotationDrill(now))} s="older than its interval" c="orange" i={RotateCcw} />)}
        {tile(exposedD, <Stat l="Exposed" v={exposureError ? "-" : count(exposedD)} s={exposureError ? "not assessed" : "stored in plaintext before"} c="purple" i={ShieldAlert} />)}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 10 }}>
        <ChartCard title="By use" sub={`${total} credentials`}>
          {byCategory.map(({ cat, d, n }) => (
            <BarRow key={cat.id} label={cat.label} value={n} max={max(byCategory)} bar={solid(SERIES_FILL)} title={tip(cat.label, n)} active={active === d.key} dim={dim(d.key)} onClick={() => toggle(d)} />
          ))}
        </ChartCard>
        <ChartCard title="By type" sub={`${byType.length} in use`}>
          <div style={{ maxHeight: 190, overflowY: "auto" }}>
            {byType.length === 0 ? <div style={{ fontSize: 11, color: C.muted, padding: 8 }}>None yet.</div> : byType.map(({ t, d, n }) => (
              <BarRow key={t.type} label={t.label} value={n} max={max(byType)} bar={solid(SERIES_FILL)} title={tip(t.label, n)} active={active === d.key} dim={dim(d.key)} onClick={() => toggle(d)} />
            ))}
          </div>
        </ChartCard>
        <ChartCard title="Health" sub="last real test">
          {byHealth.map(({ h, d, n }) => (
            <BarRow key={h.id} label={<><Swatch color={h.color} />{h.label}</>} value={n} max={max(byHealth)} bar={solid(h.color)} title={tip(h.label, n)} active={active === d.key} dim={dim(d.key)} onClick={() => toggle(d)} />
          ))}
          {exposureError ? null : <BarRow label={<><Swatch color={EXPOSED_FILL} />Exposed</>} value={count(exposedD)} max={Math.max(max(byHealth), count(exposedD))} bar={solid(EXPOSED_FILL)}
            title={tip("Exposed", count(exposedD))} active={active === exposedD.key} dim={dim(exposedD.key)} onClick={() => toggle(exposedD)} />}
        </ChartCard>
        <ChartCard title="Expiry" sub="as recorded">
          {byExpiry.map(({ b, d, n }) => (
            <BarRow key={b.id} label={<><Swatch color={b.color} />{b.label}</>} value={n} max={max(byExpiry)} bar={solid(b.color)} title={tip(b.label, n)} active={active === d.key} dim={dim(d.key)} onClick={() => toggle(d)} />
          ))}
        </ChartCard>
        <ChartCard title="Secret age" sub="since last change">
          {byAge.map(({ b, d, n }) => (
            <BarRow key={b.id} label={<><Swatch color={b.color} />{b.label}</>} value={n} max={max(byAge)} bar={solid(b.color)} title={tip(b.label, n)} active={active === d.key} dim={dim(d.key)} onClick={() => toggle(d)} />
          ))}
        </ChartCard>
      </div>

      <DrillPanel label={drill?.label ?? "All credentials"} count={shown.length} onClear={() => setDrill(null)}>
        {shown.map(row)}
      </DrillPanel>

      {/* Private ranges a root administrator approved for scan sources and mail relays. */}
      <PrivateEndpoints session={session} />

      {form ? <CredentialForm session={session} types={types} editing={form.editing} startType={form.startType} onClose={() => setForm(null)}
        onSaved={(m) => { setForm(null); onToast(m); changed(); }} /> : null}
      {open ? <CredentialDetail session={session} credential={open} type={typeOf(open.type)} exposedSince={exposed[open.id]?.exposed_since} now={now} busy={busy === open.id}
        onNavigate={onNavigate} onClose={() => setOpenId("")} onTest={() => void test(open)} onEdit={() => { setOpenId(""); setForm({ editing: open }); }} onDelete={() => void remove(open)} /> : null}
    </div>
  );
}
