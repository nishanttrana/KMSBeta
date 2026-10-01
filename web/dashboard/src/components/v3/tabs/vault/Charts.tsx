import { Clock, History, Lock, RotateCcw, ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";
import type { SecretItem, VaultStats } from "../../../../lib/secrets";
import { clickable } from "../../chartDrill";
import { Stat } from "../../legacyPrimitives";
import { C } from "../../theme";
import { BarRow, ChartCard, Swatch, solid } from "../discovery/Charts";
import {
  AGE_BUCKETS, EXPIRY_BUCKETS, SERIES_FILL, ageBucket, ageDrill, allDrill, expiringDrill, expiryBucket, expiryDrill,
  fmtAgo, fmtDate, getBadge, neverRotatedDrill, typeDrill, VAULT_ROUTES, type VaultDrill,
} from "./meta";

const MONO = "'JetBrains Mono',ui-monospace,monospace";

export const TypeBadge = ({ type }: { type?: string }) => {
  const badge = getBadge(type);
  const Icon = badge.icon;
  return <span style={{ background: badge.bg, color: badge.fg, borderRadius: 6, padding: "3px 8px", fontSize: 10, fontWeight: 600, whiteSpace: "nowrap", display: "inline-flex", alignItems: "center", gap: 4 }}><Icon size={10} /> {badge.t}</span>;
};

// One entry of a drill-down; it opens the secret's detail view.
export const SecretRow = ({ secret: s, onOpen }: { secret: SecretItem; onOpen: () => void }) => (
  <div onClick={onOpen}
    style={{ ...clickable, display: "grid", gridTemplateColumns: "2.4fr 1.1fr 60px 1.2fr 80px", gap: 10, alignItems: "center", padding: "7px 4px", borderBottom: `1px solid ${C.border}`, fontSize: 11 }}
    onMouseEnter={(e) => { e.currentTarget.style.background = C.cardHover; }} onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}>
    <span style={{ fontWeight: 600, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.name}</span>
    <span><TypeBadge type={s.secret_type} /></span>
    <span style={{ color: C.dim }}>v{s.current_version}</span>
    <span style={{ color: C.dim }}>{s.expires_at ? `expires ${fmtDate(s.expires_at)}` : "no expiry"}</span>
    <span style={{ color: C.muted, textAlign: "right" }}>{fmtAgo(s.updated_at)}</span>
  </div>
);

// The Vault / OpenBao KV routes the service registers, for client setup.
export const VaultApiCard = ({ onNavigate }: { onNavigate?: ((tab: string) => void) | undefined }) => (
  <div style={{ marginTop: 20, background: C.card, border: `1px solid ${C.border}`, borderRadius: "var(--radius-md)", padding: "14px 16px" }}>
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 8, marginBottom: 10, flexWrap: "wrap" }}>
      <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>Vault / OpenBao KV clients</span>
      <span style={{ fontSize: 10.5, color: C.muted }}>base <code style={{ fontFamily: MONO, color: C.text }}>/svc/secrets</code> · tenant in <code style={{ fontFamily: MONO, color: C.text }}>X-Vault-Namespace</code> · the path is the secret's name</span>
    </div>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))", gap: "4px 16px" }}>
      {VAULT_ROUTES.map((r) => (
        <div key={`${r.method} ${r.path}`} style={{ display: "grid", gridTemplateColumns: "48px 1fr auto", gap: 8, alignItems: "baseline", fontSize: 11, padding: "3px 0" }}>
          <span style={{ fontFamily: MONO, fontSize: 10, color: C.muted }}>{r.method}</span>
          <code style={{ fontFamily: MONO, fontSize: 10.5, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.path}</code>
          <span style={{ color: C.muted }}>{r.what}</span>
        </div>
      ))}
    </div>
    {onNavigate && <div style={{ marginTop: 10, fontSize: 11, color: C.muted }}>
      Secret activity is recorded in the <span onClick={() => onNavigate("audit")} style={{ ...clickable, color: C.accentFg }}>Audit Log</span>.
    </div>}
  </div>
);

type Props = { secrets: SecretItem[]; now: number; active: string; onDrill: (d: VaultDrill) => void };

const count = (secrets: SecretItem[], d: VaultDrill) => secrets.filter(d.match).length;
const pct = (n: number, total: number) => (total > 0 ? Math.round((n / total) * 100) : 0);

export function VaultTiles({ secrets, now, active, onDrill, stats, statsError }: Props & { stats: VaultStats | null; statsError: string }) {
  const total = secrets.length;
  const tile = (d: VaultDrill, node: ReactNode) => (
    <div role="button" tabIndex={0} title={`List: ${d.label}`} onClick={() => onDrill(d)} onKeyDown={(e) => { if (e.key === "Enter") onDrill(d); }}
      style={{ ...clickable, display: "flex", borderRadius: "var(--radius-md)", outline: active === d.key ? `2px solid ${C.accentFg}` : "none" }}>{node}</div>
  );
  const expired = count(secrets, expiryDrill("expired", now));
  const expiring = count(secrets, expiringDrill(now));
  const v1 = count(secrets, neverRotatedDrill());
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(160px,1fr))", gap: 10, marginBottom: 14 }}>
      {tile(allDrill(), <Stat l="Secrets" v={total.toLocaleString()} s={`${new Set(secrets.map((s) => s.secret_type)).size} types`} c="accent" i={Lock} />)}
      <Stat l="Versions stored" v={stats ? stats.total_versions.toLocaleString() : "-"} s={stats ? "all values, all versions" : `unavailable: ${statsError || "no answer"}`} c="blue" i={History} />
      {tile(expiringDrill(now), <Stat l="Expiring in 30 days" v={String(expiring)} s={`${pct(expiring, total)}% of secrets`} c="amber" i={Clock} />)}
      {tile(expiryDrill("expired", now), <Stat l="Expired" v={String(expired)} s="value reads are refused" c="red" i={ShieldAlert} />)}
      {tile(neverRotatedDrill(), <Stat l="Never rotated" v={String(v1)} s={`${pct(v1, total)}% still version 1`} c="orange" i={RotateCcw} />)}
    </div>
  );
}

export function VaultCharts({ secrets, now, active, onDrill }: Props) {
  const total = secrets.length;
  const types = Array.from(new Set(secrets.map((s) => String(s.secret_type || "").toLowerCase())))
    .map((t) => ({ t, d: typeDrill(t), n: 0 })).map((r) => ({ ...r, n: count(secrets, r.d) }))
    .sort((a, b) => b.n - a.n || a.t.localeCompare(b.t));
  const expiry = EXPIRY_BUCKETS.map((b) => ({ b, d: expiryDrill(b.id, now), n: secrets.filter((s) => expiryBucket(s, now) === b.id).length }));
  const age = AGE_BUCKETS.map((b) => ({ b, d: ageDrill(b.id, now), n: secrets.filter((s) => ageBucket(s, now) === b.id).length }));
  const max = (rows: { n: number }[]) => Math.max(0, ...rows.map((r) => r.n));
  const tip = (label: string, n: number) => `${label}: ${n} of ${total} (${pct(n, total)}%)`;
  const dim = (key: string) => !!active && active !== key;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(280px,1fr))", gap: 10 }}>
      <ChartCard title="By type" sub={`${total.toLocaleString()} secrets`}>
        <div style={{ maxHeight: 190, overflowY: "auto" }}>
          {types.map(({ t, d, n }) => (
            <BarRow key={t} label={getBadge(t).t} value={n} max={max(types)} bar={solid(SERIES_FILL)} title={tip(getBadge(t).t, n)}
              active={active === d.key} dim={dim(d.key)} onClick={() => onDrill(d)} />
          ))}
        </div>
      </ChartCard>
      <ChartCard title="Expiry" sub="by lease end">
        {expiry.map(({ b, d, n }) => (
          <BarRow key={b.id} label={<><Swatch color={b.color} />{b.label}</>} value={n} max={max(expiry)} bar={solid(b.color)} title={tip(b.label, n)}
            active={active === d.key} dim={dim(d.key)} onClick={() => onDrill(d)} />
        ))}
      </ChartCard>
      <ChartCard title="Last changed" sub="new value or edit">
        {age.map(({ b, d, n }) => (
          <BarRow key={b.id} label={b.label} value={n} max={max(age)} bar={solid(SERIES_FILL)} title={tip(b.label, n)}
            active={active === d.key} dim={dim(d.key)} onClick={() => onDrill(d)} />
        ))}
      </ChartCard>
    </div>
  );
}
