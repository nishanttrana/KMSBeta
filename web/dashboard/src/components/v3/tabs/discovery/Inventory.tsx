import { useEffect, useState, type ReactNode } from "react";
import { ChevronLeft, ChevronRight, Clock3, Search } from "lucide-react";
import { Inp, Sel } from "../../legacyPrimitives";
import { C } from "../../theme";
import { errMsg } from "../../runtimeUtils";
import { listDiscoveryAssets, type CryptoAsset, type DiscoverySource } from "../../../../lib/discovery";
import type { AuthSession } from "../../../../lib/auth";
import { CLASS_ORDER, MONO, REVIEW_LABEL, SOURCE_META, TYPE_LABEL, classMeta, isStale, relTime, reviewOf, sourceMeta, typeLabel } from "./meta";
import { Swatch } from "./Charts";

export type Filters = { q: string; cls: string; source: string; type: string; stale: boolean };
export const NO_FILTERS: Filters = { q: "", cls: "", source: "", type: "", stale: false };

const PAGE = 25;
const TH = { padding: "8px 10px", fontSize: 10.5, fontWeight: 600, color: C.muted, textAlign: "left" as const, borderBottom: `1px solid ${C.border}`, whiteSpace: "nowrap" as const };
const TD = { padding: "9px 10px", fontSize: 11.5, color: C.text, borderBottom: `1px solid ${C.border}`, verticalAlign: "middle" as const };

export const ClassPill = ({ cls }: { cls: string }) => {
  const m = classMeta(cls);
  return <span style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, color: C.text, whiteSpace: "nowrap" }}><Swatch color={m.color} />{m.label}</span>;
};

type Props = {
  session: AuthSession;
  sources: DiscoverySource[];
  filters: Filters;
  setFilters: (f: Filters) => void;
  onOpen: (a: CryptoAsset) => void;
  // Bumped when the inventory changed (a scan, an upload, a review).
  reloadKey: number;
};

// The table pages the service: filters and the total are the server's.
export function Inventory({ session, sources, filters, setFilters, onOpen, reloadKey }: Props) {
  const [page, setPage] = useState(0);
  const [rows, setRows] = useState<CryptoAsset[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState("");
  const [q, setQ] = useState(filters.q);
  const set = (patch: Partial<Filters>) => setFilters({ ...filters, ...patch });

  useEffect(() => setQ(filters.q), [filters.q]);
  useEffect(() => {
    if (q === filters.q) return;
    const t = setTimeout(() => setFilters({ ...filters, q }), 300);
    return () => clearTimeout(t);
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: debounce the typed text only.
  }, [q]);
  useEffect(() => setPage(0), [filters]);
  useEffect(() => {
    let stale = false;
    const query = { q: filters.q.trim(), classification: filters.cls, source: filters.source, asset_type: filters.type, not_seen: filters.stale };
    listDiscoveryAssets(session, query, page * PAGE, PAGE)
      .then((r) => { if (!stale) { setRows(r.items); setTotal(r.total); setError(""); } })
      .catch((e) => { if (!stale) { setRows([]); setTotal(0); setError(errMsg(e)); } });
    return () => { stale = true; };
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: refetch on tenant, filter, page or inventory change.
  }, [session?.tenantId, session?.token, filters, page, reloadKey]);

  const pages = Math.max(1, Math.ceil(total / PAGE));
  const active = filters.cls || filters.source || filters.type || filters.stale || filters.q;

  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: "var(--radius-md)", boxShadow: "var(--shadow-sm)" }}>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center", padding: 12 }}>
        <div style={{ position: "relative", flex: "2 1 220px" }}>
          <Search size={13} color={C.muted} style={{ position: "absolute", left: 10, top: 9 }} />
          <Inp placeholder="Search name, location, algorithm" value={q} onChange={(e) => setQ(e.target.value)} style={{ paddingLeft: 30 }} />
        </div>
        <div style={{ flex: "1 1 150px" }}>
          <Sel value={filters.cls} onChange={(e) => set({ cls: e.target.value })}>
            <option value="">All classes</option>
            {CLASS_ORDER.map((c) => <option key={c} value={c}>{classMeta(c).label}</option>)}
          </Sel>
        </div>
        <div style={{ flex: "1 1 140px" }}>
          <Sel value={filters.source} onChange={(e) => set({ source: e.target.value })}>
            <option value="">All sources</option>
            {Object.keys(SOURCE_META).map((s) => <option key={s} value={s}>{sourceMeta(s).label}</option>)}
          </Sel>
        </div>
        <div style={{ flex: "1 1 140px" }}>
          <Sel value={filters.type} onChange={(e) => set({ type: e.target.value })}>
            <option value="">All types</option>
            {Object.keys(TYPE_LABEL).map((t) => <option key={t} value={t}>{typeLabel(t)}</option>)}
          </Sel>
        </div>
        <button type="button" onClick={() => set({ stale: !filters.stale })} title="Assets the last scan of their source didn't observe"
          style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, fontWeight: 600, borderRadius: 7, padding: "7px 10px", cursor: "pointer", border: `1px solid ${filters.stale ? C.accentFg : C.border}`, background: filters.stale ? C.accentDim : "transparent", color: filters.stale ? C.accentFg : C.muted }}>
          <Clock3 size={12} />Not seen
        </button>
      </div>
      {active && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center", padding: "0 12px 10px" }}>
          <span style={{ fontSize: 10.5, color: C.muted }}>{total.toLocaleString()} matching</span>
          <button type="button" onClick={() => setFilters(NO_FILTERS)} style={{ background: "none", border: "none", color: C.accentFg, fontSize: 10.5, cursor: "pointer", padding: 0 }}>Clear filters</button>
        </div>
      )}
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>{["Asset", "Algorithm", "Strength", "Class", "Source", "Last seen", "Review"].map((h) => <th key={h} style={TH}>{h}</th>)}</tr>
          </thead>
          <tbody>
            {rows.map((a) => {
              const stale = isStale(a, sources);
              const S = sourceMeta(a.source);
              const SI = S.icon;
              const review = reviewOf(a);
              return (
                <tr key={a.id} onClick={() => onOpen(a)} style={{ cursor: "pointer" }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = C.cardHover; }} onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}>
                  <td style={{ ...TD, maxWidth: 300 }}>
                    <div style={{ fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.name || "-"}</div>
                    <div style={{ fontSize: 10.5, color: C.muted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {typeLabel(a.asset_type)}{a.location && !a.name.startsWith(a.location) ? <> · <span style={{ fontFamily: MONO }}>{a.location}</span></> : null}
                    </div>
                  </td>
                  <td style={{ ...TD, fontFamily: MONO, fontSize: 11, whiteSpace: "nowrap" }}>
                    {a.algorithm || "-"}
                    {a.pqc_ready && <span style={{ marginLeft: 6, fontFamily: "inherit", fontSize: 9.5, fontWeight: 700, color: C.greenFg, background: C.greenDim, borderRadius: 4, padding: "1px 5px" }}>PQC</span>}
                  </td>
                  <td style={{ ...TD, whiteSpace: "nowrap", color: a.strength_bits > 0 ? C.text : C.muted }}>{a.strength_bits > 0 ? `${a.strength_bits}-bit` : "not assessed"}</td>
                  <td style={TD}><ClassPill cls={a.classification} /></td>
                  <td style={{ ...TD, whiteSpace: "nowrap", color: C.dim }}><span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}><SI size={12} />{S.label}</span></td>
                  <td style={{ ...TD, whiteSpace: "nowrap" }} title={a.last_seen}>
                    {relTime(a.last_seen)}
                    {stale && <div style={{ fontSize: 10, color: C.amberFg }}>not in last scan</div>}
                  </td>
                  <td style={{ ...TD, whiteSpace: "nowrap", color: review === "active" ? C.muted : C.text }}>{REVIEW_LABEL[review] ?? review}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!rows.length && (
          <div style={{ textAlign: "center", padding: "28px 0", color: error ? C.redFg : C.muted, fontSize: 11.5 }}>
            {error ? `Inventory unavailable: ${error}` : active ? "No assets match these filters." : "No assets yet. Set up a source above, then scan."}
          </div>
        )}
      </div>
      {total > PAGE && (
        <div style={{ display: "flex", justifyContent: "flex-end", alignItems: "center", gap: 8, padding: "8px 12px", fontSize: 10.5, color: C.muted }}>
          {page * PAGE + 1}–{Math.min(total, page * PAGE + PAGE)} of {total.toLocaleString()}
          <PageBtn label="Previous page" disabled={page === 0} onClick={() => setPage(page - 1)}><ChevronLeft size={13} /></PageBtn>
          <PageBtn label="Next page" disabled={page >= pages - 1} onClick={() => setPage(page + 1)}><ChevronRight size={13} /></PageBtn>
        </div>
      )}
    </div>
  );
}

const PageBtn = ({ label, disabled, onClick, children }: { label: string; disabled: boolean; onClick: () => void; children: ReactNode }) => (
  <button type="button" aria-label={label} disabled={disabled} onClick={onClick}
    style={{ display: "inline-flex", border: `1px solid ${C.border}`, borderRadius: 6, background: "transparent", color: disabled ? C.border : C.text, cursor: disabled ? "default" : "pointer", padding: 3 }}>{children}</button>
);
