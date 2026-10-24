import { useEffect, useMemo, useState } from "react";
import { CheckCircle2, Download, Eye, Lock, RotateCcw, ShieldAlert, ShieldX, Trash2, X, XCircle } from "lucide-react";
import { Bar, Btn, Card, Inp, Sel } from "../../legacyPrimitives";
import { C } from "../../theme";
import { HSMPartitionTable } from "../../../../modules/hsm/HSMPartitionTable";
import { CertMenu, type CertMenuItem } from "./CertMenu";
import { type CertFilter, type ExpiryPolicy, expiryDaysLeft, matchesCertFilter } from "./certFilters";

export type CertActions = {
  download: (c: any) => void;
  renew: (c: any) => void;
  revoke: (c: any) => void;
  ocsp: (c: any) => void;
  remove: (c: any) => void;
};

type Props = {
  session: any;
  onToast: (msg: string) => void;
  certs: any[];
  cas: any[];
  filter: CertFilter;
  onClearFilter: () => void;
  caFilter: string;
  onClearCA: () => void;
  search: string;
  onSearch: (q: string) => void;
  policy: ExpiryPolicy;
  busy: string;
  actions: CertActions;
  hsmConfigured: boolean;
};

const COLS = "minmax(0,1.5fr) minmax(0,.9fr) minmax(0,1fr) .7fr minmax(0,1fr) 34px";
const lower = (v: unknown) => String(v ?? "").toLowerCase();
const ts = (v: unknown) => { const t = Date.parse(String(v ?? "")); return Number.isNaN(t) ? 0 : t; };
const day = (v: unknown) => { const t = new Date(String(v || "")); return Number.isNaN(t.getTime()) ? "-" : t.toLocaleDateString(); };

function rowMenu(c: any, busy: string, a: CertActions): CertMenuItem[] {
  const id = String(c.id || "");
  const status = lower(c.status);
  const live = status === "active" || status === "expired";
  const managed = lower(c.cert_class) === "internal-mtls" || lower(c.protocol).includes("internal-mtls");
  const items: CertMenuItem[] = [];
  items.push(status !== "deleted" ? { label: "Download", icon: Download, run: () => a.download(c) } : { label: "Download unavailable (deleted)", icon: XCircle });
  if (live) items.push({ label: busy === `renew-${id}` ? "Renewing…" : "Renew", icon: RotateCcw, run: () => a.renew(c), disabled: busy === `renew-${id}` });
  if (live) items.push({ label: busy === `revoke-${id}` ? "Revoking…" : "Revoke", icon: ShieldX, run: () => a.revoke(c), disabled: busy === `revoke-${id}` });
  items.push({ label: busy === `ocsp-${id}` ? "Checking…" : "OCSP status", icon: Eye, run: () => a.ocsp(c), disabled: busy === `ocsp-${id}` });
  if (status === "deleted") items.push({ label: "Already deleted", icon: Trash2 });
  else if (managed) items.push({ label: "Managed mTLS (renew/rotate only)", icon: Lock });
  else items.push({ label: busy === `delete-${id}` ? "Deleting…" : "Delete permanently", icon: Trash2, run: () => a.remove(c), danger: true, disabled: busy === `delete-${id}` });
  return items;
}

const Chip = ({ label, onClear }: { label: string; onClear: () => void }) => (
  <button type="button" onClick={onClear} aria-label={`Clear ${label}`}
    style={{ display: "inline-flex", alignItems: "center", gap: 5, height: 26, padding: "0 8px", borderRadius: 3, border: `1px solid ${C.accentFg}`, background: C.accentDim, color: C.text, fontSize: 11, cursor: "pointer" }}>
    {label}<X size={11} />
  </button>
);

export function CertTable({ session, onToast, certs, cas, filter, onClearFilter, caFilter, onClearCA, search, onSearch, policy, busy, actions, hsmConfigured }: Props) {
  const [source, setSource] = useState<"kms" | "hsm">("kms");
  const [page, setPage] = useState(0);
  const [size, setSize] = useState(25);
  // The time the list was fetched, so a row's filter agrees with the count.
  const now = useMemo(() => Date.now(), [certs]); // eslint-disable-line react-hooks/exhaustive-deps -- reviewed: recomputed only when a new list arrives
  const caName = useMemo(() => new Map(cas.map((ca) => [String(ca.id), String(ca.name || ca.id)])), [cas]);

  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    const out = certs.filter((c) => {
      if (caFilter && String(c.ca_id || "") !== caFilter) return false;
      if (!matchesCertFilter(c, filter, policy, now)) return false;
      return !q || [c.subject_cn, c.id, c.algorithm, c.cert_class, c.status].some((v) => lower(v).includes(q));
    });
    return filter === "expiring"
      ? out.sort((a, b) => ts(a.not_after) - ts(b.not_after))
      : out.sort((a, b) => ts(b.created_at) - ts(a.created_at));
  }, [certs, caFilter, filter, policy, now, search]);

  useEffect(() => setPage(0), [filter, caFilter, search, size]);
  const pages = Math.max(1, Math.ceil(rows.length / size));
  const current = Math.min(page, pages - 1);
  const shown = rows.slice(current * size, (current + 1) * size);
  const filterLabel = filter === "expiring" ? `Expiring ≤${policy.alertDays}d` : filter === "active" ? "Active" : filter === "revoked" ? "Revoked" : "";

  return (
    <div style={{ minWidth: 0 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
        {source === "kms" ? <Inp aria-label="Search certificates" placeholder="Search name, ID, algorithm…" w={260} value={search} onChange={(e: any) => onSearch(String(e.target.value || ""))} /> : null}
        {source === "kms" && filterLabel ? <Chip label={filterLabel} onClear={onClearFilter} /> : null}
        {source === "kms" && caFilter ? <Chip label={`CA: ${caName.get(caFilter) || caFilter}`} onClear={onClearCA} /> : null}
        <span style={{ flex: 1 }} />
        {hsmConfigured ? (
          <Sel w={170} aria-label="Certificate source" value={source} onChange={(e: any) => setSource(e.target.value === "hsm" ? "hsm" : "kms")}>
            <option value="kms">Issued by the KMS</option>
            <option value="hsm">In the HSM partition</option>
          </Sel>
        ) : null}
      </div>
      {source === "hsm" ? <HSMPartitionTable session={session} kind="certificates" onToast={onToast} /> : <>
        <Card style={{ padding: 0 }}>
          <div style={{ display: "grid", gridTemplateColumns: COLS, gap: 8, padding: "8px 12px", borderBottom: `1px solid ${C.border}`, fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>
            <div>Common name</div><div>Algorithm</div><div>CA</div><div>Status</div><div>Expires</div><div />
          </div>
          {shown.map((c) => {
            const status = lower(c.status);
            const days = expiryDaysLeft(c, policy, now);
            const start = ts(c.not_before), end = ts(c.not_after);
            const pct = days === null || !(end > start) ? 0 : Math.max(3, Math.min(100, ((end - now) / (end - start)) * 100));
            const tone = days === null ? C.dim : days <= 7 ? C.red : days <= policy.alertDays ? C.amber : C.accent;
            const icon = status === "active" ? <CheckCircle2 size={11} color={C.green} /> : status === "revoked" ? <XCircle size={11} color={C.red} /> : <ShieldAlert size={11} color={C.amber} />;
            return (
              <div key={c.id} data-testid="cert-row" style={{ display: "grid", gridTemplateColumns: COLS, gap: 8, padding: "8px 12px", borderBottom: `1px solid ${C.border}`, fontSize: 11, alignItems: "center" }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ color: C.text, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.subject_cn || c.id}</div>
                  <div title={String(c.id)} style={{ fontSize: 10, color: C.muted, fontFamily: "var(--font-mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{`${String(c.cert_class || "").toUpperCase()} · ${c.id}`}</div>
                </div>
                <div style={{ color: C.accentFg, fontFamily: "var(--font-mono)", fontSize: 10.5, overflow: "hidden", textOverflow: "ellipsis" }}>{c.algorithm}</div>
                <div style={{ color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{caName.get(String(c.ca_id)) || String(c.ca_id || "-")}</div>
                <div style={{ display: "flex", alignItems: "center", gap: 4, color: C.dim }}>{icon}{status}</div>
                <div title={String(c.not_after || "")}>
                  <div style={{ display: "flex", justifyContent: "space-between", color: C.dim, marginBottom: 3 }}><span>{day(c.not_after)}</span>{days !== null ? <span className="vk-num" style={{ color: days <= policy.alertDays ? tone : C.muted }}>{`${days}d`}</span> : status === "active" && end && now > end ? <span style={{ color: C.redFg }}>expired</span> : null}</div>
                  {days !== null ? <Bar pct={pct} color={tone} /> : null}
                </div>
                <div style={{ display: "flex", justifyContent: "flex-end" }}><CertMenu ariaLabel="Certificate actions" items={rowMenu(c, busy, actions)} /></div>
              </div>
            );
          })}
          {!shown.length ? <div style={{ fontSize: 11, color: C.muted, padding: 14 }}>{certs.length ? "No certificate matches." : "No certificates yet."}</div> : null}
        </Card>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, marginTop: 8, fontSize: 10, color: C.dim }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Sel w={80} aria-label="Rows per page" value={String(size)} onChange={(e: any) => setSize(Number(e.target.value) || 25)}>
              {[10, 25, 50, 100].map((n) => <option key={n} value={String(n)}>{n}</option>)}
            </Sel>
            <span className="vk-num">{rows.length ? `${current * size + 1}-${Math.min((current + 1) * size, rows.length)} of ${rows.length}` : "0 of 0"}</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Btn small onClick={() => setPage(current - 1)} disabled={current <= 0}>Prev</Btn>
            <span className="vk-num">{`${current + 1} / ${pages}`}</span>
            <Btn small onClick={() => setPage(current + 1)} disabled={current >= pages - 1}>Next</Btn>
          </div>
        </div>
      </>}
    </div>
  );
}
