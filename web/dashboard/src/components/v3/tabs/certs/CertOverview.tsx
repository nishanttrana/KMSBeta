import { useState } from "react";
import { AlertTriangle, Clock, FileText, Fingerprint, Globe, RefreshCcw, ShieldCheck, ShieldX } from "lucide-react";
import { Btn, Stat } from "../../legacyPrimitives";
import { CertCATree } from "./CertCATree";
import { CertMenu } from "./CertMenu";
import { type CertActions, CertTable } from "./CertTable";
import { FilterTile } from "./FilterTile";
import type { CertFilter, ExpiryPolicy } from "./certFilters";

type Props = {
  session: any;
  onToast: (msg: string) => void;
  cas: any[];
  certs: any[];
  summary: any;
  renewal: any;
  policy: ExpiryPolicy;
  loading: boolean;
  onRefresh: () => void;
  openModal: (name: string) => void;
  busy: string;
  actions: CertActions;
  onCRL: (ca: any) => void;
  onDeleteCA: (ca: any) => void;
  search: string;
  onSearch: (q: string) => void;
  hsmConfigured: boolean;
  onOpenRenewals: () => void;
};

// Certificates → Certificate Operations (13.61.0-beta): one toolbar, four
// counts that filter the table, and the CA hierarchy beside the table as a
// filter. Renewal planning is Certificates → Renewals; ACME STAR is under
// Enrollment Protocols.
export function CertOverview(p: Props) {
  const [filter, setFilter] = useState<CertFilter>("");
  const [caFilter, setCAFilter] = useState("");
  const toggle = (f: CertFilter) => setFilter((cur) => (cur === f ? "" : f));
  const s = p.summary;
  const count = (k: string) => (s ? String(Number(s[k] || 0)) : "unavailable");
  const missed = p.renewal ? Number(p.renewal.missed_window_count || 0) : null;
  return (
    <div data-testid="cert-overview">
      <div style={{ display: "flex", justifyContent: "flex-end", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <Btn small onClick={p.onRefresh} disabled={p.loading}><span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}><RefreshCcw size={12} />{p.loading ? "Refreshing…" : "Refresh"}</span></Btn>
        <CertMenu label="Policies" items={[
          { label: "Alert policy", icon: AlertTriangle, run: () => p.openModal("cert-alert-policy"), title: "When certificates count as expiring" },
          { label: "Lifetime policy", icon: Clock, run: () => p.openModal("cert-clm-policy"), title: "The longest validity this tenant allows" },
        ]} />
        <CertMenu label="More" ariaLabel="More ways to add a certificate" items={[
          { label: "Sign CSR", icon: Fingerprint, run: () => p.openModal("sign-csr") },
          { label: "Upload 3rd-party", icon: Globe, run: () => p.openModal("upload-3p") },
        ]}>
          <Btn small primary onClick={() => p.openModal("issue")}><span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}><FileText size={12} />Issue certificate</span></Btn>
        </CertMenu>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 10, marginBottom: 12 }}>
        <FilterTile on={filter === "active"} onPress={() => toggle("active")} l="Active" v={count("active")} i={ShieldCheck}
          s={s?.total ? `${Math.round((Number(s.active || 0) * 100) / Number(s.total))}% of ${s.total}` : undefined} />
        <FilterTile on={filter === "expiring"} onPress={() => toggle("expiring")} l="Expiring" v={count("expiring")} i={Clock}
          s={`within ${p.policy.alertDays}d`} c={Number(s?.expiring || 0) > 0 ? "amber" : "accent"} />
        <FilterTile on={filter === "revoked"} onPress={() => toggle("revoked")} l="Revoked" v={count("revoked")} i={ShieldX} />
        <button type="button" onClick={p.onOpenRenewals} title="Open Renewals"
          style={{ display: "flex", padding: 0, border: 0, background: "none", font: "inherit", color: "inherit", textAlign: "left", cursor: "pointer" }}>
          <Stat l="Missed windows" v={missed === null ? "unavailable" : String(missed)} s="renewals" c={missed ? "red" : "accent"} i={AlertTriangle} />
        </button>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "minmax(220px,280px) minmax(0,1fr)", gap: 12, alignItems: "start" }}>
        <CertCATree cas={p.cas} certs={p.certs} selected={caFilter} onSelect={setCAFilter} onCreate={() => p.openModal("create-ca")}
          onCRL={p.onCRL} onDelete={p.onDeleteCA} busy={p.busy} loading={p.loading} />
        <CertTable session={p.session} onToast={p.onToast} certs={p.certs} cas={p.cas} filter={filter} onClearFilter={() => setFilter("")}
          caFilter={caFilter} onClearCA={() => setCAFilter("")} search={p.search} onSearch={p.onSearch} policy={p.policy}
          busy={p.busy} actions={p.actions} hsmConfigured={p.hsmConfigured} />
      </div>
    </div>
  );
}
