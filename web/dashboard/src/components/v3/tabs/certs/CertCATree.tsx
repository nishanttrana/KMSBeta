import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Download, Plus, Shield, Trash2 } from "lucide-react";
import { B, Btn, Card } from "../../legacyPrimitives";
import { C } from "../../theme";
import { CertMenu } from "./CertMenu";

type Props = {
  cas: any[];
  certs: any[];
  selected: string;
  onSelect: (caID: string) => void;
  onCreate: () => void;
  onCRL: (ca: any) => void;
  onDelete: (ca: any) => void;
  busy: string;
  loading: boolean;
};

const keyPlace = (backend: unknown) => backend === "hsm" ? "HSM" : backend === "keycore" ? "keycore" : "software";

// The CA hierarchy as a filter: pressing a CA lists its certificates in the
// table beside it. Certificates are not repeated under each CA.
export function CertCATree({ cas, certs, selected, onSelect, onCreate, onCRL, onDelete, busy, loading }: Props) {
  const [closed, setClosed] = useState<Record<string, boolean>>({});
  const { roots, children, issued } = useMemo(() => {
    const ids = new Set(cas.map((c) => String(c.id)));
    const kids: Record<string, any[]> = {};
    const top: any[] = [];
    for (const ca of cas) {
      const parent = String(ca.parent_ca_id || "").trim();
      if (parent && ids.has(parent)) (kids[parent] ||= []).push(ca);
      else top.push(ca);
    }
    const count: Record<string, number> = {};
    for (const c of certs) count[String(c.ca_id || "")] = (count[String(c.ca_id || "")] || 0) + 1;
    return { roots: top, children: kids, issued: count };
  }, [cas, certs]);

  const node = (ca: any, depth: number) => {
    const id = String(ca.id || "");
    const kids = children[id] || [];
    const open = !closed[id];
    const on = selected === id;
    const status = String(ca.status || "unknown").toLowerCase();
    return (
      <div key={id}>
        <div data-testid="ca-node" style={{ display: "flex", alignItems: "center", gap: 4, padding: "5px 6px", paddingLeft: 6 + depth * 14, borderRadius: 3, background: on ? C.accentDim : "transparent" }}>
          <button type="button" aria-label={open ? "Collapse" : "Expand"} onClick={() => setClosed((p) => ({ ...p, [id]: open }))}
            style={{ visibility: kids.length ? "visible" : "hidden", background: "none", border: 0, padding: 0, color: C.muted, cursor: "pointer", display: "inline-flex" }}>
            {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          </button>
          <button type="button" aria-pressed={on} onClick={() => onSelect(on ? "" : id)} title={`${depth === 0 ? "Root" : "Intermediate"} CA · ${String(ca.algorithm || "-")} · key in ${keyPlace(ca.key_backend)}`}
            style={{ flex: 1, minWidth: 0, display: "flex", alignItems: "center", gap: 6, background: "none", border: 0, padding: 0, cursor: "pointer", textAlign: "left", color: C.text }}>
            <Shield size={13} color={depth === 0 ? C.accent : C.dim} style={{ flexShrink: 0 }} />
            <span style={{ minWidth: 0 }}>
              <span style={{ display: "block", fontSize: 12, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(ca.name || id)}</span>
              <span style={{ display: "block", fontSize: 10, color: C.muted, fontFamily: "var(--font-mono)" }}>{`${String(ca.algorithm || "-")} · ${keyPlace(ca.key_backend)}`}</span>
            </span>
          </button>
          {status !== "active" ? <B c={status === "revoked" ? "red" : "amber"}>{status}</B> : null}
          <span className="vk-num" title="Certificates issued by this CA" style={{ fontSize: 11, color: C.dim, fontFamily: "var(--font-mono)", minWidth: 22, textAlign: "right" }}>{issued[id] || 0}</span>
          <CertMenu ariaLabel={`Actions for ${String(ca.name || id)}`} items={[
            { label: busy === `crl-${id}` ? "Downloading…" : "Download CRL", icon: Download, run: () => onCRL(ca), disabled: busy === `crl-${id}` },
            { label: busy === `delete-ca-${id}` ? "Deleting…" : "Delete CA", icon: Trash2, run: () => onDelete(ca), danger: true, disabled: busy === `delete-ca-${id}` },
          ]} />
        </div>
        {open ? kids.map((k) => node(k, depth + 1)) : null}
      </div>
    );
  };

  return (
    <Card style={{ padding: 10, alignSelf: "start" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
        <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>CAs <span className="vk-num" style={{ color: C.muted, fontWeight: 500 }}>{cas.length}</span></span>
        <Btn small onClick={onCreate}><span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}><Plus size={11} />Create CA</span></Btn>
      </div>
      {cas.length ? roots.map((ca) => node(ca, 0)) : loading ? null : <div style={{ fontSize: 11, color: C.muted, padding: "8px 4px" }}>No CA yet. Create a root CA to start issuing.</div>}
    </Card>
  );
}
