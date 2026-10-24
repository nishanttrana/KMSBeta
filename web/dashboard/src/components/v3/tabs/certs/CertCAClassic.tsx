import { useState } from "react";
import { CheckCircle2, ChevronDown, ChevronRight, Download, FileText, Shield, ShieldAlert, Trash2, XCircle } from "lucide-react";
import { B, Btn, Card } from "../../legacyPrimitives";
import { C } from "../../theme";
import type { CATree } from "./caTree";

type Props = {
  tree: CATree;
  selected: string;
  onSelect: (caID: string) => void;
  onCRL: (ca: any) => void;
  onDelete: (ca: any) => void;
  busy: string;
};

const when = (v: unknown) => { const t = new Date(String(v || "")); return Number.isNaN(t.getTime()) ? "-" : t.toLocaleString(); };
const ts = (v: unknown) => { const t = Date.parse(String(v ?? "")); return Number.isNaN(t) ? 0 : t; };
const keyLabel = (b: unknown) => (b === "hsm" ? "Key in HSM" : b === "keycore" ? "Software key, keycore co-signed" : "Software vault");
const tone = (s: string) => (s === "active" ? "green" : s === "revoked" || s === "deleted" ? "red" : "amber");

// The CA hierarchy as nested cards, each with its issued certificates (the
// view before 13.61.0-beta), kept as the Classic choice beside the diagram.
export function CertCAClassic({ tree, selected, onSelect, onCRL, onDelete, busy }: Props) {
  const [closed, setClosed] = useState<Record<string, boolean>>({});
  const [issuedClosed, setIssuedClosed] = useState<Record<string, boolean>>({});

  const certRow = (crt: any) => {
    const status = String(crt.status || "unknown").toLowerCase();
    const icon = status === "active" ? <CheckCircle2 size={10} color={C.green} /> : status === "revoked" ? <XCircle size={10} color={C.red} /> : <ShieldAlert size={10} color={C.amber} />;
    return (
      <div key={crt.id} data-testid="ca-issued-row" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, padding: "7px 10px", border: `1px solid ${C.border}`, borderRadius: 4, background: C.bg }}>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontSize: 11, color: C.text, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(crt.subject_cn || crt.id)}</div>
          <div style={{ display: "flex", gap: 8, marginTop: 3, alignItems: "center", flexWrap: "wrap" }}>
            <span style={{ display: "inline-flex", alignItems: "center", gap: 3 }}>{icon}<B c={tone(status)}>{status}</B></span>
            <span style={{ fontSize: 10, color: C.accentFg, fontFamily: "var(--font-mono)", background: C.accentDim, padding: "1px 5px", borderRadius: 3 }}>{String(crt.algorithm || "-")}</span>
            <span style={{ fontSize: 10, color: C.dim }}>{when(crt.not_after)}</span>
          </div>
        </div>
        <div title={String(crt.id)} style={{ fontSize: 10, color: C.muted, fontFamily: "var(--font-mono)", maxWidth: 90, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(crt.id)}</div>
      </div>
    );
  };

  const node = (ca: any, depth: number) => {
    const id = String(ca.id || "");
    const kids = tree.children[id] || [];
    const certs = [...(tree.issued[id] || [])].sort((a, b) => ts(b.created_at) - ts(a.created_at));
    const open = !closed[id];
    const issuedOpen = !issuedClosed[id];
    const status = String(ca.status || "unknown").toLowerCase();
    const on = selected === id;
    return (
      <Card key={id} style={{ padding: 10, marginLeft: depth * 20, borderColor: on ? C.accent : depth === 0 ? C.accentDim : C.border }}>
        <div data-testid="ca-classic" style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "flex-start" }}>
          <div style={{ minWidth: 0, flex: 1 }}>
            <button type="button" onClick={() => setClosed((p) => ({ ...p, [id]: open }))}
              style={{ background: "transparent", border: "none", padding: 0, color: depth === 0 ? C.accentFg : C.text, cursor: "pointer", fontSize: 12, fontWeight: 700, display: "flex", alignItems: "center", gap: 6 }}>
              {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              <Shield size={14} color={depth === 0 ? C.accent : C.dim} />
              <span>{`${depth === 0 ? "Root CA" : "Intermediate CA"}: ${String(ca.name || id)}`}</span>
            </button>
            <div style={{ display: "flex", gap: 10, marginTop: 5, marginLeft: 34, flexWrap: "wrap", alignItems: "center" }}>
              <span style={{ fontSize: 10, color: C.accentFg, fontFamily: "var(--font-mono)", background: C.accentDim, padding: "2px 6px", borderRadius: 4 }}>{String(ca.algorithm || "-")}</span>
              <span style={{ fontSize: 10, color: ca.key_backend === "hsm" ? C.accentFg : C.dim }}>{keyLabel(ca.key_backend)}</span>
              <span style={{ fontSize: 10, color: C.muted }}>{`Created: ${when(ca.created_at)}`}</span>
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap", justifyContent: "flex-end", flexShrink: 0 }}>
            <B c={tone(status)}>{status}</B>
            <Btn small onClick={() => onSelect(on ? "" : id)} aria-pressed={on} title="List these certificates in the table">{`${certs.length} cert${certs.length !== 1 ? "s" : ""}`}</Btn>
            <Btn small onClick={() => onCRL(ca)} disabled={busy === `crl-${id}`}><span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}><Download size={10} />{busy === `crl-${id}` ? "..." : "CRL"}</span></Btn>
            <Btn small danger onClick={() => onDelete(ca)} disabled={busy === `delete-ca-${id}`}><span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}><Trash2 size={10} />{busy === `delete-ca-${id}` ? "..." : "Delete"}</span></Btn>
          </div>
        </div>
        {open ? <>
          {kids.length ? <div style={{ display: "grid", gap: 8, marginTop: 10 }}>{kids.map((k) => node(k, depth + 1))}</div> : null}
          <div style={{ marginTop: 10, paddingTop: 8, borderTop: `1px solid ${C.border}` }}>
            <button type="button" onClick={() => setIssuedClosed((p) => ({ ...p, [id]: issuedOpen }))}
              style={{ background: "transparent", border: "none", padding: 0, color: C.blueFg, cursor: "pointer", fontSize: 10, fontWeight: 700, display: "flex", alignItems: "center", gap: 6 }}>
              {issuedOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}<FileText size={12} />{`Issued Certificates (${certs.length})`}
            </button>
            {issuedOpen ? (
              <div style={{ display: "grid", gap: 6, marginTop: 6, maxHeight: 200, overflowY: "auto", paddingRight: 4 }}>
                {certs.length ? certs.map(certRow) : <div style={{ fontSize: 10, color: C.muted, padding: "6px 0" }}>No issued certificates under this CA.</div>}
              </div>
            ) : null}
          </div>
        </> : null}
      </Card>
    );
  };

  return <div style={{ display: "grid", gap: 8, maxHeight: 480, overflowY: "auto", paddingRight: 4 }}>{tree.roots.map((r) => node(r, 0))}</div>;
}
