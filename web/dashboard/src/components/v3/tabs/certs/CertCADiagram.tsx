import { useEffect, useMemo, useRef, useState } from "react";
import { Download, FileBadge, HardDrive, KeyRound, Landmark, Server, Trash2 } from "lucide-react";
import { B } from "../../legacyPrimitives";
import { C } from "../../theme";
import { CertMenu } from "./CertMenu";
import { type CATree, keyPlace } from "./caTree";
import type { CertFilter } from "./certFilters";

type Props = {
  tree: CATree;
  selected: string;
  onSelect: (caID: string) => void;
  onPick: (caID: string, filter: CertFilter) => void;
  onCRL: (ca: any) => void;
  onDelete: (ca: any) => void;
  busy: string;
};

const W = 236, H = 88, GX = 28, GY = 46, LEFT = 92, TOP = 14;
type Placed = { id: string; ca?: any; caID: string; x: number; depth: number; parent?: string };

// Lays the hierarchy out as a tree: leaves take the next slot, a parent sits
// over the middle of its children. A CA's own certificates are one node
// under it.
function layout(tree: CATree): Placed[] {
  const out: Placed[] = [];
  let slot = 0;
  const place = (ca: any, depth: number, parent?: string): Placed => {
    const id = String(ca.id);
    const kids: Placed[] = (tree.children[id] || []).map((k) => place(k, depth + 1, id));
    if (tree.stats[id]?.total) {
      const group: Placed = { id: `certs:${id}`, caID: id, x: slot++, depth: depth + 1, parent: id };
      out.push(group);
      kids.push(group);
    }
    const x = kids.length ? (kids[0]!.x + kids[kids.length - 1]!.x) / 2 : slot++;
    const node: Placed = { id, ca, caID: id, x, depth, ...(parent ? { parent } : {}) };
    out.push(node);
    return node;
  };
  tree.roots.forEach((r) => { place(r, 0); slot += 0.25; });
  return out;
}

// x is relative to the tree; at() centres the tree in the card, clear of the tier labels.
const px = (n: Placed) => ({ x: n.x * (W + GX), top: TOP + n.depth * (H + GY) });

// The CA hierarchy as a diagram (13.63.0-beta): tiers down the page, where
// each CA key lives, and each CA's certificates by state. Pressing a CA or a
// count lists those certificates in the table. A node whose numbers changed
// since the last update is outlined for a moment.
export function CertCADiagram({ tree, selected, onSelect, onPick, onCRL, onDelete, busy }: Props) {
  const nodes = useMemo(() => layout(tree), [tree]);
  const byID = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);
  const [flash, setFlash] = useState<Set<string>>(new Set());
  const prev = useRef<Map<string, string> | null>(null);
  useEffect(() => {
    const sig = new Map(nodes.map((n) => [n.id, JSON.stringify(n.ca ? [n.ca.status, n.ca.name] : tree.stats[n.caID])]));
    const before = prev.current;
    prev.current = sig;
    if (!before) return undefined;
    const changed = new Set([...sig].filter(([id, s]) => before.get(id) !== s).map(([id]) => id));
    if (!changed.size) return undefined;
    setFlash(changed);
    const t = setTimeout(() => setFlash(new Set()), 2500);
    return () => clearTimeout(t);
  }, [nodes, tree]);

  if (!nodes.length) return null;
  const depth = Math.max(...nodes.map((n) => n.depth));
  const treeW = (Math.max(...nodes.map((n) => n.x)) + 1) * (W + GX) - GX;
  const width = LEFT + treeW + GX;
  const at = (x: number) => `calc(max(${LEFT}px, 50% - ${treeW / 2}px) + ${x}px)`;
  const rows = Array.from({ length: depth + 1 }, (_, d) => nodes.some((n) => n.depth === d && n.ca));
  // Room under a bottom-row CA for its menu, which the scroll box would clip.
  const height = TOP + (depth + 1) * (H + GY) - GY + TOP + (rows[depth] ? 60 : 0);
  let tier = 0;

  return (
    <div style={{ overflowX: "auto" }} data-testid="ca-diagram">
      <div style={{ position: "relative", width, height, minWidth: "100%" }}>
        {rows.map((hasCA, d) => (
          <div key={d} style={{ position: "absolute", left: 0, top: TOP + d * (H + GY), height: H, display: "flex", alignItems: "center", fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase", color: C.muted, fontFamily: "var(--font-mono)" }}>
            {hasCA ? `Tier ${++tier}` : "Certificates"}
          </div>
        ))}
        {rows.slice(1).map((_, d) => (
          <div key={`rule-${d}`} style={{ position: "absolute", left: 0, right: 0, top: TOP + (d + 1) * (H + GY) - GY / 2, borderTop: `1px dashed ${C.border}` }} />
        ))}
        {nodes.filter((n) => n.parent).map((n) => {
          const a = px(byID.get(n.parent!)!), b = px(n);
          const x1 = a.x + W / 2, y1 = a.top + H, x2 = b.x + W / 2, y2 = b.top, mid = y1 + GY / 2 - 6;
          const on = Boolean(selected) && n.caID === selected;
          const line = `${on ? 2 : 1}px ${n.ca ? "solid" : "dashed"} ${on ? C.accent : C.borderHi}`;
          const seg = (style: Record<string, number | string>) => <div aria-hidden="true" style={{ position: "absolute", pointerEvents: "none", ...style }} />;
          return (
            <div key={`edge-${n.id}`}>
              {seg({ left: at(x1), top: y1, height: mid - y1, borderLeft: line })}
              {x1 !== x2 ? seg({ left: at(Math.min(x1, x2)), top: mid, width: Math.abs(x2 - x1), borderTop: line }) : null}
              {seg({ left: at(x2), top: mid, height: y2 - mid, borderLeft: line })}
            </div>
          );
        })}
        {nodes.map((n) => {
          const pos = px(n);
          const lit = flash.has(n.id);
          const box = { position: "absolute" as const, left: at(pos.x), top: pos.top, width: W, height: H, boxSizing: "border-box" as const, borderRadius: 6, background: C.card, transition: "box-shadow .3s, border-color .3s",
            boxShadow: lit ? `0 0 0 3px ${C.accentDim}` : "none" };
          if (!n.ca) {
            const s = tree.stats[n.caID]!;
            const seg = [[s.active - s.expiring, "var(--cls-ontime)"], [s.expiring, "var(--cls-late)"], [s.revoked, "var(--cls-missed)"], [s.total - s.active - s.revoked, C.border]] as const;
            const chip = (label: string, f: CertFilter) => (
              <button type="button" onClick={() => onPick(n.caID, f)} style={{ border: 0, background: "none", padding: 0, fontSize: 10.5, color: C.dim, cursor: "pointer" }}>{label}</button>
            );
            return (
              <div key={n.id} data-testid="ca-certs" style={{ ...box, border: `1px dashed ${lit ? C.accent : C.borderHi}`, padding: "9px 11px" }}>
                <button type="button" onClick={() => onPick(n.caID, "")} style={{ display: "flex", alignItems: "center", gap: 7, border: 0, background: "none", padding: 0, cursor: "pointer", color: C.text }}>
                  <FileBadge size={15} color={C.dim} />
                  <span className="vk-num" style={{ fontSize: 13, fontWeight: 700 }}>{s.total}</span>{" "}
                  <span style={{ fontSize: 11.5, color: C.dim }}>{s.total === 1 ? "certificate" : "certificates"}</span>
                </button>
                <div style={{ display: "flex", height: 6, borderRadius: 3, overflow: "hidden", background: C.border, margin: "8px 0 6px" }}>
                  {seg.map(([v, fill], i) => (v > 0 ? <div key={i} style={{ width: `${(v / s.total) * 100}%`, background: fill }} /> : null))}
                </div>
                <div style={{ display: "flex", gap: 9 }} className="vk-num">
                  {chip(`${s.active} active`, "active")}
                  {s.expiring ? chip(`${s.expiring} expiring`, "expiring") : null}
                  {s.revoked ? chip(`${s.revoked} revoked`, "revoked") : null}
                </div>
              </div>
            );
          }
          const ca = n.ca;
          const id = n.caID;
          const on = selected === id;
          const root = n.depth === 0;
          const issues = Boolean(tree.stats[id]?.total);
          const status = String(ca.status || "unknown").toLowerCase();
          const place = keyPlace(ca.key_backend);
          const Icon = root ? Landmark : Server;
          return (
            <div key={n.id} data-testid="ca-node" style={{ ...box, border: `${on ? 2 : 1}px solid ${on || lit ? C.accent : C.borderHi}`, display: "flex" }}>
              <button type="button" aria-pressed={on} onClick={() => onSelect(on ? "" : id)} title={`List ${String(ca.name || id)}'s certificates`}
                style={{ flex: 1, minWidth: 0, display: "flex", gap: 10, alignItems: "flex-start", border: 0, background: "none", padding: "10px 4px 10px 11px", cursor: "pointer", textAlign: "left", color: C.text }}>
                <span style={{ width: 34, height: 34, flexShrink: 0, borderRadius: 6, display: "inline-flex", alignItems: "center", justifyContent: "center", background: root ? C.accentDim : "var(--c-surface)", color: root ? C.accentFg : C.dim }}>
                  <Icon size={17} />
                </span>
                <span style={{ minWidth: 0, flex: 1 }}>
                  <span style={{ display: "block", fontSize: 12.5, fontWeight: 700, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(ca.name || id)}</span>
                  <span style={{ display: "block", fontSize: 10, color: C.muted, letterSpacing: "0.06em", textTransform: "uppercase", fontFamily: "var(--font-mono)", marginTop: 2 }}>
                    {root ? (issues ? "Root · issuing CA" : "Root CA") : issues ? "Issuing CA" : "Intermediate CA"}
                  </span>
                  <span style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 7 }}>
                    <span style={{ fontSize: 10, color: C.accentFg, fontFamily: "var(--font-mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(ca.algorithm || "-")}</span>
                    <span title={`Private key: ${place}`} style={{ display: "inline-flex", alignItems: "center", gap: 3, fontSize: 10, padding: "1px 5px", borderRadius: 3, flexShrink: 0,
                      background: place === "HSM" ? C.accentDim : "var(--c-surface)", color: place === "HSM" ? C.accentFg : C.dim }}>
                      {place === "HSM" ? <HardDrive size={10} /> : <KeyRound size={10} />}{place}
                    </span>
                  </span>
                </span>
              </button>
              <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", justifyContent: "space-between", padding: "8px 8px 8px 0" }}>
                <CertMenu ariaLabel={`Actions for ${String(ca.name || id)}`} items={[
                  { label: busy === `crl-${id}` ? "Downloading…" : "Download CRL", icon: Download, run: () => onCRL(ca), disabled: busy === `crl-${id}` },
                  { label: busy === `delete-ca-${id}` ? "Deleting…" : "Delete CA", icon: Trash2, run: () => onDelete(ca), danger: true, disabled: busy === `delete-ca-${id}` },
                ]} />
                {status !== "active" ? <B c={status === "revoked" ? "red" : "amber"}>{status}</B> : null}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
