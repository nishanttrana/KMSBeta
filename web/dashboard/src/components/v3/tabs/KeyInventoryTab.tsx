// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useCallback, useEffect, useState } from "react";
import { Database, RefreshCcw, Download, GitBranch } from "lucide-react";
import { C } from "../../v3/theme";

const base = "/svc/keycore";
const hdr = (tok: string, tid: string) => ({ "Authorization": `Bearer ${tok}`, "X-Tenant-ID": tid });

const TH = ({ c }: any) => <th style={{ padding: "7px 10px", textAlign: "left", fontSize: 10, fontWeight: 600, color: C.muted, textTransform: "uppercase", letterSpacing: 0.6, borderBottom: `1px solid ${C.border}` }}>{c}</th>;
const TD = ({ c, mono }: any) => <td style={{ padding: "8px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid rgba(26,41,68,.5)`, ...(mono ? { fontFamily: "'JetBrains Mono', monospace" } : {}) }}>{c ?? "—"}</td>;
const Badge = ({ color, children }: any) => <span style={{ display: "inline-flex", padding: "2px 7px", borderRadius: 4, background: color + "18", color, fontSize: 10, fontWeight: 600 }}>{children}</span>;
const Btn = ({ onClick, children, small, variant = "default" }: any) => {
  const s: any = { default: { background: C.accent, color: C.bg }, ghost: { background: "rgba(255,255,255,.06)", color: C.dim, border: `1px solid ${C.border}` } };
  return <button onClick={onClick} style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: small ? "4px 10px" : "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", border: "none", ...s[variant] }}>{children}</button>;
};
const Card = ({ children, style }: any) => <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, ...style }}>{children}</div>;

export function KeyInventoryTab({ session }: any) {
  const [inventory, setInventory] = useState<any[]>([]);
  const [deps, setDeps] = useState<any[]>([]);
  const [view, setView] = useState<"inventory" | "deps">("inventory");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    if (!session?.token) return;
    const tid = session?.tenantId ?? "";
    setLoading(true); setErr("");
    try {
      const [iRes, dRes] = await Promise.all([
        fetch(`${base}/inventory/keys`, { headers: hdr(session.token, tid) }),
        fetch(`${base}/inventory/dependencies`, { headers: hdr(session.token, tid) }),
      ]);
      const i = await iRes.json().catch(() => ({}));
      const d = await dRes.json().catch(() => ({}));
      setInventory(Array.isArray(i.keys) ? i.keys : Array.isArray(i) ? i : []);
      setDeps(Array.isArray(d.dependencies) ? d.dependencies : Array.isArray(d) ? d : []);
    } catch (e: any) { setErr(e.message); }
    finally { setLoading(false); }
  }, [session?.token, session?.tenantId]);

  useEffect(() => { load(); }, [load]);

  const handleExport = async () => {
    const tid = session?.tenantId ?? "";
    const r = await fetch(`${base}/inventory/export`, { headers: hdr(session.token, tid) });
    const d = await r.json();
    const blob = new Blob([JSON.stringify(d, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = "key-inventory.json"; a.click();
    URL.revokeObjectURL(url);
  };

  const fmtDate = (iso?: string) => iso ? new Date(iso).toLocaleDateString() : "—";
  const statusColor = (s: string) => s === "active" ? C.green : s === "disabled" ? C.amber : C.red;

  return (
    <div style={{ padding: 24, maxWidth: 1200 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Database size={20} style={{ color: C.accent }} />
          <span style={{ fontSize: 16, fontWeight: 700, color: C.text }}>Key Inventory & Dependency Mapping</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn onClick={handleExport} variant="ghost" small><Download size={12} /> Export</Btn>
          <Btn onClick={load} small><RefreshCcw size={12} />{loading ? "Loading…" : "Refresh"}</Btn>
        </div>
      </div>

      {err && <div style={{ padding: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 12, marginBottom: 16 }}>{err}</div>}

      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {(["inventory", "deps"] as const).map(v => (
          <button key={v} onClick={() => setView(v)} style={{ padding: "6px 14px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer", border: `1px solid ${C.border}`, background: view === v ? C.accent : "transparent", color: view === v ? C.bg : C.dim }}>
            {v === "inventory" ? `Key Inventory (${inventory.length})` : `Dependencies (${deps.length})`}
          </button>
        ))}
      </div>

      {view === "inventory" ? (
        <Card>
          {inventory.length === 0 ? (
            <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No inventory data.</div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr><TH c="Key ID" /><TH c="Label" /><TH c="Algorithm" /><TH c="Status" /><TH c="Created" /><TH c="Expires" /><TH c="Operations" /></tr></thead>
                <tbody>
                  {inventory.map((k: any, i: number) => (
                    <tr key={i}>
                      <TD c={k.id} mono /><TD c={k.label} /><TD c={k.algorithm} /><TD c={<Badge color={statusColor(k.status)}>{k.status}</Badge>} />
                      <TD c={fmtDate(k.created_at)} /><TD c={fmtDate(k.expires_at)} /><TD c={k.operation_count?.toLocaleString()} />
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      ) : (
        <Card>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
            <GitBranch size={14} style={{ color: C.accent }} />
            <span style={{ fontSize: 13, fontWeight: 600, color: C.text }}>Key Dependencies</span>
          </div>
          {deps.length === 0 ? (
            <div style={{ color: C.muted, fontSize: 12, padding: 16, textAlign: "center" }}>No dependencies mapped.</div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead><tr><TH c="Key ID" /><TH c="Depends On" /><TH c="Type" /><TH c="Service" /></tr></thead>
                <tbody>
                  {deps.map((d: any, i: number) => (
                    <tr key={i}>
                      <TD c={d.key_id} mono /><TD c={d.depends_on_key_id} mono /><TD c={d.dependency_type} /><TD c={d.service_name} />
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
