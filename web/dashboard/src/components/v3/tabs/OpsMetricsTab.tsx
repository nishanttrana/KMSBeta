// @ts-nocheck
import { useCallback, useEffect, useState } from "react";
import { Activity, BarChart2, Clock, RefreshCw, Zap } from "lucide-react";
import { C } from "../../v3/theme";
import { getOverview, getLatencyPercentiles, getServiceStats, getErrorBreakdown } from "../../../lib/opsMetrics";

const OP_COLORS: Record<string, string> = {
  encrypt: C.accent,
  decrypt: C.purple,
  sign: C.green,
  verify: C.blue,
  wrap: C.amber,
  unwrap: C.orange,
  generate: C.pink,
};

const OP_ICONS: Record<string, string> = {
  encrypt: "ENC", decrypt: "DEC", sign: "SGN",
  verify: "VRF", wrap: "WRP", unwrap: "UWP", generate: "GEN",
};

function fmt(n: number): string {
  if (!n) return "0";
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
  return String(n);
}

function pct(n: number): string { return ((n ?? 0) * 100).toFixed(3) + "%"; }
function ms(n: number): string { return (n ?? 0).toFixed(1) + "ms"; }

const CELL: React.CSSProperties = { padding: "8px 12px", color: C.dim, fontSize: 12, verticalAlign: "middle" };
const TH: React.CSSProperties = { padding: "7px 12px", fontSize: 10, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: "0.08em", textAlign: "left" };

export function OpsMetricsTab({ session }: { session: any }) {
  const [timeWindow, setTimeWindow] = useState<"1h" | "24h" | "7d" | "30d">("24h");
  const [section, setSection] = useState<"ops" | "latency" | "services" | "errors">("ops");
  const [overview, setOverview] = useState<any>(null);
  const [latency, setLatency] = useState<any[]>([]);
  const [services, setServices] = useState<any[]>([]);
  const [errors, setErrors] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [ov, lat, svc, err] = await Promise.all([
        getOverview(session),
        getLatencyPercentiles(session),
        getServiceStats(session),
        getErrorBreakdown(session),
      ]);
      setOverview(ov);
      setLatency(lat ?? []);
      setServices(svc ?? []);
      setErrors(err ?? []);
    } catch { /* leave state as-is */ }
    setLoading(false);
  }, [session, timeWindow]);

  useEffect(() => { load(); }, [load]);

  const ov = overview ?? {};
  const totalOps = latency.reduce((s, r) => s + (r.sample_ops ?? r.sample_count ?? 0), 0);

  const statCard = (icon: React.ReactNode, label: string, value: string, sub?: string, color?: string) => (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: "14px 16px", flex: 1, display: "flex", gap: 10, alignItems: "flex-start" }}>
      <div style={{ color: color || C.accent, marginTop: 2 }}>{icon}</div>
      <div>
        <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>{label}</div>
        <div style={{ fontSize: 20, fontWeight: 700, color: color || C.text }}>{value}</div>
        {sub && <div style={{ fontSize: 11, color: C.muted, marginTop: 2 }}>{sub}</div>}
      </div>
    </div>
  );

  return (
    <div style={{ padding: 24, fontFamily: '"IBM Plex Sans", sans-serif', color: C.text, minHeight: "100%" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
            <BarChart2 size={18} color={C.accent} />
            <span style={{ fontSize: 16, fontWeight: 700 }}>Operations Metrics</span>
          </div>
          <div style={{ fontSize: 12, color: C.muted }}>Cryptographic operation throughput, latency, and error analytics</div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ display: "flex", gap: 2, background: C.surface, borderRadius: 6, padding: 2, border: `1px solid ${C.border}` }}>
            {(["1h", "24h", "7d", "30d"] as const).map(w => (
              <button key={w} onClick={() => setTimeWindow(w)} style={{
                padding: "4px 10px", borderRadius: 4, border: "none", cursor: "pointer", fontSize: 11, fontWeight: 600,
                background: timeWindow === w ? C.accent : "transparent",
                color: timeWindow === w ? "#000" : C.muted,
              }}>{w}</button>
            ))}
          </div>
          <button onClick={load} style={{ background: "transparent", border: `1px solid ${C.border}`, borderRadius: 6, padding: "5px 10px", color: C.muted, cursor: "pointer", display: "flex", alignItems: "center", gap: 4, fontSize: 11 }}>
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
      </div>

      {/* Stat Cards */}
      <div style={{ display: "flex", gap: 12, marginBottom: 20 }}>
        {statCard(<Zap size={16} />, "Total Ops", loading ? "—" : fmt(ov.total_ops ?? 0), `window: ${ov.window ?? timeWindow}`, C.accent)}
        {statCard(<Activity size={16} />, "Avg Latency", loading ? "—" : ms(ov.avg_latency_ms ?? 0), "across all operations", (ov.avg_latency_ms ?? 0) > 10 ? C.amber : C.green)}
        {statCard(<Clock size={16} />, "Error Rate", loading ? "—" : pct(ov.error_rate ?? 0), `${ov.total_errors ?? 0} errors`, (ov.error_rate ?? 0) > 0.02 ? C.red : C.green)}
        {statCard(<BarChart2 size={16} />, "Total Errors", loading ? "—" : String(ov.total_errors ?? 0), "in selected window", (ov.total_errors ?? 0) > 0 ? C.amber : C.green)}
      </div>

      {/* Section Tabs */}
      <div style={{ display: "flex", gap: 2, marginBottom: 16, borderBottom: `1px solid ${C.border}` }}>
        {[
          { id: "ops", label: "Operations Breakdown" },
          { id: "latency", label: "Latency Percentiles" },
          { id: "services", label: "By Service" },
          { id: "errors", label: "Error Breakdown" },
        ].map(s => (
          <button key={s.id} onClick={() => setSection(s.id as any)} style={{
            padding: "8px 16px", border: "none", background: "transparent", cursor: "pointer",
            fontSize: 12, fontWeight: section === s.id ? 700 : 400,
            color: section === s.id ? C.accent : C.muted,
            borderBottom: section === s.id ? `2px solid ${C.accent}` : "2px solid transparent",
            marginBottom: -1,
          }}>{s.label}</button>
        ))}
      </div>

      {/* Operations Breakdown */}
      {section === "ops" && (
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 16 }}>Operations by Type — {timeWindow}</div>
          {loading ? <div style={{ color: C.muted, padding: 20, textAlign: "center" }}>Loading...</div> : latency.length === 0 ? (
            <div style={{ textAlign: "center", padding: 40, color: C.muted }}>
              <Activity size={28} style={{ marginBottom: 8, opacity: 0.4 }} />
              <div style={{ fontSize: 13 }}>No operations recorded yet. Operations appear here as keys are used.</div>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {latency.map(row => {
                const count = row.sample_ops ?? row.sample_count ?? 0;
                const p = totalOps > 0 ? (count / totalOps) * 100 : 0;
                const color = OP_COLORS[row.op_type] || C.dim;
                return (
                  <div key={row.op_type + row.service} style={{ display: "flex", alignItems: "center", gap: 12 }}>
                    <div style={{ width: 36, height: 22, borderRadius: 4, background: color + "22", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                      <span style={{ fontSize: 8, fontWeight: 800, color, fontFamily: "monospace" }}>{OP_ICONS[row.op_type] ?? row.op_type?.toUpperCase().slice(0, 3)}</span>
                    </div>
                    <div style={{ width: 90, fontSize: 12, fontWeight: 600, color: C.text, textTransform: "capitalize" }}>{row.service ? `${row.service}/${row.op_type}` : row.op_type}</div>
                    <div style={{ flex: 1, background: C.border, borderRadius: 3, height: 6, overflow: "hidden" }}>
                      <div style={{ width: `${p}%`, height: "100%", background: color, borderRadius: 3, transition: "width 0.4s" }} />
                    </div>
                    <div style={{ width: 60, textAlign: "right", fontSize: 12, color: C.dim }}>{fmt(count)}</div>
                    <div style={{ width: 44, textAlign: "right", fontSize: 11, color: C.muted }}>{p.toFixed(1)}%</div>
                  </div>
                );
              })}
              <div style={{ marginTop: 8, paddingTop: 8, borderTop: `1px solid ${C.border}`, display: "flex", justifyContent: "flex-end", gap: 8 }}>
                <span style={{ fontSize: 12, color: C.muted }}>Total:</span>
                <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{fmt(totalOps)}</span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Latency Percentiles */}
      {section === "latency" && (
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
          <div style={{ padding: "14px 20px", borderBottom: `1px solid ${C.border}`, fontSize: 13, fontWeight: 700 }}>Latency by Operation Type</div>
          {loading ? <div style={{ padding: 24, textAlign: "center", color: C.muted }}>Loading...</div> : latency.length === 0 ? (
            <div style={{ padding: 40, textAlign: "center", color: C.muted }}>No latency data recorded yet.</div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                  {["Service", "Op Type", "Avg", "P50", "P90", "P99", "Samples"].map(h => <th key={h} style={TH}>{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {latency.map((row, i) => {
                  const color = OP_COLORS[row.op_type] || C.dim;
                  return (
                    <tr key={i} style={{ borderBottom: `1px solid ${C.border}22` }}>
                      <td style={{ ...CELL, fontWeight: 600, color: C.text }}>{row.service || "—"}</td>
                      <td style={CELL}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <div style={{ width: 8, height: 8, borderRadius: "50%", background: color }} />
                          <span style={{ fontWeight: 600, color: C.text, textTransform: "capitalize" }}>{row.op_type}</span>
                        </div>
                      </td>
                      <td style={{ ...CELL, color: C.dim }}>{ms(row.avg_ms ?? 0)}</td>
                      <td style={{ ...CELL, color: C.green }}>{ms(row.p50_ms ?? 0)}</td>
                      <td style={{ ...CELL, color: (row.p90_ms ?? 0) > 20 ? C.amber : C.dim }}>{ms(row.p90_ms ?? 0)}</td>
                      <td style={{ ...CELL, color: (row.p99_ms ?? 0) > 30 ? C.orange : C.dim }}>{ms(row.p99_ms ?? 0)}</td>
                      <td style={{ ...CELL, fontFamily: "monospace" }}>{fmt(row.sample_ops ?? row.sample_count ?? 0)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* By Service */}
      {section === "services" && (
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
          <div style={{ padding: "14px 20px", borderBottom: `1px solid ${C.border}`, fontSize: 13, fontWeight: 700 }}>Operations by Service</div>
          {loading ? <div style={{ padding: 24, textAlign: "center", color: C.muted }}>Loading...</div> : services.length === 0 ? (
            <div style={{ padding: 40, textAlign: "center", color: C.muted }}>No service data recorded yet.</div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                  {["Service", "Total Ops", "Errors", "Error Rate", "Avg Latency"].map(h => <th key={h} style={TH}>{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {services.map(svc => (
                  <tr key={svc.service} style={{ borderBottom: `1px solid ${C.border}22` }}>
                    <td style={{ ...CELL, color: C.text, fontWeight: 600 }}>{svc.service}</td>
                    <td style={{ ...CELL, fontFamily: "monospace" }}>{fmt(svc.total_ops ?? 0)}</td>
                    <td style={{ ...CELL, fontFamily: "monospace", color: (svc.total_errors ?? 0) > 0 ? C.amber : C.muted }}>{svc.total_errors ?? 0}</td>
                    <td style={CELL}>
                      <span style={{ color: (svc.error_rate ?? 0) > 0.02 ? C.red : C.green, fontWeight: 600 }}>
                        {pct(svc.error_rate ?? 0)}
                      </span>
                    </td>
                    <td style={{ ...CELL, color: (svc.avg_latency_ms ?? 0) > 10 ? C.amber : C.dim }}>{ms(svc.avg_latency_ms ?? 0)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Error Breakdown */}
      {section === "errors" && (
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, overflow: "hidden" }}>
          <div style={{ padding: "14px 20px", borderBottom: `1px solid ${C.border}`, fontSize: 13, fontWeight: 700 }}>
            Error Breakdown <span style={{ fontSize: 11, fontWeight: 400, color: C.muted, marginLeft: 8 }}>by service and operation</span>
          </div>
          {loading ? <div style={{ padding: 24, textAlign: "center", color: C.muted }}>Loading...</div> : errors.length === 0 ? (
            <div style={{ padding: 40, textAlign: "center", color: C.green }}>
              <Activity size={32} style={{ marginBottom: 8, opacity: 0.5 }} />
              <div>No errors recorded in this window</div>
            </div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                  {["Service", "Op Type", "Errors", "Total Ops", "Error Rate"].map(h => <th key={h} style={TH}>{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {errors.map((err, i) => {
                  const rate = (err.total_count ?? 0) > 0 ? (err.error_count ?? 0) / (err.total_count ?? 1) : 0;
                  return (
                    <tr key={i} style={{ borderBottom: `1px solid ${C.border}22` }}>
                      <td style={{ ...CELL, fontWeight: 600, color: C.text }}>{err.service}</td>
                      <td style={{ ...CELL, fontFamily: "monospace", color: C.amber, fontWeight: 600, fontSize: 11, textTransform: "capitalize" }}>{err.op_type}</td>
                      <td style={{ ...CELL, fontFamily: "monospace", fontWeight: 700, color: C.red }}>{err.error_count ?? 0}</td>
                      <td style={{ ...CELL, fontFamily: "monospace" }}>{fmt(err.total_count ?? 0)}</td>
                      <td style={CELL}>
                        <span style={{ color: rate > 0.05 ? C.red : rate > 0.01 ? C.amber : C.green, fontWeight: 600 }}>{pct(rate)}</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
