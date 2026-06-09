// @ts-nocheck -- legacy v3 tab; types relaxed pending typed-client refactor
import { useEffect, useState } from "react";
import { Activity, AlertTriangle, CheckCircle, RefreshCw } from "lucide-react";
import { C } from "../theme";
import {
  fetchHeartbeats,
  fetchIncidents,
  fetchReconcilerStatus,
  type ServiceState,
  type Incident,
  type ReconcilerStatus,
} from "../../../lib/health";

interface Props {
  session?: any;
}

// HealthTab surfaces the data the watchdog + reconciler emit. The tab
// polls every 15 seconds; the underlying endpoints are cheap (in-memory
// snapshots) so the poll cost is negligible.
export function HealthTab(_: Props) {
  const [heartbeats, setHeartbeats] = useState<ServiceState[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [reconcilers, setReconcilers] = useState<ReconcilerStatus[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const [hbs, inc, rec] = await Promise.all([
        fetchHeartbeats().catch(() => []),
        fetchIncidents().catch(() => []),
        fetchReconcilerStatus().catch(() => []),
      ]);
      setHeartbeats(hbs);
      setIncidents(inc);
      setReconcilers(rec);
    } catch (e: any) {
      setError(e?.message || "fetch failed");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
    const t = setInterval(load, 15_000);
    return () => clearInterval(t);
  }, []);

  return (
    <div style={{ padding: "1.5rem", display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h2 style={{ margin: 0, color: C.text }}>Health & Reconciliation</h2>
          <p style={{ margin: "0.25rem 0 0", color: C.dim, fontSize: 13 }}>
            Live service heartbeats, reconciler controllers, and recent
            playbook-triggered incidents.
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          style={{
            display: "inline-flex", alignItems: "center", gap: 6,
            padding: "0.4rem 0.8rem", borderRadius: 6,
            background: C.surface, color: C.text, border: `1px solid ${C.border}`,
            cursor: loading ? "wait" : "pointer",
          }}
        >
          <RefreshCw size={14} /> Refresh
        </button>
      </header>

      {error && (
        <div style={{ background: C.redBg, color: C.red, padding: "0.5rem 0.75rem", borderRadius: 6 }}>
          {error}
        </div>
      )}

      <section>
        <h3 style={{ color: C.text, marginBottom: "0.5rem" }}>Service Heartbeats</h3>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
          {heartbeats.length === 0 && (
            <div style={{ color: C.dim, fontSize: 13 }}>No heartbeats received yet.</div>
          )}
          {heartbeats.map((h) => (
            <div
              key={h.service}
              style={{
                background: C.surface, border: `1px solid ${C.border}`,
                borderRadius: 8, padding: "0.75rem 1rem",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span style={{ color: C.text, fontWeight: 600 }}>{h.service}</span>
                {h.healthy ? (
                  <CheckCircle size={16} color={C.green} />
                ) : (
                  <AlertTriangle size={16} color={C.amber} />
                )}
              </div>
              <div style={{ color: C.dim, fontSize: 12, marginTop: 4 }}>
                state: {h.state || "unknown"} · silence {h.silence_seconds}s
              </div>
            </div>
          ))}
        </div>
      </section>

      <section>
        <h3 style={{ color: C.text, marginBottom: "0.5rem" }}>Reconciler Controllers</h3>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 12 }}>
          {reconcilers.length === 0 && (
            <div style={{ color: C.dim, fontSize: 13 }}>Reconciler not reachable.</div>
          )}
          {reconcilers.map((r) => (
            <div
              key={r.name}
              style={{
                background: C.surface, border: `1px solid ${C.border}`,
                borderRadius: 8, padding: "0.75rem 1rem",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <Activity size={14} color={r.last_error ? C.red : C.green} />
                <span style={{ color: C.text, fontWeight: 600 }}>{r.name}</span>
              </div>
              <div style={{ color: C.dim, fontSize: 12, marginTop: 4 }}>
                last run: {r.last_run_at || "never"}
              </div>
              {r.last_error && (
                <div style={{ color: C.red, fontSize: 12, marginTop: 4 }}>
                  error: {r.last_error}
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      <section>
        <h3 style={{ color: C.text, marginBottom: "0.5rem" }}>Recent Incidents</h3>
        {incidents.length === 0 ? (
          <div style={{ color: C.dim, fontSize: 13 }}>No incidents in the rolling window.</div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse", background: C.surface, borderRadius: 8 }}>
            <thead>
              <tr style={{ textAlign: "left", color: C.dim, fontSize: 12 }}>
                <th style={{ padding: "0.5rem 0.75rem" }}>Time</th>
                <th style={{ padding: "0.5rem 0.75rem" }}>Service</th>
                <th style={{ padding: "0.5rem 0.75rem" }}>Reason</th>
                <th style={{ padding: "0.5rem 0.75rem" }}>Playbook</th>
              </tr>
            </thead>
            <tbody>
              {incidents.slice(-20).reverse().map((i) => (
                <tr key={i.id} style={{ borderTop: `1px solid ${C.border}`, color: C.text, fontSize: 13 }}>
                  <td style={{ padding: "0.5rem 0.75rem" }}>{i.timestamp}</td>
                  <td style={{ padding: "0.5rem 0.75rem" }}>{i.service}</td>
                  <td style={{ padding: "0.5rem 0.75rem" }}>{i.reason}</td>
                  <td style={{ padding: "0.5rem 0.75rem" }}>{i.action}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
