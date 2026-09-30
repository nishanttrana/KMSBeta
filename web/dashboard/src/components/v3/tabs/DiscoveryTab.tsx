import { useEffect, useMemo, useState } from "react";
import { B, Btn, Card, Chk, Inp, Section, Sel, Stat, Tabs } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  DISCOVERY_SCAN_TYPES,
  getDiscoverySummary,
  listDiscoveryAssets,
  listDiscoveryScans,
  reviewAsset,
  startDiscoveryScan,
  type CryptoAsset,
  type DiscoveryScan,
  type DiscoverySummary,
} from "../../../lib/discovery";

// What each scan source reads, and what it needs to be configured.
const SOURCE_HINT: Record<string, string> = {
  network: "TLS handshakes with DISCOVERY_TLS_ENDPOINTS",
  cloud: "live key inventory of connected cloud accounts",
  certs: "certificates issued by this KMS",
  code: "key and certificate fingerprints under WORKSPACE_ROOT",
};

const REVIEW_STATUSES = ["active", "reviewed", "accepted_risk", "remediated"];

const CELL = { padding: "7px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid ${C.border}`, textAlign: "left" as const };
const HEAD = { ...CELL, color: C.muted, fontWeight: 600 };

function classTone(c: string) {
  return c === "strong" ? "green" : c === "vulnerable" ? "red" : "amber";
}

function fmtTS(v?: string) {
  if (!v) return "-";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) || d.getFullYear() < 2000 ? "-" : d.toLocaleString();
}

export const DiscoveryTab = ({ session, onToast }: any) => {
  const [view, setView] = useState("Inventory");
  const [summary, setSummary] = useState<DiscoverySummary | null>(null);
  const [assets, setAssets] = useState<CryptoAsset[]>([]);
  const [scans, setScans] = useState<DiscoveryScan[]>([]);
  const [loadError, setLoadError] = useState("");
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [types, setTypes] = useState<string[]>([...DISCOVERY_SCAN_TYPES]);
  const [source, setSource] = useState("");
  const [classification, setClassification] = useState("");
  const [search, setSearch] = useState("");

  const load = async () => {
    if (!session?.token) return;
    setLoading(true);
    try {
      const [s, a, sc] = await Promise.all([
        getDiscoverySummary(session),
        listDiscoveryAssets(session, { limit: 500, source, classification }),
        listDiscoveryScans(session, 20),
      ]);
      setSummary(s);
      setAssets(a);
      setScans(sc);
      setLoadError("");
    } catch (error) {
      setSummary(null);
      setLoadError(errMsg(error));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: reload when the tenant or a server-side filter changes; load is a per-render closure.
  }, [session?.tenantId, session?.token, source, classification]);

  const runScan = async () => {
    if (!types.length) return;
    setScanning(true);
    try {
      const scan = await startDiscoveryScan(session, types);
      const errs = (scan?.stats as any)?.errors;
      onToast?.(errs ? `Scan ${scan.status}: ${Object.keys(errs).join(", ")} not scanned` : `Scan ${scan.status || "started"}`);
      setView("Scans");
      await load();
    } catch (error) {
      onToast?.(`Discovery scan failed: ${errMsg(error)}`);
    } finally {
      setScanning(false);
    }
  };

  const review = async (asset: CryptoAsset, status: string) => {
    try {
      const next = await reviewAsset(session, asset.id, status);
      setAssets((prev) => prev.map((a) => (a.id === asset.id ? { ...a, ...next } : a)));
    } catch (error) {
      onToast?.(`Review failed: ${errMsg(error)}`);
    }
  };

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return assets;
    return assets.filter((a) => [a.name, a.location, a.algorithm, a.asset_type, a.source].join(" ").toLowerCase().includes(q));
  }, [assets, search]);

  const counts = summary?.classification_counts || {};
  const sources = Object.keys(summary?.source_distribution || {}).sort();

  return (
    <div>
      <Section
        title="Crypto Discovery"
        actions={<Btn onClick={() => void load()}>{loading ? "Refreshing..." : "Refresh"}</Btn>}
      />

      {loadError ? (
        <Card style={{ marginBottom: 14, borderColor: C.red }}>
          <div style={{ fontSize: 12, color: C.red }}>Discovery unavailable: {loadError}</div>
        </Card>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))", gap: 10, marginBottom: 14 }}>
          <Stat l="Assets" v={summary ? String(summary.total_assets) : "-"} s={`${sources.length} sources`} c="accent" />
          <Stat l="Post-quantum" v={summary ? String(summary.pqc_ready_count) : "-"} s={summary ? `${summary.pqc_readiness_percent}% of assets` : ""} c="green" />
          <Stat l="Quantum-vulnerable" v={summary ? String(counts.vulnerable || 0) : "-"} s="per the algorithm catalogue" c="red" />
          <Stat l="Not assessed" v={summary ? String(counts.unknown || 0) : "-"} s="algorithm not in the catalogue" c="amber" />
        </div>
      )}

      <Card style={{ marginBottom: 14 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 10 }}>Run a scan</div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 16, marginBottom: 10 }}>
          {DISCOVERY_SCAN_TYPES.map((t) => (
            <div key={t} title={SOURCE_HINT[t]}>
              <Chk
                label={`${t} — ${SOURCE_HINT[t]}`}
                checked={types.includes(t)}
                onChange={() => setTypes((prev) => (prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t]))}
              />
            </div>
          ))}
        </div>
        <Btn primary onClick={() => void runScan()} disabled={scanning || !types.length}>{scanning ? "Scanning..." : "Start scan"}</Btn>
      </Card>

      <Tabs tabs={["Inventory", "Scans"]} active={view} onChange={setView} />

      {view === "Inventory" && (
        <Card>
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 10, marginBottom: 10 }}>
            <Inp placeholder="Search name, location, algorithm" value={search} onChange={(e) => setSearch(e.target.value)} />
            <Sel value={source} onChange={(e) => setSource(e.target.value)}>
              <option value="">All sources</option>
              {sources.map((s) => <option key={s} value={s}>{s}</option>)}
            </Sel>
            <Sel value={classification} onChange={(e) => setClassification(e.target.value)}>
              <option value="">All classifications</option>
              <option value="strong">strong</option>
              <option value="vulnerable">vulnerable</option>
              <option value="unknown">not assessed</option>
            </Sel>
          </div>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>{["Name", "Type", "Source", "Location", "Algorithm", "Strength", "Classification", "Last seen", "Review"].map((h) => <th key={h} style={HEAD}>{h}</th>)}</tr>
              </thead>
              <tbody>
                {visible.map((a) => (
                  <tr key={a.id}>
                    <td style={CELL}>{a.name}</td>
                    <td style={CELL}>{a.asset_type}</td>
                    <td style={CELL}>{a.source}</td>
                    <td style={{ ...CELL, fontFamily: "'JetBrains Mono',monospace", maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis" }}>{a.location || "-"}</td>
                    <td style={CELL}>{a.algorithm}{a.pqc_ready ? <> <B c="green">PQC</B></> : null}</td>
                    <td style={CELL}>{a.strength_bits > 0 ? `${a.strength_bits}-bit` : "not assessed"}</td>
                    <td style={CELL}><B c={classTone(a.classification)}>{a.classification === "unknown" ? "not assessed" : a.classification}</B></td>
                    <td style={CELL}>{fmtTS(a.last_seen)}</td>
                    <td style={CELL}>
                      <Sel w={130} value={REVIEW_STATUSES.includes(a.status) ? a.status : "active"} onChange={(e) => void review(a, e.target.value)}>
                        {REVIEW_STATUSES.map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
                      </Sel>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!visible.length && !loadError && (
              <div style={{ textAlign: "center", padding: "24px 0", color: C.muted, fontSize: 11 }}>No assets discovered yet. Run a scan above.</div>
            )}
          </div>
        </Card>
      )}

      {view === "Scans" && (
        <Card>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>{["Started", "Sources", "Status", "Assets", "Not scanned", "Trigger"].map((h) => <th key={h} style={HEAD}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {scans.map((s) => {
                const stats: any = s.stats || {};
                const errs: Record<string, string> = stats.errors || {};
                return (
                  <tr key={s.id}>
                    <td style={CELL}>{fmtTS(s.started_at)}</td>
                    <td style={CELL}>{s.scan_type}</td>
                    <td style={CELL}><B c={s.status === "completed" ? "green" : s.status === "failed" ? "red" : "amber"}>{s.status}</B></td>
                    <td style={CELL}>{String(stats.assets_discovered ?? "-")}</td>
                    <td style={{ ...CELL, color: C.muted }}>{Object.entries(errs).map(([k, v]) => `${k}: ${v}`).join("; ") || "-"}</td>
                    <td style={CELL}>{s.trigger}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {!scans.length && !loadError && (
            <div style={{ textAlign: "center", padding: "24px 0", color: C.muted, fontSize: 11 }}>No scans yet.</div>
          )}
        </Card>
      )}
    </div>
  );
};
