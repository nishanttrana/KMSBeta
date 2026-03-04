// @ts-nocheck
import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Check,
  Cpu,
  Database,
  Globe,
  Pencil,
  Plus,
  RefreshCw,
  Server,
  Shield,
  Trash2,
  X,
  Zap,
} from "lucide-react";
import type { AuthSession } from "../../../lib/auth";
import type {
  QRNGSource,
  QRNGPoolStatus,
  QRNGHealthEvent,
} from "../../../lib/qrng";
import {
  deleteQRNGSource,
  getQRNGPoolStatus,
  listQRNGHealthEvents,
  listQRNGSources,
  registerQRNGSource,
  updateQRNGSource,
  QRNG_VENDORS,
} from "../../../lib/qrng";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { Bar, Btn, Card, FG, Inp, Modal, Row2, Row3, Section, Stat } from "../legacyPrimitives";

type Props = { session: AuthSession; onToast?: (msg: string) => void };
type ModalType = null | "register" | "edit";

const Dot = ({ ok }: { ok: boolean }) => (
  <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: ok ? C.green : C.red, boxShadow: ok ? `0 0 6px ${C.green}` : `0 0 6px ${C.red}` }} />
);

const StatusBadge = ({ status }: { status: string }) => {
  const colors = { active: C.green, paused: C.amber, error: C.red, removed: C.dim };
  const col = colors[status] || C.dim;
  return <span style={{ padding: "2px 10px", borderRadius: 6, fontSize: 11, fontWeight: 600, background: col + "22", color: col, border: `1px solid ${col}44` }}>{status.toUpperCase()}</span>;
};

const ModeBadge = ({ mode }: { mode: string }) => {
  const col = mode === "push" ? C.accent : C.purple;
  return <span style={{ padding: "2px 10px", borderRadius: 6, fontSize: 11, fontWeight: 600, background: col + "22", color: col, border: `1px solid ${col}44` }}>{mode.toUpperCase()}</span>;
};

export function QRNGTab({ session, onToast }: Props) {
  const tid = session.tenantId || "";
  const toast = onToast || (() => {});

  const [sources, setSources] = useState([]);
  const [pool, setPool] = useState(null);
  const [health, setHealth] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [modal, setModal] = useState(null);
  const [editSrc, setEditSrc] = useState(null);
  const [healthOpen, setHealthOpen] = useState(false);

  const [regName, setRegName] = useState("");
  const [regVendor, setRegVendor] = useState("custom");
  const [regEndpoint, setRegEndpoint] = useState("");
  const [regAuthToken, setRegAuthToken] = useState("");
  const [regMode, setRegMode] = useState("push");
  const [regMinEntropy, setRegMinEntropy] = useState("7.0");
  const [regPullInterval, setRegPullInterval] = useState("60");

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const [srcs, ps, he] = await Promise.all([
        listQRNGSources(tid), getQRNGPoolStatus(tid), listQRNGHealthEvents(tid, 50),
      ]);
      setSources(srcs); setPool(ps); setHealth(he); setError("");
    } catch (e) { setError(errMsg(e)); } finally { setLoading(false); }
  }, [tid]);

  useEffect(() => { load(); }, [load]);

  const resetForm = () => {
    setRegName(""); setRegVendor("custom"); setRegEndpoint(""); setRegAuthToken("");
    setRegMode("push"); setRegMinEntropy("7.0"); setRegPullInterval("60");
  };

  const handleRegister = async () => {
    try {
      await registerQRNGSource({
        tenant_id: tid, name: regName, vendor: regVendor, endpoint: regEndpoint,
        auth_token: regAuthToken, mode: regMode,
        min_entropy_bpb: parseFloat(regMinEntropy) || 7.0,
        pull_interval_s: parseInt(regPullInterval) || 60,
      });
      toast("QRNG source registered"); setModal(null); resetForm(); load();
    } catch (e) { toast("Registration failed: " + errMsg(e)); }
  };

  const handleUpdate = async () => {
    if (!editSrc) return;
    try {
      await updateQRNGSource(tid, editSrc.id, {
        tenant_id: tid, name: regName || editSrc.name, vendor: regVendor,
        endpoint: regEndpoint || editSrc.endpoint, auth_token: regAuthToken, mode: regMode,
        min_entropy_bpb: parseFloat(regMinEntropy) || editSrc.min_entropy_bpb,
        pull_interval_s: parseInt(regPullInterval) || editSrc.pull_interval_s,
      });
      toast("Source updated"); setModal(null); resetForm(); setEditSrc(null); load();
    } catch (e) { toast("Update failed: " + errMsg(e)); }
  };

  const handleDelete = async (id) => {
    if (!confirm("Delete this QRNG source?")) return;
    try { await deleteQRNGSource(tid, id); toast("Source deleted"); load(); }
    catch (e) { toast("Delete failed: " + errMsg(e)); }
  };

  const openEdit = (src) => {
    setEditSrc(src); setRegName(src.name); setRegVendor(src.vendor);
    setRegEndpoint(src.endpoint); setRegAuthToken(""); setRegMode(src.mode);
    setRegMinEntropy(String(src.min_entropy_bpb)); setRegPullInterval(String(src.pull_interval_s));
    setModal("edit");
  };

  if (error && !loading) {
    return (
      <div>
        <Section title="QRNG Entropy Sources">
          <Card>
            <div style={{ color: C.red, padding: 20 }}>
              <AlertTriangle size={16} style={{ marginRight: 6, verticalAlign: -2 }} />
              QRNG load failed: {error}
              <Btn small onClick={load} style={{ marginLeft: 16 }}>Retry</Btn>
            </div>
          </Card>
        </Section>
      </div>
    );
  }

  const activeSources = sources.filter((s) => s.status === "active").length;
  const poolHealthy = pool?.pool_healthy ?? false;
  const avgEntropy = pool?.avg_entropy_bpb ?? 0;
  const availSamples = pool?.available_samples ?? 0;

  return (
    <div>
      {/* KPI Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10, marginBottom: 12 }}>
        <Stat l="Pool Health" v={poolHealthy ? "Healthy" : "Degraded"} s={poolHealthy ? "All checks passing" : "Check source status"} c={poolHealthy ? "green" : "red"} i={Shield} />
        <Stat l="Available Samples" v={String(availSamples)} s={`${pool?.consumed_samples ?? 0} consumed`} c="accent" i={Database} />
        <Stat l="Avg Entropy" v={avgEntropy > 0 ? avgEntropy.toFixed(2) + " bpb" : "--"} s="NIST SP 800-90B" c={avgEntropy >= 7.0 ? "green" : "amber"} i={Zap} />
        <Stat l="Active Sources" v={String(activeSources)} s={`${sources.length} total registered`} c={activeSources > 0 ? "green" : "dim"} i={Server} />
      </div>

      {/* Pool Status + Architecture */}
      <Row2>
        <Section title="Entropy Pool">
          <Card>
            <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
              <Dot ok={poolHealthy} />
              <span style={{ fontWeight: 600, color: C.text }}>{poolHealthy ? "Pool is healthy" : "Pool degraded"}</span>
              <Btn small onClick={load} style={{ marginLeft: "auto" }}>Refresh</Btn>
            </div>
            <Bar pct={pool ? Math.round((pool.available_samples / Math.max(pool.total_samples, 1)) * 100) : 0} color={C.accent} />
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginTop: 12, fontSize: 12, color: C.dim }}>
              <div>Total: <span style={{ color: C.text }}>{pool?.total_samples ?? 0}</span></div>
              <div>Available: <span style={{ color: C.green }}>{pool?.available_samples ?? 0}</span></div>
              <div>Consumed: <span style={{ color: C.amber }}>{pool?.consumed_samples ?? 0}</span></div>
            </div>
          </Card>
        </Section>

        <Section title="Defense-in-Depth Architecture">
          <Card>
            <div style={{ fontSize: 12, color: C.dim, lineHeight: 1.7 }}>
              <div><Zap size={12} style={{ verticalAlign: -2, marginRight: 4, color: C.accent }} />External QRNG entropy XOR-absorbed into 512-byte ring buffer</div>
              <div><Shield size={12} style={{ verticalAlign: -2, marginRight: 4, color: C.green }} />SHA-256 counter-mode extraction with OS CSPRNG mixing</div>
              <div><Activity size={12} style={{ verticalAlign: -2, marginRight: 4, color: C.purple }} />NIST SP 800-90B health tests on every ingest</div>
              <div><Cpu size={12} style={{ verticalAlign: -2, marginRight: 4, color: C.amber }} />Raw entropy bytes never persisted (only SHA-256 hash for audit)</div>
            </div>
          </Card>
        </Section>
      </Row2>

      {/* Source Registry */}
      <Section title="Source Registry" actions={<Btn primary small onClick={() => { resetForm(); setModal("register"); }}>+ Register Source</Btn>}>
        <Card>
          {sources.length === 0 && !loading ? (
            <div style={{ color: C.dim, padding: 20, textAlign: "center" }}>No QRNG sources registered. Register your first external quantum entropy source.</div>
          ) : (
            <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}`, color: C.dim, textAlign: "left" }}>
                  <th style={{ padding: "8px 6px" }}>Name</th><th style={{ padding: "8px 6px" }}>Vendor</th>
                  <th style={{ padding: "8px 6px" }}>Mode</th><th style={{ padding: "8px 6px" }}>Status</th>
                  <th style={{ padding: "8px 6px" }}>Entropy</th><th style={{ padding: "8px 6px" }}>Last Seen</th>
                  <th style={{ padding: "8px 6px" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sources.map((src) => (
                  <tr key={src.id} style={{ borderBottom: `1px solid ${C.border}15` }}>
                    <td style={{ padding: "8px 6px", color: C.text, fontWeight: 500 }}>{src.name}</td>
                    <td style={{ padding: "8px 6px" }}>{QRNG_VENDORS.find(v => v.value === src.vendor)?.label || src.vendor}</td>
                    <td style={{ padding: "8px 6px" }}><ModeBadge mode={src.mode} /></td>
                    <td style={{ padding: "8px 6px" }}><StatusBadge status={src.status} /></td>
                    <td style={{ padding: "8px 6px", color: src.min_entropy_bpb >= 7.0 ? C.green : C.amber }}>{src.min_entropy_bpb.toFixed(1)} bpb</td>
                    <td style={{ padding: "8px 6px", color: C.dim, fontSize: 11 }}>{src.last_seen_at ? new Date(src.last_seen_at).toLocaleString() : "Never"}</td>
                    <td style={{ padding: "8px 6px" }}>
                      <div style={{ display: "flex", gap: 4 }}>
                        <Btn small onClick={() => openEdit(src)}><Pencil size={12} /></Btn>
                        <Btn small danger onClick={() => handleDelete(src.id)}><Trash2 size={12} /></Btn>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </Section>

      {/* Vendor Info */}
      <Row3>
        <Card>
          <div style={{ fontWeight: 600, fontSize: 13, color: C.accent, marginBottom: 8 }}>
            <Globe size={14} style={{ verticalAlign: -2, marginRight: 6 }} />ID Quantique Quantis
          </div>
          <div style={{ fontSize: 11, color: C.dim, lineHeight: 1.6 }}>Swiss-made quantum random number generator. Uses photon detection for true quantum randomness. Supports PCIe, USB, and network-attached form factors. NIST SP 800-90B certified.</div>
        </Card>
        <Card>
          <div style={{ fontWeight: 600, fontSize: 13, color: C.purple, marginBottom: 8 }}>
            <Cpu size={14} style={{ verticalAlign: -2, marginRight: 6 }} />QuintessenceLabs qStream
          </div>
          <div style={{ fontSize: 11, color: C.dim, lineHeight: 1.6 }}>Quantum tunneling-based QRNG delivering continuous entropy. Full-disk rate up to 1 Gbps. REST API for entropy-as-a-service. AIS 31 PTG.2 compliant.</div>
        </Card>
        <Card>
          <div style={{ fontWeight: 600, fontSize: 13, color: C.green, marginBottom: 8 }}>
            <Zap size={14} style={{ verticalAlign: -2, marginRight: 6 }} />Toshiba QRNG
          </div>
          <div style={{ fontSize: 11, color: C.dim, lineHeight: 1.6 }}>Photonic integrated circuit QRNG. Compact, high-speed quantum randomness source. Network-ready with enterprise management interface. NIST certified entropy source.</div>
        </Card>
      </Row3>

      {/* Health Log */}
      <Section title="Health Event Log" actions={<Btn small onClick={() => setHealthOpen(!healthOpen)}>{healthOpen ? "Collapse" : "Expand"}</Btn>}>
        {healthOpen && (
          <Card>
            {health.length === 0 ? (
              <div style={{ color: C.dim, padding: 16, textAlign: "center" }}>No health events recorded yet.</div>
            ) : (
              <table style={{ width: "100%", fontSize: 11, borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.border}`, color: C.dim, textAlign: "left" }}>
                    <th style={{ padding: "6px" }}>Time</th><th style={{ padding: "6px" }}>Source</th>
                    <th style={{ padding: "6px" }}>Check</th><th style={{ padding: "6px" }}>Result</th>
                    <th style={{ padding: "6px" }}>Entropy</th>
                  </tr>
                </thead>
                <tbody>
                  {health.map((h) => (
                    <tr key={h.id} style={{ borderBottom: `1px solid ${C.border}10` }}>
                      <td style={{ padding: "6px", color: C.dim }}>{new Date(h.created_at).toLocaleString()}</td>
                      <td style={{ padding: "6px", color: C.text }}>{h.source_id?.slice(0, 12) || "pool"}</td>
                      <td style={{ padding: "6px" }}>{h.check_type}</td>
                      <td style={{ padding: "6px" }}>
                        {h.result === "pass"
                          ? <span style={{ color: C.green }}><Check size={12} style={{ verticalAlign: -2 }} /> PASS</span>
                          : <span style={{ color: C.red }}><X size={12} style={{ verticalAlign: -2 }} /> FAIL</span>}
                      </td>
                      <td style={{ padding: "6px", color: h.entropy_bpb >= 7.0 ? C.green : C.red }}>{h.entropy_bpb > 0 ? h.entropy_bpb.toFixed(2) + " bpb" : "--"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        )}
      </Section>

      {/* Register/Edit Modal */}
      <Modal open={modal === "register" || modal === "edit"} onClose={() => { setModal(null); setEditSrc(null); resetForm(); }} title={modal === "register" ? "Register QRNG Source" : "Edit QRNG Source"}>
        <div style={{ display: "grid", gap: 12 }}>
          <FG label="Source Name"><Inp value={regName} onChange={(e) => setRegName(e.target.value)} placeholder="My QRNG Source" /></FG>
          <FG label="Vendor">
            <select value={regVendor} onChange={(e) => setRegVendor(e.target.value)} style={{ backgroundColor: C.card, border: `1px solid ${C.border}`, borderRadius: 7, padding: "8px 10px", color: C.text, fontSize: 11, width: "100%" }}>
              {QRNG_VENDORS.map((v) => <option key={v.value} value={v.value}>{v.label}</option>)}
            </select>
          </FG>
          <FG label="Endpoint URL"><Inp value={regEndpoint} onChange={(e) => setRegEndpoint(e.target.value)} placeholder="https://qrng.example.com/api" /></FG>
          <FG label="Auth Token"><Inp type="password" value={regAuthToken} onChange={(e) => setRegAuthToken(e.target.value)} placeholder="Bearer token or API key" /></FG>
          <FG label="Mode">
            <select value={regMode} onChange={(e) => setRegMode(e.target.value)} style={{ backgroundColor: C.card, border: `1px solid ${C.border}`, borderRadius: 7, padding: "8px 10px", color: C.text, fontSize: 11, width: "100%" }}>
              <option value="push">Push (source sends entropy to KMS)</option>
              <option value="pull">Pull (KMS fetches from source)</option>
            </select>
          </FG>
          <Row2>
            <FG label="Min Entropy (bpb)"><Inp value={regMinEntropy} onChange={(e) => setRegMinEntropy(e.target.value)} placeholder="7.0" /></FG>
            <FG label="Pull Interval (s)"><Inp value={regPullInterval} onChange={(e) => setRegPullInterval(e.target.value)} placeholder="60" /></FG>
          </Row2>
          <Btn primary onClick={modal === "register" ? handleRegister : handleUpdate}>
            {modal === "register" ? "Register Source" : "Update Source"}
          </Btn>
        </div>
      </Modal>
    </div>
  );
}
