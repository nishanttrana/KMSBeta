import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowRightLeft,
  ChevronDown,
  ChevronUp,
  Globe,
  Key,
  Layers,
  Link2,
  Network,
  Pencil,
  Plus,
  Radio,
  RefreshCw,
  Send,
  Server,
  Settings,
  Shield,
  Trash2,
  Zap,
} from "lucide-react";
import type { AuthSession } from "../../../lib/auth";
import type {
  Distribution,
  QKDConfig,
  QKDGenerateTestInput,
  QKDKey,
  QKDLogEntry,
  QKDOverview,
  RegisterSAEInput,
  SlaveSAE,
} from "../../../lib/qkd";
import {
  deleteSlaveSAE,
  distributeKeys,
  getQKDConfig,
  getQKDOverview,
  injectQKDKey,
  listDistributions,
  listQKDKeys,
  listQKDLogs,
  listSlaveSAEs,
  registerSlaveSAE,
  runQKDTestGenerate,
  updateQKDConfig,
  updateSlaveSAE,
} from "../../../lib/qkd";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Bar, Btn, Card, Chk, FG, Inp, Modal, Row2, Row3, Section, Sel, Stat } from "../legacyPrimitives";

type Props = { session: AuthSession; onToast?: (msg: string) => void };

type ModalType =
  | null
  | "config"
  | "inject"
  | "keys"
  | "register-sae"
  | "edit-sae"
  | "distribute"
  | "distributions";

// ── Small helper components ──────────────────────────────────

const Dot = ({ ok }: { ok: boolean }) => (
  <span
    style={{
      display: "inline-block",
      width: 8,
      height: 8,
      borderRadius: "50%",
      background: ok ? C.green : C.red,
      boxShadow: ok ? `0 0 6px ${C.green}` : `0 0 6px ${C.red}`,
    }}
  />
);

const KV = ({ k, v, mono }: { k: string; v: string; mono?: boolean }) => (
  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, padding: "3px 0", gap: 10 }}>
    <span style={{ color: C.muted, whiteSpace: "nowrap" }}>{k}</span>
    <span
      style={{
        color: C.text,
        fontFamily: mono ? "'JetBrains Mono',monospace" : undefined,
        textAlign: "right",
        wordBreak: "break-all",
      }}
    >
      {v}
    </span>
  </div>
);

const ModeBadge = ({ mode }: { mode: string }) => {
  const m = String(mode || "etsi").toLowerCase();
  if (m === "cisco-ckm") return <B c="purple">Cisco CKM</B>;
  if (m === "relay") return <B c="amber">Relay</B>;
  return <B c="blue">ETSI</B>;
};

const StatusBadge = ({ status }: { status: string }) => {
  const s = String(status || "").toLowerCase();
  if (s === "active") return <B c="green">Active</B>;
  if (s === "error") return <B c="red">Error</B>;
  return <B c="amber">Inactive</B>;
};

// ── Main QKD Tab ─────────────────────────────────────────────

export const QKDTab = ({ session, onToast }: Props) => {
  const [modal, setModal] = useState<ModalType>(null);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  // Existing QKD state
  const [overview, setOverview] = useState<QKDOverview | null>(null);
  const [qkdConfig, setQKDConfig] = useState<QKDConfig | null>(null);
  const [keys, setKeys] = useState<QKDKey[]>([]);
  const [logs, setLogs] = useState<QKDLogEntry[]>([]);
  const [slaveSAEID, setSlaveSAEID] = useState("");

  // Slave SAE registry state
  const [slaveSAEs, setSlaveSAEs] = useState<SlaveSAE[]>([]);
  const [distributions, setDistributions] = useState<Distribution[]>([]);
  const [selectedSAE, setSelectedSAE] = useState<SlaveSAE | null>(null);

  // Config modal
  const [configDraft, setConfigDraft] = useState({
    qber_threshold: 0.11,
    pool_low_threshold: 10,
    pool_capacity: 1250000,
    auto_inject: false,
    service_enabled: true,
    etsi_api_enabled: true,
    protocol: "ETSI GS QKD 014",
    distance_km: 47,
  });
  const [savingConfig, setSavingConfig] = useState(false);

  // SAE registration/edit modal
  const [saeDraft, setSaeDraft] = useState<RegisterSAEInput>({
    name: "",
    endpoint: "",
    auth_token: "",
    protocol: "ETSI GS QKD 014",
    role: "consumer",
    mode: "etsi",
    max_key_rate: 0,
    qber_threshold: 0.11,
  });
  const [savingSAE, setSavingSAE] = useState(false);

  // Distribute modal
  const [distSAEId, setDistSAEId] = useState("");
  const [distCount, setDistCount] = useState("10");
  const [distKeyBits, setDistKeyBits] = useState("256");
  const [distributing, setDistributing] = useState(false);

  // Inject modal
  const [selectedKeyID, setSelectedKeyID] = useState("");
  const [injectPurpose, setInjectPurpose] = useState("encrypt");
  const [injectConsume, setInjectConsume] = useState(true);
  const [injecting, setInjecting] = useState(false);

  // Self-test
  const [runningTest, setRunningTest] = useState(false);
  const [testCount, setTestCount] = useState("64");
  const [testKeyBits, setTestKeyBits] = useState("256");
  const [testQberMin, setTestQberMin] = useState("0.01");
  const [testQberMax, setTestQberMax] = useState("0.08");

  // Expand/collapse
  const [showSAEPanel, setShowSAEPanel] = useState(true);
  const [showLogsPanel, setShowLogsPanel] = useState(true);

  const activeSlave = String(overview?.slave_sae_id || slaveSAEID || "");

  // ── Data loading ──────────────────────────────────────────

  const loadData = useCallback(
    async (silent = false) => {
      if (!session?.token) return;
      if (!silent) setLoading(true);
      else setRefreshing(true);
      try {
        const [cfg, ov, saeList] = await Promise.all([
          getQKDConfig(session),
          getQKDOverview(session, slaveSAEID || ""),
          listSlaveSAEs(session),
        ]);
        const slave = String(ov?.slave_sae_id || slaveSAEID || "");
        const [keyItems, logItems, distItems] = await Promise.all([
          slave
            ? listQKDKeys(session, { slave_sae_id: slave, status: ["available", "reserved", "injected"], limit: 300 })
            : Promise.resolve([]),
          listQKDLogs(session, 120),
          listDistributions(session, "", 50),
        ]);
        setQKDConfig(cfg);
        setOverview(ov);
        setSlaveSAEs(Array.isArray(saeList) ? saeList : []);
        setKeys(Array.isArray(keyItems) ? keyItems : []);
        setLogs(Array.isArray(logItems) ? logItems : []);
        setDistributions(Array.isArray(distItems) ? distItems : []);
        if (slave && !slaveSAEID) setSlaveSAEID(slave);
        const injectable = (Array.isArray(keyItems) ? keyItems : []).find(
          (item) => item.status === "available" || item.status === "reserved"
        );
        setSelectedKeyID(injectable?.id || "");
      } catch (error) {
        onToast?.(`QKD load failed: ${errMsg(error)}`);
      } finally {
        if (!silent) setLoading(false);
        else setRefreshing(false);
      }
    },
    [session, slaveSAEID, onToast]
  );

  useEffect(() => {
    if (!session?.token) return;
    void loadData(false);
    const id = setInterval(() => void loadData(true), 15000);
    return () => clearInterval(id);
  }, [session?.token, session?.tenantId, slaveSAEID, loadData]);

  // ── Derived values ────────────────────────────────────────

  const poolAvailable = Number(overview?.pool?.available_keys || 0);
  const poolPct = Math.max(0, Math.min(100, Number(overview?.pool?.pool_fill_pct || 0)));
  const usedToday = Number(overview?.pool?.used_today || 0);
  const createdToday = Number(overview?.status?.keys_received_today || 0);
  const qberAvg = Number(overview?.status?.qber_avg || 0);
  const keyRate = Number(overview?.status?.key_rate || 0);
  const active = Boolean(overview?.status?.active);
  const serviceEnabled = Boolean(overview?.config?.service_enabled);
  const etsiEnabled = Boolean(overview?.config?.etsi_api_enabled);
  const totalSAEs = slaveSAEs.length;
  const activeSAEs = slaveSAEs.filter((s) => s.status === "active").length;
  const totalDistributed = slaveSAEs.reduce((sum, s) => sum + Number(s.keys_distributed || 0), 0);

  const injectableKeys = useMemo(
    () => keys.filter((k) => k.status === "available" || k.status === "reserved"),
    [keys]
  );

  // ── Actions ───────────────────────────────────────────────

  const openConfig = () => {
    setConfigDraft({
      qber_threshold: Number(qkdConfig?.qber_threshold || 0.11),
      pool_low_threshold: Number(qkdConfig?.pool_low_threshold || 10),
      pool_capacity: Number(qkdConfig?.pool_capacity || 1250000),
      auto_inject: Boolean(qkdConfig?.auto_inject),
      service_enabled: Boolean(qkdConfig?.service_enabled),
      etsi_api_enabled: Boolean(qkdConfig?.etsi_api_enabled),
      protocol: String(qkdConfig?.protocol || "ETSI GS QKD 014"),
      distance_km: Number(qkdConfig?.distance_km || 47),
    });
    setModal("config");
  };

  const saveConfig = async () => {
    if (!session?.token) return;
    setSavingConfig(true);
    try {
      const updated = await updateQKDConfig(session, {
        qber_threshold: Math.max(0, Math.min(1, Number(configDraft.qber_threshold || 0.11))),
        pool_low_threshold: Math.max(1, Math.trunc(Number(configDraft.pool_low_threshold || 10))),
        pool_capacity: Math.max(1, Math.trunc(Number(configDraft.pool_capacity || 1250000))),
        auto_inject: Boolean(configDraft.auto_inject),
        service_enabled: Boolean(configDraft.service_enabled),
        etsi_api_enabled: Boolean(configDraft.etsi_api_enabled),
        protocol: String(configDraft.protocol || "ETSI GS QKD 014").trim() || "ETSI GS QKD 014",
        distance_km: Math.max(0, Number(configDraft.distance_km || 47)),
      });
      setQKDConfig(updated);
      onToast?.("QKD configuration updated.");
      setModal(null);
      await loadData(true);
    } catch (error) {
      onToast?.(`Config update failed: ${errMsg(error)}`);
    } finally {
      setSavingConfig(false);
    }
  };

  const openRegisterSAE = () => {
    setSaeDraft({
      name: "",
      endpoint: "",
      auth_token: "",
      protocol: "ETSI GS QKD 014",
      role: "consumer",
      mode: "etsi",
      max_key_rate: 0,
      qber_threshold: 0.11,
    });
    setSelectedSAE(null);
    setModal("register-sae");
  };

  const openEditSAE = (sae: SlaveSAE) => {
    setSaeDraft({
      name: sae.name,
      endpoint: sae.endpoint,
      auth_token: "",
      protocol: sae.protocol,
      role: sae.role,
      mode: sae.mode,
      max_key_rate: sae.max_key_rate,
      qber_threshold: sae.qber_threshold,
    });
    setSelectedSAE(sae);
    setModal("edit-sae");
  };

  const handleSaveSAE = async () => {
    if (!session?.token) return;
    if (!saeDraft.name.trim()) {
      onToast?.("SAE name is required.");
      return;
    }
    setSavingSAE(true);
    try {
      if (modal === "edit-sae" && selectedSAE) {
        await updateSlaveSAE(session, selectedSAE.id, saeDraft);
        onToast?.(`SAE "${saeDraft.name}" updated.`);
      } else {
        await registerSlaveSAE(session, saeDraft);
        onToast?.(`SAE "${saeDraft.name}" registered.`);
      }
      setModal(null);
      await loadData(true);
    } catch (error) {
      onToast?.(`SAE save failed: ${errMsg(error)}`);
    } finally {
      setSavingSAE(false);
    }
  };

  const handleDeleteSAE = async (sae: SlaveSAE) => {
    if (!session?.token) return;
    if (!window.confirm(`Delete slave SAE "${sae.name}"? This cannot be undone.`)) return;
    try {
      await deleteSlaveSAE(session, sae.id);
      onToast?.(`SAE "${sae.name}" deleted.`);
      await loadData(true);
    } catch (error) {
      onToast?.(`Delete failed: ${errMsg(error)}`);
    }
  };

  const openDistribute = (saeId?: string) => {
    setDistSAEId(saeId || (slaveSAEs[0]?.id ?? ""));
    setDistCount("10");
    setDistKeyBits("256");
    setModal("distribute");
  };

  const handleDistribute = async () => {
    if (!session?.token || !distSAEId) return;
    setDistributing(true);
    try {
      const result = await distributeKeys(session, distSAEId, {
        count: Math.max(1, Math.trunc(Number(distCount || 10))),
        key_size_bits: Math.max(128, Math.trunc(Number(distKeyBits || 256))),
      });
      onToast?.(`Distributed ${result.key_count} keys to SAE. Status: ${result.status}`);
      setModal(null);
      await loadData(true);
    } catch (error) {
      onToast?.(`Distribution failed: ${errMsg(error)}`);
    } finally {
      setDistributing(false);
    }
  };

  const runSelfTest = async () => {
    if (!session?.token || !activeSlave) {
      onToast?.("Set a slave SAE ID first.");
      return;
    }
    setRunningTest(true);
    try {
      const result = await runQKDTestGenerate(session, {
        slave_sae_id: activeSlave,
        device_id: `selftest-${activeSlave}`,
        device_name: `QKD SelfTest ${activeSlave}`,
        role: "peer",
        link_status: "up",
        count: Math.max(1, Math.min(500, Math.trunc(Number(testCount || 64)))),
        key_size_bits: Math.max(128, Math.min(4096, Math.trunc(Number(testKeyBits || 256)))),
        qber_min: Math.max(0, Math.min(1, Number(testQberMin || 0.01))),
        qber_max: Math.max(0, Math.min(1, Number(testQberMax || 0.08))),
      });
      onToast?.(
        `QKD test: accepted ${result?.accepted_count || 0}, discarded ${result?.discarded_count || 0}`
      );
      await loadData(true);
    } catch (error) {
      onToast?.(`QKD test failed: ${errMsg(error)}`);
    } finally {
      setRunningTest(false);
    }
  };

  const injectSelected = async () => {
    if (!session?.token || !selectedKeyID) return;
    setInjecting(true);
    try {
      const out = await injectQKDKey(session, selectedKeyID, {
        name: `qkd-${selectedKeyID}`,
        purpose: injectPurpose,
        consume: injectConsume,
      });
      onToast?.(`Injected ${out.qkd_key_id} -> KeyCore ${out.keycore_key_id}`);
      setModal(null);
      await loadData(true);
    } catch (error) {
      onToast?.(`Inject failed: ${errMsg(error)}`);
    } finally {
      setInjecting(false);
    }
  };

  // ── Render ────────────────────────────────────────────────

  return (
    <div>
      {/* ── Header ───────────────────────────────────────── */}
      <Section
        title="Quantum Key Distribution"
        actions={
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <Btn small onClick={() => void loadData(false)} disabled={loading || refreshing}>
              <RefreshCw size={12} style={{ marginRight: 4 }} />
              {loading || refreshing ? "Loading..." : "Refresh"}
            </Btn>
            <Btn small onClick={openConfig}>
              <Settings size={12} style={{ marginRight: 4 }} />
              Configure
            </Btn>
          </div>
        }
      >
        {/* ── KPI Stats Row ──────────────────────────────── */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: 10, marginBottom: 14 }}>
          <Stat
            i={Radio}
            l="Link Status"
            v={active && serviceEnabled ? "Active" : "Inactive"}
            c={active && serviceEnabled ? "green" : "red"}
          />
          <Stat
            i={Key}
            l="Key Pool"
            v={poolAvailable.toLocaleString()}
            s={`${poolPct.toFixed(1)}% capacity`}
            c={Number(overview?.pool?.low) ? "red" : "green"}
          />
          <Stat
            i={Zap}
            l="Key Rate"
            v={`${keyRate.toFixed(3)}/s`}
            s={`${createdToday} received today`}
            c="accent"
          />
          <Stat
            i={Activity}
            l="QBER"
            v={`${(qberAvg * 100).toFixed(2)}%`}
            s={`Threshold: ${(Number(qkdConfig?.qber_threshold || 0.11) * 100).toFixed(1)}%`}
            c={qberAvg > Number(qkdConfig?.qber_threshold || 0.11) ? "red" : "green"}
          />
          <Stat
            i={Server}
            l="Slave SAEs"
            v={`${activeSAEs}/${totalSAEs}`}
            s={`${totalDistributed.toLocaleString()} keys distributed`}
            c="purple"
          />
        </div>

        {/* ── Link Status + Key Pool Row ─────────────────── */}
        <Row2>
          <Card>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
              <Link2 size={14} style={{ color: C.accent }} />
              <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>QKD Link Status</span>
              <span style={{ marginLeft: "auto" }}>
                <Dot ok={active && serviceEnabled && etsiEnabled} />
              </span>
            </div>
            <div style={{ display: "grid", gap: 2 }}>
              <KV k="Protocol" v={String(overview?.config?.protocol || qkdConfig?.protocol || "ETSI GS QKD 014")} mono />
              <KV k="Status" v={active ? "Key streaming" : "Link down"} />
              <KV k="Source" v={String(overview?.status?.source || "-")} mono />
              <KV k="Destination" v={String(overview?.status?.destination || "-")} mono />
              <KV k="Key Rate" v={`${keyRate.toFixed(3)} keys/sec`} mono />
              <KV
                k="QBER"
                v={`${(qberAvg * 100).toFixed(2)}% (threshold: ${(Number(qkdConfig?.qber_threshold || 0.11) * 100).toFixed(1)}%)`}
                mono
              />
              <KV k="Distance" v={`${Number(qkdConfig?.distance_km || 47).toFixed(1)} km fiber`} mono />
              <KV k="Keys Today" v={`${createdToday.toLocaleString()} received`} mono />
            </div>
            <div style={{ display: "flex", gap: 6, marginTop: 10, flexWrap: "wrap" }}>
              <B c={serviceEnabled ? "green" : "red"}>{serviceEnabled ? "Service ON" : "Service OFF"}</B>
              <B c={etsiEnabled ? "blue" : "amber"}>{etsiEnabled ? "ETSI API ON" : "ETSI API OFF"}</B>
              <B c={Boolean(qkdConfig?.auto_inject) ? "green" : "amber"}>
                {Boolean(qkdConfig?.auto_inject) ? "Auto-Inject ON" : "Auto-Inject OFF"}
              </B>
            </div>
          </Card>

          <Card>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
              <Layers size={14} style={{ color: C.green }} />
              <span style={{ fontSize: 13, fontWeight: 700, color: C.text }}>Quantum Key Pool</span>
            </div>
            <div
              style={{
                fontSize: 44,
                lineHeight: 1,
                color: C.green,
                fontWeight: 700,
                letterSpacing: 1,
                textAlign: "center",
                padding: "8px 0",
              }}
            >
              {poolAvailable.toLocaleString()}
            </div>
            <div style={{ fontSize: 11, color: C.dim, textAlign: "center", marginBottom: 10 }}>
              available quantum keys
            </div>
            <Bar pct={poolPct} color={Number(overview?.pool?.low) ? C.red : C.green} />
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: C.dim, marginTop: 6 }}>
              <span>Used today: {usedToday.toLocaleString()}</span>
              <span>Pool: {poolPct.toFixed(1)}% full</span>
            </div>
            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
              <Btn small primary onClick={() => setModal("inject")} disabled={!serviceEnabled || !injectableKeys.length}>
                <Key size={11} style={{ marginRight: 4 }} />
                Inject to KeyCore
              </Btn>
              <Btn small onClick={() => setModal("keys")} disabled={!keys.length}>
                View Key Pool
              </Btn>
            </div>
          </Card>
        </Row2>

        {/* ── Protocol Info Cards ────────────────────────── */}
        <div style={{ height: 14 }} />
        <Row3>
          <Card>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
              <Globe size={13} style={{ color: C.blue }} />
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>ETSI QKD 014</span>
            </div>
            <div style={{ fontSize: 10, color: C.dim, lineHeight: 1.5 }}>
              Standard REST API for key delivery between QKD nodes. Supports
              open_connect, get_key, and close_connect operations per ETSI GS QKD 014 v1.1.1.
            </div>
            <div style={{ marginTop: 8 }}>
              <B c={etsiEnabled ? "blue" : "amber"}>{etsiEnabled ? "Enabled" : "Disabled"}</B>
            </div>
          </Card>
          <Card>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
              <Shield size={13} style={{ color: C.purple }} />
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Cisco CKM</span>
            </div>
            <div style={{ fontSize: 10, color: C.dim, lineHeight: 1.5 }}>
              Cisco Key Management integration for quantum-safe networking.
              Supports key provisioning, rotary key pools, and CKM agent enrollment.
            </div>
            <div style={{ marginTop: 8 }}>
              <B c={slaveSAEs.some((s) => s.mode === "cisco-ckm") ? "purple" : "amber"}>
                {slaveSAEs.some((s) => s.mode === "cisco-ckm") ? `${slaveSAEs.filter((s) => s.mode === "cisco-ckm").length} Agent(s)` : "No agents"}
              </B>
            </div>
          </Card>
          <Card>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
              <ArrowRightLeft size={13} style={{ color: C.accent }} />
              <span style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Key Distribution</span>
            </div>
            <div style={{ fontSize: 10, color: C.dim, lineHeight: 1.5 }}>
              Push quantum keys from the master pool to registered slave SAEs.
              Envelope-encrypted AES-256 key material distributed via secure channels.
            </div>
            <div style={{ marginTop: 8 }}>
              <B c="accent">{totalDistributed.toLocaleString()} distributed</B>
            </div>
          </Card>
        </Row3>
      </Section>

      {/* ── Slave SAE Registry ───────────────────────────── */}
      <Section
        title="Slave SAE Registry"
        actions={
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <Btn small primary onClick={openRegisterSAE}>
              <Plus size={12} style={{ marginRight: 4 }} />
              Register SAE
            </Btn>
            <Btn small primary onClick={() => openDistribute()} disabled={!slaveSAEs.length || !serviceEnabled}>
              <Send size={12} style={{ marginRight: 4 }} />
              Distribute Keys
            </Btn>
            <Btn small onClick={() => setModal("distributions")}>
              <Layers size={12} style={{ marginRight: 4 }} />
              Distributions
            </Btn>
            <button
              onClick={() => setShowSAEPanel((v) => !v)}
              style={{ background: "none", border: "none", cursor: "pointer", color: C.muted, padding: 4 }}
            >
              {showSAEPanel ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </button>
          </div>
        }
      >
        {showSAEPanel && (
          <>
            {slaveSAEs.length === 0 ? (
              <Card>
                <div style={{ textAlign: "center", padding: "20px 0" }}>
                  <Network size={32} style={{ color: C.muted, margin: "0 auto 10px" }} />
                  <div style={{ fontSize: 13, color: C.muted, marginBottom: 6 }}>No slave SAEs registered</div>
                  <div style={{ fontSize: 11, color: C.dim, marginBottom: 14 }}>
                    Register ETSI QKD nodes, Cisco CKM agents, or relay endpoints to distribute quantum keys.
                  </div>
                  <Btn small primary onClick={openRegisterSAE}>
                    <Plus size={12} style={{ marginRight: 4 }} />
                    Register First SAE
                  </Btn>
                </div>
              </Card>
            ) : (
              <Card style={{ padding: 0, overflow: "hidden" }}>
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1.4fr 0.7fr 0.7fr 0.7fr 0.9fr 0.9fr 0.6fr 100px",
                    padding: "8px 12px",
                    borderBottom: `1px solid ${C.border}`,
                    fontSize: 9,
                    color: C.muted,
                    textTransform: "uppercase",
                    letterSpacing: 1,
                  }}
                >
                  <div>Name / Endpoint</div>
                  <div>Mode</div>
                  <div>Status</div>
                  <div>Role</div>
                  <div>Keys Dist.</div>
                  <div>Keys Avail.</div>
                  <div>QBER Thr.</div>
                  <div style={{ textAlign: "right" }}>Actions</div>
                </div>
                <div style={{ maxHeight: 280, overflowY: "auto" }}>
                  {slaveSAEs.map((sae) => (
                    <div
                      key={sae.id}
                      style={{
                        display: "grid",
                        gridTemplateColumns: "1.4fr 0.7fr 0.7fr 0.7fr 0.9fr 0.9fr 0.6fr 100px",
                        padding: "8px 12px",
                        borderBottom: `1px solid ${C.border}`,
                        fontSize: 11,
                        alignItems: "center",
                      }}
                    >
                      <div>
                        <div style={{ color: C.text, fontWeight: 600 }}>{sae.name || sae.id}</div>
                        <div
                          style={{
                            fontSize: 9,
                            color: C.dim,
                            fontFamily: "'JetBrains Mono',monospace",
                            marginTop: 2,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {sae.endpoint || "-"}
                        </div>
                      </div>
                      <div><ModeBadge mode={sae.mode} /></div>
                      <div><StatusBadge status={sae.status} /></div>
                      <div style={{ color: C.dim, textTransform: "capitalize" }}>{sae.role}</div>
                      <div style={{ color: C.text, fontFamily: "'JetBrains Mono',monospace" }}>
                        {Number(sae.keys_distributed || 0).toLocaleString()}
                      </div>
                      <div style={{ color: C.green, fontFamily: "'JetBrains Mono',monospace" }}>
                        {Number(sae.keys_available || 0).toLocaleString()}
                      </div>
                      <div style={{ color: C.dim, fontFamily: "'JetBrains Mono',monospace" }}>
                        {(Number(sae.qber_threshold || 0) * 100).toFixed(1)}%
                      </div>
                      <div style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}>
                        <button
                          onClick={() => openDistribute(sae.id)}
                          title="Distribute keys"
                          style={{
                            background: C.accentDim,
                            border: `1px solid ${C.accent}33`,
                            borderRadius: 4,
                            cursor: "pointer",
                            padding: "3px 5px",
                            color: C.accent,
                          }}
                        >
                          <Send size={11} />
                        </button>
                        <button
                          onClick={() => openEditSAE(sae)}
                          title="Edit SAE"
                          style={{
                            background: C.blueDim,
                            border: `1px solid ${C.blue}33`,
                            borderRadius: 4,
                            cursor: "pointer",
                            padding: "3px 5px",
                            color: C.blue,
                          }}
                        >
                          <Pencil size={11} />
                        </button>
                        <button
                          onClick={() => handleDeleteSAE(sae)}
                          title="Delete SAE"
                          style={{
                            background: C.redDim,
                            border: `1px solid ${C.red}33`,
                            borderRadius: 4,
                            cursor: "pointer",
                            padding: "3px 5px",
                            color: C.red,
                          }}
                        >
                          <Trash2 size={11} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </Card>
            )}
          </>
        )}
      </Section>

      {/* ── QKD Logs ─────────────────────────────────────── */}
      <Section
        title="QKD Activity Log"
        actions={
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <Btn small onClick={() => void loadData(true)} disabled={refreshing}>
              {refreshing ? "Refreshing..." : "Refresh"}
            </Btn>
            <button
              onClick={() => setShowLogsPanel((v) => !v)}
              style={{ background: "none", border: "none", cursor: "pointer", color: C.muted, padding: 4 }}
            >
              {showLogsPanel ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </button>
          </div>
        }
      >
        {showLogsPanel && (
          <Card style={{ padding: 0, overflow: "hidden" }}>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "160px 140px 90px 1fr",
                padding: "8px 12px",
                borderBottom: `1px solid ${C.border}`,
                fontSize: 9,
                color: C.muted,
                textTransform: "uppercase",
                letterSpacing: 1,
              }}
            >
              <div>Timestamp</div>
              <div>Action</div>
              <div>Level</div>
              <div>Message</div>
            </div>
            <div style={{ maxHeight: 240, overflowY: "auto" }}>
              {logs.map((item) => (
                <div
                  key={item.id}
                  style={{
                    display: "grid",
                    gridTemplateColumns: "160px 140px 90px 1fr",
                    padding: "8px 12px",
                    borderBottom: `1px solid ${C.border}`,
                    fontSize: 10,
                    alignItems: "center",
                  }}
                >
                  <div style={{ color: C.dim, fontFamily: "'JetBrains Mono',monospace" }}>
                    {item.created_at ? new Date(item.created_at).toLocaleString() : "-"}
                  </div>
                  <div style={{ color: C.accent, fontFamily: "'JetBrains Mono',monospace" }}>
                    {String(item.action || "-")}
                  </div>
                  <div>
                    <B
                      c={
                        String(item.level || "info").toLowerCase() === "error"
                          ? "red"
                          : String(item.level || "info").toLowerCase() === "warn"
                            ? "amber"
                            : "blue"
                      }
                    >
                      {String(item.level || "info")}
                    </B>
                  </div>
                  <div style={{ color: C.text }}>{String(item.message || "-")}</div>
                </div>
              ))}
              {!logs.length && (
                <div style={{ padding: 16, fontSize: 11, color: C.dim, textAlign: "center" }}>
                  {loading ? "Loading QKD logs..." : "No QKD activity recorded yet."}
                </div>
              )}
            </div>
          </Card>
        )}
      </Section>

      {/* ════════════════ MODALS ════════════════════════════ */}

      {/* ── Config Modal ─────────────────────────────────── */}
      <Modal open={modal === "config"} onClose={() => setModal(null)} title="QKD Configuration" wide>
        <div style={{ fontSize: 11, color: C.dim, marginBottom: 12 }}>
          Runtime configuration for QKD service, ETSI API, key pool management, and QBER thresholds.
        </div>
        <Row2>
          <FG label="Protocol">
            <Sel
              value={String(configDraft.protocol || "ETSI GS QKD 014")}
              onChange={(e: React.ChangeEvent<HTMLSelectElement>) =>
                setConfigDraft((prev) => ({ ...prev, protocol: e.target.value }))
              }
            >
              <option value="ETSI GS QKD 014">ETSI GS QKD 014</option>
              <option value="ETSI GS QKD 004">ETSI GS QKD 004</option>
              <option value="Cisco CKM v2">Cisco CKM v2</option>
            </Sel>
          </FG>
          <FG label="Distance (km)">
            <Inp
              type="number"
              min={0}
              value={String(configDraft.distance_km)}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setConfigDraft((prev) => ({ ...prev, distance_km: Number(e.target.value || 0) }))
              }
            />
          </FG>
        </Row2>
        <Row2>
          <FG label="QBER Threshold" hint="Maximum quantum bit error rate before key discard (0-1)">
            <Inp
              type="number"
              step="0.001"
              min={0}
              max={1}
              value={String(configDraft.qber_threshold)}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setConfigDraft((prev) => ({ ...prev, qber_threshold: Number(e.target.value || 0.11) }))
              }
            />
          </FG>
          <FG label="Pool Low Threshold" hint="Alert when available keys drop below this count">
            <Inp
              type="number"
              min={1}
              value={String(configDraft.pool_low_threshold)}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setConfigDraft((prev) => ({ ...prev, pool_low_threshold: Number(e.target.value || 10) }))
              }
            />
          </FG>
        </Row2>
        <Row2>
          <FG label="Pool Capacity">
            <Inp
              type="number"
              min={1}
              value={String(configDraft.pool_capacity)}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setConfigDraft((prev) => ({ ...prev, pool_capacity: Number(e.target.value || 1250000) }))
              }
            />
          </FG>
          <FG label="Auto-Inject">
            <Chk
              label="Automatically inject accepted keys into KeyCore"
              checked={Boolean(configDraft.auto_inject)}
              onChange={() => setConfigDraft((prev) => ({ ...prev, auto_inject: !prev.auto_inject }))}
            />
          </FG>
        </Row2>
        <FG label="Service Toggles">
          <Chk
            label="Enable QKD service"
            checked={Boolean(configDraft.service_enabled)}
            onChange={() => setConfigDraft((prev) => ({ ...prev, service_enabled: !prev.service_enabled }))}
          />
          <Chk
            label="Enable ETSI QKD API endpoints"
            checked={Boolean(configDraft.etsi_api_enabled)}
            onChange={() => setConfigDraft((prev) => ({ ...prev, etsi_api_enabled: !prev.etsi_api_enabled }))}
          />
        </FG>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 14 }}>
          <Btn onClick={() => setModal(null)} disabled={savingConfig}>Cancel</Btn>
          <Btn primary onClick={() => void saveConfig()} disabled={savingConfig}>
            {savingConfig ? "Saving..." : "Save Configuration"}
          </Btn>
        </div>
      </Modal>

      {/* ── Register / Edit SAE Modal ────────────────────── */}
      <Modal
        open={modal === "register-sae" || modal === "edit-sae"}
        onClose={() => setModal(null)}
        title={modal === "edit-sae" ? `Edit SAE: ${selectedSAE?.name || ""}` : "Register Slave SAE"}
        wide
      >
        <div style={{ fontSize: 11, color: C.dim, marginBottom: 12 }}>
          {modal === "edit-sae"
            ? "Update the configuration for this slave SAE endpoint."
            : "Register a new ETSI QKD node, Cisco CKM agent, or relay endpoint for key distribution."}
        </div>
        <Row2>
          <FG label="SAE Name" required>
            <Inp
              value={saeDraft.name}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setSaeDraft((prev) => ({ ...prev, name: e.target.value }))
              }
              placeholder="e.g. Branch-Office-QKD-1"
            />
          </FG>
          <FG label="Endpoint URL" required>
            <Inp
              value={saeDraft.endpoint || ""}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setSaeDraft((prev) => ({ ...prev, endpoint: e.target.value }))
              }
              placeholder="https://sae.example.com:8443/api/v1"
              mono
            />
          </FG>
        </Row2>
        <Row3>
          <FG label="Mode">
            <Sel
              value={saeDraft.mode || "etsi"}
              onChange={(e: React.ChangeEvent<HTMLSelectElement>) =>
                setSaeDraft((prev) => ({ ...prev, mode: e.target.value }))
              }
            >
              <option value="etsi">ETSI QKD</option>
              <option value="cisco-ckm">Cisco CKM</option>
              <option value="relay">Relay</option>
            </Sel>
          </FG>
          <FG label="Role">
            <Sel
              value={saeDraft.role || "consumer"}
              onChange={(e: React.ChangeEvent<HTMLSelectElement>) =>
                setSaeDraft((prev) => ({ ...prev, role: e.target.value }))
              }
            >
              <option value="consumer">Consumer</option>
              <option value="provider">Provider</option>
              <option value="peer">Peer</option>
            </Sel>
          </FG>
          <FG label="Protocol">
            <Sel
              value={saeDraft.protocol || "ETSI GS QKD 014"}
              onChange={(e: React.ChangeEvent<HTMLSelectElement>) =>
                setSaeDraft((prev) => ({ ...prev, protocol: e.target.value }))
              }
            >
              <option value="ETSI GS QKD 014">ETSI GS QKD 014</option>
              <option value="ETSI GS QKD 004">ETSI GS QKD 004</option>
              <option value="Cisco CKM v2">Cisco CKM v2</option>
            </Sel>
          </FG>
        </Row3>
        <Row2>
          <FG label="Max Key Rate (keys/sec)">
            <Inp
              type="number"
              min={0}
              step="0.001"
              value={String(saeDraft.max_key_rate || 0)}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setSaeDraft((prev) => ({ ...prev, max_key_rate: Number(e.target.value || 0) }))
              }
            />
          </FG>
          <FG label="QBER Threshold">
            <Inp
              type="number"
              min={0}
              max={1}
              step="0.001"
              value={String(saeDraft.qber_threshold || 0.11)}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setSaeDraft((prev) => ({ ...prev, qber_threshold: Number(e.target.value || 0.11) }))
              }
            />
          </FG>
        </Row2>
        <FG label="Auth Token" hint={modal === "edit-sae" ? "Leave blank to keep existing token" : "Bearer token for SAE API authentication"}>
          <Inp
            value={saeDraft.auth_token || ""}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setSaeDraft((prev) => ({ ...prev, auth_token: e.target.value }))
            }
            placeholder={modal === "edit-sae" ? "(unchanged)" : "Bearer token or API key"}
            type="password"
          />
        </FG>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 14 }}>
          <Btn onClick={() => setModal(null)} disabled={savingSAE}>Cancel</Btn>
          <Btn primary onClick={() => void handleSaveSAE()} disabled={savingSAE || !saeDraft.name.trim()}>
            {savingSAE ? "Saving..." : modal === "edit-sae" ? "Update SAE" : "Register SAE"}
          </Btn>
        </div>
      </Modal>

      {/* ── Distribute Keys Modal ────────────────────────── */}
      <Modal open={modal === "distribute"} onClose={() => setModal(null)} title="Distribute Keys to Slave SAE">
        <div style={{ fontSize: 11, color: C.dim, marginBottom: 12 }}>
          Push quantum keys from the master pool to the selected slave SAE. Keys are envelope-encrypted
          during transit and marked as consumed in the local pool.
        </div>
        <FG label="Target Slave SAE" required>
          <Sel
            value={distSAEId}
            onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setDistSAEId(e.target.value)}
          >
            {slaveSAEs.map((sae) => (
              <option key={sae.id} value={sae.id}>
                {sae.name} ({sae.mode}) - {sae.status}
              </option>
            ))}
            {!slaveSAEs.length && <option value="">No SAEs registered</option>}
          </Sel>
        </FG>
        <Row2>
          <FG label="Key Count" hint="Number of quantum keys to distribute">
            <Inp
              type="number"
              min={1}
              max={1000}
              value={distCount}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setDistCount(e.target.value)}
            />
          </FG>
          <FG label="Key Size (bits)">
            <Sel value={distKeyBits} onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setDistKeyBits(e.target.value)}>
              <option value="128">128-bit</option>
              <option value="256">256-bit (AES-256)</option>
              <option value="512">512-bit</option>
            </Sel>
          </FG>
        </Row2>
        <Card style={{ background: C.accentDim, border: `1px solid ${C.accent}22`, marginTop: 4 }}>
          <div style={{ fontSize: 10, color: C.accent }}>
            Available in pool: <strong>{poolAvailable.toLocaleString()}</strong> keys.
            {Number(distCount || 0) > poolAvailable && (
              <span style={{ color: C.red, marginLeft: 8 }}>
                Not enough keys available.
              </span>
            )}
          </div>
        </Card>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 14 }}>
          <Btn onClick={() => setModal(null)} disabled={distributing}>Cancel</Btn>
          <Btn
            primary
            onClick={() => void handleDistribute()}
            disabled={distributing || !distSAEId || Number(distCount || 0) > poolAvailable}
          >
            {distributing ? "Distributing..." : "Distribute Keys"}
          </Btn>
        </div>
      </Modal>

      {/* ── Distributions History Modal ──────────────────── */}
      <Modal open={modal === "distributions"} onClose={() => setModal(null)} title="Key Distribution History" wide>
        <Card style={{ padding: 0, overflow: "hidden" }}>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1.2fr 1fr 0.6fr 0.6fr 0.7fr 1fr",
              padding: "8px 12px",
              borderBottom: `1px solid ${C.border}`,
              fontSize: 9,
              color: C.muted,
              textTransform: "uppercase",
              letterSpacing: 1,
            }}
          >
            <div>Distribution ID</div>
            <div>Slave SAE</div>
            <div>Keys</div>
            <div>Bits</div>
            <div>Status</div>
            <div>Distributed At</div>
          </div>
          <div style={{ maxHeight: 340, overflowY: "auto" }}>
            {distributions.map((d) => (
              <div
                key={d.id}
                style={{
                  display: "grid",
                  gridTemplateColumns: "1.2fr 1fr 0.6fr 0.6fr 0.7fr 1fr",
                  padding: "8px 12px",
                  borderBottom: `1px solid ${C.border}`,
                  fontSize: 10,
                  alignItems: "center",
                }}
              >
                <div style={{ color: C.text, fontFamily: "'JetBrains Mono',monospace" }}>{d.id}</div>
                <div style={{ color: C.dim, fontFamily: "'JetBrains Mono',monospace" }}>
                  {slaveSAEs.find((s) => s.id === d.slave_sae_id)?.name || d.slave_sae_id}
                </div>
                <div style={{ color: C.text }}>{d.key_count}</div>
                <div style={{ color: C.dim }}>{d.key_size_bits}</div>
                <div>
                  <B c={d.status === "completed" ? "green" : d.status === "failed" ? "red" : "amber"}>
                    {d.status}
                  </B>
                </div>
                <div style={{ color: C.dim, fontFamily: "'JetBrains Mono',monospace" }}>
                  {d.distributed_at ? new Date(d.distributed_at).toLocaleString() : "-"}
                </div>
              </div>
            ))}
            {!distributions.length && (
              <div style={{ padding: 16, fontSize: 11, color: C.dim, textAlign: "center" }}>
                No key distributions recorded yet.
              </div>
            )}
          </div>
        </Card>
        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10 }}>
          <Btn onClick={() => setModal(null)}>Close</Btn>
        </div>
      </Modal>

      {/* ── Inject Key Modal ─────────────────────────────── */}
      <Modal open={modal === "inject"} onClose={() => setModal(null)} title="Inject QKD Key into KeyCore">
        <div style={{ fontSize: 11, color: C.dim, marginBottom: 12 }}>
          Promote a quantum-derived key from the QKD pool into KeyCore as an AES-256 encryption key.
        </div>
        <FG label="QKD Key ID" required>
          <Sel value={selectedKeyID} onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setSelectedKeyID(e.target.value)}>
            {injectableKeys.map((k) => (
              <option key={k.id} value={k.id}>
                {k.id} ({k.status}, {k.key_size_bits}b, QBER: {(k.qber * 100).toFixed(2)}%)
              </option>
            ))}
            {!injectableKeys.length && <option value="">No injectable keys in pool</option>}
          </Sel>
        </FG>
        <Row2>
          <FG label="Purpose">
            <Sel value={injectPurpose} onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setInjectPurpose(e.target.value)}>
              <option value="encrypt">Encrypt</option>
              <option value="decrypt">Decrypt</option>
              <option value="wrap">Key Wrap</option>
              <option value="sign">Sign</option>
            </Sel>
          </FG>
          <FG label="Options">
            <Chk label="Consume key after injection" checked={injectConsume} onChange={() => setInjectConsume((v) => !v)} />
          </FG>
        </Row2>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 14 }}>
          <Btn onClick={() => setModal(null)} disabled={injecting}>Cancel</Btn>
          <Btn primary onClick={() => void injectSelected()} disabled={injecting || !selectedKeyID}>
            {injecting ? "Injecting..." : "Inject Key"}
          </Btn>
        </div>
      </Modal>

      {/* ── Key Pool + Self-Test Modal ───────────────────── */}
      <Modal
        open={modal === "keys"}
        onClose={() => setModal(null)}
        title={`QKD Key Pool${activeSlave ? ` — ${activeSlave}` : ""}`}
        wide
      >
        <FG label="Self-Test Key Generator" hint="Generate cryptographically random test keys via ETSI key receive path.">
          <Row2>
            <Inp
              value={slaveSAEID}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSlaveSAEID(e.target.value)}
              placeholder="slave_sae_id"
              mono
            />
            <div style={{ display: "flex", gap: 6 }}>
              <Inp
                type="number"
                min={1}
                max={500}
                value={testCount}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setTestCount(e.target.value)}
                placeholder="Count"
              />
              <Inp
                type="number"
                min={128}
                max={4096}
                step={8}
                value={testKeyBits}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setTestKeyBits(e.target.value)}
                placeholder="Bits"
              />
            </div>
          </Row2>
          <Row3>
            <Inp
              type="number"
              step="0.0001"
              min={0}
              max={1}
              value={testQberMin}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setTestQberMin(e.target.value)}
              placeholder="QBER min"
            />
            <Inp
              type="number"
              step="0.0001"
              min={0}
              max={1}
              value={testQberMax}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setTestQberMax(e.target.value)}
              placeholder="QBER max"
            />
            <Btn primary onClick={() => void runSelfTest()} disabled={runningTest || !serviceEnabled}>
              {runningTest ? "Generating..." : "Run Test"}
            </Btn>
          </Row3>
        </FG>
        <Card style={{ padding: 0, overflow: "hidden" }}>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1.5fr 0.7fr 0.6fr 0.5fr 0.9fr",
              padding: "8px 12px",
              borderBottom: `1px solid ${C.border}`,
              fontSize: 9,
              color: C.muted,
              textTransform: "uppercase",
              letterSpacing: 1,
            }}
          >
            <div>Key ID</div>
            <div>Status</div>
            <div>QBER</div>
            <div>Bits</div>
            <div>Created</div>
          </div>
          <div style={{ maxHeight: 300, overflowY: "auto" }}>
            {keys.map((k) => (
              <div
                key={k.id}
                style={{
                  display: "grid",
                  gridTemplateColumns: "1.5fr 0.7fr 0.6fr 0.5fr 0.9fr",
                  padding: "8px 12px",
                  borderBottom: `1px solid ${C.border}`,
                  fontSize: 10,
                  alignItems: "center",
                }}
              >
                <div style={{ color: C.text, fontFamily: "'JetBrains Mono',monospace" }}>{k.id}</div>
                <div>
                  <B c={k.status === "available" ? "green" : k.status === "discarded" ? "red" : "blue"}>
                    {k.status}
                  </B>
                </div>
                <div style={{ color: C.dim, fontFamily: "'JetBrains Mono',monospace" }}>
                  {(k.qber * 100).toFixed(3)}%
                </div>
                <div style={{ color: C.dim }}>{k.key_size_bits}</div>
                <div style={{ color: C.dim, fontFamily: "'JetBrains Mono',monospace" }}>
                  {k.created_at ? new Date(k.created_at).toLocaleString() : "-"}
                </div>
              </div>
            ))}
            {!keys.length && (
              <div style={{ padding: 16, fontSize: 11, color: C.dim, textAlign: "center" }}>
                No QKD keys in pool. Run a self-test to generate test keys.
              </div>
            )}
          </div>
        </Card>
        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10 }}>
          <Btn onClick={() => setModal(null)}>Close</Btn>
        </div>
      </Modal>
    </div>
  );
};
