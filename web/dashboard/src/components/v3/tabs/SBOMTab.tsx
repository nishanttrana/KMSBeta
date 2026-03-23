// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { type ReactNode, useEffect, useMemo, useState } from "react";
import { AlertTriangle, Atom, Ban, Package, RefreshCcw, ShieldCheck } from "lucide-react";
import {
  AreaChart, Area, BarChart, Bar as RBar, PieChart, Pie, Cell,
  RadialBarChart, RadialBar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend
} from "recharts";
import { B, Btn, Card, Inp, Modal, Row3, Section, Sel, Stat, Tabs } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  deleteSBOMAdvisory,
  diffCBOM,
  diffSBOM,
  exportCBOM,
  exportSBOM,
  generateCBOM,
  generateSBOM,
  getCBOMPQCReadiness,
  getCBOMSummary,
  getLatestCBOM,
  getLatestSBOM,
  listSBOMAdvisories,
  listCBOMHistory,
  listSBOMHistory,
  listSBOMVulnerabilities,
  saveSBOMAdvisory
} from "../../../lib/sbom";

const ChartTip = ({ children }: { children: ReactNode }) => (
  <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, padding: "6px 10px", fontSize: 10, color: C.text }}>
    {children}
  </div>
);

const ALGO_COLORS: Record<string, string> = { AES: C.cyan, RSA: C.blue, ECDSA: C.purple, PQC: C.green, Other: C.yellow };

export const SBOMTab = ({ session, onToast }: any) => {
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [exportingSBOM, setExportingSBOM] = useState("");
  const [exportingCBOM, setExportingCBOM] = useState(false);
  const [sbomLatest, setSBOMLatest] = useState<any>(null);
  const [sbomHistory, setSBOMHistory] = useState<any[]>([]);
  const [sbomVulns, setSBOMVulns] = useState<any[]>([]);
  const [cbomLatest, setCBOMLatest] = useState<any>(null);
  const [cbomSummary, setCBOMSummary] = useState<any>({});
  const [cbomHistory, setCBOMHistory] = useState<any[]>([]);
  const [pqcReadiness, setPQCReadiness] = useState<any>(null);
  const [activeSBOMFormat, setActiveSBOMFormat] = useState("cyclonedx");
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const [selectedDepCategory, setSelectedDepCategory] = useState("");
  const [depListOpen, setDepListOpen] = useState(false);
  const [depListTitle, setDepListTitle] = useState("");
  const [depListItems, setDepListItems] = useState<any[]>([]);
  const [depListFilter, setDepListFilter] = useState("");
  const [selectedCBOMCategory, setSelectedCBOMCategory] = useState("");
  const [cbomAssetListOpen, setCBOMAssetListOpen] = useState(false);
  const [cbomAssetListTitle, setCBOMAssetListTitle] = useState("");
  const [cbomAssetListItems, setCBOMAssetListItems] = useState<any[]>([]);
  const [cbomAssetListFilter, setCBOMAssetListFilter] = useState("");
  const [diffOpen, setDiffOpen] = useState(false);
  const [diffData, setDiffData] = useState<any>(null);
  const [sbomDiffOpen, setSBOMDiffOpen] = useState(false);
  const [sbomDiffData, setSBOMDiffData] = useState<any>(null);
  const [tab, setTab] = useState("Overview");
  const [vulnSevFilter, setVulnSevFilter] = useState("all");
  const [vulnSearch, setVulnSearch] = useState("");
  const [componentSearch, setComponentSearch] = useState("");
  const [componentCategoryFilter, setComponentCategoryFilter] = useState("all");
  const [manualAdvisories, setManualAdvisories] = useState<any[]>([]);
  const [vulnLoading, setVulnLoading] = useState(false);
  const [vulnLoaded, setVulnLoaded] = useState(false);
  const [vulnAttempted, setVulnAttempted] = useState(false);
  const [advisoryModalOpen, setAdvisoryModalOpen] = useState(false);
  const [savingAdvisory, setSavingAdvisory] = useState(false);
  const [deletingAdvisory, setDeletingAdvisory] = useState("");
  const [advisoryForm, setAdvisoryForm] = useState<any>({
    id: "",
    component: "",
    ecosystem: "go",
    introduced_version: "",
    fixed_version: "",
    severity: "high",
    summary: "",
    reference: ""
  });

  // ── Download helpers ──────────────────────────────────────────
  const downloadTextFile = (filename: string, content: string, mime = "application/json") => {
    const blob = new Blob([String(content || "")], { type: mime });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = String(filename || "download.txt");
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const downloadBase64File = (filename: string, b64: string, mime = "application/octet-stream") => {
    try {
      const bin = atob(String(b64 || ""));
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
      const blob = new Blob([bytes], { type: mime });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = String(filename || "download.bin");
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch {
      onToast?.("Export download failed: invalid base64 payload.");
    }
  };

  // ── Data loading ──────────────────────────────────────────────
  const loadData = async (opts: any = {}) => {
    if (!session?.token) {
      setSBOMLatest(null); setSBOMHistory([]); setSBOMVulns([]);
      setCBOMLatest(null); setCBOMSummary({}); setCBOMHistory([]);
      setManualAdvisories([]);
      setPQCReadiness(null);
      setVulnLoading(false);
      setVulnLoaded(false);
      setVulnAttempted(false);
      return;
    }
    const doRefresh = Boolean(opts?.refresh);
    if (doRefresh) setRefreshing(true);
    else if (!opts?.silent) setLoading(true);
    try {
      if (doRefresh) {
        await Promise.all([generateSBOM(session, "manual"), generateCBOM(session, "manual")]);
      }
      const [sbomOut, sbomHistoryOut, advisoryOut, cbomOut, summaryOut, historyOut, pqcOut] = await Promise.all([
        getLatestSBOM(session),
        listSBOMHistory(session, 12),
        listSBOMAdvisories(session).catch(() => []),
        getLatestCBOM(session),
        getCBOMSummary(session),
        listCBOMHistory(session, 8),
        getCBOMPQCReadiness(session).catch(() => null)
      ]);
      setSBOMLatest(sbomOut || null);
      setSBOMHistory(Array.isArray(sbomHistoryOut) ? sbomHistoryOut : []);
      setManualAdvisories(Array.isArray(advisoryOut) ? advisoryOut : []);
      setCBOMLatest(cbomOut || null);
      setCBOMSummary(summaryOut || {});
      setCBOMHistory(Array.isArray(historyOut) ? historyOut : []);
      setPQCReadiness(pqcOut || null);
      if (doRefresh) {
        onToast?.("SBOM and CBOM refreshed. Vulnerability findings are updating in the background.");
      }
    } catch (error) {
      onToast?.(`SBOM/CBOM load failed: ${errMsg(error)}`);
    } finally {
      if (doRefresh) setRefreshing(false);
      else if (!opts?.silent) setLoading(false);
    }
  };

  const loadVulnerabilities = async (opts: any = {}) => {
    if (!session?.token) {
      setSBOMVulns([]);
      setVulnLoading(false);
      setVulnLoaded(false);
      setVulnAttempted(false);
      return;
    }
    if (vulnLoading && !opts?.force) return;
    setVulnAttempted(true);
    setVulnLoading(true);
    try {
      const out = await listSBOMVulnerabilities(session);
      setSBOMVulns(Array.isArray(out) ? out : []);
      setVulnLoaded(true);
      if (opts?.notify) onToast?.("Vulnerability findings updated.");
    } catch (error) {
      if (!opts?.suppressToast) onToast?.(`Vulnerability scan failed: ${errMsg(error)}`);
    } finally {
      setVulnLoading(false);
    }
  };

  const resetAdvisoryForm = () => setAdvisoryForm({
    id: "",
    component: "",
    ecosystem: "go",
    introduced_version: "",
    fixed_version: "",
    severity: "high",
    summary: "",
    reference: ""
  });

  const saveOfflineAdvisory = async () => {
    if (!session?.token) { onToast?.("Login is required."); return; }
    setSavingAdvisory(true);
    try {
      await saveSBOMAdvisory(session, advisoryForm);
      await loadData({ silent: true });
      void loadVulnerabilities({ force: true, suppressToast: true });
      resetAdvisoryForm();
      setAdvisoryModalOpen(false);
      onToast?.("Offline advisory saved.");
    } catch (error) {
      onToast?.(`Offline advisory save failed: ${errMsg(error)}`);
    } finally {
      setSavingAdvisory(false);
    }
  };

  const removeOfflineAdvisory = async (id: string) => {
    if (!session?.token || !id) return;
    if (!window.confirm(`Delete advisory ${id}?`)) return;
    setDeletingAdvisory(id);
    try {
      await deleteSBOMAdvisory(session, id);
      await loadData({ silent: true });
      void loadVulnerabilities({ force: true, suppressToast: true });
      onToast?.(`Advisory ${id} deleted.`);
    } catch (error) {
      onToast?.(`Delete advisory failed: ${errMsg(error)}`);
    } finally {
      setDeletingAdvisory("");
    }
  };

  useEffect(() => {
    setSBOMVulns([]);
    setVulnLoading(false);
    setVulnLoaded(false);
    setVulnAttempted(false);
    void loadData({ silent: true });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session?.token, session?.tenantId]);

  useEffect(() => {
    if (!session?.token || tab !== "Vulnerabilities" || vulnLoaded || vulnLoading || vulnAttempted) return;
    void loadVulnerabilities({ suppressToast: true });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, session?.token, session?.tenantId, vulnLoaded, vulnLoading, vulnAttempted]);

  // ── Export functions ──────────────────────────────────────────
  const exportSBOMFile = async (format: string) => {
    if (!session?.token) { onToast?.("Login is required."); return; }
    const snapshotID = String(sbomLatest?.id || "").trim();
    if (!snapshotID) { onToast?.("SBOM snapshot is not ready. Refresh BOM first."); return; }
    setActiveSBOMFormat(format);
    setExportingSBOM(format);
    try {
      const encoding = format === "cyclonedx" ? "json" : "json";
      const artifact = await exportSBOM(session, snapshotID, format as any, encoding);
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      if (String(artifact?.encoding || "").toLowerCase() === "base64") {
        const ext = format === "pdf" ? "pdf" : "bin";
        downloadBase64File(`vecta-sbom-${format}-${stamp}.${ext}`, artifact?.content || "", String(artifact?.content_type || "application/octet-stream"));
      } else {
        const ext = format === "spdx" ? "spdx.json" : format === "cyclonedx" ? "cyclonedx.json" : "txt";
        const mime = String(artifact?.content_type || "application/json");
        downloadTextFile(`vecta-sbom-${format}-${stamp}.${ext}`, artifact?.content || "", mime);
      }
      onToast?.(`SBOM exported as ${format.toUpperCase()}.`);
    } catch (error) {
      onToast?.(`SBOM export failed: ${errMsg(error)}`);
    } finally {
      setExportingSBOM("");
    }
  };

  const exportSBOMCSV = () => {
    const list = Array.isArray(sbomLatest?.document?.components) ? sbomLatest.document.components : [];
    if (!list.length) { onToast?.("SBOM snapshot is not ready. Refresh BOM first."); return; }
    try {
      setExportingSBOM("csv");
      const esc = (v: any) => `"${String(v ?? "").replace(/"/g, '""')}"`;
      const rows = [
        ["name", "version", "type", "ecosystem", "supplier"],
        ...list.map((item: any) => [String(item?.name || ""), String(item?.version || ""), String(item?.type || ""), String(item?.ecosystem || ""), String(item?.supplier || "")])
      ];
      const csv = rows.map((row: any[]) => row.map((v: any) => esc(v)).join(",")).join("\n");
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      downloadTextFile(`vecta-sbom-csv-${stamp}.csv`, csv, "text/csv;charset=utf-8");
      onToast?.("SBOM exported as CSV.");
    } catch (error) {
      onToast?.(`SBOM CSV export failed: ${errMsg(error)}`);
    } finally {
      setExportingSBOM("");
    }
  };

  const exportCBOMFile = async () => {
    if (!session?.token) { onToast?.("Login is required."); return; }
    const snapshotID = String(cbomLatest?.id || "").trim();
    if (!snapshotID) { onToast?.("CBOM snapshot is not ready. Refresh BOM first."); return; }
    setExportingCBOM(true);
    try {
      const artifact = await exportCBOM(session, snapshotID, "cyclonedx");
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      if (String(artifact?.encoding || "").toLowerCase() === "base64") {
        downloadBase64File(`vecta-cbom-${stamp}.pdf`, artifact?.content || "", String(artifact?.content_type || "application/pdf"));
      } else {
        downloadTextFile(`vecta-cbom-${stamp}.json`, artifact?.content || "", String(artifact?.content_type || "application/json"));
      }
      onToast?.("CBOM exported.");
    } catch (error) {
      onToast?.(`CBOM export failed: ${errMsg(error)}`);
    } finally {
      setExportingCBOM(false);
    }
  };

  // ── CBOM Diff ─────────────────────────────────────────────────
  const openCBOMDiff = async () => {
    if (!session?.token) { onToast?.("Login is required."); return; }
    const history = Array.isArray(cbomHistory) ? [...cbomHistory] : [];
    history.sort((a: any, b: any) => new Date(String(b?.created_at || 0)).getTime() - new Date(String(a?.created_at || 0)).getTime());
    if (history.length < 2) { onToast?.("Need at least two CBOM snapshots for diff. Click Refresh BOM again."); return; }
    try {
      const out = await diffCBOM(session, String(history[1]?.id || ""), String(history[0]?.id || ""));
      setDiffData(out || null);
      setDiffOpen(true);
    } catch (error) {
      onToast?.(`CBOM diff failed: ${errMsg(error)}`);
    }
  };

  // ── SBOM Diff ─────────────────────────────────────────────────
  const openSBOMDiff = async () => {
    if (!session?.token) { onToast?.("Login is required."); return; }
    const history = Array.isArray(sbomHistory) ? [...sbomHistory] : [];
    history.sort((a: any, b: any) => new Date(String(b?.created_at || 0)).getTime() - new Date(String(a?.created_at || 0)).getTime());
    if (history.length < 2) { onToast?.("Need at least two SBOM snapshots for diff. Click Refresh BOM again."); return; }
    try {
      const out = await diffSBOM(session, String(history[1]?.id || ""), String(history[0]?.id || ""));
      setSBOMDiffData(out || null);
      setSBOMDiffOpen(true);
    } catch (error) {
      onToast?.(`SBOM diff failed: ${errMsg(error)}`);
    }
  };

  // ── Computed data ─────────────────────────────────────────────
  const components = Array.isArray(sbomLatest?.document?.components) ? sbomLatest.document.components : [];
  const vulnerabilities = Array.isArray(sbomVulns) ? sbomVulns : [];
  const vulnerabilitySources = useMemo(() => {
    const counts: Record<string, number> = {};
    vulnerabilities.forEach((item: any) => {
      const raw = String(item?.source || "unknown").trim() || "unknown";
      raw.split(",").map((part) => part.trim()).filter(Boolean).forEach((key) => {
        counts[key] = Number(counts[key] || 0) + 1;
      });
    });
    return counts;
  }, [vulnerabilities]);

  const severityRank = (sev: string) => {
    const n = String(sev || "").toLowerCase();
    if (n === "critical") return 5;
    if (n === "high") return 4;
    if (n === "medium") return 3;
    if (n === "low") return 2;
    return 1;
  };

  const componentVulnStats = useMemo(() => {
    const out: any = {};
    vulnerabilities.forEach((item: any) => {
      const key = String(item?.component || "").trim().toLowerCase();
      if (!key) return;
      if (!out[key]) out[key] = { count: 0, top: "none", rank: 0 };
      out[key].count += 1;
      const rank = severityRank(String(item?.severity || ""));
      if (rank > Number(out[key].rank || 0)) { out[key].rank = rank; out[key].top = String(item?.severity || "none").toLowerCase(); }
    });
    return out;
  }, [vulnerabilities]);

  const goComponents = components.filter((c: any) => String(c?.type || "").toLowerCase() === "library" && String(c?.ecosystem || "").toLowerCase() === "go");
  const containerComponents = components.filter((c: any) => String(c?.type || "").toLowerCase() === "container");
  const systemComponents = components.filter((c: any) => ["runtime", "infrastructure", "os-pkg"].includes(String(c?.type || "").toLowerCase()));

  const normalizeComponentKey = (name: any, version?: any) => {
    const base = String(name || "").trim().toLowerCase();
    const ver = String(version || "").trim().toLowerCase();
    if (!base) return "";
    return ver ? `${base}@${ver}` : base;
  };

  const vulnerableComponentKeys = useMemo(() => {
    const keys = new Set<string>();
    vulnerabilities.forEach((item: any) => {
      const nameKey = normalizeComponentKey(item?.component);
      const versionKey = normalizeComponentKey(item?.component, item?.installed_version);
      if (nameKey) keys.add(nameKey);
      if (versionKey) keys.add(versionKey);
    });
    return keys;
  }, [vulnerabilities]);

  const isVulnerableComponent = (component: any) => {
    const versionKey = normalizeComponentKey(component?.name, component?.version);
    const nameKey = normalizeComponentKey(component?.name);
    return vulnerableComponentKeys.has(versionKey) || vulnerableComponentKeys.has(nameKey);
  };

  const vulnerableComponentCount = components.filter((component: any) => isVulnerableComponent(component)).length;
  const hasVulnerabilityCoverage = vulnLoaded;
  const healthyComponentCount = hasVulnerabilityCoverage ? Math.max(0, components.length - vulnerableComponentCount) : 0;
  const dependencyHealthPct = hasVulnerabilityCoverage && components.length > 0 ? Math.round((healthyComponentCount / components.length) * 100) : 0;
  const dependencyHealthTone = !hasVulnerabilityCoverage ? "dim" : dependencyHealthPct >= 90 ? "green" : dependencyHealthPct >= 70 ? "amber" : "red";
  const dependencyHealthColor = dependencyHealthTone === "green" ? C.green : dependencyHealthTone === "amber" ? C.amber : C.red;
  const dependencyHealthGaugeData = [{ name: "Dependency health", value: dependencyHealthPct, fill: hasVulnerabilityCoverage ? dependencyHealthColor : C.dim }];

  const categorySeverity = (names: string[]) => {
    if (!hasVulnerabilityCoverage) return { label: vulnLoading ? "Scanning" : "Pending", tone: "dim" };
    const set = new Set(names.map((n) => String(n || "").trim().toLowerCase()).filter(Boolean));
    const items = vulnerabilities.filter((v: any) => set.has(String(v?.component || "").trim().toLowerCase()));
    if (!items.length) return { label: "0 CVEs", tone: "green" };
    const stats = { critical: 0, high: 0, medium: 0, low: 0, other: 0 };
    items.forEach((v: any) => {
      const sev = String(v?.severity || "").toLowerCase();
      if (sev === "critical") stats.critical += 1;
      else if (sev === "high") stats.high += 1;
      else if (sev === "medium") stats.medium += 1;
      else if (sev === "low") stats.low += 1;
      else stats.other += 1;
    });
    if (stats.critical > 0) return { label: `${stats.critical} critical`, tone: "red" };
    if (stats.high > 0) return { label: `${stats.high} high`, tone: "red" };
    if (stats.medium > 0) return { label: `${stats.medium} medium`, tone: "amber" };
    if (stats.low > 0) return { label: `${stats.low} low`, tone: "amber" };
    return { label: `${items.length} CVEs`, tone: "blue" };
  };

  const sbomRows = [
    { label: "Go modules", count: goComponents.length, names: goComponents.map((c: any) => String(c?.name || "")), components: goComponents },
    { label: "Containers", count: containerComponents.length, names: containerComponents.map((c: any) => String(c?.name || "")), components: containerComponents },
    { label: "System pkgs", count: systemComponents.length, names: systemComponents.map((c: any) => String(c?.name || "")), components: systemComponents }
  ].map((row) => ({ ...row, sev: categorySeverity(row.names) }));

  const openDependencyList = (row: any) => {
    setSelectedDepCategory(String(row?.label || ""));
    setDepListTitle(String(row?.label || "Dependencies"));
    setDepListFilter("");
    setDepListItems(Array.isArray(row?.components) ? [...row.components] : []);
    setDepListOpen(true);
  };

  const sbomTrend = useMemo(() => {
    const items = Array.isArray(sbomHistory) ? [...sbomHistory] : [];
    items.sort((a: any, b: any) => {
      const ta = new Date(String(a?.created_at || a?.document?.generated_at || 0)).getTime();
      const tb = new Date(String(b?.created_at || b?.document?.generated_at || 0)).getTime();
      return ta - tb;
    });
    return items.slice(-10).map((item: any) => {
      const docs = Array.isArray(item?.document?.components) ? item.document.components : [];
      const go = docs.filter((c: any) => String(c?.type || "").toLowerCase() === "library" && String(c?.ecosystem || "").toLowerCase() === "go").length;
      const containers = docs.filter((c: any) => String(c?.type || "").toLowerCase() === "container").length;
      const sys = docs.filter((c: any) => ["runtime", "infrastructure", "os-pkg"].includes(String(c?.type || "").toLowerCase())).length;
      return {
        label: new Date(String(item?.created_at || item?.document?.generated_at || Date.now())).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
        total: docs.length, go, containers, system: sys
      };
    });
  }, [sbomHistory]);

  const filteredDepList = depListItems.filter((item: any) => {
    const q = String(depListFilter || "").trim().toLowerCase();
    if (!q) return true;
    return [item?.name, item?.version, item?.type, item?.ecosystem].map((v) => String(v ?? "").toLowerCase()).join(" ").includes(q);
  });

  // ── CBOM computed data ────────────────────────────────────────
  const rawDist = cbomSummary?.algorithm_distribution || cbomLatest?.document?.algorithm_distribution || {};
  const grouped = { AES: 0, RSA: 0, ECDSA: 0, PQC: 0, Other: 0 };
  Object.entries(rawDist || {}).forEach(([alg, val]) => {
    const count = Math.max(0, Number(val || 0));
    const upper = String(alg || "").toUpperCase();
    if (upper.includes("AES")) { grouped.AES += count; return; }
    if (upper.includes("RSA")) { grouped.RSA += count; return; }
    if (upper.includes("ECDSA") || upper.includes("EDDSA") || upper.includes("ECDH")) { grouped.ECDSA += count; return; }
    if (upper.includes("ML-") || upper.includes("SLH") || upper.includes("XMSS") || upper.includes("KYBER") || upper.includes("DILITHIUM") || upper.includes("FALCON")) { grouped.PQC += count; return; }
    grouped.Other += count;
  });

  const distItems = Object.entries(grouped).filter(([, v]) => v > 0).map(([label, value]) => ({ name: label, value, fill: ALGO_COLORS[label] || C.yellow }));
  const totalAssets = Math.max(0, Number(cbomSummary?.total_assets ?? cbomLatest?.document?.total_asset_count ?? 0));
  const cbomAssets = Array.isArray(cbomLatest?.document?.assets) ? cbomLatest.document.assets : [];

  const isHSMBackedAsset = (asset: any) => {
    const metadata = (asset && typeof asset.metadata === "object" && asset.metadata) ? asset.metadata : {};
    const sourceBlob = [asset?.source, asset?.status, asset?.asset_type, asset?.name, asset?.algorithm, metadata?.storage, metadata?.provider, metadata?.backend, metadata?.key_store, metadata?.kek_mode, metadata?.origin, metadata?.hsm, metadata?.hsm_backed, metadata?.location].map((v) => String(v ?? "")).join(" ").toLowerCase();
    if (metadata?.hsm_backed === true) return true;
    if (String(metadata?.storage || "").toLowerCase() === "hsm") return true;
    return /\bhsm\b|pkcs11|cloudhsm|luna|thales|utimaco|hsm-backed/.test(sourceBlob);
  };

  const isWeakLegacyAsset = (asset: any) => {
    const alg = String(asset?.algorithm || "").toUpperCase();
    const status = String(asset?.status || "").toLowerCase();
    const bits = Number(asset?.strength_bits || 0);
    if (bits > 0 && bits < 128) return true;
    if (/\bDES\b|\b3DES\b|RC2|RC4|MD5|SHA1|RSA-1024|DSA-1024/.test(alg)) return true;
    if (status.includes("weak") || status.includes("legacy") || status.includes("deprecated")) return true;
    return Boolean(asset?.deprecated);
  };

  const cbomCategoryRows = useMemo(() => {
    const list = Array.isArray(cbomAssets) ? cbomAssets : [];
    const hsmBacked = list.filter((asset: any) => isHSMBackedAsset(asset));
    const softwareBacked = list.filter((asset: any) => !isHSMBackedAsset(asset));
    return [
      { label: "PQC-ready", items: list.filter((asset: any) => Boolean(asset?.pqc_ready)), tone: "green" },
      { label: "Deprecated", items: list.filter((asset: any) => Boolean(asset?.deprecated)), tone: "amber" },
      { label: "Weak / Legacy", items: list.filter((asset: any) => isWeakLegacyAsset(asset)), tone: "red" },
      { label: "HSM-backed", items: hsmBacked, tone: "blue" },
      { label: "Software-backed", items: softwareBacked, tone: "blue" }
    ].map((row: any) => ({ ...row, count: Array.isArray(row.items) ? row.items.length : 0 }));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cbomAssets]);

  const openCBOMAssetList = (row: any) => {
    setSelectedCBOMCategory(String(row?.label || ""));
    setCBOMAssetListTitle(`${String(row?.label || "")} Assets`);
    setCBOMAssetListFilter("");
    setCBOMAssetListItems(Array.isArray(row?.items) ? [...row.items] : []);
    setCBOMAssetListOpen(true);
  };

  const filteredCBOMAssetList = cbomAssetListItems.filter((asset: any) => {
    const q = String(cbomAssetListFilter || "").trim().toLowerCase();
    if (!q) return true;
    return [asset?.id, asset?.name, asset?.asset_type, asset?.source, asset?.algorithm, asset?.status, asset?.strength_bits].map((v) => String(v ?? "").toLowerCase()).join(" ").includes(q);
  });

  // ── PQC readiness data ────────────────────────────────────────
  const pqcPct = Math.max(0, Math.min(100, Math.round(Number(pqcReadiness?.pqc_readiness_percent ?? cbomLatest?.document?.pqc_readiness_percent ?? 0))));
  const pqcGaugeData = [{ name: "PQC", value: pqcPct, fill: pqcPct >= 75 ? C.green : pqcPct >= 40 ? C.amber : C.red }];
  const deprecatedCount = Number(pqcReadiness?.deprecated_count ?? cbomLatest?.document?.deprecated_count ?? 0);
  const criticalHighVulns = hasVulnerabilityCoverage ? vulnerabilities.filter((v: any) => { const s = String(v?.severity || "").toLowerCase(); return s === "critical" || s === "high"; }).length : 0;
  const vulnerabilitySummaryLabel = vulnLoading ? "Scanning..." : hasVulnerabilityCoverage ? `${vulnerabilities.length} total` : "Open Vulnerabilities to scan";
  const dependencyHealthSummary = !hasVulnerabilityCoverage
    ? (vulnLoading ? "Scanning dependency risk..." : "Open Vulnerabilities to calculate")
    : components.length > 0
      ? `${healthyComponentCount} of ${components.length} without known CVEs`
      : "Refresh BOM to score";

  // ── Strength histogram data ───────────────────────────────────
  const strengthHist = pqcReadiness?.strength_histogram || cbomLatest?.document?.strength_histogram || {};
  const strengthBars = Object.entries(strengthHist)
    .map(([bits, count]) => ({ name: `${bits}-bit`, bits: Number(bits), value: Number(count || 0) }))
    .sort((a, b) => a.bits - b.bits);

  // ── Vulnerability filtering ───────────────────────────────────
  const filteredVulns = useMemo(() => {
    let items = [...vulnerabilities];
    if (vulnSevFilter !== "all") items = items.filter((v: any) => String(v?.severity || "").toLowerCase() === vulnSevFilter);
    const q = vulnSearch.trim().toLowerCase();
    if (q) items = items.filter((v: any) => [v?.id, v?.component, v?.summary, v?.source].map((x) => String(x ?? "").toLowerCase()).join(" ").includes(q));
    items.sort((a: any, b: any) => severityRank(String(b?.severity || "")) - severityRank(String(a?.severity || "")));
    return items;
  }, [vulnerabilities, vulnSevFilter, vulnSearch]);

  // ── Component filtering (Software BOM) ────────────────────────
  const filteredComponents = useMemo(() => {
    let items = [...components];
    if (componentCategoryFilter === "go") items = goComponents;
    else if (componentCategoryFilter === "containers") items = containerComponents;
    else if (componentCategoryFilter === "system") items = systemComponents;
    const q = componentSearch.trim().toLowerCase();
    if (q) items = items.filter((c: any) => [c?.name, c?.version, c?.type, c?.ecosystem, c?.supplier].map((v) => String(v ?? "").toLowerCase()).join(" ").includes(q));
    return items;
  }, [components, componentCategoryFilter, componentSearch, goComponents, containerComponents, systemComponents]);

  const sevColor = (sev: string) => {
    const s = String(sev || "").toLowerCase();
    if (s === "critical") return C.red;
    if (s === "high") return C.orange;
    if (s === "medium") return C.amber;
    if (s === "low") return C.blue;
    return C.dim;
  };

  const sevTone = (sev: string) => {
    const s = String(sev || "").toLowerCase();
    if (s === "critical" || s === "high") return "red";
    if (s === "medium") return "amber";
    if (s === "low") return "blue";
    return "dim";
  };

  const sbomGenerated = String(sbomLatest?.document?.generated_at || sbomLatest?.created_at || "");
  const cbomGenerated = String(cbomLatest?.document?.generated_at || cbomLatest?.created_at || "");

  // ── Render ────────────────────────────────────────────────────
  return <div style={{ display: "grid", gap: 14 }}>
    {/* Header Stats Row */}
    <div style={{ display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: 10 }}>
      <Stat l="Dependencies" v={components.length} s={sbomGenerated ? `Updated ${new Date(sbomGenerated).toLocaleDateString()}` : undefined} c="accent" i={Package} />
      <Stat l="Critical CVEs" v={hasVulnerabilityCoverage ? criticalHighVulns : "--"} s={vulnerabilitySummaryLabel} c={hasVulnerabilityCoverage ? "red" : "dim"} i={AlertTriangle} />
      <Stat l="Crypto Assets" v={totalAssets} s={cbomGenerated ? `Updated ${new Date(cbomGenerated).toLocaleDateString()}` : undefined} c="blue" i={Atom} />
      <Stat l="Clean Deps" v={hasVulnerabilityCoverage ? `${dependencyHealthPct}%` : "--"} s={dependencyHealthSummary} c={dependencyHealthTone} i={ShieldCheck} />
      <Stat l="Deprecated" v={deprecatedCount} s={deprecatedCount > 0 ? "Action needed" : "All clear"} c="amber" i={Ban} />
    </div>

    {/* Sub-tabs + Refresh */}
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
      <Tabs tabs={["Overview", "Software BOM", "Crypto BOM", "Vulnerabilities"]} active={tab} onChange={setTab} />
      <Btn small onClick={() => {
        void loadData({ refresh: true }).then(() => loadVulnerabilities({ force: true, suppressToast: true }));
      }} disabled={refreshing || loading}>
        <RefreshCcw size={12} />{refreshing ? "Refreshing..." : "Refresh BOM"}
      </Btn>
    </div>

    {/* ── Overview Tab ──────────────────────────────────────── */}
    {tab === "Overview" && <>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        {/* Dependency Trend */}
        <Card style={{ padding: "14px 16px" }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 10 }}>Dependency Trend</div>
          {sbomTrend.length > 0 ? <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={sbomTrend}>
              <defs>
                <linearGradient id="depGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={C.accent} stopOpacity={0.25} />
                  <stop offset="95%" stopColor={C.accent} stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="label" tick={{ fill: C.muted, fontSize: 8 }} axisLine={{ stroke: C.border }} tickLine={false} interval="preserveStartEnd" />
              <YAxis tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} width={30} allowDecimals={false} />
              <Tooltip content={({ active, payload, label }) => active && payload?.length ? <ChartTip><div style={{ fontWeight: 700, color: C.accent, marginBottom: 2 }}>{label}</div>Total: <span style={{ fontWeight: 700 }}>{payload[0]?.value}</span></ChartTip> : null} cursor={{ stroke: C.borderHi, strokeDasharray: "3 3" }} />
              <Area type="monotone" dataKey="total" stroke={C.accent} strokeWidth={2} fill="url(#depGrad)" dot={{ fill: C.accent, r: 2, strokeWidth: 0 }} activeDot={{ fill: C.accent, r: 4, stroke: C.bg, strokeWidth: 2 }} />
            </AreaChart>
          </ResponsiveContainer> : <div style={{ height: 180, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, color: C.muted }}>No historical SBOM snapshots yet.</div>}
          <div style={{ fontSize: 9, color: C.muted, marginTop: 4 }}>{`${sbomTrend.length} snapshots — total dependency count per scan`}</div>
        </Card>

        {/* Dependency Health Gauge + Quick Stats */}
        <Card style={{ padding: "14px 16px" }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 10 }}>Dependency Health</div>
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <div style={{ width: 160 }}>
              <ResponsiveContainer width="100%" height={140}>
                <RadialBarChart cx="50%" cy="50%" innerRadius="55%" outerRadius="90%" startAngle={210} endAngle={-30} data={dependencyHealthGaugeData} barSize={14}>
                  <RadialBar dataKey="value" cornerRadius={7} background={{ fill: C.border }} />
                </RadialBarChart>
              </ResponsiveContainer>
              <div style={{ textAlign: "center", marginTop: -10 }}>
                <span style={{ fontSize: 24, fontWeight: 800, color: hasVulnerabilityCoverage ? dependencyHealthColor : C.dim }}>{hasVulnerabilityCoverage ? `${dependencyHealthPct}%` : "--"}</span>
                <div style={{ fontSize: 9, color: C.muted }}>Dependencies without known CVEs</div>
                <div style={{ fontSize: 9, color: C.dim, marginTop: 4 }}>
                  {!hasVulnerabilityCoverage
                    ? (vulnLoading ? "Vulnerability findings are being calculated." : "Open the Vulnerabilities tab or refresh BOM to calculate this score.")
                    : components.length > 0
                      ? `${healthyComponentCount} of ${components.length} components are currently clean in the latest SBOM scan.`
                      : "Refresh BOM to populate software inventory."}
                </div>
              </div>
            </div>
            <div style={{ flex: 1, display: "grid", gap: 8 }}>
              {sbomRows.map((row) => <div key={row.label} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: `1px solid ${C.border}` }}>
                <span style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{row.label}</span>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 11, color: C.dim }}>{row.count}</span>
                  <B c={String(row.sev?.tone || "green")}>{String(row.sev?.label || "0 CVEs")}</B>
                </div>
              </div>)}
            </div>
          </div>
        </Card>
      </div>

      {/* Snapshot Timeline */}
      <Card style={{ padding: "14px 16px" }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 10 }}>Recent Snapshots</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          <div>
            <div style={{ fontSize: 10, color: C.muted, fontWeight: 700, marginBottom: 6, textTransform: "uppercase", letterSpacing: 0.5 }}>Software BOM</div>
            {(Array.isArray(sbomHistory) ? sbomHistory.slice(0, 5) : []).map((snap: any, idx: number) => {
              const comps = Array.isArray(snap?.document?.components) ? snap.document.components.length : 0;
              return <div key={snap?.id || idx} style={{ display: "flex", justifyContent: "space-between", padding: "5px 0", borderBottom: `1px solid ${C.border}`, fontSize: 10 }}>
                <span style={{ color: C.dim }}>{new Date(String(snap?.created_at || snap?.document?.generated_at || "")).toLocaleString()}</span>
                <span style={{ color: C.text, fontWeight: 600 }}>{comps} deps</span>
              </div>;
            })}
            {!sbomHistory.length && <div style={{ fontSize: 10, color: C.muted }}>No snapshots yet.</div>}
          </div>
          <div>
            <div style={{ fontSize: 10, color: C.muted, fontWeight: 700, marginBottom: 6, textTransform: "uppercase", letterSpacing: 0.5 }}>Crypto BOM</div>
            {(Array.isArray(cbomHistory) ? cbomHistory.slice(0, 5) : []).map((snap: any, idx: number) => {
              const assets = Number(snap?.document?.total_asset_count ?? 0);
              return <div key={snap?.id || idx} style={{ display: "flex", justifyContent: "space-between", padding: "5px 0", borderBottom: `1px solid ${C.border}`, fontSize: 10 }}>
                <span style={{ color: C.dim }}>{new Date(String(snap?.created_at || snap?.document?.generated_at || "")).toLocaleString()}</span>
                <span style={{ color: C.text, fontWeight: 600 }}>{assets} assets</span>
              </div>;
            })}
            {!cbomHistory.length && <div style={{ fontSize: 10, color: C.muted }}>No snapshots yet.</div>}
          </div>
        </div>
      </Card>
    </>}

    {/* ── Software BOM Tab ──────────────────────────────────── */}
    {tab === "Software BOM" && <>
      {/* Actions bar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <Sel value={componentCategoryFilter} onChange={(e: any) => setComponentCategoryFilter(e.target.value)} style={{ height: 30, fontSize: 11 }}>
            <option value="all">All categories</option>
            <option value="go">Go modules</option>
            <option value="containers">Containers</option>
            <option value="system">System pkgs</option>
          </Sel>
          <Inp value={componentSearch} onChange={(e: any) => setComponentSearch(e.target.value)} placeholder="Search components..." style={{ height: 30, fontSize: 11, width: 200 }} />
        </div>
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <Btn small onClick={() => void exportSBOMFile("cyclonedx")} disabled={Boolean(exportingSBOM)} style={{ height: 30, fontSize: 11, background: activeSBOMFormat === "cyclonedx" ? C.accentDim : "transparent", borderColor: activeSBOMFormat === "cyclonedx" ? C.accent : C.border, color: activeSBOMFormat === "cyclonedx" ? C.accent : C.dim }}>
            {exportingSBOM === "cyclonedx" ? "..." : "CycloneDX"}
          </Btn>
          <Btn small onClick={() => void exportSBOMFile("spdx")} disabled={Boolean(exportingSBOM)} style={{ height: 30, fontSize: 11, background: activeSBOMFormat === "spdx" ? C.accentDim : "transparent", borderColor: activeSBOMFormat === "spdx" ? C.accent : C.border, color: activeSBOMFormat === "spdx" ? C.accent : C.dim }}>
            {exportingSBOM === "spdx" ? "..." : "SPDX"}
          </Btn>
          <div style={{ position: "relative" }}>
            <Btn small onClick={() => setExportMenuOpen((prev) => !prev)} disabled={Boolean(exportingSBOM)} style={{ height: 30, fontSize: 11 }}>Export</Btn>
            {exportMenuOpen ? <div style={{ position: "absolute", right: 0, top: 34, minWidth: 120, background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, padding: 6, zIndex: 20 }}>
              <Btn small onClick={() => { setExportMenuOpen(false); void exportSBOMFile("pdf"); }} disabled={Boolean(exportingSBOM)} style={{ width: "100%", justifyContent: "flex-start", height: 28, borderColor: "transparent", fontSize: 11 }}>
                {exportingSBOM === "pdf" ? "Exporting..." : "PDF"}
              </Btn>
              <Btn small onClick={() => { setExportMenuOpen(false); exportSBOMCSV(); }} disabled={Boolean(exportingSBOM)} style={{ width: "100%", justifyContent: "flex-start", height: 28, borderColor: "transparent", fontSize: 11 }}>
                {exportingSBOM === "csv" ? "Exporting..." : "CSV"}
              </Btn>
            </div> : null}
          </div>
          <Btn small onClick={() => void openSBOMDiff()} style={{ height: 30, fontSize: 11 }}>SBOM Diff</Btn>
        </div>
      </div>

      {/* Category summary */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
        {sbomRows.map((row) => <Card key={row.label} style={{ padding: "10px 14px", cursor: "pointer" }} onClick={() => openDependencyList(row)}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{row.label}</div>
              <div style={{ fontSize: 20, fontWeight: 800, color: C.accent, marginTop: 2 }}>{row.count}</div>
            </div>
            <B c={String(row.sev?.tone || "green")}>{String(row.sev?.label || "0 CVEs")}</B>
          </div>
        </Card>)}
      </div>

      {/* Component table */}
      <Card style={{ padding: "12px 14px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <div style={{ fontSize: 11, color: C.muted }}>{filteredComponents.length} of {components.length} components</div>
        </div>
        <div style={{ maxHeight: 400, overflowY: "auto" }}>
          {/* Table header */}
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr 100px", gap: 8, padding: "6px 0", borderBottom: `1px solid ${C.borderHi}`, fontSize: 9, color: C.muted, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5, position: "sticky", top: 0, background: C.card, zIndex: 1 }}>
            <span>Name</span><span>Version</span><span>Type</span><span>Ecosystem</span><span style={{ textAlign: "right" }}>CVEs</span>
          </div>
          {filteredComponents.map((c: any, idx: number) => {
            const key = String(c?.name || "").trim().toLowerCase();
            const vuln = componentVulnStats[key];
            const top = String(vuln?.top || "none");
            const tone = top === "critical" || top === "high" ? "red" : top === "medium" || top === "low" ? "amber" : "green";
            return <div key={`${c?.name}-${c?.version}-${idx}`} style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr 100px", gap: 8, padding: "7px 0", borderBottom: `1px solid ${C.border}`, fontSize: 11, alignItems: "center" }}>
              <span style={{ color: C.text, fontWeight: 600 }}>{String(c?.name || "-")}</span>
              <span style={{ color: C.dim }}>{String(c?.version || "-")}</span>
              <span style={{ color: C.dim }}>{String(c?.type || "-")}</span>
              <span style={{ color: C.dim }}>{String(c?.ecosystem || "-")}</span>
              <span style={{ textAlign: "right" }}><B c={tone}>{vuln ? `${vuln.count} CVEs` : "0 CVEs"}</B></span>
            </div>;
          })}
          {!filteredComponents.length && <div style={{ padding: "20px 0", textAlign: "center", fontSize: 10, color: C.muted }}>No components match the current filter.</div>}
        </div>
      </Card>

      {/* Dependency Trend */}
      <Card style={{ padding: "14px 16px" }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 10 }}>Dependency Trend</div>
        {sbomTrend.length > 0 ? <ResponsiveContainer width="100%" height={160}>
          <AreaChart data={sbomTrend}>
            <defs>
              <linearGradient id="depGrad2" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={C.accent} stopOpacity={0.25} />
                <stop offset="95%" stopColor={C.accent} stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="label" tick={{ fill: C.muted, fontSize: 8 }} axisLine={{ stroke: C.border }} tickLine={false} interval="preserveStartEnd" />
            <YAxis tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} width={30} allowDecimals={false} />
            <Tooltip content={({ active, payload, label }) => active && payload?.length ? <ChartTip><div style={{ fontWeight: 700, color: C.accent, marginBottom: 2 }}>{label}</div>Total: <span style={{ fontWeight: 700 }}>{payload[0]?.value}</span></ChartTip> : null} cursor={{ stroke: C.borderHi, strokeDasharray: "3 3" }} />
            <Area type="monotone" dataKey="total" stroke={C.accent} strokeWidth={2} fill="url(#depGrad2)" dot={{ fill: C.accent, r: 2, strokeWidth: 0 }} activeDot={{ fill: C.accent, r: 4, stroke: C.bg, strokeWidth: 2 }} />
          </AreaChart>
        </ResponsiveContainer> : <div style={{ height: 160, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, color: C.muted }}>No historical SBOM snapshots yet.</div>}
        <div style={{ fontSize: 9, color: C.muted, marginTop: 4 }}>{`Generated ${sbomGenerated ? new Date(sbomGenerated).toLocaleString() : "-"}`}</div>
      </Card>
    </>}

    {/* ── Crypto BOM Tab ────────────────────────────────────── */}
    {tab === "Crypto BOM" && <>
      {/* Actions bar */}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 6 }}>
        <Btn small onClick={() => void exportCBOMFile()} disabled={exportingCBOM} style={{ height: 30, fontSize: 11 }}>
          {exportingCBOM ? "Exporting..." : "Export CBOM"}
        </Btn>
        <Btn small onClick={() => void openCBOMDiff()} style={{ height: 30, fontSize: 11 }}>View Diff</Btn>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        {/* Algorithm Distribution Donut */}
        <Card style={{ padding: "14px 16px" }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 10 }}>Algorithm Distribution</div>
          {distItems.length > 0 ? <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={distItems} cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={3} dataKey="value" strokeWidth={0}>
                {distItems.map((entry, idx) => <Cell key={idx} fill={entry.fill} />)}
              </Pie>
              <Tooltip content={({ active, payload }) => active && payload?.length ? <ChartTip><span style={{ color: payload[0]?.payload?.fill, fontWeight: 700 }}>{payload[0]?.name}</span>: {payload[0]?.value} assets</ChartTip> : null} />
              <Legend verticalAlign="bottom" height={28} iconType="circle" iconSize={8} formatter={(v: string) => <span style={{ color: C.dim, fontSize: 9 }}>{v}</span>} />
            </PieChart>
          </ResponsiveContainer> : <div style={{ height: 200, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, color: C.muted }}>No algorithm data available.</div>}
          <div style={{ textAlign: "center", fontSize: 20, fontWeight: 800, color: C.text, marginTop: 4 }}>{totalAssets.toLocaleString()} <span style={{ fontSize: 10, fontWeight: 400, color: C.muted }}>total assets</span></div>
        </Card>

        {/* Strength Histogram + PQC Gauge */}
        <Card style={{ padding: "14px 16px" }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 10 }}>Key Strength Distribution</div>
          {strengthBars.length > 0 ? <ResponsiveContainer width="100%" height={160}>
            <BarChart data={strengthBars} layout="vertical">
              <XAxis type="number" tick={{ fill: C.muted, fontSize: 9 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fill: C.dim, fontSize: 10 }} axisLine={false} tickLine={false} width={60} />
              <Tooltip content={({ active, payload }) => active && payload?.length ? <ChartTip><span style={{ fontWeight: 700, color: C.accent }}>{payload[0]?.payload?.name}</span>: {payload[0]?.value} assets</ChartTip> : null} cursor={{ fill: "rgba(6,214,224,.04)" }} />
              <RBar dataKey="value" radius={[0, 4, 4, 0]} fill={C.accent} />
            </BarChart>
          </ResponsiveContainer> : <div style={{ height: 160, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, color: C.muted }}>No strength data available.</div>}

          <div style={{ marginTop: 16, borderTop: `1px solid ${C.border}`, paddingTop: 12 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: C.text, marginBottom: 6 }}>PQC Readiness</div>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <div style={{ width: 100 }}>
                <ResponsiveContainer width="100%" height={80}>
                  <RadialBarChart cx="50%" cy="50%" innerRadius="50%" outerRadius="90%" startAngle={210} endAngle={-30} data={pqcGaugeData} barSize={10}>
                    <RadialBar dataKey="value" cornerRadius={5} background={{ fill: C.border }} />
                  </RadialBarChart>
                </ResponsiveContainer>
              </div>
              <div>
                <div style={{ fontSize: 22, fontWeight: 800, color: pqcPct >= 75 ? C.green : pqcPct >= 40 ? C.amber : C.red }}>{pqcPct}%</div>
                <div style={{ fontSize: 9, color: C.muted }}>{Number(pqcReadiness?.pqc_ready_count ?? cbomLatest?.document?.pqc_ready_count ?? 0)} of {totalAssets} assets PQC-ready</div>
              </div>
            </div>
          </div>
        </Card>
      </div>

      {/* Category Drilldown */}
      <Card style={{ padding: "14px 16px" }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 10 }}>Asset Categories</div>
        <div style={{ display: "grid", gap: 2 }}>
          {cbomCategoryRows.map((row: any) => <div key={String(row.label)} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 0", borderBottom: `1px solid ${C.border}`, cursor: "pointer" }} onClick={() => openCBOMAssetList(row)}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 12, color: C.text, fontWeight: 600 }}>{String(row.label)}</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 18, fontWeight: 700, color: C[row.tone as keyof typeof C] || C.accent }}>{Number(row.count || 0).toLocaleString()}</span>
              <span style={{ fontSize: 9, color: C.muted }}>assets</span>
            </div>
          </div>)}
        </div>
        <div style={{ marginTop: 10, fontSize: 9, color: C.muted }}>
          {`Generated ${cbomGenerated ? new Date(cbomGenerated).toLocaleString() : "-"} — Auto-scheduled daily and refreshed from live inventory.`}
        </div>
      </Card>
    </>}

    {/* ── Vulnerabilities Tab ───────────────────────────────── */}
    {tab === "Vulnerabilities" && <>
      {/* Filters */}
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <Sel value={vulnSevFilter} onChange={(e: any) => setVulnSevFilter(e.target.value)} style={{ height: 30, fontSize: 11 }}>
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </Sel>
        <Inp value={vulnSearch} onChange={(e: any) => setVulnSearch(e.target.value)} placeholder="Search CVE ID, component, summary..." style={{ height: 30, fontSize: 11, flex: 1, minWidth: 200 }} />
        <span style={{ fontSize: 10, color: C.muted }}>{filteredVulns.length} of {vulnerabilities.length} vulnerabilities</span>
        <span style={{ fontSize: 10, color: C.dim }}>{vulnLoading ? "Scanning..." : hasVulnerabilityCoverage ? "Latest findings loaded" : "Scan starts on first open"}</span>
        <Btn onClick={() => { resetAdvisoryForm(); setAdvisoryModalOpen(true); }}>Add Offline Advisory</Btn>
      </div>

      <Card style={{ padding: "12px 14px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>Detection Sources</div>
            <div style={{ fontSize: 10, color: C.muted, marginTop: 4 }}>
              Manual advisories are merged first for air-gapped KMS use. OSV adds package intelligence, and Trivy contributes repository scan findings.
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {Object.entries(vulnerabilitySources).map(([source, count]) => (
              <div key={source} style={{ padding: "6px 10px", border: `1px solid ${C.border}`, borderRadius: 999, fontSize: 10, color: C.text }}>
                <span style={{ color: C.muted }}>{source}</span> {Number(count || 0)}
              </div>
            ))}
            {!Object.keys(vulnerabilitySources).length && <div style={{ fontSize: 10, color: C.muted }}>No findings yet.</div>}
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginTop: 10, flexWrap: "wrap" }}>
          <div style={{ fontSize: 10, color: C.muted }}>{manualAdvisories.length} saved offline advisories</div>
          <div style={{ fontSize: 10, color: C.muted }}>Trivy may need internet on first run unless its DB cache is preloaded.</div>
        </div>
      </Card>

      {/* Severity summary cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 10 }}>
        {(["critical", "high", "medium", "low"] as const).map((sev) => {
          const count = vulnerabilities.filter((v: any) => String(v?.severity || "").toLowerCase() === sev).length;
          return <Card key={sev} style={{ padding: "10px 14px", cursor: "pointer", border: vulnSevFilter === sev ? `1px solid ${sevColor(sev)}` : undefined }} onClick={() => setVulnSevFilter(vulnSevFilter === sev ? "all" : sev)}>
            <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5 }}>{sev}</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: sevColor(sev), marginTop: 2 }}>{count}</div>
          </Card>;
        })}
      </div>

      {/* Vulnerability table */}
      <Card style={{ padding: "12px 14px" }}>
        <div style={{ maxHeight: 480, overflowY: "auto" }}>
          {/* Table header */}
          <div style={{ display: "grid", gridTemplateColumns: "80px 110px 1.35fr 1fr 1fr 2fr 80px", gap: 8, padding: "6px 0", borderBottom: `1px solid ${C.borderHi}`, fontSize: 9, color: C.muted, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5, position: "sticky", top: 0, background: C.card, zIndex: 1 }}>
            <span>Severity</span><span>Source</span><span>Component</span><span>Installed</span><span>Fixed</span><span>Summary</span><span>Ref</span>
          </div>
          {filteredVulns.map((v: any, idx: number) => <div key={`${v?.id}-${idx}`} style={{ display: "grid", gridTemplateColumns: "80px 110px 1.35fr 1fr 1fr 2fr 80px", gap: 8, padding: "7px 0", borderBottom: `1px solid ${C.border}`, fontSize: 11, alignItems: "center" }}>
            <span><B c={sevTone(v?.severity)}>{String(v?.severity || "unknown")}</B></span>
            <span style={{ color: String(v?.source || "").toLowerCase().includes("manual") ? C.yellow : String(v?.source || "").toLowerCase().includes("trivy") ? C.blue : C.accent, fontWeight: 600 }}>{String(v?.source || "-")}</span>
            <span style={{ color: C.text, fontWeight: 600 }}>{String(v?.component || "-")}</span>
            <span style={{ color: C.dim }}>{String(v?.installed_version || "-")}</span>
            <span style={{ color: C.green, fontWeight: 600 }}>{String(v?.fixed_version || "-")}</span>
            <span style={{ color: C.dim, fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{String(v?.summary || "-")}</span>
            <span>{(() => { const ref = String(v?.reference || "").trim(); const safe = /^https?:\/\//i.test(ref); return safe ? <a href={ref} target="_blank" rel="noopener noreferrer" style={{ color: C.accent, fontSize: 10, textDecoration: "none" }}>Link</a> : <span style={{ color: C.muted, fontSize: 10 }}>—</span>; })()}</span>
          </div>)}
          {!filteredVulns.length && <div style={{ padding: "20px 0", textAlign: "center", fontSize: 10, color: C.muted }}>
            {vulnerabilities.length === 0 ? "No vulnerabilities detected. Refresh BOM to scan." : "No vulnerabilities match the current filter."}
          </div>}
        </div>
      </Card>
    </>}

    {/* ── No data fallback ──────────────────────────────────── */}
    <Modal open={advisoryModalOpen} onClose={() => setAdvisoryModalOpen(false)} title="Offline Advisory">
      <div style={{ fontSize: 10, color: C.dim, marginBottom: 10 }}>
        Add an OSV-style advisory manually for air-gapped environments. Saved advisories are merged into the live vulnerability list ahead of online sources.
      </div>
      <div style={{ display: "grid", gap: 8 }}>
        <Inp value={advisoryForm.id} onChange={(e: any) => setAdvisoryForm((prev: any) => ({ ...prev, id: e.target.value }))} placeholder="Advisory ID, e.g. CVE-2026-1234" />
        <Inp value={advisoryForm.component} onChange={(e: any) => setAdvisoryForm((prev: any) => ({ ...prev, component: e.target.value }))} placeholder="Component / package name" />
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 8 }}>
          <Sel value={advisoryForm.ecosystem} onChange={(e: any) => setAdvisoryForm((prev: any) => ({ ...prev, ecosystem: e.target.value }))}>
            <option value="go">Go</option>
            <option value="npm">npm</option>
            <option value="any">Any ecosystem</option>
          </Sel>
          <Inp value={advisoryForm.introduced_version} onChange={(e: any) => setAdvisoryForm((prev: any) => ({ ...prev, introduced_version: e.target.value }))} placeholder="Introduced version (optional)" />
          <Inp value={advisoryForm.fixed_version} onChange={(e: any) => setAdvisoryForm((prev: any) => ({ ...prev, fixed_version: e.target.value }))} placeholder="Fixed version" />
        </div>
        <Sel value={advisoryForm.severity} onChange={(e: any) => setAdvisoryForm((prev: any) => ({ ...prev, severity: e.target.value }))}>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </Sel>
        <Inp value={advisoryForm.reference} onChange={(e: any) => setAdvisoryForm((prev: any) => ({ ...prev, reference: e.target.value }))} placeholder="Reference URL (optional)" />
        <textarea
          value={advisoryForm.summary}
          onChange={(e: any) => setAdvisoryForm((prev: any) => ({ ...prev, summary: e.target.value }))}
          placeholder="Summary"
          style={{ minHeight: 92, borderRadius: 10, border: `1px solid ${C.border}`, background: C.surface, color: C.text, padding: 12, resize: "vertical" }}
        />
      </div>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
        <Btn onClick={() => setAdvisoryModalOpen(false)}>Cancel</Btn>
        <Btn onClick={() => void saveOfflineAdvisory()} disabled={savingAdvisory}>{savingAdvisory ? "Saving..." : "Save Advisory"}</Btn>
      </div>
      <div style={{ height: 12 }} />
      <Card style={{ padding: "12px 14px", maxHeight: 260, overflowY: "auto" }}>
        <div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginBottom: 8 }}>Saved Offline Advisories</div>
        {manualAdvisories.map((item: any) => (
          <div key={String(item?.id)} style={{ display: "grid", gridTemplateColumns: "1.1fr 1fr auto", gap: 8, alignItems: "center", padding: "8px 0", borderBottom: `1px solid ${C.border}` }}>
            <div>
              <div style={{ fontSize: 11, color: C.text, fontWeight: 600 }}>{String(item?.id || "-")} - {String(item?.component || "-")}</div>
              <div style={{ fontSize: 9, color: C.muted, marginTop: 2 }}>{String(item?.ecosystem || "any")} {item?.introduced_version ? `from ${item.introduced_version}` : ""} {item?.fixed_version ? `fixed ${item.fixed_version}` : ""}</div>
            </div>
            <div style={{ fontSize: 10, color: C.dim, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{String(item?.summary || "-")}</div>
            <Btn onClick={() => void removeOfflineAdvisory(String(item?.id || ""))} disabled={deletingAdvisory === String(item?.id || "")}>{deletingAdvisory === String(item?.id || "") ? "Deleting..." : "Delete"}</Btn>
          </div>
        ))}
        {!manualAdvisories.length && <div style={{ fontSize: 10, color: C.muted }}>No offline advisories saved yet.</div>}
      </Card>
    </Modal>

    {!loading && !refreshing && !sbomLatest && !cbomLatest && <Card style={{ padding: 16 }}><div style={{ fontSize: 10, color: C.muted, textAlign: "center" }}>No BOM data available. Click "Refresh BOM" to generate your first Software and Cryptographic BOM snapshots.</div></Card>}

    {/* ── CBOM Diff Modal ───────────────────────────────────── */}
    <Modal open={diffOpen} onClose={() => setDiffOpen(false)} title="CBOM Diff (Latest vs Previous)">
      <div style={{ fontSize: 10, color: C.dim, marginBottom: 8 }}>
        Changes between the latest two CBOM snapshots for tenant {String(session?.tenantId || "-")}.
      </div>
      <Row3>
        <Card><div style={{ fontSize: 10, color: C.muted }}>Added</div><div style={{ fontSize: 20, color: C.green, fontWeight: 700 }}>{Number(diffData?.metrics?.added || 0)}</div></Card>
        <Card><div style={{ fontSize: 10, color: C.muted }}>Removed</div><div style={{ fontSize: 20, color: C.red, fontWeight: 700 }}>{Number(diffData?.metrics?.removed || 0)}</div></Card>
        <Card><div style={{ fontSize: 10, color: C.muted }}>Changed</div><div style={{ fontSize: 20, color: C.amber, fontWeight: 700 }}>{Number(diffData?.metrics?.changed || 0)}</div></Card>
      </Row3>
      <div style={{ height: 8 }} />
      <Card style={{ maxHeight: 260, overflowY: "auto" }}>
        <div style={{ fontSize: 11, color: C.text, fontWeight: 700, marginBottom: 6 }}>Algorithm delta</div>
        {Object.entries(diffData?.metrics?.algorithm_delta || {}).map(([alg, val]) => <div key={alg} style={{ display: "flex", justifyContent: "space-between", fontSize: 10, padding: "3px 0", borderBottom: `1px solid ${C.border}` }}>
          <span style={{ color: C.dim }}>{alg}</span>
          <span style={{ color: Number(val) >= 0 ? C.green : C.red, fontWeight: 700 }}>{`${Number(val) >= 0 ? "+" : ""}${Number(val || 0)}`}</span>
        </div>)}
        {!Object.keys(diffData?.metrics?.algorithm_delta || {}).length ? <div style={{ fontSize: 10, color: C.muted }}>No algorithm distribution changes detected.</div> : null}
      </Card>
      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10 }}>
        <Btn onClick={() => setDiffOpen(false)}>Close</Btn>
      </div>
    </Modal>

    {/* ── SBOM Diff Modal ───────────────────────────────────── */}
    <Modal open={sbomDiffOpen} onClose={() => setSBOMDiffOpen(false)} title="SBOM Diff (Latest vs Previous)">
      <div style={{ fontSize: 10, color: C.dim, marginBottom: 8 }}>
        Changes between the latest two SBOM snapshots.
      </div>
      <Row3>
        <Card><div style={{ fontSize: 10, color: C.muted }}>Added</div><div style={{ fontSize: 20, color: C.green, fontWeight: 700 }}>{Number(sbomDiffData?.metrics?.added || 0)}</div></Card>
        <Card><div style={{ fontSize: 10, color: C.muted }}>Removed</div><div style={{ fontSize: 20, color: C.red, fontWeight: 700 }}>{Number(sbomDiffData?.metrics?.removed || 0)}</div></Card>
        <Card><div style={{ fontSize: 10, color: C.muted }}>Changed</div><div style={{ fontSize: 20, color: C.amber, fontWeight: 700 }}>{Number(sbomDiffData?.metrics?.changed || 0)}</div></Card>
      </Row3>
      <div style={{ height: 8 }} />
      {Array.isArray(sbomDiffData?.added) && sbomDiffData.added.length > 0 && <Card style={{ maxHeight: 180, overflowY: "auto", marginBottom: 8 }}>
        <div style={{ fontSize: 11, color: C.green, fontWeight: 700, marginBottom: 6 }}>Added components</div>
        {sbomDiffData.added.map((item: any, idx: number) => <div key={idx} style={{ fontSize: 10, padding: "3px 0", borderBottom: `1px solid ${C.border}`, color: C.dim }}>
          {String(item?.name || item?.component || JSON.stringify(item))} {item?.version ? `v${item.version}` : ""}
        </div>)}
      </Card>}
      {Array.isArray(sbomDiffData?.removed) && sbomDiffData.removed.length > 0 && <Card style={{ maxHeight: 180, overflowY: "auto", marginBottom: 8 }}>
        <div style={{ fontSize: 11, color: C.red, fontWeight: 700, marginBottom: 6 }}>Removed components</div>
        {sbomDiffData.removed.map((item: any, idx: number) => <div key={idx} style={{ fontSize: 10, padding: "3px 0", borderBottom: `1px solid ${C.border}`, color: C.dim }}>
          {String(item?.name || item?.component || JSON.stringify(item))} {item?.version ? `v${item.version}` : ""}
        </div>)}
      </Card>}
      {Array.isArray(sbomDiffData?.changed) && sbomDiffData.changed.length > 0 && <Card style={{ maxHeight: 180, overflowY: "auto", marginBottom: 8 }}>
        <div style={{ fontSize: 11, color: C.amber, fontWeight: 700, marginBottom: 6 }}>Changed components</div>
        {sbomDiffData.changed.map((item: any, idx: number) => <div key={idx} style={{ fontSize: 10, padding: "3px 0", borderBottom: `1px solid ${C.border}`, color: C.dim }}>
          {String(item?.name || item?.component || JSON.stringify(item))} {item?.from_version ? `${item.from_version} → ${item.to_version || "?"}` : ""}
        </div>)}
      </Card>}
      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10 }}>
        <Btn onClick={() => setSBOMDiffOpen(false)}>Close</Btn>
      </div>
    </Modal>

    {/* ── Dependency List Modal ──────────────────────────────── */}
    <Modal open={depListOpen} onClose={() => { setDepListOpen(false); setSelectedDepCategory(""); }} title={`${depListTitle} Dependencies`}>
      <div style={{ fontSize: 10, color: C.dim, marginBottom: 8 }}>
        Package list for this category.
      </div>
      <Inp value={depListFilter} onChange={(e: any) => setDepListFilter(e.target.value)} placeholder="Search name, version, type, ecosystem..." />
      <div style={{ height: 8 }} />
      <Card style={{ maxHeight: 360, overflowY: "auto" }}>
        <div style={{ display: "grid", gap: 6 }}>
          {filteredDepList.map((item: any, idx: number) => {
            const key = String(item?.name || "").trim().toLowerCase();
            const vuln = componentVulnStats[key];
            const top = String(vuln?.top || "none");
            const tone = top === "critical" || top === "high" ? "red" : top === "medium" || top === "low" ? "amber" : "green";
            return <div key={`${String(item?.name || "dep")}-${String(item?.version || "")}-${idx}`} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "7px 0", borderBottom: `1px solid ${C.border}` }}>
              <div style={{ display: "grid", gap: 2 }}>
                <div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>{String(item?.name || "-")}</div>
                <div style={{ fontSize: 10, color: C.dim }}>
                  {`${String(item?.version || "-")} · ${String(item?.type || "-")}${String(item?.ecosystem || "") ? ` · ${String(item?.ecosystem || "")}` : ""}`}
                </div>
              </div>
              <B c={tone}>{vuln ? `${Number(vuln.count || 0)} CVEs` : "0 CVEs"}</B>
            </div>;
          })}
          {!filteredDepList.length && <div style={{ fontSize: 10, color: C.muted }}>No dependencies found for current filter.</div>}
        </div>
      </Card>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 10 }}>
        <span style={{ fontSize: 10, color: C.muted }}>{`${filteredDepList.length} of ${depListItems.length} shown`}</span>
        <Btn onClick={() => { setDepListOpen(false); setSelectedDepCategory(""); }}>Close</Btn>
      </div>
    </Modal>

    {/* ── CBOM Asset List Modal ──────────────────────────────── */}
    <Modal open={cbomAssetListOpen} onClose={() => { setCBOMAssetListOpen(false); setSelectedCBOMCategory(""); }} title={cbomAssetListTitle || "CBOM Assets"}>
      <div style={{ fontSize: 10, color: C.dim, marginBottom: 8 }}>
        Filtered cryptographic assets from the current CBOM snapshot.
      </div>
      <Inp value={cbomAssetListFilter} onChange={(e: any) => setCBOMAssetListFilter(e.target.value)} placeholder="Search name, id, algorithm, source, status..." />
      <div style={{ height: 8 }} />
      <Card style={{ maxHeight: 360, overflowY: "auto" }}>
        <div style={{ display: "grid", gap: 6 }}>
          {filteredCBOMAssetList.map((asset: any, idx: number) => {
            const tone = Boolean(asset?.deprecated) || isWeakLegacyAsset(asset) ? "red" : Boolean(asset?.pqc_ready) ? "green" : "blue";
            return <div key={`${String(asset?.id || "asset")}-${idx}`} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "7px 0", borderBottom: `1px solid ${C.border}` }}>
              <div style={{ display: "grid", gap: 2 }}>
                <div style={{ fontSize: 11, color: C.text, fontWeight: 700 }}>{String(asset?.name || asset?.id || "-")}</div>
                <div style={{ fontSize: 10, color: C.dim }}>
                  {`${String(asset?.algorithm || "-")} · ${String(asset?.asset_type || "-")} · ${String(asset?.source || "-")} · ${Number(asset?.strength_bits || 0) || "-"} bits`}
                </div>
              </div>
              <B c={tone}>{String(asset?.status || "unknown")}</B>
            </div>;
          })}
          {!filteredCBOMAssetList.length && <div style={{ fontSize: 10, color: C.muted }}>No assets found for current filter.</div>}
        </div>
      </Card>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 10 }}>
        <span style={{ fontSize: 10, color: C.muted }}>{`${filteredCBOMAssetList.length} of ${cbomAssetListItems.length} shown`}</span>
        <Btn onClick={() => { setCBOMAssetListOpen(false); setSelectedCBOMCategory(""); }}>Close</Btn>
      </div>
    </Modal>
  </div>;
};
