import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Atom,
  BarChart3,
  BarChart2,
  Bell,
  Building2,
  CalendarClock,
  CheckCircle2,
  ChevronsLeft,
  ChevronsRight,
  ClipboardCheck,
  Cloud,
  Cpu,
  Database,
  FileText,
  Gauge,
  GitBranch,
  GitMerge,
  Globe,
  Home as HomeIcon,
  KeyRound,
  Layers,
  Layers3 as LayersIcon,
  LayoutGrid,
  Link,
  List,
  Lock,
  Network,
  Pin,
  PinOff,
  Play,
  Plug,
  ScanSearch,
  ScrollText,
  Settings,
  ShieldCheck,
  Siren,
  VenetianMask,
  Vault,
  Webhook,
  Zap,
  CreditCard,
  Users,
  Server,
  RefreshCw,
  Sparkles,
  Archive
} from "lucide-react";
import type { AuthSession } from "../lib/auth";
import { canAccessModule, isSystemAdminSession } from "../config/moduleRegistry";
import type { FeatureKey } from "../config/tabs";
import { CommandPalette, type PaletteItem } from "./CommandPalette";
import { getAuthCLIStatus, listAuthTenants } from "../lib/authAdmin";
import { getGovernanceSystemState } from "../lib/governance";
import { listKeys, listKeysPaginated, listTags } from "../lib/keycore";
import { getUnreadAlertCounts } from "../lib/reporting";
import { B, Btn, Sel } from "./v3/legacyPrimitives";
import { isFipsModeEnabled, normalizeFipsModeValue, TabErrorBoundary } from "./v3/runtimeUtils";
import { C } from "./v3/theme";

// Lazy-loaded tab components for code splitting
const AdminTab = lazy(() => import("./v3/tabs/AdminTab").then(m => ({ default: m.AdminTab })));
const AlertsTab = lazy(() => import("./v3/tabs/AlertsTab").then(m => ({ default: m.AlertsTab })));
const ClusterTab = lazy(() => import("./v3/tabs/ClusterTab").then(m => ({ default: m.ClusterTab })));
const DashboardTab = lazy(() => import("./v3/tabs/DashboardTab").then(m => ({ default: m.DashboardTab })));
const GovernanceTab = lazy(() => import("./v3/tabs/GovernanceTab").then(m => ({ default: m.GovernanceTab })));
const RestAPITab = lazy(() => import("./v3/tabs/RestAPITab").then(m => ({ default: m.RestAPITab })));
const VaultTab = lazy(() => import("./v3/tabs/VaultTab").then(m => ({ default: m.VaultTab })));
const EKMTab = lazy(() => import("./v3/tabs/EKMTab").then(m => ({ default: m.EKMTab })));
const DataProtectionTabs = lazy(() => import("./v3/tabs/DataProtectionTabs").then(m => ({ default: m.DataProtectionTab })));
const TokenizeTab = lazy(() => import("./v3/tabs/DataProtectionTabs").then(m => ({ default: m.TokenizeTab })));
const DataEncryptionTab = lazy(() => import("./v3/tabs/DataProtectionTabs").then(m => ({ default: m.DataEncryptionTab })));
const PKCS11Tab = lazy(() => import("./v3/tabs/PKCS11Tab").then(m => ({ default: m.PKCS11Tab })));
const BYOKTab = lazy(() => import("./v3/tabs/BYOKTab").then(m => ({ default: m.BYOKTab })));
const HYOKTab = lazy(() => import("./v3/tabs/HYOKTab").then(m => ({ default: m.HYOKTab })));
const CloudKeyControlTab = lazy(() => import("./v3/tabs/CloudKeyControlTab").then(m => ({ default: m.CloudKeyControlTab })));
const WorkbenchTab = lazy(() => import("./v3/tabs/WorkbenchTab").then(m => ({ default: m.WorkbenchTab })));
const CryptoTab = lazy(() => import("./v3/tabs/CryptoTab").then(m => ({ default: m.CryptoTab })));
const PaymentTab = lazy(() => import("./v3/tabs/PaymentTab").then(m => ({ default: m.PaymentTab })));
const HSMTab = lazy(() => import("./v3/tabs/HSMTab").then(m => ({ default: m.HSMTab })));
const CertsTab = lazy(() => import("./v3/tabs/CertsTab").then(m => ({ default: m.CertsTab })));
const KeysTab = lazy(() => import("./v3/tabs/KeysTab").then(m => ({ default: m.KeysTab })));
const ComplianceTab = lazy(() => import("./v3/tabs/ComplianceTab").then(m => ({ default: m.ComplianceTab })));
const SBOMTab = lazy(() => import("./v3/tabs/SBOMTab").then(m => ({ default: m.SBOMTab })));
const PostureTab = lazy(() => import("./v3/tabs/PostureTab").then(m => ({ default: m.PostureTab })));
const AuditLogTab = lazy(() => import("./v3/tabs/AuditLogTab").then(m => ({ default: m.AuditLogTab })));
const MPCTab = lazy(() => import("./v3/tabs/MPCTab").then(m => ({ default: m.MPCTab })));
const QKDTab = lazy(() => import("./v3/tabs/QKDTab").then(m => ({ default: m.QKDTab })));
const QRNGTab = lazy(() => import("./v3/tabs/QRNGTab").then(m => ({ default: m.QRNGTab })));
const DocsViewTab = lazy(() => import("./v3/tabs/DocsViewTab").then(m => ({ default: m.DocsViewTab })));
const AITab = lazy(() => import("./v3/tabs/AITab").then(m => ({ default: m.AITab })));
const KeyCeremonyTab = lazy(() => import("./v3/tabs/KeyCeremonyTab").then(m => ({ default: m.KeyCeremonyTab })));
const RotationSchedulerTab = lazy(() => import("./v3/tabs/RotationSchedulerTab").then(m => ({ default: m.RotationSchedulerTab })));
const CryptoAgilityTab = lazy(() => import("./v3/tabs/CryptoAgilityTab").then(m => ({ default: m.CryptoAgilityTab })));
const WebhooksTab = lazy(() => import("./v3/tabs/WebhooksTab").then(m => ({ default: m.WebhooksTab })));
const LeakScannerTab = lazy(() => import("./v3/tabs/LeakScannerTab").then(m => ({ default: m.LeakScannerTab })));
const CTMonitorTab = lazy(() => import("./v3/tabs/CTMonitorTab").then(m => ({ default: m.CTMonitorTab })));
const MTLSMeshTab = lazy(() => import("./v3/tabs/MTLSMeshTab").then(m => ({ default: m.MTLSMeshTab })));
const EscrowTab = lazy(() => import("./v3/tabs/EscrowTab").then(m => ({ default: m.EscrowTab })));
const EnvelopeEncTab = lazy(() => import("./v3/tabs/EnvelopeEncTab").then(m => ({ default: m.EnvelopeEncTab })));
const DRDrillTab = lazy(() => import("./v3/tabs/DRDrillTab").then(m => ({ default: m.DRDrillTab })));
const OpsMetricsTab = lazy(() => import("./v3/tabs/OpsMetricsTab").then(m => ({ default: m.OpsMetricsTab })));
const BackupTab = lazy(() => import("./v3/tabs/BackupTab").then(m => ({ default: m.BackupTab })));
const DSPMTab = lazy(() => import("./v3/tabs/DSPMTab").then(m => ({ default: m.DSPMTab })));
const DevSecOpsTab = lazy(() => import("./v3/tabs/DevSecOpsTab").then(m => ({ default: m.DevSecOpsTab })));
const TDETab = lazy(() => import("./v3/tabs/TDETab").then(m => ({ default: m.TDETab })));
const TFETab = lazy(() => import("./v3/tabs/TFETab").then(m => ({ default: m.TFETab })));
const DataActivityTab = lazy(() => import("./v3/tabs/DataActivityTab").then(m => ({ default: m.DataActivityTab })));
const AIProtectTab = lazy(() => import("./v3/tabs/AIProtectTab").then(m => ({ default: m.AIProtectTab })));
const LineageTab = lazy(() => import("./v3/tabs/LineageTab").then(m => ({ default: m.LineageTab })));
const CanaryKeysTab = lazy(() => import("./v3/tabs/CanaryKeysTab").then(m => ({ default: m.CanaryKeysTab })));
const PlaybooksTab = lazy(() => import("./v3/tabs/PlaybooksTab").then(m => ({ default: m.PlaybooksTab })));

type Props = {
  session: AuthSession;
  enabledFeatures: Set<FeatureKey>;
  alerts: any[];
  audit: any[];
  unreadAlerts: number;
  onLogout: () => void;
  markAlertsRead: () => void;
};

const TAB_STORAGE_KEY = "vecta_active_tab";
const TZ_STORAGE_KEY = "vecta_timezone";
const COMMON_TIMEZONES = [
  { label: "Local", value: "local" },
  { label: "UTC", value: "UTC" },
  { label: "US/Eastern", value: "America/New_York" },
  { label: "US/Central", value: "America/Chicago" },
  { label: "US/Pacific", value: "America/Los_Angeles" },
  { label: "Europe/London", value: "Europe/London" },
  { label: "Europe/Berlin", value: "Europe/Berlin" },
  { label: "Asia/Dubai", value: "Asia/Dubai" },
  { label: "Asia/Kolkata", value: "Asia/Kolkata" },
  { label: "Asia/Singapore", value: "Asia/Singapore" },
  { label: "Asia/Tokyo", value: "Asia/Tokyo" },
  { label: "Australia/Sydney", value: "Australia/Sydney" }
];

function canSeeFeature(need: any, enabledFeatures: Set<FeatureKey>, session?: any): boolean {
  if (isSystemAdminSession(session)) {
    return true;
  }
  if (!need) {
    return true;
  }
  if (Array.isArray(need)) {
    return need.some((item) => canSeeFeature(item, enabledFeatures, session));
  }
  if (need === "hsm_hardware_or_software") {
    return enabledFeatures.has("hsm_hardware") || enabledFeatures.has("hsm_software");
  }
  return enabledFeatures.has(need as FeatureKey);
}

function canSeeTab(tab: string, enabledFeatures: Set<FeatureKey>, session?: any): boolean {
  return canAccessModule(tab, enabledFeatures, session);
}

function toViewKey(k: any): any {
  return {
    id: String(k?.id || ""),
    name: String(k?.name || "unnamed-key"),
    algo: String(k?.algorithm || "unknown"),
    state: String(k?.status || "unknown").toLowerCase(),
    ver: `v${Number(k?.current_version || 1)}`,
    tags: Array.isArray(k?.tags) ? k.tags.map((t: any) => String(t)) : [],
    componentRole: String(k?.labels?.component_role || k?.labels?.component || "")
  };
}

const TABS: Record<string, any> = {
  home: DashboardTab,
  keys: KeysTab,
  workbench: WorkbenchTab,
  crypto: CryptoTab,
  restapi: RestAPITab,
  vault: VaultTab,
  certs: CertsTab,
  dataprotection: DataProtectionTabs,
  tokenize: TokenizeTab,
  dataenc: DataEncryptionTab,
  payment: PaymentTab,
  cloudctl: CloudKeyControlTab,
  byok: BYOKTab,
  hyok: HYOKTab,
  ekm: EKMTab,
  hsm: HSMTab,
  qkd: QKDTab,
  qrng: QRNGTab,
  mpc: MPCTab,
  cluster: ClusterTab,
  approvals: GovernanceTab,
  alerts: AlertsTab,
  audit: AuditLogTab,
  posture: PostureTab,
  compliance: ComplianceTab,
  sbom: SBOMTab,
  pkcs11: PKCS11Tab,
  admin: AdminTab,
  docs: DocsViewTab,
  ai: AITab,
  ceremony: KeyCeremonyTab,
  rotation: RotationSchedulerTab,
  crypto_agility: CryptoAgilityTab,
  webhooks: WebhooksTab,
  leak_scanner: LeakScannerTab,
  ct_monitor: CTMonitorTab,
  mtls_mesh: MTLSMeshTab,
  escrow: EscrowTab,
  envelope_enc: EnvelopeEncTab,
  dr_drill: DRDrillTab,
  ops_metrics: OpsMetricsTab,
  backup: BackupTab,
  dspm: DSPMTab,
  devsecops: DevSecOpsTab,
  tde: TDETab,
  tfe: TFETab,
  data_activity: DataActivityTab,
  ai_protect: AIProtectTab,
  lineage: LineageTab,
  canary: CanaryKeysTab,
  playbooks: PlaybooksTab
};

const TITLES: Record<string, string> = {
  home: "Dashboard",
  keys: "Key Management",
  workbench: "Workbench",
  crypto: "Crypto Console",
  restapi: "REST API",
  vault: "Secret Vault",
  certs: "Certificates / PKI",
  dataprotection: "Data Protection",
  tokenize: "Tokenize / Mask / Redact",
  dataenc: "Data Encryption",
  payment: "Payment Crypto",
  cloudctl: "Cloud Key Control",
  byok: "BYOK",
  hyok: "HYOK",
  ekm: "Enterprise Key Management",
  hsm: "HSM",
  qkd: "QKD Interface",
  qrng: "QRNG Entropy",
  mpc: "MPC Engine",
  cluster: "Cluster",
  approvals: "Approvals",
  alerts: "Alert Center",
  audit: "Audit Log",
  posture: "Posture Management",
  compliance: "Compliance",
  sbom: "SBOM / CBOM",
  pkcs11: "PKCS#11 / JCA",
  admin: "Administration",
  docs: "Documentation",
  ai: "AI Assistant",
  ceremony: "Key Ceremony",
  rotation: "Rotation Scheduler",
  crypto_agility: "Crypto Agility",
  webhooks: "Webhooks & SIEM",
  leak_scanner: "Leak Scanner",
  ct_monitor: "CT Log Monitor",
  mtls_mesh: "mTLS Mesh",
  escrow: "Key Escrow",
  envelope_enc: "Envelope Encryption",
  dr_drill: "DR Drill",
  ops_metrics: "Operations Metrics",
  backup: "Backup & Restore",
  dspm: "Data Security Posture",
  devsecops: "DevSecOps / IaC",
  tde: "Database TDE",
  tfe: "File Encryption (TFE)",
  data_activity: "Data Activity Monitor",
  ai_protect: "AI/GenAI Data Protection",
  lineage: "Source Traceability",
  canary: "Canary / Honeypot Keys",
  playbooks: "Incident Playbooks"
};

const NAV = [
  { g: "CORE", items: [
    { id: "home", icon: HomeIcon, label: "Dashboard" },
    { id: "keys", icon: KeyRound, label: "Key Management" },
    { id: "ops_metrics", icon: BarChart2, label: "Operations Metrics" },
    { id: "certs", icon: FileText, label: "Certificates / PKI" },
    { id: "cloudctl", icon: Cloud, label: "Cloud Key Control" },
    { id: "ekm", icon: Database, label: "Enterprise Key Management" },
    { id: "vault", icon: Lock, label: "Secret Vault" },
    { id: "dataprotection", icon: ShieldCheck, label: "Data Protection" },
  ]},
  { g: "WORKBENCH", items: [{ id: "workbench", icon: LayoutGrid, label: "Workbench" }] },
  { g: "SECRETS & CERTS", items: [
    { id: "rotation", icon: CalendarClock, label: "Rotation Scheduler" },
    { id: "ct_monitor", icon: Globe, label: "CT Log Monitor" },
    { id: "escrow", icon: Vault, label: "Key Escrow" },
    { id: "canary", icon: AlertTriangle, label: "Canary Keys" },
  ]},
  { g: "DATA PROTECTION", items: [
    { id: "envelope_enc", icon: Layers, label: "Envelope Encryption" },
    { id: "tde", icon: Database, label: "Database TDE" },
    { id: "tfe", icon: Lock, label: "File Encryption (TFE)" },
  ]},
  { g: "INFRASTRUCTURE", items: [
    { id: "hsm", icon: Cpu, label: "HSM" },
    { id: "qkd", icon: GitBranch, label: "QKD Interface" },
    { id: "qrng", icon: Atom, label: "QRNG Entropy" },
    { id: "mpc", icon: Cpu, label: "MPC Engine" },
    { id: "cluster", icon: GitBranch, label: "Cluster" },
    { id: "ceremony", icon: GitMerge, label: "Key Ceremony" },
    { id: "mtls_mesh", icon: Network, label: "mTLS Mesh" },
    { id: "dr_drill", icon: Siren, label: "DR Drill" },
    { id: "backup", icon: Archive, label: "Backup & Restore" },
  ]},
  { g: "GOVERNANCE", items: [
    { id: "approvals", icon: CheckCircle2, label: "Approvals" },
    { id: "alerts", icon: Bell, label: "Alert Center" },
    { id: "audit", icon: ScrollText, label: "Audit Log" },
    { id: "dspm", icon: ShieldCheck, label: "Data Security Posture" },
    { id: "data_activity", icon: Activity, label: "Data Activity Monitor" },
    { id: "posture", icon: Gauge, label: "Posture Management" },
    { id: "compliance", icon: ClipboardCheck, label: "Compliance" },
    { id: "sbom", icon: BarChart3, label: "SBOM / CBOM" },
    { id: "crypto_agility", icon: Gauge, label: "Crypto Agility" },
    { id: "leak_scanner", icon: ScanSearch, label: "Leak Scanner" },
    { id: "lineage", icon: GitMerge, label: "Source Traceability" },
    { id: "playbooks", icon: Play, label: "Incident Playbooks" },
  ]},
  { g: "AI", items: [
    { id: "ai", icon: Sparkles, label: "AI Assistant" },
    { id: "ai_protect", icon: ShieldCheck, label: "AI/GenAI Data Protection" },
  ]},
  { g: "ADMIN", items: [
    { id: "admin", icon: Settings, label: "Administration" },
    { id: "webhooks", icon: Webhook, label: "Webhooks & SIEM" },
    { id: "devsecops", icon: GitBranch, label: "DevSecOps / IaC" },
    { id: "docs", icon: FileText, label: "Documentation" },
  ]}
];

const SUB_PANES: Record<string, any[]> = {
  workbench: [
    { id: "crypto", label: "Crypto Console", hint: "Interactive cryptographic operations and algorithm console", icon: Zap },
    { id: "restapi", label: "REST API", hint: "Authenticated API explorer and endpoint documentation", icon: FileText },
    { id: "tokenize", label: "Tokenize / Mask / Redact", hint: "Vault and vaultless tokenization with masking/redaction", icon: VenetianMask, feature: "data_protection" },
    { id: "dataenc", label: "Data Encryption", hint: "Field-level, envelope, searchable and FPE crypto", icon: Database, feature: "data_protection" },
    { id: "payment", label: "Payment Crypto", hint: "TR-31, PIN, CVV, MAC and ISO20022 operations", icon: CreditCard, feature: "payment_crypto" }
  ],
  dataprotection: [
    { id: "fieldenc", label: "Field Encryption", hint: "Wrapper registration, challenge-response and local crypto lease control", icon: KeyRound, feature: "data_protection" },
    { id: "dataenc-policy", label: "Data Encryption Policy", hint: "Policy controls only for data encryption interfaces", icon: List, feature: "data_protection" },
    { id: "token-policy", label: "Token / Mask / Redact Policy", hint: "Policy controls only for tokenization, masking and redaction", icon: VenetianMask, feature: "data_protection" },
    { id: "payment-policy", label: "Payment Policy", hint: "Policy controls only for payment cryptography operations", icon: CreditCard, feature: "payment_crypto" },
    { id: "pkcs11", label: "PKCS#11 / JCA", hint: "SDK providers, mechanism usage and client telemetry", icon: Plug }
  ],
  cloudctl: [
    { id: "byok", label: "BYOK", hint: "Cloud provider key import and sync", icon: Cloud, feature: "cloud_byok" },
    { id: "hyok", label: "HYOK", hint: "Hold-your-own-key policy and cryptographic controls", icon: ShieldCheck, feature: "hyok_proxy" }
  ],
  ekm: [
    { id: "db", label: "EKM for DBs", hint: "MSSQL / Oracle TDE agents", icon: Database, feature: "ekm_database" },
    { id: "bitlocker", label: "BitLocker", hint: "Windows endpoint key lifecycle", icon: Lock, feature: "ekm_database" },
    { id: "kmip", label: "KMIP", hint: "Profiles, clients, mTLS onboarding", icon: Link, feature: "kmip_server" }
  ],
  certs: [
    { id: "cert-overview", label: "Certificate Operations", hint: "CA hierarchy, issuance, signing and certificate lifecycle", icon: FileText, feature: "certs" },
    { id: "cert-enrollment", label: "Enrollment Protocols", hint: "ACME, EST, SCEP, CMPv2 and runtime mTLS enrollment settings", icon: Link, feature: "certs" }
  ],
  hsm: [
    { id: "hsm-aws", label: "AWS CloudHSM", hint: "Cluster endpoint, slot mapping and crypto user binding", icon: Cloud, feature: "hsm_hardware_or_software" },
    { id: "hsm-azure", label: "Azure Managed HSM", hint: "Managed HSM endpoint mapping and PKCS#11 bridge profile", icon: Cloud, feature: "hsm_hardware_or_software" },
    { id: "hsm-thales", label: "Thales Luna HSM", hint: "NTLS endpoint, Luna slot and partition settings", icon: Cpu, feature: "hsm_hardware_or_software" },
    { id: "hsm-utimaco", label: "Utimaco HSM", hint: "CryptoServer slot/partition profile and provider settings", icon: Cpu, feature: "hsm_hardware_or_software" },
    { id: "hsm-entrust", label: "Entrust nShield HSM", hint: "Security World connector, slot profile and token mapping", icon: ShieldCheck, feature: "hsm_hardware_or_software" },
    { id: "hsm-securosys", label: "Vecta KMS HSM", hint: "Vecta KMS provider, slot and partition configuration", icon: ShieldCheck, feature: "hsm_hardware_or_software" },
    { id: "hsm-generic", label: "Generic PKCS#11 HSM", hint: "Vendor-neutral PKCS#11 library onboarding profile", icon: Plug, feature: "hsm_hardware_or_software" }
  ],
  cluster: [
    { id: "topology", label: "Topology", hint: "Visual cluster map with node connections and health", icon: GitBranch, feature: "clustering" },
    { id: "nodes", label: "Node Management", hint: "Detailed node metrics, role changes, and components", icon: Server, feature: "clustering" },
    { id: "profiles", label: "Deploy Profiles", hint: "Replication profiles with deployment tier presets", icon: Layers, feature: "clustering" },
    { id: "sync", label: "Sync Monitor", hint: "Real-time sync events, checkpoints, and replication lag", icon: RefreshCw, feature: "clustering" },
    { id: "logs", label: "Cluster Logs", hint: "Cluster operation audit log with filtering", icon: ScrollText, feature: "clustering" }
  ],
  admin: [
    { id: "system", label: "System Administration", hint: "Platform health, runtime hardening, FIPS and governance settings", icon: Settings },
    { id: "tenant", label: "Tenant Administration", hint: "Tenant lifecycle disable/delete workflow", icon: Building2 },
    { id: "users", label: "User Management", hint: "User and group administration with role assignments", icon: Users }
  ]
};

export default function VectaDashboardV3Shell(props: Props) {
  const { session: sessionBase, enabledFeatures, alerts, audit, unreadAlerts, onLogout, markAlertsRead } = props;
  const [tab, setTab] = useState(() => {
    try {
      const hash = window.location.hash.replace("#", "");
      if (hash) return hash;
      const stored = localStorage.getItem(TAB_STORAGE_KEY);
      if (stored) return stored;
    } catch {}
    return "home";
  });
  const [collapsed, setCollapsed] = useState(false);
  const [t, setT] = useState(new Date());
  const [tz, setTz] = useState(() => {
    try { return localStorage.getItem(TZ_STORAGE_KEY) || "local"; } catch { return "local"; }
  });
  const [tzOpen, setTzOpen] = useState(false);
  const formattedTime = useMemo(() => {
    if (tz === "local") return t.toLocaleTimeString();
    try { return t.toLocaleTimeString(undefined, { timeZone: tz }); } catch { return t.toLocaleTimeString(); }
  }, [t, tz]);
  const changeTz = useCallback((val: string) => {
    setTz(val);
    setTzOpen(false);
    try { localStorage.setItem(TZ_STORAGE_KEY, val); } catch {}
  }, []);
  const [pinnedTabs, setPinnedTabs] = useState<string[]>(() => {
    try {
      const raw = localStorage.getItem("vecta_pinned_tabs");
      const parsed = JSON.parse(raw || "[]");
      return Array.isArray(parsed) ? parsed.filter((v: any) => typeof v === "string") : [];
    } catch { return []; }
  });

  const togglePin = (tabId: string) => {
    if (tabId === "home") return;
    setPinnedTabs((prev) => {
      const next = prev.includes(tabId) ? prev.filter((id) => id !== tabId) : [...prev, tabId];
      try { localStorage.setItem("vecta_pinned_tabs", JSON.stringify(next)); } catch {}
      return next;
    });
  };
  const [toast, setToast] = useState("");
  const [keyCatalog, setKeyCatalog] = useState<any[]>([]);
  const [tagCatalog, setTagCatalog] = useState<any[]>([]);
  const [fipsMode, setFipsMode] = useState<"enabled" | "disabled">("disabled");
  const [reportedUnread, setReportedUnread] = useState(Number(unreadAlerts || 0));
  const [cliEnabled, setCliEnabled] = useState(false);
  const [tenantOptions, setTenantOptions] = useState<Array<{ id: string; name: string; status?: string }>>([]);
  const [tenantScope, setTenantScope] = useState(String(sessionBase?.tenantId || ""));
  const [subPaneSelection, setSubPaneSelection] = useState<any>(() => ({
    workbench: "crypto",
    dataprotection: "fieldenc",
    cloudctl: "byok",
    ekm: "db",
    certs: "cert-overview",
    hsm: "hsm-generic",
    cluster: "topology",
    admin: "system"
  }));
  const [paletteOpen, setPaletteOpen] = useState(false);

  const session = useMemo(
    () => ({
      ...sessionBase,
      tenantId: String(tenantScope || sessionBase?.tenantId || "").trim() || String(sessionBase?.tenantId || "")
    }),
    [sessionBase, tenantScope]
  );

  useEffect(() => {
    const id = setInterval(() => setT(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  // ⌘K / Ctrl+K — open command palette.
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      const target = e.target as HTMLElement;
      // Don't capture inside text inputs/textareas to avoid interfering with typing.
      if (
        target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.isContentEditable
      ) return;
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  useEffect(() => {
    setTenantScope(String(sessionBase?.tenantId || ""));
  }, [sessionBase?.tenantId, sessionBase?.token]);

  useEffect(() => {
    if (!sessionBase?.token) {
      setTenantOptions([]);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const items = await listAuthTenants(sessionBase);
        if (cancelled) return;
        const rows = (Array.isArray(items) ? items : [])
          .map((item: any) => ({
            id: String(item?.id || "").trim(),
            name: String(item?.name || item?.id || "").trim(),
            status: String(item?.status || "active").trim()
          }))
          .filter((item) => Boolean(item.id));
        setTenantOptions(rows.length ? rows : [{ id: sessionBase.tenantId, name: sessionBase.tenantId, status: "active" }]);
      } catch {
        if (!cancelled) {
          setTenantOptions([{ id: sessionBase.tenantId, name: sessionBase.tenantId, status: "active" }]);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [sessionBase]);

  useEffect(() => {
    let stop = false;
    (async () => {
      try {
        const [keysPage, tags, state] = await Promise.all([
          listKeysPaginated(session, { limit: 100, includeDeleted: true }),
          listTags(session),
          getGovernanceSystemState(session)
        ]);
        if (stop) return;
        setKeyCatalog((Array.isArray(keysPage.items) ? keysPage.items : []).map(toViewKey));
        setTagCatalog(Array.isArray(tags) ? tags : []);
        setFipsMode(normalizeFipsModeValue(String((state as any)?.state?.fips_mode || "disabled")));
      } catch {
        if (!stop) {
          setFipsMode("disabled");
        }
      }
    })();
    return () => {
      stop = true;
    };
  }, [session]);

  useEffect(() => {
    if (!session?.token) { setCliEnabled(false); return; }
    let stop = false;
    (async () => {
      try {
        const status = await getAuthCLIStatus(session);
        if (!stop) setCliEnabled(Boolean(status?.enabled));
      } catch { if (!stop) setCliEnabled(false); }
    })();
    return () => { stop = true; };
  }, [session?.token]);

  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(""), 4000);
    return () => clearTimeout(id);
  }, [toast]);

  useEffect(() => {
    if (!session?.token) {
      setReportedUnread(0);
      return;
    }
    let cancelled = false;
    const pullUnread = async () => {
      try {
        const counts = await getUnreadAlertCounts(session);
        if (cancelled) return;
        const total = Object.values(counts || {}).reduce((sum: number, val: any) => sum + Math.max(0, Number(val || 0)), 0);
        setReportedUnread(total);
      } catch {
        if (!cancelled) setReportedUnread(Number(unreadAlerts || 0));
      }
    };
    void pullUnread();
    const id = setInterval(() => void pullUnread(), 10000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [session?.token, session?.tenantId, unreadAlerts]);

  const navGroups = useMemo(
    () =>
      NAV.map((group) => ({
        ...group,
        items: group.items.filter((item: any) => canSeeTab(String(item?.id || ""), enabledFeatures || new Set<FeatureKey>(), session))
      })).filter((group) => group.items.length > 0),
    [enabledFeatures, session]
  );

  const visibleTabIDs = useMemo(
    () =>
      navGroups.flatMap((group) =>
        (Array.isArray(group?.items) ? group.items : []).map((item: any) => String(item?.id || "")).filter(Boolean)
      ),
    [navGroups]
  );

  useEffect(() => {
    if (!visibleTabIDs.includes(String(tab || ""))) {
      setTab(String(visibleTabIDs[0] || "home"));
    }
  }, [tab, visibleTabIDs]);

  const activePaneItems = (Array.isArray(SUB_PANES[tab]) ? SUB_PANES[tab] : []).filter((item) =>
    canSeeFeature(item?.feature, enabledFeatures || new Set<FeatureKey>(), session)
  );
  const selectedSubRaw = String((subPaneSelection as any)[tab] || "");
  const activeSubPaneSelection = String(
    activePaneItems.some((item) => String(item.id) === selectedSubRaw) ? selectedSubRaw : (activePaneItems[0]?.id || "")
  );
  const globalFipsEnabled = isFipsModeEnabled(fipsMode);

  // Flatten visible nav into command-palette items.
  const paletteItems = useMemo<PaletteItem[]>(
    () =>
      navGroups.flatMap((g: any) =>
        (Array.isArray(g.items) ? g.items : []).map((item: any) => ({
          id: String(item.id),
          label: String(TITLES[item.id] || item.label || item.id),
          group: String(g.g || ""),
          icon: item.icon,
        }))
      ),
    [navGroups]
  );

  const selectTab = (nextTab: string) => {
    setTab(nextTab);
    try { localStorage.setItem(TAB_STORAGE_KEY, nextTab); } catch {}
    try { window.history.replaceState(null, "", `#${nextTab}`); } catch {}
    const paneItems = (Array.isArray(SUB_PANES[nextTab]) ? SUB_PANES[nextTab] : []).filter((item) =>
      canSeeFeature(item?.feature, enabledFeatures || new Set<FeatureKey>(), session)
    );
    if (paneItems.length) {
      setSubPaneSelection((prev: any) => ({ ...prev, [nextTab]: String(prev?.[nextTab] || paneItems[0].id) }));
    }
  };

  // One-time cleanup: strip query params, set hash to current tab
  useEffect(() => {
    try {
      if (window.location.search) {
        window.history.replaceState(null, "", window.location.pathname + `#${tab}`);
      } else if (!window.location.hash) {
        window.history.replaceState(null, "", `#${tab}`);
      }
    } catch {}
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const Tab = TABS[tab] || DashboardTab;

  return (
    <div style={{ display: "flex", height: "100vh", background: C.bg, fontFamily: "'IBM Plex Sans',-apple-system,sans-serif", color: C.text, overflow: "hidden" }}>
      {/* ── Global keyframes + scrollbar + transition helpers ── */}
      <style>{`
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}
        @keyframes slideIn{from{opacity:0;transform:translateX(16px)}to{opacity:1;transform:translateX(0)}}
        @keyframes fadeDown{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
        @keyframes spinArc{to{transform:rotate(360deg)}}
        *::-webkit-scrollbar{width:4px;height:4px}
        *::-webkit-scrollbar-track{background:transparent}
        *::-webkit-scrollbar-thumb{background:${C.border};border-radius:4px}
        *::-webkit-scrollbar-thumb:hover{background:${C.borderHi}}
        .vk-nav-item{transition:background .12s,border-color .12s,color .12s}
        .vk-nav-item:hover .vk-nav-icon{color:${C.accent}!important}
        .vk-nav-item:hover .vk-nav-label{color:${C.text}!important}
        .vk-subcard{transition:border-color .12s,background .12s,box-shadow .12s}
        .vk-subcard:hover{border-color:${C.borderHi}!important;background:rgba(255,255,255,.02)!important}
        .vk-subcard-active{border-color:${C.accent}!important;background:${C.accentDim}!important}
        .vk-icon-btn{transition:border-color .12s,color .12s,background .12s}
        .vk-icon-btn:hover{border-color:${C.borderHi}!important;color:${C.text}!important}
        .vk-topbar-cluster{transition:border-color .12s}
        .vk-topbar-cluster:hover{border-color:${C.borderHi}!important}
        .vk-search-btn{transition:border-color .12s,color .12s}
        .vk-search-btn:hover{border-color:${C.borderHi}!important;color:${C.text}!important}
      `}</style>

      {/* ── Rainbow accent bar (fixed, topmost) ── */}
      <div style={{ position: "fixed", top: 0, left: 0, right: 0, height: 2, zIndex: 9999, background: `linear-gradient(90deg,${C.accent},${C.purple},${C.blue})` }} />

      {/* ══════════════════════════════════════════════
          SIDEBAR
      ══════════════════════════════════════════════ */}
      <div style={{
        width: collapsed ? 60 : 240,
        background: C.sidebar,
        borderRight: `1px solid ${C.border}`,
        display: "flex",
        flexDirection: "column",
        transition: "width .2s cubic-bezier(.4,0,.2,1)",
        flexShrink: 0,
        overflow: "hidden",
        paddingTop: 2,
      }}>
        {/* Brand header */}
        <div style={{
          height: 58,
          borderBottom: `1px solid ${C.border}`,
          display: "flex",
          alignItems: "center",
          justifyContent: collapsed ? "center" : "space-between",
          padding: collapsed ? "0 15px" : "0 14px",
          flexShrink: 0,
          gap: 10,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0, flex: 1 }}>
            <div style={{
              width: 32, height: 32,
              borderRadius: 9,
              background: `linear-gradient(135deg,${C.accent},${C.purple})`,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 15, fontWeight: 800, color: C.bg,
              flexShrink: 0,
              boxShadow: `0 2px 10px rgba(6,214,224,.25)`,
            }}>V</div>
            {!collapsed && (
              <div style={{ overflow: "hidden", flex: 1 }}>
                <div style={{ fontSize: 13, fontWeight: 700, letterSpacing: 1.4, color: C.text, lineHeight: 1.25, whiteSpace: "nowrap" }}>VECTA KMS</div>
                <div style={{ fontSize: 9, color: C.accent, letterSpacing: 1.2, textTransform: "uppercase", opacity: 0.65, lineHeight: 1 }}>Key Management</div>
              </div>
            )}
          </div>
          <button
            onClick={() => setCollapsed((v) => !v)}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className="vk-icon-btn"
            style={{
              width: 22, height: 22, borderRadius: 6,
              border: `1px solid ${C.border}`, background: "transparent",
              color: C.muted, display: "inline-flex", alignItems: "center", justifyContent: "center",
              cursor: "pointer", flexShrink: 0,
            }}
          >
            {collapsed ? <ChevronsRight size={12} strokeWidth={2} /> : <ChevronsLeft size={12} strokeWidth={2} />}
          </button>
        </div>

        {/* Nav items */}
        <div style={{ flex: 1, overflowY: "auto", overflowX: "hidden", padding: "8px 0" }}>
          {navGroups.map((g: any) => (
            <div key={g.g} style={{ marginBottom: 6 }}>
              {!collapsed && (
                <div style={{
                  padding: "10px 16px 4px",
                  fontSize: 9, fontWeight: 700,
                  color: C.muted,
                  textTransform: "uppercase",
                  letterSpacing: 1.8,
                }}>
                  {g.g}
                </div>
              )}
              {g.items.map((it: any) => {
                const isActive = tab === it.id;
                return (
                  <div
                    key={it.id}
                    className="vk-nav-item"
                    onClick={() => selectTab(it.id)}
                    title={collapsed ? it.label : undefined}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 10,
                      padding: collapsed ? "9px 0" : "7px 16px",
                      justifyContent: collapsed ? "center" : "flex-start",
                      cursor: "pointer",
                      background: isActive ? `linear-gradient(90deg,rgba(6,214,224,.1),rgba(6,214,224,.02))` : "transparent",
                      borderLeft: isActive ? `2px solid ${C.accent}` : "2px solid transparent",
                      marginLeft: collapsed ? 8 : 0,
                      marginRight: collapsed ? 8 : 0,
                      borderRadius: collapsed ? 8 : "0 6px 6px 0",
                    }}
                  >
                    <span
                      className="vk-nav-icon"
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        justifyContent: "center",
                        color: isActive ? C.accent : C.muted,
                        flexShrink: 0,
                        width: collapsed ? "100%" : "auto",
                      }}
                    >
                      <it.icon size={16} strokeWidth={isActive ? 2.5 : 2} />
                    </span>
                    {!collapsed && (
                      <span
                        className="vk-nav-label"
                        style={{
                          fontSize: 12,
                          color: isActive ? C.text : C.dim,
                          fontWeight: isActive ? 600 : 400,
                          whiteSpace: "nowrap",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          flex: 1,
                        }}
                      >
                        {it.label}
                      </span>
                    )}
                    {!collapsed && pinnedTabs.includes(it.id) && (
                      <span title="Pinned" style={{
                        width: 5, height: 5, borderRadius: "50%",
                        background: C.accent, flexShrink: 0,
                        boxShadow: `0 0 5px ${C.accent}`,
                      }} />
                    )}
                  </div>
                );
              })}
            </div>
          ))}
        </div>

        {/* User footer */}
        <div style={{
          borderTop: `1px solid ${C.border}`,
          padding: collapsed ? "10px 0" : "10px 12px",
          display: "flex",
          alignItems: "center",
          justifyContent: collapsed ? "center" : "flex-start",
          gap: 10,
          flexShrink: 0,
        }}>
          <div style={{
            width: 30, height: 30,
            borderRadius: 8,
            background: `linear-gradient(135deg,rgba(6,214,224,.15),rgba(167,139,250,.1))`,
            border: `1px solid rgba(6,214,224,.2)`,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 11, fontWeight: 700, color: C.accent,
            flexShrink: 0,
          }}>
            {(session?.username || "NA").slice(0, 2).toUpperCase()}
          </div>
          {!collapsed && (
            <>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: C.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                  {session?.username || "admin"}
                </div>
                <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.5, lineHeight: 1.4 }}>
                  {isSystemAdminSession(session) ? "System Admin" : "Admin"}
                </div>
              </div>
              <button
                onClick={onLogout}
                title="Sign out"
                className="vk-icon-btn"
                style={{
                  width: 26, height: 26,
                  borderRadius: 6,
                  border: `1px solid ${C.border}`,
                  background: "transparent",
                  color: C.muted,
                  display: "inline-flex", alignItems: "center", justifyContent: "center",
                  cursor: "pointer",
                  flexShrink: 0,
                }}
              >
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-label="Sign out">
                  <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
                  <polyline points="16,17 21,12 16,7"/>
                  <line x1="21" y1="12" x2="9" y2="12"/>
                </svg>
              </button>
            </>
          )}
        </div>
      </div>

      {/* ══════════════════════════════════════════════
          MAIN AREA
      ══════════════════════════════════════════════ */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>

        {/* ── Topbar ── */}
        <div style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "0 20px",
          height: 52,
          borderBottom: `1px solid ${C.border}`,
          flexShrink: 0,
          background: C.surface,
          boxShadow: `0 1px 0 ${C.border}, 0 2px 16px rgba(0,0,0,.18)`,
          paddingTop: 2,
        }}>
          {/* Left: page title + pin */}
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 14, fontWeight: 700, color: C.text, letterSpacing: -0.2 }}>{TITLES[tab]}</span>
            {tab !== "home" && (
              <button
                onClick={() => togglePin(tab)}
                title={pinnedTabs.includes(tab) ? "Unpin from Dashboard" : "Pin to Dashboard"}
                style={{
                  display: "inline-flex", alignItems: "center", gap: 4,
                  background: pinnedTabs.includes(tab) ? C.accentDim : "transparent",
                  border: `1px solid ${pinnedTabs.includes(tab) ? C.accent : C.border}`,
                  borderRadius: 6, padding: "3px 8px", cursor: "pointer",
                  color: pinnedTabs.includes(tab) ? C.accent : C.muted,
                  fontSize: 9, fontWeight: 600, letterSpacing: 0.4,
                  transition: "all .15s",
                }}
              >
                {pinnedTabs.includes(tab) ? <PinOff size={10} strokeWidth={2.5} /> : <Pin size={10} strokeWidth={2.5} />}
                {pinnedTabs.includes(tab) ? "Pinned" : "Pin"}
              </button>
            )}
          </div>

          {/* Right: action strip */}
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>

            {/* ⌘K search button */}
            <button
              onClick={() => setPaletteOpen(true)}
              title="Command palette (⌘K)"
              className="vk-search-btn"
              style={{
                display: "inline-flex", alignItems: "center", gap: 7,
                height: 30, padding: "0 10px",
                borderRadius: 8,
                border: `1px solid ${C.border}`,
                background: "transparent",
                color: C.muted,
                cursor: "pointer",
                fontSize: 11,
              }}
            >
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
              </svg>
              <span style={{
                fontSize: 9, background: C.card,
                border: `1px solid ${C.border}`,
                borderRadius: 4, padding: "1px 5px",
                fontFamily: "'IBM Plex Mono',monospace",
                color: C.muted,
              }}>⌘K</span>
            </button>

            {/* FIPS badge */}
            <B c={globalFipsEnabled ? "green" : "blue"} pulse={globalFipsEnabled}>
              {globalFipsEnabled ? "FIPS STRICT" : "STANDARD"}
            </B>

            {/* Tenant selector */}
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, whiteSpace: "nowrap" }}>Tenant</span>
              <Sel w={160} value={String(session?.tenantId || "")} onChange={(e) => setTenantScope(String(e.target.value || ""))} style={{ height: 28, borderRadius: 8, padding: "4px 24px 4px 8px", fontSize: 10 }}>
                {(Array.isArray(tenantOptions) && tenantOptions.length ? tenantOptions : [{ id: String(session?.tenantId || ""), name: String(session?.tenantId || ""), status: "active" }])
                  .filter((item: any) => Boolean(String(item?.id || "").trim()))
                  .map((item: any) => (
                    <option key={String(item.id)} value={String(item.id)}>
                      {`${String(item.name || item.id)} (${String(item.id)})`}
                    </option>
                  ))}
              </Sel>
            </div>

            {/* CLI (system admin only) */}
            {isSystemAdminSession(session) && (
              <Btn small onClick={() => selectTab("admin")} style={cliEnabled ? {} : { opacity: 0.4 }}>
                {cliEnabled ? "CLI" : "CLI (off)"}
              </Btn>
            )}

            {/* Clock + timezone picker */}
            <div style={{ position: "relative" }}>
              <div
                onClick={() => setTzOpen((v) => !v)}
                style={{ display: "flex", alignItems: "center", gap: 4, cursor: "pointer", padding: "3px 8px", borderRadius: 6, border: `1px solid transparent`, transition: "border-color .12s" }}
              >
                <span style={{ fontSize: 11, color: C.accent, fontFamily: "'IBM Plex Mono',monospace" }} title={`Timezone: ${tz === "local" ? "Local" : tz}`}>
                  {formattedTime}
                </span>
                {tz !== "local" && (
                  <span style={{ fontSize: 8, color: C.muted, fontFamily: "'IBM Plex Mono',monospace" }}>{tz.split("/").pop()}</span>
                )}
              </div>
              {tzOpen && (
                <div style={{
                  position: "absolute", top: 32, right: 0, zIndex: 1000,
                  background: C.card, border: `1px solid ${C.border}`,
                  borderRadius: 10, padding: 6, minWidth: 170,
                  boxShadow: "0 12px 36px rgba(0,0,0,.5)",
                  animation: "fadeDown .15s ease-out",
                }}>
                  {COMMON_TIMEZONES.map((item) => (
                    <div key={item.value} onClick={() => changeTz(item.value)} style={{ padding: "6px 10px", fontSize: 11, color: tz === item.value ? C.accent : C.text, cursor: "pointer", borderRadius: 6, background: tz === item.value ? C.accentDim : "transparent", fontWeight: tz === item.value ? 700 : 400 }}>
                      {item.label}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Alert bell */}
            <button
              onClick={() => { selectTab("alerts"); markAlertsRead?.(); }}
              className="vk-icon-btn"
              style={{
                display: "inline-flex", alignItems: "center", justifyContent: "center",
                cursor: "pointer", position: "relative", color: C.dim,
                width: 32, height: 32, borderRadius: 8,
                border: `1px solid ${C.border}`,
                background: "transparent",
              }}
              title="Alert center"
            >
              <Bell size={14} strokeWidth={2} />
              {reportedUnread > 0 && (
                <span style={{
                  position: "absolute", top: 4, right: 4,
                  background: C.red, color: C.white,
                  fontSize: 7, borderRadius: 999,
                  padding: "1px 3px", fontWeight: 700,
                  minWidth: 12, textAlign: "center",
                  border: `1.5px solid ${C.surface}`,
                  lineHeight: 1.4,
                }}>
                  {reportedUnread > 99 ? "99+" : reportedUnread}
                </span>
              )}
            </button>

            {/* User pill */}
            <div
              className="vk-topbar-cluster"
              style={{
                display: "flex", alignItems: "center", gap: 8,
                padding: "4px 6px 4px 8px",
                borderRadius: 8,
                border: `1px solid ${C.border}`,
                background: C.card,
              }}
            >
              <div style={{
                width: 22, height: 22, borderRadius: 5,
                background: `linear-gradient(135deg,rgba(6,214,224,.2),rgba(167,139,250,.15))`,
                border: `1px solid rgba(6,214,224,.25)`,
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 9, fontWeight: 700, color: C.accent,
              }}>
                {(session?.username || "NA").slice(0, 2).toUpperCase()}
              </div>
              <span style={{ fontSize: 11, color: C.dim, maxWidth: 80, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {session?.username || "admin"}
              </span>
              <Btn small onClick={onLogout}>Logout</Btn>
            </div>
          </div>
        </div>

        {/* ── Content row ── */}
        <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>

          {/* Sub-pane module panel */}
          {activePaneItems.length > 0 && (
            <div style={{
              width: 232, flexShrink: 0,
              background: C.surface,
              borderRight: `1px solid ${C.border}`,
              padding: "14px 10px",
              overflowY: "auto",
            }}>
              <div style={{
                fontSize: 9, color: C.muted,
                textTransform: "uppercase", letterSpacing: 1.6,
                marginBottom: 10, padding: "0 2px",
                fontWeight: 700,
              }}>
                {TITLES[tab]}
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                {activePaneItems.map((item: any) => {
                  const isActive = String(activeSubPaneSelection) === String(item.id);
                  const ItemIcon = item.icon || null;
                  return (
                    <div
                      key={String(item.id)}
                      className={`vk-subcard${isActive ? " vk-subcard-active" : ""}`}
                      onClick={() => setSubPaneSelection((prev: any) => ({ ...prev, [tab]: String(item.id) }))}
                      style={{
                        border: `1px solid ${isActive ? C.accent : C.border}`,
                        background: isActive ? C.accentDim : "transparent",
                        borderRadius: 8,
                        padding: "9px 10px",
                        cursor: "pointer",
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
                        {ItemIcon && (
                          <span style={{
                            width: 24, height: 24, borderRadius: 6,
                            border: `1px solid ${isActive ? C.accent : C.border}`,
                            background: isActive ? C.accentDim : C.card,
                            display: "inline-flex", alignItems: "center", justifyContent: "center",
                            color: isActive ? C.accent : C.dim,
                            flexShrink: 0,
                          }}>
                            <ItemIcon size={12} strokeWidth={2} />
                          </span>
                        )}
                        <div style={{
                          fontSize: 11,
                          color: isActive ? C.text : C.dim,
                          fontWeight: isActive ? 600 : 500,
                          lineHeight: 1.25,
                        }}>
                          {String(item.label || item.id)}
                        </div>
                      </div>
                      {item.hint && (
                        <div style={{
                          fontSize: 9, color: C.muted,
                          marginTop: 5, lineHeight: 1.45,
                          paddingLeft: ItemIcon ? 33 : 0,
                        }}>
                          {String(item.hint)}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Tab content */}
          <div style={{ flex: 1, overflowY: "auto", padding: 20 }}>
            <TabErrorBoundary resetKey={`${tab}:${activeSubPaneSelection}`}>
              <Suspense fallback={
                <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 200, color: C.muted, fontSize: 12, gap: 10, flexDirection: "column" }}>
                  <svg style={{ animation: "spinArc 1s linear infinite" }} width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <circle cx="12" cy="12" r="10" stroke={C.border} strokeWidth="2"/>
                    <path d="M12 2a10 10 0 0 1 10 10" stroke={C.accent} strokeWidth="2" strokeLinecap="round"/>
                  </svg>
                  Loading module…
                </div>
              }>
                <Tab
                  session={session}
                  keyCatalog={keyCatalog}
                  setKeyCatalog={setKeyCatalog}
                  tagCatalog={tagCatalog}
                  setTagCatalog={setTagCatalog}
                  alerts={alerts}
                  audit={audit}
                  onToast={setToast}
                  onLogout={onLogout}
                  fipsMode={fipsMode}
                  onFipsModeChange={setFipsMode}
                  onUnreadSync={setReportedUnread}
                  subView={activeSubPaneSelection}
                  onSubViewChange={(next: string) => setSubPaneSelection((prev: any) => ({ ...prev, [tab]: String(next || "") }))}
                  pinnedTabs={pinnedTabs}
                  onTogglePin={togglePin}
                  onNavigate={(tabId: string) => selectTab(tabId)}
                />
              </Suspense>
            </TabErrorBoundary>
          </div>
        </div>
      </div>

      {/* Shell-level toast (distinct from global ToastStack) */}
      {toast && (
        <div style={{
          position: "fixed", right: 16, bottom: 72,
          background: C.surface,
          border: `1px solid ${C.borderHi}`,
          borderRadius: 10,
          padding: "10px 14px",
          fontSize: 12, color: C.text,
          zIndex: 1200, maxWidth: 380,
          boxShadow: "0 8px 28px rgba(0,0,0,.45)",
          animation: "slideIn .2s ease-out",
        }}>
          {toast}
        </div>
      )}

      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        items={paletteItems}
        onSelect={(id) => { selectTab(id); }}
      />
    </div>
  );
}
