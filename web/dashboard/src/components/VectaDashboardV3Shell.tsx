import React, { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import {
  Atom,
  BarChart3,
  Bell,
  Building2,
  CheckCircle2,
  ChevronsLeft,
  ChevronsRight,
  ClipboardCheck,
  Cloud,
  Cpu,
  Database,
  Fingerprint,
  FileText,
  Gauge,
  GitBranch,
  Home as HomeIcon,
  KeyRound,
  LayoutGrid,
  Link,
  List,
  Lock,
  Pin,
  PinOff,
  Plug,
  ScrollText,
  Settings,
  ShieldCheck,
  VenetianMask,
  Zap,
  CreditCard,
  Users,
  Server,
  Layers,
  Moon,
  RefreshCw,
  Sparkles,
  Sun,
  SunMoon
} from "lucide-react";
import type { AuthSession } from "../lib/auth";
import { canAccessModule, isSystemAdminSession, matchesFeatureNeed } from "../config/moduleRegistry";
import type { FeatureKey } from "../config/tabs";
import { getAuthCLIStatus, listAuthTenants } from "../lib/authAdmin";
import { getGovernanceSystemState } from "../lib/governance";
import { listKeys, listKeysPaginated, listTags } from "../lib/keycore";
import { getUnreadAlertCounts } from "../lib/reporting";
import { B, Btn, Sel } from "./v3/legacyPrimitives";
import { isFipsModeEnabled, normalizeFipsModeValue, TabErrorBoundary } from "./v3/runtimeUtils";
import { C } from "./v3/theme";

// Wraps lazy() so a failed chunk load shows a fallback instead of a blank screen
function safeTab<T extends Record<string, any>>(
  importFn: () => Promise<T>,
  pick: keyof T
) {
  return lazy(() =>
    importFn()
      .then((m) => ({ default: m[pick] as React.ComponentType<any> }))
      .catch(() => ({
        default: () => (
          <div style={{ padding: 32, color: "#ef4444", fontFamily: "monospace", fontSize: 13 }}>
            Module failed to load. Refresh the page to retry.
          </div>
        )
      }))
  );
}

// Lazy-loaded tab components for code splitting
const AdminTab            = safeTab(() => import("./v3/tabs/AdminTab"),              "AdminTab");
const AlertsTab           = safeTab(() => import("./v3/tabs/AlertsTab"),             "AlertsTab");
const ClusterTab          = safeTab(() => import("./v3/tabs/ClusterTab"),            "ClusterTab");
const DashboardTab        = safeTab(() => import("./v3/tabs/DashboardTab"),          "DashboardTab");
const GovernanceTab       = safeTab(() => import("./v3/tabs/GovernanceTab"),         "GovernanceTab");
const VaultTab            = safeTab(() => import("./v3/tabs/VaultTab"),              "VaultTab");
const EKMTab              = safeTab(() => import("./v3/tabs/EKMTab"),                "EKMTab");
const DataProtectionTabs  = safeTab(() => import("./v3/tabs/DataProtectionTabs"),    "DataProtectionTab");
const PKCS11Tab           = safeTab(() => import("./v3/tabs/PKCS11Tab"),             "PKCS11Tab");
const CloudKeyControlTab  = safeTab(() => import("./v3/tabs/CloudKeyControlTab"),    "CloudKeyControlTab");
const WorkbenchTab        = safeTab(() => import("./v3/tabs/WorkbenchTab"),          "WorkbenchTab");
const AutokeyTab          = safeTab(() => import("./v3/tabs/AutokeyTab"),            "AutokeyTab");
const ArtifactSigningTab  = safeTab(() => import("./v3/tabs/ArtifactSigningTab"),    "ArtifactSigningTab");
const KeyAccessTab        = safeTab(() => import("./v3/tabs/KeyAccessTab"),          "KeyAccessTab");
const PostQuantumTab      = safeTab(() => import("./v3/tabs/PostQuantumTab"),        "PostQuantumTab");
const ConfidentialComputeTab = safeTab(() => import("./v3/tabs/ConfidentialComputeTab"), "ConfidentialComputeTab");
const WorkloadIdentityTab = safeTab(() => import("./v3/tabs/WorkloadIdentityTab"),   "WorkloadIdentityTab");
const HSMTab              = safeTab(() => import("./v3/tabs/HSMTab"),                "HSMTab");
const CertsTab            = safeTab(() => import("./v3/tabs/CertsTab"),              "CertsTab");
const KeysTab             = safeTab(() => import("./v3/tabs/KeysTab"),               "KeysTab");
const ComplianceTab       = safeTab(() => import("./v3/tabs/ComplianceTab"),         "ComplianceTab");
const SBOMTab             = safeTab(() => import("./v3/tabs/SBOMTab"),               "SBOMTab");
const PostureTab          = safeTab(() => import("./v3/tabs/PostureTab"),            "PostureTab");
const AuditLogTab         = safeTab(() => import("./v3/tabs/AuditLogTab"),           "AuditLogTab");
const MPCTab              = safeTab(() => import("./v3/tabs/MPCTab"),                "MPCTab");
const QKDTab              = safeTab(() => import("./v3/tabs/QKDTab"),                "QKDTab");
const QRNGTab             = safeTab(() => import("./v3/tabs/QRNGTab"),               "QRNGTab");
const DocsViewTab         = safeTab(() => import("./v3/tabs/DocsViewTab"),           "DocsViewTab");
const AITab               = safeTab(() => import("./v3/tabs/AITab"),                 "AITab");

type Props = {
  session: AuthSession;
  enabledFeatures: Set<FeatureKey>;
  alerts: any[];
  audit: any[];
  unreadAlerts: number;
  onLogout: () => void;
  markAlertsRead: () => void;
};

const TAB_STORAGE_KEY   = "vecta_active_tab";
const TZ_STORAGE_KEY    = "vecta_timezone";
const THEME_STORAGE_KEY = "vecta_theme";

const ls = {
  get: (key: string, fallback = "") => { try { return localStorage.getItem(key) ?? fallback; } catch { return fallback; } },
  set: (key: string, val: string)   => {
    try {
      localStorage.setItem(key, val);
    } catch (err) {
      // DOMException: QuotaExceededError — storage full; preference won't persist
      console.warn(`[storage] Failed to persist "${key}":`, err);
    }
  },
  getJSON: <T,>(key: string, fallback: T): T => { try { return JSON.parse(localStorage.getItem(key) || "null") ?? fallback; } catch { return fallback; } }
};


type ThemeMode = "dark" | "light" | "auto";

function resolvedTheme(mode: ThemeMode): "dark" | "light" {
  if (mode !== "auto") return mode;
  const h = new Date().getHours();
  // Light 07:00–19:59, dark 20:00–06:59
  return h >= 7 && h < 20 ? "light" : "dark";
}
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
// Allowlist — prevents storing invalid/malicious timezone strings
const VALID_TIMEZONES = new Set(COMMON_TIMEZONES.map((tz) => tz.value));

// Self-contained clock — own state means it never re-renders the parent shell
function ClockDisplay({ tz, onClick }: { tz: string; onClick: () => void }) {
  const [t, setT] = useState(new Date());
  useEffect(() => {
    const id = setInterval(() => setT(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  const formatted = useMemo(() => {
    if (tz === "local") return t.toLocaleTimeString();
    try { return t.toLocaleTimeString(undefined, { timeZone: tz }); } catch { return t.toLocaleTimeString(); }
  }, [t, tz]);
  return (
    <span onClick={onClick} style={{ fontSize: 11, color: C.accentFg, fontFamily: "'JetBrains Mono',monospace", cursor: "pointer" }} title={`Timezone: ${tz === "local" ? "Local" : tz}`}>{formatted}</span>
  );
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
  vault: VaultTab,
  audit: AuditLogTab,
  certs: CertsTab,
  pqc: PostQuantumTab,
  workbench: WorkbenchTab,
  dataprotection: DataProtectionTabs,
  autokey: AutokeyTab,
  keyaccess: KeyAccessTab,
  signing: ArtifactSigningTab,
  workload: WorkloadIdentityTab,
  cloudctl: CloudKeyControlTab,
  ekm: EKMTab,
  hsm: HSMTab,
  qkd: QKDTab,
  mpc: MPCTab,
  cluster: ClusterTab,
  approvals: GovernanceTab,
  alerts: AlertsTab,
  compliance: ComplianceTab,
  admin: AdminTab,
  ai: AITab
};

const NAV = [
  {
    g: "CORE",
    items: [
      { id: "home",    icon: HomeIcon,  label: "Dashboard" },
      { id: "keys",   icon: KeyRound,  label: "Key Management" },
      { id: "vault",  icon: Lock,      label: "Secret Vault" },
      { id: "audit",  icon: ScrollText, label: "Audit Log" }
    ]
  },
  {
    g: "CRYPTO & PKI",
    items: [
      { id: "certs", icon: FileText, label: "Certificates / PKI" },
      { id: "pqc",   icon: Atom,     label: "Post-Quantum Crypto" }
    ]
  },
  {
    g: "DATA & POLICY",
    items: [
      { id: "dataprotection", icon: ShieldCheck, label: "Data Protection" },
      { id: "autokey",        icon: Layers,      label: "Auto-Provisioning" },
      { id: "keyaccess",      icon: ShieldCheck, label: "Access Justifications" }
    ]
  },
  {
    g: "CLOUD & IDENTITY",
    items: [
      { id: "cloudctl", icon: Cloud,    label: "Cloud Keys (BYOK/HYOK)" },
      { id: "ekm",      icon: Database, label: "EKM" },
      { id: "signing",  icon: FileText, label: "Signing" },
      { id: "workload", icon: Users,    label: "Workload & Identity" }
    ]
  },
  {
    g: "INFRASTRUCTURE",
    items: [
      { id: "hsm",     icon: Cpu,       label: "HSM" },
      { id: "qkd",     icon: GitBranch, label: "Quantum Sources" },
      { id: "mpc",     icon: Cpu,       label: "MPC / FROST" },
      { id: "cluster", icon: GitBranch, label: "Cluster" }
    ]
  },
  {
    g: "GOVERNANCE",
    items: [
      { id: "approvals",  icon: CheckCircle2,   label: "Approvals" },
      { id: "alerts",     icon: Bell,           label: "Alert Center" },
      { id: "compliance", icon: ClipboardCheck, label: "Risk & Compliance" }
    ]
  },
  {
    g: "ADMIN",
    items: [
      { id: "admin",     icon: Settings,   label: "Administration" },
      { id: "workbench", icon: LayoutGrid, label: "Dev Workbench" },
      { id: "ai",        icon: Sparkles,   label: "AI Assistant" }
    ]
  }
];

// Derived from NAV — single source of truth, no separate maintenance needed
const TITLES: Record<string, string> = Object.fromEntries(
  NAV.flatMap((g) => g.items).map((it) => [it.id, it.label])
);

const SUB_PANES: Record<string, any[]> = {
  workbench: [
    { id: "crypto", label: "Crypto Console", hint: "Interactive cryptographic operations and algorithm console", icon: Zap },
    { id: "restapi", label: "REST API", hint: "Authenticated API explorer and endpoint documentation", icon: FileText },
    { id: "tokenize", label: "Tokenize / Mask / Redact", hint: "Vault and vaultless tokenization with masking/redaction", icon: VenetianMask, feature: "data_protection" },
    { id: "dataenc", label: "Data Encryption", hint: "Field-level, envelope, searchable and FPE crypto", icon: Database, feature: "data_protection" },
    { id: "payment", label: "Payment Crypto", hint: "TR-31, PIN blocks, ISO 20022 and payment HSM operations", icon: CreditCard, feature: "payment_crypto" }
  ],
  dataprotection: [
    { id: "fieldenc", label: "Field Encryption", hint: "Wrapper registration, challenge-response and local crypto lease control", icon: KeyRound, feature: "data_protection" },
    { id: "dataenc-policy", label: "Data Encryption Policy", hint: "Policy controls only for data encryption interfaces", icon: List, feature: "data_protection" },
    { id: "token-policy", label: "Token / Mask / Redact Policy", hint: "Policy controls only for tokenization, masking and redaction", icon: VenetianMask, feature: "data_protection" },
    { id: "payment-policy", label: "Payment Policy", hint: "KMS-wide payment guardrails for REST and payment interfaces", icon: CreditCard, feature: "payment_crypto" },
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
    { id: "hsm-securosys", label: "Securosys HSM", hint: "Primus PKCS#11 provider, slot ID and partition user configuration", icon: ShieldCheck, feature: "hsm_hardware_or_software" },
    { id: "hsm-generic", label: "Generic PKCS#11 HSM", hint: "Vendor-neutral PKCS#11 library onboarding profile", icon: Plug, feature: "hsm_hardware_or_software" }
  ],
  cluster: [
    { id: "topology", label: "Topology", hint: "Visual cluster map with node connections and health", icon: GitBranch, feature: "clustering" },
    { id: "nodes", label: "Node Management", hint: "Detailed node metrics, role changes, and components", icon: Server, feature: "clustering" },
    { id: "profiles", label: "Deploy Profiles", hint: "Replication profiles with deployment tier presets", icon: Layers, feature: "clustering" },
    { id: "sync", label: "Sync Monitor", hint: "Real-time sync events, checkpoints, and replication lag", icon: RefreshCw, feature: "clustering" },
    { id: "logs", label: "Cluster Logs", hint: "Cluster operation audit log with filtering", icon: ScrollText, feature: "clustering" }
  ],
  compliance: [
    { id: "frameworks", label: "Frameworks & Scoring", hint: "PCI DSS, FIPS, NIST framework scores and gap analysis", icon: ClipboardCheck, feature: "compliance_dashboard" },
    { id: "posture",    label: "Posture & Risk",       hint: "Drift detection, risk findings, blast radius and remediation actions", icon: Gauge, feature: "compliance_dashboard" },
    { id: "sbom",       label: "SBOM / CBOM",          hint: "Software and crypto BOM intelligence for PQC readiness and evidence", icon: BarChart3, feature: "sbom_cbom" }
  ],
  qkd: [
    { id: "qkd-main", label: "QKD Interface",   hint: "Quantum key distribution network links, key rate and session health", icon: GitBranch, feature: "qkd_interface" },
    { id: "qrng",     label: "QRNG Entropy",    hint: "Quantum random number generator entropy sources and health metrics", icon: Atom, feature: "qrng_generator" }
  ],
  workload: [
    { id: "registrations", label: "Workload Registrations", hint: "SPIFFE workload registrations, selectors and key bindings", icon: Users, feature: "workload_identity" },
    { id: "confidential",  label: "Confidential Compute",   hint: "Attested key release for TEE and enclave workloads", icon: Fingerprint, feature: "confidential_compute" }
  ],
  admin: [
    { id: "system", label: "System Administration", hint: "Platform health, runtime hardening, FIPS and governance settings", icon: Settings },
    { id: "tenant", label: "Tenant Administration", hint: "Tenant lifecycle disable/delete workflow", icon: Building2 },
    { id: "users",  label: "User Management",       hint: "User and group administration with role assignments", icon: Users },
    { id: "docs",   label: "Documentation",         hint: "Platform guides, API reference and component documentation", icon: FileText }
  ]
};

export default function VectaDashboardV3Shell(props: Props) {
  const { session: sessionBase, enabledFeatures, alerts, audit, unreadAlerts, onLogout, markAlertsRead } = props;
  const [tab, setTab] = useState(() => {
    try { const h = window.location.hash.replace("#", ""); if (h) return h; } catch {}
    return ls.get(TAB_STORAGE_KEY) || "home";
  });
  const [collapsed, setCollapsed] = useState(false);
  const [themeMode, setThemeMode] = useState<ThemeMode>(() => (ls.get(THEME_STORAGE_KEY) as ThemeMode) || "dark");
  const [tz, setTz] = useState(() => {
    const stored = ls.get(TZ_STORAGE_KEY) || "local";
    // Reject persisted values that are no longer in our allowlist
    return VALID_TIMEZONES.has(stored) ? stored : "local";
  });
  const [tzOpen, setTzOpen] = useState(false);
  const changeTz = useCallback((val: string) => {
    if (!VALID_TIMEZONES.has(val)) return; // Reject unknown timezones
    setTz(val);
    setTzOpen(false);
    ls.set(TZ_STORAGE_KEY, val);
  }, []);
  const [pinnedTabs, setPinnedTabs] = useState<string[]>(() =>
    ls.getJSON<string[]>("vecta_pinned_tabs", []).filter((v: any) => typeof v === "string")
  );

  const togglePin = (tabId: string) => {
    if (tabId === "home") return;
    setPinnedTabs((prev) => {
      const next = prev.includes(tabId) ? prev.filter((id) => id !== tabId) : [...prev, tabId];
      ls.set("vecta_pinned_tabs", JSON.stringify(next));
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
    admin: "system",
    compliance: "frameworks",
    qkd: "qkd-main",
    workload: "registrations"
  }));

  const session = useMemo(
    () => ({
      ...sessionBase,
      tenantId: String(tenantScope || sessionBase?.tenantId || "").trim() || String(sessionBase?.tenantId || "")
    }),
    [sessionBase, tenantScope]
  );

  // Apply data-theme to <html>; auto mode re-checks every minute
  useEffect(() => {
    const apply = () => document.documentElement.setAttribute("data-theme", resolvedTheme(themeMode));
    apply();
    if (themeMode === "auto") {
      const id = setInterval(apply, 60000);
      return () => clearInterval(id);
    }
  }, [themeMode]);

  const cycleTheme = () => {
    setThemeMode((prev) => {
      const next: ThemeMode = prev === "dark" ? "light" : prev === "light" ? "auto" : "dark";
      ls.set(THEME_STORAGE_KEY, next);
      return next;
    });
  };

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
        items: group.items.filter((item: any) => canAccessModule(String(item?.id || ""), enabledFeatures || new Set<FeatureKey>(), session))
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

  const features = enabledFeatures || new Set<FeatureKey>();
  const filterPanes = (tabId: string) =>
    (SUB_PANES[tabId] || []).filter((item) => isSystemAdminSession(session) || matchesFeatureNeed(item?.feature, features));
  const activePaneItems = filterPanes(tab);
  const selectedSubRaw = String((subPaneSelection as any)[tab] || "");
  const activeSubPaneSelection = String(
    activePaneItems.some((item) => String(item.id) === selectedSubRaw) ? selectedSubRaw : (activePaneItems[0]?.id || "")
  );
  const globalFipsEnabled = isFipsModeEnabled(fipsMode);

  const selectTab = (nextTab: string) => {
    setTab(nextTab);
    ls.set(TAB_STORAGE_KEY, nextTab);
    try { window.history.replaceState(null, "", `#${nextTab}`); } catch {}
    const panes = filterPanes(nextTab);
    if (panes.length) {
      setSubPaneSelection((prev: any) => ({ ...prev, [nextTab]: String(prev?.[nextTab] || panes[0].id) }));
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

  // Sub-pane overrides: some merged tabs render a different component for a specific sub-view.
  const SUB_OVERRIDES: Record<string, Record<string, React.ComponentType<any>>> = {
    compliance:     { posture: PostureTab, sbom: SBOMTab },
    dataprotection: { pkcs11: PKCS11Tab },
    qkd:            { qrng: QRNGTab },
    workload:       { confidential: ConfidentialComputeTab },
    admin:          { docs: DocsViewTab }
  };
  function resolveTab(tabId: string, subView: string): React.ComponentType<any> {
    return SUB_OVERRIDES[tabId]?.[subView] || TABS[tabId] || DashboardTab;
  }
  const Tab = resolveTab(tab, activeSubPaneSelection);

  return (
    <div style={{ display: "flex", height: "100vh", background: C.bg, fontFamily: "'IBM Plex Sans',-apple-system,sans-serif", color: C.text, overflow: "hidden", paddingTop: 2 }}>
      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}} @keyframes slideIn{from{opacity:0;transform:translateX(20px)}to{opacity:1;transform:translateX(0)}} *::-webkit-scrollbar{width:5px;height:5px} *::-webkit-scrollbar-track{background:transparent} *::-webkit-scrollbar-thumb{background:${C.borderHi};border-radius:3px} *::-webkit-scrollbar-thumb:hover{background:${C.accent}60}`}</style>
      <div style={{ position: "fixed", top: 0, left: 0, right: 0, height: 2, zIndex: 9999, background: `linear-gradient(90deg,${C.accent},${C.purple},${C.blue})` }} />
      <div style={{ width: collapsed ? 56 : 210, background: `linear-gradient(180deg, ${C.sidebar} 0%, ${C.bg} 100%)`, borderRight: `1px solid ${C.border}`, display: "flex", flexDirection: "column", transition: "width .2s", flexShrink: 0, overflow: "hidden", boxShadow: "2px 0 16px rgba(0,0,0,.25)" }}>
        <div style={{ padding: collapsed ? "10px 6px" : "10px 12px 10px 14px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: collapsed ? 6 : 8, minHeight: collapsed ? 66 : 50, justifyContent: collapsed ? "center" : "space-between", flexDirection: collapsed ? "column" : "row" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0, justifyContent: "center", width: collapsed ? "100%" : "auto" }}>
            <div style={{ width: 30, height: 30, borderRadius: 8, background: `linear-gradient(135deg,${C.accent},${C.purple})`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 15, fontWeight: 700, color: C.bg, flexShrink: 0, boxShadow: `0 2px 10px rgba(6,214,224,.35)` }}>V</div>
            {!collapsed && <span style={{ fontSize: 12, fontWeight: 700, letterSpacing: 2, color: C.text, fontFamily: "'Rajdhani',sans-serif" }}>VECTA KMS</span>}
          </div>
          <button
            onClick={() => setCollapsed((v) => !v)}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            style={{ width: collapsed ? 20 : 24, height: collapsed ? 20 : 24, borderRadius: 6, border: `1px solid ${C.border}`, background: "transparent", color: C.dim, display: "inline-flex", alignItems: "center", justifyContent: "center", cursor: "pointer", flexShrink: 0, transition: "border-color .15s, color .15s" }}
            onMouseEnter={(e) => { e.currentTarget.style.borderColor = C.accentFg; e.currentTarget.style.color = C.accentFg; }}
            onMouseLeave={(e) => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.dim; }}
          >
            {collapsed ? <ChevronsRight size={13} strokeWidth={2} /> : <ChevronsLeft size={13} strokeWidth={2} />}
          </button>
        </div>
        <div style={{ flex: 1, overflowY: "auto", padding: "8px 0" }}>
          {navGroups.map((g: any, gi: number) => (
            <div key={g.g} style={{ marginTop: gi > 0 ? 4 : 0 }}>
              {!collapsed && (
                <div style={{ padding: "6px 14px 3px", display: "flex", alignItems: "center", gap: 6 }}>
                  <div style={{ flex: 1, height: 1, background: C.border, opacity: 0.5 }} />
                  <span style={{ fontSize: 8, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 1.5, flexShrink: 0 }}>{g.g}</span>
                </div>
              )}
              {g.items.map((it: any) => (
                <div
                  key={it.id}
                  onClick={() => selectTab(it.id)}
                  style={{ display: "flex", alignItems: "center", gap: 8, padding: collapsed ? "8px" : "7px 14px 7px 12px", cursor: "pointer", background: tab === it.id ? `linear-gradient(90deg, rgba(6,214,224,.13) 0%, rgba(6,214,224,.04) 100%)` : "transparent", borderLeft: tab === it.id ? `3px solid ${C.accent}` : "3px solid transparent", boxShadow: tab === it.id ? `inset 0 0 16px rgba(6,214,224,.05)` : "none", transition: "all .15s" }}
                  title={it.label}
                  onMouseEnter={(e) => { if (tab !== it.id) e.currentTarget.style.background = `rgba(6,214,224,.05)`; }}
                  onMouseLeave={(e) => { if (tab !== it.id) e.currentTarget.style.background = "transparent"; }}
                >
                  <span style={{ display: "inline-flex", alignItems: "center", justifyContent: collapsed ? "center" : "flex-start", color: tab === it.id ? C.accentFg : C.muted, flexShrink: 0, width: collapsed ? "100%" : "auto", filter: tab === it.id ? `drop-shadow(0 0 4px ${C.accent}80)` : "none" }}>
                    <it.icon size={collapsed ? 16 : 14} strokeWidth={tab === it.id ? 2.2 : 1.8} />
                  </span>
                  {!collapsed && <span style={{ fontSize: 11, color: tab === it.id ? C.text : C.dim, fontWeight: tab === it.id ? 600 : 400, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", flex: 1 }}>{it.label}</span>}
                  {!collapsed && pinnedTabs.includes(it.id) && <span title="Pinned to dashboard" style={{ width: 5, height: 5, borderRadius: 3, background: C.accentFg, flexShrink: 0 }} />}
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>

      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "0 20px", height: 50, borderBottom: `1px solid ${C.border}`, flexShrink: 0, background: `linear-gradient(180deg, ${C.surface} 0%, ${C.bg} 100%)`, boxShadow: `0 1px 0 ${C.border}, 0 4px 20px rgba(0,0,0,.3)` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 15, fontWeight: 700, color: C.text, letterSpacing: -0.4 }}>{TITLES[tab]}</span>
            {tab !== "home" && (
              <button
                onClick={() => togglePin(tab)}
                title={pinnedTabs.includes(tab) ? "Unpin from Dashboard" : "Pin to Dashboard"}
                style={{ display: "inline-flex", alignItems: "center", gap: 4, background: pinnedTabs.includes(tab) ? C.accentDim : "transparent", border: `1px solid ${pinnedTabs.includes(tab) ? C.accent : C.border}`, borderRadius: 6, padding: "3px 7px", cursor: "pointer", color: pinnedTabs.includes(tab) ? C.accentFg : C.muted, fontSize: 9, fontWeight: 600, letterSpacing: 0.3, transition: "all .15s" }}
              >
                {pinnedTabs.includes(tab) ? <PinOff size={11} strokeWidth={2} /> : <Pin size={11} strokeWidth={2} />}
                {pinnedTabs.includes(tab) ? "Pinned" : "Pin"}
              </button>
            )}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            {/* Theme toggle: cycles dark → light → auto */}
            <button
              onClick={cycleTheme}
              title={themeMode === "dark" ? "Dark theme (click for Light)" : themeMode === "light" ? "Light theme (click for Auto)" : "Auto theme by time (click for Dark)"}
              style={{ display: "inline-flex", alignItems: "center", gap: 5, background: "transparent", border: `1px solid ${C.border}`, borderRadius: 7, padding: "4px 9px", cursor: "pointer", color: C.dim, fontSize: 9, fontWeight: 600, letterSpacing: 0.4, textTransform: "uppercase", transition: "border-color .15s, color .15s" }}
              onMouseEnter={(e) => { e.currentTarget.style.borderColor = C.accentFg; e.currentTarget.style.color = C.accentFg; }}
              onMouseLeave={(e) => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.dim; }}
            >
              {themeMode === "dark"  ? <Moon size={12} strokeWidth={2} />    : null}
              {themeMode === "light" ? <Sun size={12} strokeWidth={2} />     : null}
              {themeMode === "auto"  ? <SunMoon size={12} strokeWidth={2} /> : null}
              <span>{themeMode === "auto" ? "Auto" : themeMode === "light" ? "Light" : "Dark"}</span>
            </button>
            <B c={globalFipsEnabled ? "green" : "blue"} pulse={globalFipsEnabled}>{globalFipsEnabled ? "FIPS STRICT" : "STANDARD MODE"}</B>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8 }}>Tenant</span>
              <Sel w={170} value={String(session?.tenantId || "")} onChange={(e) => setTenantScope(String(e.target.value || ""))} style={{ height: 28, borderRadius: 8, padding: "4px 24px 4px 8px", fontSize: 10 }}>
                {(Array.isArray(tenantOptions) && tenantOptions.length ? tenantOptions : [{ id: String(session?.tenantId || ""), name: String(session?.tenantId || ""), status: "active" }])
                  .filter((item: any) => Boolean(String(item?.id || "").trim()))
                  .map((item: any) => (
                    <option key={String(item.id)} value={String(item.id)}>
                      {`${String(item.name || item.id)} (${String(item.id)})`}
                    </option>
                  ))}
              </Sel>
            </div>
            {isSystemAdminSession(session) && <Btn small onClick={() => selectTab("admin")} style={cliEnabled ? {} : { opacity: 0.4 }}>{cliEnabled ? "CLI" : "CLI (off)"}</Btn>}
            <div style={{ position: "relative" }}>
              <ClockDisplay tz={tz} onClick={() => setTzOpen((v) => !v)} />
              {tz !== "local" && <span style={{ fontSize: 8, color: C.muted, fontFamily: "'JetBrains Mono',monospace", marginLeft: 4 }}>{tz.split("/").pop()}</span>}
              {tzOpen && (
                <div style={{ position: "absolute", top: 22, right: 0, zIndex: 1000, background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 4, minWidth: 160, boxShadow: "0 8px 24px rgba(0,0,0,0.4)" }}>
                  {COMMON_TIMEZONES.map((item) => (
                    <div key={item.value} onClick={() => changeTz(item.value)} style={{ padding: "5px 10px", fontSize: 10, color: tz === item.value ? C.accentFg : C.text, cursor: "pointer", borderRadius: 4, background: tz === item.value ? C.accentDim : "transparent", fontWeight: tz === item.value ? 700 : 400 }}>{item.label}</div>
                  ))}
                </div>
              )}
            </div>
            <span
              onClick={() => {
                selectTab("alerts");
                markAlertsRead?.();
              }}
              style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", cursor: "pointer", position: "relative", color: C.dim }}
            >
              <Bell size={14} strokeWidth={2} />
              <span style={{ position: "absolute", top: -4, right: -6, background: C.red, color: C.white, fontSize: 8, borderRadius: 6, padding: "1px 4px", fontWeight: 700 }}>{String(reportedUnread || 0)}</span>
            </span>
            <div style={{ width: 26, height: 26, borderRadius: 6, background: C.accentDim, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700, color: C.accentFg }}>
              {(session?.username || "NA").slice(0, 2).toUpperCase()}
            </div>
            <Btn small onClick={onLogout}>Logout</Btn>
          </div>
        </div>

        <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
          {activePaneItems.length > 0 && (
            <div style={{ width: 224, flexShrink: 0, background: `linear-gradient(180deg, ${C.surface} 0%, ${C.bg} 100%)`, borderRight: `1px solid ${C.border}`, padding: "12px 8px", overflowY: "auto" }}>
              <div style={{ fontSize: 8, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 1.5, marginBottom: 8, padding: "0 4px" }}>{`${TITLES[tab]} Modules`}</div>
              <div style={{ display: "grid", gap: 4 }}>
                {activePaneItems.map((item: any) => {
                  const isActive = String(activeSubPaneSelection) === String(item.id);
                  const ItemIcon = item.icon || null;
                  return (
                    <div
                      key={String(item.id)}
                      onClick={() => setSubPaneSelection((prev: any) => ({ ...prev, [tab]: String(item.id) }))}
                      style={{ border: `1px solid ${isActive ? C.accent : C.border}`, borderLeft: `3px solid ${isActive ? C.accent : "transparent"}`, background: isActive ? `linear-gradient(135deg, rgba(6,214,224,.12) 0%, rgba(6,214,224,.04) 100%)` : "transparent", borderRadius: 8, padding: "9px 10px", cursor: "pointer", transition: "all .15s", boxShadow: isActive ? `0 2px 12px rgba(6,214,224,.1)` : "none" }}
                      onMouseEnter={(e) => { if (!isActive) e.currentTarget.style.background = `rgba(6,214,224,.04)`; }}
                      onMouseLeave={(e) => { if (!isActive) e.currentTarget.style.background = "transparent"; }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        {ItemIcon && (
                          <span style={{ width: 22, height: 22, borderRadius: 6, border: `1px solid ${isActive ? C.accent : C.border}`, background: isActive ? C.accentDim : C.card, display: "inline-flex", alignItems: "center", justifyContent: "center", color: isActive ? C.accentFg : C.dim, flexShrink: 0 }}>
                            <ItemIcon size={12} strokeWidth={2} />
                          </span>
                        )}
                        <div style={{ fontSize: 11, color: isActive ? C.text : C.dim, fontWeight: isActive ? 700 : 500, lineHeight: 1.2 }}>{String(item.label || item.id)}</div>
                      </div>
                      {item.hint && <div style={{ fontSize: 9, color: C.muted, marginTop: 5, lineHeight: 1.4, paddingLeft: ItemIcon ? 30 : 0 }}>{String(item.hint)}</div>}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>
            <TabErrorBoundary resetKey={`${tab}:${activeSubPaneSelection}`}>
              <Suspense fallback={<div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 200, color: C.dim, fontSize: 12 }}>Loading module...</div>}>
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
        {toast && <div style={{ position: "fixed", right: 16, bottom: 16, background: `linear-gradient(135deg, ${C.surface} 0%, ${C.card} 100%)`, border: `1px solid ${C.borderHi}`, borderLeft: `3px solid ${C.accent}`, borderRadius: 10, padding: "12px 16px", fontSize: 11, color: C.text, zIndex: 1200, maxWidth: 380, animation: "slideIn .2s ease-out", boxShadow: `0 8px 32px rgba(0,0,0,.4), 0 0 0 1px ${C.glow}` }}>{toast}</div>}
      </div>
    </div>
  );
}
