import { useEffect, useMemo, useState } from "react";
import {
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
  Users
} from "lucide-react";
import type { AuthSession } from "../lib/auth";
import { canAccessModule, isSystemAdminSession } from "../config/moduleRegistry";
import type { FeatureKey } from "../config/tabs";
import { listAuthTenants } from "../lib/authAdmin";
import { getGovernanceSystemState } from "../lib/governance";
import { listKeys, listTags } from "../lib/keycore";
import { getUnreadAlertCounts } from "../lib/reporting";
import { B, Btn, Sel } from "./v3/legacyPrimitives";
import { isFipsModeEnabled, normalizeFipsModeValue, TabErrorBoundary } from "./v3/runtimeUtils";
import { C } from "./v3/theme";
import { AdminTab } from "./v3/tabs/AdminTab";
import { AlertsTab } from "./v3/tabs/AlertsTab";
import { ClusterTab } from "./v3/tabs/ClusterTab";
import { DashboardTab } from "./v3/tabs/DashboardTab";
import { GovernanceTab } from "./v3/tabs/GovernanceTab";
import { RestAPITab } from "./v3/tabs/RestAPITab";
import { VaultTab } from "./v3/tabs/VaultTab";
import { EKMTab } from "./v3/tabs/EKMTab";
import { DataEncryptionTab, DataProtectionTab, TokenizeTab } from "./v3/tabs/DataProtectionTabs";
import { PKCS11Tab } from "./v3/tabs/PKCS11Tab";
import { BYOKTab } from "./v3/tabs/BYOKTab";
import { HYOKTab } from "./v3/tabs/HYOKTab";
import { CloudKeyControlTab } from "./v3/tabs/CloudKeyControlTab";
import { WorkbenchTab } from "./v3/tabs/WorkbenchTab";
import { CryptoTab } from "./v3/tabs/CryptoTab";
import { PaymentTab } from "./v3/tabs/PaymentTab";
import { HSMTab } from "./v3/tabs/HSMTab";
import { CertsTab } from "./v3/tabs/CertsTab";
import { KeysTab } from "./v3/tabs/KeysTab";
import { ComplianceTab } from "./v3/tabs/ComplianceTab";
import { SBOMTab } from "./v3/tabs/SBOMTab";
import { PostureTab } from "./v3/tabs/PostureTab";
import { AuditLogTab } from "./v3/tabs/AuditLogTab";
import { MPCTab } from "./v3/tabs/MPCTab";
import { QKDTab } from "./v3/tabs/QKDTab";

type Props = {
  session: AuthSession;
  enabledFeatures: Set<FeatureKey>;
  alerts: any[];
  audit: any[];
  unreadAlerts: number;
  onLogout: () => void;
  markAlertsRead: () => void;
};

const DASHBOARD_TAB_QUERY_KEY = "tab";
const DASHBOARD_SUB_QUERY_KEY = "sub";
const UI_BUILD_ID = "mod-shell-01";

function readLocationState(): { tab: string; sub: string } {
  try {
    const qp = new URLSearchParams(window.location.search);
    return {
      tab: String(qp.get(DASHBOARD_TAB_QUERY_KEY) || "").trim().toLowerCase(),
      sub: String(qp.get(DASHBOARD_SUB_QUERY_KEY) || "").trim()
    };
  } catch {
    return { tab: "", sub: "" };
  }
}

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

const Keys = KeysTab;
const Crypto = CryptoTab;
const Workbench = WorkbenchTab;
const Certs = CertsTab;
const Tokenize = TokenizeTab;
const DataEncryption = DataEncryptionTab;
const DataProtection = DataProtectionTab;
const Payment = PaymentTab;
const BYOK = BYOKTab;
const HYOK = HYOKTab;
const CloudKeyControl = CloudKeyControlTab;
const EKM = EKMTab;
const HSM = HSMTab;
const QKD = QKDTab;
const MPC = MPCTab;
const AuditLog = AuditLogTab;
const Compliance = ComplianceTab;
const Posture = PostureTab;
const SBOM = SBOMTab;
const PKCS11 = PKCS11Tab;

const TABS: Record<string, any> = {
  home: DashboardTab,
  keys: Keys,
  workbench: Workbench,
  crypto: Crypto,
  restapi: RestAPITab,
  vault: VaultTab,
  certs: Certs,
  dataprotection: DataProtection,
  tokenize: Tokenize,
  dataenc: DataEncryption,
  payment: Payment,
  cloudctl: CloudKeyControl,
  byok: BYOK,
  hyok: HYOK,
  ekm: EKM,
  hsm: HSM,
  qkd: QKD,
  mpc: MPC,
  cluster: ClusterTab,
  approvals: GovernanceTab,
  alerts: AlertsTab,
  audit: AuditLog,
  posture: Posture,
  compliance: Compliance,
  sbom: SBOM,
  pkcs11: PKCS11,
  admin: AdminTab
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
  mpc: "MPC Engine",
  cluster: "Cluster",
  approvals: "Approvals",
  alerts: "Alert Center",
  audit: "Audit Log",
  posture: "Posture Management",
  compliance: "Compliance",
  sbom: "SBOM / CBOM",
  pkcs11: "PKCS#11 / JCA",
  admin: "Administration"
};

const NAV = [
  { g: "CORE", items: [{ id: "home", icon: HomeIcon, label: "Dashboard" }, { id: "keys", icon: KeyRound, label: "Key Management" }, { id: "certs", icon: FileText, label: "Certificates / PKI" }, { id: "cloudctl", icon: Cloud, label: "Cloud Key Control" }, { id: "ekm", icon: Database, label: "Enterprise Key Management" }, { id: "vault", icon: Lock, label: "Secret Vault" }, { id: "dataprotection", icon: ShieldCheck, label: "Data Protection" }] },
  { g: "WORKBENCH", items: [{ id: "workbench", icon: LayoutGrid, label: "Workbench" }] },
  { g: "INFRASTRUCTURE", items: [{ id: "hsm", icon: Cpu, label: "HSM" }, { id: "qkd", icon: GitBranch, label: "QKD Interface" }, { id: "mpc", icon: Cpu, label: "MPC Engine" }, { id: "cluster", icon: GitBranch, label: "Cluster" }] },
  { g: "GOVERNANCE", items: [{ id: "approvals", icon: CheckCircle2, label: "Approvals" }, { id: "alerts", icon: Bell, label: "Alert Center" }, { id: "audit", icon: ScrollText, label: "Audit Log" }, { id: "posture", icon: Gauge, label: "Posture Management" }, { id: "compliance", icon: ClipboardCheck, label: "Compliance" }, { id: "sbom", icon: BarChart3, label: "SBOM / CBOM" }] },
  { g: "ADMIN", items: [{ id: "admin", icon: Settings, label: "Administration" }] }
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
    { id: "hsm-securosys", label: "Securosys HSM", hint: "Securosys provider, slot and partition configuration", icon: ShieldCheck, feature: "hsm_hardware_or_software" },
    { id: "hsm-generic", label: "Generic PKCS#11 HSM", hint: "Vendor-neutral PKCS#11 library onboarding profile", icon: Plug, feature: "hsm_hardware_or_software" }
  ],
  cluster: [
    { id: "settings", label: "Cluster Settings", hint: "Replication profiles and existing-instance node controls", icon: Settings, feature: "clustering" },
    { id: "health", label: "Cluster Health", hint: "Live node health view with selective component sync status", icon: Gauge, feature: "clustering" }
  ],
  admin: [
    { id: "system", label: "System Administration", hint: "Platform health, runtime hardening, FIPS and governance settings", icon: Settings },
    { id: "tenant", label: "Tenant Administration", hint: "Tenant lifecycle disable/delete workflow", icon: Building2 },
    { id: "users", label: "User Management", hint: "User and group administration with role assignments", icon: Users }
  ]
};

export default function VectaDashboardV3Shell(props: Props) {
  const { session: sessionBase, enabledFeatures, alerts, audit, unreadAlerts, onLogout, markAlertsRead } = props;
  const locationState = useMemo(() => readLocationState(), []);

  const initialTab = useMemo(() => {
    const requested = String(locationState.tab || "").trim();
    if (requested && Object.prototype.hasOwnProperty.call(TABS, requested)) {
      return requested;
    }
    return "home";
  }, [locationState.tab]);

  const [tab, setTab] = useState(initialTab);
  const [collapsed, setCollapsed] = useState(false);
  const [t, setT] = useState(new Date());
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
  const [tenantOptions, setTenantOptions] = useState<Array<{ id: string; name: string; status?: string }>>([]);
  const [tenantScope, setTenantScope] = useState(String(sessionBase?.tenantId || ""));
  const [subPaneSelection, setSubPaneSelection] = useState<any>(() => {
    const defaults: Record<string, string> = {
      workbench: "crypto",
      dataprotection: "fieldenc",
      cloudctl: "byok",
      ekm: "db",
      certs: "cert-overview",
      hsm: "hsm-generic",
      cluster: "settings",
      admin: "system"
    };
    const requestedSub = String(locationState.sub || "").trim();
    if (requestedSub && initialTab) {
      return { ...defaults, [initialTab]: requestedSub };
    }
    return defaults;
  });

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
        const [keys, tags, state] = await Promise.all([
          listKeys(session, { includeDeleted: true }),
          listTags(session),
          getGovernanceSystemState(session)
        ]);
        if (stop) return;
        setKeyCatalog((Array.isArray(keys) ? keys : []).map(toViewKey));
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

  const openRestApiWindow = () => {
    const url = new URL(window.location.href);
    url.pathname = "/";
    url.search = `?${DASHBOARD_TAB_QUERY_KEY}=workbench&${DASHBOARD_SUB_QUERY_KEY}=restapi`;
    url.hash = "";
    const opened = window.open(url.toString(), "_blank");
    if (!opened) {
      window.location.assign(url.toString());
    }
  };

  const selectTab = (nextTab: string) => {
    setTab(nextTab);
    const paneItems = (Array.isArray(SUB_PANES[nextTab]) ? SUB_PANES[nextTab] : []).filter((item) =>
      canSeeFeature(item?.feature, enabledFeatures || new Set<FeatureKey>(), session)
    );
    if (paneItems.length) {
      setSubPaneSelection((prev: any) => ({ ...prev, [nextTab]: String(prev?.[nextTab] || paneItems[0].id) }));
    }
  };

  useEffect(() => {
    try {
      const currentTab = String(tab || "").trim();
      if (!currentTab) return;
      const qp = new URLSearchParams(window.location.search);
      qp.set(DASHBOARD_TAB_QUERY_KEY, currentTab);
      const currentSub = String(activeSubPaneSelection || "").trim();
      if (currentSub) qp.set(DASHBOARD_SUB_QUERY_KEY, currentSub);
      else qp.delete(DASHBOARD_SUB_QUERY_KEY);
      qp.delete("restapi");
      const qs = qp.toString();
      const nextURL = qs ? `${window.location.pathname}?${qs}` : window.location.pathname;
      const currentURL = `${window.location.pathname}${window.location.search}`;
      if (nextURL !== currentURL) window.history.replaceState(window.history.state, "", nextURL);
    } catch {
      // ignore
    }
  }, [tab, activeSubPaneSelection]);

  const Tab = TABS[tab] || DashboardTab;

  return (
    <div style={{ display: "flex", height: "100vh", background: C.bg, fontFamily: "'IBM Plex Sans',-apple-system,sans-serif", color: C.text, overflow: "hidden", paddingTop: 2 }}>
      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}} @keyframes slideIn{from{opacity:0;transform:translateX(20px)}to{opacity:1;transform:translateX(0)}} *::-webkit-scrollbar{width:5px;height:5px} *::-webkit-scrollbar-track{background:transparent} *::-webkit-scrollbar-thumb{background:${C.border};border-radius:3px}`}</style>
      <div style={{ position: "fixed", top: 0, left: 0, right: 0, height: 2, zIndex: 9999, background: `linear-gradient(90deg,${C.accent},${C.purple},${C.blue})` }} />
      <div style={{ width: collapsed ? 56 : 210, background: C.sidebar, borderRight: `1px solid ${C.border}`, display: "flex", flexDirection: "column", transition: "width .2s", flexShrink: 0, overflow: "hidden" }}>
        <div style={{ padding: collapsed ? "8px 6px" : "8px 10px 8px 14px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: collapsed ? 6 : 8, minHeight: collapsed ? 66 : 44, justifyContent: collapsed ? "center" : "space-between", flexDirection: collapsed ? "column" : "row" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0, justifyContent: "center", width: collapsed ? "100%" : "auto" }}>
            <div style={{ width: 28, height: 28, borderRadius: 7, background: `linear-gradient(135deg,${C.accent},${C.purple})`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, fontWeight: 700, color: C.bg, flexShrink: 0 }}>V</div>
            {!collapsed && <span style={{ fontSize: 13, fontWeight: 700, letterSpacing: 1.5, color: C.text }}>VECTA KMS</span>}
          </div>
          <button
            onClick={() => setCollapsed((v) => !v)}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            style={{ width: collapsed ? 20 : 24, height: collapsed ? 20 : 24, borderRadius: 6, border: `1px solid ${C.border}`, background: "transparent", color: C.dim, display: "inline-flex", alignItems: "center", justifyContent: "center", cursor: "pointer", flexShrink: 0 }}
          >
            {collapsed ? <ChevronsRight size={13} strokeWidth={2} /> : <ChevronsLeft size={13} strokeWidth={2} />}
          </button>
        </div>
        <div style={{ flex: 1, overflowY: "auto", padding: "6px 0" }}>
          {navGroups.map((g: any) => (
            <div key={g.g}>
              {!collapsed && <div style={{ padding: "8px 14px 3px", fontSize: 8, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 1.5 }}>{g.g}</div>}
              {g.items.map((it: any) => (
                <div
                  key={it.id}
                  onClick={() => {
                    if (it.id === "restapi") {
                      openRestApiWindow();
                      return;
                    }
                    selectTab(it.id);
                  }}
                  style={{ display: "flex", alignItems: "center", gap: 8, padding: collapsed ? "8px" : "6px 14px", cursor: "pointer", background: tab === it.id ? `linear-gradient(90deg,${C.accentDim} 0%,rgba(6,214,224,.03) 100%)` : "transparent", borderLeft: tab === it.id ? `2px solid ${C.accent}` : "2px solid transparent", transition: "all .15s" }}
                  title={it.label}
                  onMouseEnter={(e) => { if (tab !== it.id) e.currentTarget.style.background = `rgba(6,214,224,.04)`; }}
                  onMouseLeave={(e) => { if (tab !== it.id) e.currentTarget.style.background = "transparent"; }}
                >
                  <span style={{ display: "inline-flex", alignItems: "center", justifyContent: collapsed ? "center" : "flex-start", color: tab === it.id ? C.accent : C.dim, flexShrink: 0, width: collapsed ? "100%" : "auto" }}>
                    <it.icon size={collapsed ? 16 : 14} strokeWidth={2} />
                  </span>
                  {!collapsed && <span style={{ fontSize: 11, color: tab === it.id ? C.text : C.dim, fontWeight: tab === it.id ? 600 : 400, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", flex: 1 }}>{it.label}</span>}
                  {!collapsed && pinnedTabs.includes(it.id) && <span title="Pinned to dashboard" style={{ width: 5, height: 5, borderRadius: 3, background: C.accent, flexShrink: 0 }} />}
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>

      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "0 20px", height: 46, borderBottom: `1px solid ${C.border}`, flexShrink: 0, background: C.surface, boxShadow: `0 1px 8px rgba(0,0,0,.25)` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 14, fontWeight: 700, color: C.text, letterSpacing: -0.3 }}>{TITLES[tab]}</span>
            {tab !== "home" && (
              <button
                onClick={() => togglePin(tab)}
                title={pinnedTabs.includes(tab) ? "Unpin from Dashboard" : "Pin to Dashboard"}
                style={{ display: "inline-flex", alignItems: "center", gap: 4, background: pinnedTabs.includes(tab) ? C.accentDim : "transparent", border: `1px solid ${pinnedTabs.includes(tab) ? C.accent : C.border}`, borderRadius: 6, padding: "3px 7px", cursor: "pointer", color: pinnedTabs.includes(tab) ? C.accent : C.muted, fontSize: 9, fontWeight: 600, letterSpacing: 0.3, transition: "all .15s" }}
              >
                {pinnedTabs.includes(tab) ? <PinOff size={11} strokeWidth={2} /> : <Pin size={11} strokeWidth={2} />}
                {pinnedTabs.includes(tab) ? "Pinned" : "Pin"}
              </button>
            )}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
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
            <Btn small onClick={() => selectTab("admin")}>CLI</Btn>
            <span style={{ fontSize: 11, color: C.accent, fontFamily: "'JetBrains Mono',monospace" }}>{t.toLocaleTimeString()}</span>
            <span style={{ fontSize: 9, color: C.muted, fontFamily: "'JetBrains Mono',monospace" }}>{UI_BUILD_ID}</span>
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
            <div style={{ width: 26, height: 26, borderRadius: 6, background: C.accentDim, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700, color: C.accent }}>
              {(session?.username || "NA").slice(0, 2).toUpperCase()}
            </div>
            <Btn small onClick={onLogout}>Logout</Btn>
          </div>
        </div>

        <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
          {activePaneItems.length > 0 && (
            <div style={{ width: 220, flexShrink: 0, background: C.surface, borderRight: `1px solid ${C.border}`, padding: "12px 10px", overflowY: "auto" }}>
              <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 10 }}>{`${TITLES[tab]} Modules`}</div>
              <div style={{ display: "grid", gap: 6 }}>
                {activePaneItems.map((item: any) => {
                  const isActive = String(activeSubPaneSelection) === String(item.id);
                  const ItemIcon = item.icon || null;
                  return (
                    <div
                      key={String(item.id)}
                      onClick={() => {
                        if (tab === "workbench" && String(item.id) === "restapi") {
                          openRestApiWindow();
                          return;
                        }
                        setSubPaneSelection((prev: any) => ({ ...prev, [tab]: String(item.id) }));
                      }}
                      style={{ border: `1px solid ${isActive ? C.accent : C.border}`, background: isActive ? C.accentDim : "transparent", borderRadius: 8, padding: "10px 10px", cursor: "pointer" }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        {ItemIcon && (
                          <span style={{ width: 20, height: 20, borderRadius: 999, border: `1px solid ${isActive ? C.accent : C.border}`, background: isActive ? C.accentDim : "transparent", display: "inline-flex", alignItems: "center", justifyContent: "center", color: isActive ? C.accent : C.dim }}>
                            <ItemIcon size={12} strokeWidth={2} />
                          </span>
                        )}
                        <div style={{ fontSize: 11, color: isActive ? C.text : C.dim, fontWeight: isActive ? 700 : 600, lineHeight: 1.2 }}>{String(item.label || item.id)}</div>
                      </div>
                      {item.hint && <div style={{ fontSize: 9, color: C.muted, marginTop: 4, lineHeight: 1.3 }}>{String(item.hint)}</div>}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>
            <TabErrorBoundary resetKey={`${tab}:${activeSubPaneSelection}`}>
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
            </TabErrorBoundary>
          </div>
        </div>
        {toast && <div style={{ position: "fixed", right: 16, bottom: 16, background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 8, padding: "10px 12px", fontSize: 11, color: C.text, zIndex: 1200, maxWidth: 380, animation: "slideIn .2s ease-out" }}>{toast}</div>}
      </div>
    </div>
  );
}
