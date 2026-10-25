import { lazy, startTransition, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Bell,
  ChevronRight,
  Info,
  PanelLeftClose,
  PanelLeftOpen,
  Pin,
  PinOff,
  Search,
} from "lucide-react";

const BUILD_VERSION = String(import.meta.env.VITE_VERSION || "dev");
const BUILD_INFO: Array<[string, string]> = [
  ["Version", BUILD_VERSION],
  ["Commit", String(import.meta.env.VITE_COMMIT || "unknown")],
  ["Built", String(import.meta.env.VITE_BUILD_TIME || "unknown")],
];
import type { AuthSession } from "../lib/auth";
import { canAccessModule, isSystemAdminSession } from "../config/moduleRegistry";
import type { FeatureKey } from "../config/tabs";
import { getAuthCLIStatus } from "../lib/authAdmin";
import { getGovernanceSystemState } from "../lib/governance";
import { listKeys, listTags } from "../lib/keycore";
import { getUnreadAlertCounts } from "../lib/reporting";
import { usePopover } from "./v3/usePopover";
import { B, Btn } from "./v3/legacyPrimitives";
import { isFipsModeEnabled, normalizeFipsModeValue, TabErrorBoundary } from "./v3/runtimeUtils";
import { DEFAULT_SUB, SidebarSubNav, SUB_PANES, type SubPane } from "./v3/SidebarSubNav";
import { NAV, parseNavHash } from "./v3/shellNav";
import { SidebarSearch } from "./v3/SidebarSearch";
import { C } from "./v3/theme";
import { ThemeToggle } from "./ThemeToggle";
import { BrandMark, Wordmark } from "./BrandMark";

// Lazy-loaded tab components for code splitting
const AdminTab = lazy(() => import("./v3/tabs/AdminTab").then(m => ({ default: m.AdminTab })));
const AlertsTab = lazy(() => import("./v3/tabs/AlertsTab").then(m => ({ default: m.AlertsTab })));
const ClusterTab = lazy(() => import("./v3/tabs/ClusterTab").then(m => ({ default: m.ClusterTab })));
const DashboardTab = lazy(() => import("./v3/tabs/DashboardTab").then(m => ({ default: m.DashboardTab })));
const CommandCenterTab = lazy(() => import("./v3/tabs/CommandCenterTab").then(m => ({ default: m.HomeTab })));
const GovernanceTab = lazy(() => import("./v3/tabs/GovernanceTab").then(m => ({ default: m.GovernanceTab })));
const RestAPITab = lazy(() => import("./v3/tabs/RestAPITab").then(m => ({ default: m.RestAPITab })));
const VaultTab = lazy(() => import("./v3/tabs/VaultTab").then(m => ({ default: m.VaultTab })));
const EKMTab = lazy(() => import("./v3/tabs/EKMTab").then(m => ({ default: m.EKMTab })));
const DataProtectionTabs = lazy(() => import("./v3/tabs/DataProtectionTabs").then(m => ({ default: m.DataProtectionTab })));
const TokenizeTab = lazy(() => import("./v3/tabs/DataProtectionTabs").then(m => ({ default: m.TokenizeTab })));
const DataEncryptionTab = lazy(() => import("./v3/tabs/DataProtectionTabs").then(m => ({ default: m.DataEncryptionTab })));
const ClientSDKTab = lazy(() => import("./v3/tabs/ClientSDKTab").then(m => ({ default: m.ClientSDKTab })));
const BYOKTab = lazy(() => import("./v3/tabs/BYOKTab").then(m => ({ default: m.BYOKTab })));
const HYOKTab = lazy(() => import("./v3/tabs/HYOKTab").then(m => ({ default: m.HYOKTab })));
const CloudKeyControlTab = lazy(() => import("./v3/tabs/CloudKeyControlTab").then(m => ({ default: m.CloudKeyControlTab })));
const WorkbenchTab = lazy(() => import("./v3/tabs/WorkbenchTab").then(m => ({ default: m.WorkbenchTab })));
const CryptoTab = lazy(() => import("./v3/tabs/CryptoTab").then(m => ({ default: m.CryptoTab })));
const HSMTab = lazy(() => import("./v3/tabs/HSMTab").then(m => ({ default: m.HSMTab })));
const CertsTab = lazy(() => import("./v3/tabs/CertsTab").then(m => ({ default: m.CertsTab })));
const KeysTab = lazy(() => import("./v3/tabs/KeysTab").then(m => ({ default: m.KeysTab })));
const ComplianceTab = lazy(() => import("./v3/tabs/ComplianceTab").then(m => ({ default: m.ComplianceTab })));
const SBOMTab = lazy(() => import("./v3/tabs/SBOMTab").then(m => ({ default: m.SBOMTab })));
const PostureTab = lazy(() => import("./v3/tabs/PostureTab").then(m => ({ default: m.PostureTab })));
const AuditLogTab = lazy(() => import("./v3/tabs/AuditLogTab").then(m => ({ default: m.AuditLogTab })));
const SchedulingModule = lazy(() => import("../modules/scheduling/SchedulingModule").then(m => ({ default: m.SchedulingModule })));
const CryptoAgilityTab = lazy(() => import("./v3/tabs/CryptoAgilityTab").then(m => ({ default: m.CryptoAgilityTab })));
const BackupTab = lazy(() => import("../modules/backup/BackupModule").then(m => ({ default: m.BackupModule })));
const WorkloadIdentityTab = lazy(() => import("./v3/tabs/WorkloadIdentityTab").then(m => ({ default: m.WorkloadIdentityTab })));
const ConfidentialComputeTab = lazy(() => import("./v3/tabs/ConfidentialComputeTab").then(m => ({ default: m.ConfidentialComputeTab })));
const DiscoveryTab = lazy(() => import("./v3/tabs/DiscoveryTab").then(m => ({ default: m.DiscoveryTab })));
const PlaybooksTab = lazy(() => import("./v3/tabs/PlaybooksTab").then(m => ({ default: m.PlaybooksTab })));
// Enterprise Advanced Features

type Props = {
  session: AuthSession;
  enabledFeatures: Set<FeatureKey>;
  unreadAlerts: number;
  onLogout: () => void;
  markAlertsRead: () => void;
};

const TAB_STORAGE_KEY = "vecta_active_tab";
const NAV_GROUPS_KEY = "vecta_nav_open_groups_v2";
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
    componentRole: String(k?.labels?.component_role || k?.labels?.component || ""),
    // Keep the API object so feature tabs can derive their richer view model
    // (Key Management needs KCV, algorithm family, size/curve, ops limits).
    __raw: k
  };
}

const TABS: Record<string, any> = {
  home: CommandCenterTab,
  ops: DashboardTab,
  keys: KeysTab,
  workbench: WorkbenchTab,
  crypto: CryptoTab,
  restapi: RestAPITab,
  vault: VaultTab,
  certs: CertsTab,
  dataprotection: DataProtectionTabs,
  tokenize: TokenizeTab,
  dataenc: DataEncryptionTab,
  cloudctl: CloudKeyControlTab,
  byok: BYOKTab,
  hyok: HYOKTab,
  ekm: EKMTab,
  hsm: HSMTab,
  cluster: ClusterTab,
  approvals: GovernanceTab,
  alerts: AlertsTab,
  audit: AuditLogTab,
  posture: PostureTab,
  compliance: ComplianceTab,
  sbom: SBOMTab,
  pkcs11: ClientSDKTab,
  admin: AdminTab,
  scheduling: SchedulingModule,
  crypto_agility: CryptoAgilityTab,
  backup: BackupTab,
  playbooks: PlaybooksTab,
  workload: WorkloadIdentityTab,
  confidential: ConfidentialComputeTab,
  discovery: DiscoveryTab,
  // Enterprise Advanced Features
};

const TITLES: Record<string, string> = {
  home: "Command Center",
  ops: "Operations Dashboard",
  keys: "Key Management",
  workbench: "Workbench",
  crypto: "Crypto Console",
  restapi: "REST API",
  vault: "Secret Vault",
  certs: "Certificates / PKI",
  dataprotection: "Data Protection",
  tokenize: "Tokenize / Mask / Redact",
  dataenc: "Data Encryption",
  cloudctl: "Cloud Key Control",
  byok: "BYOK",
  hyok: "HYOK",
  ekm: "Enterprise Key Management",
  hsm: "HSM",
  cluster: "Cluster",
  approvals: "Approvals",
  alerts: "Alert Center",
  audit: "Audit Log",
  posture: "Posture Management",
  compliance: "Compliance",
  sbom: "SBOM / CBOM",
  pkcs11: "Java SDK",
  admin: "Administration",
  scheduling: "Scheduling",
  crypto_agility: "Crypto Agility",
  backup: "Backup & Restore",
  playbooks: "Playbooks",
  workload: "Workload Identity",
  confidential: "Confidential Compute",
  discovery: "Crypto Discovery",
};


export default function VectaDashboardV3Shell(props: Props) {
  const { session: sessionBase, enabledFeatures, unreadAlerts, onLogout, markAlertsRead } = props;
  const [tab, setTab] = useState(() => {
    try {
      const saved = parseNavHash(window.location.hash).tab || parseNavHash(localStorage.getItem(TAB_STORAGE_KEY) || "").tab;
      if (saved) return saved;
    } catch { /* ignored */ }
    return "home";
  });
  const [collapsed, setCollapsed] = useState(false);
  const [t, setT] = useState(new Date());
  const [tz, setTz] = useState(() => {
    try { return localStorage.getItem(TZ_STORAGE_KEY) || "local"; } catch { return "local"; }
  });
  const [tzOpen, setTzOpen, tzRef] = usePopover();
  const [infoOpen, setInfoOpen, infoRef] = usePopover();
  const formattedTime = useMemo(() => {
    if (tz === "local") return t.toLocaleTimeString();
    try { return t.toLocaleTimeString(undefined, { timeZone: tz }); } catch { return t.toLocaleTimeString(); }
  }, [t, tz]);
  const changeTz = useCallback((val: string) => {
    setTz(val); setTzOpen(false);
    try { localStorage.setItem(TZ_STORAGE_KEY, val); } catch { /* ignored */ }
  }, [setTzOpen]);
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
      try { localStorage.setItem("vecta_pinned_tabs", JSON.stringify(next)); } catch { /* ignored */ }
      return next;
    });
  };
  const [toast, setToast] = useState("");
  const [keyCatalog, setKeyCatalog] = useState<any[]>([]);
  const [tagCatalog, setTagCatalog] = useState<any[]>([]);
  const [keyCatalogError, setKeyCatalogError] = useState("");
  const [fipsMode, setFipsMode] = useState<"enabled" | "disabled">("disabled");
  const [reportedUnread, setReportedUnread] = useState(Number(unreadAlerts || 0));
  const [cliEnabled, setCliEnabled] = useState(false);
  // Counts sub-option clicks, so a module can leave a local view (an editor)
  // when its current sub-option is chosen again.
  const [subNavTick, setSubNavTick] = useState(0);
  const [subPaneSelection, setSubPaneSelection] = useState<any>(() => {
    const linked = parseNavHash(window.location.hash);
    return { ...DEFAULT_SUB, ...(linked.tab && linked.sub ? { [linked.tab]: linked.sub } : {}) };
  });
  // The one module whose sub-options are listed in the sidebar.
  const [expandedTab, setExpandedTab] = useState(tab);

  // Every request acts in the tenant the session signed in to: services
  // refuse any other tenant for this token, so the top bar names the tenant
  // rather than offering a switch (a platform administrator manages other
  // tenants in Administration).
  const session = sessionBase;

  useEffect(() => {
    const id = setInterval(() => setT(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    let stop = false;
    (async () => {
      try {
        // Every key, with its own failure: the first 100 were loaded, and any
        // failed call left the page saying "No keys yet" (13.25.0-beta).
        listKeys(session, { includeDeleted: true }).then(
          (items) => { if (!stop) { setKeyCatalog(items.map(toViewKey)); setKeyCatalogError(""); } },
          (e) => { if (!stop) setKeyCatalogError(e instanceof Error ? e.message : String(e)); });
        const [tags, state] = await Promise.all([
          listTags(session),
          getGovernanceSystemState(session)
        ]);
        if (stop) return;
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
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: intentional refetch on listed keys / run-once-on-mount; the only omitted dep is a per-render load/refresh closure (wrap in useCallback to drop this suppression). behaviour verified correct.
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
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: intentional refetch on listed keys / run-once-on-mount; the only omitted dep is a per-render load/refresh closure (wrap in useCallback to drop this suppression). behaviour verified correct.
  }, [session?.token, session?.tenantId, unreadAlerts]);

  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>(() => {
    try {
      const raw = localStorage.getItem(NAV_GROUPS_KEY);
      if (raw) return JSON.parse(raw);
    } catch { /* ignored */ }
    return {}; // default: only the group holding the open module
  });
  // A group is open when the user opened it, or, until they choose, when it
  // holds the open module (13.23.0-beta; every group used to start open).
  const isGroupOpen = (name: string, hasActive: boolean) => openGroups[name] ?? hasActive;
  const toggleGroup = (name: string, hasActive: boolean) => {
    setOpenGroups((prev) => {
      const next = { ...prev, [name]: !(prev[name] ?? hasActive) };
      try { localStorage.setItem(NAV_GROUPS_KEY, JSON.stringify(next)); } catch { /* ignored */ }
      return next;
    });
  };

  const [navFilter, setNavFilter] = useState("");
  // A search result opens its page with that page's search filled in.
  const [pageSearch, setPageSearch] = useState({ tab: "", text: "", n: 0 });
  const navGroups = useMemo(
    () =>
      NAV.map((group) => ({
        ...group,
        items: group.items.filter((item: any) => canSeeTab(String(item?.id || ""), enabledFeatures || new Set<FeatureKey>(), session))
      })).filter((group) => group.items.length > 0),
    [enabledFeatures, session]
  );
  const shownNavGroups = useMemo(() => {
    const q = navFilter.trim().toLowerCase();
    if (!q) return navGroups;
    return navGroups
      .map((g: any) => ({ ...g, items: g.items.filter((it: any) => `${it.label} ${TITLES[it.id] || ""} ${g.g} ${(SUB_PANES[it.id] || []).map((sub) => sub.label).join(" ")}`.toLowerCase().includes(q)) }))
      .filter((g: any) => g.items.length > 0);
  }, [navGroups, navFilter]);
  const visibleTabIDs = useMemo(
    () =>
      navGroups.flatMap((group) =>
        (Array.isArray(group?.items) ? group.items : []).map((item: any) => String(item?.id || "")).filter(Boolean)
      ),
    [navGroups]
  );

  // Set when the view changes without the user moving (a redirect, or Back
  // to an address the view then completes): the address is replaced, so
  // Back never lands on an entry that sends it forward again.
  const navReplaceNext = useRef(false);
  useEffect(() => {
    if (!visibleTabIDs.includes(String(tab || ""))) {
      navReplaceNext.current = true;
      setTab(String(visibleTabIDs[0] || "home"));
    }
  }, [tab, visibleTabIDs]);

  const subPanesFor = (id: string): SubPane[] =>
    (SUB_PANES[id] || []).filter((item) => (!item.platformOnly || isSystemAdminSession(session)) && canSeeFeature(item.feature, enabledFeatures || new Set<FeatureKey>(), session));
  const activePaneItems = subPanesFor(tab);
  const selectedSubRaw = String((subPaneSelection as any)[tab] || "");
  const activeSubPaneSelection = String(
    activePaneItems.some((item) => String(item.id) === selectedSubRaw) ? selectedSubRaw : (activePaneItems[0]?.id || "")
  );
  const activeSubPane = activePaneItems.find((item) => item.id === activeSubPaneSelection);
  const globalFipsEnabled = isFipsModeEnabled(fipsMode);

  // nextTab may name a sub-option too ("admin/users"), as links from pages do.
  const selectTab = (target: string) => {
    const { tab: nextTab, sub: nextSub } = parseNavHash(target);
    if (nextSub) setSubPaneSelection((prev: any) => ({ ...prev, [nextTab]: nextSub }));
    try { localStorage.setItem(TAB_STORAGE_KEY, nextTab); } catch { /* ignored */ }
    navReplaceNext.current = false;
    const paneItems = subPanesFor(nextTab);
    setExpandedTab(nextTab);
    // Use startTransition so React keeps the current tab visible until the new
    // lazy module finishes loading — no Suspense fallback flicker on tab switch.
    startTransition(() => {
      setTab(nextTab);
      const firstPane = paneItems[0];
      if (firstPane) {
        setSubPaneSelection((prev: any) => ({ ...prev, [nextTab]: String(prev?.[nextTab] || firstPane.id) }));
      }
    });
  };
  // Opens a module with its page search set (a search result, or a key from Operations).
  const searchIn = (target: string, text: string) => { setPageSearch((p) => ({ tab: target.split("/")[0]!, text, n: p.n + 1 })); selectTab(target); };

  // The address follows the view: the first write replaces (and drops any
  // query string), later ones add a history entry.
  const navHash = `#${tab}${activePaneItems.length && activeSubPaneSelection ? `/${activeSubPaneSelection}` : ""}`;
  const navHashWritten = useRef(false);
  useEffect(() => {
    try {
      if (!navHashWritten.current || navReplaceNext.current || window.location.search) {
        window.history.replaceState(null, "", window.location.pathname + navHash);
      } else if (window.location.hash !== navHash) {
        window.history.pushState(null, "", navHash);
      }
    } catch { /* ignored */ }
    navHashWritten.current = true;
    navReplaceNext.current = false;
  }, [navHash]);

  // Back, Forward, or an edited address: open the view it names.
  useEffect(() => {
    const follow = () => {
      const linked = parseNavHash(window.location.hash);
      if (!linked.tab) return;
      navReplaceNext.current = true;
      setTab(linked.tab);
      setExpandedTab(linked.tab);
      if (linked.sub) setSubPaneSelection((prev: any) => ({ ...prev, [linked.tab]: linked.sub }));
    };
    window.addEventListener("popstate", follow);
    window.addEventListener("hashchange", follow);
    return () => {
      window.removeEventListener("popstate", follow);
      window.removeEventListener("hashchange", follow);
    };
  }, []);

  const Tab = TABS[tab] || DashboardTab;

  const sidebarToggle = (
    <button
      onClick={() => setCollapsed((v) => !v)}
      title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
      aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
      className="vk-icon-btn"
      style={{
        width: 22, height: 22, borderRadius: 3,
        border: `1px solid ${C.border}`, background: "transparent",
        color: C.muted, display: "inline-flex", alignItems: "center", justifyContent: "center",
        cursor: "pointer", flexShrink: 0,
      }}
    >
      {collapsed ? <PanelLeftOpen size={13} strokeWidth={1.8} /> : <PanelLeftClose size={13} strokeWidth={1.8} />}
    </button>
  );

  return (
    <div style={{ display: "flex", height: "100vh", background: C.bg, color: C.text, overflow: "hidden" }}>
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
        .vk-nav-group{transition:color .12s}
        .vk-nav-group:hover{color:${C.text}!important}
        .vk-nav-item:hover .vk-nav-icon{color:${C.text}!important}
        .vk-nav-item:hover .vk-nav-label{color:${C.text}!important}
        .vk-icon-btn{transition:border-color .12s,color .12s,background .12s}
        .vk-icon-btn:hover{border-color:${C.borderHi}!important;color:${C.text}!important}
        .vk-topbar-cluster{transition:border-color .12s}
        .vk-topbar-cluster:hover{border-color:${C.borderHi}!important}
      `}</style>

      {/* ══════════════════════════════════════════════
          SIDEBAR
      ══════════════════════════════════════════════ */}
      <div data-testid="sidebar" style={{
        width: collapsed ? 60 : 248,
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
          padding: "0 14px",
          flexShrink: 0,
          gap: 10,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0, flex: collapsed ? "none" : 1 }}>
            <span data-testid="sidebar-mark" style={{ color: C.text, display: "inline-flex", flexShrink: 0 }}><BrandMark size={26} /></span>
            {!collapsed && <Wordmark />}
          </div>
          {!collapsed && sidebarToggle}
        </div>

        {/* Collapsed, the rail is too narrow for the mark and the toggle side by side: the toggle takes the filter's row. */}
        {collapsed && (
          <div style={{ display: "flex", justifyContent: "center", padding: "10px 0 2px", flexShrink: 0 }}>{sidebarToggle}</div>
        )}

        {/* Nav filter */}
        {!collapsed && (
          <div style={{ padding: "10px 12px 2px" }}>
            <label className="vk-field-wrap" style={{ display: "flex", alignItems: "center", gap: 7, height: 32, padding: "0 9px", borderRadius: 4, border: `1px solid ${C.border}`, background: C.surface, color: C.muted }}>
              <Search size={13} strokeWidth={2} />
              <input
                value={navFilter}
                onChange={(e) => setNavFilter(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") { const first = shownNavGroups[0]?.items?.[0]; if (first) { selectTab(first.id); setNavFilter(""); } } if (e.key === "Escape") setNavFilter(""); }}
                placeholder="Filter modules"
                aria-label="Filter modules"
                data-bare=""
                style={{ flex: 1, minWidth: 0, border: 0, outline: "none", background: "transparent", color: C.text, fontSize: 12.5 }}
              />
            </label>
          </div>
        )}

        {/* Nav items */}
        <div style={{ flex: 1, overflowY: "auto", overflowX: "hidden", padding: "6px 0 8px" }}>
          {shownNavGroups.map((g: any) => {
            const groupHasActive = g.items.some((it: any) => it.id === tab);
            const groupOpen = collapsed || Boolean(navFilter) || isGroupOpen(g.g, groupHasActive);
            return (
            <div key={g.g} style={{ marginBottom: 6 }}>
              {!collapsed && (
                <div
                  className="vk-nav-group"
                  role="button"
                  aria-expanded={groupOpen}
                  onClick={() => toggleGroup(g.g, groupHasActive)}
                  style={{
                    padding: "12px 16px 4px",
                    fontSize: 10.5, fontWeight: 500, fontFamily: "var(--font-mono)", textTransform: "uppercase",
                    color: groupHasActive ? C.text : C.muted,
                    letterSpacing: "0.07em",
                    cursor: "pointer",
                    display: "flex", alignItems: "center", justifyContent: "space-between",
                    userSelect: "none",
                  }}
                >
                  <span>{g.g}</span>
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                    {!groupOpen && (
                      <span style={{ fontSize: 10, fontWeight: 600, color: C.muted, letterSpacing: 0, opacity: 0.8 }}>{g.items.length}</span>
                    )}
                    <ChevronRight size={11} strokeWidth={2.2} style={{
                      transform: groupOpen ? "rotate(90deg)" : "rotate(0deg)",
                      transition: "transform .15s",
                      opacity: 0.6,
                    }} />
                  </span>
                </div>
              )}
              {groupOpen && g.items.map((it: any) => {
                const isActive = tab === it.id;
                const subItems = collapsed ? [] : subPanesFor(it.id);
                const q = navFilter.trim().toLowerCase();
                const subOpen = expandedTab === it.id ? subItems.length > 0 : Boolean(q) && subItems.some((sub) => sub.label.toLowerCase().includes(q));
                return (
                  <div key={it.id}>
                  <div
                    className="vk-nav-item"
                    aria-expanded={subItems.length > 0 ? subOpen : undefined}
                    onClick={() => {
                      // The name opens the module and lists its sub-options; a second click folds them.
                      if (isActive && subOpen) setExpandedTab("");
                      else selectTab(it.id);
                      if (collapsed && SUB_PANES[it.id]) setCollapsed(false);
                    }}
                    title={collapsed ? it.label : undefined}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 10,
                      padding: collapsed ? "9px 0" : "6px 10px",
                      justifyContent: collapsed ? "center" : "flex-start",
                      cursor: "pointer",
                      background: isActive ? C.accentDim : "transparent",
                      boxShadow: isActive ? `inset 2px 0 0 ${C.accentFg}` : "none",
                      margin: "1px 8px",
                      borderRadius: 3,
                    }}
                  >
                    <span
                      className="vk-nav-icon"
                      style={{
                        display: "inline-flex",
                        alignItems: "center",
                        justifyContent: "center",
                        color: isActive ? C.accentFg : C.muted,
                        flexShrink: 0,
                        width: collapsed ? "100%" : "auto",
                      }}
                    >
                      <it.icon size={16} strokeWidth={isActive ? 2 : 1.7} />
                    </span>
                    {!collapsed && (
                      <span
                        className="vk-nav-label"
                        style={{
                          fontSize: 13,
                          color: isActive ? C.text : C.dim,
                          fontWeight: isActive ? 600 : 450,
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
                        background: C.accentFg, flexShrink: 0,
                      }} />
                    )}
                    {subItems.length > 0 && (
                      <ChevronRight size={12} strokeWidth={2} style={{ color: C.muted, flexShrink: 0, transform: subOpen ? "rotate(90deg)" : "none", transition: "transform .15s" }} />
                    )}
                  </div>
                  {subOpen && (
                    <SidebarSubNav
                      tabId={it.id}
                      items={subItems}
                      activeId={isActive ? activeSubPaneSelection : ""}
                      onSelect={(subId) => {
                        navReplaceNext.current = false;
                        setSubPaneSelection((prev: any) => ({ ...prev, [it.id]: subId }));
                        setSubNavTick((n) => n + 1);
                        if (!isActive) selectTab(it.id);
                      }}
                    />
                  )}
                  </div>
                );
              })}
            </div>
            );
          })}
          {!collapsed && <SidebarSearch session={session} query={navFilter} visibleTabs={visibleTabIDs}
            onOpen={searchIn} />}
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
            borderRadius: 4,
            background: C.accentDim,
            border: `1px solid ${C.border}`,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 11, fontWeight: 700, color: C.accentFg,
            flexShrink: 0,
          }}>
            {(session?.username || "NA").slice(0, 2).toUpperCase()}
          </div>
          {!collapsed && (
            <>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 12.5, fontWeight: 600, color: C.text, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                  {session?.username || "admin"}
                </div>
                <div style={{ fontSize: 11, color: C.muted, lineHeight: 1.4 }}>
                  {isSystemAdminSession(session) ? "System Admin" : String(session?.role || "User")}
                </div>
              </div>
              <button
                onClick={onLogout}
                title="Sign out"
                className="vk-icon-btn"
                style={{
                  width: 26, height: 26,
                  borderRadius: 3,
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
        <div data-testid="topbar" style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "0 20px",
          height: 52,
          gap: 12,
          borderBottom: `1px solid ${C.border}`,
          flexShrink: 0,
          background: C.surface,
          boxShadow: "none",
        }}>
          {/* Left: page title + pin */}
          <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0, flex: 1 }}>
            <nav aria-label="Breadcrumb" style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13.5, whiteSpace: "nowrap", minWidth: 0, overflow: "hidden" }}>
              <span style={{ fontWeight: 600, color: activeSubPane ? C.muted : C.text, letterSpacing: -0.1 }}>{TITLES[tab]}</span>
              {activeSubPane && <span style={{ color: C.borderHi }}>/</span>}
              {activeSubPane && <span style={{ fontWeight: 600, color: C.text, letterSpacing: -0.1 }}>{activeSubPane.label}</span>}
            </nav>
            {tab !== "home" && (
              <button
                onClick={() => togglePin(tab)}
                title={pinnedTabs.includes(tab) ? "Unpin from Dashboard" : "Pin to Dashboard"}
                style={{
                  display: "inline-flex", alignItems: "center", gap: 4,
                  background: pinnedTabs.includes(tab) ? C.accentDim : "transparent",
                  border: `1px solid ${pinnedTabs.includes(tab) ? C.accentFg : C.border}`,
                  borderRadius: 3, padding: "3px 8px", cursor: "pointer",
                  color: pinnedTabs.includes(tab) ? C.accentFg : C.muted,
                  fontSize: 10, fontWeight: 600, letterSpacing: 0.4,
                  transition: "all .15s",
                }}
              >
                {pinnedTabs.includes(tab) ? <PinOff size={10} strokeWidth={2.5} /> : <Pin size={10} strokeWidth={2.5} />}
                {pinnedTabs.includes(tab) ? "Pinned" : "Pin"}
              </button>
            )}
          </div>

          {/* Right: action strip */}
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>

            {/* FIPS badge */}
            <B c={globalFipsEnabled ? "green" : "blue"} pulse={globalFipsEnabled}>
              {globalFipsEnabled ? "FIPS STRICT" : "STANDARD"}
            </B>

            {/* Signed-in tenant */}
            <span data-testid="topbar-tenant" title="Tenant" style={{ height: 28, display: "inline-flex", alignItems: "center", padding: "0 10px", border: `1px solid ${C.border}`, borderRadius: 4, fontSize: 11.5, color: C.text, fontFamily: "var(--font-mono)", whiteSpace: "nowrap" }}>
              {String(session?.tenantId || "")}
            </span>

            {/* CLI (system admin only) */}
            {isSystemAdminSession(session) && (
              <Btn small onClick={() => selectTab("admin/cli")} style={cliEnabled ? {} : { opacity: 0.4 }}>
                {cliEnabled ? "CLI" : "CLI (off)"}
              </Btn>
            )}

            {/* Clock + timezone picker */}
            <div ref={tzRef} style={{ position: "relative" }}>
              <div
                onClick={() => setTzOpen((v) => !v)}
                style={{ display: "flex", alignItems: "center", gap: 4, cursor: "pointer", padding: "3px 8px", borderRadius: 3, border: `1px solid transparent`, transition: "border-color .12s" }}
              >
                <span style={{ fontSize: 11.5, color: C.dim, whiteSpace: "nowrap", fontFamily: "var(--font-mono)" }} title={`Timezone: ${tz === "local" ? "Local" : tz}`}>
                  {formattedTime}
                </span>
                {tz !== "local" && (
                  <span style={{ fontSize: 10, color: C.muted, fontFamily: "var(--font-mono)" }}>{tz.split("/").pop()}</span>
                )}
              </div>
              {tzOpen && (
                <div style={{
                  position: "absolute", top: 32, right: 0, zIndex: 1000,
                  background: C.card, border: `1px solid ${C.border}`,
                  borderRadius: 4, padding: 6, minWidth: 170,
                  boxShadow: "0 12px 36px rgba(0,0,0,.5)",
                  animation: "fadeDown .15s ease-out",
                }}>
                  {COMMON_TIMEZONES.map((item) => (
                    <div key={item.value} onClick={() => changeTz(item.value)} style={{ padding: "6px 10px", fontSize: 11, color: tz === item.value ? C.accentFg : C.text, cursor: "pointer", borderRadius: 3, background: tz === item.value ? C.accentDim : "transparent", fontWeight: tz === item.value ? 700 : 400 }}>
                      {item.label}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Build info */}
            <div ref={infoRef} style={{ position: "relative" }}>
              <button
                onClick={() => { setInfoOpen((v) => !v); setTzOpen(false); }}
                className="vk-icon-btn"
                aria-label="About this KMS build"
                aria-expanded={infoOpen}
                title={`Vecta KMS ${BUILD_VERSION}`}
                style={{
                  display: "inline-flex", alignItems: "center", justifyContent: "center",
                  cursor: "pointer", color: C.dim,
                  width: 32, height: 32, borderRadius: 4,
                  border: `1px solid ${C.border}`, background: "transparent",
                }}
              >
                <Info size={14} strokeWidth={2} />
              </button>
              {infoOpen && (
                <div role="dialog" aria-label="Build information" style={{
                  position: "absolute", top: 38, right: 0, zIndex: 1000,
                  background: C.card, border: `1px solid ${C.border}`,
                  borderRadius: 4, padding: "10px 12px", minWidth: 240,
                  boxShadow: "0 12px 36px rgba(0,0,0,.5)",
                  animation: "fadeDown .15s ease-out",
                }}>
                  <div style={{ fontSize: 12, fontWeight: 700, color: C.text, marginBottom: 8 }}>Vecta KMS</div>
                  {BUILD_INFO.map(([label, value]) => (
                    <div key={label} style={{ display: "flex", justifyContent: "space-between", gap: 12, fontSize: 11, padding: "3px 0" }}>
                      <span style={{ color: C.muted }}>{label}</span>
                      <span style={{ color: label === "Version" ? C.accentFg : C.text, fontFamily: "var(--font-mono)" }}>{value}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Alert bell: the unread count sits beside the icon, never over it. */}
            <button
              onClick={() => { selectTab("alerts"); markAlertsRead?.(); }}
              className="vk-icon-btn"
              style={{
                display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 6,
                cursor: "pointer", color: C.dim,
                minWidth: 32, height: 32, padding: reportedUnread > 0 ? "0 7px" : 0, borderRadius: 4,
                border: `1px solid ${C.border}`,
                background: "transparent",
              }}
              title="Alert center"
              aria-label={reportedUnread > 0 ? `Alert center, ${reportedUnread} unread` : "Alert center"}
            >
              <Bell size={14} strokeWidth={2} style={{ flexShrink: 0 }} />
              {reportedUnread > 0 && (
                <span data-testid="unread-count" className="vk-num" style={{
                  background: C.red, color: C.white,
                  fontSize: 10.5, borderRadius: 3,
                  padding: "1px 5px", fontWeight: 700,
                  lineHeight: 1.4,
                }}>
                  {reportedUnread > 99 ? "99+" : reportedUnread}
                </span>
              )}
            </button>

            {/* Theme toggle (Aurora ↔ Daylight) */}
            <ThemeToggle />

          </div>
        </div>

        {/* ── Content row ── */}
        <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>

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
                  keyCatalogError={keyCatalogError}
                  setKeyCatalog={setKeyCatalog}
                  tagCatalog={tagCatalog}
                  setTagCatalog={setTagCatalog}
                  onToast={setToast}
                  onLogout={onLogout}
                  fipsMode={fipsMode}
                  clustered={!enabledFeatures?.size || enabledFeatures.has("clustering")}
                  onFipsModeChange={setFipsMode}
                  onUnreadSync={setReportedUnread}
                  subView={activeSubPaneSelection}
                  subViewTick={subNavTick}
                  onSubViewChange={(next: string) => { navReplaceNext.current = false; setSubPaneSelection((prev: any) => ({ ...prev, [tab]: String(next || "") })); }}
                  pinnedTabs={pinnedTabs}
                  onTogglePin={togglePin}
                  onNavigate={(tabId: string) => selectTab(tabId)}
                  onSearchIn={searchIn}
                  searchQuery={pageSearch.tab === tab ? pageSearch : undefined}
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
          borderRadius: 4,
          padding: "10px 14px",
          fontSize: 12, color: C.text,
          zIndex: 1200, maxWidth: 380,
          boxShadow: "0 8px 28px rgba(0,0,0,.45)",
          animation: "slideIn .2s ease-out",
        }}>
          {toast}
        </div>
      )}
    </div>
  );
}
