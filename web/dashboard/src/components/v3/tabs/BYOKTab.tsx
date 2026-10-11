// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { useEffect, useMemo, useState } from "react";
import { LayoutGrid, List, MoreVertical, RefreshCcw, MapPin, Database, ChevronDown, ChevronRight } from "lucide-react";
import {
  deleteCloudAccount,
  discoverCloudInventory,
  listCloudAccounts,
  listCloudBindings,
  listCloudRegionMappings,
  setCloudRegionMapping,
  normalizeCloudProvider,
  registerCloudAccount,
  syncCloudKeys,
  type CloudAccount,
  type DeleteCloudAccountResult,
  type CloudKeyBinding,
  type CloudProvider,
  type CloudSyncJob,
  type CloudInventoryItem,
  type CloudRegionMapping
} from "../../../lib/cloud";
import { CredentialPicker } from "../CredentialPicker";
import { BYOKConsole } from "./byok/Console";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, FG, Inp, Modal, Row2, Section, Sel, usePromptDialog } from "../legacyPrimitives";

function normalizeKeyState(state: string): string {
  const raw = String(state || "").toLowerCase().trim();
  if (raw === "destroyed" || raw === "deleted") return "deleted";
  if (raw === "destroy-pending" || raw === "delete-pending" || raw === "deletion-pending") return "destroy-pending";
  if (raw === "preactive" || raw === "pre-active") return "pre-active";
  if (raw === "retired" || raw === "deactivated") return "deactivated";
  if (raw === "generation" || raw === "generated") return "pre-active";
  return raw || "unknown";
}

function formatAgo(value: string): string {
  const raw = String(value || "").trim();
  if (!raw) return "-";
  const ts = new Date(raw).getTime();
  if (!Number.isFinite(ts)) return raw;
  const diffMs = Date.now() - ts;
  if (diffMs < 30_000) return "now";
  const sec = Math.floor(diffMs / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

function formatDate(value: string): string {
  const raw = String(value || "").trim();
  if (!raw) return "-";
  const ts = new Date(raw);
  if (Number.isNaN(ts.getTime())) return raw;
  return ts.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function copyToClipboard(text: string) {
  try { navigator.clipboard.writeText(text); } catch { /* ignore */ }
}

const CLOUD_PROVIDER_LABELS: Record<string, string> = { aws: "AWS KMS", azure: "Azure Key Vault", gcp: "Google Cloud KMS", oci: "Oracle Cloud Vault", salesforce: "Salesforce Shield", alibaba: "Alibaba Cloud KMS" };
const CLOUD_PROVIDER_ORDER = ["aws", "azure", "gcp", "oci", "salesforce", "alibaba"];


const PROVIDER_REGIONS: Record<string, string[]> = {
  aws: ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"],
  azure: ["eastus", "eastus2", "westus", "westus2", "westeurope", "northeurope", "southeastasia", "eastasia"],
  gcp: ["us-central1", "us-east1", "us-west1", "europe-west1", "europe-west4", "asia-east1", "asia-southeast1"],
  oci: ["us-ashburn-1", "us-phoenix-1", "eu-frankfurt-1", "eu-amsterdam-1", "ap-tokyo-1", "ap-mumbai-1"],
  salesforce: ["na", "eu", "ap"],
  alibaba: ["cn-hangzhou", "cn-shanghai", "cn-beijing", "cn-shenzhen", "cn-hongkong", "ap-southeast-1", "eu-central-1", "us-east-1"],
};

export const BYOKTab = ({ session, keyCatalog, onToast, onNavigate }) => {
  const [modal, setModal] = useState<null | "add" | "import" | "region" | "inventory">(null);
  const [accounts, setAccounts] = useState<CloudAccount[]>([]);
  const [bindings, setBindings] = useState<CloudKeyBinding[]>([]);
  const [regionMappings, setRegionMappings] = useState<CloudRegionMapping[]>([]);
  const [inventoryItems, setInventoryItems] = useState<CloudInventoryItem[]>([]);
  const [inventoryCounts, setInventoryCounts] = useState<Record<string, number>>({});
  const [accountProbeByID, setAccountProbeByID] = useState<Record<string, boolean>>({});
  const [accountProbeErrorByID, setAccountProbeErrorByID] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [syncingAccount, setSyncingAccount] = useState("");
  const [deletingAccount, setDeletingAccount] = useState("");
  const [submittingAdd, setSubmittingAdd] = useState(false);
  const [submittingRegion, setSubmittingRegion] = useState(false);
  const [connectorView, setConnectorView] = useState<"cards" | "list">("cards");
  const [connectorSearch, setConnectorSearch] = useState("");
  const [connectorMenu, setConnectorMenu] = useState("");
  const [expandedProvider, setExpandedProvider] = useState<string | null>(null);
  const [inventoryLoading, setInventoryLoading] = useState(false);
  const [inventoryProvider, setInventoryProvider] = useState<string>("");
  const [inventoryAccountId, setInventoryAccountId] = useState<string>("");

  const [addProvider, setAddProvider] = useState<CloudProvider>("aws");
  const [addName, setAddName] = useState("");
  const [addDefaultRegion, setAddDefaultRegion] = useState("");
  const [addCredential, setAddCredential] = useState("");

  const [regionProvider, setRegionProvider] = useState<CloudProvider>("aws");
  const [regionVecta, setRegionVecta] = useState("");
  const [regionCloud, setRegionCloud] = useState("");

  const promptDialog = usePromptDialog();

  const refresh = async (silent = false) => {
    if (!session?.token) {
      setAccounts([]); setBindings([]); setInventoryCounts({});
      setAccountProbeByID({}); setAccountProbeErrorByID({});
      setRegionMappings([]);
      return;
    }
    if (!silent) setRefreshing(true);
    try {
      const [acctItems, bindingItems, mappings] = await Promise.all([
        listCloudAccounts(session),
        listCloudBindings(session, { limit: 500, offset: 0 }),
        listCloudRegionMappings(session).catch(() => [])
      ]);
      setAccounts(Array.isArray(acctItems) ? acctItems : []);
      setBindings(Array.isArray(bindingItems) ? bindingItems : []);
      setRegionMappings(Array.isArray(mappings) ? mappings : []);
      const counts: Record<string, number> = {};
      const probe: Record<string, boolean> = {};
      const probeErr: Record<string, string> = {};
      await Promise.all((Array.isArray(acctItems) ? acctItems : []).map(async (acct) => {
        try {
          const items = await discoverCloudInventory(session, { provider: acct.provider as CloudProvider, accountId: acct.id });
          counts[acct.id] = Array.isArray(items) ? items.length : 0;
          probe[acct.id] = true;
          probeErr[acct.id] = "";
        } catch (error) {
          counts[acct.id] = 0;
          probe[acct.id] = false;
          probeErr[acct.id] = errMsg(error);
        }
      }));
      setInventoryCounts(counts);
      setAccountProbeByID(probe);
      setAccountProbeErrorByID(probeErr);
    } catch (error) {
      onToast?.(`BYOK refresh failed: ${errMsg(error)}`);
    } finally {
      if (!silent) setRefreshing(false);
    }
  };

  useEffect(() => {
    if (!session?.token) return;
    setLoading(true);
    void refresh(true).finally(() => setLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: intentional refetch on listed keys / run-once-on-mount; the only omitted dep is a per-render load/refresh closure (wrap in useCallback to drop this suppression). behaviour verified correct.
  }, [session?.token, session?.tenantId]);

  // A credential belongs to one provider.
  useEffect(() => { setAddCredential(""); }, [addProvider]);

  const providerCards = useMemo(() => {
    const availableProviders = Array.from(new Set((Array.isArray(accounts) ? accounts : []).map((acct) => String(acct.provider || "").toLowerCase()).filter(Boolean)));
    const orderedProviders = CLOUD_PROVIDER_ORDER.filter((provider) => availableProviders.includes(provider));
    return orderedProviders.map((provider) => {
      const acctList = (Array.isArray(accounts) ? accounts : []).filter((acct) => String(acct.provider || "").toLowerCase() === provider);
      const bindingList = (Array.isArray(bindings) ? bindings : []).filter((binding) => String(binding.provider || "").toLowerCase() === provider);
      const regions = Array.from(new Set([
        ...acctList.map((acct) => String(acct.default_region || "").trim()).filter(Boolean),
        ...bindingList.map((binding) => String(binding.region || "").trim()).filter(Boolean)
      ]));
      const inventoryTotal = acctList.reduce((sum, acct) => sum + Number(inventoryCounts[acct.id] || 0), 0);
      const connectedCount = acctList.filter((acct) => accountProbeByID[acct.id] === true).length;
      const failedCount = acctList.filter((acct) => accountProbeByID[acct.id] === false).length;
      const hasProbePending = acctList.some((acct) => typeof accountProbeByID[acct.id] === "undefined");
      const firstProbeError = (acctList.map((acct) => String(accountProbeErrorByID[acct.id] || "").trim()).find(Boolean) || "");
      const hasFailure = bindingList.some((binding) => String(binding.sync_status || "").toLowerCase() === "failed");
      const hasAnyBindings = bindingList.length > 0;
      const allSynced = hasAnyBindings && bindingList.every((binding) => String(binding.sync_status || "").toLowerCase() === "synced");
      let stateLabel = "Configured";
      let stateColor: "blue" | "green" | "amber" | "red" = "blue";
      if (connectedCount > 0 && failedCount === 0) { stateLabel = "Connected"; stateColor = "green"; }
      else if (connectedCount > 0 && failedCount > 0) { stateLabel = "Partial"; stateColor = "amber"; }
      else if (failedCount > 0 && !hasProbePending) { stateLabel = "Auth Failed"; stateColor = "red"; }
      if (stateColor !== "red" && allSynced) { stateLabel = "Synced"; stateColor = "green"; }
      else if (stateColor !== "red" && hasFailure) { stateLabel = "Partial"; stateColor = "amber"; }
      else if (stateColor !== "red" && hasAnyBindings && connectedCount > 0) { stateLabel = "Syncing"; stateColor = "blue"; }
      return { provider, accounts: acctList, bindings: bindingList, regions, stateLabel, stateColor, inventoryTotal, probeError: firstProbeError };
    });
  }, [accounts, bindings, inventoryCounts, accountProbeByID, accountProbeErrorByID]);

  const normalizedConnectorSearch = String(connectorSearch || "").trim().toLowerCase();
  const filteredProviderCards = useMemo(() => {
    if (!normalizedConnectorSearch) return providerCards;
    return providerCards.filter((card) => {
      const providerLabel = String(CLOUD_PROVIDER_LABELS[card.provider] || card.provider).toLowerCase();
      const regions = String((card.regions || []).join(" ")).toLowerCase();
      const accountNames = String((card.accounts || []).map((acct: any) => String(acct?.name || "")).join(" ")).toLowerCase();
      return providerLabel.includes(normalizedConnectorSearch) || regions.includes(normalizedConnectorSearch) || accountNames.includes(normalizedConnectorSearch);
    });
  }, [providerCards, normalizedConnectorSearch]);

  const runSync = async (provider: string, accountId: string) => {
    if (!session?.token) return;
    setSyncingAccount(accountId || provider);
    try {
      const job: CloudSyncJob = await syncCloudKeys(session, { provider: provider as CloudProvider, accountId, mode: "full" });
      onToast?.(`${CLOUD_PROVIDER_LABELS[provider] || provider} sync ${String(job?.status || "completed")}.`);
      await refresh(true);
    } catch (error) {
      onToast?.(`Cloud sync failed: ${errMsg(error)}`);
    } finally {
      setSyncingAccount("");
    }
  };

  const deleteConnector = async (provider: string, account: CloudAccount | undefined) => {
    if (!session?.token) return;
    const accountId = String(account?.id || "").trim();
    if (!accountId) { onToast?.("No connector selected to delete."); return; }
    const providerLabel = CLOUD_PROVIDER_LABELS[provider] || provider;
    const accountName = String(account?.name || accountId);
    const ok = await promptDialog.confirm({
      title: "Delete Cloud Connector",
      message: `Delete connector "${accountName}" for ${providerLabel}?\n\nThis permanently removes:\n• All key bindings for this connector\n• All sync job history\n• Region mappings (if last connector for this provider)`,
      confirmLabel: "Delete Connector",
      cancelLabel: "Cancel",
      danger: true
    });
    if (!ok) return;
    setConnectorMenu("");
    setDeletingAccount(accountId);
    try {
      const out: DeleteCloudAccountResult = await deleteCloudAccount(session, accountId);
      onToast?.(`Connector deleted: ${accountName}`);
      await refresh(true);
    } catch (error) {
      onToast?.(`Delete connector failed: ${errMsg(error)}`);
    } finally {
      setDeletingAccount("");
    }
  };

  const submitAddConnector = async () => {
    if (!session?.token) return;
    const name = String(addName || "").trim();
    if (!name) { onToast?.("Connector name is required."); return; }
    if (!addCredential) { onToast?.("Choose the provider's credential."); return; }
    setSubmittingAdd(true);
    try {
      const account = await registerCloudAccount(session, {
        provider: addProvider,
        name,
        defaultRegion: String(addDefaultRegion || "").trim(),
        connectionId: addCredential
      });
      onToast?.(`Cloud connector added: ${account.name}`);
      setModal(null);
      setAddName("");
      await refresh(true);
    } catch (error) {
      onToast?.(`Add connector failed: ${errMsg(error)}`);
    } finally {
      setSubmittingAdd(false);
    }
  };

  const submitRegionMapping = async () => {
    if (!session?.token) return;
    const vecta = String(regionVecta || "").trim();
    const cloud = String(regionCloud || "").trim();
    if (!vecta || !cloud) { onToast?.("Both Vecta region and cloud region are required."); return; }
    setSubmittingRegion(true);
    try {
      await setCloudRegionMapping(session, { provider: regionProvider, vectaRegion: vecta, cloudRegion: cloud });
      onToast?.(`Region mapping saved: ${vecta} → ${cloud}`);
      setRegionVecta("");
      setRegionCloud("");
      await refresh(true);
    } catch (error) {
      onToast?.(`Region mapping failed: ${errMsg(error)}`);
    } finally {
      setSubmittingRegion(false);
    }
  };

  const openInventory = async (provider: string, accountId: string) => {
    if (!session?.token) return;
    setInventoryProvider(provider);
    setInventoryAccountId(accountId);
    setModal("inventory");
    setInventoryLoading(true);
    try {
      const items = await discoverCloudInventory(session, { provider: provider as CloudProvider, accountId });
      setInventoryItems(Array.isArray(items) ? items : []);
    } catch (error) {
      onToast?.(`Inventory discovery failed: ${errMsg(error)}`);
      setInventoryItems([]);
    } finally {
      setInventoryLoading(false);
    }
  };

  const hasAnyConnector = (Array.isArray(accounts) ? accounts : []).length > 0;
  return <div>
    <BYOKConsole session={session} accounts={accounts} keyCatalog={keyCatalog} onAddConnector={() => setModal("add")} onToast={onToast} />

    {/* === Cloud Connectors === */}
    <Section
      title="Cloud Connectors"
      actions={<div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <Inp style={{ width: 180 }} value={connectorSearch} onChange={(e) => setConnectorSearch(e.target.value)} placeholder="Search provider/region..." />
        <Btn small primary={connectorView === "cards"} onClick={() => setConnectorView("cards")} title="Card view"><LayoutGrid size={12} strokeWidth={2} /></Btn>
        <Btn small primary={connectorView === "list"} onClick={() => setConnectorView("list")} title="List view"><List size={12} strokeWidth={2} /></Btn>
        <Btn small onClick={() => void refresh()} disabled={refreshing || loading}><RefreshCcw size={12} strokeWidth={2} /> Refresh</Btn>
        <Btn small onClick={() => { setRegionProvider("aws"); setModal("region"); }}><MapPin size={12} strokeWidth={2} /> Region Mappings</Btn>
        <Btn small primary onClick={() => setModal("add")}>+ Add Connector</Btn>
      </div>}
    >
      {connectorView === "cards"
        ? <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 10 }}>
          {filteredProviderCards.map((card) => {
            const isExpanded = expandedProvider === card.provider;
            return <Card key={card.provider}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <div style={{ fontSize: 12, color: C.text, fontWeight: 700 }}>{CLOUD_PROVIDER_LABELS[card.provider] || card.provider}</div>
                <B c={card.stateColor}>{card.stateLabel}</B>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "2px 8px", fontSize: 10, marginBottom: 8 }}>
                <span style={{ color: C.muted }}>Accounts</span>
                <span style={{ color: C.text }}>{card.accounts.length}</span>
                <span style={{ color: C.muted }}>Bindings</span>
                <span style={{ color: C.text }}>{card.bindings.length} keys synced</span>
                <span style={{ color: C.muted }}>Cloud keys</span>
                <span style={{ color: C.text }}>{card.inventoryTotal} discovered</span>
                <span style={{ color: C.muted }}>Regions</span>
                <span style={{ color: C.dim, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{card.regions.length ? card.regions.join(", ") : "default"}</span>
              </div>
              {card.probeError && <div style={{ fontSize: 10, color: C.redFg, marginBottom: 6, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }} title={card.probeError}>{card.probeError}</div>}

              {/* Per-account details (expandable) */}
              {card.accounts.length > 1 && (
                <button onClick={() => setExpandedProvider(isExpanded ? null : card.provider)} style={{ background: "transparent", border: "none", color: C.accentFg, cursor: "pointer", fontSize: 10, padding: "4px 0", display: "flex", alignItems: "center", gap: 4 }}>
                  {isExpanded ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
                  {card.accounts.length} accounts
                </button>
              )}
              {isExpanded && card.accounts.map((acct) => (
                <div key={acct.id} style={{ fontSize: 10, padding: "4px 0", borderTop: `1px solid ${C.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <div style={{ color: C.text, fontWeight: 600 }}>{acct.name}</div>
                    <div style={{ color: C.dim }}>{acct.default_region || "default"} · {String(acct.status || "configured")}</div>
                  </div>
                  <div style={{ display: "flex", gap: 4 }}>
                    <span style={{ width: 6, height: 6, borderRadius: 3, background: accountProbeByID[acct.id] === true ? C.green : accountProbeByID[acct.id] === false ? C.red : C.dim }} title={accountProbeByID[acct.id] === true ? "Connected" : accountProbeErrorByID[acct.id] || "Probing..."} />
                  </div>
                </div>
              ))}

              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 6 }}>
                <Btn small onClick={() => {
                  const activeAccount = card.accounts[0];
                  if (activeAccount) void runSync(card.provider, activeAccount.id);
                }} disabled={!card.accounts[0]?.id || syncingAccount === (card.accounts[0]?.id || card.provider) || deletingAccount === card.accounts[0]?.id}>
                  {syncingAccount === (card.accounts[0]?.id || card.provider) ? "Syncing..." : "Sync"}
                </Btn>
                <Btn small onClick={() => { if (card.accounts[0]?.id) void openInventory(card.provider, card.accounts[0].id); }} disabled={!card.accounts[0]?.id}>
                  <Database size={10} strokeWidth={2} /> Inventory
                </Btn>
                <Btn small danger onClick={() => void deleteConnector(card.provider, card.accounts[0])} disabled={!card.accounts[0]?.id || deletingAccount === card.accounts[0]?.id}>
                  {deletingAccount === card.accounts[0]?.id ? "Deleting..." : "Delete"}
                </Btn>
              </div>
            </Card>;
          })}
        </div>
        : <Card style={{ padding: 0, overflow: "visible" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1.2fr .7fr .7fr .7fr .8fr auto", padding: "8px 12px", borderBottom: `1px solid ${C.border}`, fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>
            <div>Provider</div><div>Status</div><div>Accounts</div><div>Bindings</div><div>Regions</div><div>Actions</div>
          </div>
          <div style={{ overflow: "visible" }}>
            {filteredProviderCards.map((card) => {
              const activeAccount = card.accounts[0];
              const accountId = activeAccount?.id || "";
              const menuOpen = connectorMenu === String(card.provider);
              return <div key={card.provider} style={{ display: "grid", gridTemplateColumns: "1.2fr .7fr .7fr .7fr .8fr auto", alignItems: "center", padding: "8px 12px", borderBottom: `1px solid ${C.border}`, fontSize: 10 }}>
                <div style={{ color: C.text, fontWeight: 600 }}>{CLOUD_PROVIDER_LABELS[card.provider] || card.provider}</div>
                <div><B c={card.stateColor}>{card.stateLabel}</B></div>
                <div style={{ color: C.dim }}>{card.accounts.length}</div>
                <div style={{ color: C.dim }}>{String(card.bindings.length)}</div>
                <div style={{ color: C.dim, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{card.regions.length ? card.regions.join(", ") : "-"}</div>
                <div style={{ position: "relative", justifySelf: "end" }}>
                  <button onClick={() => setConnectorMenu(menuOpen ? "" : String(card.provider))} style={{ border: `1px solid ${C.border}`, background: "transparent", color: C.accentFg, borderRadius: 4, padding: "4px 6px", cursor: "pointer" }}>
                    <MoreVertical size={13} strokeWidth={2} />
                  </button>
                  {menuOpen && <div style={{ position: "absolute", right: 0, top: 30, zIndex: 20, minWidth: 150, background: C.surface, border: `1px solid ${C.borderHi}`, borderRadius: 4, padding: 6, display: "grid", gap: 4 }}>
                    <button onClick={() => { setConnectorMenu(""); void runSync(card.provider, accountId); }} disabled={!accountId || syncingAccount === accountId} style={{ textAlign: "left", background: "transparent", border: "none", color: C.text, cursor: "pointer", padding: "6px 8px", borderRadius: 6 }}>Sync Now</button>
                    <button onClick={() => { setConnectorMenu(""); if (accountId) void openInventory(card.provider, accountId); }} disabled={!accountId} style={{ textAlign: "left", background: "transparent", border: "none", color: C.text, cursor: "pointer", padding: "6px 8px", borderRadius: 6 }}>Browse Inventory</button>
                    <button onClick={() => { void deleteConnector(card.provider, activeAccount); }} disabled={!accountId || deletingAccount === accountId} style={{ textAlign: "left", background: "transparent", border: "none", color: C.redFg, cursor: "pointer", padding: "6px 8px", borderRadius: 6 }}>Delete Connector</button>
                  </div>}
                </div>
              </div>;
            })}
            {!filteredProviderCards.length && <div style={{ padding: 12, fontSize: 10, color: C.dim }}>
              {hasAnyConnector ? "No connectors match search." : "No cloud connectors configured. Click + Add Connector to get started."}
            </div>}
          </div>
        </Card>}
      {!filteredProviderCards.length && connectorView === "cards" && <Card><div style={{ fontSize: 10, color: C.dim }}>
        {hasAnyConnector ? "No connectors match search." : "No cloud connectors configured. Click + Add Connector to connect AWS KMS, Azure Key Vault, GCP Cloud KMS, Oracle Vault, or Salesforce."}
      </div></Card>}
    </Section>

    {/* === Region Mappings (inline) === */}
    {(Array.isArray(regionMappings) ? regionMappings : []).length > 0 && (
      <Section title="Region Mappings">
        <Card style={{ padding: 0, overflow: "hidden" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", padding: "8px 12px", borderBottom: `1px solid ${C.border}`, fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>
            <div>Provider</div><div>Vecta Region</div><div>Cloud Region</div><div>Updated</div>
          </div>
          {(Array.isArray(regionMappings) ? regionMappings : []).map((m, i) => (
            <div key={`${m.provider}-${m.vecta_region}-${i}`} style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", padding: "6px 12px", borderBottom: `1px solid ${C.border}`, fontSize: 10, alignItems: "center" }}>
              <div style={{ color: C.accentFg }}>{CLOUD_PROVIDER_LABELS[m.provider] || m.provider}</div>
              <div style={{ color: C.text, fontFamily: "var(--font-mono)" }}>{m.vecta_region}</div>
              <div style={{ color: C.text, fontFamily: "var(--font-mono)" }}>{m.cloud_region}</div>
              <div style={{ color: C.dim }}>{formatAgo(String(m.updated_at || ""))}</div>
            </div>
          ))}
        </Card>
      </Section>
    )}

    {/* === Add Connector Modal === */}
    <Modal open={modal === "add"} onClose={() => setModal(null)} title="Add Cloud Connector" wide>
      <FG label="Cloud Provider" required>
        <Sel value={addProvider} onChange={(e) => setAddProvider(normalizeCloudProvider(e.target.value))}>
          <option value="aws">AWS KMS</option>
          <option value="azure">Azure Key Vault</option>
          <option value="gcp">Google Cloud KMS</option>
          <option value="oci">Oracle Cloud Vault</option>
          <option value="salesforce">Salesforce BYOK</option>
          <option value="alibaba">Alibaba Cloud KMS</option>
        </Sel>
      </FG>
      <FG label="Connector Name" required hint="A descriptive name for this connector (e.g., prod-main, staging-eu).">
        <Inp value={addName} onChange={(e) => setAddName(e.target.value)} placeholder="prod-main" mono />
      </FG>
      <FG label="Default Region" hint={`Common regions: ${(PROVIDER_REGIONS[addProvider] || []).slice(0, 4).join(", ")}`}>
        <Sel value={addDefaultRegion} onChange={(e) => setAddDefaultRegion(e.target.value)}>
          <option value="">Select a region...</option>
          {(PROVIDER_REGIONS[addProvider] || []).map((r) => <option key={r} value={r}>{r}</option>)}
        </Sel>
      </FG>
      <FG label="Credential" required>
        <CredentialPicker session={session} type={addProvider} value={addCredential} onChange={setAddCredential} onNavigate={onNavigate} />
      </FG>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
        <Btn onClick={() => setModal(null)} disabled={submittingAdd}>Cancel</Btn>
        <Btn primary onClick={() => void submitAddConnector()} disabled={submittingAdd}>{submittingAdd ? "Adding..." : "Add Connector"}</Btn>
      </div>
    </Modal>

    {/* === Region Mapping Modal === */}
    <Modal open={modal === "region"} onClose={() => setModal(null)} title="Region Mappings" wide>
      <div className="vk-fold" tabIndex={0} style={{ fontSize: 10, color: C.muted, marginBottom: 10, padding: "8px 10px", background: C.bg, borderRadius: 6 }}>
        Map your Vecta logical regions to cloud provider regions. When importing a key, if a cloud region isn't specified, the system will use this mapping to determine the target region.
      </div>

      {/* Existing mappings */}
      {(Array.isArray(regionMappings) ? regionMappings : []).length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 10, color: C.text, fontWeight: 600, marginBottom: 6 }}>Current Mappings</div>
          <div style={{ display: "grid", gap: 4 }}>
            {(Array.isArray(regionMappings) ? regionMappings : []).map((m, i) => (
              <div key={`${m.provider}-${m.vecta_region}-${i}`} style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, padding: "4px 8px", background: C.bg, borderRadius: 4, fontSize: 10 }}>
                <span style={{ color: C.accentFg }}>{CLOUD_PROVIDER_LABELS[m.provider] || m.provider}</span>
                <span style={{ color: C.text, fontFamily: "var(--font-mono)" }}>{m.vecta_region} →</span>
                <span style={{ color: C.text, fontFamily: "var(--font-mono)" }}>{m.cloud_region}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Add new mapping */}
      <div style={{ fontSize: 10, color: C.text, fontWeight: 600, marginBottom: 6 }}>Add / Update Mapping</div>
      <Row2>
        <FG label="Provider" required>
          <Sel value={regionProvider} onChange={(e) => setRegionProvider(normalizeCloudProvider(e.target.value))}>
            <option value="aws">AWS KMS</option>
            <option value="azure">Azure Key Vault</option>
            <option value="gcp">Google Cloud KMS</option>
            <option value="oci">Oracle Cloud Vault</option>
            <option value="salesforce">Salesforce BYOK</option>
            <option value="alibaba">Alibaba Cloud KMS</option>
          </Sel>
        </FG>
        <FG label="Vecta Region" required hint="Your internal region identifier (e.g., us-primary, eu-west).">
          <Inp value={regionVecta} onChange={(e) => setRegionVecta(e.target.value)} placeholder="us-primary" mono />
        </FG>
      </Row2>
      <FG label="Cloud Region" required hint={`Target cloud region (e.g., ${(PROVIDER_REGIONS[regionProvider] || ["us-east-1"]).slice(0, 3).join(", ")})`}>
        <Sel value={regionCloud} onChange={(e) => setRegionCloud(e.target.value)}>
          <option value="">Select cloud region...</option>
          {(PROVIDER_REGIONS[regionProvider] || []).map((r) => <option key={r} value={r}>{r}</option>)}
        </Sel>
      </FG>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
        <Btn onClick={() => setModal(null)}>Close</Btn>
        <Btn primary onClick={() => void submitRegionMapping()} disabled={submittingRegion}>{submittingRegion ? "Saving..." : "Save Mapping"}</Btn>
      </div>
    </Modal>

    {/* === Cloud Inventory Modal === */}
    <Modal open={modal === "inventory"} onClose={() => setModal(null)} title={`Cloud Key Inventory — ${CLOUD_PROVIDER_LABELS[inventoryProvider] || inventoryProvider}`} wide>
      <div className="vk-fold" tabIndex={0} style={{ fontSize: 10, color: C.muted, marginBottom: 10, padding: "8px 10px", background: C.bg, borderRadius: 6 }}>
        Discovered keys in your cloud provider account. Keys marked "Managed by Vecta" have active bindings. Unmanaged keys exist only in the cloud and are not synced with Vecta KMS.
      </div>
      {inventoryLoading ? (
        <div style={{ padding: 20, textAlign: "center", fontSize: 11, color: C.dim }}>Discovering cloud keys...</div>
      ) : (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: ".8fr 1.2fr .6fr .6fr .6fr .6fr", padding: "8px 12px", borderBottom: `1px solid ${C.border}`, fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>
            <div>Cloud Key ID</div><div>Reference / ARN</div><div>Region</div><div>Algorithm</div><div>State</div><div>Managed</div>
          </div>
          <div style={{ maxHeight: 350, overflowY: "auto" }}>
            {(Array.isArray(inventoryItems) ? inventoryItems : []).map((item, idx) => (
              <div key={`${item.cloud_key_id}-${idx}`} style={{ display: "grid", gridTemplateColumns: ".8fr 1.2fr .6fr .6fr .6fr .6fr", padding: "6px 12px", borderBottom: `1px solid ${C.border}`, fontSize: 10, alignItems: "center" }}>
                <div style={{ color: C.text, fontFamily: "var(--font-mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={item.cloud_key_id}>{item.cloud_key_id}</div>
                <div style={{ color: C.dim, fontFamily: "var(--font-mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={item.cloud_key_ref}>{item.cloud_key_ref || "-"}</div>
                <div style={{ color: C.dim }}>{item.region || "-"}</div>
                <div style={{ color: C.dim }}>{item.algorithm || "-"}</div>
                <div><B c={item.state === "Enabled" || item.state === "active" ? "green" : item.state === "Disabled" || item.state === "disabled" ? "amber" : "red"}>{item.state || "unknown"}</B></div>
                <div>{item.managed_by_vecta ? <B c="green">Vecta</B> : <span style={{ color: C.dim }}>Unmanaged</span>}</div>
              </div>
            ))}
            {!inventoryItems.length && <div style={{ padding: 12, fontSize: 10, color: C.dim }}>No keys discovered in this cloud account.</div>}
          </div>
          <div style={{ padding: "8px 12px", fontSize: 10, color: C.muted, borderTop: `1px solid ${C.border}` }}>
            {inventoryItems.length} keys discovered · {inventoryItems.filter((i) => i.managed_by_vecta).length} managed by Vecta
          </div>
        </div>
      )}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
        <Btn onClick={() => setModal(null)}>Close</Btn>
      </div>
    </Modal>

    {promptDialog.ui}
  </div>;
};
