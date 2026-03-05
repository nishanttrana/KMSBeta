import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../../lib/auth";
import {
  deleteClusterProfile,
  getClusterOverview,
  listClusterLogs,
  listClusterSyncEvents,
  getClusterSyncCheckpoint,
  removeClusterNode,
  updateClusterNodeRole,
  upsertClusterNode,
  upsertClusterProfile,
  type ClusterSyncEvent,
  type ClusterLogEntry,
  type ClusterSyncCheckpoint
} from "../../../lib/cluster";
import { usePromptDialog } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { ClusterTabView } from "./ClusterTabView";

type ClusterTabProps = {
  session: AuthSession | null;
  onToast?: (message: string) => void;
  subView?: string;
};

export const CLUSTER_COMPONENT_CHOICES: Array<{ id: string; label: string; core?: boolean; category: string }> = [
  // Core (always required)
  { id: "auth", label: "Auth", core: true, category: "core" },
  { id: "keycore", label: "KeyCore", core: true, category: "core" },
  { id: "policy", label: "Policy", core: true, category: "core" },
  { id: "governance", label: "Governance", core: true, category: "core" },
  // Standard services
  { id: "secrets", label: "Secrets", category: "standard" },
  { id: "certs", label: "Certificates", category: "standard" },
  { id: "cloud", label: "Cloud BYOK", category: "standard" },
  { id: "ekm", label: "EKM", category: "standard" },
  { id: "dataprotect", label: "Data Protection", category: "standard" },
  // Security & Compliance
  { id: "compliance", label: "Compliance", category: "security" },
  { id: "posture", label: "Posture", category: "security" },
  { id: "discovery", label: "Discovery", category: "security" },
  { id: "sbom", label: "SBOM/CBOM", category: "security" },
  { id: "reporting", label: "Reporting", category: "security" },
  // Specialized
  { id: "payment", label: "Payment", category: "specialized" },
  { id: "hyok", label: "HYOK", category: "specialized" },
  { id: "byok", label: "BYOK", category: "specialized" },
  { id: "kmip", label: "KMIP", category: "specialized" },
  { id: "pqc", label: "PQC", category: "specialized" },
  { id: "qkd", label: "QKD", category: "specialized" },
  { id: "mpc", label: "MPC", category: "specialized" },
  { id: "qrng", label: "QRNG", category: "specialized" },
  { id: "ai", label: "AI Security", category: "specialized" },
];

export const DEPLOYMENT_TIERS = [
  {
    id: "core",
    label: "Core Only",
    description: "Minimum viable KMS — auth, keys, policy, governance",
    components: ["auth", "keycore", "policy", "governance"],
    color: C.blue,
    icon: "minimal"
  },
  {
    id: "standard",
    label: "Standard",
    description: "Core + secrets, certificates, cloud keys, EKM, data protection",
    components: ["auth", "keycore", "policy", "governance", "secrets", "certs", "cloud", "ekm", "dataprotect"],
    color: C.green,
    icon: "standard"
  },
  {
    id: "security",
    label: "Security Suite",
    description: "Standard + compliance, posture, discovery, SBOM, reporting",
    components: ["auth", "keycore", "policy", "governance", "secrets", "certs", "cloud", "ekm", "dataprotect", "compliance", "posture", "discovery", "sbom", "reporting"],
    color: C.purple,
    icon: "security"
  },
  {
    id: "full",
    label: "Full Platform",
    description: "All services — maximum capability across the entire KMS",
    components: CLUSTER_COMPONENT_CHOICES.map((c) => c.id),
    color: C.accent,
    icon: "full"
  }
];

const CORE_COMPONENTS = new Set(["auth", "keycore", "policy", "governance"]);

export const clusterComponentLabel = (value: string): string => {
  const key = String(value || "").trim().toLowerCase();
  const hit = CLUSTER_COMPONENT_CHOICES.find((item) => item.id === key);
  if (hit) return hit.label;
  return key
    .split(/[-_]/g)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ") || String(value || "");
};

export const componentCategoryColor = (componentId: string): string => {
  const choice = CLUSTER_COMPONENT_CHOICES.find((c) => c.id === componentId);
  if (!choice) return C.blue;
  switch (choice.category) {
    case "core": return C.accent;
    case "standard": return C.green;
    case "security": return C.purple;
    case "specialized": return C.blue;
    default: return C.blue;
  }
};

export const ClusterTab = ({ session, onToast, subView }: ClusterTabProps) => {
  const promptDialog = usePromptDialog();
  const [loading, setLoading] = useState(false);
  const [overview, setOverview] = useState<any>(null);

  // Profile form state
  const [profileName, setProfileName] = useState("");
  const [profileDescription, setProfileDescription] = useState("");
  const [profileComponents, setProfileComponents] = useState<string[]>(["auth", "keycore", "policy", "governance"]);
  const [profileDefault, setProfileDefault] = useState(false);
  const [savingProfile, setSavingProfile] = useState(false);
  const [selectedTier, setSelectedTier] = useState("");

  // Node form state
  const [directNodeForm, setDirectNodeForm] = useState<any>({
    node_id: "", node_name: "", endpoint: "", profile_id: "", role: "follower",
    components: ["auth", "keycore", "policy", "governance"], seed_sync: true
  });
  const [directNodeBusy, setDirectNodeBusy] = useState(false);
  const [addNodeModalOpen, setAddNodeModalOpen] = useState(false);

  // Node management state
  const [roleDrafts, setRoleDrafts] = useState<Record<string, string>>({});
  const [roleUpdatingNode, setRoleUpdatingNode] = useState("");
  const [removeBusyNode, setRemoveBusyNode] = useState("");

  // Sync state
  const [syncEvents, setSyncEvents] = useState<ClusterSyncEvent[]>([]);
  const [syncLoading, setSyncLoading] = useState(false);
  const [syncCheckpoints, setSyncCheckpoints] = useState<Record<string, ClusterSyncCheckpoint>>({});

  // Logs state
  const [clusterLogs, setClusterLogs] = useState<ClusterLogEntry[]>([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [logNodeFilter, setLogNodeFilter] = useState("");
  const [logTypeFilter, setLogTypeFilter] = useState("");

  const clusterView = String(subView || "topology").trim().toLowerCase();

  // Refresh overview
  const refresh = useCallback(async (silent = false) => {
    if (!session?.token) { setOverview(null); return; }
    if (!silent) setLoading(true);
    try {
      const out = await getClusterOverview(session);
      setOverview(out || { nodes: [], profiles: [] });
      const profiles = Array.isArray(out?.profiles) ? out.profiles : [];
      setDirectNodeForm((prev: any) => {
        const profileCurrent = String(prev?.profile_id || "").trim();
        const defaultProfile = profiles.find((item: any) => Boolean(item?.is_default)) || profiles[0] || null;
        const nextProfile = profiles.find((item: any) => String(item?.id || "").trim() === profileCurrent) || defaultProfile;
        const allowedComponents = (Array.isArray(nextProfile?.components) ? nextProfile.components : [])
          .map((v: any) => String(v || "").trim().toLowerCase()).filter(Boolean).filter((v: string) => v !== "audit");
        const requestedComponents = (Array.isArray(prev?.components) ? prev.components : [])
          .map((v: any) => String(v || "").trim().toLowerCase()).filter(Boolean);
        const mergedComponents = requestedComponents.length
          ? requestedComponents.filter((c: string) => allowedComponents.includes(c))
          : allowedComponents;
        return { ...prev, profile_id: String(nextProfile?.id || ""), components: mergedComponents.length ? mergedComponents : allowedComponents };
      });
    } catch (error) {
      onToast?.(`Cluster load failed: ${errMsg(error)}`);
    } finally {
      if (!silent) setLoading(false);
    }
  }, [onToast, session]);

  // Refresh sync events
  const refreshSyncEvents = useCallback(async () => {
    if (!session?.token) return;
    setSyncLoading(true);
    try {
      const events = await listClusterSyncEvents(session, undefined, undefined, 100);
      setSyncEvents(events);
      // Fetch checkpoints for each node
      const nodes = Array.isArray(overview?.nodes) ? overview.nodes : [];
      const profiles = Array.isArray(overview?.profiles) ? overview.profiles : [];
      const defaultProfile = profiles.find((p: any) => p?.is_default) || profiles[0];
      if (defaultProfile) {
        const checks: Record<string, ClusterSyncCheckpoint> = {};
        for (const node of nodes) {
          try {
            const cp = await getClusterSyncCheckpoint(session, String(node.id), String(defaultProfile.id));
            checks[String(node.id)] = cp;
          } catch { /* ignore */ }
        }
        setSyncCheckpoints(checks);
      }
    } catch (error) {
      onToast?.(`Sync events load failed: ${errMsg(error)}`);
    } finally {
      setSyncLoading(false);
    }
  }, [session, overview, onToast]);

  // Refresh cluster logs
  const refreshClusterLogs = useCallback(async () => {
    if (!session?.token) return;
    setLogsLoading(true);
    try {
      const logs = await listClusterLogs(session, logNodeFilter || undefined, logTypeFilter || undefined, 200);
      setClusterLogs(logs);
    } catch (error) {
      onToast?.(`Cluster logs load failed: ${errMsg(error)}`);
    } finally {
      setLogsLoading(false);
    }
  }, [session, logNodeFilter, logTypeFilter, onToast]);

  // Initial load + auto-refresh
  useEffect(() => {
    if (!session?.token) { setOverview(null); return; }
    void refresh(false);
  }, [refresh, session?.tenantId, session?.token]);

  useEffect(() => {
    if (!session?.token) return;
    const timer = window.setInterval(() => void refresh(true), 10000);
    return () => window.clearInterval(timer);
  }, [refresh, session?.tenantId, session?.token]);

  // Load sync/logs when switching to those views
  useEffect(() => {
    if (clusterView === "sync" && session?.token) void refreshSyncEvents();
    if (clusterView === "logs" && session?.token) void refreshClusterLogs();
  }, [clusterView, session?.token]); // eslint-disable-line react-hooks/exhaustive-deps

  const nodes = Array.isArray(overview?.nodes) ? overview.nodes : [];
  const profiles = Array.isArray(overview?.profiles) ? overview.profiles : [];
  const summary = overview?.summary || {};
  const selectiveNote = String(overview?.selective_component_sync?.note || "Nodes sync only the state for their enabled components.");

  const profileComponentScope = (profileID: string) => {
    const profile = profiles.find((item: any) => String(item?.id || "").trim() === String(profileID || "").trim());
    return (Array.isArray(profile?.components) ? profile.components : [])
      .map((v: any) => String(v || "").trim().toLowerCase()).filter(Boolean).filter((v: string) => v !== "audit");
  };

  const toggleDirectComponent = (componentID: string) => {
    const allowed = profileComponentScope(String(directNodeForm?.profile_id || ""));
    if (!allowed.includes(componentID)) return;
    setDirectNodeForm((prev: any) => {
      const existing = (Array.isArray(prev?.components) ? prev.components : [])
        .map((v: any) => String(v || "").trim().toLowerCase()).filter(Boolean);
      return existing.includes(componentID)
        ? { ...prev, components: existing.filter((item: string) => item !== componentID) }
        : { ...prev, components: [...existing, componentID] };
    });
  };

  const updateNodeRoleAction = async (node: any) => {
    const nodeID = String(node?.id || "").trim();
    if (!session?.token || !nodeID) return;
    const requestedRole = String(roleDrafts[nodeID] || node?.role || "follower").trim().toLowerCase() === "leader" ? "leader" : "follower";
    const currentRole = String(node?.role || "follower").trim().toLowerCase() === "leader" ? "leader" : "follower";
    if (requestedRole === currentRole) return;
    setRoleUpdatingNode(nodeID);
    try {
      await updateClusterNodeRole(session, nodeID, requestedRole);
      await refresh(true);
      onToast?.(`Node role updated: ${nodeID} -> ${requestedRole}.`);
    } catch (error) {
      onToast?.(`Role update failed: ${errMsg(error)}`);
    } finally {
      setRoleUpdatingNode("");
    }
  };

  const removeNodeAction = async (node: any) => {
    const nodeID = String(node?.id || "").trim();
    const nodeName = String(node?.name || nodeID).trim();
    if (!session?.token || !nodeID) return;
    const confirmed = await promptDialog.confirm({
      title: "Remove Cluster Node",
      message: `Remove "${nodeName}" from the cluster? This will erase synced data on that node and convert it to standalone mode.`,
      confirmLabel: "Remove Node", cancelLabel: "Cancel", danger: true
    });
    if (!confirmed) return;
    setRemoveBusyNode(nodeID);
    try {
      const result = await removeClusterNode(session, nodeID, { reason: "removed_from_cluster", purge_synced_data: true });
      await refresh(true);
      const promoted = String(result?.promoted_leader_node || "").trim();
      onToast?.(promoted ? `Node removed. New leader: ${promoted}.` : "Node removed from cluster.");
    } catch (error) {
      onToast?.(`Remove node failed: ${errMsg(error)}`);
    } finally {
      setRemoveBusyNode("");
    }
  };

  const addExistingNode = async () => {
    if (!session?.token) return;
    const nodeID = String(directNodeForm?.node_id || "").trim();
    const profileID = String(directNodeForm?.profile_id || "").trim();
    if (!nodeID || !profileID) { onToast?.("Node ID and replication profile are required."); return; }
    const allowed = profileComponentScope(profileID);
    const selected = (Array.isArray(directNodeForm?.components) ? directNodeForm.components : [])
      .map((v: any) => String(v || "").trim().toLowerCase()).filter((v: string) => allowed.includes(v));
    setDirectNodeBusy(true);
    try {
      await upsertClusterNode(session, {
        node_id: nodeID,
        node_name: String(directNodeForm?.node_name || nodeID).trim(),
        endpoint: String(directNodeForm?.endpoint || "").trim(),
        role: String(directNodeForm?.role || "follower").trim().toLowerCase() === "leader" ? "leader" : "follower",
        profile_id: profileID,
        components: selected.length ? selected : allowed,
        status: "unknown", join_state: "active",
        seed_sync: Boolean(directNodeForm?.seed_sync)
      });
      setDirectNodeForm((prev: any) => ({
        ...prev, node_id: "", node_name: "", endpoint: "", role: "follower",
        components: selected.length ? selected : allowed
      }));
      setAddNodeModalOpen(false);
      await refresh(true);
      onToast?.("KMS instance added to cluster.");
    } catch (error) {
      onToast?.(`Add node failed: ${errMsg(error)}`);
    } finally {
      setDirectNodeBusy(false);
    }
  };

  const toggleProfileComponent = (componentID: string) => {
    if (CORE_COMPONENTS.has(componentID)) return; // core components can't be toggled off
    setProfileComponents((prev) =>
      prev.includes(componentID) ? prev.filter((item) => item !== componentID) : [...prev, componentID]
    );
  };

  const applyTier = (tierId: string) => {
    const tier = DEPLOYMENT_TIERS.find((t) => t.id === tierId);
    if (!tier) return;
    setSelectedTier(tierId);
    setProfileComponents([...tier.components]);
    if (!profileName) setProfileName(`${tier.label} Profile`);
  };

  const saveProfile = async () => {
    if (!session?.token) return;
    if (!String(profileName || "").trim()) { onToast?.("Profile name is required."); return; }
    if (!profileComponents.length) { onToast?.("Select at least one component."); return; }
    setSavingProfile(true);
    try {
      await upsertClusterProfile(session, {
        name: String(profileName).trim(),
        description: String(profileDescription || "").trim(),
        components: profileComponents,
        is_default: Boolean(profileDefault)
      });
      setProfileName(""); setProfileDescription(""); setProfileDefault(false); setSelectedTier("");
      setProfileComponents(["auth", "keycore", "policy", "governance"]);
      await refresh(true);
      onToast?.("Cluster replication profile saved.");
    } catch (error) {
      onToast?.(`Profile save failed: ${errMsg(error)}`);
    } finally {
      setSavingProfile(false);
    }
  };

  const removeProfile = async (profile: any) => {
    const profileID = String(profile?.id || "").trim();
    if (!session?.token || !profileID) return;
    if (profile?.is_default) { onToast?.("Default profile cannot be deleted."); return; }
    const confirmed = await promptDialog.confirm({
      title: "Delete Replication Profile",
      message: `Delete replication profile "${String(profile?.name || profileID)}"?`,
      confirmLabel: "Delete", cancelLabel: "Cancel", danger: true
    });
    if (!confirmed) return;
    try {
      await deleteClusterProfile(session, profileID);
      await refresh(true);
      onToast?.("Cluster replication profile deleted.");
    } catch (error) {
      onToast?.(`Delete profile failed: ${errMsg(error)}`);
    }
  };

  const statusMeta = (status: string) => {
    const n = String(status || "").trim().toLowerCase();
    if (n === "online") return { label: "Online", color: C.green, bg: C.greenDim, dotClass: "sync-dot sync-dot--online" };
    if (n === "degraded") return { label: "Degraded", color: C.amber, bg: C.amberDim, dotClass: "sync-dot sync-dot--degraded" };
    if (n === "down") return { label: "Down", color: C.red, bg: C.redDim, dotClass: "sync-dot sync-dot--down" };
    return { label: "Unknown", color: C.blue, bg: C.blueDim, dotClass: "sync-dot sync-dot--unknown" };
  };

  return <>
    <ClusterTabView
      clusterView={clusterView}
      loading={loading}
      refresh={refresh}
      nodes={nodes}
      profiles={profiles}
      summary={summary}
      selectiveNote={selectiveNote}
      statusMeta={statusMeta}
      clusterComponentLabel={clusterComponentLabel}
      componentCategoryColor={componentCategoryColor}
      // Node management
      roleDrafts={roleDrafts}
      setRoleDrafts={setRoleDrafts}
      roleUpdatingNode={roleUpdatingNode}
      updateNodeRoleAction={updateNodeRoleAction}
      removeBusyNode={removeBusyNode}
      removeNodeAction={removeNodeAction}
      // Add node
      addNodeModalOpen={addNodeModalOpen}
      setAddNodeModalOpen={setAddNodeModalOpen}
      directNodeForm={directNodeForm}
      setDirectNodeForm={setDirectNodeForm}
      profileComponentScope={profileComponentScope}
      toggleDirectComponent={toggleDirectComponent}
      directNodeBusy={directNodeBusy}
      addExistingNode={addExistingNode}
      // Profiles
      profileName={profileName}
      setProfileName={setProfileName}
      profileDescription={profileDescription}
      setProfileDescription={setProfileDescription}
      profileComponents={profileComponents}
      toggleProfileComponent={toggleProfileComponent}
      profileDefault={profileDefault}
      setProfileDefault={setProfileDefault}
      savingProfile={savingProfile}
      saveProfile={saveProfile}
      removeProfile={removeProfile}
      selectedTier={selectedTier}
      applyTier={applyTier}
      componentChoices={CLUSTER_COMPONENT_CHOICES}
      deploymentTiers={DEPLOYMENT_TIERS}
      // Sync
      syncEvents={syncEvents}
      syncLoading={syncLoading}
      syncCheckpoints={syncCheckpoints}
      refreshSyncEvents={refreshSyncEvents}
      // Logs
      clusterLogs={clusterLogs}
      logsLoading={logsLoading}
      logNodeFilter={logNodeFilter}
      setLogNodeFilter={setLogNodeFilter}
      logTypeFilter={logTypeFilter}
      setLogTypeFilter={setLogTypeFilter}
      refreshClusterLogs={refreshClusterLogs}
    />
    {promptDialog.ui}
  </>;
};
