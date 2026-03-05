import { B, Bar, Btn, Card, Chk, FG, Inp, Modal, Section, Sel, Stat } from "../legacyPrimitives";
import { C } from "../theme";
import type { ClusterSyncEvent, ClusterLogEntry, ClusterSyncCheckpoint } from "../../../lib/cluster";

type ClusterTabViewProps = {
  clusterView: string;
  loading: boolean;
  refresh: (silent?: boolean) => Promise<void>;
  nodes: any[];
  profiles: any[];
  summary: any;
  selectiveNote: string;
  statusMeta: (status: string) => { label: string; color: string; bg: string; dotClass: string };
  clusterComponentLabel: (value: string) => string;
  componentCategoryColor: (componentId: string) => string;
  roleDrafts: Record<string, string>;
  setRoleDrafts: (updater: any) => void;
  roleUpdatingNode: string;
  updateNodeRoleAction: (node: any) => Promise<void>;
  removeBusyNode: string;
  removeNodeAction: (node: any) => Promise<void>;
  addNodeModalOpen: boolean;
  setAddNodeModalOpen: (open: boolean) => void;
  directNodeForm: any;
  setDirectNodeForm: (updater: any) => void;
  profileComponentScope: (profileID: string) => string[];
  toggleDirectComponent: (componentID: string) => void;
  directNodeBusy: boolean;
  addExistingNode: () => Promise<void>;
  profileName: string;
  setProfileName: (value: string) => void;
  profileDescription: string;
  setProfileDescription: (value: string) => void;
  profileComponents: string[];
  toggleProfileComponent: (componentID: string) => void;
  profileDefault: boolean;
  setProfileDefault: (value: boolean) => void;
  savingProfile: boolean;
  saveProfile: () => Promise<void>;
  removeProfile: (profile: any) => Promise<void>;
  selectedTier: string;
  applyTier: (tierId: string) => void;
  componentChoices: Array<{ id: string; label: string; core?: boolean; category: string }>;
  deploymentTiers: Array<{ id: string; label: string; description: string; components: string[]; color: string }>;
  syncEvents: ClusterSyncEvent[];
  syncLoading: boolean;
  syncCheckpoints: Record<string, ClusterSyncCheckpoint>;
  refreshSyncEvents: () => Promise<void>;
  clusterLogs: ClusterLogEntry[];
  logsLoading: boolean;
  logNodeFilter: string;
  setLogNodeFilter: (value: string) => void;
  logTypeFilter: string;
  setLogTypeFilter: (value: string) => void;
  refreshClusterLogs: () => Promise<void>;
};

function relativeTime(dateStr: string | undefined): string {
  if (!dateStr) return "never";
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return "never";
  const diff = Date.now() - d.getTime();
  if (diff < 0) return "just now";
  if (diff < 60000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return `${Math.floor(diff / 86400000)}d ago`;
}

function roleBadge(role: string, status: string, statusMeta: (s: string) => any) {
  const leader = String(role || "").trim().toLowerCase() === "leader";
  const h = statusMeta(status);
  return <span style={{
    display: "inline-flex", alignItems: "center", gap: 6, padding: "5px 12px",
    borderRadius: 999, background: h.bg, color: h.color,
    border: leader ? `1px solid ${C.accent}` : `1px solid transparent`,
    fontSize: 10, fontWeight: 700
  }}>
    <span style={{ width: 6, height: 6, borderRadius: 999, background: h.color }} />
    {leader ? "Leader" : "Follower"}
  </span>;
}

function componentPill(component: string, label: string, color: string) {
  const dimColor = color + "18";
  return <span key={component} style={{
    padding: "3px 8px", borderRadius: 999, fontSize: 9, fontWeight: 700,
    color, background: dimColor, border: `1px solid ${color}22`
  }}>{label}</span>;
}

export const ClusterTabView = (props: ClusterTabViewProps) => {
  const {
    clusterView, loading, refresh, nodes, profiles, summary, selectiveNote,
    statusMeta, clusterComponentLabel, componentCategoryColor,
    roleDrafts, setRoleDrafts, roleUpdatingNode, updateNodeRoleAction,
    removeBusyNode, removeNodeAction,
    addNodeModalOpen, setAddNodeModalOpen,
    directNodeForm, setDirectNodeForm, profileComponentScope, toggleDirectComponent,
    directNodeBusy, addExistingNode,
    profileName, setProfileName, profileDescription, setProfileDescription,
    profileComponents, toggleProfileComponent, profileDefault, setProfileDefault,
    savingProfile, saveProfile, removeProfile, selectedTier, applyTier,
    componentChoices, deploymentTiers,
    syncEvents, syncLoading, syncCheckpoints, refreshSyncEvents,
    clusterLogs, logsLoading, logNodeFilter, setLogNodeFilter,
    logTypeFilter, setLogTypeFilter, refreshClusterLogs
  } = props;

  const onlineCount = Number(summary?.online_nodes || 0);
  const degradedCount = Number(summary?.degraded_nodes || 0);
  const downCount = Number(summary?.down_nodes || 0);
  const totalNodes = nodes.length;
  const leaderNode = nodes.find((n: any) => String(n?.role || "").toLowerCase() === "leader");

  const headerActions = <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
    {loading ? <B c="blue" pulse>Syncing</B> : null}
    <Btn onClick={() => void refresh(false)}>Refresh</Btn>
  </div>;

  // ── TOPOLOGY VIEW ──────────────────────────────────────────────────
  if (clusterView === "topology") {
    const followers = nodes.filter((n: any) => String(n?.role || "").toLowerCase() !== "leader");
    return <div>
      <Section title="Cluster Topology" actions={headerActions}>
        {/* Hero stats */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))", gap: 10, marginBottom: 16 }}>
          <Stat l="Total Nodes" v={String(totalNodes)} c="accent" />
          <Stat l="Online" v={String(onlineCount)} c="green" />
          <Stat l="Degraded" v={String(degradedCount)} c="amber" />
          <Stat l="Down" v={String(downCount)} c="red" />
          <Stat l="Profiles" v={String(profiles.length)} c="blue" />
          <Stat l="Leader" v={String(leaderNode?.name || leaderNode?.id || "none")} c="accent" />
        </div>

        {/* Leader node */}
        {leaderNode ? <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>Leader Node</div>
          <div style={{
            background: `linear-gradient(135deg, ${C.card} 0%, ${C.accentTint} 100%)`,
            border: `1px solid ${C.accent}`, borderRadius: 14, padding: 18,
            boxShadow: `0 0 24px ${C.glow}`
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div>
                <div style={{ fontSize: 18, color: C.white, fontWeight: 700 }}>{String(leaderNode.name || leaderNode.id)}</div>
                <div style={{ fontSize: 10, color: C.muted, fontFamily: "'JetBrains Mono',monospace", marginTop: 2 }}>{String(leaderNode.endpoint || "unknown")}</div>
              </div>
              {roleBadge("leader", String(leaderNode.status || "unknown"), statusMeta)}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 16, marginTop: 14 }}>
              <div>
                <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>CPU</div>
                <div style={{ fontSize: 18, color: C.white, fontWeight: 700, marginTop: 2 }}>{Number(leaderNode.cpu_percent || 0).toFixed(1)}%</div>
                <Bar pct={Number(leaderNode.cpu_percent || 0)} color={C.accent} />
              </div>
              <div>
                <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>RAM</div>
                <div style={{ fontSize: 18, color: C.white, fontWeight: 700, marginTop: 2 }}>{Number(leaderNode.ram_gb || 0).toFixed(1)} GB</div>
                <Bar pct={Math.min(Number(leaderNode.ram_gb || 0) / 32 * 100, 100)} color={C.green} />
              </div>
              <div>
                <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>Heartbeat</div>
                <div style={{ fontSize: 14, color: C.text, fontWeight: 600, marginTop: 4 }}>{relativeTime(leaderNode.last_heartbeat_at)}</div>
              </div>
              <div>
                <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1 }}>Last Sync</div>
                <div style={{ fontSize: 14, color: C.text, fontWeight: 600, marginTop: 4 }}>{relativeTime(leaderNode.last_sync_at)}</div>
              </div>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginTop: 12 }}>
              {(Array.isArray(leaderNode.enabled_components) ? leaderNode.enabled_components : [])
                .map((c: string) => componentPill(c, clusterComponentLabel(c), componentCategoryColor(c)))}
            </div>
          </div>
        </div> : null}

        {/* Connection indicator */}
        {leaderNode && followers.length > 0 ? <div style={{
          display: "flex", justifyContent: "center", margin: "0 0 12px",
        }}>
          <div style={{ width: 2, height: 24, background: C.borderHi }} />
        </div> : null}

        {/* Follower nodes */}
        {followers.length > 0 ? <>
          <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>
            Follower Nodes <span style={{ color: C.dim }}>({followers.length})</span>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))", gap: 10 }}>
            {followers.map((node: any) => {
              const status = String(node?.status || "unknown");
              const h = statusMeta(status);
              const components = (Array.isArray(node?.enabled_components) ? node.enabled_components : []).map((c: any) => String(c || "")).filter(Boolean);
              return <div key={String(node?.id || Math.random())} style={{
                background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 14,
                borderLeft: `3px solid ${h.color}`
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8 }}>
                  <div>
                    <div style={{ fontSize: 14, color: C.white, fontWeight: 700 }}>{String(node?.name || node?.id || "-")}</div>
                    <div style={{ fontSize: 9, color: C.muted, fontFamily: "'JetBrains Mono',monospace", marginTop: 2 }}>{String(node?.endpoint || "unknown")}</div>
                  </div>
                  {roleBadge("follower", status, statusMeta)}
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, marginTop: 10 }}>
                  <div>
                    <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: .7 }}>CPU</div>
                    <div style={{ fontSize: 14, color: C.text, fontWeight: 700 }}>{Number(node?.cpu_percent || 0).toFixed(1)}%</div>
                    <Bar pct={Number(node?.cpu_percent || 0)} color={C.accent} />
                  </div>
                  <div>
                    <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: .7 }}>RAM</div>
                    <div style={{ fontSize: 14, color: C.text, fontWeight: 700 }}>{Number(node?.ram_gb || 0).toFixed(1)} GB</div>
                    <Bar pct={Math.min(Number(node?.ram_gb || 0) / 32 * 100, 100)} color={C.green} />
                  </div>
                  <div>
                    <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: .7 }}>Heartbeat</div>
                    <div style={{ fontSize: 12, color: C.text, fontWeight: 600, marginTop: 4 }}>{relativeTime(node?.last_heartbeat_at)}</div>
                  </div>
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 10 }}>
                  {components.map((c: string) => componentPill(c, clusterComponentLabel(c), componentCategoryColor(c)))}
                </div>
              </div>;
            })}
          </div>
        </> : null}

        {!nodes.length ? <Card style={{ marginTop: 12 }}>
          <div style={{ textAlign: "center", padding: 24 }}>
            <div style={{ fontSize: 14, color: C.dim, marginBottom: 8 }}>No cluster nodes discovered yet.</div>
            <div style={{ fontSize: 11, color: C.muted }}>Use Node Management to add instances to the cluster.</div>
          </div>
        </Card> : null}

        {/* Sync info banner */}
        <div style={{
          marginTop: 14, border: `1px solid ${C.borderHi}`, borderRadius: 10,
          background: C.card, padding: "12px 16px", display: "flex", alignItems: "center", gap: 8
        }}>
          <span style={{ fontSize: 11, color: C.accent, fontWeight: 700 }}>Selective Sync</span>
          <span style={{ fontSize: 11, color: C.dim }}>{selectiveNote}</span>
        </div>
      </Section>
    </div>;
  }

  // ── NODES VIEW ─────────────────────────────────────────────────────
  if (clusterView === "nodes") {
    return <div>
      <Section title="Node Management" actions={<div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        {loading ? <B c="blue" pulse>Syncing</B> : null}
        <Btn primary onClick={() => setAddNodeModalOpen(true)}>Add Instance</Btn>
        <Btn onClick={() => void refresh(false)}>Refresh</Btn>
      </div>}>
        {/* Summary badges */}
        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <B c="accent">Leader: {String(summary?.leader_node_id || "not elected")}</B>
          <B c="green">Online: {onlineCount}</B>
          <B c="amber">Degraded: {degradedCount}</B>
          <B c="red">Down: {downCount}</B>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(340px,1fr))", gap: 10 }}>
          {nodes.map((node: any) => {
            const nodeID = String(node?.id || "");
            const status = String(node?.status || "unknown");
            const h = statusMeta(status);
            const components = (Array.isArray(node?.enabled_components) ? node.enabled_components : []).map((c: any) => String(c || "")).filter(Boolean);
            const isLeader = String(node?.role || "").toLowerCase() === "leader";
            return <Card key={nodeID} style={{
              padding: 14, borderColor: isLeader ? C.accent : C.borderHi,
              borderLeft: `3px solid ${h.color}`
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <div style={{ fontSize: 16, fontWeight: 700, color: C.text }}>{String(node?.name || nodeID)}</div>
                {roleBadge(String(node?.role || "follower"), status, statusMeta)}
              </div>
              <div style={{ fontSize: 10, color: C.dim, fontFamily: "'JetBrains Mono',monospace", marginBottom: 8 }}>{String(node?.endpoint || "unknown")}</div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 8, marginBottom: 10 }}>
                <div>
                  <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: .7 }}>CPU</div>
                  <div style={{ fontSize: 16, color: C.text, fontWeight: 700 }}>{Number(node?.cpu_percent || 0).toFixed(1)}%</div>
                  <Bar pct={Number(node?.cpu_percent || 0)} color={C.accent} />
                </div>
                <div>
                  <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: .7 }}>RAM</div>
                  <div style={{ fontSize: 16, color: C.text, fontWeight: 700 }}>{Number(node?.ram_gb || 0).toFixed(1)} GB</div>
                  <Bar pct={Math.min(Number(node?.ram_gb || 0) / 32 * 100, 100)} color={C.green} />
                </div>
                <div>
                  <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: .7 }}>Heartbeat</div>
                  <div style={{ fontSize: 12, color: C.text, fontWeight: 600, marginTop: 4 }}>{relativeTime(node?.last_heartbeat_at)}</div>
                </div>
                <div>
                  <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: .7 }}>Last Sync</div>
                  <div style={{ fontSize: 12, color: C.text, fontWeight: 600, marginTop: 4 }}>{relativeTime(node?.last_sync_at)}</div>
                </div>
              </div>

              <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: 10 }}>
                {components.map((c: string) => componentPill(c, clusterComponentLabel(c), componentCategoryColor(c)))}
              </div>

              <div style={{ display: "flex", gap: 6, alignItems: "center", borderTop: `1px solid ${C.border}`, paddingTop: 10 }}>
                <Sel
                  value={String(roleDrafts[nodeID] || node?.role || "follower").trim().toLowerCase() === "leader" ? "leader" : "follower"}
                  onChange={(e) => setRoleDrafts((prev: any) => ({ ...prev, [nodeID]: e.target.value }))}
                  w="120px"
                >
                  <option value="follower">Follower</option>
                  <option value="leader">Leader</option>
                </Sel>
                <Btn small
                  disabled={roleUpdatingNode === nodeID || String(roleDrafts[nodeID] || node?.role || "follower").trim().toLowerCase() === String(node?.role || "follower").trim().toLowerCase()}
                  onClick={() => void updateNodeRoleAction(node)}
                >{roleUpdatingNode === nodeID ? "Applying..." : "Apply"}</Btn>
                <div style={{ flex: 1 }} />
                <Btn small danger disabled={removeBusyNode === nodeID} onClick={() => void removeNodeAction(node)}>
                  {removeBusyNode === nodeID ? "Removing..." : "Remove"}
                </Btn>
              </div>
            </Card>;
          })}
        </div>

        {!nodes.length ? <Card style={{ marginTop: 10 }}>
          <div style={{ textAlign: "center", padding: 24 }}>
            <div style={{ fontSize: 14, color: C.dim }}>No nodes registered yet.</div>
            <Btn primary style={{ marginTop: 12 }} onClick={() => setAddNodeModalOpen(true)}>Add First Instance</Btn>
          </div>
        </Card> : null}
      </Section>

      {/* Add Node Modal */}
      <Modal open={addNodeModalOpen} onClose={() => setAddNodeModalOpen(false)} title="Add KMS Instance to Cluster" wide>
        <FG label="Node ID" required><Inp value={directNodeForm.node_id} onChange={(e) => setDirectNodeForm((p: any) => ({ ...p, node_id: e.target.value }))} placeholder="vecta-kms-03" /></FG>
        <FG label="Node Name"><Inp value={directNodeForm.node_name} onChange={(e) => setDirectNodeForm((p: any) => ({ ...p, node_name: e.target.value }))} placeholder="vecta-kms-03" /></FG>
        <FG label="Node Endpoint"><Inp value={directNodeForm.endpoint} onChange={(e) => setDirectNodeForm((p: any) => ({ ...p, endpoint: e.target.value }))} placeholder="10.0.2.100:8210" /></FG>
        <FG label="Role">
          <Sel value={String(directNodeForm.role || "follower")} onChange={(e) => setDirectNodeForm((p: any) => ({ ...p, role: e.target.value }))}>
            <option value="follower">Follower</option>
            <option value="leader">Leader</option>
          </Sel>
        </FG>
        <FG label="Replication Profile" required>
          <Sel value={String(directNodeForm.profile_id || "")} onChange={(e) => {
            const nextProfileID = String(e.target.value || "");
            const allowed = profileComponentScope(nextProfileID);
            setDirectNodeForm((p: any) => ({ ...p, profile_id: nextProfileID, components: allowed }));
          }}>
            <option value="">Select profile</option>
            {profiles.map((p: any) => <option key={String(p?.id)} value={String(p?.id || "")}>{String(p?.name || p?.id || "-")}</option>)}
          </Sel>
        </FG>
        <FG label="Sync Components">
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 6 }}>
            {profileComponentScope(String(directNodeForm?.profile_id || "")).map((cid: string) =>
              <Chk key={cid} label={clusterComponentLabel(cid)}
                checked={(Array.isArray(directNodeForm?.components) ? directNodeForm.components : []).includes(cid)}
                onChange={() => toggleDirectComponent(cid)} />
            )}
          </div>
        </FG>
        <Chk label="Seed realtime sync events immediately after add" checked={Boolean(directNodeForm?.seed_sync)}
          onChange={() => setDirectNodeForm((p: any) => ({ ...p, seed_sync: !p.seed_sync }))} />
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 14 }}>
          <Btn onClick={() => setAddNodeModalOpen(false)}>Cancel</Btn>
          <Btn primary disabled={directNodeBusy} onClick={() => void addExistingNode()}>{directNodeBusy ? "Adding..." : "Add Instance"}</Btn>
        </div>
      </Modal>
    </div>;
  }

  // ── PROFILES VIEW ──────────────────────────────────────────────────
  if (clusterView === "profiles") {
    const coreChoices = componentChoices.filter((c) => c.category === "core");
    const standardChoices = componentChoices.filter((c) => c.category === "standard");
    const securityChoices = componentChoices.filter((c) => c.category === "security");
    const specializedChoices = componentChoices.filter((c) => c.category === "specialized");

    return <div>
      <Section title="Deployment Profiles" actions={headerActions}>
        {/* Tier presets */}
        <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>Quick Start Tiers</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))", gap: 10, marginBottom: 16 }}>
          {deploymentTiers.map((tier) => {
            const isActive = selectedTier === tier.id;
            const dimColor = tier.color + "18";
            return <div key={tier.id} onClick={() => applyTier(tier.id)} style={{
              background: isActive ? dimColor : C.card,
              border: `1px solid ${isActive ? tier.color : C.border}`,
              borderRadius: 12, padding: 14, cursor: "pointer",
              transition: "all .2s", boxShadow: isActive ? `0 0 16px ${tier.color}22` : "none"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                <div style={{ fontSize: 13, fontWeight: 700, color: isActive ? tier.color : C.text }}>{tier.label}</div>
                <span style={{
                  fontSize: 9, fontWeight: 700, padding: "2px 8px", borderRadius: 999,
                  background: dimColor, color: tier.color
                }}>{tier.components.length} services</span>
              </div>
              <div style={{ fontSize: 10, color: C.dim, lineHeight: 1.4 }}>{tier.description}</div>
            </div>;
          })}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          {/* Profile form */}
          <Card style={{ padding: 14 }}>
            <div style={{ fontSize: 12, color: C.text, fontWeight: 700, marginBottom: 10 }}>Create Replication Profile</div>
            <FG label="Profile Name" required><Inp value={profileName} onChange={(e) => setProfileName(e.target.value)} placeholder="production-replication" /></FG>
            <FG label="Description"><Inp value={profileDescription} onChange={(e) => setProfileDescription(e.target.value)} placeholder="Full platform sync for production nodes" /></FG>

            <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginTop: 8, marginBottom: 6 }}>Core (required)</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 5, marginBottom: 8 }}>
              {coreChoices.map((c) => <Chk key={c.id} label={c.label} checked disabled />)}
            </div>

            <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>Standard Services</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 5, marginBottom: 8 }}>
              {standardChoices.map((c) => <Chk key={c.id} label={c.label} checked={profileComponents.includes(c.id)} onChange={() => toggleProfileComponent(c.id)} />)}
            </div>

            <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>Security & Compliance</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 5, marginBottom: 8 }}>
              {securityChoices.map((c) => <Chk key={c.id} label={c.label} checked={profileComponents.includes(c.id)} onChange={() => toggleProfileComponent(c.id)} />)}
            </div>

            <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>Specialized</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 5, marginBottom: 8 }}>
              {specializedChoices.map((c) => <Chk key={c.id} label={c.label} checked={profileComponents.includes(c.id)} onChange={() => toggleProfileComponent(c.id)} />)}
            </div>

            <Chk label="Set as default profile for new nodes" checked={profileDefault} onChange={() => setProfileDefault(!profileDefault)} />
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 10 }}>
              <span style={{ fontSize: 10, color: C.dim }}>{profileComponents.length} components selected</span>
              <Btn primary disabled={savingProfile} onClick={() => void saveProfile()}>{savingProfile ? "Saving..." : "Save Profile"}</Btn>
            </div>
          </Card>

          {/* Existing profiles */}
          <div>
            <div style={{ fontSize: 12, color: C.text, fontWeight: 700, marginBottom: 10 }}>Existing Profiles</div>
            <div style={{ display: "grid", gap: 8 }}>
              {profiles.map((profile: any) => {
                const comps = (Array.isArray(profile?.components) ? profile.components : []).map((c: any) => String(c || "")).filter(Boolean);
                return <Card key={String(profile?.id || Math.random())} style={{ padding: 12, borderColor: profile?.is_default ? C.accent : C.border }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                    <div>
                      <div style={{ fontSize: 12, color: C.text, fontWeight: 700 }}>{String(profile?.name || profile?.id || "-")}</div>
                      <div style={{ fontSize: 9, color: C.dim, fontFamily: "'JetBrains Mono',monospace" }}>{String(profile?.id || "-")}</div>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      {profile?.is_default ? <B c="green">Default</B> : null}
                      {!profile?.is_default ? <Btn small danger onClick={() => void removeProfile(profile)}>Delete</Btn> : null}
                    </div>
                  </div>
                  {profile?.description ? <div style={{ fontSize: 10, color: C.dim, marginBottom: 6 }}>{String(profile.description)}</div> : null}
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                    {comps.map((c: string) => componentPill(c, clusterComponentLabel(c), componentCategoryColor(c)))}
                  </div>
                  <div style={{ fontSize: 9, color: C.muted, marginTop: 6 }}>{comps.length} components</div>
                </Card>;
              })}
              {!profiles.length ? <Card style={{ padding: 16 }}>
                <div style={{ fontSize: 11, color: C.dim, textAlign: "center" }}>No profiles created yet.</div>
              </Card> : null}
            </div>
          </div>
        </div>
      </Section>
    </div>;
  }

  // ── SYNC VIEW ──────────────────────────────────────────────────────
  if (clusterView === "sync") {
    const maxEventId = syncEvents.length > 0 ? Math.max(...syncEvents.map((e) => e.id)) : 0;
    const pendingSyncNodes = nodes.filter((n: any) => {
      const cp = syncCheckpoints[String(n?.id || "")];
      return cp && cp.last_event_id < maxEventId;
    });

    return <div>
      <Section title="Sync Monitor" actions={<div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        {syncLoading ? <B c="blue" pulse>Loading</B> : null}
        <Btn onClick={() => void refreshSyncEvents()}>Refresh</Btn>
      </div>}>
        {/* Stats */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(160px,1fr))", gap: 10, marginBottom: 16 }}>
          <Stat l="Sync Events" v={String(syncEvents.length)} c="accent" />
          <Stat l="Latest Event ID" v={maxEventId ? String(maxEventId) : "—"} c="blue" />
          <Stat l="Nodes Pending" v={String(pendingSyncNodes.length)} c={pendingSyncNodes.length > 0 ? "amber" : "green"} />
          <Stat l="Last Event" v={syncEvents.length > 0 ? relativeTime(syncEvents[0]?.created_at) : "—"} c="blue" />
        </div>

        {/* Per-node checkpoints */}
        {nodes.length > 0 ? <>
          <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>Node Sync Checkpoints</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(240px,1fr))", gap: 8, marginBottom: 16 }}>
            {nodes.map((node: any) => {
              const nodeID = String(node?.id || "");
              const cp = syncCheckpoints[nodeID];
              const lastEventId = cp?.last_event_id || 0;
              const lag = maxEventId - lastEventId;
              const lagColor = lag === 0 ? C.green : lag < 10 ? C.amber : C.red;
              return <Card key={nodeID} style={{ padding: 12, borderColor: C.border }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                  <div style={{ fontSize: 12, fontWeight: 700, color: C.text }}>{String(node?.name || nodeID)}</div>
                  {roleBadge(String(node?.role || "follower"), String(node?.status || "unknown"), statusMeta)}
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8 }}>
                  <div>
                    <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase" }}>Last Synced</div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: C.text }}>{lastEventId || "—"}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase" }}>Lag</div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: lagColor }}>{lag} events</div>
                  </div>
                  <div>
                    <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase" }}>Updated</div>
                    <div style={{ fontSize: 11, color: C.text, marginTop: 2 }}>{relativeTime(cp?.updated_at)}</div>
                  </div>
                </div>
              </Card>;
            })}
          </div>
        </> : null}

        {/* Sync event log */}
        <div style={{ fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>Recent Sync Events</div>
        <div style={{ maxHeight: 400, overflow: "auto", borderRadius: 10, border: `1px solid ${C.border}` }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
            <thead>
              <tr style={{ background: C.surface, position: "sticky", top: 0 }}>
                {["ID", "Component", "Entity", "Operation", "Source", "Time"].map((h) =>
                  <th key={h} style={{ padding: "8px 10px", textAlign: "left", color: C.muted, fontSize: 9, textTransform: "uppercase", letterSpacing: .7, borderBottom: `1px solid ${C.border}` }}>{h}</th>
                )}
              </tr>
            </thead>
            <tbody>
              {syncEvents.map((evt) => <tr key={evt.id} style={{ borderBottom: `1px solid ${C.border}` }}>
                <td style={{ padding: "6px 10px", color: C.dim, fontFamily: "'JetBrains Mono',monospace" }}>{evt.id}</td>
                <td style={{ padding: "6px 10px" }}><B c="blue">{clusterComponentLabel(evt.component)}</B></td>
                <td style={{ padding: "6px 10px", color: C.text }}>{evt.entity_type}/{evt.entity_id}</td>
                <td style={{ padding: "6px 10px" }}><B c={evt.operation === "delete" ? "red" : evt.operation === "create" ? "green" : "amber"}>{evt.operation}</B></td>
                <td style={{ padding: "6px 10px", color: C.dim, fontSize: 10 }}>{evt.source_node_id || "—"}</td>
                <td style={{ padding: "6px 10px", color: C.dim, fontSize: 10 }}>{relativeTime(evt.created_at)}</td>
              </tr>)}
              {syncEvents.length === 0 ? <tr><td colSpan={6} style={{ padding: 20, textAlign: "center", color: C.dim }}>No sync events recorded yet.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </Section>
    </div>;
  }

  // ── LOGS VIEW ──────────────────────────────────────────────────────
  if (clusterView === "logs") {
    const levelColor = (level: string) => {
      const l = String(level || "").toLowerCase();
      if (l === "error" || l === "critical") return C.red;
      if (l === "warn" || l === "warning") return C.amber;
      return C.blue;
    };
    const levelBg = (level: string) => {
      const l = String(level || "").toLowerCase();
      if (l === "error" || l === "critical") return C.redDim;
      if (l === "warn" || l === "warning") return C.amberDim;
      return C.blueDim;
    };

    return <div>
      <Section title="Cluster Logs" actions={<div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        {logsLoading ? <B c="blue" pulse>Loading</B> : null}
        <Btn onClick={() => void refreshClusterLogs()}>Refresh</Btn>
      </div>}>
        {/* Filters */}
        <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap", alignItems: "flex-end" }}>
          <FG label="Filter by Node">
            <Sel value={logNodeFilter} onChange={(e) => setLogNodeFilter(e.target.value)} w="180px">
              <option value="">All Nodes</option>
              {nodes.map((n: any) => <option key={String(n?.id)} value={String(n?.id || "")}>{String(n?.name || n?.id || "-")}</option>)}
            </Sel>
          </FG>
          <FG label="Event Type">
            <Inp value={logTypeFilter} onChange={(e) => setLogTypeFilter(e.target.value)} placeholder="e.g. node.join" w="180px" />
          </FG>
          <Btn small onClick={() => void refreshClusterLogs()}>Apply</Btn>
        </div>

        {/* Log entries */}
        <div style={{ maxHeight: 500, overflow: "auto", borderRadius: 10, border: `1px solid ${C.border}` }}>
          {clusterLogs.map((log) => <div key={log.id} style={{
            padding: "10px 14px", borderBottom: `1px solid ${C.border}`,
            display: "flex", gap: 10, alignItems: "flex-start"
          }}>
            <span style={{
              padding: "2px 8px", borderRadius: 5, fontSize: 9, fontWeight: 700,
              color: levelColor(log.level), background: levelBg(log.level),
              flexShrink: 0, minWidth: 44, textAlign: "center", textTransform: "uppercase"
            }}>{String(log.level || "info").toUpperCase()}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 3 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: C.text }}>{log.event_type || "event"}</span>
                {log.node_id ? <span style={{ fontSize: 9, color: C.dim }}>{log.node_id}</span> : null}
                <span style={{ fontSize: 9, color: C.muted, marginLeft: "auto" }}>{relativeTime(log.created_at)}</span>
              </div>
              <div style={{ fontSize: 11, color: C.dim, lineHeight: 1.4 }}>{log.message}</div>
            </div>
          </div>)}
          {clusterLogs.length === 0 ? <div style={{ padding: 24, textAlign: "center", color: C.dim }}>No cluster logs found.</div> : null}
        </div>

        <div style={{ fontSize: 9, color: C.muted, marginTop: 8 }}>Showing {clusterLogs.length} log entries</div>
      </Section>
    </div>;
  }

  // Fallback (shouldn't happen)
  return <div><Section title="Cluster" actions={headerActions}><Card><div style={{ color: C.dim, padding: 12 }}>Unknown view: {clusterView}</div></Card></Section></div>;
};
