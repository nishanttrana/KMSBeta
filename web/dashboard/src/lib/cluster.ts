import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type ClusterProfile = {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  components: string[];
  is_default: boolean;
  created_at?: string;
  updated_at?: string;
};

export type ClusterNode = {
  id: string;
  tenant_id: string;
  name: string;
  role: "leader" | "follower" | string;
  endpoint: string;
  status: "online" | "degraded" | "down" | "unknown" | string;
  cpu_percent: number;
  ram_gb: number;
  enabled_components: string[];
  profile_id: string;
  join_state: string;
  cert_fingerprint?: string;
  last_heartbeat_at?: string;
  last_sync_at?: string;
  created_at?: string;
  updated_at?: string;
};

export type ClusterOverview = {
  nodes: ClusterNode[];
  profiles: ClusterProfile[];
  summary?: {
    leader_node_id?: string;
    total_nodes?: number;
    online_nodes?: number;
    degraded_nodes?: number;
    down_nodes?: number;
  };
  selective_component_sync?: {
    enabled?: boolean;
    note?: string;
  };
};

export type ClusterJoinBundle = {
  id: string;
  tenant_id: string;
  target_node_id: string;
  target_node_name: string;
  endpoint: string;
  profile_id: string;
  nonce: string;
  requested_by: string;
  expires_at: string;
  issued_secret: string;
  profile_name?: string;
  profile_components?: string[];
};

type OverviewResponse = { overview: ClusterOverview };
type ProfilesResponse = { items: ClusterProfile[] };
type ProfileResponse = { profile: ClusterProfile };
type JoinResponse = { join: ClusterJoinBundle };

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function getClusterOverview(session: AuthSession): Promise<ClusterOverview> {
  const out = await serviceRequest<OverviewResponse>(session, "cluster", `/cluster/overview?${tenantQuery(session)}`);
  return out?.overview || { nodes: [], profiles: [] };
}

export async function listClusterProfiles(session: AuthSession): Promise<ClusterProfile[]> {
  const out = await serviceRequest<ProfilesResponse>(session, "cluster", `/cluster/profiles?${tenantQuery(session)}`);
  return Array.isArray(out?.items) ? out.items : [];
}

export async function upsertClusterProfile(
  session: AuthSession,
  input: {
    id?: string;
    name: string;
    description?: string;
    components: string[];
    is_default?: boolean;
  }
): Promise<ClusterProfile> {
  const out = await serviceRequest<ProfileResponse>(session, "cluster", "/cluster/profiles", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      id: input.id || "",
      name: input.name,
      description: input.description || "",
      components: Array.isArray(input.components) ? input.components : [],
      is_default: Boolean(input.is_default)
    })
  });
  return out.profile;
}

export async function deleteClusterProfile(session: AuthSession, profileID: string): Promise<void> {
  await serviceRequest(session, "cluster", `/cluster/profiles/${encodeURIComponent(profileID)}?${tenantQuery(session)}`, {
    method: "DELETE"
  });
}

export async function createClusterJoinRequest(
  session: AuthSession,
  input: {
    target_node_id: string;
    target_node_name?: string;
    endpoint?: string;
    profile_id: string;
    expires_minutes?: number;
    requested_by?: string;
  }
): Promise<ClusterJoinBundle> {
  const out = await serviceRequest<JoinResponse>(session, "cluster", "/cluster/join/request", {
    method: "POST",
    body: JSON.stringify({
      tenant_id: session.tenantId,
      target_node_id: input.target_node_id,
      target_node_name: input.target_node_name || input.target_node_id,
      endpoint: input.endpoint || "",
      profile_id: input.profile_id,
      expires_minutes: Number(input.expires_minutes || 30),
      requested_by: input.requested_by || session.username || "admin"
    })
  });
  return out.join;
}
