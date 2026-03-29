import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

export type ActivityEvent = {
  id: string;
  tenant_id: string;
  event_type: string;
  source: string;
  actor: string;
  actor_ip: string;
  query: string;
  rows_affected: number;
  data_labels: string[];
  risk_level: string;
  allowed: boolean;
  reason: string;
  metadata: Record<string, unknown>;
  occurred_at: string;
  created_at: string;
};

export type ActivityStats = {
  tenant_id: string;
  total_events: number;
  denied_events: number;
  by_event_type: Record<string, number>;
  by_risk_level: Record<string, number>;
  unique_actors: number;
  high_risk_sources: string[];
};

export type ActorSummary = {
  actor: string;
  event_count: number;
  denied_count: number;
  last_seen: string;
};

export type SourceSummary = {
  source: string;
  event_count: number;
  risk_score: number;
  last_seen: string;
};

function tenantQuery(session: AuthSession): string {
  return `tenant_id=${encodeURIComponent(session.tenantId)}`;
}

export async function listActivityEvents(
  session: AuthSession,
  opts: {
    event_type?: string;
    risk_level?: string;
    source?: string;
    actor?: string;
    limit?: number;
    offset?: number;
    since?: string;
  } = {}
): Promise<ActivityEvent[]> {
  const params = new URLSearchParams();
  params.set("tenant_id", session.tenantId);
  if (opts.event_type) params.set("event_type", opts.event_type);
  if (opts.risk_level) params.set("risk_level", opts.risk_level);
  if (opts.source) params.set("source", opts.source);
  if (opts.actor) params.set("actor", opts.actor);
  if (opts.limit) params.set("limit", String(opts.limit));
  if (opts.offset) params.set("offset", String(opts.offset));
  if (opts.since) params.set("since", opts.since);
  const res = await serviceRequest<{ items?: ActivityEvent[] }>(
    session, "dam", `/activity/events?${params.toString()}`
  );
  return Array.isArray(res?.items) ? res.items : [];
}

export async function getActivityStats(session: AuthSession): Promise<ActivityStats> {
  const res = await serviceRequest<{ stats?: ActivityStats }>(
    session, "dam", `/activity/stats?${tenantQuery(session)}`
  );
  return res?.stats ?? {
    tenant_id: session.tenantId,
    total_events: 0,
    denied_events: 0,
    by_event_type: {},
    by_risk_level: {},
    unique_actors: 0,
    high_risk_sources: [],
  };
}

export async function listActivityActors(session: AuthSession): Promise<ActorSummary[]> {
  const res = await serviceRequest<{ items?: ActorSummary[] }>(
    session, "dam", `/activity/actors?${tenantQuery(session)}`
  );
  return Array.isArray(res?.items) ? res.items : [];
}

export async function listActivitySources(session: AuthSession): Promise<SourceSummary[]> {
  const res = await serviceRequest<{ items?: SourceSummary[] }>(
    session, "dam", `/activity/sources?${tenantQuery(session)}`
  );
  return Array.isArray(res?.items) ? res.items : [];
}

export async function ingestActivityEvent(
  session: AuthSession,
  payload: Partial<ActivityEvent>
): Promise<ActivityEvent> {
  const res = await serviceRequest<{ event?: ActivityEvent }>(
    session, "dam", `/activity/events?${tenantQuery(session)}`,
    {
      method: "POST",
      body: JSON.stringify({ tenant_id: session.tenantId, ...payload }),
    }
  );
  return res?.event ?? ({} as ActivityEvent);
}
