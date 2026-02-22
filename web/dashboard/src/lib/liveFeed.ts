import type { LiveEvent } from "../store/live";

type EventPayload = {
  event?: string;
  type?: string;
  severity?: string;
  message?: string;
  detail?: string;
  source?: string;
  ts?: string;
  timestamp?: string;
  created_at?: string;
};

const severityFromEvent = (eventName: string): LiveEvent["severity"] => {
  if (eventName.includes("critical") || eventName.includes("blocked")) {
    return "critical";
  }
  if (eventName.includes("warning") || eventName.includes("threshold")) {
    return "warning";
  }
  return "info";
};

export function wsBaseURL(path: string): string {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  return `${protocol}://${window.location.host}${path}`;
}

export function mapToLiveEvent(payload: EventPayload, fallbackTopic: string): LiveEvent {
  const topic = payload.event ?? payload.type ?? fallbackTopic;
  const severity =
    payload.severity === "critical" || payload.severity === "warning" || payload.severity === "info"
      ? payload.severity
      : severityFromEvent(topic);
  const ts = payload.timestamp ?? payload.ts ?? payload.created_at ?? new Date().toISOString();

  return {
    id: `${topic}-${ts}-${Math.random().toString(36).slice(2, 9)}`,
    topic,
    severity,
    message: payload.message ?? payload.detail ?? topic.replaceAll(".", " "),
    source: payload.source ?? "stream",
    timestamp: ts
  };
}

export function parseWSMessage(data: string): EventPayload | null {
  try {
    return JSON.parse(data) as EventPayload;
  } catch {
    return null;
  }
}
