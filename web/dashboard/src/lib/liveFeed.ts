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

// Strip control characters and limit length — prevents XSS via injected
// content from untrusted WebSocket messages (OWASP A03).
function sanitizeField(value: unknown, maxLen = 512): string {
  return String(value ?? "")
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "") // strip control chars (keep \t \n \r)
    .slice(0, maxLen)
    .trim();
}

export function wsBaseURL(path: string): string {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  return `${protocol}://${window.location.host}${path}`;
}

export function mapToLiveEvent(payload: EventPayload, fallbackTopic: string): LiveEvent {
  const topic = sanitizeField(payload.event ?? payload.type ?? fallbackTopic, 128);
  const rawSeverity = sanitizeField(payload.severity, 32);
  const severity =
    rawSeverity === "critical" || rawSeverity === "warning" || rawSeverity === "info"
      ? (rawSeverity as LiveEvent["severity"])
      : severityFromEvent(topic);
  const ts = sanitizeField(payload.timestamp ?? payload.ts ?? payload.created_at ?? new Date().toISOString(), 64);

  return {
    id: `${topic}-${ts}-${Math.random().toString(36).slice(2, 9)}`,
    topic,
    severity,
    message: sanitizeField(payload.message ?? payload.detail ?? topic.replaceAll(".", " "), 1024),
    source: sanitizeField(payload.source ?? "stream", 64),
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
