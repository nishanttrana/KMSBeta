import type { AuthSession } from "./auth";

type APIErrorShape = {
  error?: {
    message?: string;
  };
};

const REQUEST_TIMEOUT_MS = 20_000;
type RequestCountListener = (count: number) => void;
export type ServiceRequestInit = RequestInit & {
  skipGlobalLoading?: boolean;
};

let inFlightRequests = 0;
const requestCountListeners = new Set<RequestCountListener>();

function emitRequestCount(): void {
  requestCountListeners.forEach((listener) => {
    try {
      listener(inFlightRequests);
    } catch {
      // Listener failures must not affect request flow.
    }
  });
}

function beginRequest(): void {
  inFlightRequests += 1;
  emitRequestCount();
}

function endRequest(): void {
  inFlightRequests = Math.max(0, inFlightRequests - 1);
  emitRequestCount();
}

export function getGlobalInFlightRequestCount(): number {
  return inFlightRequests;
}

export function subscribeGlobalInFlightRequestCount(listener: RequestCountListener): () => void {
  requestCountListeners.add(listener);
  listener(inFlightRequests);
  return () => {
    requestCountListeners.delete(listener);
  };
}

export async function trackedFetch(input: RequestInfo | URL, init?: RequestInit, track = true): Promise<Response> {
  if (track) {
    beginRequest();
  }
  try {
    return await fetch(input, init);
  } finally {
    if (track) {
      endRequest();
    }
  }
}

function timeoutSignal(timeoutMs: number): AbortSignal {
  // AbortSignal.timeout is available in all modern browsers and auto-cleans up
  if (typeof AbortSignal.timeout === "function") {
    return AbortSignal.timeout(timeoutMs);
  }
  // Fallback for older environments
  const controller = new AbortController();
  window.setTimeout(() => controller.abort(), timeoutMs);
  return controller.signal;
}

function buildServiceRequestInit(session: AuthSession, init: ServiceRequestInit | undefined, timeoutMs: number): RequestInit {
  const { skipGlobalLoading: _skipGlobalLoading, ...requestInit } = (init || {}) as ServiceRequestInit;
  return {
    ...requestInit,
    signal: timeoutSignal(timeoutMs),
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${session.token}`,
      "X-Tenant-ID": session.tenantId,
      "X-Request-ID": crypto.randomUUID(),
      ...(requestInit?.headers || {})
    }
  };
}

async function parseError(response: Response): Promise<string> {
  if (response.status === 429) {
    const retryAfter = response.headers.get("Retry-After");
    const wait = retryAfter ? ` Retry after ${retryAfter}s.` : "";
    return `Rate limit exceeded.${wait}`;
  }
  const fallback = `Request failed (${response.status})`;
  try {
    const payload = (await response.json()) as APIErrorShape;
    return payload.error?.message || fallback;
  } catch {
    return fallback;
  }
}

export async function serviceRequest<T = unknown>(
  session: AuthSession,
  service: string,
  path: string,
  init?: ServiceRequestInit,
  timeoutMs = REQUEST_TIMEOUT_MS
): Promise<T> {
  const response = await serviceRequestRaw(session, service, path, init, timeoutMs);
  if (!response.ok) {
    throw new Error(await parseError(response));
  }
  if (response.status === 204) {
    return undefined as T;
  }
  const ct = response.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    return (await response.json()) as T;
  }
  return (await response.text()) as T;
}

export async function serviceRequestRaw(
  session: AuthSession,
  service: string,
  path: string,
  init?: ServiceRequestInit,
  timeoutMs = REQUEST_TIMEOUT_MS
): Promise<Response> {
  const url = `/svc/${service}${path}`;
  const track = !Boolean(init?.skipGlobalLoading);
  return trackedFetch(url, buildServiceRequestInit(session, init, timeoutMs), track);
}
