import type { AuthSession } from "./auth";

type APIErrorShape = {
  error?: {
    message?: string;
  };
};

const REQUEST_TIMEOUT_MS = 20_000;

function timeoutSignal(timeoutMs: number): AbortSignal {
  const controller = new AbortController();
  window.setTimeout(() => controller.abort(), timeoutMs);
  return controller.signal;
}

async function parseError(response: Response): Promise<string> {
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
  init?: RequestInit,
  timeoutMs = REQUEST_TIMEOUT_MS
): Promise<T> {
  const url = `/svc/${service}${path}`;
  const response = await fetch(url, {
    ...init,
    signal: timeoutSignal(timeoutMs),
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${session.token}`,
      "X-Tenant-ID": session.tenantId,
      ...(init?.headers || {})
    }
  });
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

