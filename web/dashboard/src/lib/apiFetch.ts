import { trackedFetch } from "./serviceApi";

// Thin wrapper for legacy tabs that build their own URLs/headers. Routes the
// request through the tracked client (in-flight overlay + telemetry) instead
// of calling window.fetch directly from UI modules.
export function apiFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  return trackedFetch(input, init);
}
