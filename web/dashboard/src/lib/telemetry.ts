import type { AuthSession } from "./auth";
import { serviceRequest } from "./serviceApi";

const MAX_MESSAGE = 4096;
const MAX_STACK = 32768;

type TelemetryContext = Record<string, unknown>;

function trimTo(value: string, maxLen: number): string {
  if (!value) {
    return "";
  }
  return value.length > maxLen ? value.slice(0, maxLen) : value;
}

function asError(input: unknown): Error {
  if (input instanceof Error) {
    return input;
  }
  if (typeof input === "string") {
    return new Error(input);
  }
  try {
    return new Error(JSON.stringify(input));
  } catch {
    return new Error(String(input));
  }
}

function hashFingerprint(value: string): string {
  // Lightweight deterministic hash (djb2) for grouping repeated client errors.
  let hash = 5381;
  for (let i = 0; i < value.length; i += 1) {
    hash = ((hash << 5) + hash) + value.charCodeAt(i);
    hash >>>= 0;
  }
  return `fp_${hash.toString(16)}`;
}

export async function captureFrontendError(
  session: AuthSession | null,
  err: unknown,
  context: TelemetryContext = {},
  level = "error"
): Promise<void> {
  if (!session?.token || !session.tenantId) {
    return;
  }
  const error = asError(err);
  const message = trimTo(String(error.message || "unknown frontend error"), MAX_MESSAGE);
  const stack = trimTo(String(error.stack || ""), MAX_STACK);
  const releaseTag = String(import.meta.env.VITE_RELEASE || "dashboard").trim() || "dashboard";
  const buildVersion = String(import.meta.env.VITE_VERSION || "dev").trim() || "dev";
  const component = String(context.component || "ui").trim() || "ui";
  const fingerprint = hashFingerprint(`${component}:${message}:${stack.split("\n")[1] || ""}`);
  const requestID = String(context.request_id || context.requestId || "").trim();

  try {
    await serviceRequest(session, "reporting", "/telemetry/errors", {
      method: "POST",
      body: JSON.stringify({
        tenant_id: session.tenantId,
        source: "frontend",
        service: "dashboard",
        component,
        level,
        message,
        stack_trace: stack,
        context,
        fingerprint,
        request_id: requestID,
        release_tag: releaseTag,
        build_version: buildVersion
      })
    }, 5000);
  } catch {
    // Never surface telemetry transport failures to end users.
  }
}
