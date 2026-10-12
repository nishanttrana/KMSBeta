import type { AuthSession } from "./auth";
import { DISCOVERED_SERVICES } from "./restCatalog";
import { serviceRequestRaw } from "./serviceApi";

// The playground may call the services that register routes, and no other
// name: user input never reaches an arbitrary internal host. The list is the
// discovered catalogue's (it named four services that do not exist).
const ALLOWED_SERVICES = DISCOVERED_SERVICES;

// Allowlist of HTTP methods
const ALLOWED_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]);

type ExecuteRestPlaygroundRequestInput = {
  baseSession: AuthSession | null;
  token: string;
  tenantId: string;
  service: string;
  path: string;
  method: string;
  bodyJSON?: string;
};

function buildPlaygroundSession(input: ExecuteRestPlaygroundRequestInput): AuthSession {
  return {
    token: input.token,
    tenantId: input.tenantId,
    username: String(input.baseSession?.username || "api-playground"),
    role: String(input.baseSession?.role || "admin"),
    mode: input.baseSession?.mode === "backend" ? "backend" : "local",
    mustChangePassword: Boolean(input.baseSession?.mustChangePassword)
  };
}

export async function executeRestPlaygroundRequest(
  input: ExecuteRestPlaygroundRequestInput
): Promise<Response> {
  const service = String(input.service || "").trim().toLowerCase();
  const path    = String(input.path    || "").trim();
  const method  = String(input.method  || "GET").trim().toUpperCase();

  // A01 — validate service is in the internal allowlist
  if (!ALLOWED_SERVICES.has(service)) {
    throw new Error(`Service "${service}" is not permitted`);
  }

  // A01 — block path traversal sequences
  if (path.includes("..") || path.includes("//") || /[\r\n]/.test(path)) {
    throw new Error("Invalid path");
  }

  // A03 — restrict HTTP method to safe allowlist
  if (!ALLOWED_METHODS.has(method)) {
    throw new Error(`Method "${method}" is not allowed`);
  }

  // A03 — validate body is valid JSON when provided
  const rawBody = String(input.bodyJSON || "").trim();
  if (rawBody) {
    try {
      JSON.parse(rawBody);
    } catch {
      throw new Error("Request body is not valid JSON");
    }
  }

  return serviceRequestRaw(
    buildPlaygroundSession(input),
    service,
    path,
    {
      method,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${input.token}`,
        "X-Tenant-ID": input.tenantId
      },
      ...(rawBody ? { body: rawBody } : {})
    }
  );
}
