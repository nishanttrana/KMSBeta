import type { AuthSession } from "./auth";
import { serviceRequestRaw } from "./serviceApi";

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
  const method = String(input.method || "GET").trim().toUpperCase();
  return serviceRequestRaw(
    buildPlaygroundSession(input),
    String(input.service || "").trim(),
    String(input.path || "").trim(),
    {
      method,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${input.token}`,
        "X-Tenant-ID": input.tenantId
      },
      ...(String(input.bodyJSON || "").trim() ? { body: String(input.bodyJSON) } : {})
    }
  );
}

