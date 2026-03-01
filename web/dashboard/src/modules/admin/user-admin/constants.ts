import type { PasswordPolicy, SecurityPolicy } from "../../../lib/authAdmin";

export const ROLE_OPTIONS = ["admin", "tenant-admin", "approver", "operator", "auditor", "viewer"] as const;
export const STATUS_OPTIONS = ["active", "disabled"] as const;

export const defaultPasswordPolicy: PasswordPolicy = {
  tenant_id: "",
  min_length: 12,
  max_length: 128,
  require_upper: true,
  require_lower: true,
  require_digit: true,
  require_special: true,
  require_no_whitespace: true,
  deny_username: true,
  deny_email_local_part: true,
  min_unique_chars: 6
};

export const defaultSecurityPolicy: SecurityPolicy = {
  tenant_id: "",
  max_failed_attempts: 5,
  lockout_minutes: 15,
  idle_timeout_minutes: 30
};

export const parseJsonObject = (source: string, label: string): Record<string, unknown> => {
  const raw = String(source || "").trim();
  if (!raw) {
    return {};
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // handled below
  }
  throw new Error(`${label} must be valid JSON object`);
};

export const prettyJson = (value: unknown): string => {
  if (!value || typeof value !== "object") {
    return "{}";
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return "{}";
  }
};
