import type { FeatureKey } from "./tabs";

type ModuleFeatureNeed = FeatureKey | "hsm_hardware_or_software" | ModuleFeatureNeed[];

const TAB_FEATURES: Record<string, ModuleFeatureNeed> = {
  // CORE — always visible, no feature gate
  // vault / secrets
  vault: "secrets",
  // CRYPTO & PKI
  certs: "certs",
  pqc: "pqc_migration",
  // DATA & POLICY
  dataprotection: ["data_protection"],
  tokenize: "data_protection",
  dataenc: "data_protection",
  autokey: "autokey_provisioning",
  keyaccess: "key_access_justifications",
  // CLOUD & IDENTITY
  signing: "artifact_signing",
  workload: "workload_identity",
  confidential: "confidential_compute",
  // Cloud Keys tab merges BYOK + HYOK — visible if either feature enabled
  cloudctl: ["cloud_byok", "hyok_proxy"],
  byok: "cloud_byok",
  hyok: "hyok_proxy",
  // EKM tab covers both EKM agents and KMIP clients
  ekm: ["ekm_database", "kmip_server"],
  kmip: "kmip_server",
  // INFRASTRUCTURE — qkd now hosts qrng as a sub-pane
  hsm: "hsm_hardware_or_software",
  // Quantum Sources tab visible if either QKD or QRNG feature is enabled
  cluster: "clustering",
  // GOVERNANCE — compliance now hosts posture + sbom as sub-panes
  approvals: "governance",
  alerts: "reporting_alerting",
  // Risk & Compliance tab visible if any of its three sub-pane features is enabled
  compliance: ["compliance_dashboard", "governance", "sbom_cbom"],
  // Posture tab: gated on posture_management or compliance_dashboard or governance
  posture: ["posture_management", "governance", "compliance_dashboard"],
  sbom: "sbom_cbom",
  // Crypto discovery
  discovery: "crypto_discovery",
  // Not a tab: gates Key inventory and Operation metrics in Overview > Operations
  key_analytics: "key_analytics",
};

function normalizePermissionTokens(session: unknown): Set<string> {
  const raw = Array.isArray((session as { permissions?: unknown })?.permissions)
    ? ((session as { permissions?: unknown[] }).permissions || [])
    : [];
  return new Set(
    raw
      .map((item) => String(item || "").trim().toLowerCase())
      .filter(Boolean)
  );
}

function hasPermission(session: unknown, token: string): boolean {
  const want = String(token || "").trim().toLowerCase();
  if (!want) {
    return false;
  }
  const permissions = normalizePermissionTokens(session);
  return permissions.has("*") || permissions.has(want);
}

export type { ModuleFeatureNeed };
export function matchesFeatureNeed(need: ModuleFeatureNeed | undefined, features: Set<FeatureKey>): boolean {
  if (!need) {
    return true;
  }
  // Runtime-safe fallback: when feature discovery payload is unavailable/empty,
  // keep modules visible instead of collapsing the UI.
  if (!features || features.size === 0) {
    return true;
  }
  if (Array.isArray(need)) {
    return need.some((item) => matchesFeatureNeed(item, features));
  }
  if (need === "hsm_hardware_or_software") {
    return features.has("hsm_hardware") || features.has("hsm_software");
  }
  return features.has(need);
}

export function isSystemAdminSession(session: unknown): boolean {
  const tenantID = String((session as { tenantId?: unknown })?.tenantId || "").trim().toLowerCase();
  return tenantID === "root";
}

export function canAccessModule(tabID: string, features: Set<FeatureKey>, session?: unknown): boolean {
  const normalizedTab = String(tabID || "").trim().toLowerCase();
  if (!normalizedTab) {
    return false;
  }

  // Root/system-admin sees full platform module set.
  if (isSystemAdminSession(session)) {
    return true;
  }

  // Optional explicit module-level RBAC overrides.
  if (hasPermission(session, `ui.module.deny:${normalizedTab}`)) {
    return false;
  }
  const hasExplicitAllow = hasPermission(session, `ui.module.allow:${normalizedTab}`);
  if (hasExplicitAllow) {
    return true;
  }

  if (normalizedTab === "admin") {
    return isSystemAdminSession(session);
  }

  return matchesFeatureNeed(TAB_FEATURES[normalizedTab], features);
}
