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

export function hasPermission(session: unknown, token: string): boolean {
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

// A platform administrator: signed in to the root tenant and holding
// auth.tenant.read or auth.tenant.write, the server's own rule (auth
// platformAdministrator).
// Being in the root tenant alone made the bootstrap CLI account, which holds
// only auth.password.change, a "System Admin" shown every module
// (13.21.0-beta).
export function isSystemAdminSession(session: unknown): boolean {
  const tenantID = String((session as { tenantId?: unknown })?.tenantId || "").trim().toLowerCase();
  return tenantID === "root" && (hasPermission(session, "auth.tenant.read") || hasPermission(session, "auth.tenant.write"));
}

// The permission a module's own data needs (any one of them). The service
// refuses everything else on the page without it, so the module is not
// listed: a page of "missing permission" errors and zeros is no page.
// Modules whose data is readable by any signed-in user of the tenant are
// not listed here. Checked against docs/generated/backend-routes.csv by
// tests/unit/moduleAccess.test.ts.
export const MODULE_READ: Record<string, string[]> = {
  vault: ["secrets.read"],
  crypto_agility: ["key.agility.read"],
  discovery: ["discovery.read"],
  workload: ["workload.read"],
  confidential: ["confidential.read"],
  alerts: ["reporting.read"],
  posture: ["posture.read"],
  sbom: ["sbom.read"],
  playbooks: ["compliance.playbook.read", "compliance.connection.use"],
};

function holdsModuleRead(tabID: string, session: unknown): boolean {
  const need = MODULE_READ[tabID];
  return !need || need.some((perm) => hasPermission(session, perm));
}

export function canAccessModule(tabID: string, features: Set<FeatureKey>, session?: unknown): boolean {
  const normalizedTab = String(tabID || "").trim().toLowerCase();
  if (!normalizedTab) {
    return false;
  }

  if (!holdsModuleRead(normalizedTab, session)) {
    return false;
  }

  // A module whose feature the deployment leaves out is shown to no one,
  // platform administrators included: its service isn't running, so every
  // call answers 503 (13.28.0-beta, Cluster with clustering off).
  if (!matchesFeatureNeed(TAB_FEATURES[normalizedTab], features)) {
    return false;
  }

  // Root/system-admin sees every deployed module.
  if (isSystemAdminSession(session)) {
    return true;
  }
  // Backup & Restore is system administration: both its views (Encrypted
  // Backups, Schedules) are root administrators' routes (13.43.0-beta).
  if (normalizedTab === "backup") {
    return false;
  }

  // Optional explicit module-level RBAC overrides. They match only when
  // granted by name: "*" grants every permission, and read as a deny rule
  // it hid every module from a tenant administrator outside root.
  const granted = normalizePermissionTokens(session);
  if (granted.has(`ui.module.deny:${normalizedTab}`)) {
    return false;
  }
  const hasExplicitAllow = granted.has(`ui.module.allow:${normalizedTab}`);
  if (hasExplicitAllow) {
    return true;
  }

  // A tenant's own administrators manage its users (User Management);
  // System and Tenant Administration stay with the platform (root) tenant.
  if (normalizedTab === "admin") {
    return hasPermission(session, "auth.user.read");
  }

  return true;
}
