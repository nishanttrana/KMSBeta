import { describe, expect, it } from "vitest";
import { canAccessModule, isSystemAdminSession } from "../../src/config/moduleRegistry";
import { enabledFeatures, type DeploymentConfig } from "../../src/lib/deployment";

describe("moduleRegistry", () => {
  it("opens Administration to root and to a tenant's user administrators", () => {
    const features = new Set();
    expect(canAccessModule("admin", features, { tenantId: "root", role: "admin", permissions: ["*"] })).toBe(true);
    // A role name grants nothing: root with no permissions is no administrator.
    expect(canAccessModule("admin", features, { tenantId: "root", role: "admin", permissions: [] })).toBe(false);
    expect(canAccessModule("admin", features, { tenantId: "root", role: "viewer", permissions: ["auth.tenant.read"] })).toBe(true);
    // A tenant's own administrator manages its users (User Management only).
    expect(canAccessModule("admin", features, { tenantId: "bank-a", role: "admin", permissions: ["*"] })).toBe(true);
    expect(canAccessModule("admin", features, { tenantId: "bank-a", role: "readonly", permissions: ["auth.user.read"] })).toBe(true);
    expect(canAccessModule("admin", features, { tenantId: "bank-a", role: "cli-user", permissions: ["auth.self.read"] })).toBe(false);
  });

  it("reads a module deny rule only when it is granted by name, never from \"*\"", () => {
    const features = new Set(["cloud_byok"] as const);
    const tenantAdmin = { tenantId: "bank-a", role: "admin", permissions: ["*"] };
    expect(canAccessModule("byok", features as any, tenantAdmin)).toBe(true);
    expect(canAccessModule("home", features as any, tenantAdmin)).toBe(true);
    expect(canAccessModule("byok", features as any, { tenantId: "bank-a", permissions: ["*", "ui.module.deny:byok"] })).toBe(false);
  });

  it("applies feature and permission visibility rules", () => {
    const features = new Set(["cloud_byok", "data_protection"] as const);
    expect(canAccessModule("byok", features as any, {})).toBe(true);
    expect(canAccessModule("hyok", features as any, {})).toBe(false);
    expect(canAccessModule("byok", features as any, { permissions: ["ui.module.deny:byok"] })).toBe(false);
    expect(canAccessModule("hyok", features as any, { permissions: ["ui.module.allow:hyok"] })).toBe(true);
  });

  it("derives deployment feature set from config", () => {
    const cfg: DeploymentConfig = {
      spec: {
        hsm_mode: "hardware",
        features: {
          cloud_byok: true,
          hyok_proxy: false,
          data_protection: true
        }
      }
    };
    const features = enabledFeatures(cfg);
    expect(features.has("cloud_byok")).toBe(true);
    expect(features.has("data_protection")).toBe(true);
    expect(features.has("hsm_hardware")).toBe(true);
    expect(features.has("hsm_software")).toBe(false);
  });

  it("recognizes system admin session", () => {
    expect(isSystemAdminSession({ tenantId: "root", role: "admin", permissions: ["*"] })).toBe(true);
    expect(isSystemAdminSession({ tenantId: "root", role: "super-admin" })).toBe(false);
    // The bootstrap CLI account: root tenant, one permission (13.21.0-beta).
    expect(isSystemAdminSession({ tenantId: "root", role: "cli-user", permissions: ["auth.password.change"] })).toBe(false);
    expect(isSystemAdminSession({ tenantId: "root", role: "viewer", permissions: ["auth.tenant.write"] })).toBe(true);
    expect(isSystemAdminSession({ tenantId: "tenant-a", role: "super-admin" })).toBe(false);
  });
});
