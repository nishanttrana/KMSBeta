import { describe, expect, it } from "vitest";
import { canAccessModule, isSystemAdminSession } from "../../src/config/moduleRegistry";
import { enabledFeatures, type DeploymentConfig } from "../../src/lib/deployment";

describe("moduleRegistry", () => {
  it("allows admin module only for root system admin session", () => {
    const features = new Set();
    expect(canAccessModule("admin", features, { tenantId: "root", role: "admin", permissions: [] })).toBe(true);
    expect(canAccessModule("admin", features, { tenantId: "root", role: "viewer", permissions: ["auth.tenant.read"] })).toBe(true);
    expect(canAccessModule("admin", features, { tenantId: "bank-a", role: "admin", permissions: ["*"] })).toBe(false);
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
    expect(isSystemAdminSession({ tenantId: "root", role: "super-admin" })).toBe(true);
    expect(isSystemAdminSession({ tenantId: "root", role: "viewer", permissions: ["auth.tenant.write"] })).toBe(true);
    expect(isSystemAdminSession({ tenantId: "tenant-a", role: "super-admin" })).toBe(false);
  });
});
