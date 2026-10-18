import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { canAccessModule, MODULE_READ } from "../../src/config/moduleRegistry";

// A module is listed only for a user who holds its data's read permission
// (13.21.0-beta): the bootstrap CLI account was shown every module and each
// filled with "missing permission" errors and zeros.
describe("module read permissions", () => {
  const routes = readFileSync(resolve(__dirname, "../../../../docs/generated/backend-routes.csv"), "utf8")
    .split("\n").slice(1).map((line) => line.split(","));
  const getPerms = new Set(routes.filter((r) => r[1] === "GET").map((r) => r[6]));

  it("names only permissions a GET route really requires", () => {
    for (const [mod, perms] of Object.entries(MODULE_READ)) {
      for (const perm of perms) expect(getPerms.has(perm), `${mod}: ${perm}`).toBe(true);
    }
  });

  it("hides a module whose data the user may not read, for root too", () => {
    const features = new Set<any>();
    const cli = { tenantId: "root", role: "cli-user", permissions: ["auth.password.change"] };
    for (const mod of Object.keys(MODULE_READ)) expect(canAccessModule(mod, features, cli), mod).toBe(false);
    // Modules any signed-in user of the tenant can read stay listed.
    for (const mod of ["home", "keys", "certs", "audit"]) expect(canAccessModule(mod, features, cli), mod).toBe(true);
    expect(canAccessModule("posture", features, { tenantId: "bank-a", permissions: ["posture.read"] })).toBe(true);
    expect(canAccessModule("posture", features, { tenantId: "root", permissions: ["*"] })).toBe(true);
    // Credentials alone opens Playbooks (its Credentials view).
    expect(canAccessModule("playbooks", features, { tenantId: "bank-a", permissions: ["compliance.connection.use"] })).toBe(true);
  });
});
