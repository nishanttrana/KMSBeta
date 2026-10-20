import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { enabledFeatures } from "../../src/lib/deployment";

// The console read a deployment.yaml baked into its image with every feature
// on, while the stack ran from infra/deployment/deployment.yaml with
// clustering off: the Cluster module showed and every load answered 503
// (13.28.0-beta). The deployment has one file, mounted into the container.
const dashboard = join(__dirname, "..", "..");
const repo = join(dashboard, "..", "..");

describe("deployment source", () => {
  it("ships no deployment file of its own", () => {
    expect(existsSync(join(dashboard, "public", "config", "deployment.yaml"))).toBe(false);
  });

  it("is given the stack's deployment file by compose", () => {
    const compose = readFileSync(join(repo, "docker-compose.yml"), "utf8");
    expect(compose).toContain("./infra/deployment/deployment.yaml:/usr/share/nginx/html/config/deployment.yaml:ro");
  });

  it("reads an unreadable deployment as unknown, not as one with features", () => {
    expect(enabledFeatures({}).size).toBe(0);
  });
});
