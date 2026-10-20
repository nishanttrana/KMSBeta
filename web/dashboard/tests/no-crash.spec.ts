import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "@playwright/test";

// Every view renders when its services answer nothing useful: an empty
// object, or 503. A page shows "unavailable" for a failed source; it never
// falls into the error boundary or throws (13.31.0-beta: Service mTLS and
// EKM for DBs crashed on a response without its list).

const src = (p: string) => readFileSync(join(process.cwd(), "src", p), "utf8");

function allViews(): string[] {
  const nav = [...src("components/v3/shellNav.ts").matchAll(/\{ id: "([a-z_]+)", icon:/g)].map((m) => m[1]!);
  const sub = src("components/v3/SidebarSubNav.tsx");
  const body = sub.slice(sub.indexOf("export const SUB_PANES"), sub.indexOf("// The sub-options of one module"));
  const panes: Record<string, string[]> = {};
  let cur = "";
  for (const line of body.split("\n")) {
    const mod = line.match(/^ {2}([a-z_]+): \[/);
    if (mod) { cur = mod[1]!; panes[cur] = []; continue; }
    const id = line.match(/\{ id: "([a-z0-9-]+)"/);
    if (id && cur) panes[cur]!.push(id[1]!);
  }
  return nav.flatMap((n) => (panes[n] ? panes[n]!.map((p) => `${n}/${p}`) : [n]));
}

const DEPLOYMENT = `spec:
  hsm_mode: software
  features: {secrets: true, certs: true, governance: true, cloud_byok: true, hyok_proxy: true, kmip_server: true, qkd_interface: true, qrng_generator: true, ekm_database: true, autokey_provisioning: true, artifact_signing: true, key_access_justifications: true, workload_identity: true, confidential_compute: true, compliance_dashboard: true, sbom_cbom: true, reporting_alerting: true, posture_management: true, pqc_migration: true, crypto_discovery: true, mpc_engine: true, data_protection: true, clustering: true}
`;

for (const mode of ["empty", "down"] as const) {
  test(`every view renders when services answer ${mode === "empty" ? "{}" : "503"}`, async ({ page }) => {
    test.setTimeout(180_000);
    const views = allViews();
    expect(views.length).toBeGreaterThan(50);
    await page.route("**/config/deployment.yaml", (r) => r.fulfill({ status: 200, contentType: "text/yaml", body: DEPLOYMENT }));
    for (const p of ["**/svc/**", "**/api/**"]) {
      await page.route(p, (r) => mode === "empty"
        ? r.fulfill({ status: 200, contentType: "application/json", body: "{}" })
        : r.fulfill({ status: 503, contentType: "application/json", body: '{"error":{"message":"service unavailable"}}' }));
    }
    await page.route("**/auth/**", (r) => r.fulfill({ status: 200, contentType: "application/json", body: "{}" }));
    await page.addInitScript(() => {
      window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
        tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
      }));
    });
    let errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    const faults: string[] = [];
    for (const view of views) {
      errors = [];
      await page.goto(`/#${view}`);
      await page.waitForTimeout(400);
      if (await page.getByText(/failed to render/i).count()) faults.push(`${view}: crashed`);
      if (errors.length) faults.push(`${view}: ${[...new Set(errors)].join(" | ")}`);
    }
    expect(faults).toEqual([]);
  });
}
