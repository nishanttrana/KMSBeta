import { expect, test, type Request } from "@playwright/test";

// SBOM / CBOM before the first snapshot (13.64.0-beta): the service answers
// 404 not_found for the latest reads. The page showed "not found" and nothing
// else; it now reads "Not generated", and Generate BOM makes both.
const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const notFound = json({ error: { code: "not_found", message: "snapshot not found" } }, 404);
const DEPLOYMENT = "spec:\n  hsm_mode: software\n  features: {sbom_cbom: true}\n";
const sbom = { id: "sbom_1", created_at: new Date().toISOString(), document: { format: "cyclonedx", spec_version: "1.6", components: [{ name: "golang.org/x/crypto", version: "v0.40.0", type: "library", ecosystem: "go" }] } };
const cbom = { id: "cbom_1", tenant_id: "root", created_at: new Date().toISOString(), document: { format: "cyclonedx", spec_version: "1.6", tenant_id: "root", assets: [], algorithm_distribution: {}, strength_histogram: {}, deprecated_count: 0, pqc_ready_count: 0, total_asset_count: 3, pqc_readiness_percent: 0 } };

test("SBOM / CBOM reads Not generated before the first snapshot, and Generate BOM makes both", async ({ page }) => {
  const generated: Request[] = [];
  let made = false;
  await page.route("**/config/deployment.yaml", (r) => r.fulfill({ status: 200, contentType: "text/yaml", body: DEPLOYMENT }));
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const req = r.request();
    const p = new URL(req.url()).pathname;
    if (p.endsWith("/generate")) { generated.push(req); made = true; return r.fulfill(json({ snapshot: p.includes("/cbom/") ? cbom : sbom }, 202)); }
    if (p.endsWith("/sbom/latest")) return r.fulfill(made ? json({ item: sbom }) : notFound);
    if (p.endsWith("/cbom/latest")) return r.fulfill(made ? json({ item: cbom }) : notFound);
    if (p.endsWith("/cbom/summary")) return r.fulfill(made ? json({ summary: { total_assets: 3 } }) : notFound);
    if (p.endsWith("/cbom/pqc-readiness")) return r.fulfill(made ? json({ pqc_readiness: { total_assets: 3 } }) : notFound);
    if (p.endsWith("/history")) return r.fulfill(json({ items: made ? [p.includes("/cbom/") ? cbom : sbom] : [] }));
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "admin-1", token: "t", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  await page.goto("/#sbom");

  const tile = (label: string) => page.locator(".vecta-stat-card", { hasText: label });
  await expect(tile("Dependencies")).toContainText("Not generated");
  await expect(tile("Crypto Assets")).toContainText("Not generated");
  await expect(page.getByText(/not found|load failed/i)).toHaveCount(0);

  await page.getByRole("button", { name: "Generate BOM" }).click();
  await expect.poll(() => generated.length).toBe(2);
  await expect(tile("Dependencies")).toContainText("1");
  await expect(tile("Crypto Assets")).toContainText("3");
  await expect(page.getByRole("button", { name: "Refresh BOM" })).toBeVisible();
});
