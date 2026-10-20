import { expect, test, type Page } from "@playwright/test";

// The Cluster module follows the stack's deployment file, and a cluster
// service that doesn't answer is shown once on the page, not toasted on every
// poll (13.28.0-beta).

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const deployment = (clustering: boolean) => `apiVersion: kms.vecta.io/v1
kind: DeploymentConfig
spec:
  hsm_mode: software
  features:
    secrets: true
    clustering: ${clustering}
`;

async function stub(page: Page, clustering: boolean): Promise<{ overviewCalls: number }> {
  const seen = { overviewCalls: 0 };
  await page.route("**/config/deployment.yaml", (r) => r.fulfill({ status: 200, contentType: "text/yaml", body: deployment(clustering) }));
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const p = new URL(r.request().url()).pathname;
    if (p.includes("/svc/cluster/")) {
      if (p.endsWith("/cluster/overview")) seen.overviewCalls += 1;
      // What Envoy answers when no cluster-manager is running.
      return r.fulfill({ status: 503, contentType: "text/plain", body: "no healthy upstream" });
    }
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  return seen;
}

test("Cluster is not offered where the deployment has clustering off", async ({ page }) => {
  await stub(page, false);
  await page.goto("/");
  await expect(page.locator(".vk-nav-item", { hasText: "Secret Vault" }).first()).toBeVisible();
  await expect(page.locator(".vk-nav-item", { hasText: /^Cluster$/ })).toHaveCount(0);
});

test("a cluster service that doesn't answer is shown on the page once, with a retry", async ({ page }) => {
  const seen = await stub(page, true);
  await page.goto("/#cluster/topology");
  await expect(page.getByTestId("cluster-unavailable")).toHaveText("Cluster service not running");
  await expect(page.getByText("clustering: true")).toBeVisible();
  await expect(page.getByText(/Cluster load failed/)).toHaveCount(0);
  const before = seen.overviewCalls;
  await page.getByRole("button", { name: "Retry" }).click();
  await expect.poll(() => seen.overviewCalls).toBeGreaterThan(before);
  await expect(page.getByTestId("cluster-unavailable")).toBeVisible();
});
