import { expect, test } from "@playwright/test";

// Enterprise KM → Kubernetes builds the KMS v2 plugin's configuration from
// the tenant's real keys and API clients (13.33.0-beta).

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

test("the plugin configuration names the chosen key, client and the key_id Kubernetes will see", async ({ page }) => {
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  // Registered first: Playwright answers with the last matching route.
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const p = new URL(r.request().url()).pathname;
    if (p.endsWith("/svc/keycore/keys")) return r.fulfill(json({ items: [
      { id: "key_k8s", name: "cluster-secrets", algorithm: "AES-256", status: "active", current_version: 3, key_type: "symmetric", tags: [] },
      { id: "key_rsa", name: "signer", algorithm: "RSA-3072", status: "active", current_version: 1, key_type: "asymmetric", tags: [] },
    ] }));
    if (p.endsWith("/svc/auth/auth/clients")) return r.fulfill(json({ items: [
      { id: "cli_k8s", tenant_id: "root", client_name: "k8s-prod", client_type: "rest", status: "approved", auth_mode: "api_key" },
      { id: "cli_pending", tenant_id: "root", client_name: "pending", client_type: "rest", status: "pending", auth_mode: "api_key" },
    ] }));
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({ tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"] }));
  });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/#ekm/kubernetes");
  await page.getByLabel("Key").click();
  await expect(page.getByRole("option", { name: "signer" })).toHaveCount(0);
  await page.getByRole("option", { name: "cluster-secrets" }).click();
  await page.getByLabel("API client").click();
  await expect(page.getByRole("option", { name: "pending" })).toHaveCount(0);
  await page.getByRole("option", { name: "k8s-prod" }).click();
  const cfg = JSON.parse(await page.getByTestId("k8s-plugin-config").innerText());
  expect(cfg).toMatchObject({ tenant_id: "root", key_id: "key_k8s", client_id: "cli_k8s", api_key_file: "/etc/vecta-kms/api-key", socket: "/var/run/vecta-kms/kms.sock" });
  expect(cfg).not.toHaveProperty("api_key");
  await expect(page.getByText("key_k8s:v3")).toBeVisible();
  await expect(page.getByTestId("k8s-encryption-config")).toContainText("endpoint: unix:///var/run/vecta-kms/kms.sock");
});
