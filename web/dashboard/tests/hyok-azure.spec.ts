import { expect, test, type Page, type Request } from "@playwright/test";

// Azure EKM is a HYOK protocol (13.30.0-beta): its card is on HYOK, Cloud
// Key Control no longer lists an "Azure EKM" view, and saving sends exactly
// the fields PUT /hyok/v1/endpoints/azure accepts (services/hyok/handler.go).

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const KEYS = [
  { id: "key_aes", name: "azure-kek", algorithm: "AES-256", status: "active", key_type: "symmetric", current_version: 1, tags: [] },
  { id: "key_rsa", name: "azure-rsa", algorithm: "RSA-3072", status: "active", key_type: "asymmetric", current_version: 1, tags: [] },
];
const CA = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";

async function stub(page: Page): Promise<Request[]> {
  const writes: Request[] = [];
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const req = r.request();
    const p = new URL(req.url()).pathname;
    if (p.endsWith("/compliance/connections")) return r.fulfill(json({ data: [
      { id: "pbconn_x1", tenant_id: "root", name: "aws-xks-primary", type: "aws_xks", endpoint: "", fields_set: ["access_key_id", "secret_access_key"], attributes: {}, created_by: "alice", created_at: "", updated_at: "" },
    ] }));
    if (p.endsWith("/hyok/v1/endpoints/aws_xks") && req.method() === "PUT") {
      writes.push(req);
      return r.fulfill(json({ endpoint: { protocol: "aws_xks", ...req.postDataJSON() } }));
    }
    if (p.endsWith("/hyok/v1/endpoints/oci_ekm") && req.method() === "PUT") {
      writes.push(req);
      return r.fulfill(json({ endpoint: { protocol: "oci_ekm", ...req.postDataJSON() } }));
    }
    if (p.endsWith("/hyok/v1/endpoints/azure") && req.method() === "PUT") {
      writes.push(req);
      return r.fulfill(json({ endpoint: { protocol: "azure", ...req.postDataJSON() } }));
    }
    if (p.endsWith("/hyok/v1/endpoints")) return r.fulfill(json({ items: [] }));
    if (p.endsWith("/hyok/v1/requests")) return r.fulfill(json({ items: [] }));
    if (p.endsWith("/hyok/v1/health")) return r.fulfill(json({ health: { status: "not_configured", tenant_id: "root", endpoint_count: 7, enabled_endpoints: 0, policy_fail_closed: true, protocol_statuses: {}, checked_at: new Date().toISOString() } }));
    if (p.endsWith("/svc/keycore/keys")) return r.fulfill(json({ items: KEYS }));
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  return writes;
}

test("Azure EKM is configured from HYOK and saves only the endpoint's fields", async ({ page }) => {
  const writes = await stub(page);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/#cloudctl/hyok");
  await expect(page.getByTestId("subnav-cloudctl")).toBeVisible();
  await expect(page.getByTestId("subnav-cloudctl").getByText("Azure EKM")).toHaveCount(0);

  const card = page.getByText("Azure Managed HSM external key management (EKM Proxy API)").locator("xpath=ancestor::*[.//button[normalize-space()='Configure']][1]");
  await expect(card).toBeVisible();
  await card.getByRole("button", { name: "Configure" }).click();

  const dialog = page.getByRole("dialog");
  await dialog.getByPlaceholder("contoso/mhsm-pool-1").fill("contoso/pool-1");
  await dialog.getByPlaceholder("Managed HSM client certificate CN").fill("mhsm-client");
  await dialog.getByPlaceholder("-----BEGIN CERTIFICATE-----").fill(CA);
  await dialog.getByLabel("Key name").fill("aes-key-1");
  await dialog.getByLabel("Vecta key").click();
  await page.getByRole("option", { name: /azure-kek/ }).click();
  await expect(dialog.getByTestId("azure-proxy-url")).toContainText(":8443/contoso/pool-1");
  await dialog.getByRole("button", { name: "Save" }).click();

  await expect.poll(() => writes.length).toBe(1);
  const body = writes[0]!.postDataJSON();
  expect(Object.keys(body).sort()).toEqual(["auth_mode", "enabled", "governance_required", "metadata_json", "policy_id", "tenant_id"]);
  expect(body).toMatchObject({ auth_mode: "mtls", governance_required: false, enabled: true });
  expect(JSON.parse(body.metadata_json)).toEqual({ path_prefix: "contoso/pool-1", client_ca_pem: CA, client_subject_cn: "mhsm-client", keys: { "aes-key-1": "key_aes" } });
});

test("AWS XKS is configured from HYOK with a stored credential and AES-256 keys only", async ({ page }) => {
  const writes = await stub(page);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/#cloudctl/hyok");
  const card = page.getByText("AWS KMS external key store (XKS proxy API)").locator("xpath=ancestor::*[.//button[normalize-space()='Configure']][1]");
  await card.getByRole("button", { name: "Configure" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByPlaceholder("contoso/xks").fill("contoso/xks");
  await dialog.locator("button[aria-haspopup='listbox']").first().click();
  await page.getByRole("option", { name: /aws-xks-primary/ }).click();
  await dialog.getByLabel("External key ID").fill("xks-key-1");
  await dialog.getByLabel("Vecta key").click();
  // The RSA key is not offered: XKS takes AES-256 only.
  await expect(page.getByRole("option", { name: /azure-rsa/ })).toHaveCount(0);
  await page.getByRole("option", { name: /azure-kek/ }).click();
  await expect(dialog.getByTestId("xks-uri-path")).toContainText("/svc/hyok/xks/contoso/xks");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect.poll(() => writes.length).toBe(1);
  const body = writes[0]!.postDataJSON();
  expect(Object.keys(body).sort()).toEqual(["auth_mode", "enabled", "governance_required", "metadata_json", "policy_id", "tenant_id"]);
  expect(body).toMatchObject({ auth_mode: "sigv4", governance_required: false });
  expect(JSON.parse(body.metadata_json)).toEqual({ path_prefix: "contoso/xks", credential_ids: ["pbconn_x1"], keys: { "xks-key-1": "key_aes" } });
});

test("OCI External KMS is configured from HYOK with the identity domain's JWKS and AES keys only", async ({ page }) => {
  const writes = await stub(page);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/#cloudctl/hyok");
  const card = page.getByText("Oracle Cloud external key management (External KMS vendor API)").locator("xpath=ancestor::*[.//button[normalize-space()='Configure']][1]");
  await card.getByRole("button", { name: "Configure" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByPlaceholder("contoso", { exact: true }).fill("contoso");
  await dialog.getByPlaceholder("vecta-vault-1").fill("vault-1");
  await dialog.getByPlaceholder(/SigningCert\/jwk/).fill("https://idcs-abc.identity.oraclecloud.com/admin/v1/SigningCert/jwk");
  await dialog.getByPlaceholder("https://10.0.0.5/").fill("https://10.0.0.5/");
  await dialog.getByLabel("Allowed client IDs").fill("ocid-client-1, ocid-client-2");
  await dialog.getByLabel("External key ID").fill("orders");
  await dialog.getByLabel("Vecta key").click();
  await expect(page.getByRole("option", { name: /azure-rsa/ })).toHaveCount(0);
  await page.getByRole("option", { name: /azure-kek/ }).click();
  await expect(dialog.getByTestId("oci-base-path")).toContainText("/svc/hyok/oci/contoso");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect.poll(() => writes.length).toBe(1);
  const body = writes[0]!.postDataJSON();
  expect(body).toMatchObject({ auth_mode: "oci_jwt", governance_required: false });
  expect(JSON.parse(body.metadata_json)).toEqual({
    path_prefix: "contoso", vault_id: "vault-1", issuer: "https://identity.oraclecloud.com/", jwks_url: "https://idcs-abc.identity.oraclecloud.com/admin/v1/SigningCert/jwk",
    audience: "https://10.0.0.5/", client_ids: ["ocid-client-1", "ocid-client-2"], keys: { orders: "key_aes" },
  });
});
