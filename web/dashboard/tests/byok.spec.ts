import { expect, test, type Page } from "@playwright/test";

// Cloud Key Control → BYOK: the console counts the tenant's cloud keys, every bar
// lists exactly the keys it counts, a key opens its custody and runs, an
// operation shows its steps with the CLI equivalent (a failed one too), and a
// failed source reads "unavailable". Payloads have the shape the cloud
// service returns (services/cloud/byok_routes.go).

const SHOTS = process.env.BYOK_SHOTS_DIR || "";
const DAY = 86400000;
const at = (days: number) => new Date(Date.now() + days * DAY).toISOString();
const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

const key = (id: string, provider: string, source: string, material: string, o: Record<string, unknown> = {}) => ({
  id, account_id: `acct_${provider}`, provider, region: "eu-west-1", key_id: `key_${id}`, source, origin: "byok", key_spec: "AES-256", usage: "encrypt",
  cloud_key_id: `${provider}-${id}`, cloud_key_ref: `ref-${id}`, alias: `alias/${id}`, cloud_state: "Enabled", material_state: material,
  current_material_id: material === "current" ? `mat-${id}` : "", created_by: "alice", created_at: at(-30), updated_at: at(-1), ...o,
});

const KEYS = [
  key("orders", "aws", "hsm", "current", { expires_at: at(10) }),
  key("payments", "aws", "kms", "current"),
  key("ledger", "azure", "hsm", "revoked"),
  key("search", "gcp", "kms", "pending_import"),
  { ...key("legacy", "aws", "", "current"), origin: "cloud-generated", source: "" },
];

const CAPS = { rotate: true, reimport: true, revoke: true, revoke_deletes: true, expiry: true, verify: true, specs: ["AES-256"] };
const PROVIDERS = ["aws", "azure", "gcp", "oci", "alibaba", "salesforce"].map((provider) => ({ provider, capabilities: CAPS }));

const step = (name: string, status: string, cli = "", error = "") => ({ name, status, cli, error, call: "", detail: "", started_at: at(0), finished_at: at(0) });
const RUN_OK = { id: "brun_1", byok_id: "orders", operation: "rotate", status: "succeeded", actor: "alice", started_at: at(0), finished_at: at(0), steps: [
  step("Rotate the KMS key", "succeeded"),
  step("Get the cloud's wrapping key", "succeeded", "aws kms get-parameters-for-import --key-id aws-orders --wrapping-algorithm RSAES_OAEP_SHA_256 --wrapping-key-spec RSA_4096"),
  step("Wrap the key material inside the HSM", "succeeded"),
  step("Import the wrapped material", "succeeded", "aws kms import-key-material --key-id aws-orders"),
  step("Make the new material current", "succeeded", "aws kms rotate-key-on-demand --key-id aws-orders"),
] };
const RUN_FAIL = { ...RUN_OK, id: "brun_2", operation: "verify", status: "failed", error: "Verify the key in the cloud: KMSInvalidStateException",
  steps: [step("Verify the key in the cloud", "failed", "aws kms encrypt --key-id aws-orders ...", "KMSInvalidStateException: the key has no material")] };

type Opts = { listDown?: boolean };

async function stub(page: Page, opts: Opts = {}, writes: string[] = []): Promise<void> {
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname.replace(/^\/svc\/[a-z-]+/, "");
    if (req.method() !== "GET") writes.push(`${req.method()} ${p}`);
    if (p === "/auth/tenants") return route.fulfill(json({ items: [{ id: "root", name: "root", status: "active" }] }));
    if (p === "/cloud/accounts") return route.fulfill(json({ items: [{ id: "acct_aws", provider: "aws", name: "aws-prod", default_region: "eu-west-1", status: "active", connection_id: "pbconn_aws" }] }));
    if (p === "/cloud/byok/providers") return route.fulfill(json({ items: PROVIDERS }));
    if (p === "/cloud/byok/keys") return route.fulfill(opts.listDown ? json({ error: { message: "cloud service unavailable" } }, 503) : json({ items: KEYS }));
    if (p === "/cloud/byok/runs") return route.fulfill(json({ items: [RUN_FAIL, RUN_OK] }));
    if (p === "/cloud/byok/keys/orders/rotate") return route.fulfill(json({ key: KEYS[0], run: RUN_OK }));
    if (p === "/cloud/byok/keys/orders/verify") return route.fulfill(json({ error: { code: "byok_run_failed", message: RUN_FAIL.error }, run: RUN_FAIL, key: KEYS[0] }, 502));
    if (p === "/cloud/byok/keys/orders") return route.fulfill(json({ key: KEYS[0], runs: [RUN_OK], materials: [
      { id: "m2", byok_id: "orders", kms_version: 2, kcv: "A1B2C3", cloud_material_id: "mat-orders", state: "current", scheme: "rsa-oaep-sha256", source: "hsm", wrapping_key_sha256: "AB", imported_at: at(-1) },
      { id: "m1", byok_id: "orders", kms_version: 1, kcv: "0F0F0F", cloud_material_id: "mat-old", state: "previous", scheme: "rsa-oaep-sha256", source: "hsm", wrapping_key_sha256: "CD", imported_at: at(-20) },
    ] }));
    if (p.startsWith("/cloud/inventory")) return route.fulfill(json({ items: [] }));
    return route.fulfill(json({ items: [] }));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
}

async function open(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 1200 });
  await page.goto("/");
  await page.getByText("Cloud Key Control", { exact: true }).first().click();
  await expect(page.getByRole("button", { name: "Bring your own key" })).toBeVisible();
}

const tile = (page: Page, label: string) => page.locator(".vecta-stat-card", { hasText: label });
const bar = (page: Page, label: string) => page.getByRole("button", { name: new RegExp(`^${label}\\s*\\d+$`) });

test("tiles and charts count the cloud keys, each bar lists exactly its keys", async ({ page }) => {
  await stub(page);
  await open(page);
  await expect(tile(page, "Cloud keys").locator(".vk-num")).toHaveText("5");
  await expect(tile(page, "Current material").locator(".vk-num")).toHaveText("2");
  await expect(tile(page, "Waiting for material").locator(".vk-num")).toHaveText("1");
  await expect(tile(page, "Revoked").locator(".vk-num")).toHaveText("1");
  await expect(tile(page, "Expiring in 30 days").locator(".vk-num")).toHaveText("1");
  await expect(tile(page, "Material from an HSM").locator(".vk-num")).toHaveText("2");
  if (SHOTS) {
    for (const theme of ["dark", "light"]) {
      await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
      await page.screenshot({ path: `${SHOTS}/byok-${theme}.png`, fullPage: true });
    }
  }
  await expect(page.getByText("All cloud keys: 5 entries")).toBeVisible();
  await bar(page, "AWS KMS").click();
  await expect(page.getByText("AWS KMS: 3 entries")).toBeVisible();
  await bar(page, "Cloud-generated").click();
  await expect(page.getByText("Cloud-generated (read-only): 1 entry")).toBeVisible();
  await tile(page, "Material from an HSM").click();
  await expect(page.getByText("Material from HSM: 2 entries")).toBeVisible();
});

test("a key opens its custody; rotate shows its steps; a failed verify shows the failed step", async ({ page }) => {
  const writes: string[] = [];
  await stub(page, {}, writes);
  await open(page);
  await page.getByText("alias/orders").first().click();
  await expect(page.getByText("Custody")).toBeVisible();
  await expect(page.getByText("A1B2C3")).toBeVisible();
  await expect(page.getByText("0F0F0F")).toBeVisible();

  await page.getByRole("button", { name: "Rotate", exact: true }).click();
  await expect(page.getByText("Make the new material current")).toBeVisible();
  await expect(page.getByText("aws kms rotate-key-on-demand --key-id aws-orders").first()).toBeVisible();
  expect(writes).toContain("POST /cloud/byok/keys/orders/rotate");

  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(page.getByText("KMSInvalidStateException: the key has no material").first()).toBeVisible();
});

test("a failed source reads unavailable, never zero keys", async ({ page }) => {
  await stub(page, { listDown: true });
  await open(page);
  await expect(page.getByText(/BYOK unavailable: cloud service unavailable/)).toBeVisible();
});
