import { expect, test, type Page } from "@playwright/test";
import { coveredControls } from "./fixtures/layout";

// Cloud Key Control → BYOK: the console counts the tenant's cloud keys, every bar
// lists exactly the keys it counts, a key opens its custody and runs, an
// operation shows its steps with the CLI equivalent (a failed one too), and a
// failed source reads "unavailable". A key's settings, its automation rules
// and the cloud console send catalogue operations only, and offer only what
// the cloud has. Payloads have the shape the cloud service returns
// (services/cloud/byok_routes.go, console.go).

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

// The catalogue as GET /cloud/console/operations returns it. This account's
// cloud has no grants, so nothing about grants may be offered.
const op = (name: string, label: string, group: string, o: Record<string, unknown> = {}) => ({ name, label, group, mutating: false, needs_key: true, supported: true, ...o });
const OPS = [
  op("list-keys", "List keys", "Keys", { needs_key: false }),
  op("describe-key", "Describe key", "Keys"),
  op("enable-key", "Enable", "State", { mutating: true }),
  op("disable-key", "Disable", "State", { mutating: true, danger: true }),
  op("list-tags", "List tags", "Tags"),
  op("tag-key", "Set tag", "Tags", { mutating: true, params: [{ name: "tag_key", type: "string", required: true }, { name: "tag_value", type: "string" }] }),
  op("untag-key", "Remove tag", "Tags", { mutating: true, params: [{ name: "tag_key", type: "string", required: true }] }),
  op("encrypt", "Encrypt", "Try it", { params: [{ name: "plaintext_b64", type: "base64", required: true }] }),
  op("decrypt", "Decrypt", "Try it", { params: [{ name: "ciphertext_b64", type: "base64", required: true }] }),
  op("list-grants", "List grants", "Grants", { supported: false }),
  op("create-grant", "Create grant", "Grants", { supported: false, mutating: true }),
];
const answer = (operation: string, result: unknown, cli: string) => json({ result, cli, operation, provider: "aws" });
const CONSOLE: Record<string, ReturnType<typeof json>> = {
  "list-keys": answer("list-keys", [{ KeyId: "aws-orders" }], "aws kms list-keys"),
  "describe-key": answer("describe-key", { KeyState: "Enabled", Origin: "EXTERNAL" }, "aws kms describe-key --key-id aws-orders"),
  "list-tags": answer("list-tags", { env: "prod" }, "aws kms list-resource-tags --key-id aws-orders"),
  "tag-key": answer("tag-key", { tagged: "team" }, "aws kms tag-resource --key-id aws-orders --tags TagKey=team,TagValue=payments"),
  encrypt: answer("encrypt", { ciphertext_b64: "Y2lwaGVy" }, "aws kms encrypt --key-id aws-orders --plaintext fileb://plaintext.bin"),
  "disable-key": json({ error: { code: "cloud_error", message: "AccessDeniedException: not authorized to perform kms:DisableKey" }, cli: "aws kms disable-key --key-id aws-orders", operation: "disable-key" }, 502),
};

type Opts = { listDown?: boolean; bodies?: Record<string, unknown> };

async function stub(page: Page, opts: Opts = {}, writes: string[] = []): Promise<void> {
  const books: Record<string, unknown>[] = [];
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname.replace(/^\/svc\/[a-z-]+/, "");
    if (req.method() !== "GET") writes.push(`${req.method()} ${p}`);
    if (req.method() !== "GET" && opts.bodies) opts.bodies[p] = JSON.parse(req.postData() || "{}");
    if (p === "/cloud/console/operations") return route.fulfill(json({ provider: "aws", items: OPS }));
    if (p.startsWith("/cloud/console/")) return route.fulfill(CONSOLE[p.slice("/cloud/console/".length)] ?? json({ error: { code: "operation_not_supported", message: "not in this test's catalogue" } }, 409));
    if (p === "/cloud/byok/keys/orders/automation") return route.fulfill(json({ key: KEYS[0], automation: opts.bodies?.[p] ?? {} }));
    if (p === "/compliance/playbooks") {
      if (req.method() === "POST") books.push({ id: `pb_${books.length + 1}`, enabled: true, ...(JSON.parse(req.postData() || "{}") as Record<string, unknown>) });
      return route.fulfill(json({ data: books }));
    }
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

test("a key's settings show what its cloud has and send catalogue operations; a refused one shows the cloud's error", async ({ page }) => {
  const writes: string[] = [];
  const bodies: Record<string, unknown> = {};
  await stub(page, { bodies }, writes);
  await open(page);
  await page.getByText("alias/orders").first().click();
  await page.getByRole("button", { name: "Key settings", exact: true }).click();

  // State is read from the cloud on opening, with its CLI equivalent.
  await expect(page.getByText('"KeyState": "Enabled"')).toBeVisible();
  await expect(page.getByText("aws kms describe-key --key-id aws-orders")).toBeVisible();
  expect(bodies["/cloud/console/describe-key"]).toEqual({ account_id: "acct_aws", key: "aws-orders" });
  // This cloud has no grants: neither the tab nor an action is offered.
  await expect(page.getByRole("button", { name: "Grants", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Policy", exact: true })).toHaveCount(0);

  await page.getByRole("button", { name: "Tags", exact: true }).click();
  await expect(page.getByText("prod", { exact: true })).toBeVisible();
  await page.getByPlaceholder("key", { exact: true }).fill("team");
  await page.getByPlaceholder("value", { exact: true }).fill("payments");
  await page.getByRole("button", { name: "Set tag", exact: true }).click();
  await expect.poll(() => bodies["/cloud/console/tag-key"]).toEqual({ account_id: "acct_aws", key: "aws-orders", params: { tag_key: "team", tag_value: "payments" } });

  await page.getByRole("button", { name: "Try it", exact: true }).click();
  await page.getByPlaceholder("a message (text)").fill("hello");
  await page.getByRole("button", { name: "Encrypt", exact: true }).click();
  await expect(page.getByPlaceholder("ciphertext (base64)")).toHaveValue("Y2lwaGVy");
  expect(bodies["/cloud/console/encrypt"]).toEqual({ account_id: "acct_aws", key: "aws-orders", params: { plaintext_b64: "aGVsbG8=" } });

  // A change that stops applications asks first; the cloud's refusal is shown as it came.
  await page.getByRole("button", { name: "State", exact: true }).click();
  await page.getByRole("button", { name: "Disable", exact: true }).click();
  expect(writes).not.toContain("POST /cloud/console/disable-key");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("AccessDeniedException: not authorized to perform kms:DisableKey")).toBeVisible();
  await expect(page.getByText("aws kms disable-key --key-id aws-orders")).toBeVisible();
  if (SHOTS) {
    for (const theme of ["dark", "light"]) {
      await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
      await page.screenshot({ path: `${SHOTS}/byok-settings-${theme}.png`, fullPage: true });
    }
  }
});

test("automation rules are saved on the key, and a playbook is created to act on them", async ({ page }) => {
  const writes: string[] = [];
  const bodies: Record<string, unknown> = {};
  await stub(page, { bodies }, writes);
  await open(page);
  await page.getByText("alias/orders").first().click();
  await page.getByRole("button", { name: "Automation", exact: true }).click();

  await page.getByPlaceholder("30", { exact: true }).fill("30");
  await page.getByPlaceholder("90", { exact: true }).fill("90");
  await page.getByRole("button", { name: "Save rules" }).click();
  await expect.poll(() => bodies["/cloud/byok/keys/orders/automation"]).toEqual({ renew_before_days: 30, renew_validity_days: 90, rotate_every_days: 0 });
  expect(writes).toContain("PUT /cloud/byok/keys/orders/automation");

  await expect(page.getByText("Cloud BYOK: renew expiring material")).toBeVisible();
  await expect(page.getByRole("button", { name: "Create playbook" })).toHaveCount(2);
  await page.getByRole("button", { name: "Create playbook" }).first().click();
  await expect.poll(() => bodies["/compliance/playbooks"]).toEqual({
    name: "Cloud BYOK: renew expiring material", enabled: true, trigger: { type: "byok_material_expiring" },
    actions: [{ type: "byok_reimport", parameters: { byok_id: "{{event.target_id}}", validity_days: "{{event.details.validity_days}}" } }],
  });
  await expect(page.getByText("active", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Create playbook" })).toHaveCount(1);
  if (SHOTS) {
    for (const theme of ["dark", "light"]) {
      await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
      await page.screenshot({ path: `${SHOTS}/byok-automation-${theme}.png`, fullPage: true });
    }
  }
});

test("the cloud console runs a catalogue operation and keeps its CLI equivalent", async ({ page }) => {
  const bodies: Record<string, unknown> = {};
  await stub(page, { bodies });
  await open(page);
  await page.getByRole("button", { name: "Cloud console", exact: true }).click();
  const consoleBox = page.getByRole("dialog", { name: "Cloud console" });
  await expect(consoleBox.getByRole("button", { name: "Run List keys" })).toBeEnabled();
  await expect(consoleBox.getByRole("button", { name: "Export as script" })).toBeDisabled();
  expect(await coveredControls(consoleBox)).toEqual([]);

  await consoleBox.getByRole("button", { name: "Run List keys" }).click();
  await expect(consoleBox.getByText("aws kms list-keys", { exact: true })).toBeVisible();
  await expect(consoleBox.getByText("done", { exact: true })).toBeVisible();
  await expect(consoleBox.getByText('"KeyId": "aws-orders"')).toBeVisible();
  expect(bodies["/cloud/console/list-keys"]).toEqual({ account_id: "acct_aws", key: "", version: "", params: {} });
  await expect(consoleBox.getByRole("button", { name: "Export as script" })).toBeEnabled();
  expect(await coveredControls(consoleBox)).toEqual([]);
  if (SHOTS) {
    for (const theme of ["dark", "light"]) {
      await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
      await page.screenshot({ path: `${SHOTS}/byok-console-${theme}.png` });
    }
  }
});
