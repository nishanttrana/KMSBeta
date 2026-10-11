import { expect, test, type Page } from "@playwright/test";

// Playbooks → Credentials: the one place a credential for an external system
// is added. Tiles and charts count the tenant's own credentials, every bar
// lists exactly the entries it counts, a credential opens its detail with
// what uses it, and a failed source reads "unavailable" or "not assessed",
// never 0. Payloads have the shape compliance returns
// (services/compliance/playbook_connections.go).

const SHOTS = process.env.CREDENTIAL_SHOTS_DIR || "";
const DAY = 86400000;
const at = (days: number) => new Date(Date.now() + days * DAY).toISOString();
const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

type Over = { tested?: boolean | null; error?: string; ageDays?: number; expiresIn?: number; rotate?: number; attributes?: Record<string, string> };
const cred = (id: string, name: string, type: string, endpoint: string, o: Over = {}) => ({
  id, tenant_id: "root", name, type, endpoint, fields_set: ["secret"], attributes: o.attributes ?? {}, created_by: "alice",
  created_at: at(-400), updated_at: at(-(o.ageDays ?? 5)), credentials_changed_at: at(-(o.ageDays ?? 5)), rotate_after_days: o.rotate ?? 0,
  ...(o.expiresIn === undefined ? {} : { expires_at: at(o.expiresIn) }),
  ...(o.tested === undefined || o.tested === null ? {} : { last_tested_at: at(-1) }), last_test_ok: o.tested === true, last_test_error: o.error ?? "",
});

const CREDS = [
  cred("pbconn_aws", "AWS production", "aws", "AWS KMS", { tested: true, ageDays: 120, rotate: 90, attributes: { region: "eu-west-1" } }),
  cred("pbconn_azure", "Entra KMS app", "azure", "login.microsoftonline.com", { tested: false, error: "AADSTS7000215: invalid client secret", expiresIn: 5 }),
  cred("pbconn_luna", "Luna HA group", "pkcs11_hsm", "token prod-ha", { tested: true, attributes: { topology: "ha_group", vendor: "thales", token_label: "prod-ha" } }),
  cred("pbconn_smtp", "Mail relay", "smtp", "smtp.example.com", { tested: null, ageDays: 400 }),
  cred("pbconn_slack", "SOC Slack", "slack", "hooks.slack.com", { tested: true, expiresIn: -2 }),
  cred("pbconn_splunk", "Splunk HEC", "splunk_hec", "splunk.example.com", { tested: true, expiresIn: 200 }),
];

const TYPES = [
  { type: "aws", label: "AWS (access key, optional role)", category: "cloud", use: "Cloud BYOK", fields: ["access_key_id", "secret_access_key"], optional: ["region", "role_arn"], secrets: ["secret_access_key"] },
  { type: "azure", label: "Microsoft Entra app registration", category: "cloud", use: "Cloud BYOK, Azure EKM", fields: ["tenant_id", "client_id", "client_secret"], optional: [], secrets: ["client_secret"] },
  { type: "pkcs11_hsm", label: "PKCS#11 HSM", category: "hsm", use: "Keys, certificate authorities", fields: ["library_path", "pin"], optional: ["slot_id", "token_label", "topology", "vendor"], secrets: ["pin"], choices: { topology: ["single", "ha_group"] } },
  { type: "smtp", label: "SMTP mail relay", category: "mail", use: "Governance mail", fields: ["host", "port", "from"], optional: ["username", "password"], secrets: ["password"] },
  { type: "slack", label: "Slack incoming webhook", category: "notify", fields: ["webhook_url"], optional: [], secrets: ["webhook_url"], stream: true },
  { type: "splunk_hec", label: "Splunk HEC", category: "siem", fields: ["url", "token"], optional: [], secrets: ["token"], stream: true },
];

const EXPOSURE = { service: "compliance", open: 1, items: [
  { tenant_id: "root", item_type: "playbook_connection", item_id: "pbconn_slack", source: "plaintext_storage", exposed_since: "2026-09-28T08:00:00Z" },
  { tenant_id: "root", item_type: "playbook_connection", item_id: "pbconn_splunk", source: "plaintext_storage", exposed_since: "2026-09-28T08:00:00Z", remediated_at: "2026-09-28T08:30:00Z", remediation: "credentials_replaced" },
] };

const CATALOG = { triggers: [], actions: [], categories: [], connection_types: TYPES, event_fields: [], filter_ops: [], templates: [], incident_statuses: [] };

type Opts = { listDown?: boolean; exposureDown?: boolean; usageDown?: boolean };
type Write = { call: string; body: unknown };

async function stub(page: Page, opts: Opts = {}, writes: Write[] = []): Promise<void> {
  const down = json({ error: { message: "service unavailable" } }, 503);
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    const short = p.replace(/^\/svc\/[a-z-]+/, "");
    if (req.method() !== "GET") writes.push({ call: `${req.method()} ${short}`, body: req.postDataJSON() });
    if (p.endsWith("/mek/exposure")) return route.fulfill(p.startsWith("/svc/compliance/") ? (opts.exposureDown ? down : json(EXPOSURE)) : json({ items: [], open: 0 }));
    if (p.endsWith("/auth/tenants")) return route.fulfill(json({ items: [{ id: "root", name: "root", status: "active" }] }));
    if (p.endsWith("/compliance/playbooks/catalog")) return route.fulfill(json({ data: CATALOG }));
    if (p.endsWith("/compliance/private-endpoints")) return route.fulfill(json({ data: [], can_approve: false }));
    if (p.endsWith("/hsm/targets")) {
      return route.fulfill(json({ credentials_state: "listed", targets: [
        { id: "", kind: "tenant_profile", name: "Tenant HSM (HSM tab)", usable: false, reason: "HSM keys are off for the tenant's HSM: turn them on in the HSM tab", status: { connected: true, token_label: "root-of-trust" } },
        { id: "pbconn_luna", kind: "credential", name: "Luna HA group", topology: "ha_group", vendor: "thales", usable: true, status: { connected: true, manufacturer: "Thales", model: "Luna K7", token_label: "prod-ha", serial_number: "1513123" } },
        { id: "pbconn_single", kind: "credential", name: "Lab HSM", topology: "single", usable: false, reason: "C_Login: CKR_PIN_INCORRECT", status: { connected: false, error: "C_Login: CKR_PIN_INCORRECT" } },
      ] }));
    }
    if (/\/keys$/.test(p) && req.method() === "POST") return route.fulfill(json({ key_id: "key_new" }, 201));
    if (p.endsWith("/usage")) return route.fulfill(opts.usageDown ? down : json({ data: { used_by: p.includes("pbconn_luna") ? ["key payments-kek", "key ca-root-2026"] : [] } }));
    if (/\/compliance\/playbooks\/connections\/[^/]+\/test$/.test(p)) return route.fulfill(json({ data: { status: "ok" } }));
    if (p.endsWith("/compliance/playbooks/connections") && req.method() === "POST") return route.fulfill(json({ data: { ...CREDS[2], id: "pbconn_new", name: "New HSM" } }, 201));
    if (p.endsWith("/compliance/playbooks/connections")) return route.fulfill(opts.listDown ? down : json({ data: CREDS, types: TYPES }));
    if (p.endsWith("/compliance/playbooks/summary")) return route.fulfill(json({ data: {} }));
    if (p.endsWith("/compliance/playbooks") || p.includes("/playbook-runs") || p.includes("/incidents")) return route.fulfill(json({ data: [], items: [] }));
    return route.fulfill(json({}));
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
  await page.getByText("Playbooks", { exact: true }).first().click();
  await page.getByRole("button", { name: "Credentials" }).first().click();
  await expect(page.getByRole("button", { name: "Add credential" })).toBeVisible();
}

const bar = (page: Page, label: string) => page.getByRole("button", { name: new RegExp(`^${label}\\s*\\d+$`) });
const tile = (page: Page, label: string) => page.locator(".vecta-stat-card", { hasText: label });
const rows = (page: Page) => page.locator("div[style*='grid-template-columns: 2fr']");

test("tiles and charts count the credentials, and each bar lists exactly its entries", async ({ page }) => {
  await stub(page);
  await open(page);

  await expect(tile(page, "Credentials").locator(".vk-num").first()).toHaveText("6");
  await expect(tile(page, "Test passed").locator(".vk-num")).toHaveText("4");
  await expect(tile(page, "Test failed").locator(".vk-num")).toHaveText("1");
  await expect(tile(page, "Not tested").locator(".vk-num")).toHaveText("1");
  await expect(tile(page, "Expiring").locator(".vk-num")).toHaveText("2");
  await expect(tile(page, "Rotation due").locator(".vk-num")).toHaveText("1");
  await expect(tile(page, "Exposed").locator(".vk-num")).toHaveText("1");
  await expect(bar(page, "Cloud providers")).toContainText("2");
  await expect(bar(page, "HSMs")).toContainText("1");
  await expect(bar(page, "Over a year")).toContainText("1");
  await expect(bar(page, "Within 7 days")).toContainText("1");
  if (SHOTS) {
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "dark"));
    await page.screenshot({ path: `${SHOTS}/credentials-dark.png`, fullPage: true });
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "light"));
    await page.screenshot({ path: `${SHOTS}/credentials-light.png`, fullPage: true });
  }

  // Before a drill, the list is everything.
  await expect(page.getByText("All credentials: 6 entries")).toBeVisible();
  await bar(page, "Cloud providers").click();
  await expect(page.getByText("Cloud providers: 2 entries")).toBeVisible();
  await expect(rows(page)).toHaveCount(2);
  await expect(rows(page).filter({ hasText: "AWS production" })).toBeVisible();
  await expect(rows(page).filter({ hasText: "Entra KMS app" })).toBeVisible();

  await bar(page, "Test failed").click();
  await expect(page.getByText("Test failed: 1 entry")).toBeVisible();
  await expect(rows(page)).toHaveCount(1);
  await expect(rows(page).first()).toContainText("Entra KMS app");

  // The exposed credential, and only it, is flagged.
  await tile(page, "Exposed").click();
  await expect(page.getByText("Exposed: rotate now: 1 entry")).toBeVisible();
  await expect(rows(page).first()).toContainText("SOC Slack");
  await expect(rows(page).first().getByText("Rotate", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Clear" }).click();
  await expect(rows(page).filter({ hasText: "Splunk HEC" }).getByText("Rotate", { exact: true })).toHaveCount(0);
});

test("a credential opens its detail: health, age, what uses it, and no value", async ({ page }) => {
  await stub(page);
  await open(page);
  await rows(page).filter({ hasText: "Luna HA group" }).click();
  await expect(page.getByText("HA group", { exact: false }).first()).toBeVisible();
  await expect(page.getByText("(as declared)")).toBeVisible();
  await expect(page.getByText("key payments-kek")).toBeVisible();
  await expect(page.getByText("key ca-root-2026")).toBeVisible();
  await expect(page.getByText("Choose it in Keys")).toBeVisible();
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/credential-detail.png` });
});

test("when usage can't be read it says unavailable, not unused", async ({ page }) => {
  await stub(page, { usageDown: true });
  await open(page);
  await rows(page).filter({ hasText: "Luna HA group" }).click();
  await expect(page.getByText(/unavailable: service unavailable/)).toBeVisible();
  await expect(page.getByText("nothing yet")).toHaveCount(0);
});

test("adding an HSM credential sends its fields once and then tests it", async ({ page }) => {
  const writes: Write[] = [];
  await stub(page, {}, writes);
  await open(page);
  await page.getByRole("button", { name: "Add credential" }).click();
  await page.getByPlaceholder("what it is for").fill("New HSM");
  await page.getByRole("button", { name: "AWS (access key, optional role)", exact: true }).click();
  await page.getByRole("option", { name: "PKCS#11 HSM" }).click();
  await expect(page.getByText("Used by: Keys, certificate authorities")).toBeVisible();
  await page.getByPlaceholder(/libCryptoki2/).fill("/var/lib/vecta/hsm/providers/root/libCryptoki2.so");
  await page.getByPlaceholder("partition user PIN").fill("123456");
  await page.getByPlaceholder("token or partition label").fill("prod-ha");
  await page.getByRole("button", { name: "-", exact: true }).click();
  await page.getByRole("option", { name: "ha_group" }).click();
  await page.getByRole("button", { name: "Save and test" }).click();
  await expect(page.getByText("New HSM saved and tested.")).toBeVisible();
  const save = writes.find((w) => w.call === "POST /compliance/playbooks/connections");
  expect(save?.body).toMatchObject({ name: "New HSM", type: "pkcs11_hsm", rotate_after_days: 0,
    fields: { library_path: "/var/lib/vecta/hsm/providers/root/libCryptoki2.so", pin: "123456", token_label: "prod-ha", topology: "ha_group" } });
  expect(writes.some((w) => w.call === "POST /compliance/playbooks/connections/pbconn_new/test")).toBe(true);
});

test("an unreachable exposure register says not assessed, never a clean count", async ({ page }) => {
  await stub(page, { exposureDown: true });
  await open(page);
  await expect(page.getByText(/Exposure register unavailable; which credentials need rotating is not assessed/)).toBeVisible();
  await expect(tile(page, "Exposed").locator(".vk-num")).toHaveText("-");
  await expect(page.getByText("Rotate", { exact: true })).toHaveCount(0);
});

test("when the list can't be read it says unavailable, never 0", async ({ page }) => {
  await stub(page, { listDown: true });
  await open(page);
  await expect(page.getByText(/Credentials unavailable: service unavailable/)).toBeVisible();
  await expect(tile(page, "Credentials").locator(".vk-num").first()).toHaveText("-");
});

test("the Administration exposure register lists playbook connections and how they were exposed", async ({ page }) => {
  await stub(page);
  await page.goto("/");
  await page.getByText("Administration", { exact: true }).first().click();
  await page.getByText("Tenant Administration", { exact: true }).first().click();
  await page.getByRole("button", { name: "Security", exact: true }).first().click();
  await expect(page.getByText("Key exposure register", { exact: true })).toBeVisible();
  await expect(page.getByText("Playbook connections", { exact: true })).toBeVisible();
  await expect(page.getByText(/pbconn_slack · stored in plaintext by an earlier release/)).toBeVisible();
});

test("creating a key offers the HSMs: the HA group or a single HSM, and sends the one chosen", async ({ page }) => {
  const writes: Write[] = [];
  await stub(page, {}, writes);
  await page.setViewportSize({ width: 1440, height: 1200 });
  await page.goto("/");
  await page.getByText("Key Management", { exact: true }).first().click();
  await page.getByRole("button", { name: "Create Key" }).first().click();
  await page.locator("label", { hasText: "Create in HSM (generated and used only inside the HSM)" }).locator("div").first().click();
  // Checking the box picks the first HSM that is ready; the others say why not.
  const ha = page.getByRole("radio").filter({ hasText: "Luna HA group" });
  await expect(ha).toHaveAttribute("aria-checked", "true");
  await expect(ha).toContainText("HA group");
  await expect(ha).toContainText("Thales Luna K7 · token prod-ha · serial 1513123");
  await expect(page.getByRole("radio").filter({ hasText: "Lab HSM" })).toContainText("Single HSM");
  await expect(page.getByRole("radio").filter({ hasText: "Lab HSM" })).toContainText("CKR_PIN_INCORRECT");
  await expect(page.getByRole("radio").filter({ hasText: "Tenant HSM (HSM tab)" })).toContainText("HSM keys are off");
  await expect(page.getByText("Add an HSM in Playbooks, Credentials").first()).toBeVisible();
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/create-key-hsm.png` });
});
