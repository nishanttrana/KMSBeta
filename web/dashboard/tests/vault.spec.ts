import { expect, test, type Page } from "@playwright/test";

// Secret Vault: tiles and charts count the tenant's own secrets, every bar
// lists exactly the entries it counts, a value is read only on Reveal, and a
// failed source reads "unavailable", never 0. Payloads have the shape the
// secrets service returns (services/secrets/types.go).

const SHOTS = process.env.VAULT_SHOTS_DIR || "";
const DAY = 86400000;
const at = (days: number) => new Date(Date.now() + days * DAY).toISOString();
const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

const secret = (id: string, name: string, type: string, version: number, changedDaysAgo: number, expiresInDays?: number, labels: Record<string, string> = {}) => ({
  id, tenant_id: "root", name, secret_type: type, description: "", labels, metadata: {}, status: "active",
  path: `${labels.path || ""}/${name}`, restricted: (labels.path || "").startsWith("/finance"),
  lease_ttl_seconds: expiresInDays === undefined ? 0 : 86400, current_version: version, created_by: "alice",
  created_at: at(-400), updated_at: at(-changedDaysAgo), ...(expiresInDays === undefined ? {} : { expires_at: at(expiresInDays) }),
});

const SECRETS = [
  secret("sec_1", "stripe-live", "api_key", 3, 2, 20),
  secret("sec_2", "github-deploy", "ssh_private_key", 1, 45),
  secret("sec_3", "billing-db", "database_credentials", 2, 200, -3, { path: "/finance/prod" }),
  secret("sec_4", "ledger-db", "database_credentials", 1, 400, 5, { path: "/finance/prod" }),
  secret("sec_5", "slack-bot", "token", 1, 10, 60),
  secret("sec_6", "app/config", "api_key", 4, 1),
];

const DELETED = [{ ...secret("sec_9", "old-vpn", "password", 2, 30), status: "deleted", deleted_at: at(-1), deleted_by: "alice" }];
const RULES = [
  { id: "sar_1", path: "/finance/*", subject_type: "role", subject_id: "finance-admin", capabilities: ["read", "value", "write", "delete"], effect: "allow", created_by: "alice", created_at: at(-9) },
  { id: "sar_2", path: "/finance/prod/billing-db", subject_type: "user", subject_id: "contractor-7", capabilities: ["value"], effect: "deny", created_by: "alice", created_at: at(-3) },
];

type Opts = { listDown?: boolean; statsDown?: boolean; rulesDown?: boolean; noValue?: boolean };
type Write = { call: string; body: unknown };

async function stub(page: Page, opts: Opts = {}, writes: Write[] = []): Promise<string[]> {
  const calls: string[] = [];
  const down = json({ error: { message: "service unavailable" } }, 503);
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    if (p.includes("/svc/secrets/")) calls.push(`${req.method()} ${p.replace(/^.*\/svc\/secrets/, "")}`);
    if (req.method() !== "GET") writes.push({ call: `${req.method()} ${p.replace(/^.*\/svc\/secrets/, "")}`, body: req.postDataJSON() });
    if (p.endsWith("/secrets/access/rules") && req.method() === "POST") return route.fulfill(json({ rule: { ...RULES[0], id: "sar_new" } }, 201));
    if (p.endsWith("/secrets/access/rules")) return route.fulfill(opts.rulesDown ? down : json({ items: RULES }));
    if (p.endsWith("/access")) return route.fulfill(json({ path: "/stripe-live", rules: p.includes("sec_3") ? RULES : [], caller: { read: true, value: !opts.noValue, write: true, delete: true } }));
    if (p.endsWith("/rollback")) return route.fulfill(json({ secret: { ...SECRETS[0], current_version: 4 } }));
    if (p.endsWith("/svc/secrets/secrets") && new URL(req.url()).searchParams.get("deleted") === "true") return route.fulfill(json({ items: DELETED }));
    if (p.endsWith("/secrets/stats")) return route.fulfill(opts.statsDown ? down : json({ stats: { total_secrets: 6, total_versions: 12, expiring_within_30d: 2, expired: 1, by_type: {} } }));
    if (p.endsWith("/secrets/sec_1/value")) {
      const version = Number(new URL(req.url()).searchParams.get("version") || 3);
      return route.fulfill(json({ value: version === 3 ? "sk_live_fixture" : `sk_old_v${version}`, version, format: "raw", content_type: "text/plain" }));
    }
    if (p.endsWith("/secrets/sec_1/versions")) return route.fulfill(json({ versions: [3, 2, 1].map((version) => ({ version, created_at: at(-version) })) }));
    if (p.endsWith("/secrets/sec_1/audit")) return route.fulfill(json({ entries: [{ id: "aud_1", secret_id: "sec_1", action: "rotated", actor: "alice", detail: "Secret value rotated to version 3", created_at: at(-2) }] }));
    if (p.endsWith("/svc/secrets/secrets")) return route.fulfill(opts.listDown ? down : json({ items: SECRETS }));
    return route.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  return calls;
}

async function open(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 1100 });
  await page.goto("/");
  await page.getByText("Secret Vault", { exact: true }).first().click();
  await expect(page.getByText("Vault / OpenBao KV clients")).toBeVisible();
}

const bar = (page: Page, label: string) => page.getByRole("button", { name: new RegExp(`^${label}\\s*\\d+$`) });
const tile = (page: Page, label: string) => page.locator(".vecta-stat-card", { hasText: label });

test("tiles and charts count the secrets, and each bar lists its entries", async ({ page }) => {
  await stub(page);
  await open(page);

  await expect(tile(page, "Secrets").locator(".vk-num").first()).toHaveText("6");
  await expect(tile(page, "Versions stored").locator(".vk-num")).toHaveText("12");
  await expect(tile(page, "Expiring in 30 days").locator(".vk-num")).toHaveText("2");
  await expect(tile(page, "Expired").locator(".vk-num").last()).toHaveText("1");
  await expect(tile(page, "Never rotated").locator(".vk-num")).toHaveText("3");
  await expect(bar(page, "DB Credentials")).toContainText("2");
  await expect(bar(page, "No expiry")).toContainText("2");
  await expect(bar(page, "Over a year")).toContainText("1");
  if (SHOTS) {
    await page.screenshot({ path: `${SHOTS}/vault-light.png`, fullPage: true });
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "dark"));
    await page.screenshot({ path: `${SHOTS}/vault-dark.png`, fullPage: true });
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "light"));
  }

  await bar(page, "DB Credentials").click();
  await expect(page.getByText("Type: DB Credentials: 2 entries")).toBeVisible();
  await bar(page, "Within 7 days").click();
  await expect(page.getByText("Expiry: Within 7 days: 1 entry")).toBeVisible();
  await tile(page, "Never rotated").click();
  await expect(page.getByText("Never rotated (still version 1): 3 entries")).toBeVisible();
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/vault-drill.png`, fullPage: true });

  // What earlier releases showed without any backend behind it.
  for (const gone of ["sys/policies", "secret.accessed", "Event Hooks", "Lease-based access", "Delivery Format", "undelete", "SHA256"]) {
    await expect(page.getByText(gone)).toHaveCount(0);
  }
});

test("a drill-down entry opens the secret, and the value is read only on Reveal", async ({ page }) => {
  const calls = await stub(page);
  await open(page);
  await bar(page, "API Key").click();
  await page.getByText("stripe-live").first().click();
  await expect(page.getByText("Secret: stripe-live")).toBeVisible();
  await expect(page.getByText("Versions (3)")).toBeVisible();
  await expect(page.getByText("Changes (1)")).toBeVisible();
  expect(calls.filter((c) => c.endsWith("/value"))).toHaveLength(0);

  await page.getByRole("button", { name: "Reveal" }).click();
  await expect(page.locator("textarea").filter({ hasText: "sk_live_fixture" })).toBeVisible();
  expect(calls.filter((c) => c.endsWith("/value"))).toHaveLength(1);
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/vault-detail.png` });
});

test("folders come from the secrets' own paths", async ({ page }) => {
  await stub(page);
  await open(page);
  await page.getByRole("button", { name: /finance\s*2/ }).click();
  await page.getByRole("button", { name: /prod\s*2/ }).click();
  await expect(page.getByText("billing-db")).toBeVisible();
  await expect(page.getByText("stripe-live")).toHaveCount(0);
  await expect(page.getByText("+ Folder")).toHaveCount(0);
});

test("a failed source reads unavailable, never zero", async ({ page }) => {
  await stub(page, { statsDown: true });
  await open(page);
  await expect(tile(page, "Versions stored").locator(".vk-num")).toHaveText("-");
  await expect(tile(page, "Versions stored")).toContainText("unavailable");
  await expect(tile(page, "Secrets").locator(".vk-num").first()).toHaveText("6");
});

test("a failed list shows the error instead of an empty vault", async ({ page }) => {
  await stub(page, { listDown: true });
  await open(page);
  await expect(page.getByText(/Secret vault unavailable/)).toBeVisible();
  await expect(page.getByText("No secrets stored yet")).toHaveCount(0);
  await expect(tile(page, "Never rotated")).toHaveCount(0);
});

test("access rules: the restricted tile lists its secrets, and a rule is added and deleted", async ({ page }) => {
  const writes: Write[] = [];
  await stub(page, {}, writes);
  await open(page);
  await expect(tile(page, "Access-restricted").locator(".vk-num")).toHaveText("2");
  await tile(page, "Access-restricted").click();
  await expect(page.getByText("Value limited by an access rule: 2 entries")).toBeVisible();

  await page.getByText("Access rules", { exact: true }).click();
  await expect(page.getByText("2 rules · 2 of 6 secrets restricted")).toBeVisible();
  await expect(page.getByText("finance-admin")).toBeVisible();
  await expect(page.getByText("contractor-7")).toBeVisible();
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/vault-rules.png`, fullPage: true });

  await page.getByRole("button", { name: "Add rule" }).first().click();
  await page.getByPlaceholder("/finance/*").fill("/payments/*");
  await page.getByPlaceholder("finance-admin").fill("payments-ops");
  await page.getByText("Delete and destroy").click(); // untick delete
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/vault-rule-add.png` });
  await page.getByRole("button", { name: "Add rule" }).last().click();
  await expect.poll(() => writes.find((w) => w.call === "POST /secrets/access/rules")?.body).toEqual({
    tenant_id: "root", path: "/payments/*", subject_type: "role", subject_id: "payments-ops", capabilities: ["read", "value", "write"], effect: "allow",
  });

  await page.getByTitle("Delete rule").last().click();
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect.poll(() => writes.some((w) => w.call === "DELETE /secrets/access/rules/sar_2")).toBe(true);
});

test("failed access rules read unavailable, not 'no rules'", async ({ page }) => {
  await stub(page, { rulesDown: true });
  await open(page);
  await page.getByText("Access rules", { exact: true }).click();
  await expect(page.getByText(/Access rules unavailable/)).toBeVisible();
  await expect(page.getByText(/No access rules/)).toHaveCount(0);
});

test("versions: an earlier version is read on request and rolled back with the expected version", async ({ page }) => {
  const writes: Write[] = [];
  const calls = await stub(page, {}, writes);
  await open(page);
  await page.getByText("stripe-live").first().click();
  await expect(page.getByText("Versions (3)")).toBeVisible();
  await expect(page.getByText("no rule: open to the secrets permission")).toBeVisible();

  await page.getByRole("button", { name: "Read v2" }).click();
  await expect(page.locator("textarea").filter({ hasText: "sk_old_v2" })).toBeVisible();
  await expect(page.getByText("Value (v2)")).toBeVisible();
  expect(calls.filter((c) => c.endsWith("/value"))).toHaveLength(1);

  await page.getByRole("button", { name: "Roll back to v1" }).click();
  await page.getByRole("button", { name: "Roll back", exact: true }).click();
  await expect.poll(() => writes.find((w) => w.call === "POST /secrets/sec_1/rollback")?.body).toEqual({ version: 1, expected_version: 3 });
  await expect(page.getByRole("button", { name: "Destroy v3" })).toHaveCount(0); // never offered for the current version
});

test("a caller the rules do not allow cannot reveal, and sees why", async ({ page }) => {
  const calls = await stub(page, { noValue: true });
  await open(page);
  await page.getByText("billing-db").first().click();
  await expect(page.getByText("2 rules on this path")).toBeVisible();
  await expect(page.getByText("no value")).toBeVisible();
  await expect(page.getByRole("button", { name: "Reveal" })).toBeDisabled();
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/vault-detail-rules.png` });
  expect(calls.filter((c) => c.endsWith("/value"))).toHaveLength(0);
});

test("a deleted secret is listed under Deleted and can be restored", async ({ page }) => {
  const writes: Write[] = [];
  await stub(page, {}, writes);
  await open(page);
  await expect(page.getByText("old-vpn")).toHaveCount(0);
  await page.getByText("Deleted", { exact: true }).click();
  await page.getByText("old-vpn").click();
  await expect(page.getByText("Deleted by:")).toBeVisible();
  await expect(page.getByRole("button", { name: "Reveal" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Destroy", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Restore" }).click();
  await expect.poll(() => writes.some((w) => w.call === "POST /secrets/sec_9/restore")).toBe(true);
});
