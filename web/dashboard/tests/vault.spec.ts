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
  { id: "sar_3", path: "/finance/*", subject_type: "group", subject_id: "grp_aud", capabilities: ["read"], effect: "allow", created_by: "alice", created_at: at(-2), subject_status: "found", subject_label: "Auditors" },
  { id: "sar_4", path: "/ops/*", subject_type: "user", subject_id: "usr_left", capabilities: ["value"], effect: "allow", created_by: "alice", created_at: at(-40), subject_status: "missing" },
];
const CAPS = [{ id: "svc_1", path: "/logs/*", max_versions: 3, updated_by: "alice" }, { id: "svc_2", path: "/logs/audit", max_versions: 0, updated_by: "alice" }];
const GROUPS = [{ id: "grp_aud", tenant_id: "root", name: "Auditors", member_count: 3 }, { id: "grp_dba", tenant_id: "root", name: "Database admins", member_count: 2 }];
const SETTINGS = { tenant_id: "root", default_deny: false, max_versions: 0, deleted_retention_days: 30, updated_by: "alice" };

type Opts = { listDown?: boolean; statsDown?: boolean; rulesDown?: boolean; noValue?: boolean; settingsDown?: boolean; pruning?: boolean };
type Write = { call: string; body: unknown };

async function stub(page: Page, opts: Opts = {}, writes: Write[] = []): Promise<string[]> {
  const calls: string[] = [];
  let prunePolls = 0;
  const down = json({ error: { message: "service unavailable" } }, 503);
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    if (p.includes("/svc/secrets/")) calls.push(`${req.method()} ${p.replace(/^.*\/svc\/secrets/, "")}`);
    if (req.method() !== "GET" && p.includes("/svc/secrets/")) writes.push({ call: `${req.method()} ${p.replace(/^.*\/svc\/secrets/, "")}`, body: req.postDataJSON() });
    if (p.endsWith("/secrets/version-caps/prune")) {
      prunePolls += 1; // running on the first look, done after
      return route.fulfill(json({ prune: opts.pruning && prunePolls === 1 ? { state: "running", secrets_pruned: 0, versions_pruned: 0 } : opts.pruning ? { state: "done", secrets_pruned: 2, versions_pruned: 6 } : { state: "idle", secrets_pruned: 0, versions_pruned: 0 } }));
    }
    if (p.endsWith("/secrets/version-caps") && req.method() === "PUT") return route.fulfill(json({ cap: { id: "svc_new", ...req.postDataJSON() } }));
    if (p.endsWith("/secrets/version-caps")) return route.fulfill(json({ items: CAPS }));
    if (p.includes("/secrets/version-caps/")) return route.fulfill(json({ status: "deleted" }));
    if (p.endsWith("/keycore/access/groups")) return route.fulfill(json({ items: GROUPS }));
    if (p.endsWith("/secrets/settings") && req.method() === "PUT") return route.fulfill(json({ settings: { ...SETTINGS, ...req.postDataJSON() } }));
    if (p.endsWith("/secrets/settings")) return route.fulfill(opts.settingsDown ? down : json({ settings: SETTINGS }));
    if (p.endsWith("/impact")) return route.fulfill(json(p.includes("sar_1") ? { reopens: ["value", "write", "delete"], secrets_opened: 2 } : { reopens: [], secrets_opened: 0 }));
    if (p.endsWith("/secrets/access/rules") && req.method() === "POST") return route.fulfill(json({ rule: { ...RULES[0], id: "sar_new" } }, 201));
    if (p.endsWith("/secrets/access/rules")) return route.fulfill(opts.rulesDown ? down : json({ items: RULES }));
    if (p.endsWith("/access")) return route.fulfill(json({ path: "/stripe-live", rules: p.includes("sec_3") ? RULES.slice(0, 3) : [], max_versions: 3, max_versions_from: "/logs/*", caller: { read: true, value: !opts.noValue, write: true, delete: true } }));
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
  const urls: string[] = [];
  page.on("request", (r) => { if (r.method() === "DELETE") urls.push(r.url()); });
  const calls = await stub(page, {}, writes);
  await open(page);
  await expect(tile(page, "Access-restricted").locator(".vk-num")).toHaveText("2");
  await tile(page, "Access-restricted").click();
  await expect(page.getByText("Value limited by an access rule: 2 entries")).toBeVisible();

  await page.getByText("Access rules", { exact: true }).click();
  await expect(page.getByText("4 rules · 2 of 6 secrets restricted")).toBeVisible();
  await expect(page.getByText("Auditors")).toBeVisible(); // a group rule is shown by the group's name
  await expect(page.getByText("finance-admin")).toBeVisible();
  await expect(page.getByText("contractor-7")).toBeVisible();
  if (SHOTS) {
    await page.screenshot({ path: `${SHOTS}/vault-rules.png`, fullPage: true });
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "dark"));
    await page.screenshot({ path: `${SHOTS}/vault-rules-dark.png`, fullPage: true });
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "light"));
  }

  await page.getByRole("button", { name: "Add rule" }).first().click();
  await page.getByPlaceholder("/finance/*").fill("/payments/*");
  await page.getByPlaceholder("finance-admin").fill("payments-ops");
  await page.getByText("Delete and destroy").click(); // untick delete
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/vault-rule-add.png` });
  await page.getByRole("button", { name: "Add rule" }).last().click();
  await expect.poll(() => writes.find((w) => w.call === "POST /secrets/access/rules")?.body).toEqual({
    tenant_id: "root", path: "/payments/*", subject_type: "role", subject_id: "payments-ops", capabilities: ["read", "value", "write"], effect: "allow",
  });

  // A rule whose removal opens nothing deletes with a plain confirmation.
  await page.getByTitle("Delete rule").nth(1).click();
  await expect(page.getByText("No path is opened by this.")).toBeVisible();
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect.poll(() => calls.some((c) => c === "DELETE /secrets/access/rules/sar_2")).toBe(true);
  // The last allow rule: the dialog says what opens, and only then is the
  // delete sent, with the confirmation the service requires.
  await page.getByTitle("Delete rule").first().click();
  await expect(page.getByText(/last allow rule for value, write, delete on \/finance\/\*.*opens 2 secrets/)).toBeVisible();
  expect(urls.some((u) => u.includes("sar_1") && u.includes("confirm_reopens"))).toBe(false);
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/vault-reopen.png` });
  await page.getByRole("button", { name: "Delete and open" }).click();
  await expect.poll(() => urls.some((u) => u.includes("/access/rules/sar_1?") && u.includes("confirm_reopens=true"))).toBe(true);
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
  await expect(page.getByText("3 rules on this path")).toBeVisible();
  await expect(page.getByText("no value")).toBeVisible();
  await expect(page.getByRole("button", { name: "Reveal" })).toBeDisabled();
  if (SHOTS) {
    await page.screenshot({ path: `${SHOTS}/vault-detail-rules.png` });
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "dark"));
    await page.screenshot({ path: `${SHOTS}/vault-detail-rules-dark.png` });
  }
  expect(calls.filter((c) => c.endsWith("/value"))).toHaveLength(0);
});

test("a deleted secret is listed under Deleted and can be restored", async ({ page }) => {
  const writes: Write[] = [];
  await stub(page, {}, writes);
  await open(page);
  await expect(page.getByText("old-vpn")).toHaveCount(0);
  await page.getByText("Deleted", { exact: true }).click();
  await expect(page.getByText("Destroyed 30 days after the delete, unless restored.")).toBeVisible();
  await page.getByText("old-vpn").click();
  await expect(page.getByText("Deleted by:")).toBeVisible();
  await expect(page.getByRole("button", { name: "Reveal" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Destroy", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Restore" }).click();
  await expect.poll(() => writes.some((w) => w.call === "POST /secrets/sec_9/restore")).toBe(true);
});

test("vault settings: deny by default asks first and names the secrets it would hide", async ({ page }) => {
  const writes: Write[] = [];
  await stub(page, {}, writes);
  await open(page);
  await page.getByText("Access rules", { exact: true }).click();
  await expect(page.getByText("4 secrets with no allow rule")).toBeVisible();
  await expect(page.getByLabel("Days a deleted secret is kept")).toHaveValue("30");
  await expect(page.getByRole("button", { name: "Save" })).toBeDisabled();

  await page.getByLabel("Versions kept per secret").fill("10");
  await page.getByText("Open to the secrets permission", { exact: true }).first().click();
  await page.getByRole("option", { name: "Denied", exact: true }).click();
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText(/4 secrets have no allow rule/)).toBeVisible();
  expect(writes.filter((w) => w.call === "PUT /secrets/settings")).toHaveLength(0); // nothing sent before the confirmation
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/vault-default-deny.png` });
  await page.getByRole("button", { name: "Deny by default" }).click();
  // Lowering the cap removes versions at once, so that is confirmed too.
  await expect(page.getByText(/Versions beyond the newest 10 of every secret.*removed, starting now/)).toBeVisible();
  expect(writes.filter((w) => w.call === "PUT /secrets/settings")).toHaveLength(0);
  await page.getByRole("button", { name: "Remove older versions" }).click();
  await expect.poll(() => writes.find((w) => w.call === "PUT /secrets/settings")?.body).toEqual({ tenant_id: "root", default_deny: true, max_versions: 10, deleted_retention_days: 30 });
});

test("a group rule is chosen from the tenant's access groups", async ({ page }) => {
  const writes: Write[] = [];
  await stub(page, {}, writes);
  await open(page);
  await page.getByText("Access rules", { exact: true }).click();
  await page.getByRole("button", { name: "Add rule" }).first().click();
  await page.getByPlaceholder("/finance/*").fill("/db/*");
  await page.locator("label", { hasText: "Who" }).locator("..").getByText("role", { exact: true }).first().click();
  await page.getByRole("option", { name: "group", exact: true }).click();
  await page.getByText("Choose a group", { exact: true }).first().click();
  await page.getByRole("option", { name: "Database admins", exact: true }).click();
  await page.getByRole("button", { name: "Add rule" }).last().click();
  await expect.poll(() => writes.find((w) => w.call === "POST /secrets/access/rules")?.body).toMatchObject({ path: "/db/*", subject_type: "group", subject_id: "grp_dba" });
});

test("failed vault settings read unavailable", async ({ page }) => {
  await stub(page, { settingsDown: true });
  await open(page);
  await page.getByText("Access rules", { exact: true }).click();
  await expect(page.getByText(/Vault settings unavailable/)).toBeVisible();
  await expect(page.getByLabel("Versions kept per secret")).toHaveCount(0);
});

test("a rule whose subject no longer exists is flagged, and a refused subject is reported", async ({ page }) => {
  await stub(page);
  await page.route("**/svc/secrets/secrets/access/rules", (route) => route.request().method() === "POST"
    ? route.fulfill(json({ error: { code: "unknown_subject", message: "no role fin-admin in this tenant" } }, 400)) : route.fallback());
  await open(page);
  await page.getByText("Access rules", { exact: true }).click();
  await expect(page.getByText("1 name a subject that no longer exists")).toBeVisible();
  await expect(page.getByText("· not found")).toHaveCount(1);
  await page.getByRole("button", { name: "Add rule" }).first().click();
  await page.getByPlaceholder("/finance/*").fill("/x/*");
  await page.getByPlaceholder("finance-admin").fill("fin-admin");
  await page.getByRole("button", { name: "Add rule" }).last().click();
  await expect(page.getByText(/Rule refused: .*no role fin-admin in this tenant/)).toBeVisible();
});

test("version caps by path are listed, set and removed, and a secret shows the cap that applies", async ({ page }) => {
  const writes: Write[] = [];
  await stub(page, {}, writes);
  await open(page);
  await page.getByText("stripe-live").first().click();
  await expect(page.getByText("keeps 3")).toBeVisible();
  await page.getByRole("button", { name: "Close", exact: true }).last().click();

  await page.getByText("Access rules", { exact: true }).click();
  await expect(page.getByText("keeps every version")).toBeVisible(); // /logs/audit, cap 0
  await page.getByLabel("Version cap path").fill("/db/*");
  await page.getByLabel("Versions kept on this path").fill("10");
  await page.getByRole("button", { name: "Set cap" }).click();
  await expect(page.getByText(/Versions beyond the newest 10 under \/db\/\* are removed, starting now/)).toBeVisible();
  expect(writes.filter((w) => w.call === "PUT /secrets/version-caps")).toHaveLength(0);
  await page.getByRole("button", { name: "Set cap" }).last().click();
  await expect.poll(() => writes.find((w) => w.call === "PUT /secrets/version-caps")?.body).toEqual({ tenant_id: "root", path: "/db/*", max_versions: 10 });
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/vault-caps.png`, fullPage: true });
  await page.getByTitle("Remove cap").first().click();
  await expect.poll(() => writes.some((w) => w.call === "DELETE /secrets/version-caps/svc_1")).toBe(true);
});

test("a prune in the background is shown while it runs and reported when done", async ({ page }) => {
  await stub(page, { pruning: true });
  await open(page);
  await page.getByText("Access rules", { exact: true }).click();
  await expect(page.getByText("Removing older versions in the background…")).toBeVisible();
  await expect(page.getByText("Last prune removed 6 versions from 2 secrets.")).toBeVisible({ timeout: 8000 });
});
