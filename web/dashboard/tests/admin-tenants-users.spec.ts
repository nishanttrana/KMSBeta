import { expect, test, type Page } from "@playwright/test";

// Administration → Tenant Administration and User Management. Roles offered
// are the tenant's own (GET /auth/roles), a user's real role and status are
// shown, policy edits name the tenant they change and send only the fields
// auth accepts, nothing is locked by a browser-only setting, and the top bar
// names the signed-in tenant instead of offering a switch every service
// refuses. Payloads have the shape auth returns (services/auth).

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const ROLES = ["admin", "audit", "backup", "cli-user", "readonly", "tenant-admin"];
const TENANTS = [
  { id: "root", name: "Root", status: "active", created_at: "2026-10-11T09:51:44Z" },
  { id: "tenant2", name: "Second", status: "active", created_at: "2026-10-12T19:02:41Z" },
];
const USERS: Record<string, unknown[]> = {
  root: [
    { id: "usr_1", tenant_id: "root", username: "admin", email: "admin@vecta.local", role: "tenant-admin", status: "active", must_change_password: false },
    { id: "usr_2", tenant_id: "root", username: "cli-user", email: "cli@vecta.local", role: "cli-user", status: "active", must_change_password: true },
    { id: "usr_3", tenant_id: "root", username: "bob", email: "bob@example.com", role: "readonly", status: "inactive", must_change_password: false },
    { id: "usr_4", tenant_id: "root", username: "old", email: "old@example.com", role: "viewer", status: "active", must_change_password: false },
  ],
  tenant2: [{ id: "usr_9", tenant_id: "tenant2", username: "admin", email: "a@t2.example", role: "admin", status: "active", must_change_password: false }],
};
const POLICY = {
  tenant_id: "tenant2", min_length: 12, max_length: 128, require_upper: true, require_lower: true, require_digit: true,
  require_special: true, require_no_whitespace: true, deny_username: true, deny_email_local_part: true, min_unique_chars: 6,
  updated_by: "usr_1", updated_at: "2026-10-12T10:00:00Z",
};

type Write = { call: string; body: unknown };
type Opts = { platformAdmin?: boolean; usersDown?: boolean };

async function stub(page: Page, opts: Opts = {}, writes: Write[] = []): Promise<void> {
  const platformAdmin = opts.platformAdmin ?? true;
  await page.route("**/svc/**", (route) => {
    const req = route.request();
    const u = new URL(req.url());
    const p = u.pathname;
    const tenant = u.searchParams.get("tenant_id") || "root";
    if (req.method() !== "GET") writes.push({ call: `${req.method()} ${p.replace(/^\/svc\/auth/, "")}${u.search}`, body: req.postDataJSON() });
    if (p === "/svc/auth/tenants") {
      return route.fulfill(platformAdmin ? json({ items: TENANTS }) : json({ error: { message: "tenant administration requires an administrator of the platform (root) tenant" } }, 403));
    }
    if (p === "/svc/auth/auth/roles") return route.fulfill(json({ items: ROLES.map((role_name) => ({ tenant_id: tenant, role_name, permissions: [] })), tenant_id: tenant }));
    if (p === "/svc/auth/auth/users") return route.fulfill(opts.usersDown ? json({ error: { message: "store unavailable" } }, 503) : json({ items: USERS[tenant] || [] }));
    if (p.endsWith("/delete-readiness")) return route.fulfill(json({ readiness: { tenant_id: tenant, tenant_status: "active", can_disable: true, can_delete: false, blockers: [] } }));
    if (p === "/svc/auth/auth/password-policy") return route.fulfill(json({ policy: { ...POLICY, tenant_id: tenant } }));
    if (p === "/svc/auth/auth/security-policy") return route.fulfill(json({ policy: { tenant_id: tenant, max_failed_attempts: 5, lockout_minutes: 15, idle_timeout_minutes: 30, updated_at: "2026-10-12T10:00:00Z" } }));
    if (p === "/svc/auth/auth/groups/roles" || p === "/svc/auth/auth/identity/providers") return route.fulfill(json({ items: [] }));
    if (p === "/svc/governance/governance/backups") return route.fulfill(json({ items: [
      { id: "bk_t2", scope: "tenant", target_tenant_id: "tenant2", status: "completed" },
      { id: "bk_root", scope: "tenant", target_tenant_id: "root", status: "completed" },
    ] }));
    return route.fulfill(json({}));
  });
  await page.addInitScript((admin) => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: admin ? "root" : "tenant2", username: "admin", token: "smoke-token", mode: "local", mustChangePassword: false, role: "tenant-admin", permissions: ["*"],
    }));
  }, platformAdmin);
}

async function openAdmin(page: Page, view: "Tenant Administration" | "User Management"): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 1100 });
  await page.goto("/");
  await page.getByText("Administration", { exact: true }).first().click();
  await page.getByTestId("subnav-admin").getByRole("button", { name: view, exact: true }).click();
}

// A user's row, found by its email (a role selector lists every role name).
const userRow = (page: Page, email: string) =>
  page.locator("div[style*='grid-template-columns: 1.5fr 1.4fr']").filter({ has: page.getByText(email, { exact: true }) });

test("user management shows each user's real role and status and offers only the tenant's roles", async ({ page }) => {
  await stub(page);
  await openAdmin(page, "User Management");

  await expect(userRow(page, "cli@vecta.local").getByRole("button").first()).toContainText("cli-user");
  await expect(userRow(page, "bob@example.com").getByRole("button").first()).toContainText("readonly");
  await expect(userRow(page, "bob@example.com").getByRole("button").nth(1)).toContainText("inactive");
  // A role the tenant no longer defines is shown as it is, never as another.
  await expect(userRow(page, "old@example.com").getByRole("button").first()).toContainText("viewer (not defined)");
  // Changing your own role or status is refused by auth, so it isn't offered.
  await expect(userRow(page, "admin@vecta.local").getByRole("button").first()).toBeDisabled();

  const createRole = page.locator("label", { hasText: /^Role$/ }).locator("..").getByRole("button").first();
  await expect(createRole).toContainText("readonly");
  await createRole.click();
  await expect(page.getByRole("option")).toHaveText(ROLES);
});

test("user management acts on the tenant it shows", async ({ page }) => {
  const writes: Write[] = [];
  await stub(page, {}, writes);
  await openAdmin(page, "User Management");
  await page.locator("label", { hasText: /^Tenant$/ }).locator("..").getByRole("button").first().click();
  await page.getByRole("option", { name: /^tenant2/ }).click();
  await expect(userRow(page, "a@t2.example")).toBeVisible();

  // Authentication Policies is the page's last section.
  await page.getByRole("button", { name: "Save", exact: true }).last().click();
  await expect.poll(() => writes.filter((w) => w.call.includes("-policy")).length).toBe(2);
  const pwd = writes.find((w) => w.call.startsWith("PUT /auth/password-policy"))!;
  expect(pwd.call).toBe("PUT /auth/password-policy?tenant_id=tenant2");
  expect(Object.keys(pwd.body as object).sort()).toEqual([
    "deny_email_local_part", "deny_username", "max_length", "min_length", "min_unique_chars",
    "require_digit", "require_lower", "require_no_whitespace", "require_special", "require_upper",
  ]);
});

test("tenant administration has no browser-only lock or HSM copy, and saves the chosen tenant's policy", async ({ page }) => {
  const writes: Write[] = [];
  await stub(page, {}, writes);
  await openAdmin(page, "Tenant Administration");
  await expect(page.getByText("Second", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "HSM", exact: true })).toHaveCount(0);

  await page.getByText("Second", { exact: true }).first().click();
  await page.getByRole("button", { name: "Security", exact: true }).click();
  await expect(page.getByText("KMS-Wide Enforcement Active")).toHaveCount(0);
  await page.getByRole("button", { name: "Save Policies" }).click();
  await expect.poll(() => writes.map((w) => w.call).sort()).toEqual([
    "PUT /auth/password-policy?tenant_id=tenant2",
    "PUT /auth/security-policy?tenant_id=tenant2",
  ]);
  expect(Object.keys(writes.find((w) => w.call.includes("security"))!.body as object).sort()).toEqual(["idle_timeout_minutes", "lockout_minutes", "max_failed_attempts"]);

  // Tenant Administration's own Backup tab, not the sidebar's Backup section.
  await page.locator("main").getByRole("button", { name: "Backup", exact: true }).last().click();
  await expect(page.getByText("bk_t2")).toBeVisible();
  await expect(page.getByText("bk_root")).toHaveCount(0);

  await page.getByRole("button", { name: "Lifecycle", exact: true }).click();
  await expect(page.getByRole("button", { name: "Disable Tenant" })).toBeVisible();
  await page.getByRole("button", { name: /^Second \(tenant2\)/ }).click();
  await page.getByRole("option", { name: /^Root \(root\)/ }).click();
  await expect(page.getByText("The platform tenant is never disabled or deleted.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Disable Tenant" })).toHaveCount(0);
});

test("a tenant's own administrator manages its users, and the top bar names the tenant", async ({ page }) => {
  await stub(page, { platformAdmin: false });
  await openAdmin(page, "User Management");
  const subnav = page.getByTestId("subnav-admin");
  await expect(subnav.getByRole("button")).toHaveText(["User Management"]);
  await expect(page.locator("label", { hasText: /^Tenant$/ })).toHaveCount(0);
  await expect(userRow(page, "a@t2.example")).toBeVisible();
  await expect(page.getByTestId("topbar-tenant")).toHaveText("tenant2");
  await expect(page.getByRole("button", { name: "Tenant", exact: true })).toHaveCount(0);
});

test("tenant administration says why when the tenant list is refused", async ({ page }) => {
  await stub(page, { platformAdmin: false });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "reader", token: "smoke-token", mode: "local", mustChangePassword: false, role: "readonly", permissions: ["auth.user.read", "auth.tenant.read"],
    }));
  });
  await openAdmin(page, "Tenant Administration");
  await expect(page.getByText("Tenants unavailable")).toBeVisible();
  await expect(page.getByText(/administrator of the platform \(root\) tenant/)).toBeVisible();
});

// Being in the root tenant is not platform administration: without
// auth.tenant.read the console offers User Management only (13.21.0-beta).
test("a root-tenant user without auth.tenant.read is not a system administrator", async ({ page }) => {
  await stub(page, { platformAdmin: false });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "reader", token: "smoke-token", mode: "local", mustChangePassword: false, role: "readonly", permissions: ["auth.user.read"],
    }));
  });
  await openAdmin(page, "User Management");
  const subnav = page.getByTestId("subnav-admin");
  await expect(subnav.getByRole("button", { name: "User Management", exact: true })).toBeVisible();
  await expect(subnav.getByRole("button", { name: "Tenant Administration", exact: true })).toHaveCount(0);
  await expect(subnav.getByRole("button", { name: "System Administration", exact: true })).toHaveCount(0);
  await expect(page.getByText("System Admin", { exact: true })).toHaveCount(0);
});

test("a user list that fails to load reads unavailable, never 0", async ({ page }) => {
  await stub(page, { usersDown: true });
  await openAdmin(page, "Tenant Administration");
  await expect(page.locator(".vecta-stat-card", { hasText: "Users" })).toContainText("unavailable");
});
