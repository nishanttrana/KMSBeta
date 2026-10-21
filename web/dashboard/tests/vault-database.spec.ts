import { expect, test, type Page, type Request } from "@playwright/test";

// Secret Vault → Database credentials (13.34.0-beta): roles name a database
// credential, a generated password is shown once, and leases renew and
// revoke. Payloads have the shapes services/secrets/dbengine_routes.go returns.

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const ROLE = {
  tenant_id: "root", name: "orders-readers", connection_id: "pbconn_db", engine: "postgres",
  creation_statements: ["CREATE ROLE {{name}} WITH LOGIN PASSWORD {{password}} VALID UNTIL {{expiration}};"],
  revocation_statements: ["DROP ROLE IF EXISTS {{name}};"], default_ttl_seconds: 3600, max_ttl_seconds: 86400,
  created_by: "alice", created_at: "2026-10-21T10:00:00Z", updated_at: "2026-10-21T10:00:00Z",
};
const soon = new Date(Date.now() + 30 * 60_000).toISOString();
const LEASES = [
  { id: "dbl_a", role_name: "orders-readers", username: "v_orders_readers_aaaaaaaaaa", state: "active", created_by: "app", created_at: "2026-10-21T10:00:00Z", expires_at: soon, max_expires_at: soon },
  { id: "dbl_b", role_name: "orders-readers", username: "v_orders_readers_bbbbbbbbbb", state: "revoke_failed", created_by: "app", created_at: "2026-10-21T09:00:00Z", expires_at: "2026-10-21T09:30:00Z", max_expires_at: soon, last_error: "statement 1: permission denied" },
];

async function stub(page: Page): Promise<Request[]> {
  const writes: Request[] = [];
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const req = r.request();
    const p = new URL(req.url()).pathname;
    if (req.method() !== "GET") writes.push(req);
    if (p.endsWith("/compliance/connections")) return r.fulfill(json({ data: [{ id: "pbconn_db", tenant_id: "root", name: "orders-db-admin", type: "database", endpoint: "", fields_set: ["host", "database", "username", "password"], attributes: {}, created_by: "alice", created_at: "", updated_at: "" }] }));
    if (p.endsWith("/secrets/database/roles")) return r.fulfill(json({ items: [{ role: ROLE, active_leases: 1 }], defaults: { creation_statements: ["CREATE ROLE {{name}} WITH LOGIN PASSWORD {{password}} VALID UNTIL {{expiration}};"], revocation_statements: ["DROP ROLE IF EXISTS {{name}};"] } }));
    if (p.endsWith("/secrets/database/roles/new-role") && req.method() === "PUT") return r.fulfill(json({ role: { ...ROLE, name: "new-role" } }));
    if (p.endsWith("/creds")) return r.fulfill(json({ lease: { ...LEASES[0], id: "dbl_new" }, username: "v_orders_readers_newlogin1", password: "S3cretGeneratedPasswordShownOnce" }));
    if (p.endsWith("/secrets/database/leases")) return r.fulfill(json({ items: LEASES }));
    if (p.endsWith("/revoke")) return r.fulfill(json({ lease: { ...LEASES[0], state: "revoked" } }));
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({ tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"] }));
  });
  return writes;
}

test("database credentials: tiles count leases, a role saves its fields, a password is shown once", async ({ page }) => {
  const writes = await stub(page);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/#vault/database");
  await expect(page.getByTestId("db-role-orders-readers")).toBeVisible();
  await expect(page.locator(".vecta-stat-card", { hasText: "Revocation failed" })).toHaveAttribute("data-tone", "red");
  await expect(page.locator(".vecta-stat-card", { hasText: "Ending within 1h" })).toHaveAttribute("data-tone", "amber");

  await page.getByRole("button", { name: "New role" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByPlaceholder("orders-readers").fill("new-role");
  await dialog.locator("button[aria-haspopup='listbox']").first().click();
  await page.getByRole("option", { name: /orders-db-admin/ }).click();
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect.poll(() => writes.filter((w) => w.method() === "PUT").length).toBe(1);
  const put = writes.find((w) => w.method() === "PUT")!;
  expect(new URL(put.url()).pathname).toMatch(/\/secrets\/database\/roles\/new-role$/);
  expect(Object.keys(put.postDataJSON()).sort()).toEqual(["connection_id", "creation_statements", "default_ttl_seconds", "max_ttl_seconds", "revocation_statements"]);
  expect(put.postDataJSON()).toMatchObject({ connection_id: "pbconn_db", default_ttl_seconds: 3600, max_ttl_seconds: 86400 });

  await page.getByTestId("db-role-orders-readers").getByRole("button", { name: "Generate" }).click();
  await expect(page.getByLabel("Password")).toHaveValue("S3cretGeneratedPasswordShownOnce");
  await expect(page.getByText("The password is shown once.")).toBeVisible();
  await page.getByRole("button", { name: "Done" }).click();
  await expect(page.getByText("S3cretGeneratedPasswordShownOnce")).toHaveCount(0);

  await page.getByTestId("db-lease-dbl_b").getByRole("button", { name: "Revoke" }).click();
  await expect.poll(() => writes.some((w) => new URL(w.url()).pathname.endsWith("/leases/dbl_b/revoke"))).toBe(true);
});

test("a failed source reads unavailable, never zero roles", async ({ page }) => {
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => r.fulfill(json({ error: { message: "secrets down" } }, 503)));
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({ tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"] }));
  });
  await page.goto("/#vault/database");
  await expect(page.getByText(/Database credentials unavailable/)).toBeVisible();
  await expect(page.getByText("No roles yet.")).toHaveCount(0);
});
