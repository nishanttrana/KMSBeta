import { expect, test, type Page } from "@playwright/test";

// Step 3 of the console simplification (13.25.0-beta): the sidebar filter
// also finds keys, certificates and secrets (each service searches its whole
// set); Command Center lists a new tenant's first steps; the Keys page names
// its next step when empty and says "unavailable" when its list failed.

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

async function stub(page: Page, opts: { keysDown?: boolean; certsDown?: boolean; keys?: unknown[] } = {}): Promise<void> {
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const url = new URL(r.request().url());
    const q = url.searchParams.get("q");
    if (url.pathname.endsWith("/auth/users")) return r.fulfill(json({ items: [{ username: "admin", role: "admin", status: "active", must_change_password: true }] }));
    if (url.pathname.endsWith("/keycore/keys")) {
      if (opts.keysDown) return r.fulfill(json({ error: { message: "keycore down" } }, 503));
      if (q) return r.fulfill(json({ items: [{ id: "key_pay1", name: "payments-db", algorithm: "AES-256" }] }));
      return r.fulfill(json({ items: opts.keys ?? [], has_more: false }));
    }
    if (url.pathname.endsWith("/certs/certs") && q) {
      if (opts.certsDown) return r.fulfill(json({ error: { message: "certs down" } }, 503));
      return r.fulfill(json({ items: [] }));
    }
    if (url.pathname.endsWith("/secrets/secrets") && q) return r.fulfill(json({ items: [{ id: "sec_1", name: "payments-api-token", secret_type: "api_key" }] }));
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
}

test("the sidebar filter finds keys, certificates and secrets, and a result opens its page searched", async ({ page }) => {
  await stub(page, { certsDown: true });
  await page.goto("/");
  await page.getByLabel("Filter modules").fill("payments");
  const results = page.getByTestId("sidebar-search");
  await expect(results.getByRole("button", { name: /payments-db/ })).toBeVisible();
  await expect(results.getByRole("button", { name: /payments-api-token/ })).toBeVisible();
  // A source that failed says so; it never reads as "no match".
  await expect(results.getByText("unavailable", { exact: true })).toBeVisible();
  await results.getByRole("button", { name: /payments-db/ }).click();
  await expect(page.getByRole("navigation", { name: "Breadcrumb" })).toContainText("Key Management");
  await expect(page.getByPlaceholder("Search keys by name, ID, algorithm, KCV, tag...")).toHaveValue("payments-db");
});

test("one letter searches nothing", async ({ page }) => {
  await stub(page);
  await page.goto("/");
  await page.getByLabel("Filter modules").fill("p");
  await expect(page.getByTestId("sidebar-search")).toHaveCount(0);
});

test("Command Center lists the first steps with their state and where to do each", async ({ page }) => {
  await stub(page);
  await page.goto("/");
  const steps = page.getByTestId("setup-checklist");
  await expect(steps).toBeVisible();
  await expect(steps.locator("[data-step='admin-password']")).toHaveAttribute("data-status", "todo");
  await expect(steps.locator("[data-step='first-key']")).toHaveAttribute("data-status", "todo");
  await steps.locator("[data-step='first-key']").getByRole("button").click();
  await expect(page.getByRole("navigation", { name: "Breadcrumb" })).toContainText("Key Management");
});

test("an empty key list offers the first key", async ({ page }) => {
  await stub(page);
  await page.goto("/#keys");
  await page.getByRole("button", { name: "Create your first key" }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
});

test("a key list that failed to load is not 'No keys yet'", async ({ page }) => {
  await stub(page, { keysDown: true });
  await page.goto("/#keys");
  await expect(page.getByText(/^Keys unavailable:/)).toBeVisible();
  await expect(page.getByText("No keys yet.")).toHaveCount(0);
});
