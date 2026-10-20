import { expect, test, type Page } from "@playwright/test";

// Audit Log → Verify Chain. The default check walks each chain from its
// newest signed checkpoint, so the result says so and says when the hourly
// full walk last passed; it never reads as a full verification. Payloads
// have the shape services/audit/handler.go handleChainVerify returns.

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

async function open(page: Page, verify: unknown): Promise<void> {
  await page.route("**/svc/**", (route) => {
    const p = new URL(route.request().url()).pathname;
    if (p.endsWith("/audit/chain/verify")) return route.fulfill(json(verify));
    if (p.endsWith("/auth/tenants")) return route.fulfill(json({ items: [{ id: "root", name: "root", status: "active" }] }));
    return route.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/");
  await page.getByText("Audit Log", { exact: true }).first().click();
  await expect(page.getByText("CHAIN: NOT CHECKED")).toBeVisible();
  await page.getByRole("button", { name: "Verify Chain" }).click();
}

test("a check since the checkpoint says where it started and when the full walk last passed", async ({ page }) => {
  await open(page, { ok: true, breaks: null, scope: "since_checkpoint", from_sequence: { "": 78110 }, rows_checked: 86, last_full_verification: "2026-10-18T05:00:00Z", request_id: "r" });
  await expect(page.getByText("CHAIN: INTACT since #78110")).toBeVisible();
  await expect(page.getByText(/^Full check passed /)).toBeVisible();
});

test("a chain whose full walk never passed says so", async ({ page }) => {
  await open(page, { ok: true, breaks: null, scope: "since_checkpoint", from_sequence: { "": 1 }, rows_checked: 3, last_full_verification: null, request_id: "r" });
  await expect(page.getByText("Full check: not yet passed")).toBeVisible();
});

test("a break reads broken", async ({ page }) => {
  await open(page, { ok: false, breaks: [{ sequence: 9, event_id: "evt_9", reason: "chain_hash_mismatch" }], scope: "since_checkpoint", from_sequence: { "": 5 }, rows_checked: 5, last_full_verification: null, request_id: "r" });
  await expect(page.getByText("CHAIN: BROKEN")).toBeVisible();
  await expect(page.getByText("1 break(s) detected", { exact: true })).toBeVisible();
});
