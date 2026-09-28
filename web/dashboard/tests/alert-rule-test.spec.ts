import { expect, test, type Page } from "@playwright/test";

// The alert-rule editor's Test button (2.13.0-beta) sends the rule as
// entered to POST /alerts/rules/test and shows the replay over real audit
// events. The API is stubbed; the check itself is tested in
// services/reporting (rule_check_test.go).

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

async function stub(page: Page, sent: unknown[], answer: unknown): Promise<void> {
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    if (p.endsWith("/alerts/rules/test")) {
      sent.push(req.postDataJSON());
      return route.fulfill(json({ result: answer }));
    }
    if (p.endsWith("/alerts/rules")) return route.fulfill(json({ items: [] }));
    if (p.endsWith("/alerts/channels")) return route.fulfill(json({ items: [{ name: "screen", enabled: true }] }));
    if (p.endsWith("/auth/tenants")) return route.fulfill(json({ items: [{ id: "root", name: "root", status: "active" }] }));
    return route.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"]
    }));
  });
}

async function openRuleEditor(page: Page): Promise<void> {
  await page.goto("/");
  await page.getByText("Administration", { exact: true }).first().click();
  await page.getByText("System Administration", { exact: true }).first().click();
  await page.getByRole("button", { name: "Alert Rules", exact: true }).first().click();
  await page.getByRole("button", { name: "Create Rule" }).first().click();
}

test("Test rule sends the rule as entered and shows the replay", async ({ page }) => {
  const sent: any[] = [];
  await stub(page, sent, {
    valid: true,
    replay: {
      hours: 24, from: "2026-09-27T12:00:00Z", to: "2026-09-28T12:00:00Z", events_scanned: 812, matched: 9, fired: 3, truncated: false,
      basis: "matching audit events per window", samples: [{ event_id: "e1", action: "audit.auth.login_failed", actor_id: "mallory", timestamp: "2026-09-28T10:00:00Z" }]
    }
  });
  await openRuleEditor(page);
  await page.getByPlaceholder("e.g. brute_force_detection").fill("brute force");
  await page.getByPlaceholder("e.g. audit.auth.login_failed or audit.key.*").fill("audit.auth.login_failed");
  await page.getByRole("button", { name: "Test rule" }).click();
  await expect(page.getByText(/Over 812 audit events/)).toBeVisible();
  await expect(page.getByText(/would have fired/)).toContainText("3");
  await expect(page.getByText(/audit\.auth\.login_failed · mallory/)).toBeVisible();
  expect(sent).toHaveLength(1);
  expect(sent[0].rule).toMatchObject({ name: "brute force", condition: "threshold", event_pattern: "audit.auth.login_failed" });
  expect(sent[0].replay_hours).toBe(24);
});

test("an invalid rule shows the reason", async ({ page }) => {
  await stub(page, [], { valid: false, error: "invalid expression: unexpected token" });
  await openRuleEditor(page);
  await page.getByRole("button", { name: "Test rule" }).click();
  await expect(page.getByText("Not valid: invalid expression: unexpected token")).toBeVisible();
});

test("replay unavailable is shown as not assessed, never as zero matches", async ({ page }) => {
  await stub(page, [], { valid: true, replay_error: "audit events unavailable: audit HTTP 503" });
  await openRuleEditor(page);
  await page.getByRole("button", { name: "Test rule" }).click();
  await expect(page.getByText(/Replay not assessed: audit events unavailable/)).toBeVisible();
  await expect(page.getByText(/would have fired/)).toHaveCount(0);
});
