import { expect, test, type Page } from "@playwright/test";

const RENDER_ERROR_TEXT = "This tab failed to render.";

const TAB_LABELS = [
  "Command Center",
  "Key Management",
  "Cloud Key Control",
  "Secret Vault",
  "Certificates / PKI",
  "Enterprise Key Management",
  "Data Protection",
  "Workbench",
  "HSM",
  "QKD Interface",
  "MPC Engine",
  "Cluster",
  "Approvals",
  "Alert Center",
  "Audit Log",
  "Compliance",
  "Playbooks",
  "SBOM / CBOM",
  "Administration"
];

function mockResponseForPath(path: string): unknown {
  const p = path.toLowerCase();
  if (p.includes("/alerts/unread-counts")) {
    return { critical: 0, high: 0, medium: 0, low: 0 };
  }
  if (p.includes("/system/health")) {
    return { services: [] };
  }
  if (
    p.includes("/requests") ||
    p.includes("/policies") ||
    p.includes("/clients") ||
    p.includes("/profiles") ||
    p.includes("/events") ||
    p.includes("/logs") ||
    p.includes("/findings") ||
    p.includes("/reports") ||
    p.includes("/keys") ||
    p.includes("/certificates") ||
    p.includes("/templates")
  ) {
    return [];
  }
  if (p.includes("/overview")) {
    return { nodes: [] };
  }
  return {};
}

async function installApiMocks(page: Page): Promise<void> {
  await page.route("**/auth/**", async (route) => {
    const requestPath = new URL(route.request().url()).pathname;
    if (requestPath.endsWith("/auth/system/health")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ services: [] })
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({})
    });
  });

  await page.route("**/svc/**", async (route) => {
    const requestPath = new URL(route.request().url()).pathname;
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(mockResponseForPath(requestPath))
    });
  });

  await page.route("**/api/**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({})
    });
  });
}

async function assertNoRenderBoundary(page: Page): Promise<void> {
  await expect(page.getByText(RENDER_ERROR_TEXT)).toHaveCount(0);
}

test.beforeEach(async ({ page }) => {
  await installApiMocks(page);
  await page.addInitScript(() => {
    // The session is tab-scoped (src/lib/auth.ts); localStorage left the
    // app on the sign-in page and every tab below was skipped.
    window.sessionStorage.setItem(
      "vecta_ui_session",
      JSON.stringify({
        tenantId: "root",
        username: "smoke-user",
        token: "smoke-token",
        mode: "local",
        mustChangePassword: false,
        role: "admin",
        permissions: ["*"]
      })
    );
  });
  await page.goto("/");
  await assertNoRenderBoundary(page);
});

test("major tabs render without runtime boundary failures", async ({ page }) => {
  await expect(page.getByRole("button", { name: "Sign In" })).toHaveCount(0);
  let opened = 0;
  for (const label of TAB_LABELS) {
    const entry = page.getByText(label, { exact: true }).first();
    if ((await entry.count()) === 0) {
      continue;
    }
    opened += 1;
    await entry.click();
    await page.waitForTimeout(250);
    await assertNoRenderBoundary(page);
  }
  expect(opened).toBeGreaterThan(10);
});

// Each kind of view has one home (2.12.0-beta): the record and its charts in
// the Audit Log, alert triage and alert charts in the Alert Center (7.15.0-beta).
// Every chart drills into the entries it counts.
test("analytics, alerts and audit each have a single home", async ({ page }) => {
  const nav = (label: string) => page.getByText(label, { exact: true }).first().click();
  const now = new Date().toISOString();
  const json = (body: unknown) => ({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  await page.route("**/svc/audit/audit/events?**", (r) => r.fulfill(json({ items: [
    { id: "ev-denied", timestamp: now, service: "kms-keycore", action: "audit.key.decrypt", actor_id: "mallory", target_id: "key-1", result: "denied", risk_score: 70 },
    { id: "ev-ok", timestamp: now, service: "kms-auth", action: "audit.auth.login", actor_id: "alice", target_id: "alice", result: "success", risk_score: 5 },
  ] })));
  await page.route("**/svc/reporting/alerts?**", (r) => r.fulfill(json({ items: [
    { id: "al-crit", severity: "critical", status: "new", title: "Key export refused", service: "keycore", created_at: now, audit_action: "audit.key.export" },
    { id: "al-info", severity: "info", status: "new", title: "Policy read", service: "policy", created_at: now, audit_action: "audit.policy.read" },
  ] })));
  await page.route("**/svc/reporting/alerts/stats?**", (r) => r.fulfill(json({ stats: { total: 2, by_severity: { critical: 1, info: 1 }, by_status: { new: 2 }, daily_trend: {} } })));

  await nav("Audit Log");
  for (const t of ["Events", "Activity", "Forensics", "Checkpoints"]) {
    await expect(page.getByRole("button", { name: t, exact: true })).toHaveCount(1);
  }
  await page.getByRole("button", { name: "Activity", exact: true }).click();
  await expect(page.getByText("Events analysed")).toBeVisible();
  await page.getByText("mallory", { exact: true }).first().click();
  await expect(page.getByText("Actor: mallory: 1 entry")).toBeVisible();
  await expect(page.getByText("audit.auth.login")).toHaveCount(0);
  await assertNoRenderBoundary(page);

  await nav("Alert Center");
  await page.getByRole("button", { name: "Analytics", exact: true }).click();
  // A donut slice's bounding-box centre is the hole, so click the slice itself.
  await page.locator(".recharts-pie-sector path").first().dispatchEvent("click");
  await expect(page.getByText(/^Severity: (critical|info): 1 entry$/)).toBeVisible();
  await assertNoRenderBoundary(page);

  await nav("Analytics");
  await expect(page.getByRole("button", { name: "Key inventory", exact: true })).toHaveCount(1);
  for (const t of ["Audit activity", "Alerts"]) {
    await expect(page.getByRole("button", { name: t, exact: true })).toHaveCount(0);
  }

  await nav("Compliance");
  await expect(page.getByRole("button", { name: "Reports", exact: true })).toHaveCount(1);
  await expect(page.getByText("Crypto Inventory", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Mean Time to Detect")).toHaveCount(0);
  await expect(page.getByText("Threshold Signing / FROST Controls")).toHaveCount(0);
});
