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
