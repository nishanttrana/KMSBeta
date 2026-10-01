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
// Charts cover a chosen window, from a day to a year or since uptime, and every
// chart drills into the entries it counts (7.16.0-beta). The mocks answer from
// the query the dashboard sends, so the window and filters must reach the
// server for the assertions to pass.
test("analytics, alerts and audit each have a single home", async ({ page }) => {
  const nav = (label: string) => page.getByText(label, { exact: true }).first().click();
  const now = new Date().toISOString();
  const json = (body: unknown) => ({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  const events = [
    { id: "ev-denied", timestamp: now, service: "kms-keycore", action: "audit.key.decrypt", actor_id: "mallory", target_id: "key-1", result: "denied", risk_score: 70 },
    { id: "ev-ok", timestamp: now, service: "kms-auth", action: "audit.auth.login", actor_id: "alice", target_id: "alice", result: "success", risk_score: 5 },
  ];
  const alerts = [
    { id: "al-crit", severity: "critical", status: "new", title: "Key export refused", service: "keycore", created_at: now, audit_action: "audit.key.export" },
    { id: "al-info", severity: "info", status: "new", title: "Policy read", service: "policy", created_at: now, audit_action: "audit.policy.read" },
  ];
  const statsFrom: string[] = [];
  await page.route("**/svc/audit/audit/activity/stats?**", (r) => {
    const from = new URL(r.request().url()).searchParams.get("from") || "";
    statsFrom.push(from);
    return r.fulfill(json({ stats: {
      from: from || now, to: now, bucket_seconds: 3600, total: 2, actors: 2, services: 2,
      by_result: [{ key: "denied", count: 1 }, { key: "success", count: 1 }],
      top_services: [{ key: "kms-keycore", count: 1 }, { key: "kms-auth", count: 1 }],
      top_actors: [{ key: "mallory", count: 1 }, { key: "alice", count: 1 }],
      risk_buckets: [{ key: "0-20", count: 1 }, { key: "21-40", count: 0 }, { key: "41-60", count: 0 }, { key: "61-80", count: 1 }, { key: "81-100", count: 0 }],
      series: [{ start: now, count: 2 }],
    } }));
  });
  await page.route("**/svc/audit/audit/events?**", (r) => {
    const q = new URL(r.request().url()).searchParams;
    const actor = q.get("actor_id");
    return r.fulfill(json({ items: q.get("exclude_http_requests") === "true" && q.get("from") ? events.filter((e) => !actor || e.actor_id === actor) : events }));
  });
  await page.route("**/svc/reporting/alerts?**", (r) => {
    const sev = new URL(r.request().url()).searchParams.get("severity");
    return r.fulfill(json({ items: alerts.filter((a) => !sev || a.severity === sev) }));
  });
  await page.route("**/svc/reporting/alerts/stats?**", (r) => r.fulfill(json({ stats: {
    total: 2, by_severity: { critical: 1, info: 1 }, by_status: { new: 2 }, daily_trend: {},
    from: now, to: now, bucket_seconds: 3600, series: [{ start: now, count: 2 }],
  } })));

  await nav("Audit Log");
  for (const t of ["Events", "Activity", "Forensics", "Checkpoints"]) {
    await expect(page.getByRole("button", { name: t, exact: true })).toHaveCount(1);
  }
  await page.getByRole("button", { name: "Activity", exact: true }).click();
  await expect(page.getByText("Not successful")).toBeVisible();
  const pickWindow = async (current: string, next: string) => {
    await page.getByText(current, { exact: true }).first().click();
    await page.getByRole("option", { name: next, exact: true }).click();
  };
  await page.getByText("Last week", { exact: true }).first().click();
  for (const w of ["Since uptime", "Last day", "Last week", "Last month", "Last 6 months", "Last year"]) {
    await expect(page.getByRole("option", { name: w, exact: true })).toHaveCount(1);
  }
  await page.keyboard.press("Escape");
  await pickWindow("Last week", "Last year");
  await expect.poll(() => statsFrom.length).toBeGreaterThan(1);
  const yearFrom = Date.parse(statsFrom[statsFrom.length - 1] ?? "");
  expect(Math.abs(Date.now() - yearFrom - 365 * 86400_000)).toBeLessThan(3600_000);
  await pickWindow("Last year", "Since uptime");
  await expect.poll(() => statsFrom[statsFrom.length - 1]).toBe("");

  await page.getByText("mallory", { exact: true }).first().click();
  await expect(page.getByText("Actor: mallory: 1 entry")).toBeVisible();
  await expect(page.getByText("audit.key.decrypt")).toBeVisible();
  await expect(page.getByText("audit.auth.login")).toHaveCount(0);
  await assertNoRenderBoundary(page);

  await nav("Alert Center");
  await page.getByRole("button", { name: "Analytics", exact: true }).click();
  // A donut slice's bounding-box centre is the hole, so click the slice itself.
  await page.locator(".recharts-pie-sector path").first().dispatchEvent("click");
  await expect(page.getByText(/^Severity: (critical|info): 1 entry$/)).toBeVisible();
  await expect(page.getByText(/^(Key export refused|Policy read)$/)).toHaveCount(1);
  await assertNoRenderBoundary(page);

  // Analytics is no longer an Overview tab; its two views live in Operations.
  await nav("Operations");
  await expect(page.getByText("Analytics", { exact: true })).toHaveCount(0);
  // Status shows only what a service returned (7.26.0-beta): the mocked
  // cluster has no nodes, so none is listed, and nothing is invented.
  await expect(page.getByText("No nodes reported.")).toBeVisible();
  for (const fake of ["Disk Encryption", "vecta-kms-01", "34.2 / 120 GB", "Violations"]) {
    await expect(page.getByText(fake)).toHaveCount(0);
  }
  for (const t of ["Status", "Key inventory", "Operation metrics"]) {
    await expect(page.getByRole("button", { name: t, exact: true })).toHaveCount(1);
  }
  await page.getByRole("button", { name: "Operation metrics", exact: true }).click();
  await expect(page.getByText("Operations Breakdown")).toBeVisible();
  await page.getByRole("button", { name: "Key inventory", exact: true }).click();
  await expect(page.getByText("By Algorithm")).toBeVisible();
  await assertNoRenderBoundary(page);

  await nav("Compliance");
  await expect(page.getByRole("button", { name: "Reports", exact: true })).toHaveCount(1);
  await expect(page.getByText("Crypto Inventory", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Mean Time to Detect")).toHaveCount(0);
  await expect(page.getByText("Threshold Signing / FROST Controls")).toHaveCount(0);
});

// Posture gives no risk score until the baseline has enough history
// (7.19.0-beta): it says how far the baseline is, per signal, instead.
test("posture shows baseline progress instead of a score while it builds", async ({ page }) => {
  const json = (body: unknown) => ({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  await page.route("**/svc/posture/posture/risk?**", (r) => r.fulfill(json({ risk: { tenant_id: "root", risk_24h: 0, risk_7d: 0, assessed: false, baseline_days: 5 } })));
  await page.route("**/svc/posture/posture/baseline?**", (r) => r.fulfill(json({ baseline: {
    ready: false, stable: false, days: 5, required_days: 14, stable_days: 28, spike_alpha: 0.001,
    signals: [
      { key: "failed_auth", label: "Failed authentication", kind: "count", status: "building", current_24h: 500, baseline_daily_mean: 2, floor: 25, unusual: false, p_value: 1 },
      { key: "kmip", label: "KMIP failure rate", kind: "rate", status: "building", current_24h: 0, events_24h: 0, baseline_events: 40, required_baseline_events: 385, baseline_daily_mean: 0, unusual: false, p_value: 1 },
    ],
  } })));
  await page.getByText("Posture", { exact: true }).first().click();
  await expect(page.getByText("Not assessed").first()).toBeVisible();
  await expect(page.getByText("Baseline building: 5 of 14 days").first()).toBeVisible();
  await expect(page.getByText("Building: 5 of 14 days", { exact: true })).toBeVisible();
  await expect(page.getByText("Failed authentication", { exact: true })).toBeVisible();
  await expect(page.getByText("0/100")).toHaveCount(0);
  await assertNoRenderBoundary(page);
});
