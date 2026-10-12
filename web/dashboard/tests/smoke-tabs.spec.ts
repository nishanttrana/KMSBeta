import { expect, test, type Page } from "@playwright/test";
import { coveredControls } from "./fixtures/layout";

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

// A source that fails shows "unavailable", never 0 (7.28.0-beta): with keycore
// and reporting answering 500, Status must not claim zero keys or zero alerts.
test("operations status shows unavailable, not zero, when a source fails", async ({ page }) => {
  const fail = { status: 500, contentType: "application/json", body: JSON.stringify({ error: { message: "down" } }) };
  await page.route("**/svc/keycore/**", (r) => r.fulfill(fail));
  await page.route("**/svc/reporting/**", (r) => r.fulfill(fail));
  await page.getByText("Operations", { exact: true }).first().click();
  for (const label of ["Total Keys", "Open Alerts"]) {
    const card = page.locator(".vecta-stat-card", { hasText: label });
    await expect(card.getByText("Unavailable", { exact: true })).toBeVisible();
    await expect(card.getByText("—", { exact: true })).toBeVisible();
    await expect(card.getByText("0", { exact: true })).toHaveCount(0);
  }
  await assertNoRenderBoundary(page);
});

// A module's views are sub-options under its name in the sidebar, never a
// second column (9.6.0-beta). Clicking the name lists them and a second click
// folds them; choosing one opens that view and names it in the breadcrumb.
// Playbooks has no tab strip of its own: its views are sidebar sub-options.
test("Playbooks views are sidebar sub-options, not a tab strip", async ({ page }) => {
  await page.getByText("Playbooks", { exact: true }).first().click();
  const sub = page.getByTestId("subnav-playbooks");
  for (const view of ["Overview", "Playbooks", "Runs", "Incidents", "Credentials", "Event streaming"]) await expect(sub.getByRole("button", { name: view, exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Runs", exact: true })).toHaveCount(1);
  await sub.getByRole("button", { name: "Runs", exact: true }).click();
  await expect(page.getByLabel("Breadcrumb")).toContainText("Runs");
});

test("a module's sub-options expand under its name in the sidebar", async ({ page }) => {
  const module = (label: string) => page.getByText(label, { exact: true }).first();
  const crumb = page.getByRole("navigation", { name: "Breadcrumb" });
  for (const [label, id, options] of [
    ["Cloud Key Control", "cloudctl", ["BYOK", "HYOK", "Google CSE", "Azure EKM"]],
    ["Certificates / PKI", "certs", ["Certificate Operations", "Enrollment Protocols", "Service mTLS"]],
    ["Administration", "admin", ["System Administration", "Tenant Administration", "User Management"]],
  ] as const) {
    await module(label).click();
    const sub = page.getByTestId(`subnav-${id}`);
    await expect(sub.getByRole("button")).toHaveText([...options]);
    await expect(page.locator("[data-testid^='subnav-']")).toHaveCount(1);
    await sub.getByRole("button", { name: options[1], exact: true }).click();
    await expect(sub.getByRole("button", { name: options[1], exact: true })).toHaveAttribute("aria-current", "page");
    await expect(crumb).toContainText(options[1]);
    await assertNoRenderBoundary(page);
  }
  await module("Administration").click();
  await expect(page.getByTestId("subnav-admin")).toHaveCount(0);
  await module("Administration").click();
  await expect(page.getByTestId("subnav-admin").getByRole("button", { name: "Tenant Administration", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(page.locator(".vk-subcard")).toHaveCount(0);
});

// The top bar has no search box and ⌘K opens nothing (11.5.0-beta): the
// sidebar's "Filter modules" is the one way to find a module.
test("the top bar has no search box and no command palette", async ({ page }) => {
  await expect(page.getByLabel("Filter modules")).toBeVisible();
  await page.locator("body").press("Control+k");
  await page.locator("body").press("Meta+k");
  await expect(page.getByText(/Search or jump/i)).toHaveCount(0);
  await expect(page.getByPlaceholder(/search|jump/i)).toHaveCount(0);
  await expect(page.getByRole("textbox")).toHaveCount(1);
});

type Box = { x: number; y: number; width: number; height: number } | null;
function intersects(a: Box, b: Box): boolean {
  if (!a || !b) throw new Error("an element to compare is not rendered");
  return a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;
}

const json = (body: unknown) => ({ status: 200, contentType: "application/json", body: JSON.stringify(body) });

// Collapsed, the rail is 60px: the toggle sat on top of the mark. Nothing in
// the sidebar may cover another control, in either state.
test("nothing in the sidebar covers the mark or another control, collapsed or open", async ({ page }) => {
  const sidebar = page.getByTestId("sidebar");
  const covered = () => coveredControls(sidebar);
  const overlap = async () => intersects(await page.getByTestId("sidebar-mark").boundingBox(), await sidebar.getByRole("button", { name: /sidebar$/ }).boundingBox());
  const width = () => sidebar.evaluate((el) => el.getBoundingClientRect().width);

  await expect.poll(width).toBe(248);
  expect(await overlap()).toBe(false);
  expect(await covered()).toEqual([]);

  await sidebar.getByRole("button", { name: "Collapse sidebar" }).click();
  await expect.poll(width).toBe(60);
  await expect(page.getByTestId("sidebar-mark")).toBeVisible();
  expect(await overlap()).toBe(false);
  expect(await covered()).toEqual([]);

  await sidebar.getByRole("button", { name: "Expand sidebar" }).click();
  await expect.poll(width).toBe(248);
  await expect(page.getByLabel("Filter modules")).toBeVisible();
});

// The unread count was drawn over the bell (11.6.0-beta). It sits beside the
// icon, so no count can cover it, and nothing in the top bar covers a control.
test("the unread count sits beside the bell, however many alerts there are", async ({ page }) => {
  const bar = page.getByTestId("topbar");
  for (const total of [3, 4200]) {
    await page.route(/\/svc\/reporting\/alerts\/unread(\?|$)/, (route) => route.fulfill(json({ counts: { critical: total } })));
    await page.reload();
    const count = bar.getByTestId("unread-count");
    await expect(count).toHaveText(total > 99 ? "99+" : String(total));
    const bell = bar.getByTitle("Alert center");
    expect(intersects(await bell.locator("svg").boundingBox(), await count.boundingBox())).toBe(false);
    expect(await coveredControls(bar)).toEqual([]);
  }
});

// A dialog offers only what its request sends (11.6.0-beta): no one-option
// Tenant selector, no derivation or FIPS box keycore never received.
// Description and a rotation schedule came back in 12.0.0-beta with the code
// behind them: the description is in the create request, and the schedule is
// a keycore rotation policy for the new key alone.
test("the create dialog sends a description and sets the rotation schedule it offers", async ({ page }) => {
  let created: Record<string, unknown> | null = null;
  let policy: Record<string, unknown> | null = null;
  await page.route(/\/svc\/keycore\/keys(\?|$)/, async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    created = route.request().postDataJSON();
    await route.fulfill(json({ key_id: "key_1", tenant_id: "root", kcv: "A1B2C3" }));
  });
  await page.route(/\/svc\/keycore\/rotation\/policies(\?|$)/, async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    policy = route.request().postDataJSON();
    await route.fulfill(json({ policy: { id: "rp_1", ...policy } }));
  });
  await page.getByText("Key Management", { exact: true }).first().click();
  await page.getByRole("button", { name: "Create Key" }).click();
  const dialog = page.getByRole("dialog", { name: "Create New Key" });
  await expect(dialog.getByText(/^Key Name( ?\*)?$/)).toHaveCount(1);
  for (const gone of ["Tenant", "Key Derivation", "Auto-Rotation", "FIPS-only algorithms enforced"]) {
    await expect(dialog.getByText(new RegExp(`^${gone}( ?\\*)?$`))).toHaveCount(0);
  }
  await dialog.getByPlaceholder("Enter key name").fill("smoke-key");
  await dialog.getByLabel("Description").fill("  Ledger envelope key  ");
  await dialog.getByRole("button", { name: "Rotation schedule" }).click();
  await page.getByRole("option", { name: "Every 90 days" }).click();
  await dialog.getByRole("button", { name: "Create Key" }).click();
  await expect.poll(() => policy).not.toBeNull();
  expect(created).toMatchObject({ tenant_id: "root", name: "smoke-key", description: "Ledger envelope key" });
  expect(policy).toEqual({ name: "smoke-key", target_filter: "id:key_1", interval_days: 90, auto_rotate: true });
});

// Without key.rotation.write the schedule is not offered, and a key created
// without one makes no policy.
test("the rotation schedule is offered only to a caller who may set one", async ({ page }) => {
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({ tenantId: "root", username: "key-maker", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["key.create", "key.read"] }));
  });
  let policies = 0;
  let created = 0;
  await page.route(/\/svc\/keycore\/rotation\/policies(\?|$)/, async (route) => {
    if (route.request().method() === "POST") policies += 1;
    await route.fulfill(json({ items: [] }));
  });
  await page.route(/\/svc\/keycore\/keys(\?|$)/, async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    created += 1;
    await route.fulfill(json({ key_id: "key_2", tenant_id: "root", kcv: "A1B2C3" }));
  });
  await page.reload();
  await page.getByText("Key Management", { exact: true }).first().click();
  await page.getByRole("button", { name: "Create Key" }).click();
  const dialog = page.getByRole("dialog", { name: "Create New Key" });
  await expect(dialog.getByLabel("Description")).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Rotation schedule" })).toHaveCount(0);
  await dialog.getByPlaceholder("Enter key name").fill("no-schedule");
  await dialog.getByRole("button", { name: "Create Key" }).click();
  await expect.poll(() => created).toBe(1);
  await expect(dialog).toHaveCount(0);
  expect(policies).toBe(0);
});

const keyRow = (id: string, name: string, purpose: string, more: Record<string, unknown> = {}) => ({
  id, tenant_id: "root", name, description: "", algorithm: "AES-256", key_type: "symmetric", purpose, status: "active", current_version: 1,
  kcv: "A1B2C3", kcv_algorithm: "aes-ecb-zero", iv_mode: "internal", export_allowed: false, tags: [], labels: {}, ops_total: 0,
  created_at: new Date(Date.now() - 3 * 86_400_000).toISOString(), updated_at: new Date(Date.now() - 3 * 86_400_000).toISOString(), ...more
});

// Key material leaves only with a stated reason (keycore refuses it without
// one, 12.0.0-beta): the dialog cannot send the request until one is given.
// A key's description is edited in place through its own route.
test("a key is exported only with a reason, and its description is edited in place", async ({ page }) => {
  const keys = { items: [keyRow("key_data", "ledger-dek", "encrypt-decrypt", { description: "Ledger envelope key", export_allowed: true }), keyRow("key_kek", "transport-kek", "wrap-unwrap")], has_more: false };
  let exported: Record<string, unknown> | null = null;
  let described: Record<string, unknown> | null = null;
  await page.route(/\/svc\/keycore\/keys\?/, (route) => (route.request().method() === "GET" ? route.fulfill(json(keys)) : route.fallback()));
  await page.route(/\/svc\/keycore\/keys\/key_data\/export(\?|$)/, async (route) => {
    exported = route.request().postDataJSON();
    await route.fulfill(json({ key_id: "key_data", kcv: "A1B2C3", wrapped_material: "d3JhcHBlZA==", material_iv: "aXY=", wrapped_dek: "", wrapping_key_id: "key_kek", wrapping_key_kcv: "", export_format: "aes-gcm-wrapped-by-kek" }));
  });
  await page.route(/\/svc\/keycore\/keys\/key_data\/description(\?|$)/, async (route) => {
    described = route.request().postDataJSON();
    await route.fulfill(json({ status: "ok", description: "Retired" }));
  });
  await page.reload(); // the shell lists the keys once, at start
  await page.getByText("Key Management", { exact: true }).first().click();
  await page.getByText("ledger-dek", { exact: true }).first().click();
  const detail = page.getByRole("dialog", { name: "Key: ledger-dek" });
  const field = detail.getByLabel("Key description");
  await expect(field).toHaveValue("Ledger envelope key");
  await expect(detail.getByRole("button", { name: "Save" })).toBeDisabled();
  await field.fill("Retired");
  await detail.getByRole("button", { name: "Save" }).click();
  await expect.poll(() => described).toEqual({ description: "Retired" });

  await detail.getByRole("button", { name: /^Export/ }).click();
  const dialog = page.getByRole("dialog", { name: "Export Key: ledger-dek" });
  const go = dialog.getByRole("button", { name: "Export Key" });
  await expect(dialog.getByRole("button", { name: "Wrapping key" })).toContainText("transport-kek");
  await expect(go).toBeDisabled();
  await dialog.getByLabel("Reason for the export").fill("   ");
  await expect(go).toBeDisabled();
  await dialog.getByLabel("Reason for the export").fill("Moving the ledger to the DR site");
  const download = page.waitForEvent("download");
  await go.click();
  await download;
  expect(exported).toEqual({ wrapping_key_id: "key_kek", export_mode: "wrapped", reason: "Moving the ledger to the DR site" });
});

// What the certs service answers (services/certs/internal_mtls.go, edge_tls.go),
// with Go's zero time where a service has not reported.
const ZERO = "0001-01-01T00:00:00Z";
const inDays = (n: number) => new Date(Date.now() + n * 86_400_000).toISOString();
const PQC = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"];
const observed = (identity: string, kx: string, groups: string[], days: number, generation = 1) => ({
  identity, instance: `${identity}-1`, serial: "395409a7655e011f00aa", not_after: inDays(days), key_algorithm: "ECDSA-P256", kx_profile: kx,
  server_groups: groups, generation, last_handshake_group: groups[0], last_handshake_at: inDays(0), started_at: inDays(-1), updated_at: inDays(0)
});
const service = (identity: string, kx: string, days: number, applied = true) => ({
  identity, host: identity, kind: "service", policy: { key_algorithm: "ECDSA-P256", kx_profile: kx, generation: applied ? 1 : 2 },
  certificates: [{ id: `crt_${identity}`, serial: "395409a7655e011f00aa", key_algorithm: "ECDSA-P256", not_after: inDays(days), issuer: "vecta-internal-services" }],
  observed: [observed(identity, kx, kx === "pqc-required" ? PQC : [...PQC, "CurveP256", "CurveP384"], days)], applied, restart_modes: ["graceful", "force"]
});
const MTLS = {
  items: [
    service("keycore", "pqc-required", 300),
    service("auth", "pqc-preferred", 300),
    service("audit", "pqc-preferred", 10, false),
    { identity: "postgres", host: "postgres", kind: "file", policy: { key_algorithm: "ECDSA-P256", kx_profile: "pqc-preferred", generation: 1 }, certificates: null, observed: null,
      served_file: { ...observed("postgres", "", [], 300), last_handshake_group: "", last_handshake_at: ZERO, started_at: ZERO }, applied: true, restart_modes: ["graceful"],
      note: "certs writes this certificate; the daemon reloads it within 30 s (no restart). Its TLS groups are the daemon's own configuration." }
  ],
  meta: { key_algorithms: ["ECDSA-P256", "ECDSA-P384", "RSA-3072"], kx_profiles: ["pqc-required", "pqc-preferred", "classical"], fips_mode: true, sub_ca: "vecta-internal-services",
    groups: { "pqc-required": PQC, "pqc-preferred": [...PQC, "CurveP256", "CurveP384"], classical: ["CurveP256", "CurveP384"] },
    signature_note: "Certificate signatures are classical: Go's TLS can't present ML-DSA certificates. Post-quantum protection is the key exchange.", rotate_all_step: 20 }
};
const edgeCert = (listener: string) => ({ listener, choice: { source: "runtime" }, served: true,
  installed: { serial: "395409a7655e011f00aa", subject: "CN=vecta-envoy", issuer: "CN=vecta-runtime-root,O=Vecta KMS Runtime", sans: ["localhost", "envoy", "127.0.0.1"], not_after: inDays(90), key_algorithm: "RSA-3072", from_choice: true } });
const EDGE = {
  certificate: edgeCert("https"), kmip_certificate: edgeCert("kmip"), policy: { kx_profile: "pqc-preferred", generation: 1 }, applied: false,
  listeners: [
    { name: "envoy", address: "envoy:443", expected_groups: ["X25519MLKEM768", "CurveP256", "CurveP384"], observed: observed("envoy", "pqc-preferred", ["X25519MLKEM768", "CurveP256", "CurveP384"], 90), applied: true },
    { name: "kmip", address: "kmip:5696", expected_groups: [...PQC, "CurveP256", "CurveP384"], observed: observed("kmip", "pqc-preferred", ["CurveP256", "CurveP384"], 90), applied: false }
  ],
  kx_profiles: ["pqc-required", "pqc-preferred", "classical"], groups: MTLS.meta.groups
};

// Service mTLS was five paragraphs above its controls (11.6.0-beta). The page
// shows state and controls; what they mean is in docs/SECURITY/INTERNAL_TLS.md.
test("Service mTLS shows state and controls without paragraphs, and each chip lists what it counts", async ({ page }) => {
  await page.route(/\/certs\/internal-mtls(\?|$)/, (route) => route.fulfill(json(MTLS)));
  await page.route(/\/certs\/edge-tls(\?|$)/, (route) => route.fulfill(json({ edge: EDGE })));
  await page.getByText("Certificates / PKI", { exact: true }).first().click();
  await page.getByTestId("subnav-certs").getByRole("button", { name: "Service mTLS", exact: true }).click();
  const panel = page.getByTestId("service-mtls");
  const rows = panel.getByTestId("mtls-identity");
  await expect(rows).toHaveCount(4);
  await expect(panel.getByText("vecta-internal-services", { exact: true })).toBeVisible();
  await expect(panel.getByText("2 applying", { exact: true })).toBeVisible();

  for (const [label, n] of [["Applying", 1], ["PQC required", 1], ["PQC preferred", 2], ["Classical", 0], ["Expiring ≤30d", 1], ["All", 4]] as const) {
    const chip = panel.getByRole("button", { name: `${label} ${n}`, exact: true });
    await chip.click();
    await expect(chip).toHaveAttribute("aria-pressed", "true");
    await expect(rows).toHaveCount(n);
  }
  await panel.getByRole("button", { name: "Applying 1", exact: true }).click();
  await expect(rows).toContainText(["audit"]);

  // A listener that differs shows the groups it is missing; the daemon row
  // shows no time for a handshake the service never reported.
  const kmip = panel.getByTestId("edge-listener").filter({ hasText: "kmip:5696" });
  await expect(kmip).toContainText("differs");
  await expect(kmip).toContainText("X25519MLKEM768");
  await expect(panel).not.toContainText("0001");
  await expect(panel).not.toContainText("NaN");

  // No paragraph: no run of text on the page is longer than a label.
  const longest = await panel.evaluate((root) => {
    let max = "";
    const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    for (let n = walk.nextNode(); n; n = walk.nextNode()) {
      const text = (n.textContent || "").trim();
      if (text.length > max.length) max = text;
    }
    return max;
  });
  expect(longest.length, longest).toBeLessThanOrEqual(60);

  // The one warning appears with the choice it warns about.
  await expect(panel.getByText(/Refuses clients without ML-KEM/)).toHaveCount(0);
  await panel.getByRole("button", { name: "Edge key exchange" }).click();
  await page.getByRole("option", { name: "PQC required" }).click();
  await expect(panel.getByText(/Refuses clients without ML-KEM/)).toBeVisible();
  expect(await coveredControls(panel)).toEqual([]);
});

// Counts read the same everywhere (11.6.0-beta): flat tiles, a neutral number,
// hue only on the icon of a count that needs attention.
test("certificate tiles are the console's flat stat tiles", async ({ page }) => {
  await page.getByText("Certificates / PKI", { exact: true }).first().click();
  const tiles = page.locator(".vecta-stat-card");
  await expect(tiles).toHaveText([/^Active/i, /^Revoked/i, /^CAs/i, /^Expiring/i, /^Missed windows/i, /^Emergency/i]);
  const looks = await tiles.evaluateAll((els) => els.map((el) => {
    const num = el.querySelector(".vk-num")!;
    return { image: getComputedStyle(el).backgroundImage, number: getComputedStyle(num).color };
  }));
  for (const look of looks) {
    expect(look.image).toBe("none");
    expect(look.number).toBe(looks[0]!.number);
  }
});
