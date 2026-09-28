import { expect, test, type Page } from "@playwright/test";

// Playbook connections whose credentials were migrated from plaintext are
// flagged ROTATE (2.6.0-beta), from the compliance exposure register. The API
// is stubbed here; the register itself is tested in services/compliance.

const SHOTS = process.env.PLAYBOOK_SHOTS_DIR || "";

const connections = [
  { id: "pbconn_exposed", name: "SOC Slack", type: "slack", endpoint: "hooks.slack.com", fields_set: ["webhook_url"], updated_at: "2026-09-28T09:00:00Z" },
  { id: "pbconn_clean", name: "Ops Teams", type: "teams", endpoint: "example.webhook.office.com", fields_set: ["webhook_url"], updated_at: "2026-09-28T09:00:00Z" }
];

const exposure = {
  service: "compliance",
  open: 1,
  items: [
    { tenant_id: "root", item_type: "playbook_connection", item_id: "pbconn_exposed", source: "plaintext_storage", exposed_since: "2026-09-28T08:00:00Z" },
    { tenant_id: "root", item_type: "playbook_connection", item_id: "pbconn_clean", source: "plaintext_storage", exposed_since: "2026-09-28T08:00:00Z", remediated_at: "2026-09-28T08:30:00Z", remediation: "credentials_replaced" }
  ]
};

const catalog = {
  triggers: [{ type: "canary_tripped", label: "Canary key referenced", group: "Incident response", subjects: ["audit.keycore.canary_tripped"] }],
  actions: [{ type: "create_audit_event", label: "Create audit event", group: "Notifications", required: [], optional: ["message"] }],
  categories: ["incident_response"],
  connection_types: [
    { type: "slack", label: "Slack", fields: ["webhook_url"], optional: [] },
    { type: "teams", label: "Microsoft Teams", fields: ["webhook_url"], optional: [] }
  ],
  event_fields: [], filter_ops: [], templates: [], incident_statuses: []
};

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

async function stub(page: Page, exposureStatus = 200): Promise<void> {
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (route) => {
    const p = new URL(route.request().url()).pathname;
    if (p.endsWith("/mek/exposure")) {
      return route.fulfill(p.startsWith("/svc/compliance/") ? json(exposureStatus === 200 ? exposure : { error: { message: "keyring not open" } }, exposureStatus) : json({ items: [], open: 0 }));
    }
    if (p.endsWith("/auth/tenants")) return route.fulfill(json({ items: [{ id: "root", name: "root", status: "active" }] }));
    if (p.endsWith("/compliance/playbooks/catalog")) return route.fulfill(json({ data: catalog }));
    if (p.endsWith("/compliance/playbooks/connections")) return route.fulfill(json({ data: connections }));
    if (p.endsWith("/compliance/playbooks/summary")) return route.fulfill(json({ data: {} }));
    if (p.endsWith("/compliance/playbooks") || p.includes("/playbook-runs") || p.includes("/incidents")) return route.fulfill(json({ data: [], items: [] }));
    return route.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"]
    }));
  });
}

async function openConnections(page: Page): Promise<void> {
  await page.goto("/");
  await page.getByText("Playbooks", { exact: true }).first().click();
  await page.getByRole("button", { name: "Connections" }).first().click();
  await expect(page.getByText("SOC Slack")).toBeVisible();
}

test("an exposed connection is flagged ROTATE with the banner; a remediated one is not", async ({ page }) => {
  await stub(page);
  await openConnections(page);
  await expect(page.getByText("1 connection to rotate.")).toBeVisible();
  const exposedRow = page.locator("tr", { hasText: "SOC Slack" });
  const cleanRow = page.locator("tr", { hasText: "Ops Teams" });
  await expect(exposedRow.getByText("ROTATE", { exact: true })).toBeVisible();
  await expect(cleanRow.getByText("ROTATE", { exact: true })).toHaveCount(0);
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/connections-rotate.png`, fullPage: true });
});

test("an unreachable exposure register says not assessed, never shows a clean list", async ({ page }) => {
  await stub(page, 500);
  await openConnections(page);
  await expect(page.getByText(/Exposure register unavailable \(which connections need rotating is not assessed\)/)).toBeVisible();
  await expect(page.getByText("ROTATE", { exact: true })).toHaveCount(0);
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/connections-unavailable.png`, fullPage: true });
});

test("the Administration exposure register lists playbook connections and how they were exposed", async ({ page }) => {
  await stub(page);
  await page.goto("/");
  await page.getByText("Administration", { exact: true }).first().click();
  await page.getByText("Tenant Administration", { exact: true }).first().click();
  await page.getByRole("button", { name: "Security", exact: true }).first().click();
  await expect(page.getByText("Key exposure register", { exact: true })).toBeVisible();
  await expect(page.getByText("Playbook connections", { exact: true })).toBeVisible();
  await expect(page.getByText(/pbconn_exposed · stored in plaintext before 2\.5\.0-beta/)).toBeVisible();
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/admin-exposure.png` });
});
