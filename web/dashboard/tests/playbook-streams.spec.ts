import { expect, test, type Page } from "@playwright/test";

// Event streaming lives in Playbooks (2.10.0-beta): a stream names a
// connection, never a URL or credential, and SIEM types sit beside Slack and
// Teams in Connections. The APIs are stubbed; delivery is tested in
// services/audit and pkg/siem.

const SHOTS = process.env.PLAYBOOK_SHOTS_DIR || "";

const connections = [
  { id: "pbconn_splunk", name: "SOC Splunk", type: "splunk_hec", endpoint: "splunk.example.com", fields_set: ["token", "url"], updated_at: "2026-09-28T09:00:00Z" },
  { id: "pbconn_slack", name: "Ops Slack", type: "slack", endpoint: "hooks.slack.com", fields_set: ["webhook_url"], updated_at: "2026-09-28T09:00:00Z" },
  { id: "pbconn_jira", name: "Jira", type: "jira", endpoint: "example.atlassian.net", fields_set: ["base_url"], updated_at: "2026-09-28T09:00:00Z" }
];

const streams = [
  { id: "wh_1", tenant_id: "root", name: "SIEM feed", connection_id: "pbconn_splunk", connection_type: "splunk_hec", legacy: false, events: ["*"], enabled: true, created_at: "2026-09-28T09:00:00Z", failure_count: 0 },
  { id: "wh_2", tenant_id: "root", name: "Old Datadog", connection_id: "", connection_type: "", legacy: true, format: "datadog", events: ["audit.key.*"], enabled: true, created_at: "2026-09-01T09:00:00Z", failure_count: 0 }
];

const catalog = {
  triggers: [{ type: "canary_tripped", label: "Canary key referenced", group: "Incident response", subjects: ["audit.keycore.canary_tripped"] }],
  actions: [{ type: "send_siem_alert", label: "Raise SIEM alert", group: "Notification", connection: "siem", required: ["connection_id"], optional: ["title", "severity"] }],
  categories: ["incident_response"],
  connection_types: [
    { type: "slack", label: "Slack incoming webhook", fields: ["webhook_url"], optional: [], category: "notify", secrets: ["webhook_url"], stream: true },
    { type: "jira", label: "Jira", fields: ["base_url"], optional: ["api_token"], category: "ticketing", secrets: ["api_token"], stream: false },
    { type: "splunk_hec", label: "Splunk HTTP Event Collector", fields: ["url", "token"], optional: ["index", "sourcetype"], category: "siem", secrets: ["token"], stream: true },
    { type: "syslog", label: "Syslog over TLS, CEF (QRadar, ArcSight)", fields: ["address"], optional: ["ca_pem", "server_name"], category: "siem", secrets: [], stream: true }
  ],
  event_fields: [], filter_ops: [], templates: [], incident_statuses: []
};

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

async function stub(page: Page, created: unknown[]): Promise<void> {
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    if (p.endsWith("/audit/webhooks") && req.method() === "POST") {
      created.push(req.postDataJSON());
      return route.fulfill(json({ webhook: { ...streams[0], id: "wh_new", name: "new" } }, 201));
    }
    if (p.endsWith("/audit/webhooks")) return route.fulfill(json({ items: streams }));
    if (p.endsWith("/mek/exposure")) return route.fulfill(json({ items: [], open: 0 }));
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

async function openPlaybooks(page: Page, view: string): Promise<void> {
  await page.goto("/");
  await page.getByText("Playbooks", { exact: true }).first().click();
  await page.getByRole("button", { name: view }).first().click();
}

test("event streaming is a Playbooks view; there is no separate Webhooks tab", async ({ page }) => {
  await stub(page, []);
  await openPlaybooks(page, "Event streaming");
  await expect(page.getByText("SIEM feed")).toBeVisible();
  await expect(page.getByText("SOC Splunk → splunk.example.com")).toBeVisible();
  await expect(page.getByText("Legacy: pick a connection")).toBeVisible();
  await expect(page.getByText("Webhooks & SIEM")).toHaveCount(0);
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/event-streams.png`, fullPage: true });
});

test("a new stream names a stream-capable connection and sends no URL or secret", async ({ page }) => {
  const created: any[] = [];
  await stub(page, created);
  await openPlaybooks(page, "Event streaming");
  await page.getByRole("button", { name: "New stream" }).click();
  const select = page.locator("select").filter({ hasText: "choose…" });
  await expect(select.locator("option", { hasText: "Jira" })).toHaveCount(0); // ticketing can't carry a stream
  await page.getByPlaceholder("e.g. SOC Splunk").fill("new");
  await select.selectOption("pbconn_splunk");
  await page.getByTitle("Keys and crypto operations").click();
  await page.getByRole("button", { name: "Create stream" }).click();
  await expect.poll(() => created.length).toBe(1);
  expect(created[0]).toEqual({ name: "new", connection_id: "pbconn_splunk", events: ["audit.key.*"] });
});

test("SIEM connection types are grouped with masked credentials", async ({ page }) => {
  await stub(page, []);
  await openPlaybooks(page, "Connections");
  await page.getByRole("button", { name: "New connection" }).click();
  const type = page.locator("select").filter({ hasText: "Splunk HTTP Event Collector" });
  await expect(type.locator("optgroup[label='SIEM'] option")).toHaveCount(2);
  await type.selectOption("splunk_hec");
  await expect(page.getByPlaceholder("https://…")).toHaveAttribute("type", "text");
  const token = page.locator("input[type='password']");
  await expect(token).toHaveCount(1);
  await expect(page.getByText("Test sends one labelled event to the SIEM.", { exact: false })).toBeVisible();
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/siem-connection.png`, fullPage: true });
});
