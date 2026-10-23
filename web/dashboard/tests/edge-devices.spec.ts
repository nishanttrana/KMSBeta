import { expect, test, type Request } from "@playwright/test";

// Enterprise KM → Edge devices (13.52.0-beta): a device is added with the
// fields the route takes, its registration token is shown once, its leases
// and receipts are listed, and it is revoked with a reason.
const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const now = new Date().toISOString();
const later = new Date(Date.now() + 3600_000).toISOString();
const device = {
  id: "edge_1", name: "pump-17", status: "active", allowed_key_ids: ["key-a"], max_lease_seconds: 86400, token_pending: false,
  last_receipt_seq: 6, last_seen_at: now, last_source_ip: "198.51.100.7", agent_version: "13.52.0-beta", created_by: "admin-1", created_at: now, enrolled_at: now,
};

test("an edge device is added, enrolled with a one-time token, and revoked", async ({ page }) => {
  const creates: Request[] = [];
  const revokes: Request[] = [];
  let added = false;
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const req = r.request();
    const p = new URL(req.url()).pathname;
    if (p.endsWith("/ekm/edge/devices") && req.method() === "POST") { creates.push(req); added = true; return r.fulfill(json({ device: { ...device, status: "pending" } }, 201)); }
    if (p.endsWith("/ekm/edge/devices")) return r.fulfill(json({ items: added ? [device] : [] }));
    if (p.endsWith("/registration-token")) return r.fulfill(json({ token: "vedge-reg.dDE.edge_1.secret", expires_at: later }, 201));
    if (p.endsWith("/edge_1/leases")) return r.fulfill(json({ items: [{ id: "lease_1", key_id: "key-a", key_version: 3, issued_at: now, expires_at: later }] }));
    if (p.endsWith("/edge_1/receipts")) return r.fulfill(json({ items: [{ seq: 6, lease_id: "lease_1", operation: "encrypt", bytes: 4096, at: now, received_at: now }] }));
    if (p.endsWith("/edge_1/revoke")) { revokes.push(req); return r.fulfill(json({ device: { ...device, status: "revoked" } })); }
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "admin-1", token: "t", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  await page.goto("/#ekm/edge");
  await expect(page.getByText("No edge devices.")).toBeVisible();
  await page.getByRole("button", { name: "Add device", exact: true }).first().click();
  await page.getByLabel("Edge device name").fill("pump-17");
  await page.getByLabel("Edge device keys").fill("key-a");
  await page.getByLabel("Edge device longest lease").fill("24");
  await page.getByRole("button", { name: "Add device", exact: true }).last().click();
  await expect.poll(() => creates.length).toBe(1);
  expect(creates[0]!.postDataJSON()).toEqual({ name: "pump-17", allowed_key_ids: ["key-a"], max_lease_seconds: 86400 });

  const row = page.getByTestId("edge-device-row");
  await expect(row).toContainText("Keys key-a · leases up to 24 h");
  await expect(row).toContainText("from 198.51.100.7 · receipts to 6");
  await row.getByRole("button", { name: "Re-enrol token", exact: true }).click();
  await expect(page.getByTestId("edge-token")).toHaveText("vedge-reg.dDE.edge_1.secret");

  await row.getByText("pump-17", { exact: true }).click();
  await expect(page.getByTestId("edge-lease-row")).toContainText("key-a v3");
  await expect(row).toContainText("#6 encrypt 4096 bytes under lease_1");

  await row.getByRole("button", { name: "Revoke", exact: true }).first().click();
  await page.getByRole("dialog").getByRole("textbox").fill("stolen");
  await page.getByRole("dialog").getByRole("button", { name: "Revoke", exact: true }).click();
  await expect.poll(() => revokes.length).toBe(1);
  expect(revokes[0]!.postDataJSON()).toEqual({ reason: "stolen" });
});
