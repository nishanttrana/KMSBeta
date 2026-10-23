import { expect, test, type Request } from "@playwright/test";

// Keys → Binding policies (13.51.0-beta): a binding is created with the
// fields the API takes, and the check says whether a request would reach a
// key, and why not.
const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const policy = {
  id: "kbp_1", name: "prod from the data centre", all_keys: false, key_ids: [], label_selector: { env: "prod" },
  channels: ["rest", "kms-ekm"], source_networks: ["10.0.0.0/8"], workload_identities: [], status: "active", updated_by: "admin-1", updated_at: new Date().toISOString(),
};

test("a binding policy is created and a request is checked against it", async ({ page }) => {
  const writes: Request[] = [];
  const checks: Request[] = [];
  let saved = false;
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const req = r.request();
    const p = new URL(req.url()).pathname;
    if (p.endsWith("/binding-policies/check")) {
      checks.push(req);
      return r.fulfill(json({ allowed: false, channel: "rest", policies: [{ policy_id: "kbp_1", name: policy.name, allowed: false, problem: `binding "${policy.name}" allows 10.0.0.0/8, not the address "192.0.2.1"` }] }));
    }
    if (p.endsWith("/binding-policies") && req.method() === "POST") { writes.push(req); saved = true; return r.fulfill(json({ policy }, 201)); }
    if (p.endsWith("/binding-policies")) return r.fulfill(json({ items: saved ? [policy] : [] }));
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "admin-1", token: "t", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  await page.goto("/#keys");
  await page.getByRole("button", { name: "Binding policies", exact: true }).click();
  await expect(page.getByText("No binding policies.")).toBeVisible();
  await page.getByRole("button", { name: "New binding", exact: true }).click();
  await page.getByLabel("Binding name").fill("prod from the data centre");
  await page.getByLabel("Binding label selector").fill("env=prod");
  await page.getByLabel("Binding channels").fill("rest, kms-ekm");
  await page.getByLabel("Binding networks").fill("10.0.0.0/8");
  await page.getByRole("button", { name: "Save binding", exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0]!.postDataJSON()).toEqual({
    name: "prod from the data centre", all_keys: false, key_ids: [], label_selector: { env: "prod" },
    channels: ["rest", "kms-ekm"], source_networks: ["10.0.0.0/8"], workload_identities: [], status: "active",
  });
  await expect(page.getByTestId("binding-row")).toContainText("keys labelled env=prod: through rest, kms-ekm · from 10.0.0.0/8");

  await page.getByLabel("Check key ID").fill("key_42");
  await page.getByLabel("Check address").fill("192.0.2.1");
  await page.getByRole("button", { name: "Check", exact: true }).click();
  await expect(page.getByTestId("binding-check")).toContainText("refused");
  await expect(page.getByTestId("binding-check")).toContainText('allows 10.0.0.0/8, not the address "192.0.2.1"');
  expect(checks[0]!.postDataJSON()).toEqual({ key_id: "key_42", channel: "rest", source_ip: "192.0.2.1", workload_identity: "" });
});
