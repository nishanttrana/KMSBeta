import { expect, test, type Request } from "@playwright/test";

// Keys → Metadata profiles (13.50.0-beta): a profile is created with the
// fields the API takes, and "Check keys" lists the keys that don't comply.
const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const profile = {
  id: "mdp_1", name: "encryption keys", purposes: ["encrypt"], status: "active", require_owner: true, require_description: false,
  labels: [{ key: "env", required: true, allowed: ["prod", "dev"] }], required_tags: [], created_by: "admin-1", updated_by: "admin-1", updated_at: new Date().toISOString(),
};

test("a metadata profile is created and lists the keys that don't meet it", async ({ page }) => {
  const writes: Request[] = [];
  let saved = false;
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const req = r.request();
    const p = new URL(req.url()).pathname;
    if (p.endsWith("/metadata-profiles") && req.method() === "POST") { writes.push(req); saved = true; return r.fulfill(json({ profile }, 201)); }
    if (p.endsWith("/metadata-profiles")) return r.fulfill(json({ items: saved ? [profile] : [] }));
    if (p.endsWith("/metadata-profiles/mdp_1/violations")) return r.fulfill(json({ checked: 3, items: [{ key_id: "key_9", name: "legacy-db", purpose: "encrypt", problems: ["an owner is required", 'label "env" is required'] }] }));
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "admin-1", token: "t", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  await page.goto("/#keys");
  await page.getByRole("button", { name: "Metadata profiles", exact: true }).click();
  await expect(page.getByText("No metadata profiles.")).toBeVisible();
  await page.getByRole("button", { name: "New profile", exact: true }).click();
  await page.getByLabel("Profile name").fill("encryption keys");
  await page.getByLabel("Profile purposes").fill("encrypt");
  await page.locator("label", { hasText: "Owner required" }).locator("div").first().click();
  await page.getByRole("button", { name: "Add label", exact: true }).click();
  await page.getByLabel("Label 1 key").fill("env");
  await page.getByLabel("Label 1 allowed values").fill("prod, dev");
  await page.getByRole("button", { name: "Save profile", exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0]!.postDataJSON()).toEqual({
    name: "encryption keys", purposes: ["encrypt"], status: "active", require_owner: true, require_description: false,
    labels: [{ key: "env", required: true, allowed: ["prod", "dev"] }], required_tags: [],
  });
  await expect(page.getByTestId("metadata-profile-row")).toContainText("encrypt keys · owner · env (required) ∈ prod|dev");
  await page.getByRole("button", { name: "Check keys", exact: true }).click();
  await expect(page.getByTestId("metadata-violations")).toContainText("1 of 3 keys don't comply.");
  await expect(page.getByTestId("metadata-violations")).toContainText('legacy-db: an owner is required; label "env" is required');
});
