import { expect, test, type Page, type Request } from "@playwright/test";

// Backups and approval policies have one home each (owner, 2026-10-20;
// 13.26.0-beta): Backup & Restore and Approvals.

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const PAUSED = {
  id: "gp_1", tenant_id: "root", name: "Destroy needs 2 of 3", description: "", scope: "keys", trigger_actions: ["key.destroy"],
  quorum_mode: "threshold", required_approvals: 2, total_approvers: 3, approver_users: ["a@corp.com"], approver_roles: [],
  timeout_hours: 48, notification_channels: ["dashboard"], status: "inactive",
};

async function stub(page: Page, permissions: string[]): Promise<Request[]> {
  const writes: Request[] = [];
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const req = r.request();
    const p = new URL(req.url()).pathname;
    if (req.method() === "PUT" && p.includes("/governance/policies/")) { writes.push(req); return r.fulfill(json({ policy: { ...PAUSED, ...req.postDataJSON() } })); }
    if (p.endsWith("/governance/policies")) return r.fulfill(json({ items: [PAUSED] }));
    if (p.endsWith("/governance/backups")) return r.fulfill(json({ items: [] }));
    return r.fulfill(json({}));
  });
  await page.addInitScript((perms) => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: perms,
    }));
  }, permissions);
  return writes;
}

test("a policy is enabled with its whole definition, and editing a paused one keeps it paused", async ({ page }) => {
  const writes = await stub(page, ["*"]);
  await page.goto("/#approvals/policies");
  await page.getByRole("button", { name: "Enable", exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  // The server replaces the whole policy: a status-only body would blank it.
  expect(writes[0]!.postDataJSON()).toMatchObject({ name: PAUSED.name, trigger_actions: ["key.destroy"], approver_users: ["a@corp.com"], status: "active" });

  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const dialog = page.getByRole("dialog");
  // A channel can be unticked: the old handler only ever added one.
  await dialog.locator("label", { hasText: "Email" }).locator("div").first().click();
  await dialog.locator("label", { hasText: "Email" }).locator("div").first().click();
  await dialog.getByRole("button", { name: "Update Policy", exact: true }).click();
  await expect.poll(() => writes.length).toBe(2);
  expect(writes[1]!.postDataJSON().status).toBe("inactive");
  expect(writes[1]!.postDataJSON().notification_channels).toEqual(["dashboard"]);
});

test("a policy without triggers or approvers is not saved", async ({ page }) => {
  const writes = await stub(page, ["*"]);
  await page.goto("/#approvals/policies");
  await page.getByRole("button", { name: "Create Policy" }).first().click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("textbox").first().fill("Export needs approval");
  await dialog.getByRole("button", { name: "Create Policy", exact: true }).click();
  await expect(page.getByText("Name at least one trigger action.")).toBeVisible();
  await dialog.getByPlaceholder("key.destroy, playbook.*").fill("key.export");
  await dialog.getByRole("button", { name: "Create Policy", exact: true }).click();
  await expect(page.getByText("Name at least one approver or approver role.")).toBeVisible();
  expect(writes).toHaveLength(0);
});

test("Backup & Restore is offered to platform administrators only", async ({ page }) => {
  await stub(page, ["auth.user.read"]); // root tenant, not a platform administrator
  await page.goto("/");
  await expect(page.getByText("Backup & Restore", { exact: true })).toHaveCount(0);
});

// The trigger choices are actions services really submit for approval; a
// tick adds one, an untick removes it, and typed patterns stay (13.27.0-beta).
test("trigger checkboxes edit the pattern list without losing typed patterns", async ({ page }) => {
  const writes = await stub(page, ["*"]);
  await page.goto("/#approvals/policies");
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const dialog = page.getByRole("dialog");
  const box = dialog.getByPlaceholder("key.destroy, playbook.*");
  await box.fill("key.destroy, custom.*");
  const picker = dialog.getByTestId("approval-trigger-picker");
  const tick = (label: string) => picker.locator("label", { hasText: label }).locator("div").first().click();
  await tick("Revoke certificate");
  await expect(box).toHaveValue("key.destroy, custom.*, playbook.revoke-certificate");
  await tick("Destroy (when Posture forces quorum on destructive operations)");
  await expect(box).toHaveValue("custom.*, playbook.revoke-certificate");
  await expect(picker.getByText("User create")).toHaveCount(0);
  await dialog.getByRole("button", { name: "Update Policy", exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0]!.postDataJSON().trigger_actions).toEqual(["custom.*", "playbook.revoke-certificate"]);
});
