import { expect, test, type Request } from "@playwright/test";

// Workbench → REST API → REST Client Security (13.53.0-beta): a client is
// given a role, sending only the role, and the page shows what its tokens
// will hold.
const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

test("a REST client is given a role and its token permissions are shown", async ({ page }) => {
  const puts: Request[] = [];
  let role = "";
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const req = r.request();
    const p = new URL(req.url()).pathname;
    if (p.endsWith("/auth/clients")) return r.fulfill(json({ items: [{ id: "reg_1", tenant_id: "root", client_name: "release-pipeline", status: "approved", requested_role: "app-service", auth_mode: "api_key", interface_name: "rest", rate_limit: 1000 }] }));
    if (p.endsWith("/auth/clients/reg_1/role") && req.method() === "PUT") {
      puts.push(req);
      role = req.postDataJSON().role;
      return r.fulfill(json({ client_id: "reg_1", role, permissions: ["key.decrypt", "key.encrypt"] }));
    }
    if (p.endsWith("/auth/clients/reg_1/role")) return r.fulfill(json({ client_id: "reg_1", role, permissions: role ? ["key.decrypt", "key.encrypt"] : ["kms.read", "kms.write"] }));
    if (p.endsWith("/auth/roles")) return r.fulfill(json({ items: [{ tenant_id: "root", role_name: "key-operator", permissions: ["key.encrypt", "key.decrypt"] }] }));
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "admin-1", token: "t", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  await page.goto("/#workbench/restapi");
  await page.getByRole("button", { name: /release-pipeline/ }).first().click();
  await expect(page.getByTestId("client-role-permissions")).toHaveText("Tokens hold: kms.read, kms.write");
  await expect(page.getByRole("button", { name: "Save role", exact: true })).toBeDisabled();
  await page.getByText("None (secrets and signing)", { exact: true }).first().click();
  await page.getByRole("option", { name: "key-operator", exact: true }).click();
  await page.getByRole("button", { name: "Save role", exact: true }).click();
  await expect.poll(() => puts.length).toBe(1);
  expect(puts[0]!.postDataJSON()).toEqual({ role: "key-operator" });
  await expect(page.getByTestId("client-role-permissions")).toHaveText("Tokens hold: key.decrypt, key.encrypt");
});
