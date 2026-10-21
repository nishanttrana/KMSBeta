import { expect, test, type Page, type Request } from "@playwright/test";

// Cluster → Failover (13.37.0-beta): a member is promoted for real
// (POST /cluster/failover/promote); if the primary doesn't answer, the
// console says what forcing costs before it sends force. A fenced node is
// told it must rejoin. The old Leader/Follower relabelling is gone.

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const deployment = `apiVersion: kms.vecta.io/v1
kind: DeploymentConfig
spec:
  hsm_mode: software
  features:
    clustering: true
`;
const member = {
  configured: true, voters: 2, majority: 2, failover_mode: "manual", lease_required: false, promotable: true,
  node: { node_id: "node-2", role: "follower", epoch: 1, primary_node_id: "node-1", last_primary_contact_ago_ms: 61000, primary_contact_ok: false, resubscribe_pending: false },
  peers: [{ node_id: "node-1", url: "https://kms-1:8210", is_primary: true, voter: true }, { node_id: "node-2", url: "https://kms-2:8210", is_primary: false, voter: true }],
};

async function stub(page: Page, failover: unknown, primaryAnswers: boolean): Promise<Request[]> {
  const promotes: Request[] = [];
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const req = r.request();
    const p = new URL(req.url()).pathname;
    if (p.endsWith("/cluster/failover/status")) return r.fulfill(json({ failover }));
    if (p.endsWith("/cluster/failover/promote")) {
      promotes.push(req);
      if (!primaryAnswers && !req.postDataJSON().force) {
        return r.fulfill(json({ error: { code: "primary_reachable_check_failed", message: "the primary did not answer. If it is down, promote with force" } }, 409));
      }
      return r.fulfill(json({ result: { node_id: "node-2", epoch: 2, previous_primary_node_id: "node-1", previous_primary_fenced: primaryAnswers, caught_up: primaryAnswers } }));
    }
    return r.fulfill(json({}));
  });
  await page.route("**/config/deployment.yaml", (r) => r.fulfill({ status: 200, contentType: "text/yaml", body: deployment }));
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  return promotes;
}

test("a member is promoted; an unreachable primary needs a second, explained confirmation", async ({ page }) => {
  const promotes = await stub(page, member, false);
  await page.goto("/#cluster/failover");
  await expect(page.getByTestId("failover-peer-node-1")).toContainText("primary");
  await page.getByRole("button", { name: "Promote this node" }).click();
  await page.getByRole("button", { name: "Promote", exact: true }).click();
  await expect(page.getByText(/loses its writes that have not reached this node/)).toBeVisible();
  await page.getByRole("button", { name: "Promote anyway" }).click();
  await expect.poll(() => promotes.length).toBe(2);
  expect(promotes[0]!.postDataJSON()).toMatchObject({ confirm: true, force: false });
  expect(promotes[1]!.postDataJSON()).toMatchObject({ confirm: true, force: true });
});

test("a switchover sends no force", async ({ page }) => {
  const promotes = await stub(page, member, true);
  await page.goto("/#cluster/failover");
  await page.getByRole("button", { name: "Promote this node" }).click();
  await page.getByRole("button", { name: "Promote", exact: true }).click();
  await expect.poll(() => promotes.length).toBe(1);
  expect(promotes[0]!.postDataJSON()).toMatchObject({ force: false });
});

test("a fenced node is told to rejoin and offers no promotion", async ({ page }) => {
  await stub(page, { ...member, node: { ...member.node, role: "fenced", epoch: 3 } }, true);
  await page.goto("/#cluster/failover");
  await expect(page.getByRole("alert")).toContainText("Rejoin it");
  await expect(page.getByRole("button", { name: "Promote this node" })).toHaveCount(0);
  await page.goto("/#cluster/nodes");
  await expect(page.getByRole("button", { name: "Apply" })).toHaveCount(0);
});
