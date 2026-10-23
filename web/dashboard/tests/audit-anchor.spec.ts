import { expect, test, type Request } from "@playwright/test";

// Audit Log → Checkpoints (13.47.0-beta): each checkpoint's RFC 3161
// timestamp as the audit service verified it, and turning timestamping on
// with a "tsa" credential, sending only the fields the route takes.
const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const now = new Date().toISOString();
const cp = (seq: number, anchor: unknown) => ({ event_id: `evt_${seq}`, chain_node: "", sequence: seq, chain_hash: "ab".repeat(32), signed_at: now,
  key_id: "cd".repeat(32), algorithm: "ECDSA-P384", message: "{}", signature: "MEUCIQ==", status: "verified", anchor });

test("checkpoints show their timestamp, and timestamping is turned on with a credential", async ({ page }) => {
  const writes: Request[] = [];
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const req = r.request();
    const p = new URL(req.url()).pathname;
    if (p.endsWith("/audit/checkpoints")) return r.fulfill(json({ items: [
      cp(42, { status: "anchored", gen_time: now, tsa: "freetsa.org", serial: "157076171", trust: "root a6379e7cecc05faa", token_b64: "MIIRAQ==" }),
      cp(41, { status: "late", gen_time: now, tsa: "freetsa.org", serial: "1", trust: "system roots", error: "the authority's time is not within an hour" }),
      cp(40, { status: "not_anchored" }),
    ] }));
    if (p.endsWith("/audit/anchor") && req.method() === "PUT") { writes.push(req); return r.fulfill(json({ anchor: { ...req.postDataJSON(), updated_by: "admin-1" } })); }
    if (p.endsWith("/audit/anchor")) return r.fulfill(json({ anchor: { enabled: false, connection_id: "" } }));
    if (p.endsWith("/compliance/connections")) return r.fulfill(json({ data: [{ id: "pbconn_tsa", name: "FreeTSA", type: "tsa", endpoint: "freetsa.org" }] }));
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "admin-1", token: "t", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  await page.goto("/#audit/checkpoints");
  await expect(page.getByText("Timestamped", { exact: true })).toBeVisible();
  await expect(page.getByText("Timestamped late", { exact: true })).toBeVisible();
  await page.getByText("Timestamped", { exact: true }).click();
  await expect(page.getByText(/^Timestamped at .* by freetsa\.org \(serial 157076171, root a6379e7cecc05faa\)$/)).toBeVisible();
  await expect(page.getByText("MIIRAQ==")).toBeVisible();
  await page.getByRole("dialog").getByRole("button", { name: "Close", exact: true }).click();

  await expect(page.getByRole("button", { name: "Turn on", exact: true })).toBeDisabled();
  await page.getByText("choose a credential…", { exact: true }).first().click();
  await page.getByRole("option", { name: "FreeTSA (freetsa.org)", exact: true }).click();
  await page.getByRole("button", { name: "Turn on", exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0]!.postDataJSON()).toEqual({ enabled: true, connection_id: "pbconn_tsa" });
});
