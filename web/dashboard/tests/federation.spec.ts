import { expect, test, type Request } from "@playwright/test";

// Keys → Federation (13.60.0-beta): a peer is added from its pasted
// identity, a key is replicated to it, and a replica is promoted here.
const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const identity = { tenant_id: "root", fingerprint: "a".repeat(64), kem_public: "AAAA", sign_public_pem: "-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----\n" };
const theirs = { ...identity, fingerprint: "b".repeat(64) };
const peer = { id: "fedp_1", name: "dr-site", url: "https://kms-dr.example.com", peer_tenant_id: "root", fingerprint: theirs.fingerprint, client_id: "fed-client", created_at: new Date().toISOString() };
const link = { id: "fedl_1", key_id: "key_42", peer_id: "fedp_1", status: "in_sync", last_sync_at: new Date().toISOString() };

test("a peer is added, a key replicated to it, and a replica promoted", async ({ page }) => {
  const peerWrites: Request[] = [];
  const linkWrites: Request[] = [];
  const promotes: Request[] = [];
  let peers: unknown[] = [];
  let links: unknown[] = [];
  let role = "replica";
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const req = r.request();
    const p = new URL(req.url()).pathname;
    if (p.endsWith("/federation/identity")) return r.fulfill(json({ identity }));
    if (p.endsWith("/federation/peers") && req.method() === "POST") { peerWrites.push(req); peers = [peer]; return r.fulfill(json({ peer }, 201)); }
    if (p.endsWith("/federation/peers")) return r.fulfill(json({ items: peers }));
    if (p.endsWith("/federation/links") && req.method() === "POST") { linkWrites.push(req); links = [link]; return r.fulfill(json({ link }, 201)); }
    if (p.endsWith("/federation/links")) return r.fulfill(json({ items: links }));
    if (p.endsWith("/promote")) { promotes.push(req); role = "primary"; return r.fulfill(json({ state: { key_id: "key_7", role, epoch: 2 } })); }
    if (p.includes("/federation/keys/")) return r.fulfill(json({ state: { key_id: "key_7", role, epoch: role === "primary" ? 2 : 1 }, versions: [{ version: 1, status: "active", kcv: "A1B2C3" }] }));
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "admin-1", token: "t", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  await page.goto("/#keys");
  await page.getByRole("button", { name: "Federation", exact: true }).click();
  await expect(page.getByTestId("federation-fingerprint")).toContainText("a".repeat(64));

  await page.getByRole("button", { name: "Add peer", exact: true }).click();
  await page.getByLabel("Peer name").fill("dr-site");
  await page.getByLabel("Peer URL").fill("https://kms-dr.example.com");
  await page.getByLabel("Peer identity").fill(JSON.stringify({ identity: theirs }));
  await page.getByLabel("Peer client ID").fill("fed-client");
  await page.getByLabel("Peer API key").fill("secret-key");
  await page.getByRole("button", { name: "Add peer", exact: true }).last().click();
  await expect.poll(() => peerWrites.length).toBe(1);
  expect(peerWrites[0]!.postDataJSON()).toEqual({
    name: "dr-site", url: "https://kms-dr.example.com", peer_tenant_id: "", identity: theirs, ca_pem: "", client_id: "fed-client", api_key: "secret-key",
  });
  await expect(page.getByTestId("federation-peer")).toContainText("dr-site");

  await page.getByLabel("Key to replicate").fill("key_42");
  await page.getByLabel("Replicate to").click();
  await page.getByRole("option", { name: "dr-site", exact: true }).click();
  await page.getByRole("button", { name: "Replicate", exact: true }).click();
  await expect.poll(() => linkWrites.length).toBe(1);
  expect(linkWrites[0]!.postDataJSON()).toEqual({ key_id: "key_42", peer_id: "fedp_1" });
  await expect(page.getByTestId("federation-link")).toContainText("in sync");

  await page.getByLabel("Federation key ID").fill("key_7");
  await page.getByRole("button", { name: "Show", exact: true }).click();
  await expect(page.getByTestId("federation-state")).toContainText("replica");
  await page.getByLabel("Promotion reason").fill("site A is down: failover");
  await page.getByRole("button", { name: "Promote here", exact: true }).click();
  await expect.poll(() => promotes.length).toBe(1);
  expect(promotes[0]!.postDataJSON()).toEqual({ reason: "site A is down: failover" });
  await expect(page.getByTestId("federation-state")).toContainText("primary");
});
