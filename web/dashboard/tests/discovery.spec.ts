import { expect, test, type Page, type Request } from "@playwright/test";
import { discoveryFixture as fx } from "./fixtures/discovery-fixture";

// Crypto Discovery: sources, drill-downs, targets, background scans and
// uploads against the payloads the discovery service produced
// (tests/fixtures/discovery-fixture.ts).

const SHOTS = process.env.DISCOVERY_SHOTS_DIR || "";
const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const running = { ...fx.scans[1], id: "scan_live", status: "running", stats: { sources_done: ["certs"], certs_assets: 2 } };
const finished = { ...running, status: "completed", stats: { sources_done: ["network", "cloud", "certs"], network_assets: 6, cloud_assets: 1, certs_assets: 2, assets_discovered: 9 } };

// The asset list as the service filters and pages it (FindAssets).
function assetPage(url: URL) {
  const q = url.searchParams;
  const classes = (q.get("classification") || "").split(",").filter(Boolean);
  const text = (q.get("q") || "").toLowerCase();
  const all = fx.assets.filter((a) =>
    (!classes.length || classes.includes(a.classification)) &&
    (!q.get("source") || a.source === q.get("source")) &&
    (!q.get("asset_type") || a.asset_type === q.get("asset_type")) &&
    (!q.has("algorithm") || a.algorithm === q.get("algorithm")) &&
    (q.get("pqc_ready") !== "true" || a.pqc_ready) &&
    (!text || `${a.name} ${a.location} ${a.algorithm}`.toLowerCase().includes(text)));
  const offset = Number(q.get("offset") || 0);
  return { items: all.slice(offset, offset + Number(q.get("limit") || 25)), total: all.length };
}

async function stub(page: Page, opts: { down?: boolean } = {}): Promise<Request[]> {
  const writes: Request[] = [];
  let polls = 0;
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    if (req.method() !== "GET") writes.push(req);
    if (p.endsWith("/discovery/summary")) return opts.down ? route.fulfill(json({ error: { message: "service unavailable" } }, 503)) : route.fulfill(json({ summary: fx.summary }));
    if (p.endsWith("/discovery/assets")) return opts.down ? route.fulfill(json({ error: { message: "service unavailable" } }, 503)) : route.fulfill(json(assetPage(new URL(req.url()))));
    if (p.endsWith("/discovery/scans")) return route.fulfill(json({ items: fx.scans }));
    if (p.endsWith("/discovery/sources")) return route.fulfill(json({ items: fx.sources }));
    if (p.endsWith("/discovery/targets") && req.method() === "POST") return route.fulfill(json({ target: { id: "target_new", host: "10.0.4.0/24", port: 22, protocol: "ssh" } }, 201));
    if (p.endsWith("/discovery/targets")) return route.fulfill(json({ items: fx.targets }));
    if (p.endsWith("/discovery/scan")) return route.fulfill(json({ scan: running }, 202));
    if (p.endsWith("/discovery/scans/scan_live")) return route.fulfill(json({ scan: ++polls > 1 ? finished : running }));
    if (p.endsWith("/discovery/upload")) return route.fulfill(json({ scan: fx.scans[0], assets: fx.assets.filter((a) => a.source === "upload") }));
    if (p.endsWith("/auth/tenants")) return route.fulfill(json({ items: [{ id: "root", name: "root", status: "active" }] }));
    return route.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  return writes;
}

async function open(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/");
  await page.getByText("Crypto Discovery", { exact: true }).first().click();
  await expect(page.getByText("Sources", { exact: true })).toBeVisible();
}

const qv = fx.summary.classification_counts.quantum_vulnerable;

test("sources, charts and drill-downs show the scanned inventory", async ({ page }) => {
  await stub(page);
  await open(page);
  for (const name of ["Network", "Cloud KMS", "KMS certificates", "Source code", "File upload"]) {
    await expect(page.getByText(name, { exact: true }).first()).toBeVisible();
  }
  await expect(page.getByText("Not mounted")).toBeVisible();
  if (SHOTS) {
    await page.screenshot({ path: `${SHOTS}/discovery-overview.png`, fullPage: true });
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "dark"));
    await page.screenshot({ path: `${SHOTS}/discovery-overview-dark.png`, fullPage: true });
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "light"));
  }

  // A class bar lists exactly the assets it counts: the drill-down asks the
  // service for the filter the summary counted with.
  const drillRequest = page.waitForRequest((r) => r.url().includes("/discovery/assets") && r.url().includes("classification=quantum_vulnerable"));
  await page.getByRole("button", { name: /Quantum-vulnerable\s+\d+/ }).first().click();
  await drillRequest;
  await expect(page.getByText(`Quantum-vulnerable: ${qv} entries`)).toBeVisible();
  await expect(page.getByText(/, \d+ loaded/)).toHaveCount(0);
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/discovery-drill.png`, fullPage: true });

  // An entry opens its detail with what the scan recorded.
  await page.getByText("ssh-ed25519", { exact: false }).first().click();
  await expect(page.getByText("Fingerprint", { exact: true })).toBeVisible();
  await expect(page.getByText("Remove from inventory")).toBeVisible();
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/discovery-detail.png` });
});

test("an SSH range is added as a network target", async ({ page }) => {
  const writes = await stub(page);
  await open(page);
  await page.getByRole("button", { name: "Targets" }).click();
  await page.getByRole("button", { name: "SSH", exact: true }).click();
  await page.getByPlaceholder("host, IP or range (10.0.4.0/24)").fill("10.0.4.0/24");
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/discovery-targets.png` });
  await page.getByRole("button", { name: "Add" }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0]!.postDataJSON()).toEqual({ host: "10.0.4.0/24", port: 22, protocol: "ssh" });
});

test("a scan runs in the background and reports when it settles", async ({ page }) => {
  const writes = await stub(page);
  await open(page);
  await page.getByRole("button", { name: "Scan all" }).click();
  await expect(page.getByText("Scanning", { exact: true })).toBeVisible();
  // Only configured sources are scanned.
  expect(writes[0]!.postDataJSON().scan_types).toEqual(["network", "cloud", "certs"]);
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/discovery-running.png` });
  await expect(page.getByText(/Scan completed: 9 assets/)).toBeVisible({ timeout: 10_000 });
});

test("an uploaded file is sent for inventory", async ({ page }) => {
  const writes = await stub(page);
  await open(page);
  const pemText = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
  await page.locator("input[type=file]").setInputFiles({ name: "bundle.pem", mimeType: "application/x-pem-file", buffer: Buffer.from(pemText) });
  await expect.poll(() => writes.length).toBe(1);
  const body = writes[0]!.postDataJSON();
  expect(body.name).toBe("bundle.pem");
  expect(Buffer.from(body.content, "base64").toString()).toBe(pemText);
  await expect(page.getByText(/3 assets found, 1 exposed secrets/)).toBeVisible();
});

test("a discovery outage shows unavailable, never an empty inventory", async ({ page }) => {
  await stub(page, { down: true });
  await open(page);
  await expect(page.getByText(/Discovery unavailable/)).toBeVisible();
  await expect(page.getByText("No assets yet")).toHaveCount(0);
});
