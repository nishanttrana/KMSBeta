import { expect, test, type Page } from "@playwright/test";
import { coveredControls } from "./fixtures/layout";

// Enterprise KM → EKM for DBs: tiles count the tenant's clients and filter
// the table to the clients they count, a row opens the client's health with
// every recent check-in, and a new client stays "awaiting registration"
// until the service says its agent enrolled. Payloads have the shape
// services/ekm/clients.go returns.

const SHOTS = process.env.EKM_SHOTS_DIR || "";
const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const ago = (sec: number) => new Date(Date.now() - sec * 1000).toISOString();
const THRESHOLDS = { healthy_within_sec: 300, degraded_within_sec: 3600 };

const client = (id: string, name: string, engine: string, host: string, health: string, ageSec?: number) => ({
  id, name, db_engine: engine, host, registration: health === "pending" ? "pending" : "registered", health,
  ...(ageSec === undefined ? {} : { last_seen_at: ago(ageSec), last_seen_age_sec: ageSec, registered_at: ago(86400 * 9) }),
  created_at: ago(86400 * 10), source_ip: health === "pending" ? "" : "10.20.15.32", version: health === "pending" ? "" : "vecta-ekm-agent/1.0.0",
  tde_state: health === "pending" ? "unknown" : "enabled", heartbeat_interval_sec: 30, assigned_key_id: `key_${id}`, assigned_key_version: "v1",
  credential: health === "pending" ? "" : "client_key",
});

const CLIENTS = [
  client("ekm_1", "ORCL-PROD-01", "oracle", "orcl-prod-01.corp.local", "healthy", 18),
  client("ekm_2", "MSSQL-FIN-02", "mssql", "sqlfin02.corp.local", "degraded", 25 * 60),
  client("ekm_3", "ORCL-DR-03", "oracle", "orcl-dr-03.dr.corp.local", "offline", 3 * 3600 + 180),
  client("ekm_4", "test-db", "mssql", "", "healthy", 17),
  client("ekm_5", "PG-STAGE-07", "postgresql", "pg-stage-07.corp.local", "pending"),
];

// Thirty check-ins 30s apart, one of them late and one after a long silence.
const CHECK_INS = Array.from({ length: 31 }, (_, i) => i).reduce<{ at: string; source_ip: string; version: string; status: string }[]>((out, i) => {
  const late = i === 9 ? 45 : i === 28 ? 400 : 0;
  const prev = out.length ? new Date(out[out.length - 1]!.at).getTime() : Date.now() - 2000 * 1000;
  out.push({ at: new Date(prev + (30 + late) * 1000).toISOString(), source_ip: "10.20.15.32", version: "vecta-ekm-agent/1.0.0", status: "connected" });
  return out;
}, []);

type Opts = { listDown?: boolean; enrolAfterPolls?: number; clients?: ReturnType<typeof client>[] };
type Write = { call: string; body: unknown };

async function stub(page: Page, opts: Opts = {}, writes: Write[] = []): Promise<string[]> {
  const calls: string[] = [];
  const added: ReturnType<typeof client>[] = [];
  let polls = 0;
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    if (!p.includes("/svc/ekm/")) return route.fulfill(json({}));
    const call = `${req.method()} ${p.replace(/^.*\/svc\/ekm/, "")}`;
    calls.push(call);
    if (req.method() !== "GET") writes.push({ call, body: req.postDataJSON() });
    if (call === "GET /ekm/clients") {
      return route.fulfill(opts.listDown ? json({ error: { message: "service unavailable" } }, 503) : json({ items: [...(opts.clients ?? CLIENTS), ...added], thresholds: THRESHOLDS, server_time: new Date().toISOString() }));
    }
    if (call === "POST /ekm/clients") {
      const body = req.postDataJSON() as { name: string; db_engine: string; host: string };
      added.push(client("ekm_new", body.name, body.db_engine, body.host, "pending"));
      return route.fulfill(json({ client: added[0] }, 201));
    }
    if (call === "POST /ekm/clients/ekm_new/registration-token") {
      return route.fulfill(json({ token: "vekm-reg.cm9vdA.ekm_new.fixture-secret", expires_at: ago(-86400), client_id: "ekm_new", enroll_path: "/ekm/clients/enroll" }, 201));
    }
    if (call === "GET /ekm/clients/ekm_new") {
      polls += 1;
      const done = opts.enrolAfterPolls !== undefined && polls > opts.enrolAfterPolls;
      const c = done ? { ...added[0]!, registration: "registered", health: "healthy", registered_at: ago(1), last_seen_at: ago(1), last_seen_age_sec: 1, source_ip: "10.20.15.40", version: "vecta-ekm-agent/1.0.0", credential: "client_key" } : added[0];
      if (done) added[0] = c as ReturnType<typeof client>;
      return route.fulfill(json({ client: c, check_ins: [], thresholds: THRESHOLDS, server_time: new Date().toISOString() }));
    }
    if (call === "GET /ekm/clients/ekm_1") {
      return route.fulfill(json({
        client: CLIENTS[0], check_ins: CHECK_INS, thresholds: THRESHOLDS, server_time: new Date().toISOString(),
        key: { id: "key_ekm_1", name: "tde-agent-ekm_1", algorithm: "RSA-3072", version: "v1", status: "active" },
        metrics: { hostname: "orcl-prod-01", os_name: "linux", os_version: "", cpu_usage_pct: 31, memory_usage_pct: 62, disk_usage_pct: 93, uptime_sec: 86400 },
        databases: 2, tde_enabled_databases: 1,
      }));
    }
    if (call === "GET /ekm/agents/ekm_1/logs") return route.fulfill(json({ items: [{ id: "log_1", tenant_id: "root", key_id: "key_ekm_1", agent_id: "ekm_1", database_id: "", operation: "unwrap", status: "success", error_message: "", created_at: ago(120) }] }));
    if (req.method() === "GET") return route.fulfill(json({ items: [] }));
    return route.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  return calls;
}

async function open(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/");
  await page.getByText("Enterprise KM", { exact: true }).first().click();
  await page.getByTestId("subnav-ekm").getByRole("button", { name: "EKM for DBs", exact: true }).click();
  await expect(page.getByTestId("ekm-clients")).toBeVisible();
}

const tile = (page: Page, key: string) => page.getByTestId(`ekm-tile-${key}`);
const rows = (page: Page) => page.getByTestId("ekm-client-row");

test("tiles count the clients and filter the table to the ones they count", async ({ page }) => {
  await stub(page);
  await open(page);

  for (const [key, n] of [["registered", "4"], ["pending", "1"], ["healthy", "2"], ["degraded", "1"], ["offline", "1"]] as const) {
    await expect(tile(page, key).locator(".vk-num")).toHaveText(n);
  }
  await expect(tile(page, "healthy")).toContainText("within 5 min");
  await expect(tile(page, "offline")).toContainText("over 60 min");
  // A count is neutral: every number has the same colour, whatever its tile.
  const inks = await page.locator("[data-testid^='ekm-tile-'] .vk-num").evaluateAll((els) => els.map((e) => getComputedStyle(e).color));
  expect(new Set(inks).size).toBe(1);
  await expect(rows(page)).toHaveCount(5);
  await expect(rows(page).filter({ hasText: "MSSQL-FIN-02" })).toContainText("25 min ago");
  await expect(rows(page).filter({ hasText: "ORCL-DR-03" })).toContainText("3 h 3 min ago");
  await expect(rows(page).filter({ hasText: "PG-STAGE-07" })).toContainText("Never");
  if (SHOTS) {
    await page.screenshot({ path: `${SHOTS}/ekm-clients-light.png`, fullPage: true });
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "dark"));
    await page.waitForTimeout(400);
    await page.screenshot({ path: `${SHOTS}/ekm-clients-dark.png`, fullPage: true });
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "light"));
  }

  // Each number is the length of the list it opens.
  for (const [key, names] of [["healthy", ["ORCL-PROD-01", "test-db"]], ["degraded", ["MSSQL-FIN-02"]], ["offline", ["ORCL-DR-03"]], ["pending", ["PG-STAGE-07"]]] as const) {
    await tile(page, key).click();
    await expect(rows(page)).toHaveCount(names.length);
    for (const n of names) await expect(rows(page).filter({ hasText: n })).toHaveCount(1);
    await tile(page, key).click();
    await expect(rows(page)).toHaveCount(5);
  }
  await tile(page, "pending").click();
  await expect(page.getByTestId("ekm-drill")).toContainText("Awaiting registration · 1");
  await page.getByTestId("ekm-drill").click();
  await expect(rows(page)).toHaveCount(5);

  // Nothing here is simulated: no demo clock, no simulated check-in.
  for (const gone of ["Demo clock", "Fast-forward", "Simulate", "Pause agent", "Deploy Agent", "Verify Connection"]) {
    await expect(page.getByText(gone)).toHaveCount(0);
  }
});

test("a failed list reads unavailable, never zero clients", async ({ page }) => {
  await stub(page, { listDown: true });
  await open(page);
  await expect(page.getByText(/Clients unavailable: /)).toBeVisible();
  await expect(page.locator("[data-testid^='ekm-tile-']")).toHaveCount(0);
  await expect(page.getByText("No database clients yet.")).toHaveCount(0);
});

// Every state the layout has: no clients, and a thousand with the longest
// names and hosts the service accepts. Nothing covers a control or spills
// out, on the page or in the drawer.
test("the layout holds with no clients and with a thousand", async ({ page }) => {
  const opts: Opts = { clients: [] };
  await stub(page, opts);
  await open(page);
  await expect(page.getByText("No database clients yet.")).toBeVisible();
  for (const key of ["registered", "pending", "healthy", "degraded", "offline"]) await expect(tile(page, key).locator(".vk-num")).toHaveText("0");
  expect(await coveredControls(page.getByTestId("ekm-clients"))).toEqual([]);

  const health = ["healthy", "degraded", "offline", "pending"];
  const many = Array.from({ length: 1000 }, (_, i) => client(`ekm_${i}`, `${"CLIENT-WITH-THE-LONGEST-ALLOWED-NAME-0000".slice(0, 36)}${String(i).padStart(4, "0")}`, "postgresql", `${"very-long-host-name-".repeat(6)}${i}.dr.corp.example.local`, health[i % 4]!, i % 4 === 3 ? undefined : 4200 * (i % 4) + 7));
  opts.clients = many;
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(tile(page, "registered").locator(".vk-num")).toHaveText("750");
  await expect(tile(page, "pending").locator(".vk-num")).toHaveText("250");
  await expect(rows(page)).toHaveCount(1000);
  // The first screen, then the last rows.
  expect(await coveredControls(page.getByTestId("ekm-clients"))).toEqual([]);
  await rows(page).last().scrollIntoViewIfNeeded();
  await expect(rows(page).last()).toBeInViewport();
  expect(await coveredControls(page.getByTestId("ekm-clients"))).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  // A long name or host is cut with its full text in a tooltip, so every column stays on screen.
  await expect(rows(page).last().getByRole("button")).toBeInViewport();
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/ekm-clients-crowded.png` });
});

test("a row opens the client's health, and every bar shows its check-in", async ({ page }) => {
  const calls = await stub(page);
  await open(page);
  await rows(page).filter({ hasText: "ORCL-PROD-01" }).click();
  const drawer = page.getByTestId("ekm-client-drawer");
  await expect(drawer.getByTestId("ekm-client-health")).toContainText("Healthy");
  await expect(drawer).toContainText("Vecta KMS");
  await expect(drawer).toContainText("Key · tde-agent-ekm_1");
  await expect(drawer).toContainText("10.20.15.32");
  await expect(drawer).toContainText("Client key");
  await expect(drawer).toContainText("up to 5 min");
  await expect(drawer).toContainText("over 60 min");
  // What the prototype asserted without evidence is not claimed.
  await expect(drawer.getByText(/Key requests are being served/)).toHaveCount(0);

  const bars = drawer.getByTestId("ekm-checkin-strip").getByRole("button");
  await expect(bars).toHaveCount(30);
  await expect(drawer.locator("[data-kind='late']")).toHaveCount(1);
  await expect(drawer.locator("[data-kind='missed']")).toHaveCount(1);
  await drawer.locator("[data-kind='missed']").click();
  await expect(drawer.getByTestId("ekm-checkin-entry")).toContainText("7 min after the one before");
  expect(await coveredControls(drawer)).toEqual([]);
  await drawer.getByRole("button", { name: "List", exact: true }).click();
  await expect(drawer.getByTestId("ekm-checkin-list").locator("tbody tr")).toHaveCount(30);
  if (SHOTS) {
    await page.screenshot({ path: `${SHOTS}/ekm-drawer-light.png` });
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "dark"));
    await page.waitForTimeout(400);
    await page.screenshot({ path: `${SHOTS}/ekm-drawer-dark.png` });
    await page.evaluate(() => document.documentElement.setAttribute("data-theme", "light"));
  }

  // The open drawer refreshes itself.
  await expect.poll(() => calls.filter((c) => c === "GET /ekm/clients/ekm_1").length, { timeout: 9000 }).toBeGreaterThan(1);
  await drawer.getByRole("button", { name: "Show recent" }).click();
  await expect(drawer).toContainText("unwrap");
  await drawer.getByRole("button", { name: "Close" }).click();
  await expect(drawer).toHaveCount(0);
});

test("a new client waits for its agent: registered only when the service says so", async ({ page }) => {
  const writes: Write[] = [];
  await stub(page, { enrolAfterPolls: 1 }, writes);
  await open(page);
  await page.getByRole("button", { name: "Add client" }).first().click();

  await page.getByPlaceholder("ORCL-PROD-04").fill("x");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page.getByText("Use 3 to 40 letters, digits, dots, dashes or underscores.")).toBeVisible();
  await page.getByPlaceholder("ORCL-PROD-04").fill("orcl-prod-01");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page.getByText("A client named orcl-prod-01 already exists.")).toBeVisible();
  expect(writes).toHaveLength(0);

  await page.getByPlaceholder("ORCL-PROD-04").fill("ORCL-PROD-04");
  await page.getByPlaceholder("db-host.corp.local").fill("orcl-prod-04.corp.local");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page.getByTestId("ekm-token")).toHaveText("vekm-reg.cm9vdA.ekm_new.fixture-secret");
  await expect(page.getByText("Shown once. Copy it now; a new token replaces this one.")).toBeVisible();
  expect(writes.map((w) => w.call)).toEqual(["POST /ekm/clients", "POST /ekm/clients/ekm_new/registration-token"]);
  expect(writes[0]!.body).toMatchObject({ name: "ORCL-PROD-04", db_engine: "oracle", host: "orcl-prod-04.corp.local", auto_provision_tde: true });
  // Behind the wizard the client is listed as pending, not as connected.
  await expect(rows(page).filter({ hasText: "ORCL-PROD-04" })).toHaveAttribute("data-health", "pending");
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/ekm-wizard-token.png` });

  await page.getByRole("button", { name: "I've copied it" }).click();
  await expect(page.getByTestId("ekm-waiting")).toContainText("Waiting for ORCL-PROD-04 to register");
  // The token is pasted into a file; it is never part of a command.
  await expect(page.getByText(/-token-file \/etc\/vecta-ekm\/registration-token/)).toBeVisible();
  await expect(page.getByText(/fixture-secret/)).toHaveCount(0);
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/ekm-wizard-install.png` });
  await expect(page.getByTestId("ekm-enrolled")).toHaveCount(0);

  await expect(page.getByTestId("ekm-enrolled")).toContainText("ORCL-PROD-04 checked in at", { timeout: 15000 });
  await expect(page.getByTestId("ekm-enrolled")).toContainText("from 10.20.15.40");
  await page.getByRole("button", { name: "Done" }).click();
  await expect(rows(page).filter({ hasText: "ORCL-PROD-04" })).toHaveAttribute("data-health", "healthy");
});
