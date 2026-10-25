import { expect, test, type Page } from "@playwright/test";
import { coveredControls } from "./fixtures/layout";

// Operations (13.65.0-beta): Status, Operation metrics and Key inventory are
// sidebar sub-options; every bar lists exactly what it counts. Payloads
// follow the services' JSON: OpsStats (services/audit/ops_stats.go) and
// KeyStats (services/keycore/inventory_stats.go). Counts are crowded on
// purpose (4,200 operations), as a real tenant's are.
const json = (body: unknown) => ({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
const hour = 3600_000;
const now = Date.now();
const iso = (ms: number) => new Date(ms).toISOString();
const FROM = iso(Math.floor((now - 24 * hour) / hour) * hour);

const group = (key: string, ops: number, errors: number, avg: number) => ({ key, ops, errors, avg_latency_ms: avg, p50_ms: 0.25, p90_ms: 1, p99_ms: 5 });
const OPS = {
  from: FROM, to: iso(now), bucket_seconds: 3600, scope: "standalone", recorded_since: FROM,
  total: group("", 4200, 30, 0.42), total_values: 9800,
  series: Array.from({ length: 25 }, (_, i) => ({ start: iso(Date.parse(FROM) + i * hour), ops: i === 20 ? 4200 : 0, errors: i === 20 ? 30 : 0, avg_latency_ms: i === 20 ? 0.42 : 0 })),
  by_op: [group("encrypt", 4000, 30, 0.3), group("sign", 200, 0, 2.7)],
  by_service: [group("keycore", 4200, 30, 0.42)],
  by_node: [group("", 4200, 30, 0.42)],
};
const KEYS = {
  from: iso(now - 7 * 24 * hour), to: iso(now), bucket_seconds: 21600, total: 4, created: 2,
  by_state: [{ key: "active", count: 3 }, { key: "disabled", count: 1 }],
  by_algorithm: [{ key: "AES-256", count: 3 }, { key: "RSA-3072", count: 1 }],
  series: Array.from({ length: 29 }, (_, i) => ({ start: iso(now - (28 - i) * 6 * hour), count: i === 27 ? 2 : 0 })),
};
const key = (id: string, alg: string) => ({ id, tenant_id: "root", name: `key-${id}`, algorithm: alg, key_type: "symmetric", purpose: "encrypt", status: "active", current_version: 1, kcv: "", iv_mode: "", created_at: iso(now - hour) });
const event = (i: number, op: string, result: string) => ({
  id: `evt_${op}_${i}`, tenant_id: "root", sequence: i, chain_hash: "", previous_hash: "", timestamp: iso(now - hour), service: "keycore",
  action: `audit.key.${op}`, actor_id: "app-1", actor_type: "service", target_type: "key", target_id: "k1", method: "", endpoint: "", source_ip: "",
  user_agent: "", request_hash: "", correlation_id: "", parent_event_id: "", session_id: "", result, status_code: 0, error_message: "",
  duration_ms: 0.3, fips_compliant: true, approval_id: "", risk_score: 0, tags: [], node_id: "", details: { metered_op: op }, created_at: iso(now - hour),
});

type Seen = { events: URLSearchParams[]; keys: URLSearchParams[] };
async function stub(page: Page, opts: { failOps?: boolean } = {}): Promise<Seen> {
  const seen: Seen = { events: [], keys: [] };
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const u = new URL(r.request().url());
    const p = u.pathname;
    if (p.endsWith("/ops-metrics/stats")) {
      return opts.failOps ? r.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: { message: "audit unavailable" } }) }) : r.fulfill(json({ stats: OPS }));
    }
    if (p.endsWith("/audit/events")) {
      seen.events.push(u.searchParams);
      const op = u.searchParams.get("metered_op") ?? "";
      const n = op === "encrypt" && u.searchParams.get("outcome") === "error" ? 30 : 0;
      return r.fulfill(json({ items: Array.from({ length: n }, (_, i) => event(i, "encrypt", "refused")) }));
    }
    if (p.endsWith("/inventory/stats")) return r.fulfill(json({ stats: KEYS }));
    if (p.endsWith("/inventory/stats/keys")) {
      seen.keys.push(u.searchParams);
      const alg = u.searchParams.get("algorithm");
      return r.fulfill(json({ items: alg === "AES-256" ? ["k1", "k2", "k3"].map((id) => key(id, alg)) : [], has_more: false }));
    }
    if (p.endsWith("/ops-metrics/overview")) return r.fulfill(json({ overview: { window: "24h", total_ops: 4200, total_values: 9800, total_errors: 30, error_rate: 0.007, avg_latency_ms: 0.42, scope: "standalone", by_node: [], recorded_since: FROM } }));
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "admin-1", token: "t", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  return seen;
}


test("operation metrics: each bar lists exactly the operations it counts", async ({ page }) => {
  const seen = await stub(page);
  await page.goto("/#ops/metrics");
  await expect(page.getByTestId("subnav-ops").getByRole("button")).toHaveText(["Status", "Operation metrics", "Key inventory"]);
  await expect(page.getByRole("button", { name: "Operations Breakdown" })).toHaveCount(0); // no tab strip in the page
  const tiles = page.locator(".vecta-stat-card");
  await expect(tiles).toHaveText([/^Operations.*4,200.*9,800 values/, /^Refused or failed.*30.*0\.7%/, /^Average latency.*0\.420 ms/, /^p99 latency.*≤ 5 ms/]);
  await expect(page.getByText("Single node", { exact: true })).toBeVisible();

  // The red segment of encrypt's bar: its refused and failed operations.
  const byOp = page.getByTestId("bars-by-operation");
  await byOp.locator(".recharts-bar-rectangle").last().locator("path").dispatchEvent("click");
  await expect(page.getByText("Refused or failed: encrypt: 30 entries")).toBeVisible();
  const q = seen.events[seen.events.length - 1]!;
  expect(Object.fromEntries(["metered_op", "outcome", "from"].map((k) => [k, q.get(k)]))).toEqual({ metered_op: "encrypt", outcome: "error", from: FROM });
  await expect(page.locator("tbody tr").filter({ hasText: "app-1" })).toHaveCount(30);

  // A row opens its audit event.
  await page.locator("tbody tr").filter({ hasText: "app-1" }).first().click();
  await expect(page.getByText("Audit Event", { exact: true })).toBeVisible();
  await page.getByRole("dialog").getByRole("button", { name: "Close" }).click();

  // The latency table's rows drill too.
  await page.locator("tbody tr").filter({ hasText: "sign" }).first().click();
  await expect(page.getByText("Operations: sign: 200 entries")).toBeVisible();
  expect(seen.events[seen.events.length - 1]!.get("outcome")).toBeNull();
  expect(await coveredControls(page.locator("main"))).toEqual([]);
});

test("operation metrics say unavailable when the audit service fails", async ({ page }) => {
  await stub(page, { failOps: true });
  await page.goto("/#ops/metrics");
  await expect(page.getByText(/^Operation metrics unavailable: /)).toBeVisible();
  await expect(page.locator(".vecta-stat-card")).toHaveCount(0);
});

test("key inventory: each bar lists its keys and a key opens in Key Management", async ({ page }) => {
  const seen = await stub(page);
  await page.goto("/#ops/inventory");
  await expect(page.locator(".vecta-stat-card")).toHaveText([/^Keys.*4/, /^Active.*3.*75% of keys/, /^Created.*2.*last week/, /^Algorithms.*2/]);
  await page.getByTestId("bars-by-algorithm").locator(".recharts-bar-rectangle").first().locator("path").dispatchEvent("click");
  await expect(page.getByText("Algorithm: AES-256: 3 entries")).toBeVisible();
  expect(seen.keys[seen.keys.length - 1]!.get("algorithm")).toBe("AES-256");
  await page.locator("tbody tr").filter({ hasText: "key-k2" }).click();
  await expect(page).toHaveURL(/#keys/);
});

test("status tiles open the view that owns their number", async ({ page }) => {
  await stub(page);
  await page.goto("/#ops/status");
  await expect(page.getByText("FIPS mode", { exact: true })).toBeVisible();
  await expect(page.getByText("No nodes reported.").or(page.getByText(/^Cluster status unavailable/))).toBeVisible();
  await page.locator(".vecta-stat-card", { hasText: /^Operations · 24h/ }).click();
  await expect(page).toHaveURL(/#ops\/metrics$/);
  await page.goto("/#ops/status");
  await page.locator(".vecta-stat-card", { hasText: /^Keys/ }).click();
  await expect(page).toHaveURL(/#ops\/inventory$/);
});
