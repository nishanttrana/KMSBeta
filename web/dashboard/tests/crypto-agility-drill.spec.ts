import { expect, test, type Page, type Request } from "@playwright/test";

// Crypto Agility → Swap drill. The drill payload was produced by keycore's
// measureAlgorithm and compareDrill (RSA-2048 → ML-DSA-65, 5 iterations);
// the measurements themselves are tested in services/keycore.

const SHOTS = process.env.AGILITY_SHOTS_DIR || "";
const drill = {
  "id": "drill_1",
  "tenant_id": "",
  "from": {
    "algorithm": "RSA-2048",
    "operation": "sign_verify",
    "keygen_us": 29448,
    "operation_us": 1237,
    "check_us": 162,
    "private_key_bytes": 1216,
    "public_key_bytes": 294,
    "output_bytes": 256,
    "round_trips": 5
  },
  "to": {
    "algorithm": "ML-DSA-65",
    "operation": "sign_verify",
    "keygen_us": 151,
    "operation_us": 479,
    "check_us": 157,
    "private_key_bytes": 4032,
    "public_key_bytes": 1952,
    "output_bytes": 3309,
    "round_trips": 5
  },
  "iterations": 5,
  "result": "passed",
  "comparison": {
    "keygen_ratio": 0.01,
    "operation_ratio": 0.39,
    "check_ratio": 0.97,
    "output_bytes_diff": 3053,
    "public_key_bytes_diff": 1658
  },
  "run_by": "alice",
  "created_at": "2026-09-29T10:00:00Z"
};

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

async function stub(page: Page, opts: { down?: boolean; refuse?: boolean } = {}): Promise<Request[]> {
  const writes: Request[] = [];
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    if (p.endsWith("/agility/drills") && req.method() === "POST") {
      writes.push(req);
      if (opts.refuse) return route.fulfill(json({ error: { code: "crypto_policy_disallowed", message: "target RSA-3072 is disallowed by migration policy rule \"No new RSA\"" } }, 403));
      return route.fulfill(json({ data: drill }, 201));
    }
    if (p.endsWith("/agility/drills")) {
      if (opts.down) return route.fulfill(json({ error: { message: "service unavailable" } }, 503));
      return route.fulfill(json({ items: writes.length > 0 && !opts.refuse ? [drill] : [] }));
    }
    if (p.endsWith("/agility/posture")) return route.fulfill(json({ data: { assessed: true, as_of: "2026-09-29", total_keys: 3, not_assessed_keys: 0, quantum_vulnerable_keys: 3, post_quantum_keys: 0, weak_keys: 0, uncovered_keys: 0, policy_rules: 1, status_counts: {}, milestones: [], algorithms: [{ algorithm: "RSA-2048", key_count: 3, percentage: 100, assessed: true, canonical: "RSA-2048", quantum_vulnerable: true, post_quantum: false, hybrid: false, weak: false, status: "decrypt_only" }], findings: [] } }));
    if (p.endsWith("/agility/policy/rules")) return route.fulfill(json({ data: [{ id: "r1", name: "RSA to ML-DSA", match_kind: "family", match_value: "RSA", action: "decrypt_only", effective_date: "2027-01-01T00:00:00Z", target_algorithm: "ML-DSA-65", created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z" }] }));
    if (p.endsWith("/agility/migration-plans")) return route.fulfill(json({ data: [] }));
    if (p.endsWith("/auth/tenants")) return route.fulfill(json({ items: [{ id: "root", name: "root", status: "active" }] }));
    return route.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "smoke-user", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"]
    }));
  });
  return writes;
}

async function openDrill(page: Page): Promise<void> {
  await page.goto("/");
  await page.getByText("Crypto Agility", { exact: true }).first().click();
  await page.getByRole("tab", { name: "Swap drill" }).click();
}

test("a drill runs the customer's swap and shows what was measured", async ({ page }) => {
  const writes = await stub(page);
  await openDrill(page);
  await expect(page.getByText("No drills run yet.")).toBeVisible();
  // Suggestions are the tenant's own inventory and rule targets.
  await expect(page.locator("#drill-algorithms option")).toHaveCount(2);
  await page.getByPlaceholder("e.g. RSA-2048").fill("RSA-2048");
  await page.getByPlaceholder("e.g. ML-DSA-65").fill("ML-DSA-65");
  await page.getByRole("button", { name: "Run drill" }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(JSON.parse(writes[0]!.postData() || "{}")).toEqual({ from_algorithm: "RSA-2048", to_algorithm: "ML-DSA-65", iterations: 5 });
  await expect(page.getByText("Drill passed: RSA-2048 → ML-DSA-65.")).toBeVisible();
  await expect(page.getByTestId("drill-latest")).toContainText("output +3053 bytes, public key +1658 bytes");
  const to = page.locator("tr", { hasText: "→ ML-DSA-65" });
  await expect(to.getByText("3309 B")).toBeVisible();
  await expect(to.getByText("1952 B")).toBeVisible();
  await expect(page.locator("tr", { hasText: "RSA-2048" }).first().getByText("passed")).toBeVisible();
  await expect(page.getByText(/NIST|SP 800|IR 8547|draft/)).toHaveCount(0);
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/drill.png`, fullPage: true });
});

test("a refused drill says why and records nothing", async ({ page }) => {
  const writes = await stub(page, { refuse: true });
  await openDrill(page);
  await page.getByPlaceholder("e.g. RSA-2048").fill("RSA-2048");
  await page.getByPlaceholder("e.g. ML-DSA-65").fill("RSA-3072");
  await page.getByRole("button", { name: "Run drill" }).click();
  await expect.poll(() => writes.length).toBe(1);
  await expect(page.getByText(/Refused: .*disallowed by migration policy rule/)).toBeVisible();
  await expect(page.getByText("No drills run yet.")).toBeVisible();
});

test("drill history unavailable says so", async ({ page }) => {
  await stub(page, { down: true });
  await openDrill(page);
  await expect(page.getByText(/Drill history unavailable/)).toBeVisible();
});
