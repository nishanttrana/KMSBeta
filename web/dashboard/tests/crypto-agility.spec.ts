import { expect, test, type Page, type Request } from "@playwright/test";

// The Crypto Agility tab measures live keys against the customer's own
// migration policy. The API is stubbed with a posture and rules computed by
// keycore's computeAgilityPosture (3 RSA-2048, 5 AES-256, 2 ML-DSA-65, 1 3DES,
// 2 ECDSA-P256 and 1 "RSA" key on 2026-09-29, with a "weak disallowed" rule
// in force and an "RSA decrypt/verify only from 2027-06-30" rule); the
// figures and enforcement are tested in services/keycore.

const SHOTS = process.env.AGILITY_SHOTS_DIR || "";

const posture = {
  "assessed": true,
  "as_of": "2026-09-29",
  "total_keys": 14,
  "not_assessed_keys": 1,
  "quantum_vulnerable_keys": 5,
  "post_quantum_keys": 2,
  "weak_keys": 1,
  "uncovered_keys": 2,
  "policy_rules": 2,
  "min_algorithm_tier": "classical-128",
  "status_counts": {
    "allowed": 13,
    "disallowed": 1
  },
  "milestones": [
    {
      "date": "2027-06-30",
      "action": "decrypt_only",
      "rule_id": "agrule_rsa",
      "rule_name": "RSA to ML-DSA",
      "target_algorithm": "ML-DSA-65",
      "key_count": 3,
      "algorithms": [
        "RSA-2048"
      ]
    }
  ],
  "algorithms": [
    {
      "algorithm": "RSA-2048",
      "key_count": 3,
      "percentage": 21.428571428571427,
      "assessed": true,
      "canonical": "RSA-2048",
      "family": "RSA",
      "security_bits": 112,
      "quantum_vulnerable": true,
      "post_quantum": false,
      "weak": false,
      "policy_status": "allowed",
      "target_algorithm": "ML-DSA-65",
      "next_change": {
        "date": "2027-06-30",
        "action": "decrypt_only",
        "rule_id": "agrule_rsa",
        "rule_name": "RSA to ML-DSA",
        "target_algorithm": "ML-DSA-65"
      }
    },
    {
      "algorithm": "AES-256",
      "key_count": 5,
      "percentage": 35.714285714285715,
      "assessed": true,
      "canonical": "AES-256",
      "family": "AES",
      "security_bits": 256,
      "pqc_category": 5,
      "quantum_vulnerable": false,
      "post_quantum": false,
      "weak": false,
      "policy_status": "allowed"
    },
    {
      "algorithm": "ML-DSA-65",
      "key_count": 2,
      "percentage": 14.285714285714285,
      "assessed": true,
      "canonical": "ML-DSA-65",
      "family": "ML-DSA",
      "security_bits": 192,
      "pqc_category": 3,
      "quantum_vulnerable": false,
      "post_quantum": true,
      "weak": false,
      "policy_status": "allowed"
    },
    {
      "algorithm": "3DES",
      "key_count": 1,
      "percentage": 7.142857142857142,
      "assessed": true,
      "canonical": "3TDEA",
      "family": "TDEA",
      "security_bits": 112,
      "quantum_vulnerable": false,
      "post_quantum": false,
      "weak": true,
      "note": "64-bit block: collision attacks after a few GB under one key",
      "policy_status": "disallowed",
      "policy_rule": "Weak algorithms out"
    },
    {
      "algorithm": "ECDSA-P256",
      "key_count": 2,
      "percentage": 14.285714285714285,
      "assessed": true,
      "canonical": "ECDSA-P256",
      "family": "ECDSA",
      "security_bits": 128,
      "quantum_vulnerable": true,
      "post_quantum": false,
      "weak": false,
      "note": "strength is half the bit length of the curve order",
      "policy_status": "allowed"
    },
    {
      "algorithm": "RSA",
      "key_count": 1,
      "percentage": 7.142857142857142,
      "assessed": false,
      "quantum_vulnerable": false,
      "post_quantum": false,
      "weak": false,
      "policy_status": "allowed"
    }
  ],
  "findings": [
    "Your policy disallows 1 live key (every operation refused): 3DES. Migrate or destroy them.",
    "No rule covers 2 live keys on quantum-vulnerable algorithms: ECDSA-P256. Decide when to move them to ML-KEM or ML-DSA and add a rule.",
    "Not assessed (the algorithm name states no parameter set): 1 live key on RSA."
  ]
};
const rules = [
  {
    "id": "agrule_weak",
    "tenant_id": "",
    "name": "Weak algorithms out",
    "match_kind": "weak",
    "action": "disallowed",
    "effective_date": "2026-01-01T00:00:00Z",
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z"
  },
  {
    "id": "agrule_rsa",
    "tenant_id": "",
    "name": "RSA to ML-DSA",
    "match_kind": "family",
    "match_value": "RSA",
    "action": "decrypt_only",
    "effective_date": "2027-06-30T00:00:00Z",
    "target_algorithm": "ML-DSA-65",
    "note": "security board 2026-09",
    "created_at": "2026-09-01T00:00:00Z",
    "updated_at": "2026-09-01T00:00:00Z"
  }
];

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

async function stub(page: Page, postureStatus = 200): Promise<Request[]> {
  const writes: Request[] = [];
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    if (p.endsWith("/agility/posture")) {
      return route.fulfill(postureStatus === 200 ? json({ data: posture }) : json({ error: { message: "keycore unavailable" } }, postureStatus));
    }
    if (p.endsWith("/agility/policy/rules")) {
      if (req.method() === "POST") {
        writes.push(req);
        return route.fulfill(json({ data: { ...JSON.parse(req.postData() || "{}"), id: "agrule_new", created_at: "2026-09-29T00:00:00Z", updated_at: "2026-09-29T00:00:00Z" } }, 201));
      }
      return route.fulfill(json({ data: rules }));
    }
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

async function openTab(page: Page): Promise<void> {
  await page.goto("/");
  await page.getByText("Crypto Agility", { exact: true }).first().click();
}

test("the tab shows the customer's policy, schedule and inventory, and quotes no standards", async ({ page }) => {
  await stub(page);
  await openTab(page);
  await expect(page.getByText("Your migration policy", { exact: true })).toBeVisible();

  // Rules: the customer's own names, dates and targets.
  const rsaRule = page.locator("tr", { hasText: "RSA to ML-DSA" }).first();
  await expect(rsaRule.getByText("RSA family")).toBeVisible();
  await expect(rsaRule.getByText("Decrypt/verify only")).toBeVisible();
  await expect(rsaRule.getByText("2027-06-30")).toBeVisible();
  await expect(page.locator("tr", { hasText: "Weak algorithms out" }).getByText("in force")).toBeVisible();
  await expect(page.getByText("classical-128", { exact: true })).toBeVisible();

  // Schedule and inventory follow the rules.
  await expect(page.getByText("Your migration schedule")).toBeVisible();
  const des = page.locator("tr", { hasText: "3DES" }).last();
  await expect(des.getByText("Disallowed", { exact: true })).toBeVisible();
  await expect(des.getByText("WEAK", { exact: true })).toBeVisible();
  await expect(des.getByText("Weak algorithms out")).toBeVisible();
  const rsa = page.locator("tr", { hasText: "RSA-2048" }).last();
  await expect(rsa.getByText("112-bit")).toBeVisible();
  await expect(rsa.getByText("from 2027-06-30")).toBeVisible();
  await expect(page.getByText(/No rule covers 2 live keys on quantum-vulnerable algorithms: ECDSA-P256/)).toBeVisible();

  // No standards documents, drafts or references anywhere on the tab.
  await expect(page.getByText(/NIST|SP 800|IR 8547|initial public draft|proposed/)).toHaveCount(0);
  if (SHOTS) {
    await page.screenshot({ path: `${SHOTS}/agility-top.png` });
    await page.getByText("Your migration schedule", { exact: true }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${SHOTS}/agility-schedule.png` });
    await page.getByText("Algorithm inventory", { exact: true }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${SHOTS}/agility-inventory.png` });
  }
});

test("adding a rule previews the keys it covers and sends the customer's choices", async ({ page }) => {
  const writes = await stub(page);
  await openTab(page);
  await page.getByRole("button", { name: "Add Migration Rule" }).click();
  await page.getByPlaceholder("e.g. RSA to ML-DSA").fill("ECDSA to ML-DSA");
  await page.locator("select").filter({ hasText: "Specific algorithm" }).selectOption("family");
  await page.getByPlaceholder("e.g. RSA", { exact: true }).fill("ECDSA");
  await expect(page.getByText("Covers 2 live keys today (ECDSA-P256).")).toBeVisible();
  await page.locator("input[type=date]").first().fill("2028-01-01");
  await page.getByPlaceholder("e.g. ML-DSA-65").fill("ML-DSA-65");
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/agility-rule-modal.png` });
  await page.getByRole("button", { name: "Add rule" }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(JSON.parse(writes[0]!.postData() || "{}")).toEqual({
    name: "ECDSA to ML-DSA", match_kind: "family", match_value: "ECDSA", action: "decrypt_only",
    effective_date: "2028-01-01", target_algorithm: "ML-DSA-65",
  });
});

test("an unreachable keycore says not assessed and shows no figures", async ({ page }) => {
  await stub(page, 503);
  await openTab(page);
  await expect(page.getByText("Not assessed: crypto agility data is unavailable")).toBeVisible();
  await expect(page.getByText("keycore unavailable")).toBeVisible();
  await expect(page.getByText("Your migration schedule")).toHaveCount(0);
});
