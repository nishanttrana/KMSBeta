import { expect, test, type Page, type Request } from "@playwright/test";

// Crypto Agility → Risk assessment (CARAF) and Readiness & execution (the
// former Post-Quantum tab). The APIs are stubbed with payloads computed by
// keycore's computeCarafAssessment and the pqc service's scan and plan code;
// the figures are tested there.

const SHOTS = process.env.AGILITY_SHOTS_DIR || "";
const assessment = {
  "as_of": "2026-09-29",
  "summary": {
    "assets": 4,
    "threats": 2,
    "exposed": 2,
    "at_limit": 0,
    "time_to_spare": 1,
    "not_assessed": 1,
    "no_threat": 0,
    "undecided_at_risk": 1,
    "overdue": 1,
    "acceptance_expired": 0
  },
  "assets": [
    {
      "asset": {
        "id": "casset_fleet",
        "tenant_id": "",
        "name": "Smart meter fleet",
        "owner": "grid-ops",
        "ownership": "third_party",
        "implementation": "embedded",
        "pqc_support": "none",
        "location": "edge",
        "sensitivity": "high",
        "shelf_life_years": 12,
        "migration_years": 5,
        "cost": "low",
        "algorithms": [
          "ECDSA-P256"
        ],
        "key_ids": [],
        "decision": {},
        "created_at": "0001-01-01T00:00:00Z",
        "updated_at": "0001-01-01T00:00:00Z"
      },
      "algorithms": [
        "ECDSA-P256"
      ],
      "missing_keys": [],
      "threats": [
        {
          "id": "cthreat_q",
          "name": "Quantum computer breaks RSA and ECC",
          "years_to_threat": 10,
          "algorithms": [
            "ECDSA-P256"
          ]
        }
      ],
      "x": 12,
      "y": 5,
      "z": 10,
      "timeline": "exposed",
      "margin_years": -7,
      "missing": [],
      "suggestion": "secure",
      "decision_state": "undecided"
    },
    {
      "asset": {
        "id": "casset_pay",
        "tenant_id": "",
        "name": "Payments API",
        "owner": "payments",
        "ownership": "enterprise",
        "implementation": "software",
        "pqc_support": "supported",
        "location": "cloud",
        "sensitivity": "critical",
        "shelf_life_years": 3,
        "migration_years": 2,
        "cost": "high",
        "algorithms": [
          "RSA-2048"
        ],
        "key_ids": [],
        "decision": {
          "decision": "accept",
          "owner": "cfo",
          "review_by": "2027-06-30T00:00:00Z"
        },
        "created_at": "0001-01-01T00:00:00Z",
        "updated_at": "0001-01-01T00:00:00Z"
      },
      "algorithms": [
        "RSA-2048"
      ],
      "missing_keys": [],
      "threats": [
        {
          "id": "cthreat_q",
          "name": "Quantum computer breaks RSA and ECC",
          "years_to_threat": 10,
          "algorithms": [
            "RSA-2048"
          ]
        }
      ],
      "x": 3,
      "y": 2,
      "z": 10,
      "timeline": "time_to_spare",
      "margin_years": 5,
      "missing": [],
      "suggestion": "accept",
      "decision_state": "accepted"
    },
    {
      "asset": {
        "id": "casset_legacy",
        "tenant_id": "",
        "name": "Legacy batch job",
        "owner": "ops",
        "ownership": "enterprise",
        "implementation": "software",
        "pqc_support": "unknown",
        "location": "on_prem",
        "sensitivity": "medium",
        "shelf_life_years": 1,
        "migration_years": 1,
        "cost": "high",
        "algorithms": [
          "3DES"
        ],
        "key_ids": [],
        "decision": {
          "decision": "phase_out",
          "owner": "ops",
          "due": "2026-03-31T00:00:00Z",
          "status": "open"
        },
        "created_at": "0001-01-01T00:00:00Z",
        "updated_at": "0001-01-01T00:00:00Z"
      },
      "algorithms": [
        "3DES"
      ],
      "missing_keys": [],
      "threats": [
        {
          "id": "cthreat_w",
          "name": "Weak algorithms",
          "years_to_threat": 0,
          "algorithms": [
            "3DES"
          ]
        }
      ],
      "x": 1,
      "y": 1,
      "z": 0,
      "timeline": "exposed",
      "margin_years": -2,
      "missing": [],
      "suggestion": "phase_out",
      "decision_state": "overdue"
    },
    {
      "asset": {
        "id": "casset_web",
        "tenant_id": "",
        "name": "Customer portal",
        "ownership": "enterprise",
        "implementation": "unknown",
        "pqc_support": "unknown",
        "location": "unknown",
        "sensitivity": "unknown",
        "cost": "medium",
        "algorithms": [
          "RSA-3072"
        ],
        "key_ids": [],
        "decision": {},
        "created_at": "0001-01-01T00:00:00Z",
        "updated_at": "0001-01-01T00:00:00Z"
      },
      "algorithms": [
        "RSA-3072"
      ],
      "missing_keys": [],
      "threats": [
        {
          "id": "cthreat_q",
          "name": "Quantum computer breaks RSA and ECC",
          "years_to_threat": 10,
          "algorithms": [
            "RSA-3072"
          ]
        }
      ],
      "z": 10,
      "timeline": "not_assessed",
      "missing": [
        "shelf_life_years",
        "migration_years"
      ],
      "decision_state": "undecided"
    }
  ],
  "roadmap": [
    {
      "asset_id": "casset_legacy",
      "asset": "Legacy batch job",
      "decision": "phase_out",
      "owner": "ops",
      "date": "2026-03-31",
      "state": "overdue"
    },
    {
      "asset_id": "casset_pay",
      "asset": "Payments API",
      "decision": "accept",
      "owner": "cfo",
      "date": "2027-06-30",
      "state": "accepted"
    }
  ],
  "findings": [
    "Exposed with no decision (1): Smart meter fleet. Record how each will be secured, accepted or phased out.",
    "Decisions past their due date (1): Legacy batch job.",
    "Not assessed until shelf life and migration time are recorded (1): Customer portal."
  ]
};
const threats = [
  {
    "id": "cthreat_q",
    "tenant_id": "",
    "name": "Quantum computer breaks RSA and ECC",
    "category": "quantum",
    "match_kind": "quantum_vulnerable",
    "years_to_threat": 10,
    "note": "security board estimate",
    "created_at": "0001-01-01T00:00:00Z",
    "updated_at": "0001-01-01T00:00:00Z"
  },
  {
    "id": "cthreat_w",
    "tenant_id": "",
    "name": "Weak algorithms",
    "category": "cryptanalytic",
    "match_kind": "weak",
    "years_to_threat": 0,
    "created_at": "0001-01-01T00:00:00Z",
    "updated_at": "0001-01-01T00:00:00Z"
  }
];
const readiness = {
  "id": "scan_128a4196c8d6ef91",
  "tenant_id": "root",
  "status": "completed",
  "total_assets": 9,
  "pqc_ready_assets": 3,
  "hybrid_assets": 0,
  "classical_assets": 6,
  "average_qsl": 47.56,
  "readiness_score": 32,
  "algorithm_summary": {
    "ECDSA-P384 + ML-DSA-65": 1,
    "ML-DSA-65": 3,
    "ML-KEM-768-HYBRID": 1,
    "RSA-2048": 2,
    "RSA-3072": 2
  },
  "timeline_status": {},
  "risk_items": [
    {
      "asset_id": "c1",
      "asset_type": "certificate",
      "name": "api.vecta.local",
      "source": "certs",
      "algorithm": "RSA-3072",
      "classification": "vulnerable",
      "qsl_score": 0,
      "migration_target": "ML-DSA-65",
      "priority": 85,
      "reason": "classification=vulnerable, qsl=0"
    },
    {
      "asset_id": "k1",
      "asset_type": "key",
      "name": "legacy-rsa",
      "source": "keycore",
      "algorithm": "RSA-2048",
      "classification": "vulnerable",
      "qsl_score": 0,
      "migration_target": "ML-DSA-65",
      "priority": 85,
      "reason": "classification=vulnerable, qsl=0"
    },
    {
      "asset_id": "a1",
      "asset_type": "tls_endpoint",
      "name": "api.vecta.local",
      "source": "network",
      "algorithm": "RSA-2048",
      "classification": "weak",
      "qsl_score": 50,
      "migration_target": "X25519MLKEM768",
      "priority": 62,
      "reason": "classification=weak, qsl=50"
    },
    {
      "asset_id": "c2",
      "asset_type": "certificate",
      "name": "hybrid.vecta.local",
      "source": "certs",
      "algorithm": "ECDSA-P384 + ML-DSA-65",
      "classification": "unknown",
      "qsl_score": 0,
      "migration_target": "",
      "priority": 60,
      "reason": "classification=unknown, qsl=0"
    },
    {
      "asset_id": "k2",
      "asset_type": "key",
      "name": "hybrid-kem",
      "source": "keycore",
      "algorithm": "ML-KEM-768-HYBRID",
      "classification": "unknown",
      "qsl_score": 0,
      "migration_target": "",
      "priority": 60,
      "reason": "classification=unknown, qsl=0"
    },
    {
      "asset_id": "a3",
      "asset_type": "kms_key",
      "name": "aws/kms/key1",
      "source": "cloud",
      "algorithm": "RSA-3072",
      "classification": "weak",
      "qsl_score": 78,
      "migration_target": "ML-DSA-65",
      "priority": 52,
      "reason": "classification=weak, qsl=78"
    }
  ],
  "metadata": {
    "trigger": "manual"
  },
  "created_at": "2026-09-29T00:30:29Z",
  "completed_at": "2026-09-29T00:30:29.418948Z"
};
const plans = [
  {
    "id": "plan_4fa937ecec85b9f8",
    "tenant_id": "root",
    "name": "Signing keys to ML-DSA",
    "status": "planned",
    "target_profile": "hybrid-first",
    "timeline_standard": "board policy 2026",
    "deadline": "2027-12-31T00:00:00Z",
    "summary": {
      "classical_replacement": 2,
      "classical_to_hybrid": 1,
      "classical_to_pqc": 3,
      "estimated_risk_reduced": 67,
      "hybrid_to_pqc": 0,
      "pqc_hardening": 0,
      "readiness_score": 32,
      "total_steps": 6
    },
    "steps": [
      {
        "id": "step_33219f1e13b47651",
        "asset_id": "c1",
        "asset_type": "certificate",
        "name": "api.vecta.local",
        "current_algorithm": "RSA-3072",
        "target_algorithm": "ML-DSA-65",
        "phase": "classical_to_pqc",
        "priority": 85,
        "status": "pending",
        "reason": "classification=vulnerable, qsl=0",
        "metadata": {
          "classification": "vulnerable",
          "qsl_score": 0,
          "source": "certs"
        },
        "executed_at": "0001-01-01T00:00:00Z",
        "rolled_back_at": "0001-01-01T00:00:00Z"
      },
      {
        "id": "step_d67d2805d0c79ac6",
        "asset_id": "k1",
        "asset_type": "key",
        "name": "legacy-rsa",
        "current_algorithm": "RSA-2048",
        "target_algorithm": "ML-DSA-65",
        "phase": "classical_to_pqc",
        "priority": 85,
        "status": "pending",
        "reason": "classification=vulnerable, qsl=0",
        "metadata": {
          "classification": "vulnerable",
          "qsl_score": 0,
          "source": "keycore"
        },
        "executed_at": "0001-01-01T00:00:00Z",
        "rolled_back_at": "0001-01-01T00:00:00Z"
      },
      {
        "id": "step_a5149b24ba1707d8",
        "asset_id": "a1",
        "asset_type": "tls_endpoint",
        "name": "api.vecta.local",
        "current_algorithm": "RSA-2048",
        "target_algorithm": "X25519MLKEM768",
        "phase": "classical_to_hybrid",
        "priority": 62,
        "status": "pending",
        "reason": "classification=weak, qsl=50",
        "metadata": {
          "classification": "weak",
          "qsl_score": 50,
          "source": "network"
        },
        "executed_at": "0001-01-01T00:00:00Z",
        "rolled_back_at": "0001-01-01T00:00:00Z"
      },
      {
        "id": "step_0409792e474409e3",
        "asset_id": "c2",
        "asset_type": "certificate",
        "name": "hybrid.vecta.local",
        "current_algorithm": "ECDSA-P384 + ML-DSA-65",
        "target_algorithm": "",
        "phase": "classical_replacement",
        "priority": 60,
        "status": "pending",
        "reason": "classification=unknown, qsl=0",
        "metadata": {
          "classification": "unknown",
          "qsl_score": 0,
          "source": "certs"
        },
        "executed_at": "0001-01-01T00:00:00Z",
        "rolled_back_at": "0001-01-01T00:00:00Z"
      },
      {
        "id": "step_77e38e09aefe3f4d",
        "asset_id": "k2",
        "asset_type": "key",
        "name": "hybrid-kem",
        "current_algorithm": "ML-KEM-768-HYBRID",
        "target_algorithm": "",
        "phase": "classical_replacement",
        "priority": 60,
        "status": "pending",
        "reason": "classification=unknown, qsl=0",
        "metadata": {
          "classification": "unknown",
          "qsl_score": 0,
          "source": "keycore"
        },
        "executed_at": "0001-01-01T00:00:00Z",
        "rolled_back_at": "0001-01-01T00:00:00Z"
      },
      {
        "id": "step_16805df2cf56ce5a",
        "asset_id": "a3",
        "asset_type": "kms_key",
        "name": "aws/kms/key1",
        "current_algorithm": "RSA-3072",
        "target_algorithm": "ML-DSA-65",
        "phase": "classical_to_pqc",
        "priority": 52,
        "status": "pending",
        "reason": "classification=weak, qsl=78",
        "metadata": {
          "classification": "weak",
          "qsl_score": 78,
          "source": "cloud"
        },
        "executed_at": "0001-01-01T00:00:00Z",
        "rolled_back_at": "0001-01-01T00:00:00Z"
      }
    ],
    "created_by": "u-root",
    "created_at": "2026-09-29T00:30:29Z",
    "updated_at": "2026-09-29T00:30:29Z",
    "executed_at": "0001-01-01T00:00:00Z"
  }
];

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

async function stub(page: Page, down = false): Promise<Request[]> {
  const writes: Request[] = [];
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    if (req.method() !== "GET") {
      writes.push(req);
      if (p.includes("/execute")) return route.fulfill(json({ run: { id: "run_1", plan_id: "x", status: "dry_run_completed", dry_run: true, summary: {} } }));
      return route.fulfill(json({ data: {} }));
    }
    if (down && (p.includes("/agility/caraf") || p.includes("/pqc/"))) return route.fulfill(json({ error: { message: "service unavailable" } }, 503));
    if (p.endsWith("/agility/caraf/assessment")) return route.fulfill(json({ data: assessment }));
    if (p.endsWith("/agility/caraf/threats")) return route.fulfill(json({ data: threats }));
    if (p.endsWith("/pqc/readiness")) return route.fulfill(json({ readiness }));
    if (p.endsWith("/pqc/migration/plans")) return route.fulfill(json({ items: plans }));
    if (p.endsWith("/agility/posture")) return route.fulfill(json({ data: { assessed: false, as_of: "2026-09-29", total_keys: 0, not_assessed_keys: 0, quantum_vulnerable_keys: 0, post_quantum_keys: 0, weak_keys: 0, uncovered_keys: 0, policy_rules: 0, status_counts: {}, milestones: [], algorithms: [], findings: [] } }));
    if (p.endsWith("/agility/policy/rules") || p.endsWith("/agility/migration-plans")) return route.fulfill(json({ data: [] }));
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

async function openView(page: Page, view: string): Promise<void> {
  await page.goto("/");
  await page.getByText("Crypto Agility", { exact: true }).first().click();
  await page.getByRole("tab", { name: view }).click();
}

test("risk assessment shows exposure from the customer's own numbers and records decisions", async ({ page }) => {
  const writes = await stub(page);
  await openView(page, "Risk assessment");
  const fleet = page.locator("tr", { hasText: "Smart meter fleet" }).first();
  await expect(fleet.getByText("Exposed", { exact: true })).toBeVisible();
  await expect(fleet.getByText("short by 7 years")).toBeVisible(); // 10 - (12 + 5)
  await expect(fleet.getByText("Secure", { exact: true })).toBeVisible();
  await expect(fleet.getByText("Undecided")).toBeVisible();
  await expect(page.locator("tr", { hasText: "Payments API" }).first().getByText("5 years to spare")).toBeVisible();
  await expect(page.locator("tr", { hasText: "Customer portal" }).first().getByText(/missing shelf life years, migration years/)).toBeVisible();
  await expect(page.getByText(/Exposed with no decision \(1\): Smart meter fleet/)).toBeVisible();
  await expect(page.locator("tr", { hasText: "Legacy batch job" }).last().getByText("Overdue")).toBeVisible();
  await expect(page.getByText(/NIST|SP 800|IR 8547|draft/)).toHaveCount(0);
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/caraf.png`, fullPage: true });

  await fleet.getByRole("button", { name: "Decide" }).click();
  await page.locator("select").filter({ hasText: "Accept risk" }).selectOption("accept");
  await page.locator("input[type=date]").first().fill("2027-09-30");
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/caraf-decision.png` });
  await page.getByRole("button", { name: "Record decision" }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(new URL(writes[0]!.url()).pathname).toMatch(/\/agility\/caraf\/assets\/casset_fleet\/decision$/);
  expect(JSON.parse(writes[0]!.postData() || "{}")).toEqual({ decision: "accept", owner: "grid-ops", status: "open", review_by: "2027-09-30" });
});

test("adding a threat sends the years the customer expects", async ({ page }) => {
  const writes = await stub(page);
  await openView(page, "Risk assessment");
  await page.getByRole("button", { name: "Add threat" }).click();
  await page.getByPlaceholder("e.g. Quantum computer able to break RSA and ECC").fill("Regulator bans RSA-2048");
  await page.locator("select").filter({ hasText: "cryptanalytic" }).selectOption("regulatory");
  await page.locator("select").filter({ hasText: "Every quantum-vulnerable algorithm" }).selectOption("algorithm");
  await page.getByPlaceholder("RSA-2048").fill("RSA-2048");
  await page.getByPlaceholder("e.g. 10").fill("3");
  await page.getByRole("button", { name: "Add threat" }).last().click();
  await expect.poll(() => writes.length).toBe(1);
  expect(JSON.parse(writes[0]!.postData() || "{}")).toEqual({ name: "Regulator bans RSA-2048", category: "regulatory", match_kind: "algorithm", match_value: "RSA-2048", years_to_threat: 3 });
});

test("readiness and execution shows measured assets and runs plans", async ({ page }) => {
  const writes = await stub(page);
  await openView(page, "Readiness & execution");
  await expect(page.getByText("Assets scanned")).toBeVisible();
  await expect(page.locator("tr", { hasText: "legacy-rsa" }).first().getByText("ML-DSA-65")).toBeVisible();
  await expect(page.getByText("Signing keys to ML-DSA")).toBeVisible();
  await expect(page.getByText(/readiness score|Quantum Readiness|\/100/i)).toHaveCount(0);
  await page.getByRole("button", { name: "Show steps of Signing keys to ML-DSA" }).click();
  await expect(page.getByText("X25519MLKEM768").first()).toBeVisible();
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/execution.png`, fullPage: true });
  await page.getByRole("button", { name: "Dry run" }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(JSON.parse(writes[0]!.postData() || "{}")).toMatchObject({ dry_run: true });
  await expect(page.getByText("Dry run of Signing keys to ML-DSA: nothing changed.")).toBeVisible();
});

test("unavailable services say not assessed", async ({ page }) => {
  await stub(page, true);
  await openView(page, "Risk assessment");
  await expect(page.getByText(/Not assessed: the risk assessment is unavailable/)).toBeVisible();
  await page.getByRole("tab", { name: "Readiness & execution" }).click();
  await expect(page.getByText(/Not assessed: the readiness service is unavailable/)).toBeVisible();
});
