import { expect, test, type Page } from "@playwright/test";

// The Crypto Agility tab shows keycore's /agility/posture: live keys measured
// against NIST's transition schedule (pkg/cryptocatalog). The API is stubbed
// with a posture computed by keycore's computeAgilityPosture for 3 RSA-2048,
// 5 AES-256, 2 ML-DSA-65, 1 3DES and 1 "RSA" key on 2026-09-29; the figures
// themselves are tested in services/keycore and pkg/cryptocatalog.

const SHOTS = process.env.AGILITY_SHOTS_DIR || "";

const posture = {
  "assessed": true,
  "as_of": "2026-09-29",
  "total_keys": 12,
  "not_assessed_keys": 1,
  "quantum_vulnerable_keys": 3,
  "post_quantum_keys": 2,
  "status_counts": {
    "acceptable": 10,
    "legacy_use": 1
  },
  "milestones": [
    {
      "date": "2031-01-01",
      "status": "deprecated",
      "source": "SP800-131Ar3",
      "ref": "Tables 3 and 6",
      "citation": "SP 800-131Ar3 ipd, Tables 3 and 6",
      "key_count": 3,
      "algorithms": [
        "RSA-2048"
      ]
    },
    {
      "date": "2036-01-01",
      "status": "disallowed",
      "source": "IR8547",
      "ref": "Tables 2 and 4",
      "citation": "IR 8547 ipd, Tables 2 and 4",
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
      "percentage": 25,
      "assessed": true,
      "canonical": "RSA-2048",
      "family": "RSA",
      "security_bits": 112,
      "quantum_vulnerable": true,
      "post_quantum": false,
      "nist_status": "acceptable",
      "next_change": {
        "from": "2031-01-01",
        "status": "deprecated",
        "source": "SP800-131Ar3",
        "ref": "Tables 3 and 6"
      },
      "schedule": [
        {
          "status": "acceptable",
          "source": "SP800-131Ar3",
          "ref": "Tables 3 and 6"
        },
        {
          "from": "2031-01-01",
          "status": "deprecated",
          "source": "SP800-131Ar3",
          "ref": "Tables 3 and 6"
        },
        {
          "from": "2036-01-01",
          "status": "disallowed",
          "source": "IR8547",
          "ref": "Tables 2 and 4"
        }
      ]
    },
    {
      "algorithm": "AES-256",
      "key_count": 5,
      "percentage": 41.66666666666667,
      "assessed": true,
      "canonical": "AES-256",
      "family": "AES",
      "security_bits": 256,
      "pqc_category": 5,
      "quantum_vulnerable": false,
      "post_quantum": false,
      "nist_status": "acceptable",
      "schedule": [
        {
          "status": "acceptable",
          "source": "SP800-131Ar3",
          "ref": "Tables 1 and 2"
        }
      ]
    },
    {
      "algorithm": "ML-DSA-65",
      "key_count": 2,
      "percentage": 16.666666666666664,
      "assessed": true,
      "canonical": "ML-DSA-65",
      "family": "ML-DSA",
      "security_bits": 192,
      "pqc_category": 3,
      "quantum_vulnerable": false,
      "post_quantum": true,
      "nist_status": "acceptable",
      "schedule": [
        {
          "status": "acceptable",
          "source": "SP800-131Ar3",
          "ref": "Table 3"
        }
      ]
    },
    {
      "algorithm": "3DES",
      "key_count": 1,
      "percentage": 8.333333333333332,
      "assessed": true,
      "canonical": "3TDEA",
      "family": "TDEA",
      "security_bits": 112,
      "quantum_vulnerable": false,
      "post_quantum": false,
      "nist_status": "legacy_use",
      "schedule": [
        {
          "status": "legacy_use",
          "source": "SP800-131Ar3",
          "ref": "Table 1"
        }
      ],
      "note": "encryption disallowed; decryption allowed for legacy use"
    },
    {
      "algorithm": "RSA",
      "key_count": 1,
      "percentage": 8.333333333333332,
      "assessed": false,
      "quantum_vulnerable": false,
      "post_quantum": false
    }
  ],
  "findings": [
    "Live keys on algorithms NIST no longer allows for new protection: 1 (3DES). Keep them only to decrypt or verify existing data, and migrate them (SP 800-131Ar3 ipd).",
    "Quantum-vulnerable live keys that become disallowed on 2036-01-01 (IR 8547 ipd, Tables 2 and 4): 3 (RSA-2048). Plan their migration to ML-KEM or ML-DSA before then.",
    "Live keys whose algorithm name states no parameter set, so their NIST status is not assessed: 1 (RSA)."
  ],
  "sources": [
    {
      "id": "FIPS186-5",
      "label": "FIPS 186-5",
      "title": "FIPS 186-5, Digital Signature Standard",
      "revision": "final",
      "date": "2023-02",
      "url": "https://doi.org/10.6028/NIST.FIPS.186-5"
    },
    {
      "id": "FIPS204",
      "label": "FIPS 204",
      "title": "FIPS 204, Module-Lattice-Based Digital Signature Standard",
      "revision": "final",
      "date": "2024-08",
      "url": "https://doi.org/10.6028/NIST.FIPS.204"
    },
    {
      "id": "IR8547",
      "label": "IR 8547 ipd",
      "title": "NIST IR 8547 (initial public draft), Transition to Post-Quantum Cryptography Standards",
      "revision": "ipd",
      "date": "2024-11",
      "url": "https://doi.org/10.6028/NIST.IR.8547.ipd"
    },
    {
      "id": "SP800-131Ar3",
      "label": "SP 800-131Ar3 ipd",
      "title": "NIST SP 800-131A Rev. 3 (initial public draft), Transitioning the Use of Cryptographic Algorithms and Key Lengths",
      "revision": "ipd",
      "date": "2024-10",
      "url": "https://doi.org/10.6028/NIST.SP.800-131Ar3.ipd"
    },
    {
      "id": "SP800-57pt1r5",
      "label": "SP 800-57 Pt1 r5",
      "title": "NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management",
      "revision": "final",
      "date": "2020-05",
      "url": "https://doi.org/10.6028/NIST.SP.800-57pt1r5"
    }
  ]
};

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

async function stub(page: Page, postureStatus = 200): Promise<void> {
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (route) => {
    const p = new URL(route.request().url()).pathname;
    if (p.endsWith("/agility/posture")) {
      return route.fulfill(postureStatus === 200 ? json({ data: posture }) : json({ error: { message: "keycore unavailable" } }, postureStatus));
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
}

async function openTab(page: Page): Promise<void> {
  await page.goto("/");
  await page.getByText("Crypto Agility", { exact: true }).first().click();
}

test("the tab shows NIST deadlines, statuses and sources for the live keys", async ({ page }) => {
  await stub(page);
  await openTab(page);
  await expect(page.getByText("NIST transition deadlines for your keys")).toBeVisible();

  // Deadlines: 112-bit RSA deprecated from 2031, quantum-vulnerable disallowed from 2036, cited.
  const deadline2031 = page.locator("tr", { hasText: "2031-01-01" }).first();
  await expect(deadline2031.getByText("SP 800-131Ar3 ipd, Tables 3 and 6")).toBeVisible();
  await expect(deadline2031.getByText("Deprecated", { exact: true })).toBeVisible();
  const deadline2036 = page.locator("tr", { hasText: "IR 8547 ipd, Tables 2 and 4" });
  await expect(deadline2036.getByText("Disallowed", { exact: true })).toBeVisible();

  // Inventory: strength and status per algorithm; a name without a size is not assessed.
  const rsa = page.locator("tr", { hasText: "RSA-2048" }).last();
  await expect(rsa.getByText("112-bit")).toBeVisible();
  await expect(rsa.getByText("Acceptable", { exact: true })).toBeVisible();
  await expect(page.locator("tr", { hasText: "3DES" }).last().getByText("Legacy use only")).toBeVisible();
  const bare = page.locator("tr").filter({ has: page.getByText("RSA", { exact: true }) });
  await expect(bare.getByText("Not assessed", { exact: true })).toBeVisible();

  // Findings and sources carry their citations; drafts are labelled proposed.
  await expect(page.getByText(/no longer allows for new protection: 1 \(3DES\)/)).toBeVisible();
  await expect(page.getByText(/NIST IR 8547 \(initial public draft\)/)).toBeVisible();
  await expect(page.getByText(/initial public draft, dates proposed/).first()).toBeVisible();
  await expect(page.getByText(/Agility Score|grade [A-F]/)).toHaveCount(0);
  if (SHOTS) {
    await page.screenshot({ path: `${SHOTS}/crypto-agility.png`, fullPage: true });
    await page.getByText("Algorithm inventory", { exact: true }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${SHOTS}/crypto-agility-inventory.png` });
    await page.getByText("Sources", { exact: true }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${SHOTS}/crypto-agility-sources.png` });
  }
});

test("an unreachable keycore says not assessed and shows no figures", async ({ page }) => {
  await stub(page, 503);
  await openTab(page);
  await expect(page.getByText("Not assessed: crypto agility data is unavailable")).toBeVisible();
  await expect(page.getByText("keycore unavailable")).toBeVisible();
  await expect(page.getByText("NIST transition deadlines for your keys")).toHaveCount(0);
});
