import { expect, test, type Page } from "@playwright/test";
import { coveredControls } from "./fixtures/layout";

// Certificates → Certificate Operations and Renewals (13.61.0-beta). The page
// was eight cards, two copies of every certificate and five button rows; it
// is now one toolbar, count tiles that filter the table, and the CA tree as
// a filter. Payloads follow the certs service's JSON (summary.go,
// renewal_types.go), with Go's zero time where a time is unset.
const json = (body: unknown) => ({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
const ZERO = "0001-01-01T00:00:00Z";
const at = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

const CAS = [
  { id: "ca_root", name: "vecta-root", algorithm: "ECDSA-P384", key_backend: "software", status: "active", parent_ca_id: "" },
  { id: "ca_int1", name: "issuing-1", algorithm: "ECDSA-P384", key_backend: "hsm", status: "active", parent_ca_id: "ca_root" },
  { id: "ca_int2", name: "issuing-2", algorithm: "ECDSA-P256", key_backend: "software", status: "active", parent_ca_id: "ca_root" },
];
const cert = (id: string, cn: string, ca: string, days: number, status = "active", created = 0) => ({
  id, subject_cn: cn, ca_id: ca, algorithm: "ECDSA-P256", cert_class: "tls-server", status,
  not_before: at(days - 365), not_after: at(days), created_at: at(-10 + created),
});
const CERTS = [
  cert("crt_1", "api.corp", "ca_int1", 20.5, "active", 1),
  cert("crt_2", "web.corp", "ca_int1", 200.5, "active", 2),
  cert("crt_3", "mq.internal", "ca_int2", 5.5, "active", 3),
  cert("crt_4", "old.corp", "ca_int2", 50, "revoked", 4),
  cert("crt_5", "partner.example", "external-ca", 10.5, "active", 5),
  cert("crt_6", "lapsed.corp", "ca_int1", -2, "active", 6),
];
// As CertSummary counts CERTS: crt_6 is past its end, so expired.
const SUMMARY = { total: 6, active: 4, revoked: 1, expired: 1, expiring: 3, expiring_7d: 1, alert_days: 30, include_external: true };

const day = (n: number) => at(n).slice(0, 10);
const win = (certID: string, cn: string, ca: string, state: string, risk: string, bucket: string, scheduled: string, missed = ZERO, emergency = ZERO) => ({
  tenant_id: "root", cert_id: certID, ari_id: `ari_${certID}`, ca_id: ca, ca_name: ca, subject_cn: cn, protocol: "", not_after: at(20),
  window_start: at(1), window_end: at(1.2), scheduled_renewal_at: scheduled, explanation_url: "", retry_after_seconds: 86400, next_poll_at: at(1),
  renewal_state: state, risk_level: risk, missed_window_at: missed, emergency_rotation_at: emergency, mass_renewal_bucket: bucket,
  window_source: "local", metadata_json: "{}", updated_at: at(0),
});
const WINDOWS = [
  win("crt_1", "api.corp", "issuing-1", "scheduled", "low", day(12), at(12)),
  win("crt_3", "mq.internal", "issuing-2", "emergency_rotation", "critical", day(1), at(1), ZERO, at(0)),
  win("crt_5", "partner.example", "external", "missed_window", "high", day(1), at(1), at(-1)),
  win("crt_2", "web.corp", "issuing-1", "scheduled", "low", day(130), at(130)),
];
const entry = (bucket: string, count: number, risk: string, ids: string[], cas: [string, number][]) => ({
  bucket, cas: cas.map(([name, n]) => ({ ca_id: `id_${name}`, ca_name: name, count: n })), count, risk_level: risk, scheduled_start: at(1), scheduled_end: at(2), cert_ids: ids,
});
const RENEWAL = {
  tenant_id: "root", ari_enabled: true, recommended_poll_hours: 24, renewal_windows: WINDOWS,
  ca_directed_schedule: [
    entry(day(1), 2, "critical", ["crt_3", "crt_5"], [["issuing-2", 1], ["external", 1]]),
    entry(day(12), 1, "low", ["crt_1"], [["issuing-1", 1]]),
    entry(day(130), 1, "low", ["crt_2"], [["issuing-1", 1]]),
  ],
  mass_renewal_risks: [entry(day(1), 2, "critical", ["crt_3", "crt_5"], [["issuing-2", 1], ["external", 1]])],
  missed_window_count: 1, emergency_rotation_count: 1, due_soon_count: 2, non_compliant_count: 2,
  star_subscription_count: 0, star_delegated_count: 0, star_due_soon_count: 0, star_mass_rollout_risk_count: 0,
};

async function stub(page: Page) {
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const p = new URL(r.request().url()).pathname;
    if (p.endsWith("/svc/certs/certs")) return r.fulfill(json({ items: CERTS }));
    if (p.endsWith("/certs/ca")) return r.fulfill(json({ items: CAS }));
    if (p.endsWith("/certs/summary")) return r.fulfill(json({ summary: SUMMARY }));
    if (p.endsWith("/certs/alert-policy")) return r.fulfill(json({ policy: { days_before: 30, include_external: true } }));
    if (p.endsWith("/certs/renewal-intelligence")) return r.fulfill(json({ summary: RENEWAL }));
    if (p.endsWith("/certs/star/summary")) return r.fulfill(json({ summary: { enabled: true, subscriptions: [], mass_rollout_risks: [] } }));
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "admin-1", token: "t", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
}

test("each certificate tile and CA lists exactly what it counts", async ({ page }) => {
  await stub(page);
  await page.goto("/#certs/cert-overview");
  const view = page.getByTestId("cert-overview");
  const rows = view.getByTestId("cert-row");
  await expect(rows).toHaveCount(6);
  await expect(view.locator(".vecta-stat-card")).toHaveText([/^Active/i, /^Expiring/i, /^Revoked/i, /^Missed windows/i]);
  // One copy of each certificate, and no renewal or STAR cards here.
  await expect(view.getByText("api.corp", { exact: true })).toHaveCount(1);
  await expect(view).not.toContainText(/Expiry Calendar|Renewal Windows|Mass-Renewal|ACME STAR|CA-Directed/);

  for (const [label, n] of [["Active", 4], ["Expiring", 3], ["Revoked", 1]] as const) {
    const tile = view.getByRole("button", { name: new RegExp(`^${label}`) });
    await expect(tile).toContainText(String(n));
    await tile.click();
    await expect(tile).toHaveAttribute("aria-pressed", "true");
    await expect(rows).toHaveCount(n);
    if (label === "Expiring") await expect(rows.first()).toContainText("mq.internal"); // soonest first
    await tile.click();
    await expect(rows).toHaveCount(6);
  }

  // A CA filters the table; its count is the rows listed.
  const issuing2 = view.getByTestId("ca-node").filter({ hasText: "issuing-2" });
  await expect(issuing2.getByTitle("Certificates issued by this CA")).toHaveText("2");
  await issuing2.getByRole("button", { name: /^issuing-2/ }).click();
  await expect(rows).toHaveCount(2);
  await view.getByRole("button", { name: "Clear CA: issuing-2" }).click();
  await expect(rows).toHaveCount(6);

  // The row menu holds the row's actions and closes on Escape.
  await rows.filter({ hasText: "api.corp" }).getByRole("button", { name: "Certificate actions" }).click();
  const menu = page.getByRole("menu");
  await expect(menu.getByRole("menuitem")).toHaveText(["Download", "Renew", "Revoke", "OCSP status", "Delete permanently"]);
  await page.keyboard.press("Escape");
  await expect(menu).toHaveCount(0);

  await view.getByRole("button", { name: "More ways to add a certificate" }).click();
  await expect(page.getByRole("menuitem")).toHaveText(["Sign CSR", "Upload 3rd-party"]);
  await page.keyboard.press("Escape");
  expect(await coveredControls(view)).toEqual([]);

  await view.getByRole("button", { name: /^Missed windows/ }).click();
  await expect(page).toHaveURL(/#certs\/cert-renewals$/);
});

test("each renewal tile and bar lists the windows it counts, and a window opens its certificate", async ({ page }) => {
  await stub(page);
  await page.goto("/#certs/cert-renewals");
  const view = page.getByTestId("cert-renewals");
  const rows = view.getByTestId("renewal-row");
  await expect(view.getByText("All renewal windows: 4 entries")).toBeVisible();
  for (const [label, n] of [["Due in 72h", 2], ["Missed windows", 1], ["Emergency", 1], ["At risk", 2]] as const) {
    const tile = view.getByRole("button", { name: new RegExp(`^${label}`) });
    await expect(tile).toContainText(String(n));
    await tile.click();
    await expect(view.getByText(`${label}: ${n} ${n === 1 ? "entry" : "entries"}`)).toBeVisible();
    await expect(rows).toHaveCount(n);
  }
  // A day's bar names each CA renewing that day with its share.
  await view.locator(".recharts-bar-rectangle").first().hover();
  await expect(view.locator(".recharts-tooltip-wrapper")).toContainText(`${day(1)} · 2`);
  await expect(view.locator(".recharts-tooltip-wrapper")).toContainText("issuing-2");
  await expect(view.locator(".recharts-tooltip-wrapper")).toContainText("external");
  await view.locator(".recharts-bar-rectangle").first().click();
  await expect(view.getByText(`Renewing ${day(1)}: 2 entries`)).toBeVisible();
  await expect(rows).toHaveCount(2);

  await rows.filter({ hasText: "mq.internal" }).click();
  await expect(page).toHaveURL(/#certs\/cert-overview$/);
  await expect(page.getByLabel("Search certificates")).toHaveValue("crt_3");
  await expect(page.getByTestId("cert-row")).toHaveCount(1);
});

test("ACME STAR subscriptions sit with the ACME protocol", async ({ page }) => {
  await stub(page);
  await page.goto("/#certs/cert-enrollment");
  await expect(page.getByTestId("acme-star")).toContainText("ACME STAR subscriptions");
});
