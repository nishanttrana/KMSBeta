import { expect, test, type Page, type Request } from "@playwright/test";
import { coveredControls } from "./fixtures/layout";

// Scheduling (13.66.0-beta): every schedule in the platform in one module.
// Payloads follow each owning service's JSON: keycore rotation.go and
// integrity_schedule.go, secrets rotation_schedule.go, reporting
// schedule.go, discovery schedule.go, compliance assessment_schedule.go and
// governance backup_schedule.go.

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const at = (hours: number) => new Date(Date.now() + hours * 3600_000).toISOString();
const PAUSE = "alice no longer holds key.rotate";

const POLICIES = [
  { id: "rp_1", tenant_id: "root", name: "payments", target_type: "key", target_filter: "tag:pci", interval_days: 90, auto_rotate: true, enabled: true, status: "active",
    next_rotation_at: at(5), last_rotation_at: at(-24 * 85), total_rotations: 12, created_at: at(-1000), authorized_by: "alice" },
  { id: "rp_2", tenant_id: "root", name: "legacy", target_type: "key", target_filter: "old-*", interval_days: 30, auto_rotate: true, enabled: true, status: "active",
    next_rotation_at: at(-1), total_rotations: 0, created_at: at(-1000), authorized_by: "alice", paused_reason: PAUSE },
];
const INTEGRITY = [{ id: "kis_1", tenant_id: "root", name: "all keys", target_filter: "*", interval_hours: 24, enabled: true, authorized_by: "bob",
  next_run_at: at(30), last_run_at: at(-2), last_result: "failed", last_error: "", last_checked: 4200, last_failed: 1, last_not_assessed: 12 }];
const SECRET_SCHED = [{ tenant_id: "root", secret_id: "sec_1", secret_name: "deploy", secret_path: "ops/deploy", secret_type: "ssh_private_key",
  interval_hours: 720, enabled: true, authorized_by: "alice", next_run_at: at(100), last_result: "", last_version: 0 }];
const REPORTS = [{ id: "sched_1", tenant_id: "root", name: "weekly alerts", template_id: "alert_summary", format: "pdf", schedule: "weekly", enabled: true,
  authorized_by: "alice", last_result: "refused", last_error: "alice is no longer an active user", last_run_at: at(-2), next_run_at: at(20) }];
const TEMPLATES = [{ id: "alert_summary", name: "Alert Summary", description: "", formats: ["pdf", "csv", "json"] }, { id: "posture_summary", name: "Posture Summary", description: "", formats: ["pdf", "json"] }];
const DISCOVERY = { tenant_id: "root", enabled: true, interval_hours: 24, sources: ["tls"], authorized_by: "alice", next_run_at: at(6), last_scan_id: "", paused_reason: "" };
const ASSESS = { tenant_id: "root", enabled: false, frequency: "daily", authorized_by: "" };
const BACKUPS = [{ id: "bks_1", tenant_id: "root", name: "nightly", enabled: true, scope: "system", interval_hours: 24, retain_count: 7, key_protection: "hsm",
  authorized_by: "admin-1", next_run_at: at(10), last_run_at: at(-14), last_result: "succeeded", created_at: at(-100), updated_at: at(-14) }];

type Opts = { failReports?: boolean };
async function stub(page: Page, opts: Opts = {}): Promise<Request[]> {
  const writes: Request[] = [];
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const req = r.request();
    const p = new URL(req.url()).pathname;
    if (req.method() !== "GET") {
      writes.push(req);
      if (p.includes("/integrity/schedules")) return r.fulfill(json(p.endsWith("/run") ? { schedule: INTEGRITY[0], outcome: { checked: 1, verified: 1, not_assessed: 0, failed: 0, failed_keys: [] } } : { schedule: { ...INTEGRITY[0], ...req.postDataJSON() } }, 201));
      if (p.includes("/secrets/rotation-schedules")) return r.fulfill(json({ schedule: { ...SECRET_SCHED[0], ...req.postDataJSON() } }));
      if (p.includes("/reports/scheduled")) return r.fulfill(json({ item: { ...REPORTS[0], ...req.postDataJSON() } }, 201));
      if (p.endsWith("/compliance/assessment/schedule")) return r.fulfill(json({ schedule: { ...ASSESS, ...req.postDataJSON(), authorized_by: "admin-1" } }));
      return r.fulfill(json({}));
    }
    if (p.endsWith("/rotation/policies")) return r.fulfill(json({ items: POLICIES }));
    if (p.endsWith("/rotation/runs") || p.endsWith("/rotation/upcoming")) return r.fulfill(json({ items: [] }));
    if (p.endsWith("/integrity/schedules")) return r.fulfill(json({ items: INTEGRITY }));
    if (p.endsWith("/secrets/rotation-schedules")) return r.fulfill(json({ items: SECRET_SCHED }));
    if (p.endsWith("/svc/secrets/secrets")) return r.fulfill(json({ items: [
      { id: "sec_2", tenant_id: "root", name: "ci-key", path: "ci/ci-key", secret_type: "ssh_private_key", status: "active", current_version: 1, lease_ttl_seconds: 0, metadata: { generated: true, algorithm: "ed25519" } },
      { id: "sec_3", tenant_id: "root", name: "ci-password", path: "ci/ci-password", secret_type: "password", status: "active", current_version: 1, lease_ttl_seconds: 0, metadata: {} },
    ] }));
    if (p.endsWith("/reports/scheduled")) return opts.failReports ? r.fulfill(json({ error: { message: "reporting down" } }, 503)) : r.fulfill(json({ items: REPORTS }));
    if (p.endsWith("/reports/templates")) return r.fulfill(json({ items: TEMPLATES }));
    if (p.endsWith("/discovery/schedule")) return r.fulfill(json({ schedule: DISCOVERY }));
    if (p.endsWith("/discovery/sources")) return r.fulfill(json({ items: [] }));
    if (p.endsWith("/compliance/assessment/schedule")) return r.fulfill(json({ schedule: ASSESS }));
    if (p.endsWith("/governance/backups/schedules")) return r.fulfill(json({ items: BACKUPS }));
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "admin-1", token: "t", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  return writes;
}

const sent = (w: Request) => `${w.method()} ${new URL(w.url()).pathname}`;

test("the overview lists every schedule, and tiles and bars filter to exactly what they count", async ({ page }) => {
  await stub(page);
  await page.goto("/#scheduling");
  await expect(page.getByTestId("subnav-scheduling").getByRole("button")).toHaveText(
    ["Overview", "Key rotation", "Key integrity", "Secret rotation", "Reports", "Scans & assessments", "Backups", "Cryptoperiods"]);
  const view = page.getByTestId("scheduling-overview");
  const rows = view.getByTestId("schedule-row");
  // Two policies, one integrity check, one secret, one report, discovery, one backup; the assessment is off.
  await expect(rows).toHaveCount(7);
  const tile = (name: RegExp) => view.getByRole("button", { name });
  await expect(tile(/^Active/)).toContainText("6");
  await expect(tile(/^Paused/)).toContainText("1");
  await expect(tile(/^Last run failed or refused/)).toContainText("2");
  await tile(/^Paused/).click();
  await expect(rows).toHaveCount(1);
  await expect(rows).toContainText("legacy");
  await tile(/^Paused/).click();
  await expect(rows).toHaveCount(7);
  await tile(/^Last run failed or refused/).click();
  await expect(rows).toHaveText([/weekly alerts.*refused/, /all keys.*failed/]);
  await view.getByRole("button", { name: /^Clear/ }).click();
  expect(await coveredControls(view)).toEqual([]);

  // A row opens its kind's view.
  await rows.filter({ hasText: "all keys" }).click();
  await expect(page).toHaveURL(/#scheduling\/integrity$/);
  await expect(page.getByTestId("integrity-row")).toContainText("4200 checked, 1 failed, 12 not assessed");
});

test("a source that fails reads unavailable; the others still show", async ({ page }) => {
  await stub(page, { failReports: true });
  await page.goto("/#scheduling/overview");
  await expect(page.getByText("Report: unavailable")).toBeVisible();
  await expect(page.getByTestId("schedule-row")).toHaveCount(6);
});

test("each kind saves exactly the fields its route takes", async ({ page }) => {
  const writes = await stub(page);
  await page.goto("/#scheduling/integrity");
  await page.getByRole("button", { name: "New integrity check" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("textbox").first().fill("payments");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect.poll(() => writes.map(sent)).toEqual(["POST /svc/keycore/integrity/schedules"]);
  expect(Object.keys(writes[0]!.postDataJSON()).sort()).toEqual(["enabled", "interval_hours", "name", "target_filter"]);

  await page.goto("/#scheduling/secrets");
  await page.getByRole("button", { name: "Schedule a rotation" }).click();
  await page.getByPlaceholder("Name or ID").fill("ci");
  await page.getByRole("button", { name: "Find" }).click();
  await expect(page.getByRole("dialog").getByText("ci/ci-key")).toBeVisible();
  await expect(page.getByRole("dialog").getByText("ci/ci-password")).toHaveCount(0); // not generated by the KMS
  await page.getByRole("dialog").getByText("ci/ci-key").click();
  await page.getByRole("dialog").getByRole("button", { name: "Save" }).click();
  await expect.poll(() => writes.length).toBe(2);
  expect(sent(writes[1]!)).toBe("PUT /svc/secrets/secrets/rotation-schedules/sec_2");
  expect(Object.keys(writes[1]!.postDataJSON()).sort()).toEqual(["enabled", "interval_hours"]);

  await page.goto("/#scheduling/reports");
  await expect(page.getByTestId("report-schedule-row")).toContainText("refused");
  await page.getByRole("button", { name: "Schedule a report" }).click();
  await page.getByRole("dialog").getByRole("textbox").first().fill("posture");
  await page.getByRole("dialog").getByRole("button", { name: "Save" }).click();
  await expect.poll(() => writes.length).toBe(3);
  expect(sent(writes[2]!)).toBe("POST /svc/reporting/reports/scheduled");
  expect(Object.keys(writes[2]!.postDataJSON()).sort()).toEqual(["enabled", "format", "name", "schedule", "template_id"]);

  await page.goto("/#scheduling/scans");
  await page.getByRole("button", { name: "Save" }).click();
  await expect.poll(() => writes.length).toBe(4);
  expect(sent(writes[3]!)).toBe("PUT /svc/compliance/compliance/assessment/schedule");
  expect(Object.keys(writes[3]!.postDataJSON()).sort()).toEqual(["enabled", "frequency"]);
});

test("a paused schedule cannot run now and offers Resume; old addresses open Scheduling", async ({ page }) => {
  await stub(page);
  await page.goto("/#rotation");
  await expect(page).toHaveURL(/#scheduling\/keys$/);
  await expect(page.getByText("alice").first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Resume" })).toHaveCount(1);
  await expect(page.getByText("paused", { exact: true })).toHaveCount(1);
});
