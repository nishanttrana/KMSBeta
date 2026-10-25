import { expect, test, type Page, type Request } from "@playwright/test";

// Scheduling → Backups (13.43.0-beta; moved from Backup & Restore →
// Schedules in 13.66.0-beta, whose address redirects): real scheduled backups, and
// restoring one whose key is sealed to the administrator's public key, with
// the private key used only in the browser.

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const now = new Date().toISOString();
const NIGHTLY = {
  id: "bks_1", tenant_id: "root", name: "nightly", enabled: true, scope: "system", interval_hours: 24, retain_count: 7,
  key_protection: "recipient", recipient_public_key: "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n", recipient_key_sha256: "fp0123456789abcdef",
  authorized_by: "admin-1", next_run_at: now, last_run_at: now, last_result: "succeeded", last_backup_id: "bkp_9", created_at: now, updated_at: now,
};
const PAUSED = { ...NIGHTLY, id: "bks_2", name: "weekly-tenant", scope: "tenant", target_tenant_id: "t1", key_protection: "hsm", recipient_public_key: "", recipient_key_sha256: "",
  paused_reason: "the administrator who saved this schedule is no longer active or no longer holds auth.tenant.write; save it again to resume", last_result: "refused" };

async function stub(page: Page, onRestore?: (r: Request) => void): Promise<Request[]> {
  const writes: Request[] = [];
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const req = r.request();
    const p = new URL(req.url()).pathname;
    if (p.endsWith("/governance/backups/schedules") && req.method() === "GET") return r.fulfill(json({ items: [NIGHTLY, PAUSED] }));
    if (p.includes("/governance/backups/schedules")) {
      writes.push(req);
      if (p.endsWith("/run")) return r.fulfill(json({ job: { id: "bkp_10" } }));
      return r.fulfill(json({ schedule: { ...NIGHTLY, ...(req.postDataJSON() || {}), id: "bks_3" } }, 201));
    }
    if (p.endsWith("/governance/backups/restore")) { onRestore?.(req); return r.fulfill(json({ result: { rows_restored: 3, tables_processed: 1 } })); }
    if (p.endsWith("/governance/backups")) return r.fulfill(json({ items: [] }));
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "admin-1", token: "smoke-token", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  return writes;
}

test("schedules show their state, run now, and save exactly the fields the route takes", async ({ page }) => {
  const writes = await stub(page);
  await page.goto("/#backup/schedules");
  await expect(page).toHaveURL(/#scheduling\/backups$/);
  await expect(page.getByText("nightly", { exact: true })).toBeVisible();
  await expect(page.getByText(PAUSED.paused_reason)).toBeVisible();
  const runs = page.getByRole("button", { name: "Run now", exact: true });
  await expect(runs.nth(1)).toBeDisabled();
  await runs.first().click();
  await expect.poll(() => writes.map((w) => `${w.method()} ${new URL(w.url()).pathname}`)).toEqual(["POST /svc/governance/governance/backups/schedules/bks_1/run"]);

  await page.getByRole("button", { name: "New schedule", exact: true }).click();
  await page.getByPlaceholder("nightly-system").fill("hourly");
  await page.getByPlaceholder(/BEGIN PUBLIC KEY/).fill("-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => writes.length).toBe(2);
  const body = writes[1]!.postDataJSON();
  expect(Object.keys(body).sort()).toEqual(["enabled", "interval_hours", "key_protection", "name", "recipient_public_key", "retain_count", "scope", "target_tenant_id"]);
  expect(body).toMatchObject({ name: "hourly", key_protection: "recipient", interval_hours: 24, retain_count: 7, enabled: true });
});

test("a sealed key file is opened with the private key in the browser, which is never sent", async ({ page }) => {
  const subtle = globalThis.crypto.subtle;
  const kp = await subtle.generateKey({ name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["encrypt", "decrypt"]);
  const b64 = (u: ArrayBuffer | Uint8Array) => Buffer.from(new Uint8Array(u)).toString("base64");
  const backupKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const label = "vecta-kms backup key v1";
  const wrapped = await subtle.encrypt({ name: "RSA-OAEP", label: new TextEncoder().encode(label) }, kp.publicKey, backupKey);
  const sealed = JSON.stringify({ mode: "recipient_sealed", oaep_label: label, wrapped_key_b64: b64(wrapped), backup_id: "bkp_9" });
  const pem = `-----BEGIN PRIVATE KEY-----\n${b64(await subtle.exportKey("pkcs8", kp.privateKey)).replace(/(.{64})/g, "$1\n")}\n-----END PRIVATE KEY-----\n`;

  let restored: Request | undefined;
  await stub(page, (r) => { restored = r; });
  await page.goto("/#backup/encrypted");
  await page.locator('input[type="file"][accept=".vbk"]').setInputFiles({ name: "vecta-backup-bkp_9.vbk", mimeType: "application/octet-stream", buffer: Buffer.from("{}") });
  await page.locator('input[type="file"][accept=".json,.key.json"]:not([multiple])').setInputFiles({ name: "vecta-backup-bkp_9.key.json", mimeType: "application/json", buffer: Buffer.from(sealed) });
  await expect(page.getByText("Private key (PEM): opened in this browser, never sent")).toBeVisible();
  await page.getByRole("button", { name: "Restore Backup", exact: true }).click();
  await expect(page.getByText("This key file is sealed: choose the private key that opens it.")).toBeVisible();
  expect(restored).toBeUndefined();

  await page.locator('input[type="file"][accept=".pem,.key"]').setInputFiles({ name: "admin.pem", mimeType: "application/x-pem-file", buffer: Buffer.from(pem) });
  await page.getByRole("button", { name: "Restore Backup", exact: true }).click();
  await expect.poll(() => Boolean(restored)).toBe(true);
  const raw = restored!.postData() || "";
  expect(raw).not.toContain("PRIVATE KEY");
  const keyFile = JSON.parse(Buffer.from(restored!.postDataJSON().key_content_base64, "base64").toString());
  expect(keyFile.backup_key_b64).toBe(b64(backupKey));
  expect(keyFile.backup_id).toBe("bkp_9");
});
