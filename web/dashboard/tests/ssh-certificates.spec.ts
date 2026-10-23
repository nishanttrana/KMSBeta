import { expect, test, type Request } from "@playwright/test";

// Certificates → SSH Certificates (13.49.0-beta): the CA's trust lines,
// signing a public key within the CA's policy (only the fields the route
// takes), the issued list and revoking with a reason.
const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const now = new Date().toISOString();
const later = new Date(Date.now() + 8 * 3600_000).toISOString();
const ca = {
  id: "sshca_1", name: "prod-users", algorithm: "ECDSA-P384", key_backend: "software",
  public_key: "ecdsa-sha2-nistp384 AAAAE2VjZHNh vecta-ssh-ca:prod-users", fingerprint: "SHA256:abcdefghijklmnop",
  cert_types: ["user"], allowed_principals: ["deploy", "web-*"], max_validity_seconds: 28800, default_extensions: ["permit-pty"],
  status: "active", created_by: "admin-1", created_at: now,
};
const cert = {
  id: "sshcert_1", ca_id: "sshca_1", serial: "4242", cert_type: "user", key_id: "laptop-alice", principals: ["deploy"],
  key_type: "ssh-ed25519", key_fingerprint: "SHA256:zzz", extensions: ["permit-pty"], critical_options: {},
  valid_after: now, valid_before: later, issued_by: "admin-1", issued_at: now,
};

test("an SSH CA signs a public key within its policy, and a certificate is revoked with a reason", async ({ page }) => {
  const signs: Request[] = [];
  const revokes: Request[] = [];
  await page.route("**/api/**", (r) => r.fulfill(json({})));
  await page.route("**/auth/**", (r) => r.fulfill(json({})));
  await page.route("**/svc/**", (r) => {
    const req = r.request();
    const p = new URL(req.url()).pathname;
    if (p.endsWith("/certs/ssh/cas")) return r.fulfill(json({ items: [ca] }));
    if (p.endsWith("/certs/ssh/cas/sshca_1")) return r.fulfill(json({ ssh_ca: ca, trust: {
      trusted_user_ca_keys: ca.public_key, known_hosts: "@cert-authority * ecdsa-sha2-nistp384 AAAAE2VjZHNh" } }));
    if (p.endsWith("/certs/ssh/cas/sshca_1/certificates")) return r.fulfill(json({ items: [cert] }));
    if (p.endsWith("/certs/ssh/cas/sshca_1/sign")) {
      signs.push(req);
      return r.fulfill(json({ certificate: "ecdsa-sha2-nistp384-cert-v01@openssh.com AAAAKGVjZHNh issued", ssh_certificate: { ...cert, id: "sshcert_2", serial: "4343" } }, 201));
    }
    if (p.endsWith("/certs/ssh/certificates/sshcert_1/revoke")) {
      revokes.push(req);
      return r.fulfill(json({ ssh_certificate: { ...cert, revoked_at: now, revoke_reason: "laptop lost" } }));
    }
    return r.fulfill(json({}));
  });
  await page.addInitScript(() => {
    window.sessionStorage.setItem("vecta_ui_session", JSON.stringify({
      tenantId: "root", username: "admin-1", token: "t", mode: "local", mustChangePassword: false, role: "admin", permissions: ["*"],
    }));
  });
  await page.goto("/#certs/cert-ssh");
  await expect(page.getByTestId("ssh-ca-row")).toContainText("prod-users");
  await expect(page.getByText("Signs deploy, web-* · up to 8 h")).toBeVisible();
  await expect(page.getByText("ecdsa-sha2-nistp384 AAAAE2VjZHNh vecta-ssh-ca:prod-users").last()).toBeVisible();

  await expect(page.getByRole("button", { name: "Sign", exact: true })).toBeDisabled();
  await page.getByLabel("SSH public key").fill("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGs alice@laptop");
  await page.getByLabel("SSH principals").fill("deploy");
  await page.getByLabel("SSH validity hours").fill("2");
  await page.getByRole("button", { name: "Sign", exact: true }).click();
  await expect(page.getByTestId("ssh-issued-cert")).toContainText("ecdsa-sha2-nistp384-cert-v01@openssh.com");
  expect(signs[0]!.postDataJSON()).toEqual({
    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGs alice@laptop", cert_type: "user", principals: ["deploy"], valid_seconds: 7200, extensions: ["permit-pty"],
  });

  await expect(page.getByTestId("ssh-cert-row")).toContainText("4242");
  await page.getByTestId("ssh-cert-row").getByRole("button", { name: "Revoke", exact: true }).click();
  await page.getByRole("dialog").getByRole("textbox").fill("laptop lost");
  await page.getByRole("dialog").getByRole("button", { name: "Revoke", exact: true }).click();
  await expect.poll(() => revokes.length).toBe(1);
  expect(revokes[0]!.postDataJSON()).toEqual({ reason: "laptop lost" });
});
