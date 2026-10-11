import type { Credential, CredentialType } from "../../../../lib/credentials";
import type { Drill } from "../../chartDrill";

// Buckets and drill-downs of the Credentials view. A chart and the list it
// opens use the same bucket function, so the list holds exactly the
// credentials the bar counts.
export type CredentialDrill = Drill<Credential> & { key: string };

const DAY = 86400000;

export const CATEGORIES = [
  { id: "cloud", label: "Cloud providers" },
  { id: "hsm", label: "HSMs" },
  { id: "mail", label: "Mail" },
  { id: "notify", label: "Notifications" },
  { id: "ticketing", label: "Ticketing" },
  { id: "siem", label: "SIEM" },
  { id: "source", label: "Scan sources" },
] as const;

export const categoryLabel = (id: string) => CATEGORIES.find((c) => c.id === id)?.label ?? id;

// Where a credential of each category is chosen once it exists: the tab id
// the dashboard navigates to.
export const USED_IN: Record<string, { tab: string; label: string }> = {
  cloud: { tab: "byok", label: "Cloud BYOK" },
  hsm: { tab: "keys", label: "Keys" },
  mail: { tab: "approvals", label: "Governance" },
  source: { tab: "discovery", label: "Crypto Discovery" },
};

const FILL = { bad: "var(--cls-weak)", soon: "var(--cls-qv)", ok: "var(--cls-strong)", none: "var(--cls-unknown)", exposed: "var(--cls-exposed)" };
export const SERIES_FILL = FILL.ok;

// Health is the last real test of the current secret.
export const HEALTH = [
  { id: "ok", label: "Test passed", color: FILL.ok },
  { id: "failing", label: "Test failed", color: FILL.bad },
  { id: "untested", label: "Not tested", color: FILL.none },
] as const;

export const health = (c: Credential): string => (!c.last_tested_at ? "untested" : c.last_test_ok ? "ok" : "failing");

export const EXPIRY = [
  { id: "expired", label: "Expired", color: FILL.bad },
  { id: "7d", label: "Within 7 days", color: FILL.soon },
  { id: "30d", label: "8 to 30 days", color: FILL.soon },
  { id: "later", label: "Later", color: FILL.ok },
  { id: "none", label: "No expiry set", color: FILL.none },
] as const;

export function expiryBucket(c: Credential, now: number): string {
  if (!c.expires_at) return "none";
  const left = new Date(c.expires_at).getTime() - now;
  if (left <= 0) return "expired";
  if (left <= 7 * DAY) return "7d";
  if (left <= 30 * DAY) return "30d";
  return "later";
}

// Age counts from when a secret field last changed.
export const AGE = [
  { id: "30d", label: "Under 30 days", color: FILL.ok },
  { id: "90d", label: "1 to 3 months", color: FILL.ok },
  { id: "365d", label: "3 to 12 months", color: FILL.soon },
  { id: "old", label: "Over a year", color: FILL.bad },
] as const;

export const ageDays = (c: Credential, now: number) => Math.max(0, Math.floor((now - new Date(c.credentials_changed_at).getTime()) / DAY));

export function ageBucket(c: Credential, now: number): string {
  const d = ageDays(c, now);
  if (d < 30) return "30d";
  if (d < 90) return "90d";
  if (d < 365) return "365d";
  return "old";
}

export const rotationDue = (c: Credential, now: number) => c.rotate_after_days > 0 && ageDays(c, now) >= c.rotate_after_days;

const labelOf = (rows: readonly { id: string; label: string }[], id: string) => rows.find((r) => r.id === id)?.label ?? id;

export const allDrill = (): CredentialDrill => ({ key: "all", label: "All credentials", match: () => true });
export const categoryDrill = (types: CredentialType[], category: string): CredentialDrill =>
  ({ key: `category:${category}`, label: categoryLabel(category), match: (c) => types.find((t) => t.type === c.type)?.category === category });
export const typeDrill = (type: string, label: string): CredentialDrill => ({ key: `type:${type}`, label, match: (c) => c.type === type });
export const healthDrill = (id: string): CredentialDrill => ({ key: `health:${id}`, label: labelOf(HEALTH, id), match: (c) => health(c) === id });
export const expiryDrill = (id: string, now: number): CredentialDrill =>
  ({ key: `expiry:${id}`, label: `Expiry: ${labelOf(EXPIRY, id)}`, match: (c) => expiryBucket(c, now) === id });
export const expiringDrill = (now: number): CredentialDrill =>
  ({ key: "expiring", label: "Expired or expiring in 30 days", match: (c) => ["expired", "7d", "30d"].includes(expiryBucket(c, now)) });
export const ageDrill = (id: string, now: number): CredentialDrill =>
  ({ key: `age:${id}`, label: `Secret age: ${labelOf(AGE, id)}`, match: (c) => ageBucket(c, now) === id });
export const rotationDrill = (now: number): CredentialDrill => ({ key: "rotation", label: "Due for rotation", match: (c) => rotationDue(c, now) });
export const exposedDrill = (exposed: Record<string, unknown>): CredentialDrill =>
  ({ key: "exposed", label: "Exposed: rotate now", match: (c) => Boolean(exposed[c.id]) });

export const EXPOSED_FILL = FILL.exposed;

// Field hints (placeholders only; nothing here is a default).
export const FIELD_HINTS: Record<string, string> = {
  webhook_url: "https://hooks.slack.com/services/…", url: "https://…", base_url: "https://your-org.atlassian.net",
  instance_url: "https://your-instance.example.com", headers: '{"Authorization":"Bearer …"}',
  signing_secret: "16+ characters; signs each body (X-KMS-Signature)", index: "optional", sourcetype: "vecta:audit",
  dce_url: "https://<dce>.<region>.ingest.monitor.azure.com", dcr_immutable_id: "dcr-<32 hex>", stream_name: "Custom-VectaKMSAudit_CL",
  azure_tenant_id: "Entra directory (tenant) ID", tenant_id: "Entra directory (tenant) ID", client_id: "app registration (client) ID",
  client_secret: "client secret value", address: "siem.example.com:6514", server_name: "name on the collector's certificate",
  ca_pem: "-----BEGIN CERTIFICATE----- (the server's CA, if not publicly trusted)",
  git_url: "https://github.com (the hosting site; the token is sent only there)", token: "access token with read access",
  username: "account name", password: "account password", endpoint_url: "https://… (only for a non-default endpoint)",
  access_key_id: "access key ID", secret_access_key: "secret access key", session_token: "only for temporary keys",
  account_url: "https://<account>.blob.core.windows.net", sas_token: "sv=…&sp=rl&sig=… (read and list)",
  account_key: "storage account key (grants the whole account)", account_name: "storage account name", gcs_url: "https://storage.googleapis.com",
  role_arn: "arn:aws:iam::<account>:role/<name> (KMS is then called with the role's short-lived credentials)",
  external_id: "the role's external ID, if its trust policy requires one", region: "us-east-1",
  vault_url: "https://<vault>.vault.azure.net", vault_name: "key vault name",
  service_account_json: "the service account key file (JSON)", project_id: "project ID", location: "global", key_ring: "key ring name",
  tenancy_ocid: "ocid1.tenancy.oc1..", user_ocid: "ocid1.user.oc1..", fingerprint: "aa:bb:…", private_key_pem: "-----BEGIN PRIVATE KEY-----",
  private_key_passphrase: "only if the key is encrypted", compartment_id: "ocid1.compartment.oc1..", management_endpoint: "https://<vault>-management.kms.<region>.oraclecloud.com",
  access_key_secret: "access key secret", security_token: "Salesforce security token", login_url: "https://login.salesforce.com",
  options_json: '{"api_version":"7.4"} (provider options with no field of their own)',
  host: "smtp.example.com", port: "587 (STARTTLS) or 465 (TLS)", from: "kms@example.com",
  library_path: "/var/lib/vecta/hsm/providers/<tenant>/libCryptoki2.so", slot_id: "slot number (or use the token label)",
  token_label: "token or partition label", pin: "partition user PIN", vendor: "thales, securosys, entrust, utimaco, …",
  topology: "single HSM, or the vendor's HA group presented as one slot",
};

export const MULTILINE = new Set(["ca_pem", "headers", "service_account_json", "private_key_pem", "options_json"]);

export function fmtDate(iso?: string): string {
  if (!iso) return "-";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? "-" : d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

export function fmtAgo(iso?: string): string {
  if (!iso) return "-";
  const diff = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}
