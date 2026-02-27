import { useEffect, useMemo, useState } from "react";
import { Area, AreaChart, CartesianGrid, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { AuthSession } from "../lib/auth";
import { createKey, decryptData, encryptData, listKeys, rotateKey, signData, type KeyItem, verifyData } from "../lib/keycore";
import { serviceRequest } from "../lib/serviceApi";
import type { FeatureKey, TabId } from "../config/tabs";
import type { LiveEvent } from "../store/live";
import { Badge, Button, Panel, SelectInput, TextInput } from "./primitives";

type Props = {
  tabId: TabId;
  alerts: LiveEvent[];
  audit: LiveEvent[];
  enabledFeatures: Set<FeatureKey>;
  session: AuthSession;
};

type FieldSpec = {
  key: string;
  label: string;
  kind: "text" | "select" | "textarea";
  placeholder?: string;
  options?: string[];
};

type PanelSpec = {
  key: string;
  title: string;
  subtitle: string;
  fields?: FieldSpec[];
  actions?: string[];
  notes?: string[];
  table?: { columns: string[]; rows: string[][] };
};

type DashboardVM = {
  complianceScore: string;
  complianceNote: string;
  keyInventory: string;
  keyNote: string;
  activeAlerts: string;
  alertNote: string;
  clusterState: string;
  clusterNote: string;
  opsSeries: Array<{ hour: string; ops: number }>;
  algoSeries: Array<{ name: string; value: number }>;
};

const defaultDashboard: DashboardVM = {
  complianceScore: "n/a",
  complianceNote: "Awaiting compliance data",
  keyInventory: "0",
  keyNote: "No key inventory loaded",
  activeAlerts: "0",
  alertNote: "No alert data loaded",
  clusterState: "Unknown",
  clusterNote: "Awaiting service checks",
  opsSeries: [],
  algoSeries: []
};

const baseTabs: Record<TabId, PanelSpec[]> = {
  dashboard: [],
  keys: [
    {
      key: "key-inventory",
      title: "Key Inventory",
      subtitle: "Search, filter, rotate, and lifecycle actions",
      fields: [
        { key: "search", label: "Search", kind: "text", placeholder: "alias, key id, algorithm" },
        { key: "status", label: "Status", kind: "select", options: ["all", "active", "pre-active", "deactivated"] },
        { key: "algorithm", label: "Algorithm", kind: "select", options: ["all", "AES", "RSA", "ECDSA", "ML-KEM"] },
        {
          key: "csv_payload",
          label: "Bulk Import CSV",
          kind: "textarea",
          placeholder:
            "name,algorithm,key_type,purpose,material\nprod-db-aes,AES-256,symmetric,encrypt,ZmFrZS1tYXRlcmlhbC0x\nprod-db-rsa,RSA-2048,asymmetric,sign,ZmFrZS1tYXRlcmlhbC0y"
        }
      ],
      actions: ["Apply Filter", "Bulk Rotate", "Bulk Import CSV"]
    },
    {
      key: "key-create",
      title: "Key Creation Wizard",
      subtitle: "Algorithm, IV mode, rotation schedule, approval policy",
      fields: [
        { key: "key_alias", label: "Alias", kind: "text", placeholder: "prod-db-master" },
        { key: "purpose", label: "Purpose", kind: "select", options: ["encrypt_decrypt", "sign_verify", "wrap_unwrap"] },
        { key: "iv_mode", label: "IV Mode", kind: "select", options: ["random", "deterministic", "external"] },
        { key: "rotation", label: "Rotation", kind: "select", options: ["30d", "60d", "90d", "manual"] }
      ],
      actions: ["Create Key", "Set Approval Policy"]
    }
  ],
  crypto_console: [
    {
      key: "crypto-console",
      title: "Crypto Console",
      subtitle: "Interactive operation sandbox",
      fields: [
        { key: "key_id", label: "Key ID", kind: "text", placeholder: "key_xxx" },
        { key: "operation", label: "Operation", kind: "select", options: ["encrypt", "decrypt", "sign", "verify", "wrap", "unwrap"] },
        { key: "algorithm", label: "Algorithm", kind: "select", options: ["AES-256-GCM", "RSA-4096", "ECDSA-P384", "HMAC-SHA256"] },
        { key: "payload", label: "Payload", kind: "textarea", placeholder: "encrypt/sign: plain text\ndecrypt/unwrap: {\"ciphertext\":\"...\",\"iv\":\"...\"}\nverify: {\"data\":\"...\",\"signature\":\"...\"}" }
      ],
      actions: ["Execute", "Clear"]
    }
  ],
  vault: [
    {
      key: "vault-store",
      title: "Universal Secret Store",
      subtitle: "Import/export, version history, and TTL",
      fields: [
        { key: "secret_type", label: "Secret Type", kind: "select", options: ["ssh_private_key", "pgp", "x509", "api_token"] },
        { key: "secret_name", label: "Secret Name", kind: "text", placeholder: "prod/ssh/deploy" },
        { key: "secret_ttl", label: "TTL", kind: "select", options: ["1h", "24h", "7d", "never"] },
        { key: "secret_data", label: "Secret Data", kind: "textarea", placeholder: "paste secret payload" }
      ],
      actions: ["Store Secret", "Download Secret", "Version Diff"]
    }
  ],
  certificates: [
    {
      key: "cert-issue",
      title: "Certificate Issuance Wizard",
      subtitle: "ACME, EST, SCEP, CMPv2, and REST",
      fields: [
        { key: "protocol", label: "Protocol", kind: "select", options: ["REST", "ACME", "EST", "SCEP", "CMPv2"] },
        { key: "subject", label: "Subject", kind: "text", placeholder: "api.bank.local" },
        { key: "profile", label: "Profile", kind: "select", options: ["server_tls", "client_mtls", "code_signing", "pqc_hybrid"] }
      ],
      actions: ["Issue Certificate", "CRL/OCSP Status", "Expiry Calendar"]
    }
  ],
  tokenize_mask: [
    {
      key: "tokenize",
      title: "Tokenization and Masking",
      subtitle: "Deterministic tokenization, FPE, masking, redaction",
      fields: [
        { key: "input", label: "Input", kind: "text", placeholder: "4111111111111111" },
        { key: "mode", label: "Mode", kind: "select", options: ["deterministic", "irreversible", "fpe_ff1", "fpe_ff3_1"] },
        { key: "policy", label: "Policy", kind: "select", options: ["mask_last4", "email_mask", "pii_redact"] }
      ],
      actions: ["Tokenize", "Mask Preview", "Decrypt Field"]
    }
  ],
  payment: [
    {
      key: "payment-tools",
      title: "Payment Crypto Tools",
      subtitle: "TR-31 key blocks, PIN translation, ISO 20022 signing",
      fields: [
        { key: "tr31_header", label: "TR-31 Header", kind: "text", placeholder: "B0096P0TE00N0000" },
        { key: "pin_format", label: "PIN Format", kind: "select", options: ["ISO0", "ISO1", "ISO3", "ISO4"] },
        { key: "xml_ref", label: "ISO 20022 XML", kind: "text", placeholder: "pain.001.xml" }
      ],
      actions: ["Build TR-31", "Translate PIN", "Sign ISO 20022"]
    }
  ],
  byok: [{ key: "byok", title: "Cloud BYOK", subtitle: "Register cloud account and import key references", fields: [{ key: "provider", label: "Provider", kind: "select", options: ["aws", "azure", "gcp", "oci"] }, { key: "account", label: "Account", kind: "text", placeholder: "root-prod" }, { key: "external_ref", label: "External Key Ref", kind: "text", placeholder: "arn:aws:kms:..." }], actions: ["Register Account", "Sync Inventory"] }],
  hyok: [{ key: "hyok", title: "HYOK Proxy", subtitle: "Configure endpoints and authentication modes", fields: [{ key: "endpoint", label: "Endpoint", kind: "text", placeholder: "https://hyok.partner.local" }, { key: "auth_mode", label: "Auth Mode", kind: "select", options: ["mtls_or_jwt", "mtls_only", "jwt_only"] }, { key: "governance", label: "Governance", kind: "select", options: ["required", "optional"] }], actions: ["Save Endpoint", "Test Proxy"] }],
  ekm: [{ key: "ekm", title: "EKM Agent Hub", subtitle: "Agent registration and TDE key operations", fields: [{ key: "db_type", label: "Database", kind: "select", options: ["postgresql", "oracle", "mongodb", "mysql"] }, { key: "host", label: "Host", kind: "text", placeholder: "db01.bank.local" }, { key: "tenant", label: "Tenant", kind: "text", placeholder: "root" }], actions: ["Register Agent", "Issue TDE Key"] }],
  kmip: [{ key: "kmip", title: "KMIP Operations", subtitle: "Client registration and object workflow", fields: [{ key: "client_cn", label: "Client CN", kind: "text", placeholder: "tenant-root:kmip-client" }, { key: "operation", label: "Operation", kind: "select", options: ["register", "create", "get", "activate", "destroy"] }, { key: "object_id", label: "Object ID", kind: "text", placeholder: "optional" }], actions: ["Execute KMIP", "Session Diagnostics"] }],
  hsm_primus: [{ key: "hsm", title: "HSM", subtitle: "Hardware session pool and software vault fallback", fields: [{ key: "mode", label: "Mode", kind: "select", options: ["hardware", "software", "auto"] }, { key: "endpoint", label: "HSM Endpoint", kind: "text", placeholder: "hsm.local:2300" }, { key: "partition", label: "Partition", kind: "text", placeholder: "root" }], actions: ["Apply HSM Mode", "Test Wrap/Unwrap"] }],
  qkd: [{ key: "qkd", title: "QKD Interface", subtitle: "Quantum links and key exchange telemetry", notes: ["qkd-east-1 healthy, 18.2 Kbps, QBER 1.1%", "qkd-east-2 standby"], actions: ["Request Quantum Key", "Rotate Link Key"] }],
  mpc: [{ key: "mpc", title: "MPC Ceremonies", subtitle: "FROST / GG20 threshold orchestration", fields: [{ key: "protocol", label: "Protocol", kind: "select", options: ["frost", "gg20", "shamir_decrypt"] }, { key: "threshold", label: "Threshold", kind: "text", placeholder: "3" }, { key: "participants", label: "Participants", kind: "text", placeholder: "5" }], actions: ["Start Ceremony", "Generate Shares"] }],
  cluster: [{
    key: "cluster",
    title: "Cluster Health",
    subtitle: "Node status, leader election, replication lag",
    fields: [{ key: "cluster_action", label: "Requested Action", kind: "select", options: ["status", "quorum-test", "promote"] }],
    actions: ["Run Quorum Test", "Promote Follower"]
  }],
  approvals: [{
    key: "approvals",
    title: "Approval Queue",
    subtitle: "Pending governance approvals with quorum state",
    fields: [
      { key: "request_id", label: "Request ID", kind: "text", placeholder: "apr_xxx" },
      { key: "approver_email", label: "Approver Email", kind: "text", placeholder: "approver@bank.local" },
      { key: "vote_token", label: "Vote Token (optional)", kind: "text", placeholder: "token from email link (optional)" },
      { key: "comment", label: "Comment", kind: "text", placeholder: "approved from dashboard" }
    ],
    actions: ["Create Test Request", "Approve", "Deny", "Details", "Refresh Queue"]
  }],
  alert_center: [{ key: "alert_center", title: "Alert Center", subtitle: "Channels, rules, and real-time incident feed", fields: [{ key: "severity", label: "Severity", kind: "select", options: ["all", "critical", "warning", "info"] }, { key: "channel", label: "Channel", kind: "select", options: ["all", "email", "slack", "teams", "webhook", "pagerduty", "snmp", "proxy"] }], actions: ["Create Rule", "Mute Window"] }],
  audit_log: [{ key: "audit_log", title: "Audit Log", subtitle: "Filterable append-only stream and export controls", fields: [{ key: "source", label: "Source", kind: "select", options: ["all", "auth", "key", "compliance", "pkcs11", "dashboard"] }, { key: "window", label: "Window", kind: "select", options: ["15m", "1h", "24h", "7d"] }], actions: ["Apply Filter", "Export CSV"] }],
  compliance: [{ key: "compliance", title: "Compliance Frameworks", subtitle: "PCI DSS 4.0, FIPS 140-3, NIST 800-57, eIDAS", notes: ["PCI DSS 4.0: 91% (2 gaps)", "FIPS 140-3: 87% (0 critical)", "NIST 800-57: 89%", "eIDAS: 78% (1 critical)"], actions: ["View Gaps", "Generate Report"] }],
  sbom_cbom: [{ key: "sbom", title: "SBOM/CBOM", subtitle: "CycloneDX/SPDX export, CVE matching, BOM diff", notes: ["Packages: 1,842", "Critical CVEs: 0", "PQC-ready assets: 62%"], actions: ["Export CycloneDX", "Export SPDX", "Run BOM Diff"] }],
  pkcs11_jca: [{ key: "pkcs11", title: "PKCS#11/JCA", subtitle: "Provider clients and mechanism telemetry", table: { columns: ["Client", "Type", "Version", "Ops/min"], rows: [["openssl-gw-1", "PKCS#11", "3.0", "1120"], ["java-signer-2", "JCA", "1.2.5", "840"]] }, actions: ["List Clients", "Mechanism Stats"] }],
  administration: [
    {
      key: "admin-tenants",
      title: "Tenant Management",
      subtitle: "Create and list tenant records from Auth service",
      fields: [
        { key: "tenant_id", label: "Tenant ID", kind: "text", placeholder: "bank-beta" },
        { key: "tenant_name", label: "Tenant Name", kind: "text", placeholder: "Bank Beta" },
        { key: "tenant_status", label: "Status", kind: "select", options: ["active", "inactive"] }
      ],
      actions: ["Create Tenant", "List Tenants"]
    },
    {
      key: "admin-users",
      title: "User Management",
      subtitle: "Create users and update role assignments",
      fields: [
        { key: "user_id", label: "User ID", kind: "text", placeholder: "usr_xxx (for role update)" },
        { key: "username", label: "Username", kind: "text", placeholder: "ops-admin" },
        { key: "email", label: "Email", kind: "text", placeholder: "ops-admin@bank.local" },
        { key: "password", label: "Password", kind: "text", placeholder: "Min 12 characters" },
        { key: "role", label: "Role", kind: "text", placeholder: "tenant-admin" }
      ],
      actions: ["Create User", "List Users", "Update User Role"]
    },
    {
      key: "admin-governance",
      title: "SMTP / Approvals Settings",
      subtitle: "Configure governance SMTP settings and validate mail path",
      fields: [
        { key: "smtp_host", label: "SMTP Host", kind: "text", placeholder: "smtp.bank.local" },
        { key: "smtp_port", label: "SMTP Port", kind: "text", placeholder: "587" },
        { key: "smtp_username", label: "SMTP Username", kind: "text", placeholder: "approvals@bank.local" },
        { key: "smtp_password", label: "SMTP Password", kind: "text", placeholder: "app-password" },
        { key: "smtp_from", label: "SMTP From", kind: "text", placeholder: "Vecta KMS <approvals@bank.local>" },
        { key: "smtp_starttls", label: "SMTP STARTTLS", kind: "select", options: ["true", "false"] },
        { key: "approval_expiry_minutes", label: "Expiry Minutes", kind: "text", placeholder: "120" },
        { key: "smtp_test_to", label: "SMTP Test Recipient", kind: "text", placeholder: "soc@bank.local" }
      ],
      actions: ["Save SMTP Settings", "Test SMTP", "Load Governance Settings"]
    },
    {
      key: "admin-alert-channels",
      title: "Alert Channels (Email/SNMP/Webhook/Proxy)",
      subtitle: "Update channel config in reporting service",
      fields: [
        { key: "channel_name", label: "Channel", kind: "select", options: ["email", "pagerduty", "webhook", "snmp", "proxy"] },
        { key: "channel_enabled", label: "Enabled", kind: "select", options: ["true", "false"] },
        { key: "channel_endpoint", label: "Endpoint / Target", kind: "text", placeholder: "https://alerts.bank.local/hook" }
      ],
      actions: ["Load Channels", "Save Channel"]
    },
    {
      key: "admin-integrity",
      title: "FIPS / Cluster / Integrity",
      subtitle: "Operational checks tied to backend state",
      fields: [
        { key: "fips_mode", label: "FIPS Mode", kind: "select", options: ["enabled", "disabled"] },
        { key: "hsm_mode", label: "HSM Mode", kind: "select", options: ["hardware", "software", "auto"] },
        { key: "cluster_mode", label: "Cluster Mode", kind: "select", options: ["standalone", "ha", "degraded"] },
        { key: "license_key", label: "License Key", kind: "text", placeholder: "SEC-KMS-ENT-2026-XXXX" }
      ],
      actions: ["Save Security State", "Run Integrity Check", "Check Cluster", "Activate License"]
    },
    {
      key: "admin-platform",
      title: "Network / Proxy / SNMP",
      subtitle: "Persisted platform controls for management and cluster plane",
      fields: [
        { key: "mgmt_ip", label: "Management IP", kind: "text", placeholder: "10.0.1.100" },
        { key: "cluster_ip", label: "Cluster IP", kind: "text", placeholder: "172.16.0.100" },
        { key: "dns_servers", label: "DNS Servers", kind: "text", placeholder: "10.0.0.2,10.0.0.3" },
        { key: "ntp_servers", label: "NTP Servers", kind: "text", placeholder: "ntp.bank.local,ntp2.bank.local" },
        { key: "proxy_endpoint", label: "Proxy Endpoint", kind: "text", placeholder: "http://proxy.bank.local:8080" },
        { key: "snmp_target", label: "SNMP Target", kind: "text", placeholder: "udp://snmp.bank.local:162" }
      ],
      actions: ["Save Network", "Load Platform State"]
    },
    {
      key: "admin-tls",
      title: "TLS Configuration",
      subtitle: "Web/API certificate and trust chain settings",
      fields: [
        { key: "tls_mode", label: "TLS Mode", kind: "select", options: ["internal_ca", "uploaded", "acme"] },
        { key: "tls_cert_pem", label: "Certificate PEM", kind: "textarea", placeholder: "-----BEGIN CERTIFICATE-----" },
        { key: "tls_key_pem", label: "Private Key PEM", kind: "textarea", placeholder: "-----BEGIN PRIVATE KEY-----" },
        { key: "tls_ca_bundle_pem", label: "CA Bundle PEM", kind: "textarea", placeholder: "-----BEGIN CERTIFICATE-----" }
      ],
      actions: ["Save TLS Config", "Load TLS Config"]
    },
    {
      key: "admin-backup",
      title: "Backup Configuration",
      subtitle: "Backup scheduling, destination, and retention",
      fields: [
        { key: "backup_schedule", label: "Schedule", kind: "select", options: ["daily@02:00", "every_6h", "weekly", "manual"] },
        { key: "backup_target", label: "Target", kind: "select", options: ["local", "s3", "nfs"] },
        { key: "backup_retention_days", label: "Retention Days", kind: "text", placeholder: "30" },
        { key: "backup_encrypted", label: "Encrypted", kind: "select", options: ["true", "false"] }
      ],
      actions: ["Save Backup Config", "Load Backup Config"]
    }
  ]
};

function InputField(props: { spec: FieldSpec; value: string; onChange: (value: string) => void }) {
  const { spec, value, onChange } = props;
  if (spec.kind === "textarea") {
    return (
      <label className="block">
        <span className="mb-1 block text-xs uppercase tracking-wide text-cyber-muted">{spec.label}</span>
        <textarea value={value} onChange={(e) => onChange(e.target.value)} placeholder={spec.placeholder} className="h-24 w-full rounded-md border border-cyber-border bg-cyber-panel p-2 text-xs text-cyber-text" />
      </label>
    );
  }
  if (spec.kind === "select") {
    return (
      <label className="block">
        <span className="mb-1 block text-xs uppercase tracking-wide text-cyber-muted">{spec.label}</span>
        <SelectInput value={value || spec.options?.[0] || ""} onChange={onChange} options={spec.options || []} />
      </label>
    );
  }
  return (
    <label className="block">
      <span className="mb-1 block text-xs uppercase tracking-wide text-cyber-muted">{spec.label}</span>
      <TextInput value={value} onChange={onChange} placeholder={spec.placeholder} />
    </label>
  );
}

function DashboardPanels(props: { data: DashboardVM; loading: boolean }) {
  const { data, loading } = props;
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ["Compliance Posture", data.complianceScore, data.complianceNote],
          ["Key Inventory", data.keyInventory, data.keyNote],
          ["Active Alerts", data.activeAlerts, data.alertNote],
          ["Cluster", data.clusterState, data.clusterNote]
        ].map(([title, value, note]) => (
          <Panel key={title} title={title} subtitle={note}>
            <p className="font-heading text-3xl text-cyber-text">{value}</p>
          </Panel>
        ))}
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Recent Operations" subtitle="24h throughput trend">
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.opsSeries}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a3b52" />
                <XAxis dataKey="hour" stroke="#7ab7c4" />
                <YAxis stroke="#7ab7c4" />
                <Tooltip />
                <Area type="monotone" dataKey="ops" stroke="#18d2ff" fill="#18d2ff33" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Algorithm Distribution" subtitle="Portfolio mix">
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={data.algoSeries} dataKey="value" nameKey="name" outerRadius={88} fill="#18d2ff" />
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>
      {loading ? <p className="text-sm text-cyber-muted">Refreshing dashboard from live services...</p> : null}
    </div>
  );
}

function asMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return "Operation failed";
}

function mapPurpose(purpose: string): string {
  switch (purpose) {
    case "sign_verify":
      return "sign";
    case "wrap_unwrap":
      return "wrap";
    default:
      return "encrypt";
  }
}

function mapIVMode(ivMode: string): string {
  switch (ivMode) {
    case "random":
      return "internal";
    default:
      return ivMode || "internal";
  }
}

function parseJSONPayload(payload: string): Record<string, string> {
  const parsed = JSON.parse(payload) as Record<string, unknown>;
  return Object.fromEntries(Object.entries(parsed).map(([k, v]) => [k, String(v)]));
}

function encodeBase64(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let raw = "";
  for (const b of bytes) {
    raw += String.fromCharCode(b);
  }
  return btoa(raw);
}

function isBase64String(value: string): boolean {
  if (!value || value.length % 4 !== 0) {
    return false;
  }
  try {
    return btoa(atob(value)) === value;
  } catch {
    return false;
  }
}

function parseCSVLine(line: string): string[] {
  const cells: string[] = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (ch === "," && !inQuotes) {
      cells.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  cells.push(current.trim());
  return cells;
}

function parseBulkImportRows(csv: string, tenantID: string, createdBy: string): Array<Record<string, unknown>> {
  const lines = csv
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (!lines.length) {
    throw new Error("csv_payload is required");
  }

  const first = parseCSVLine(lines[0]).map((c) => c.toLowerCase());
  const hasHeader = first.includes("name") && first.includes("algorithm");
  const dataLines = hasHeader ? lines.slice(1) : lines;
  const rows: Array<Record<string, unknown>> = [];

  dataLines.forEach((line, index) => {
    const cols = parseCSVLine(line);
    if (cols.length < 5) {
      throw new Error(`Invalid CSV row ${index + 1}: expected 5 columns (name,algorithm,key_type,purpose,material)`);
    }
    const [nameRaw, algorithmRaw, keyTypeRaw, purposeRaw, materialRaw] = cols;
    const name = nameRaw.trim();
    const algorithm = algorithmRaw.trim() || "AES-256";
    const keyType = keyTypeRaw.trim() || "symmetric";
    const purpose = purposeRaw.trim() || "encrypt";
    if (!name) {
      throw new Error(`Invalid CSV row ${index + 1}: name is required`);
    }
    const material = materialRaw.trim();
    rows.push({
      tenant_id: tenantID,
      name,
      algorithm,
      key_type: keyType,
      purpose,
      iv_mode: "internal",
      created_by: createdBy,
      material: isBase64String(material) ? material : encodeBase64(material || `${name}-${Date.now()}`)
    });
  });
  return rows;
}

function asNumber(input: unknown, fallback = 0): number {
  if (typeof input === "number" && Number.isFinite(input)) {
    return input;
  }
  if (typeof input === "string") {
    const n = Number(input);
    if (Number.isFinite(n)) {
      return n;
    }
  }
  return fallback;
}

function toHour(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.valueOf())) {
    return "unknown";
  }
  return `${String(d.getHours()).padStart(2, "0")}:00`;
}

function buildOpsSeries(events: Array<{ timestamp?: string }>): Array<{ hour: string; ops: number }> {
  const bucket = new Map<string, number>();
  for (const item of events) {
    if (!item.timestamp) {
      continue;
    }
    const hour = toHour(item.timestamp);
    bucket.set(hour, (bucket.get(hour) || 0) + 1);
  }
  const out = Array.from(bucket.entries()).map(([hour, ops]) => ({ hour, ops }));
  out.sort((a, b) => a.hour.localeCompare(b.hour));
  return out;
}

function buildAlgoSeries(items: KeyItem[]): Array<{ name: string; value: number }> {
  const bucket = new Map<string, number>();
  for (const item of items) {
    const name = item.algorithm || "unknown";
    bucket.set(name, (bucket.get(name) || 0) + 1);
  }
  return Array.from(bucket.entries())
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 8);
}

export function TabView(props: Props) {
  const { tabId, alerts, audit, enabledFeatures, session } = props;
  const [values, setValues] = useState<Record<string, string>>({});
  const [busyAction, setBusyAction] = useState<string>("");
  const [actionMessage, setActionMessage] = useState<string>("");
  const [keys, setKeys] = useState<KeyItem[]>([]);
  const [selectedKeyID, setSelectedKeyID] = useState<string>("");
  const [dashboard, setDashboard] = useState<DashboardVM>(defaultDashboard);
  const [dashboardLoading, setDashboardLoading] = useState<boolean>(false);
  const [panelData, setPanelData] = useState<Record<string, unknown>>({});
  const specs = baseTabs[tabId] ?? [];

  const alertRows = useMemo(() => (alerts.length ? alerts.slice(0, 12) : []), [alerts]);
  const auditRows = useMemo(() => (audit.length ? audit.slice(0, 20) : []), [audit]);

  const readField = (panelKey: string, fieldKey: string): string => values[`${panelKey}.${fieldKey}`] ?? "";
  const writeField = (panelKey: string, fieldKey: string, next: string): void => {
    setValues((prev) => ({ ...prev, [`${panelKey}.${fieldKey}`]: next }));
  };
  const writeFields = (panelKey: string, fields: Record<string, string>): void => {
    setValues((prev) => {
      const next = { ...prev };
      Object.entries(fields).forEach(([key, value]) => {
        next[`${panelKey}.${key}`] = value ?? "";
      });
      return next;
    });
  };

  const hydrateSystemStateFields = (state: Record<string, unknown>): void => {
    writeFields("admin-integrity", {
      fips_mode: String(state.fips_mode || "disabled"),
      hsm_mode: String(state.hsm_mode || "software"),
      cluster_mode: String(state.cluster_mode || "standalone"),
      license_key: String(state.license_key || "")
    });
    writeFields("admin-platform", {
      mgmt_ip: String(state.mgmt_ip || ""),
      cluster_ip: String(state.cluster_ip || ""),
      dns_servers: String(state.dns_servers || ""),
      ntp_servers: String(state.ntp_servers || ""),
      proxy_endpoint: String(state.proxy_endpoint || ""),
      snmp_target: String(state.snmp_target || "")
    });
    writeFields("admin-tls", {
      tls_mode: String(state.tls_mode || "internal_ca"),
      tls_cert_pem: String(state.tls_cert_pem || ""),
      tls_key_pem: String(state.tls_key_pem || ""),
      tls_ca_bundle_pem: String(state.tls_ca_bundle_pem || "")
    });
    writeFields("admin-backup", {
      backup_schedule: String(state.backup_schedule || "daily@02:00"),
      backup_target: String(state.backup_target || "local"),
      backup_retention_days: String(state.backup_retention_days || "30"),
      backup_encrypted: String(state.backup_encrypted ?? true)
    });
  };

  const refreshKeys = async (applyFilters: boolean): Promise<void> => {
    const all = await listKeys(session);
    if (!applyFilters) {
      setKeys(all);
      return;
    }

    const q = readField("key-inventory", "search").trim().toLowerCase();
    const status = readField("key-inventory", "status").trim().toLowerCase();
    const alg = readField("key-inventory", "algorithm").trim().toLowerCase();

    const filtered = all.filter((item) => {
      if (q && !item.id.toLowerCase().includes(q) && !item.name.toLowerCase().includes(q) && !item.algorithm.toLowerCase().includes(q)) {
        return false;
      }
      if (status && status !== "all" && item.status.toLowerCase() !== status) {
        return false;
      }
      if (alg && alg !== "all" && !item.algorithm.toLowerCase().includes(alg)) {
        return false;
      }
      return true;
    });

    setKeys(filtered);
  };

  const loadDashboard = async (): Promise<void> => {
    setDashboardLoading(true);
    try {
      const [allKeys, postureResp, eventsResp, alertStatsResp, integrityResp] = await Promise.all([
        listKeys(session),
        serviceRequest<{ posture?: Record<string, unknown> }>(session, "compliance", `/compliance/posture?tenant_id=${encodeURIComponent(session.tenantId)}`),
        serviceRequest<{ items?: Array<{ timestamp?: string }> }>(session, "audit", `/audit/events?tenant_id=${encodeURIComponent(session.tenantId)}&limit=300`),
        serviceRequest<{ stats?: Record<string, unknown> }>(session, "reporting", `/alerts/stats?tenant_id=${encodeURIComponent(session.tenantId)}`),
        serviceRequest<{ integrity?: Record<string, unknown> }>(session, "governance", `/governance/system/integrity?tenant_id=${encodeURIComponent(session.tenantId)}`)
      ]);

      const posture = postureResp.posture || {};
      const score = asNumber((posture as Record<string, unknown>).overall_score ?? (posture as Record<string, unknown>).score, 0);
      const events = eventsResp.items || [];
      const stats = alertStatsResp.stats || {};
      const openAlerts = asNumber((stats as Record<string, unknown>).open ?? (stats as Record<string, unknown>).open_count ?? (stats as Record<string, unknown>).active, 0);
      const integrity = integrityResp.integrity || {};
      const clusterState = String((integrity as Record<string, unknown>).status || "degraded");
      const checks = ((integrity as Record<string, unknown>).checks as Record<string, unknown> | undefined) || {};
      const configuredChecks = Object.values(checks).filter((v) => String(v) === "configured" || String(v) === "active" || String(v) === "ok").length;
      const totalChecks = Object.keys(checks).length;
      setDashboard({
        complianceScore: `${score}/100`,
        complianceNote: "Live posture from compliance service",
        keyInventory: String(allKeys.length),
        keyNote: `${allKeys.filter((k) => k.status === "active").length} active`,
        activeAlerts: String(openAlerts),
        alertNote: "Live alert telemetry",
        clusterState: clusterState === "healthy" ? "Healthy" : "Degraded",
        clusterNote: totalChecks ? `${configuredChecks}/${totalChecks} integrity checks passing` : "Integrity status unavailable",
        opsSeries: buildOpsSeries(events),
        algoSeries: buildAlgoSeries(allKeys)
      });
    } catch {
      setDashboard((prev) => ({
        ...prev,
        clusterState: "Degraded",
        clusterNote: "One or more services unreachable"
      }));
    } finally {
      setDashboardLoading(false);
    }
  };

  useEffect(() => {
    if (tabId !== "keys" && tabId !== "crypto_console") {
      return;
    }
    refreshKeys(false).catch(() => {
      // no-op, surfaced on action when user interacts
    });
  }, [tabId]);

  useEffect(() => {
    if (!selectedKeyID && keys[0]) {
      setSelectedKeyID(keys[0].id);
      writeField("crypto-console", "key_id", keys[0].id);
    }
  }, [keys, selectedKeyID]);

  useEffect(() => {
    if (tabId === "dashboard") {
      loadDashboard().catch(() => {
        // surfaced via degraded status
      });
      return;
    }

    if (tabId === "approvals") {
      serviceRequest<{ items?: unknown[] }>(session, "governance", `/governance/requests?tenant_id=${encodeURIComponent(session.tenantId)}&status=pending`)
        .then((resp) => setPanelData((prev) => ({ ...prev, approvals: resp.items || [] })))
        .catch(() => {
          // no-op
        });
      return;
    }

    if (tabId === "alert_center") {
      serviceRequest<{ items?: unknown[] }>(session, "reporting", `/alerts?tenant_id=${encodeURIComponent(session.tenantId)}&limit=30`)
        .then((resp) => setPanelData((prev) => ({ ...prev, alert_center: resp.items || [] })))
        .catch(() => {
          // no-op
        });
      return;
    }

    if (tabId === "audit_log") {
      serviceRequest<{ items?: unknown[] }>(session, "audit", `/audit/events?tenant_id=${encodeURIComponent(session.tenantId)}&limit=50`)
        .then((resp) => setPanelData((prev) => ({ ...prev, audit_log: resp.items || [] })))
        .catch(() => {
          // no-op
        });
      return;
    }

    if (tabId === "administration") {
      Promise.all([
        serviceRequest<{ settings?: Record<string, unknown> }>(session, "governance", `/governance/settings?tenant_id=${encodeURIComponent(session.tenantId)}`),
        serviceRequest<{ items?: Array<Record<string, unknown>> }>(session, "reporting", `/alerts/channels?tenant_id=${encodeURIComponent(session.tenantId)}`),
        serviceRequest<{ state?: Record<string, unknown> }>(session, "governance", `/governance/system/state?tenant_id=${encodeURIComponent(session.tenantId)}`),
        serviceRequest<{ integrity?: Record<string, unknown> }>(session, "governance", `/governance/system/integrity?tenant_id=${encodeURIComponent(session.tenantId)}`)
      ])
        .then(([settingsResp, channelsResp, stateResp, integrityResp]) => {
          const settings = settingsResp.settings || {};
          const channels = channelsResp.items || [];
          const state = stateResp.state || {};
          setPanelData((prev) => ({
            ...prev,
            "admin-governance": settingsResp,
            "admin-alert-channels": { items: channels },
            "admin-platform": stateResp,
            "admin-integrity": integrityResp
          }));
          writeFields("admin-governance", {
            smtp_host: String(settings.smtp_host || ""),
            smtp_port: String(settings.smtp_port || "587"),
            smtp_username: String(settings.smtp_username || ""),
            smtp_password: "",
            smtp_from: String(settings.smtp_from || ""),
            smtp_starttls: String(settings.smtp_starttls ?? true),
            approval_expiry_minutes: String(settings.approval_expiry_minutes || "120")
          });
          const firstChannel = channels[0] || {};
          writeFields("admin-alert-channels", {
            channel_name: String(firstChannel.name || "email"),
            channel_enabled: String(firstChannel.enabled ?? true),
            channel_endpoint: String(((firstChannel.config as Record<string, unknown> | undefined)?.endpoint as string) || "")
          });
          hydrateSystemStateFields(state);
        })
        .catch(() => {
          // no-op
        });
      return;
    }

    if (tabId === "hsm_primus" || tabId === "cluster") {
      serviceRequest<{ state?: Record<string, unknown> }>(session, "governance", `/governance/system/state?tenant_id=${encodeURIComponent(session.tenantId)}`)
        .then((resp) => {
          const state = resp.state || {};
          if (tabId === "hsm_primus") {
            writeField("hsm", "mode", String(state.hsm_mode || "software"));
          }
          if (tabId === "cluster") {
            writeField("cluster", "cluster_action", "status");
            setPanelData((prev) => ({ ...prev, cluster: resp }));
          }
        })
        .catch(() => {
          // no-op
        });
      return;
    }
  }, [tabId, session]);

  const handleAction = async (panelKey: string, action: string): Promise<void> => {
    setBusyAction(`${panelKey}:${action}`);
    setActionMessage("");
    try {
      switch (`${panelKey}:${action}`) {
        case "key-inventory:Apply Filter": {
          await refreshKeys(true);
          setActionMessage("Key inventory refreshed.");
          break;
        }
        case "key-inventory:Bulk Rotate": {
          const keyID = selectedKeyID || readField("crypto-console", "key_id").trim();
          if (!keyID) {
            throw new Error("Select a key from inventory first");
          }
          await rotateKey(session, keyID, "manual");
          await refreshKeys(false);
          setActionMessage(`Rotation requested for ${keyID}.`);
          break;
        }
        case "key-inventory:Bulk Import CSV": {
          const csv = readField("key-inventory", "csv_payload");
          const rows = parseBulkImportRows(csv, session.tenantId, session.username);
          const out = await serviceRequest<Record<string, unknown>>(session, "keycore", "/keys/bulk-import", {
            method: "POST",
            body: JSON.stringify(rows)
          });
          await refreshKeys(false);
          setPanelData((prev) => ({ ...prev, "key-inventory": out }));
          setActionMessage(`Bulk import submitted (${rows.length} rows).`);
          break;
        }
        case "key-create:Create Key": {
          const alias = readField("key-create", "key_alias").trim();
          if (!alias) {
            throw new Error("Alias is required");
          }
          const created = await createKey(session, {
            name: alias,
            algorithm: "AES-256",
            key_type: "symmetric",
            purpose: mapPurpose(readField("key-create", "purpose")),
            iv_mode: mapIVMode(readField("key-create", "iv_mode")),
            created_by: session.username
          });
          await refreshKeys(false);
          setSelectedKeyID(created.key_id);
          writeField("crypto-console", "key_id", created.key_id);
          setActionMessage(`Created key ${created.key_id} (KCV: ${created.kcv}).`);
          break;
        }
        case "key-create:Set Approval Policy": {
          const keyID = selectedKeyID || readField("crypto-console", "key_id").trim();
          if (!keyID) {
            throw new Error("Select a key first to apply approval policy");
          }
          const out = await serviceRequest<Record<string, unknown>>(session, "keycore", `/keys/${encodeURIComponent(keyID)}/approval`, {
            method: "PUT",
            body: JSON.stringify({ tenant_id: session.tenantId, required: true, policy_id: "" })
          });
          setPanelData((prev) => ({ ...prev, "key-create": out }));
          setActionMessage(`Approval requirement enabled for ${keyID}.`);
          break;
        }
        case "crypto-console:Execute": {
          const keyID = readField("crypto-console", "key_id").trim() || selectedKeyID;
          if (!keyID) {
            throw new Error("Key ID is required");
          }
          const operation = (readField("crypto-console", "operation") || "encrypt").toLowerCase();
          const payload = readField("crypto-console", "payload");

          if (operation === "encrypt" || operation === "wrap") {
            const out = await encryptData(session, keyID, payload);
            const response = { ciphertext: out.ciphertext, iv: out.iv, version: out.version, key_id: out.keyId };
            writeField("crypto-console", "payload", JSON.stringify(response, null, 2));
            setActionMessage(`Encrypt succeeded for ${out.keyId} (v${out.version}).`);
            break;
          }

          if (operation === "decrypt" || operation === "unwrap") {
            const parsed = parseJSONPayload(payload);
            const ciphertext = parsed.ciphertext || "";
            const iv = parsed.iv || "";
            if (!ciphertext || !iv) {
              throw new Error("Decrypt payload must include JSON fields: ciphertext and iv");
            }
            const out = await decryptData(session, keyID, ciphertext, iv);
            writeField("crypto-console", "payload", out.plaintext);
            setActionMessage(`Decrypt succeeded for ${out.keyId} (v${out.version}).`);
            break;
          }

          if (operation === "sign") {
            const out = await signData(session, keyID, payload);
            writeField("crypto-console", "payload", JSON.stringify({ data: payload, signature: out.signature }, null, 2));
            setActionMessage(`Sign succeeded for ${out.key_id} (v${out.version}).`);
            break;
          }

          if (operation === "verify") {
            const parsed = parseJSONPayload(payload);
            const data = parsed.data || "";
            const signature = parsed.signature || "";
            if (!data || !signature) {
              throw new Error("Verify payload must include JSON fields: data and signature");
            }
            const out = await verifyData(session, keyID, data, signature);
            setActionMessage(`Verify ${out.verified ? "succeeded" : "failed"} for ${out.key_id} (v${out.version}).`);
            break;
          }

          throw new Error(`Unsupported operation: ${operation}`);
        }
        case "crypto-console:Clear": {
          writeField("crypto-console", "payload", "");
          setActionMessage("Console payload cleared.");
          break;
        }
        case "vault-store:Store Secret": {
          const rawType = readField("vault-store", "secret_type").trim().toLowerCase();
          const mappedType =
            rawType === "pgp" ? "pgp_private_key" : rawType === "x509" ? "x509_certificate" : rawType === "api_token" ? "token" : rawType || "token";
          const ttl = readField("vault-store", "secret_ttl").trim().toLowerCase();
          const ttlSeconds = ttl === "1h" ? 3600 : ttl === "24h" ? 86400 : ttl === "7d" ? 7 * 86400 : 0;
          const secret = await serviceRequest<Record<string, unknown>>(session, "secrets", "/secrets", {
            method: "POST",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              name: readField("vault-store", "secret_name"),
              secret_type: mappedType,
              value: readField("vault-store", "secret_data"),
              lease_ttl_seconds: ttlSeconds,
              created_by: session.username
            })
          });
          setPanelData((prev) => ({ ...prev, "vault-store": secret }));
          setActionMessage("Secret stored successfully.");
          break;
        }
        case "vault-store:Download Secret": {
          const secretName = readField("vault-store", "secret_name").trim();
          const listed = await serviceRequest<{ items?: Array<{ id?: string; name?: string }> }>(
            session,
            "secrets",
            `/secrets?tenant_id=${encodeURIComponent(session.tenantId)}&limit=200`
          );
          const selected = (listed.items || []).find((item) => (item.name || "").toLowerCase() === secretName.toLowerCase());
          if (!selected?.id) {
            throw new Error("Secret not found by name");
          }
          const value = await serviceRequest<Record<string, unknown>>(
            session,
            "secrets",
            `/secrets/${encodeURIComponent(selected.id)}/value?tenant_id=${encodeURIComponent(session.tenantId)}`
          );
          writeField("vault-store", "secret_data", String(value.value || ""));
          setPanelData((prev) => ({ ...prev, "vault-store": value }));
          setActionMessage(`Loaded secret value for ${secretName}.`);
          break;
        }
        case "vault-store:Version Diff": {
          const listed = await serviceRequest<Record<string, unknown>>(session, "secrets", `/secrets?tenant_id=${encodeURIComponent(session.tenantId)}&limit=200`);
          setPanelData((prev) => ({ ...prev, "vault-store": listed }));
          setActionMessage("Loaded latest secret inventory for version review.");
          break;
        }
        case "cert-issue:Issue Certificate": {
          const caList = await serviceRequest<{ items?: Array<{ id?: string }> }>(session, "certs", `/certs/ca?tenant_id=${encodeURIComponent(session.tenantId)}`);
          const caID = caList.items?.[0]?.id;
          if (!caID) {
            throw new Error("No CA available. Create a CA first in Certificates service.");
          }
          const cert = await serviceRequest<Record<string, unknown>>(session, "certs", "/certs", {
            method: "POST",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              ca_id: caID,
              subject_cn: readField("cert-issue", "subject"),
              cert_type: readField("cert-issue", "profile") || "server_tls",
              algorithm: "RSA-2048",
              protocol: readField("cert-issue", "protocol") || "REST",
              validity_days: 365
            })
          });
          setPanelData((prev) => ({ ...prev, "cert-issue": cert }));
          setActionMessage("Certificate issuance request submitted.");
          break;
        }
        case "cert-issue:CRL/OCSP Status": {
          const [crl, ocsp] = await Promise.all([
            serviceRequest<Record<string, unknown>>(session, "certs", `/certs/crl?tenant_id=${encodeURIComponent(session.tenantId)}`),
            serviceRequest<Record<string, unknown>>(session, "certs", `/certs/ocsp?tenant_id=${encodeURIComponent(session.tenantId)}`)
          ]);
          setPanelData((prev) => ({ ...prev, "cert-issue": { crl, ocsp } }));
          setActionMessage("Loaded CRL and OCSP status.");
          break;
        }
        case "cert-issue:Expiry Calendar": {
          const inventory = await serviceRequest<Record<string, unknown>>(session, "certs", `/certs/inventory?tenant_id=${encodeURIComponent(session.tenantId)}`);
          setPanelData((prev) => ({ ...prev, "cert-issue": inventory }));
          setActionMessage("Loaded certificate inventory.");
          break;
        }
        case "tokenize:Tokenize": {
          const vaults = await serviceRequest<{ items?: Array<{ id?: string }> }>(session, "dataprotect", `/token-vaults?tenant_id=${encodeURIComponent(session.tenantId)}&limit=10`);
          let vaultID = vaults.items?.[0]?.id || "";
          if (!vaultID) {
            const keyID = selectedKeyID || keys[0]?.id;
            if (!keyID) {
              throw new Error("Create/select a key before tokenization.");
            }
            const created = await serviceRequest<{ vault?: { id?: string } }>(session, "dataprotect", "/token-vaults", {
              method: "POST",
              body: JSON.stringify({
                tenant_id: session.tenantId,
                name: "dashboard-default-vault",
                token_type: "generic",
                format: "plain",
                key_id: keyID
              })
            });
            vaultID = created.vault?.id || "";
          }
          const tokenized = await serviceRequest<Record<string, unknown>>(session, "dataprotect", "/tokenize", {
            method: "POST",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              vault_id: vaultID,
              values: [readField("tokenize", "input")],
              ttl_hours: 24
            })
          });
          setPanelData((prev) => ({ ...prev, tokenize: tokenized }));
          setActionMessage("Tokenization completed.");
          break;
        }
        case "tokenize:Mask Preview": {
          const masked = await serviceRequest<Record<string, unknown>>(session, "dataprotect", "/mask/preview", {
            method: "POST",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              policy_id: readField("tokenize", "policy"),
              data: { field: readField("tokenize", "input") },
              role: "tenant-admin"
            })
          });
          setPanelData((prev) => ({ ...prev, tokenize: masked }));
          setActionMessage("Mask preview completed.");
          break;
        }
        case "tokenize:Decrypt Field": {
          const values = readField("tokenize", "input")
            .split(",")
            .map((v) => v.trim())
            .filter(Boolean);
          const clear = await serviceRequest<Record<string, unknown>>(session, "dataprotect", "/detokenize", {
            method: "POST",
            body: JSON.stringify({ tenant_id: session.tenantId, tokens: values })
          });
          setPanelData((prev) => ({ ...prev, tokenize: clear }));
          setActionMessage("Detokenization completed.");
          break;
        }
        case "payment-tools:Build TR-31": {
          const keyID = selectedKeyID || keys[0]?.id;
          if (!keyID) {
            throw new Error("Select a key first for TR-31 operations.");
          }
          const out = await serviceRequest<Record<string, unknown>>(session, "payment", "/payment/tr31/create", {
            method: "POST",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              key_id: keyID,
              tr31_version: "B",
              algorithm: "AES",
              usage_code: "P0",
              mode_of_use: "E",
              key_version_num: "01",
              exportability: "N",
              source_format: "hex",
              material_b64: btoa(readField("payment-tools", "tr31_header") || "vecta")
            })
          });
          setPanelData((prev) => ({ ...prev, "payment-tools": out }));
          setActionMessage("TR-31 block generation completed.");
          break;
        }
        case "payment-tools:Translate PIN": {
          const out = await serviceRequest<Record<string, unknown>>(session, "payment", "/payment/pin/translate", {
            method: "POST",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              source_format: readField("payment-tools", "pin_format") || "ISO0",
              target_format: "ISO1",
              pin_block: readField("payment-tools", "tr31_header") || "1234",
              zpk_key_id: selectedKeyID || keys[0]?.id || ""
            })
          });
          setPanelData((prev) => ({ ...prev, "payment-tools": out }));
          setActionMessage("PIN translation completed.");
          break;
        }
        case "payment-tools:Sign ISO 20022": {
          const keyID = selectedKeyID || keys[0]?.id;
          if (!keyID) {
            throw new Error("Select a key first for ISO 20022 signing.");
          }
          const out = await serviceRequest<Record<string, unknown>>(session, "payment", "/payment/iso20022/sign", {
            method: "POST",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              key_id: keyID,
              xml: readField("payment-tools", "xml_ref") || "<Document/>"
            })
          });
          setPanelData((prev) => ({ ...prev, "payment-tools": out }));
          setActionMessage("ISO 20022 signature operation completed.");
          break;
        }
        case "byok:Register Account": {
          const out = await serviceRequest<Record<string, unknown>>(session, "cloud", "/cloud/accounts", {
            method: "POST",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              provider: readField("byok", "provider") || "aws",
              name: readField("byok", "account") || "default-account",
              default_region: "us-east-1",
              credentials_json: "{}"
            })
          });
          const account = (out.account as { id?: string; name?: string } | undefined) || {};
          if (account.id) {
            writeField("byok", "account", account.id);
          }
          setPanelData((prev) => ({ ...prev, byok: out }));
          setActionMessage(`Cloud account registered${account.id ? ` (${account.id})` : ""}.`);
          break;
        }
        case "byok:Sync Inventory": {
          const provider = readField("byok", "provider") || "aws";
          const accountHint = readField("byok", "account") || "";
          const accountList = await serviceRequest<{ items?: Array<{ id?: string; name?: string }> }>(
            session,
            "cloud",
            `/cloud/accounts?tenant_id=${encodeURIComponent(session.tenantId)}&provider=${encodeURIComponent(provider)}`
          );
          const accounts = accountList.items || [];
          const matchedAccount = accounts.find((a) => a.id === accountHint || a.name === accountHint);
          const accountID = matchedAccount?.id || accounts[0]?.id || accountHint;
          if (!accountID) {
            throw new Error("Register a cloud account before running sync.");
          }
          const [job, inventory] = await Promise.all([
            serviceRequest<Record<string, unknown>>(session, "cloud", "/cloud/sync", {
              method: "POST",
              body: JSON.stringify({
                tenant_id: session.tenantId,
                provider,
                account_id: accountID,
                mode: "full"
              })
            }),
            serviceRequest<Record<string, unknown>>(
              session,
              "cloud",
              `/cloud/inventory?tenant_id=${encodeURIComponent(session.tenantId)}&provider=${encodeURIComponent(provider)}&account_id=${encodeURIComponent(accountID)}`
            )
          ]);
          writeField("byok", "account", accountID);
          setPanelData((prev) => ({ ...prev, byok: { job, inventory } }));
          setActionMessage("BYOK sync completed.");
          break;
        }
        case "hyok:Save Endpoint": {
          const out = await serviceRequest<Record<string, unknown>>(session, "hyok", "/hyok/v1/endpoints/generic", {
            method: "PUT",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              enabled: true,
              auth_mode: readField("hyok", "auth_mode") || "mtls_or_jwt",
              governance_required: (readField("hyok", "governance") || "required") === "required",
              metadata_json: JSON.stringify({ endpoint: readField("hyok", "endpoint") })
            })
          });
          setPanelData((prev) => ({ ...prev, hyok: out }));
          setActionMessage("HYOK endpoint saved.");
          break;
        }
        case "hyok:Test Proxy": {
          const out = await serviceRequest<Record<string, unknown>>(session, "hyok", `/hyok/v1/health?tenant_id=${encodeURIComponent(session.tenantId)}`);
          setPanelData((prev) => ({ ...prev, hyok: out }));
          setActionMessage("HYOK health check completed.");
          break;
        }
        case "ekm:Register Agent": {
          const out = await serviceRequest<Record<string, unknown>>(session, "ekm", "/ekm/agents/register", {
            method: "POST",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              name: readField("ekm", "tenant") || "dashboard-agent",
              role: "tde-agent",
              db_engine: readField("ekm", "db_type") || "postgresql",
              host: readField("ekm", "host") || "localhost",
              version: "1.0.0"
            })
          });
          setPanelData((prev) => ({ ...prev, ekm: out }));
          setActionMessage("EKM agent registered.");
          break;
        }
        case "ekm:Issue TDE Key": {
          const out = await serviceRequest<Record<string, unknown>>(session, "ekm", "/ekm/tde/keys", {
            method: "POST",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              name: `tde-${Date.now()}`,
              algorithm: "RSA-3072",
              created_by: session.username
            })
          });
          setPanelData((prev) => ({ ...prev, ekm: out }));
          setActionMessage("TDE key issued.");
          break;
        }
        case "approvals:Refresh Queue": {
          const items = await serviceRequest<Record<string, unknown>>(session, "governance", `/governance/requests?tenant_id=${encodeURIComponent(session.tenantId)}&status=pending`);
          setPanelData((prev) => ({ ...prev, approvals: items }));
          setActionMessage("Approval queue refreshed.");
          break;
        }
        case "approvals:Create Test Request": {
          const approverEmail = readField("approvals", "approver_email").trim().toLowerCase();
          if (!approverEmail) {
            throw new Error("approver_email is required");
          }
          const keyID = selectedKeyID || keys[0]?.id;
          if (!keyID) {
            throw new Error("Create/select a key before creating an approval request");
          }
          const policies = await serviceRequest<{ items?: Array<{ id?: string }> }>(
            session,
            "governance",
            `/governance/policies?tenant_id=${encodeURIComponent(session.tenantId)}&status=active&scope=key`
          );
          let policyID = policies.items?.[0]?.id || "";
          if (!policyID) {
            const createdPolicy = await serviceRequest<{ policy?: { id?: string } }>(session, "governance", "/governance/policies", {
              method: "POST",
              body: JSON.stringify({
                tenant_id: session.tenantId,
                name: "dashboard-key-approval",
                description: "Dashboard default key approval policy",
                scope: "key",
                trigger_actions: ["key.rotate"],
                required_approvals: 1,
                total_approvers: 1,
                approver_roles: [],
                approver_users: [approverEmail],
                timeout_hours: 48,
                retention_days: 90,
                notification_channels: ["email"],
                status: "active"
              })
            });
            policyID = createdPolicy.policy?.id || "";
          }
          if (!policyID) {
            throw new Error("Unable to resolve an active key approval policy.");
          }
          const out = await serviceRequest<Record<string, unknown>>(session, "governance", "/governance/key-approval", {
            method: "POST",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              key_id: keyID,
              operation: "rotate",
              payload_hash: `dashboard-${Date.now()}`,
              requester_id: session.username,
              requester_email: `${session.username}@bank.local`,
              callback_service: "keycore",
              callback_action: "rotate",
              callback_payload: {}
            })
          });
          const requestID = String(((out.request as { id?: string } | undefined)?.id) || "");
          if (requestID) {
            writeField("approvals", "request_id", requestID);
          }
          setPanelData((prev) => ({ ...prev, approvals: out }));
          setActionMessage(`Created approval request${requestID ? ` ${requestID}` : ""}.`);
          break;
        }
        case "approvals:Details": {
          const reqID = readField("approvals", "request_id").trim();
          if (!reqID) {
            throw new Error("request_id is required");
          }
          const details = await serviceRequest<Record<string, unknown>>(session, "governance", `/governance/requests/${encodeURIComponent(reqID)}?tenant_id=${encodeURIComponent(session.tenantId)}`);
          setPanelData((prev) => ({ ...prev, approvals: details }));
          setActionMessage(`Loaded approval request ${reqID}.`);
          break;
        }
        case "approvals:Approve":
        case "approvals:Deny": {
          const reqID = readField("approvals", "request_id").trim();
          if (!reqID) {
            throw new Error("request_id is required");
          }
          const vote = action === "Approve" ? "approved" : "denied";
          const out = await serviceRequest<Record<string, unknown>>(session, "governance", `/governance/approve/${encodeURIComponent(reqID)}?tenant_id=${encodeURIComponent(session.tenantId)}`, {
            method: "POST",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              request_id: reqID,
              vote,
              token: readField("approvals", "vote_token"),
              approver_email: readField("approvals", "approver_email"),
              comment: readField("approvals", "comment"),
              vote_method: "dashboard"
            })
          });
          setPanelData((prev) => ({ ...prev, approvals: out }));
          setActionMessage(`${vote} vote submitted for ${reqID}.`);
          break;
        }
        case "alert_center:Create Rule": {
          const severity = (readField("alert_center", "severity") || "warning").toLowerCase();
          const channel = (readField("alert_center", "channel") || "email").toLowerCase();
          const out = await serviceRequest<Record<string, unknown>>(session, "reporting", "/alerts/rules", {
            method: "POST",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              name: `dashboard-${Date.now()}`,
              condition: "count > 0",
              severity: severity === "all" ? "warning" : severity,
              event_pattern: "*",
              threshold: 1,
              window_seconds: 300,
              channels: [channel === "all" ? "email" : channel],
              enabled: true
            })
          });
          setPanelData((prev) => ({ ...prev, alert_center: out }));
          setActionMessage("Alert rule created.");
          break;
        }
        case "alert_center:Mute Window": {
          const out = await serviceRequest<Record<string, unknown>>(
            session,
            "reporting",
            `/alerts?tenant_id=${encodeURIComponent(session.tenantId)}&severity=${encodeURIComponent(readField("alert_center", "severity") || "")}&limit=50`
          );
          setPanelData((prev) => ({ ...prev, alert_center: out }));
          setActionMessage("Loaded alert set for mute workflow.");
          break;
        }
        case "audit_log:Apply Filter": {
          const items = await serviceRequest<Record<string, unknown>>(
            session,
            "audit",
            `/audit/events?tenant_id=${encodeURIComponent(session.tenantId)}&limit=100`
          );
          setPanelData((prev) => ({ ...prev, audit_log: items }));
          setActionMessage("Audit stream refreshed.");
          break;
        }
        case "audit_log:Export CSV": {
          const items = await serviceRequest<{ items?: Array<Record<string, unknown>> }>(
            session,
            "audit",
            `/audit/events?tenant_id=${encodeURIComponent(session.tenantId)}&limit=100`
          );
          const rows = (items.items || []).map((e) => `${String(e.timestamp || "")},${String(e.action || "")},${String(e.result || "")}`);
          const csv = ["timestamp,action,result", ...rows].join("\n");
          setPanelData((prev) => ({ ...prev, audit_log: { csv } }));
          setActionMessage("CSV payload generated in panel output.");
          break;
        }
        case "compliance:View Gaps": {
          const frameworks = await serviceRequest<{ items?: Array<{ id?: string }> }>(session, "compliance", "/compliance/frameworks");
          const fwID = frameworks.items?.[0]?.id || "pci_dss_4";
          const gaps = await serviceRequest<Record<string, unknown>>(session, "compliance", `/compliance/frameworks/${encodeURIComponent(fwID)}/gaps?tenant_id=${encodeURIComponent(session.tenantId)}`);
          setPanelData((prev) => ({ ...prev, compliance: gaps }));
          setActionMessage(`Loaded gaps for ${fwID}.`);
          break;
        }
        case "compliance:Generate Report": {
          const report = await serviceRequest<Record<string, unknown>>(session, "reporting", "/reports/generate", {
            method: "POST",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              template_id: "compliance-summary",
              format: "json",
              requested_by: session.username,
              filters: {}
            })
          });
          setPanelData((prev) => ({ ...prev, compliance: report }));
          setActionMessage("Compliance report generation started.");
          break;
        }
        case "sbom:Export CycloneDX": {
          const out = await serviceRequest<Record<string, unknown>>(session, "sbom", "/sbom/latest");
          setPanelData((prev) => ({ ...prev, sbom: out }));
          setActionMessage("Loaded latest CycloneDX SBOM.");
          break;
        }
        case "sbom:Export SPDX": {
          const out = await serviceRequest<Record<string, unknown>>(session, "compliance", "/compliance/sbom?format=spdx");
          setPanelData((prev) => ({ ...prev, sbom: out }));
          setActionMessage("Loaded SPDX view.");
          break;
        }
        case "sbom:Run BOM Diff": {
          const out = await serviceRequest<Record<string, unknown>>(session, "sbom", "/sbom/diff");
          setPanelData((prev) => ({ ...prev, sbom: out }));
          setActionMessage("SBOM diff executed.");
          break;
        }
        case "pkcs11:List Clients":
        case "pkcs11:Mechanism Stats": {
          const clients = await serviceRequest<Record<string, unknown>>(session, "auth", `/auth/clients?tenant_id=${encodeURIComponent(session.tenantId)}`);
          setPanelData((prev) => ({ ...prev, pkcs11: clients }));
          setActionMessage("Loaded client registry telemetry.");
          break;
        }
        case "admin-tenants:Create Tenant": {
          const tenantID = readField("admin-tenants", "tenant_id").trim();
          if (!tenantID) {
            throw new Error("tenant_id is required");
          }
          const out = await serviceRequest<Record<string, unknown>>(session, "auth", "/tenants", {
            method: "POST",
            body: JSON.stringify({
              id: tenantID,
              name: readField("admin-tenants", "tenant_name"),
              status: readField("admin-tenants", "tenant_status") || "active"
            })
          });
          setPanelData((prev) => ({ ...prev, "admin-tenants": out }));
          setActionMessage("Tenant created/updated.");
          break;
        }
        case "admin-tenants:List Tenants": {
          const out = await serviceRequest<Record<string, unknown>>(session, "auth", "/tenants");
          setPanelData((prev) => ({ ...prev, "admin-tenants": out }));
          setActionMessage("Tenant list refreshed.");
          break;
        }
        case "admin-users:Create User": {
          const username = readField("admin-users", "username").trim();
          const email = readField("admin-users", "email").trim();
          const password = readField("admin-users", "password");
          if (!username || !email || !password) {
            throw new Error("username, email, and password are required");
          }
          const out = await serviceRequest<Record<string, unknown>>(session, "auth", "/auth/users", {
            method: "POST",
            body: JSON.stringify({
              username,
              email,
              password,
              role: readField("admin-users", "role"),
              must_change_password: false
            })
          });
          setPanelData((prev) => ({ ...prev, "admin-users": out }));
          setActionMessage("User created.");
          break;
        }
        case "admin-users:List Users": {
          const out = await serviceRequest<Record<string, unknown>>(session, "auth", "/auth/users");
          setPanelData((prev) => ({ ...prev, "admin-users": out }));
          setActionMessage("User list refreshed.");
          break;
        }
        case "admin-users:Update User Role": {
          const userID = readField("admin-users", "user_id").trim();
          if (!userID) {
            throw new Error("user_id is required for role update");
          }
          const out = await serviceRequest<Record<string, unknown>>(session, "auth", `/auth/users/${encodeURIComponent(userID)}/role`, {
            method: "PUT",
            body: JSON.stringify({ role: readField("admin-users", "role") })
          });
          setPanelData((prev) => ({ ...prev, "admin-users": out }));
          setActionMessage("User role updated.");
          break;
        }
        case "admin-governance:Save SMTP Settings": {
          const out = await serviceRequest<Record<string, unknown>>(session, "governance", "/governance/settings", {
            method: "PUT",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              smtp_host: readField("admin-governance", "smtp_host"),
              smtp_port: readField("admin-governance", "smtp_port") || "587",
              smtp_username: readField("admin-governance", "smtp_username"),
              smtp_password: readField("admin-governance", "smtp_password"),
              smtp_from: readField("admin-governance", "smtp_from"),
              smtp_starttls: (readField("admin-governance", "smtp_starttls") || "true") === "true",
              approval_expiry_minutes: asNumber(readField("admin-governance", "approval_expiry_minutes"), 120),
              expiry_check_interval_seconds: 60,
              updated_by: session.username
            })
          });
          setPanelData((prev) => ({ ...prev, "admin-governance": out }));
          setActionMessage("Governance SMTP settings updated.");
          break;
        }
        case "admin-governance:Test SMTP": {
          const out = await serviceRequest<Record<string, unknown>>(session, "governance", "/governance/settings/smtp/test", {
            method: "POST",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              to: readField("admin-governance", "smtp_test_to")
            })
          });
          setPanelData((prev) => ({ ...prev, "admin-governance": out }));
          setActionMessage("SMTP test executed.");
          break;
        }
        case "admin-governance:Load Governance Settings": {
          const out = await serviceRequest<Record<string, unknown>>(session, "governance", `/governance/settings?tenant_id=${encodeURIComponent(session.tenantId)}`);
          const settings = ((out.settings as Record<string, unknown> | undefined) || {}) as Record<string, unknown>;
          writeFields("admin-governance", {
            smtp_host: String(settings.smtp_host || ""),
            smtp_port: String(settings.smtp_port || "587"),
            smtp_username: String(settings.smtp_username || ""),
            smtp_password: "",
            smtp_from: String(settings.smtp_from || ""),
            smtp_starttls: String(settings.smtp_starttls ?? true),
            approval_expiry_minutes: String(settings.approval_expiry_minutes || "120")
          });
          setPanelData((prev) => ({ ...prev, "admin-governance": out }));
          setActionMessage("Governance settings loaded.");
          break;
        }
        case "admin-alert-channels:Load Channels": {
          const out = await serviceRequest<{ items?: Array<Record<string, unknown>> }>(session, "reporting", `/alerts/channels?tenant_id=${encodeURIComponent(session.tenantId)}`);
          const channels = out.items || [];
          const selectedName = readField("admin-alert-channels", "channel_name");
          const selected = channels.find((c) => String(c.name || "") === selectedName) || channels[0] || {};
          const config = (selected.config as Record<string, unknown> | undefined) || {};
          writeFields("admin-alert-channels", {
            channel_name: String(selected.name || "email"),
            channel_enabled: String(selected.enabled ?? true),
            channel_endpoint: String(config.endpoint || config.target || "")
          });
          setPanelData((prev) => ({ ...prev, "admin-alert-channels": { items: channels } }));
          setActionMessage("Alert channel configuration loaded.");
          break;
        }
        case "admin-alert-channels:Save Channel": {
          const channel = readField("admin-alert-channels", "channel_name") || "email";
          const enabled = (readField("admin-alert-channels", "channel_enabled") || "true") === "true";
          const endpoint = readField("admin-alert-channels", "channel_endpoint");
          const config: Record<string, unknown> = { endpoint };
          if (channel === "snmp") {
            config.target = endpoint;
            config.version = "v2c";
          }
          if (channel === "proxy") {
            config.url = endpoint;
            config.mode = "forward";
          }
          const out = await serviceRequest<Record<string, unknown>>(session, "reporting", `/alerts/channels?tenant_id=${encodeURIComponent(session.tenantId)}`, {
            method: "PUT",
            body: JSON.stringify([
              {
                tenant_id: session.tenantId,
                name: channel,
                enabled,
                config
              }
            ])
          });
          setPanelData((prev) => ({ ...prev, "admin-alert-channels": out }));
          setActionMessage(`Channel ${channel} updated.`);
          break;
        }
        case "admin-integrity:Save Security State": {
          const state = await serviceRequest<{ state?: Record<string, unknown> }>(session, "governance", "/governance/system/state", {
            method: "PUT",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              fips_mode: readField("admin-integrity", "fips_mode") || "disabled",
              hsm_mode: readField("admin-integrity", "hsm_mode") || "software",
              cluster_mode: readField("admin-integrity", "cluster_mode") || "standalone",
              license_key: readField("admin-integrity", "license_key").trim(),
              updated_by: session.username
            })
          });
          if (state.state) {
            hydrateSystemStateFields(state.state);
          }
          setPanelData((prev) => ({ ...prev, "admin-integrity": state }));
          setActionMessage("Security state persisted.");
          break;
        }
        case "admin-integrity:Run Integrity Check": {
          const [integrity, auditVerify] = await Promise.all([
            serviceRequest<Record<string, unknown>>(session, "governance", `/governance/system/integrity?tenant_id=${encodeURIComponent(session.tenantId)}`),
            serviceRequest<Record<string, unknown>>(session, "audit", `/audit/chain/verify?tenant_id=${encodeURIComponent(session.tenantId)}`)
          ]);
          setPanelData((prev) => ({ ...prev, "admin-integrity": { integrity, audit: auditVerify } }));
          setActionMessage("System and audit integrity checks completed.");
          break;
        }
        case "admin-integrity:Check Cluster": {
          const [k, a, integrity] = await Promise.all([
            serviceRequest<Record<string, unknown>>(session, "keycore", `/keys?tenant_id=${encodeURIComponent(session.tenantId)}&limit=1`),
            serviceRequest<Record<string, unknown>>(session, "auth", "/auth/me"),
            serviceRequest<Record<string, unknown>>(session, "governance", `/governance/system/integrity?tenant_id=${encodeURIComponent(session.tenantId)}`)
          ]);
          setPanelData((prev) => ({ ...prev, "admin-integrity": { keycore: k, auth: a, integrity } }));
          setActionMessage("Cluster connectivity check completed.");
          break;
        }
        case "admin-integrity:Activate License": {
          const licenseKey = readField("admin-integrity", "license_key").trim();
          if (!licenseKey) {
            throw new Error("license_key is required");
          }
          const out = await serviceRequest<{ state?: Record<string, unknown> }>(session, "governance", "/governance/system/state", {
            method: "PUT",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              license_key: licenseKey,
              license_status: "active",
              updated_by: session.username
            })
          });
          if (out.state) {
            hydrateSystemStateFields(out.state);
          }
          setPanelData((prev) => ({ ...prev, "admin-integrity": out }));
          setActionMessage("License activated in persisted system state.");
          break;
        }
        case "admin-platform:Save Network": {
          const out = await serviceRequest<{ state?: Record<string, unknown> }>(session, "governance", "/governance/system/state", {
            method: "PUT",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              mgmt_ip: readField("admin-platform", "mgmt_ip"),
              cluster_ip: readField("admin-platform", "cluster_ip"),
              dns_servers: readField("admin-platform", "dns_servers"),
              ntp_servers: readField("admin-platform", "ntp_servers"),
              proxy_endpoint: readField("admin-platform", "proxy_endpoint"),
              snmp_target: readField("admin-platform", "snmp_target"),
              updated_by: session.username
            })
          });
          if (out.state) {
            hydrateSystemStateFields(out.state);
          }
          setPanelData((prev) => ({ ...prev, "admin-platform": out }));
          setActionMessage("Network/proxy/SNMP settings saved.");
          break;
        }
        case "admin-platform:Load Platform State": {
          const out = await serviceRequest<{ state?: Record<string, unknown> }>(session, "governance", `/governance/system/state?tenant_id=${encodeURIComponent(session.tenantId)}`);
          if (out.state) {
            hydrateSystemStateFields(out.state);
          }
          setPanelData((prev) => ({ ...prev, "admin-platform": out }));
          setActionMessage("Platform state loaded.");
          break;
        }
        case "admin-tls:Save TLS Config": {
          const out = await serviceRequest<{ state?: Record<string, unknown> }>(session, "governance", "/governance/system/state", {
            method: "PUT",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              tls_mode: readField("admin-tls", "tls_mode") || "internal_ca",
              tls_cert_pem: readField("admin-tls", "tls_cert_pem"),
              tls_key_pem: readField("admin-tls", "tls_key_pem"),
              tls_ca_bundle_pem: readField("admin-tls", "tls_ca_bundle_pem"),
              updated_by: session.username
            })
          });
          if (out.state) {
            hydrateSystemStateFields(out.state);
          }
          setPanelData((prev) => ({ ...prev, "admin-tls": out }));
          setActionMessage("TLS configuration saved.");
          break;
        }
        case "admin-tls:Load TLS Config": {
          const out = await serviceRequest<{ state?: Record<string, unknown> }>(session, "governance", `/governance/system/state?tenant_id=${encodeURIComponent(session.tenantId)}`);
          if (out.state) {
            hydrateSystemStateFields(out.state);
          }
          setPanelData((prev) => ({ ...prev, "admin-tls": out }));
          setActionMessage("TLS configuration loaded.");
          break;
        }
        case "admin-backup:Save Backup Config": {
          const out = await serviceRequest<{ state?: Record<string, unknown> }>(session, "governance", "/governance/system/state", {
            method: "PUT",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              backup_schedule: readField("admin-backup", "backup_schedule") || "daily@02:00",
              backup_target: readField("admin-backup", "backup_target") || "local",
              backup_retention_days: asNumber(readField("admin-backup", "backup_retention_days"), 30),
              backup_encrypted: (readField("admin-backup", "backup_encrypted") || "true") === "true",
              updated_by: session.username
            })
          });
          if (out.state) {
            hydrateSystemStateFields(out.state);
          }
          setPanelData((prev) => ({ ...prev, "admin-backup": out }));
          setActionMessage("Backup configuration saved.");
          break;
        }
        case "admin-backup:Load Backup Config": {
          const out = await serviceRequest<{ state?: Record<string, unknown> }>(session, "governance", `/governance/system/state?tenant_id=${encodeURIComponent(session.tenantId)}`);
          if (out.state) {
            hydrateSystemStateFields(out.state);
          }
          setPanelData((prev) => ({ ...prev, "admin-backup": out }));
          setActionMessage("Backup configuration loaded.");
          break;
        }
        case "kmip:Execute KMIP":
        case "kmip:Session Diagnostics": {
          const out = await serviceRequest<Record<string, unknown>>(session, "kmip", "/healthz");
          setPanelData((prev) => ({ ...prev, kmip: out }));
          setActionMessage("KMIP endpoint check completed.");
          break;
        }
        case "hsm:Apply HSM Mode": {
          const [provider, state] = await Promise.all([
            serviceRequest<Record<string, unknown>>(session, "software-vault", "/provider-info"),
            serviceRequest<{ state?: Record<string, unknown> }>(session, "governance", "/governance/system/state", {
              method: "PUT",
              body: JSON.stringify({
                tenant_id: session.tenantId,
                hsm_mode: readField("hsm", "mode") || "software",
                updated_by: session.username
              })
            })
          ]);
          if (state.state) {
            hydrateSystemStateFields(state.state);
          }
          setPanelData((prev) => ({ ...prev, hsm: { provider, state } }));
          setActionMessage("HSM mode applied and persisted.");
          break;
        }
        case "hsm:Test Wrap/Unwrap": {
          const out = await serviceRequest<Record<string, unknown>>(session, "software-vault", "/healthz");
          setPanelData((prev) => ({ ...prev, hsm: out }));
          setActionMessage("Software vault health check completed.");
          break;
        }
        case "qkd:Request Quantum Key":
        case "qkd:Rotate Link Key": {
          const out = await serviceRequest<Record<string, unknown>>(session, "qkd", "/qkd/v1/devices");
          setPanelData((prev) => ({ ...prev, qkd: out }));
          setActionMessage("QKD device telemetry loaded.");
          break;
        }
        case "mpc:Start Ceremony": {
          const out = await serviceRequest<Record<string, unknown>>(session, "mpc", "/mpc/dkg/initiate", {
            method: "POST",
            body: JSON.stringify({
              tenant_id: session.tenantId,
              key_id: selectedKeyID || "",
              protocol: readField("mpc", "protocol") || "frost",
              threshold: asNumber(readField("mpc", "threshold"), 2),
              participants: asNumber(readField("mpc", "participants"), 3)
            })
          });
          setPanelData((prev) => ({ ...prev, mpc: out }));
          setActionMessage("MPC ceremony started.");
          break;
        }
        case "mpc:Generate Shares": {
          const out = await serviceRequest<Record<string, unknown>>(session, "mpc", "/mpc/shares");
          setPanelData((prev) => ({ ...prev, mpc: out }));
          setActionMessage("MPC share inventory loaded.");
          break;
        }
        case "cluster:Run Quorum Test":
        case "cluster:Promote Follower": {
          const requested = readField("cluster", "cluster_action") || (action === "Promote Follower" ? "promote" : "quorum-test");
          const desiredMode = requested === "promote" ? "ha" : "standalone";
          const [integrity, state] = await Promise.all([
            serviceRequest<Record<string, unknown>>(session, "governance", `/governance/system/integrity?tenant_id=${encodeURIComponent(session.tenantId)}`),
            serviceRequest<{ state?: Record<string, unknown> }>(session, "governance", "/governance/system/state", {
              method: "PUT",
              body: JSON.stringify({
                tenant_id: session.tenantId,
                cluster_mode: desiredMode,
                updated_by: session.username
              })
            })
          ]);
          if (state.state) {
            hydrateSystemStateFields(state.state);
          }
          setPanelData((prev) => ({ ...prev, cluster: { integrity, state } }));
          setActionMessage(action === "Promote Follower" ? "Cluster promote request persisted." : "Cluster quorum check completed.");
          break;
        }
        default:
          setActionMessage(`${action} action is not wired yet.`);
      }
    } catch (error) {
      setActionMessage(`Error: ${asMessage(error)}`);
    } finally {
      setBusyAction("");
    }
  };

  if (tabId === "dashboard") {
    return <DashboardPanels data={dashboard} loading={dashboardLoading} />;
  }

  return (
    <div className="space-y-4">
      {specs.map((panel) => (
        <Panel key={panel.key} title={panel.title} subtitle={panel.subtitle}>
          {panel.fields?.length ? (
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {panel.fields.map((field) => (
                <InputField key={field.key} spec={field} value={readField(panel.key, field.key)} onChange={(next) => writeField(panel.key, field.key, next)} />
              ))}
            </div>
          ) : null}

          {panel.key === "key-inventory" ? (
            <div className="mt-3 overflow-auto rounded-lg border border-cyber-border">
              <table className="min-w-full text-sm">
                <thead className="bg-cyber-elevated text-cyber-muted">
                  <tr>
                    <th className="px-3 py-2 text-left">ID</th>
                    <th className="px-3 py-2 text-left">Name</th>
                    <th className="px-3 py-2 text-left">Algorithm</th>
                    <th className="px-3 py-2 text-left">Status</th>
                    <th className="px-3 py-2 text-left">Version</th>
                  </tr>
                </thead>
                <tbody>
                  {(keys.length ? keys : []).map((key) => (
                    <tr
                      key={key.id}
                      className={`cursor-pointer border-t border-cyber-border/60 ${selectedKeyID === key.id ? "bg-cyber-elevated" : ""}`}
                      onClick={() => {
                        setSelectedKeyID(key.id);
                        writeField("crypto-console", "key_id", key.id);
                      }}
                    >
                      <td className="px-3 py-2 text-cyber-muted">{key.id}</td>
                      <td className="px-3 py-2 text-cyber-text">{key.name}</td>
                      <td className="px-3 py-2 text-cyber-muted">{key.algorithm}</td>
                      <td className="px-3 py-2 text-cyber-muted">{key.status}</td>
                      <td className="px-3 py-2 text-cyber-muted">{key.current_version}</td>
                    </tr>
                  ))}
                  {!keys.length ? (
                    <tr className="border-t border-cyber-border/60">
                      <td colSpan={5} className="px-3 py-3 text-cyber-muted">No keys loaded yet. Click Apply Filter to fetch keys.</td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          ) : null}

          {panel.table ? (
            <div className="mt-3 overflow-auto rounded-lg border border-cyber-border">
              <table className="min-w-full text-sm">
                <thead className="bg-cyber-elevated text-cyber-muted"><tr>{panel.table.columns.map((c) => <th key={c} className="px-3 py-2 text-left">{c}</th>)}</tr></thead>
                <tbody>{panel.table.rows.map((row, idx) => <tr key={idx} className="border-t border-cyber-border/60">{row.map((cell) => <td key={cell} className="px-3 py-2 text-cyber-muted">{cell}</td>)}</tr>)}</tbody>
              </table>
            </div>
          ) : null}

          {panel.notes?.length ? <div className="mt-3 space-y-1 rounded-lg border border-cyber-border bg-cyber-elevated p-3 text-sm text-cyber-muted">{panel.notes.map((n) => <p key={n}>{n}</p>)}</div> : null}

          {tabId === "alert_center" ? (
            <div className="mt-3 space-y-2">
              {(alertRows.length ? alertRows : [{ id: "none", topic: "alerts.stream", severity: "info", message: "No alerts yet", timestamp: new Date().toISOString() }]).map((a) => (
                <div key={a.id} className="rounded-lg border border-cyber-border bg-cyber-elevated p-3 text-sm">
                  <Badge tone={a.severity === "critical" ? "critical" : a.severity === "warning" ? "warning" : "success"}>{a.severity}</Badge>
                  <span className="ml-2 text-cyber-muted">{a.topic}</span>
                  <p className="mt-1 text-cyber-text">{a.message}</p>
                </div>
              ))}
            </div>
          ) : null}

          {tabId === "audit_log" ? (
            <div className="mt-3 space-y-2">
              {(auditRows.length ? auditRows : [{ id: "none", topic: "audit.stream", severity: "info", message: "No audit events yet", timestamp: new Date().toISOString() }]).map((e) => (
                <div key={e.id} className="rounded-lg border border-cyber-border bg-cyber-elevated p-3 text-sm">
                  <p className="text-cyber-text">{e.topic}</p>
                  <p className="text-cyber-muted">{e.message}</p>
                </div>
              ))}
            </div>
          ) : null}

          {tabId === "administration" ? (
            <div className="mt-3 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
              {Array.from(enabledFeatures).sort().map((f) => (
                <label key={f} className="rounded-md border border-cyber-border bg-cyber-elevated px-3 py-2 text-sm text-cyber-muted"><input type="checkbox" checked readOnly className="mr-2" />{f}</label>
              ))}
            </div>
          ) : null}

          {panelData[panel.key] ? (
            <div className="mt-3 overflow-auto rounded-lg border border-cyber-border bg-cyber-elevated p-3">
              <pre className="text-xs text-cyber-muted">{JSON.stringify(panelData[panel.key], null, 2)}</pre>
            </div>
          ) : null}

          {actionMessage ? <div className="mt-3 rounded-lg border border-cyber-border bg-cyber-elevated p-3 text-sm text-cyber-text">{actionMessage}</div> : null}

          {panel.actions?.length ? (
            <div className="mt-3 flex flex-wrap gap-2">
              {panel.actions.map((action) => (
                <Button key={action} kind="secondary" onClick={() => { void handleAction(panel.key, action); }}>
                  {busyAction === `${panel.key}:${action}` ? "Working..." : action}
                </Button>
              ))}
            </div>
          ) : null}
        </Panel>
      ))}
    </div>
  );
}
