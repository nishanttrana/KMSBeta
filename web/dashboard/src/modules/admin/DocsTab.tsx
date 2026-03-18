// @ts-nocheck
import { useState, useMemo } from "react";
import { Card, Inp, B } from "../../components/v3/legacyPrimitives";
import { C } from "../../components/v3/theme";
import { ChevronRight, ChevronDown, Copy, Search } from "lucide-react";

const S: Record<string, React.CSSProperties> = {
  wrap: { display: "flex", gap: 0, height: "calc(100vh - 120px)" },
  nav: { width: 230, minWidth: 230, borderRight: `1px solid ${C.border}`, overflowY: "auto", padding: "10px 0" },
  content: { flex: 1, overflowY: "auto", padding: "16px 20px" },
  navItem: { display: "flex", alignItems: "center", gap: 6, padding: "7px 14px", fontSize: 11, cursor: "pointer", borderLeft: "2px solid transparent", transition: "all .15s" },
  h1: { fontSize: 16, fontWeight: 700, color: C.text, marginBottom: 4 },
  h2: { fontSize: 13, fontWeight: 700, color: C.text, margin: "18px 0 8px" },
  h3: { fontSize: 11, fontWeight: 700, color: C.text, margin: "14px 0 6px" },
  p: { fontSize: 11, color: C.dim, lineHeight: 1.7, margin: "4px 0 8px" },
  code: { background: C.bg, border: `1px solid ${C.border}`, borderRadius: 6, padding: "10px 12px", fontSize: 10, color: C.accent, fontFamily: "'JetBrains Mono',monospace", overflowX: "auto", whiteSpace: "pre-wrap", display: "block", margin: "6px 0 10px", lineHeight: 1.6 },
  inlineCode: { background: C.bg, border: `1px solid ${C.border}`, borderRadius: 3, padding: "1px 5px", fontSize: 10, color: C.accent, fontFamily: "'JetBrains Mono',monospace" },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 10, margin: "6px 0 12px" },
  th: { textAlign: "left", padding: "6px 8px", borderBottom: `1px solid ${C.border}`, color: C.muted, fontWeight: 600, fontSize: 9, textTransform: "uppercase", letterSpacing: 0.5 },
  td: { padding: "5px 8px", borderBottom: `1px solid ${C.border}`, color: C.dim, fontFamily: "'JetBrains Mono',monospace", fontSize: 10 },
  badge: { display: "inline-block", padding: "1px 6px", borderRadius: 4, fontSize: 9, fontWeight: 600, marginRight: 4 },
};

const methodColor = (m: string) => {
  if (m === "POST") return { color: C.green, bg: C.greenDim };
  if (m === "PUT") return { color: C.amber, bg: C.amberDim };
  if (m === "DELETE") return { color: C.red, bg: C.redDim };
  return { color: C.blue, bg: C.blueDim };
};

const Code = ({ children }: { children: string }) => <pre style={S.code}>{children}</pre>;
const P = ({ children }: { children: React.ReactNode }) => <div style={S.p}>{children}</div>;
const H2 = ({ children }: { children: React.ReactNode }) => <div style={S.h2}>{children}</div>;
const H3 = ({ children }: { children: React.ReactNode }) => <div style={S.h3}>{children}</div>;
const IC = ({ children }: { children: string }) => <span style={S.inlineCode}>{children}</span>;

const EndpointTable = ({ rows }: { rows: [string, string, string][] }) => (
  <table style={S.table}>
    <thead><tr><th style={S.th}>Method</th><th style={S.th}>Path</th><th style={S.th}>Description</th></tr></thead>
    <tbody>{rows.map(([m, p, d], i) => {
      const mc = methodColor(m);
      return (
        <tr key={i}>
          <td style={S.td}><span style={{ ...S.badge, color: mc.color, background: mc.bg }}>{m}</span></td>
          <td style={S.td}>{p}</td>
          <td style={{ ...S.td, fontFamily: "inherit", color: C.dim }}>{d}</td>
        </tr>
      );
    })}</tbody>
  </table>
);

const EnvTable = ({ rows }: { rows: [string, string, string][] }) => (
  <table style={S.table}>
    <thead><tr><th style={S.th}>Variable</th><th style={S.th}>Default</th><th style={S.th}>Description</th></tr></thead>
    <tbody>{rows.map(([v, d, desc], i) => (
      <tr key={i}>
        <td style={S.td}>{v}</td>
        <td style={S.td}>{d}</td>
        <td style={{ ...S.td, fontFamily: "inherit", color: C.dim }}>{desc}</td>
      </tr>
    ))}</tbody>
  </table>
);

const Collapse = ({ title, children, defaultOpen = false }: { title: string; children: React.ReactNode; defaultOpen?: boolean }) => {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ margin: "6px 0" }}>
      <div onClick={() => setOpen(!open)} style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", padding: "6px 0" }}>
        {open ? <ChevronDown size={12} color={C.accent} /> : <ChevronRight size={12} color={C.muted} />}
        <span style={{ fontSize: 11, fontWeight: 600, color: open ? C.accent : C.text }}>{title}</span>
      </div>
      {open && <div style={{ paddingLeft: 18 }}>{children}</div>}
    </div>
  );
};

/* ───────── NAV SECTIONS ───────── */
const NAV = [
  { id: "overview", label: "Platform Overview" },
  { id: "deploy", label: "Deployment Guide" },
  { id: "credentials", label: "Default Credentials" },
  { id: "architecture", label: "Architecture" },
  { id: "services", label: "Service Reference" },
  { id: "api-auth", label: "API: Auth" },
  { id: "api-keycore", label: "API: Keycore" },
  { id: "api-secrets", label: "API: Secrets" },
  { id: "api-certs", label: "API: Certificates" },
  { id: "api-audit", label: "API: Audit" },
  { id: "api-policy", label: "API: Policy" },
  { id: "api-governance", label: "API: Governance" },
  { id: "api-dataprotect", label: "API: Data Protection" },
  { id: "api-payment", label: "API: Payment" },
  { id: "api-cloud", label: "API: Cloud / BYOK" },
  { id: "api-hyok", label: "API: HYOK" },
  { id: "api-ekm", label: "API: EKM" },
  { id: "api-ekm-bitlocker", label: "API: BitLocker" },
  { id: "api-ekm-sdk", label: "API: PKCS#11/JCA" },
  { id: "guide-agent-deploy", label: "Guide: Agent Deploy" },
  { id: "guide-key-cache", label: "Guide: Key Cache" },
  { id: "api-mpc", label: "API: MPC" },
  { id: "api-qkd", label: "API: QKD" },
  { id: "api-compliance", label: "API: Compliance" },
  { id: "api-sbom", label: "API: SBOM / CBOM" },
  { id: "api-posture", label: "API: Posture" },
  { id: "api-reporting", label: "API: Reporting" },
  { id: "api-cluster", label: "API: Cluster" },
  { id: "api-pqc", label: "API: PQC" },
  { id: "api-discovery", label: "API: Discovery" },
  { id: "api-ai", label: "API: AI / LLM" },
  { id: "api-openapi", label: "API: OpenAPI / Swagger" },
  { id: "ui-guide", label: "UI Guide: Dashboard" },
  { id: "ui-keys", label: "UI Guide: Keys" },
  { id: "ui-workbench", label: "UI Guide: Workbench" },
  { id: "ui-vault", label: "UI Guide: Vault" },
  { id: "ui-certs", label: "UI Guide: Certificates" },
  { id: "ui-dataprotect", label: "UI Guide: Data Protection" },
  { id: "ui-cloud", label: "UI Guide: Cloud Control" },
  { id: "ui-ekm", label: "UI Guide: EKM" },
  { id: "ui-hsm", label: "UI Guide: HSM" },
  { id: "ui-advanced", label: "UI Guide: Advanced" },
  { id: "ui-governance", label: "UI Guide: Governance" },
  { id: "ui-monitoring", label: "UI Guide: Monitoring" },
  { id: "ui-cluster", label: "UI Guide: Cluster" },
  { id: "ui-admin", label: "UI Guide: Admin" },
  { id: "config-env", label: "Config: Environment" },
  { id: "config-fips", label: "Config: FIPS Mode" },
  { id: "config-hsm", label: "Config: HSM" },
  { id: "config-network", label: "Config: Networking" },
  { id: "config-cluster", label: "Config: Clustering" },
  { id: "config-backup", label: "Config: Backup" },
  { id: "config-profiles", label: "Config: Docker Profiles" },
  { id: "config-fastinstall", label: "Config: Fast Install" },
  { id: "api-fde", label: "API: Disk Encryption" },
  { id: "guide-crypto-inventory", label: "Guide: Crypto Inventory" },
  { id: "guide-vault-hierarchy", label: "Guide: Vault Hierarchy" },
  { id: "guide-hsm-certs", label: "Guide: HSM Certificates" },
  { id: "troubleshooting", label: "Troubleshooting" },
];

/* ───────── SECTION RENDERERS ───────── */

const SectionOverview = () => (
  <div>
    <div style={S.h1}>Vecta KMS Platform Documentation</div>
    <P>Vecta KMS is an enterprise-grade Key Management System providing comprehensive cryptographic key lifecycle management, secrets management, certificate PKI, data protection, payment cryptography, and cloud key control. The platform consists of 26+ microservices, a web dashboard, and an Envoy edge proxy.</P>
    <H2>Key Capabilities</H2>
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
      {[
        ["Key Lifecycle", "Create, rotate, disable, destroy, import, export keys with policy controls"],
        ["Cryptographic Ops", "Encrypt, decrypt, sign, verify, MAC, wrap, unwrap, KEM, derive"],
        ["Secrets Vault", "Store and manage credentials, SSH keys, PGP keys, tokens, certificates"],
        ["Certificate PKI", "Full CA hierarchy, ACME, EST, SCEP, CMPv2, OCSP, CRL management"],
        ["Data Protection", "Tokenization, masking, redaction, FPE, envelope encryption, searchable encryption"],
        ["Payment Crypto", "TR-31 key blocks, PIN translation, CVV, MAC, ISO 20022, key injection"],
        ["Cloud Key Control", "BYOK (AWS, Azure, GCP, Oracle, Salesforce) and HYOK (DKE, Cache-Only, EKM)"],
        ["Post-Quantum", "PQC algorithms (ML-KEM, ML-DSA, SLH-DSA), migration planning, CBOM"],
        ["MPC", "Distributed key generation, threshold signing, multi-party decryption"],
        ["Governance", "Multi-party approval workflows, policy enforcement, compliance frameworks"],
        ["Audit", "Immutable audit trail with Merkle tree verification, alerting, SIEM integration"],
        ["Cluster", "Multi-node clustering with etcd consensus, sync replication, role management"],
      ].map(([t, d]) => (
        <Card key={t} style={{ padding: 10 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.accent, marginBottom: 2 }}>{t}</div>
          <div style={{ fontSize: 10, color: C.dim }}>{d}</div>
        </Card>
      ))}
    </div>
    <H2>Supported Standards</H2>
    <P>FIPS 140-3, PKCS#11, KMIP 2.1, ACME (RFC 8555), EST (RFC 7030), SCEP, CMPv2, TR-31, ISO 20022, ETSI QKD 014/004, X.509v3, OCSP, CRL, Shamir Secret Sharing, Merkle Hash Trees, CycloneDX SBOM/CBOM, SPDX.</P>
  </div>
);

const SectionDeploy = () => (
  <div>
    <div style={S.h1}>Deployment Guide</div>
    <H2>Prerequisites</H2>
    <P>Docker Engine 24+ and Docker Compose v2 are required on all platforms. Minimum 4 CPU cores, 8 GB RAM, 50 GB disk for production. For development, 2 CPU / 4 GB RAM is sufficient.</P>

    <H2>Linux (Ubuntu / RHEL / Debian)</H2>
    <Code>{`# Install Docker
curl -fsSL https://get.docker.com | sh
sudo systemctl enable docker && sudo systemctl start docker

# Clone and start KMS
git clone <repository-url> vecta-kms && cd vecta-kms

# Start core services (7 containers)
docker compose up -d

# Start with optional features
docker compose --profile secrets --profile governance --profile cloud_byok up -d

# Start all services
docker compose --profile '*' up -d

# Verify health
docker compose ps
curl -s http://localhost:8001/health   # Auth service
curl -s http://localhost:8010/health   # Keycore service`}</Code>

    <H2>macOS</H2>
    <Code>{`# Install Docker Desktop for Mac
brew install --cask docker

# Open Docker Desktop and wait for it to start
open -a Docker

# Clone and start KMS
git clone <repository-url> vecta-kms && cd vecta-kms
docker compose up -d

# Dashboard is available at http://localhost:5173`}</Code>

    <H2>Windows</H2>
    <Code>{`# Install Docker Desktop for Windows
# Download from https://docs.docker.com/desktop/install/windows-install/
# Enable WSL2 backend in Docker Desktop settings

# In PowerShell or WSL2 terminal:
git clone <repository-url> vecta-kms
cd vecta-kms
docker compose up -d

# Dashboard: http://localhost:5173`}</Code>

    <H2>Port Reference</H2>
    <EndpointTable rows={[
      ["—", "5173", "Web Dashboard UI"],
      ["—", "80 / 443", "Envoy edge proxy (HTTP / HTTPS)"],
      ["—", "5696", "KMIP protocol endpoint"],
      ["—", "2222", "HSM CLI SSH (profile: hsm_cli)"],
      ["—", "4222 / 8222", "NATS messaging (profile: event_streaming)"],
      ["—", "6379", "Valkey/Redis cache (profile: distributed_cache)"],
      ["—", "8500", "Consul UI (profile: service_discovery)"],
      ["—", "5432", "PostgreSQL database"],
      ["—", "6432", "PgBouncer (profile: connection_pooling)"],
    ]} />

    <H2>Verifying Deployment</H2>
    <Code>{`# Check all containers are healthy
docker compose ps --format "table {{.Name}}\\t{{.Status}}"

# Test authentication
curl -s -X POST http://localhost:8001/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":"<your-password>","tenant_id":"root"}'

# The response includes a JWT token for subsequent API calls`}</Code>
  </div>
);

const SectionCredentials = () => (
  <div>
    <div style={S.h1}>Default Credentials</div>
    <Card style={{ padding: 14, border: `1px solid ${C.amber}`, background: C.amberDim }}>
      <div style={{ fontSize: 11, fontWeight: 700, color: C.amber, marginBottom: 4 }}>Security Notice</div>
      <div style={{ fontSize: 10, color: C.dim }}>Change all default credentials immediately after first login. The admin account forces a password change on first authentication.</div>
    </Card>
    <div style={{ height: 10 }} />

    <H2>Admin Account</H2>
    <EnvTable rows={[
      ["Username", "admin", "Bootstrap administrator account"],
      ["Password", "<your-password>", "Must be changed on first login"],
      ["Email", "admin@vecta.local", "Admin email address"],
      ["Tenant", "root", "Default root tenant"],
      ["Role", "tenant-admin", "Full administrative privileges"],
    ]} />

    <H2>CLI Account</H2>
    <EnvTable rows={[
      ["Username", "cli-user", "CLI / SSH access account"],
      ["Password", "<your-cli-password>", "Used for HSM CLI SSH sessions"],
      ["Email", "cli@vecta.local", "CLI user email"],
      ["Enabled", "false", "Must be enabled via AUTH_BOOTSTRAP_CLI_ENABLED=true"],
      ["SSH Port", "2222", "Connect via ssh cli-user@localhost -p 2222"],
    ]} />

    <H2>Database</H2>
    <EnvTable rows={[
      ["Username", "postgres", "PostgreSQL superuser"],
      ["Password", "postgres", "Database password"],
      ["Database", "vecta", "Application database name"],
      ["Port", "5432", "PostgreSQL port"],
      ["DSN", "postgres://postgres:postgres@postgres:5432/vecta?sslmode=disable", "Full connection string"],
    ]} />

    <H2>User Roles</H2>
    <EnvTable rows={[
      ["admin", "—", "Full system access across all tenants"],
      ["tenant-admin", "—", "Full access within assigned tenant"],
      ["approver", "—", "Can vote on governance approval requests"],
      ["operator", "—", "Key operations (create, rotate, encrypt/decrypt)"],
      ["auditor", "—", "Read-only access to audit logs and compliance data"],
      ["viewer", "—", "Read-only access to key metadata and dashboards"],
      ["cli-user", "—", "SSH CLI access for HSM operations"],
    ]} />
  </div>
);

const SectionArchitecture = () => (
  <div>
    <div style={S.h1}>Architecture Overview</div>
    <P>Vecta KMS follows a microservices architecture. Each service owns its domain, communicates via REST/gRPC, and uses PostgreSQL for persistence. Optional infrastructure (NATS, Valkey, Consul, PgBouncer, etcd) can be enabled via Docker profiles.</P>

    <H2>Service Groups</H2>
    <H3>Core Services (Always Running)</H3>
    <EnvTable rows={[
      ["kms-auth", "8001 / 18001", "Authentication, RBAC, tenant management, SSO, API keys"],
      ["kms-keycore", "8010 / 18010", "Key lifecycle, cryptographic operations, access policies"],
      ["kms-policy", "8040 / 18040", "Policy decision point, permission evaluation"],
      ["kms-audit", "8070 / 18070", "Immutable audit trail, alerts, Merkle integrity"],
      ["dashboard", "5173", "Web management UI (React/Vite)"],
      ["envoy", "80/443/5696", "Edge proxy, TLS termination, routing"],
      ["postgres", "5432", "Primary database (PostgreSQL 16)"],
    ]} />

    <H3>Security Services (Profile-Gated)</H3>
    <EnvTable rows={[
      ["kms-secrets", "8020 / 18020", "Secret vault (profile: secrets)"],
      ["kms-certs", "8030 / 18030", "Certificate PKI (profile: certs)"],
      ["kms-governance", "8050 / 18050", "Approval workflows (profile: governance)"],
      ["kms-dataprotect", "8200 / 18200", "Tokenization, masking (profile: data_protection)"],
      ["kms-payment", "8170 / 18170", "Payment cryptography (profile: payment_crypto)"],
    ]} />

    <H3>Cloud & Integration</H3>
    <EnvTable rows={[
      ["kms-cloud", "8080 / 18080", "BYOK cloud integration (profile: cloud_byok)"],
      ["kms-hyok-proxy", "8120 / 18120", "HYOK proxy (profile: hyok_proxy)"],
      ["kms-ekm", "8130 / 18130", "EKM database agents (profile: ekm_database)"],
      ["kms-kmip", "8160 / 15696", "KMIP 2.1 server (profile: kmip_server)"],
    ]} />

    <H3>Advanced Crypto</H3>
    <EnvTable rows={[
      ["kms-pqc", "8060 / 18060", "Post-quantum crypto (profile: pqc_migration)"],
      ["kms-mpc", "8190 / 18190", "Multi-party computation (profile: mpc_engine)"],
      ["kms-qkd", "8150 / 18150", "Quantum key distribution (profile: qkd_interface)"],
      ["kms-discovery", "8100 / 18100", "Crypto discovery (profile: crypto_discovery)"],
    ]} />

    <H3>Governance & Ops</H3>
    <EnvTable rows={[
      ["kms-compliance", "8110 / 18110", "Compliance frameworks (profile: compliance_dashboard)"],
      ["kms-reporting", "8140 / 18140", "Reporting & alerting (profile: reporting_alerting)"],
      ["kms-posture", "8220 / 18220", "Security posture (profile: posture_management)"],
      ["kms-sbom", "8180 / 18180", "SBOM/CBOM (profile: sbom_cbom)"],
      ["kms-ai", "8090 / 18090", "AI/LLM analysis (profile: ai_llm)"],
    ]} />

    <H3>Infrastructure (Profile-Gated)</H3>
    <EnvTable rows={[
      ["nats", "4222 / 8222", "Event streaming (profile: event_streaming)"],
      ["valkey", "6379", "Cache/sessions (profile: distributed_cache)"],
      ["consul", "8500", "Service discovery (profile: service_discovery)"],
      ["pgbouncer", "6432", "Connection pooling (profile: connection_pooling)"],
      ["etcd", "2379", "Cluster consensus (profile: clustering)"],
      ["cluster-manager", "8210 / 18210", "Cluster orchestration (profile: clustering)"],
    ]} />
  </div>
);

const SectionServiceRef = () => (
  <div>
    <div style={S.h1}>Service Reference</div>
    <P>Every KMS service follows a common pattern: HTTP API on port 8xxx, gRPC on port 18xxx, health check at GET /health. All services authenticate requests via JWT (issued by kms-auth) passed in the Authorization: Bearer header.</P>
    <H2>Common Headers</H2>
    <EnvTable rows={[
      ["Authorization", "Bearer &lt;jwt&gt;", "JWT token from /auth/login"],
      ["Content-Type", "application/json", "All request/response bodies are JSON"],
      ["X-Tenant-ID", "<tenant_id>", "Optional tenant override (admin only)"],
      ["X-Request-ID", "<uuid>", "Optional request correlation ID"],
    ]} />
    <H2>Authentication Flow</H2>
    <Code>{`# 1. Login to get JWT
TOKEN=$(curl -s -X POST http://localhost:8001/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":"<your-password>","tenant_id":"root"}' \\
  | jq -r '.token')

# 2. Use token in subsequent requests
curl -s http://localhost:8010/keys \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json"

# 3. Refresh token before expiry
curl -s -X POST http://localhost:8001/auth/refresh \\
  -H "Authorization: Bearer $TOKEN"`}</Code>
    <H2>Common Response Format</H2>
    <Code>{`# Success
{ "data": { ... }, "meta": { "page": 1, "limit": 50, "total": 123 } }

# Error
{ "error": "descriptive error message", "code": "ERROR_CODE" }`}</Code>
  </div>
);

/* ─── API SECTION GENERATORS ─── */

const SectionApiAuth = () => (
  <div>
    <div style={S.h1}>API: Authentication & User Management</div>
    <P>Service: kms-auth | Port: 8001 (HTTP) / 18001 (gRPC)</P>
    <Collapse title="Authentication" defaultOpen>
      <EndpointTable rows={[
        ["POST", "/auth/login", "Authenticate user, returns JWT token"],
        ["POST", "/auth/register", "Register new user account"],
        ["POST", "/auth/refresh", "Refresh JWT token"],
        ["POST", "/auth/logout", "Invalidate current session"],
        ["POST", "/auth/change-password", "Change user password"],
        ["GET", "/auth/me", "Get current authenticated user info"],
        ["POST", "/auth/client-token", "Issue a client token for service-to-service auth"],
      ]} />
    </Collapse>
    <Collapse title="SSO & Identity Providers">
      <EndpointTable rows={[
        ["GET", "/auth/sso/providers", "List configured SSO providers"],
        ["GET", "/auth/sso/{provider}/login", "Initiate SSO login flow"],
        ["POST", "/auth/sso/{provider}/callback", "SSO callback handler"],
        ["GET", "/auth/sso/saml/metadata", "Get SAML SP metadata XML"],
        ["GET", "/auth/identity/providers", "List identity provider configs (LDAP, SAML, OIDC)"],
        ["PUT", "/auth/identity/providers/{provider}", "Update identity provider configuration"],
        ["POST", "/auth/identity/providers/{provider}/test", "Test provider connectivity"],
        ["POST", "/auth/identity/import/users", "Bulk import users from identity provider"],
      ]} />
    </Collapse>
    <Collapse title="User Management">
      <EndpointTable rows={[
        ["GET", "/auth/users", "List all users (filterable by tenant, role, status)"],
        ["POST", "/auth/users", "Create new user"],
        ["PUT", "/auth/users/{id}/role", "Update user role"],
        ["PUT", "/auth/users/{id}/status", "Enable/disable user"],
        ["POST", "/auth/users/{id}/reset-password", "Reset user password (admin)"],
      ]} />
    </Collapse>
    <Collapse title="Tenant Management">
      <EndpointTable rows={[
        ["POST", "/tenants", "Create new tenant"],
        ["GET", "/tenants", "List all tenants"],
        ["GET", "/tenants/{id}", "Get tenant details"],
        ["PUT", "/tenants/{id}", "Update tenant settings"],
        ["DELETE", "/tenants/{id}", "Delete tenant (requires readiness check)"],
        ["POST", "/tenants/{id}/disable", "Disable tenant"],
        ["GET", "/tenants/{id}/delete-readiness", "Check if tenant can be safely deleted"],
      ]} />
    </Collapse>
    <Collapse title="Policy & Security">
      <EndpointTable rows={[
        ["GET", "/auth/password-policy", "Get password policy (min length, complexity, expiry)"],
        ["PUT", "/auth/password-policy", "Update password policy"],
        ["GET", "/auth/security-policy", "Get security policy (MFA, session timeout, IP allowlist)"],
        ["PUT", "/auth/security-policy", "Update security policy"],
      ]} />
    </Collapse>
    <Collapse title="API Keys & Clients">
      <EndpointTable rows={[
        ["POST", "/auth/api-keys", "Create API key for programmatic access"],
        ["DELETE", "/auth/api-keys/{id}", "Revoke API key"],
        ["GET", "/auth/clients", "List registered clients"],
        ["POST", "/auth/clients/{id}/rotate-key", "Rotate client credentials"],
      ]} />
    </Collapse>
    <Collapse title="CLI & HSM">
      <EndpointTable rows={[
        ["GET", "/auth/cli/status", "Get CLI SSH daemon status"],
        ["POST", "/auth/cli/session", "Create CLI session"],
        ["GET", "/auth/cli/hsm/config", "Get HSM CLI configuration"],
        ["PUT", "/auth/cli/hsm/config", "Update HSM CLI configuration"],
        ["GET", "/auth/cli/hsm/partitions", "List HSM partitions"],
      ]} />
    </Collapse>
    <H2>Example: Create User</H2>
    <Code>{`curl -X POST http://localhost:8001/auth/users \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "username": "alice",
    "email": "alice@example.com",
    "password": "SecurePass123!",
    "role": "operator",
    "tenant_id": "root"
  }'`}</Code>
  </div>
);

const SectionApiKeycore = () => (
  <div>
    <div style={S.h1}>API: Key Management (Keycore)</div>
    <P>Service: kms-keycore | Port: 8010 (HTTP) / 18010 (gRPC)</P>
    <Collapse title="Key Lifecycle" defaultOpen>
      <EndpointTable rows={[
        ["POST", "/keys", "Create new cryptographic key"],
        ["GET", "/keys", "List keys (supports pagination, filtering)"],
        ["GET", "/keys/{id}", "Get key metadata and details"],
        ["PUT", "/keys/{id}", "Update key metadata (name, tags, expiry)"],
        ["POST", "/keys/{id}/rotate", "Rotate key (creates new version)"],
        ["POST", "/keys/{id}/activate", "Activate a pre-active key"],
        ["POST", "/keys/{id}/deactivate", "Deactivate key (reversible)"],
        ["POST", "/keys/{id}/disable", "Disable key (prevents operations)"],
        ["POST", "/keys/{id}/destroy", "Destroy key (irreversible after grace period)"],
        ["POST", "/keys/{id}/export", "Export key material (if policy allows)"],
        ["POST", "/keys/import", "Import external key material"],
        ["POST", "/keys/form", "Form key from components"],
      ]} />
    </Collapse>
    <Collapse title="Bulk Operations">
      <EndpointTable rows={[
        ["POST", "/keys/bulk-import", "Import up to 500 keys in parallel"],
        ["POST", "/keys/bulk-rotate", "Rotate multiple keys by ID"],
        ["POST", "/keys/bulk-delete", "Soft-delete multiple keys by ID"],
      ]} />
    </Collapse>
    <Collapse title="Cryptographic Operations">
      <EndpointTable rows={[
        ["POST", "/keys/{id}/encrypt", "Encrypt data with key"],
        ["POST", "/keys/{id}/decrypt", "Decrypt ciphertext"],
        ["POST", "/keys/{id}/sign", "Create digital signature"],
        ["POST", "/keys/{id}/verify", "Verify digital signature"],
        ["POST", "/keys/{id}/wrap", "Wrap (encrypt) another key"],
        ["POST", "/keys/{id}/unwrap", "Unwrap (decrypt) a wrapped key"],
        ["POST", "/keys/{id}/derive", "Derive new key from existing key"],
        ["POST", "/keys/{id}/mac", "Compute message authentication code"],
        ["POST", "/keys/{id}/kem/encapsulate", "KEM encapsulation (post-quantum)"],
        ["POST", "/keys/{id}/kem/decapsulate", "KEM decapsulation (post-quantum)"],
      ]} />
    </Collapse>
    <Collapse title="Key Versions & Usage">
      <EndpointTable rows={[
        ["GET", "/keys/{id}/versions", "List all versions of a key"],
        ["GET", "/keys/{id}/usage", "Get key usage statistics"],
        ["PUT", "/keys/{id}/usage/limit", "Set operation count limit"],
        ["GET", "/keys/{id}/kcv", "Get key check value"],
        ["GET", "/keys/{id}/access-policy", "Get key access policy"],
        ["PUT", "/keys/{id}/access-policy", "Set allowed operations per role"],
      ]} />
    </Collapse>
    <Collapse title="Tags & Access Groups">
      <EndpointTable rows={[
        ["GET", "/tags", "List all tags"],
        ["POST", "/tags", "Create or update tag"],
        ["DELETE", "/tags/{name}", "Delete tag"],
        ["GET", "/access/groups", "List access groups"],
        ["POST", "/access/groups", "Create access group"],
      ]} />
    </Collapse>
    <H2>Example: Create AES-256 Key</H2>
    <Code>{`curl -X POST http://localhost:8010/keys \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "my-encryption-key",
    "algorithm": "AES",
    "size": 256,
    "operations": ["encrypt", "decrypt"],
    "tags": ["production", "pci"]
  }'`}</Code>
    <H2>Example: Encrypt Data</H2>
    <Code>{`curl -X POST http://localhost:8010/keys/{key_id}/encrypt \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "plaintext": "SGVsbG8gV29ybGQ=",
    "aad": "optional-context"
  }'
# Returns: { "ciphertext": "base64...", "iv": "base64...", "tag": "base64..." }`}</Code>
  </div>
);

const SectionApiSecrets = () => (
  <div>
    <div style={S.h1}>API: Secrets Vault</div>
    <P>Service: kms-secrets | Port: 8020 (HTTP) / 18020 (gRPC) | Profile: secrets</P>

    <H2>What is the Secrets Vault?</H2>
    <P>The Secrets Vault is a secure, encrypted store for sensitive data that isn't a cryptographic key — think database passwords, API tokens, SSH keys, TLS certificates, PGP keys, OAuth secrets, and any other credentials your applications need. Every secret is encrypted at rest using envelope encryption (AES-256-GCM), versioned so you can see history, and every access is audit-logged.</P>

    <H2>How It Works</H2>
    <P>1. Store a secret with a name, category, and value. The value is encrypted using a Data Encryption Key (DEK) which is itself wrapped by the KMS master key. 2. Applications retrieve secrets by ID or name via the REST API. Every retrieval is logged in the audit trail. 3. When credentials change, rotate the secret — this creates a new version while preserving the old one for rollback. 4. Set lease-based access to auto-expire secrets after a time period.</P>

    <H2>Use Cases</H2>
    <P>- Application configuration: Store database connection strings, API keys, and service credentials centrally instead of in config files or environment variables</P>
    <P>- CI/CD pipelines: Inject secrets into build and deployment pipelines without hardcoding them in repos</P>
    <P>- SSH key management: Generate, store, and rotate SSH keypairs for server access with full audit trail</P>
    <P>- Certificate storage: Store TLS certificates and private keys, with expiry tracking and rotation reminders</P>
    <P>- Credential rotation: Automate password rotation for database accounts, service accounts, and API keys</P>
    <P>- Audit compliance: Demonstrate to auditors that all secrets are encrypted, access-controlled, and logged</P>

    <Collapse title="Secret Management" defaultOpen>
      <EndpointTable rows={[
        ["POST", "/secrets", "Create a new secret (encrypted, versioned, audit-logged)"],
        ["GET", "/secrets", "List secrets — returns metadata only, never values"],
        ["GET", "/secrets/{id}", "Get secret metadata (name, category, version, created, updated)"],
        ["PUT", "/secrets/{id}", "Update secret metadata (name, tags, lease settings)"],
        ["DELETE", "/secrets/{id}", "Delete secret (soft-delete, recoverable within retention period)"],
        ["GET", "/secrets/{id}/value", "Retrieve the actual secret value — every call is audit-logged"],
        ["POST", "/secrets/{id}/rotate", "Rotate to a new value (old version preserved in history)"],
        ["GET", "/secrets/{id}/versions", "List all versions with timestamps and who rotated"],
        ["GET", "/secrets/{id}/audit", "Get the complete audit trail for this specific secret"],
        ["GET", "/secrets/stats", "Vault statistics: total secrets, by category, access frequency"],
      ]} />
    </Collapse>
    <Collapse title="Key Generation">
      <EndpointTable rows={[
        ["POST", "/secrets/generate/keypair", "Generate RSA/EC/ED25519 keypair, store both keys as a secret"],
        ["POST", "/secrets/generate/ssh_key", "Generate SSH key (RSA/ED25519), store as an SSH Key secret"],
      ]} />
    </Collapse>

    <H2>Secret Categories</H2>
    <P>Secrets are organized by type for easy filtering and policy application: Credentials (username/password, connection strings), SSH Keys (public/private keypairs), PGP Keys (encryption/signing), X.509 Certificates (TLS certs and keys), Tokens (API keys, OAuth tokens, JWTs), Key Material (raw key bytes), Other (custom data).</P>

    <H2>Example: Store, Retrieve, and Rotate a Secret</H2>
    <Code>{`# Store a database credential
curl -X POST http://localhost:8020/secrets \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{
    "name": "prod-db-password",
    "category": "credentials",
    "value": "SuperSecretPassword123!",
    "metadata": { "environment": "production", "database": "orders-db" }
  }'

# Retrieve the secret value (audit-logged)
curl http://localhost:8020/secrets/sec-xxx/value \\
  -H "Authorization: Bearer $TOKEN"
# Returns: { "value": "SuperSecretPassword123!", "version": 1 }

# Rotate the password (after changing it in the database)
curl -X POST http://localhost:8020/secrets/sec-xxx/rotate \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{ "value": "NewPassword456!" }'
# Now version 2 is active; version 1 is preserved in history

# Generate an SSH keypair and store it
curl -X POST http://localhost:8020/secrets/generate/ssh_key \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{ "name": "deploy-key", "algorithm": "ed25519" }'`}</Code>
  </div>
);

const SectionApiCerts = () => (
  <div>
    <div style={S.h1}>API: Certificates & PKI</div>
    <P>Service: kms-certs | Port: 8030 (HTTP) / 18030 (gRPC) | Profile: certs</P>

    <H2>What is PKI?</H2>
    <P>Public Key Infrastructure (PKI) is the system of digital certificates, certificate authorities, and trust chains that enables secure identity verification and encrypted communication across networks. Vecta KMS provides a complete, private PKI — you can create your own Certificate Authorities, issue certificates to servers, users, and devices, manage revocation, and support automated enrollment protocols.</P>

    <H2>How It Works</H2>
    <P>1. Create a Root CA — the trust anchor for your organization. 2. Optionally create Intermediate CAs signed by the root for department or environment separation. 3. Issue certificates from your CAs: TLS server certs, client auth certs, code signing certs, email (S/MIME) certs. 4. Distribute the CA certificate to clients so they trust certificates issued by your PKI. 5. Manage the lifecycle: renew before expiry, revoke compromised certs, publish CRLs and OCSP responses.</P>

    <H2>Use Cases</H2>
    <P>- Internal TLS: Issue certificates for internal services, APIs, and microservices without relying on public CAs</P>
    <P>- mTLS (Mutual TLS): Issue client certificates for zero-trust authentication between services, IoT devices, or KMIP clients</P>
    <P>- DevOps automation: Use ACME protocol (like Let's Encrypt) for automated certificate issuance and renewal in CI/CD pipelines</P>
    <P>- MDM / Network devices: Use SCEP for automated certificate enrollment on mobile devices and network equipment (routers, switches, APs)</P>
    <P>- Enterprise PKI: Replace or supplement Microsoft AD CS with a vendor-neutral PKI for cross-platform certificate management</P>
    <P>- Code signing: Issue code signing certificates to developers for signing binaries, containers, and packages</P>
    <P>- Email security: Issue S/MIME certificates for encrypted and signed email communication</P>

    <H2>Enrollment Protocols Explained</H2>
    <H3>ACME (RFC 8555)</H3>
    <P>Automated Certificate Management Environment. The same protocol used by Let's Encrypt. Clients request certificates, complete challenges (HTTP-01, DNS-01, TLS-ALPN-01) to prove domain ownership, and receive certificates automatically. Ideal for web servers, load balancers, and any system that supports ACME (certbot, cert-manager, Caddy).</P>
    <H3>EST (RFC 7030)</H3>
    <P>Enrollment over Secure Transport. A modern, TLS-based protocol for certificate enrollment. Simpler than SCEP, supports initial enrollment and re-enrollment. Used by enterprise devices, IoT gateways, and modern network equipment.</P>
    <H3>SCEP (Simple Certificate Enrollment Protocol)</H3>
    <P>Legacy but widely supported protocol used by MDM platforms (Intune, Jamf, MobileIron) and network devices (Cisco, Juniper). Devices request certificates using a one-time password or challenge. Still required for compatibility with older infrastructure.</P>
    <H3>CMPv2 (Certificate Management Protocol v2)</H3>
    <P>Full-featured certificate management protocol supporting initial enrollment, key update, revocation, and cross-certification. Used in telecom and high-security environments.</P>

    <Collapse title="Certificate Authority" defaultOpen>
      <EndpointTable rows={[
        ["POST", "/certs/ca", "Create a new CA (root or intermediate, RSA/EC/ED25519)"],
        ["GET", "/certs/ca", "List all certificate authorities with chain info"],
        ["DELETE", "/certs/ca/{id}", "Delete a CA (only if no active certs issued)"],
      ]} />
    </Collapse>
    <Collapse title="Certificate Lifecycle">
      <EndpointTable rows={[
        ["POST", "/certs", "Issue a new certificate from a CA"],
        ["GET", "/certs", "List all certificates with status and expiry"],
        ["GET", "/certs/{id}", "Get certificate details (subject, issuer, validity, chain)"],
        ["GET", "/certs/download/{id}", "Download in PEM, DER, or PKCS12 format"],
        ["POST", "/certs/{id}/renew", "Renew certificate with same subject and new validity"],
        ["POST", "/certs/{id}/revoke", "Revoke certificate (added to CRL)"],
        ["POST", "/certs/sign-csr", "Sign an externally generated CSR"],
        ["POST", "/certs/upload-3p", "Upload a third-party certificate for inventory tracking"],
        ["GET", "/certs/inventory", "Full certificate inventory with expiry alerts"],
      ]} />
    </Collapse>
    <Collapse title="ACME Protocol (RFC 8555)">
      <EndpointTable rows={[
        ["GET", "/acme/directory", "ACME directory (entry point for ACME clients)"],
        ["POST", "/acme/new-account", "Register a new ACME account"],
        ["POST", "/acme/new-order", "Create a certificate order for a domain"],
        ["POST", "/acme/challenge/{id}", "Complete domain validation challenge"],
        ["POST", "/acme/finalize/{id}", "Finalize order and download certificate"],
      ]} />
    </Collapse>
    <Collapse title="EST / SCEP / CMPv2">
      <EndpointTable rows={[
        ["GET", "/est/.well-known/est/cacerts", "EST: Download CA certificates"],
        ["POST", "/est/.well-known/est/simpleenroll", "EST: Initial enrollment"],
        ["POST", "/est/.well-known/est/simplereenroll", "EST: Re-enrollment (renewal)"],
        ["GET", "/scep/pkiclient.exe", "SCEP: GetCACert, GetCACaps operations"],
        ["POST", "/scep/pkiclient.exe", "SCEP: PKIOperation (enrollment request)"],
        ["POST", "/cmpv2", "CMPv2: Certificate request/update/revocation"],
      ]} />
    </Collapse>
    <Collapse title="CRL & OCSP">
      <EndpointTable rows={[
        ["GET", "/certs/crl", "Download the Certificate Revocation List"],
        ["POST", "/certs/ocsp", "OCSP responder for real-time revocation checking"],
      ]} />
    </Collapse>
    <Collapse title="Merkle Transparency">
      <EndpointTable rows={[
        ["POST", "/certs/merkle/build", "Build a Merkle epoch for certificate transparency logging"],
        ["GET", "/certs/merkle/epochs", "List Merkle transparency epochs"],
        ["GET", "/certs/merkle/proof/{id}", "Get cryptographic proof that a certificate was properly logged"],
        ["POST", "/certs/merkle/verify", "Verify a Merkle inclusion proof"],
      ]} />
    </Collapse>

    <H2>Example: Create CA and Issue Certificate</H2>
    <Code>{`# Step 1: Create a root CA
curl -X POST http://localhost:8030/certs/ca \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{
    "name": "My Organization Root CA",
    "algorithm": "EC", "curve": "P-384",
    "validity_years": 10, "is_root": true,
    "subject": { "organization": "My Org", "country": "US" }
  }'

# Step 2: Issue a TLS server certificate from the CA
curl -X POST http://localhost:8030/certs \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{
    "ca_id": "ca-xxx", "common_name": "api.myorg.internal",
    "san_dns": ["api.myorg.internal", "api"],
    "san_ip": ["10.0.1.50"],
    "validity_days": 365, "key_usage": ["digitalSignature", "keyEncipherment"],
    "extended_key_usage": ["serverAuth"]
  }'

# Step 3: Download the certificate
curl -o server.pem http://localhost:8030/certs/download/cert-xxx?format=pem \\
  -H "Authorization: Bearer $TOKEN"`}</Code>
  </div>
);

const SectionApiAudit = () => (
  <div>
    <div style={S.h1}>API: Audit & Alerting</div>
    <P>Service: kms-audit | Port: 8070 (HTTP) / 18070 (gRPC)</P>
    <P>The audit stream now records posture/compliance/reporting interactions for the newer operational views too. Operators will see subjects such as <IC>audit.posture.dashboard_viewed</IC>, <IC>audit.compliance.assessment_delta_viewed</IC>, <IC>audit.reporting.evidence_pack_requested</IC>, and <IC>audit.reporting.mttd_stats_viewed</IC> in the same tamper-evident audit timeline.</P>
    <Collapse title="Audit Events" defaultOpen>
      <EndpointTable rows={[
        ["POST", "/audit/publish", "Publish audit event (internal)"],
        ["GET", "/audit/events", "Query audit events (filterable)"],
        ["GET", "/audit/events/{id}", "Get specific event details"],
        ["GET", "/audit/events/{id}/proof", "Get Merkle proof for event"],
        ["GET", "/audit/timeline/{target_id}", "Get event timeline for a resource"],
        ["POST", "/audit/search", "Advanced event search"],
        ["GET", "/audit/stats", "Get audit statistics"],
      ]} />
    </Collapse>
    <Collapse title="Merkle Chain Verification">
      <EndpointTable rows={[
        ["GET", "/audit/chain/verify", "Verify audit chain integrity"],
        ["POST", "/audit/merkle/build", "Build Merkle epoch"],
        ["GET", "/audit/merkle/epochs", "List Merkle epochs"],
        ["POST", "/audit/merkle/verify", "Verify Merkle tree"],
      ]} />
    </Collapse>
    <Collapse title="Alert Management">
      <EndpointTable rows={[
        ["GET", "/alerts", "List alerts"],
        ["GET", "/alerts/{id}", "Get alert details"],
        ["PUT", "/alerts/{id}/{action}", "Acknowledge / escalate / resolve alert"],
        ["GET", "/alerts/stats", "Get alert statistics"],
        ["POST", "/alerts/rules", "Create alert rule"],
        ["GET", "/alerts/rules", "List alert rules"],
        ["GET", "/alerts/channels", "Get alert channels (SMTP, Slack, webhook)"],
        ["PUT", "/alerts/channels", "Update alert channels"],
        ["POST", "/alerts/channels/test", "Test alert channel delivery"],
      ]} />
    </Collapse>
    <Collapse title="New Posture / Compliance / Reporting Subjects">
      <EndpointTable rows={[
        ["AUDIT", "audit.posture.dashboard_viewed", "Recorded when the enriched posture dashboard is fetched, including risk-driver and cockpit counts"],
        ["AUDIT", "audit.compliance.assessment_delta_viewed", "Recorded when the operator opens the 'What Changed Since Last Scan' delta view"],
        ["AUDIT", "audit.reporting.evidence_pack_requested", "Recorded when an Evidence Pack export is requested"],
        ["AUDIT", "audit.reporting.mttd_stats_viewed", "Recorded when MTTD timing analytics are fetched"],
      ]} />
    </Collapse>
  </div>
);

const SectionApiPolicy = () => (
  <div>
    <div style={S.h1}>API: Policy Engine</div>
    <P>Service: kms-policy | Port: 8040 (HTTP) / 18040 (gRPC)</P>
    <EndpointTable rows={[
      ["POST", "/policies", "Create policy"],
      ["GET", "/policies", "List policies"],
      ["GET", "/policies/{id}", "Get policy"],
      ["PUT", "/policies/{id}", "Update policy"],
      ["DELETE", "/policies/{id}", "Delete policy"],
      ["GET", "/policies/{id}/versions", "List policy versions"],
      ["POST", "/policy/evaluate", "Evaluate policy against request context"],
    ]} />
  </div>
);

const SectionApiGovernance = () => (
  <div>
    <div style={S.h1}>API: Governance & Approvals</div>
    <P>Service: kms-governance | Port: 8050 (HTTP) / 18050 (gRPC) | Profile: governance</P>

    <H2>What is Governance?</H2>
    <P>Governance adds multi-party approval workflows to high-risk KMS operations. Instead of a single admin being able to destroy a production key, create a tenant, or export key material, governance policies require multiple authorized users to approve the operation. This implements the security principles of dual control (two people required) and separation of duties (the requester can't approve their own request).</P>

    <H2>How Approval Workflows Work</H2>
    <P>1. An operator requests a sensitive operation (e.g., "destroy key prod-master-key"). 2. The governance engine checks if a policy applies to this operation type. 3. If a policy matches, the request enters "pending" status and notifications are sent to eligible approvers. 4. Approvers review the request and vote (approve or deny). 5. When the quorum is met (e.g., 2 of 3 approvers), the operation is automatically executed. 6. If the timeout expires before quorum, the request is rejected.</P>

    <H2>Use Cases</H2>
    <P>- Key destruction: Require 2 security officers to approve before any production key is destroyed</P>
    <P>- Key export: Require compliance officer approval before key material can be exported</P>
    <P>- Tenant creation: Require management approval before creating new organizational tenants</P>
    <P>- User role changes: Require admin approval before granting elevated privileges</P>
    <P>- Backup restoration: Require dual authorization before restoring a backup (prevents unauthorized data recovery)</P>

    <Collapse title="Approval Workflows" defaultOpen>
      <EndpointTable rows={[
        ["GET", "/governance/requests", "List approval requests (filter by status, requester, type)"],
        ["POST", "/governance/requests", "Create a new approval request for a sensitive operation"],
        ["GET", "/governance/requests/{id}", "Get request details with vote history and status"],
        ["POST", "/governance/requests/{id}/cancel", "Cancel a pending request (requester only)"],
        ["GET", "/governance/requests/pending/count", "Get count of pending requests (for dashboard badge)"],
        ["POST", "/governance/approve/{id}", "Vote on a request (approve or deny with comment)"],
      ]} />
    </Collapse>
    <Collapse title="Policies">
      <EndpointTable rows={[
        ["GET", "/governance/policies", "List all governance policies with scope and quorum"],
        ["POST", "/governance/policies", "Create a governance policy (define scope, quorum, approvers)"],
        ["PUT", "/governance/policies/{id}", "Update an existing policy"],
        ["DELETE", "/governance/policies/{id}", "Delete a policy (operations revert to no approval required)"],
      ]} />
    </Collapse>
    <Collapse title="Backup & Restore">
      <EndpointTable rows={[
        ["GET", "/governance/backups", "List available backups with scope and timestamp"],
        ["POST", "/governance/backups", "Create an encrypted backup (AES-256-GCM, .vbk format)"],
        ["POST", "/governance/backups/restore", "Restore from a backup (may require approval policy)"],
        ["GET", "/governance/backups/{id}/artifact", "Download the encrypted backup file"],
        ["GET", "/governance/backups/{id}/key", "Download the backup encryption key (separate from artifact)"],
      ]} />
    </Collapse>
    <Collapse title="Notification Settings">
      <EndpointTable rows={[
        ["GET", "/governance/settings", "Get notification settings (SMTP, Slack, webhook config)"],
        ["PUT", "/governance/settings", "Update notification channels"],
        ["POST", "/governance/settings/smtp/test", "Send a test email to verify SMTP configuration"],
        ["POST", "/governance/settings/webhook/test", "Send a test webhook to verify endpoint"],
      ]} />
    </Collapse>
  </div>
);

const SectionApiDataprotect = () => (
  <div>
    <div style={S.h1}>API: Data Protection</div>
    <P>Service: kms-dataprotect | Port: 8200 (HTTP) / 18200 (gRPC) | Profile: data_protection</P>

    <H2>What is Data Protection?</H2>
    <P>Data Protection provides application-level tools to protect sensitive data in your databases, APIs, and applications — without changing your database schema or application architecture. It offers tokenization (replace real data with non-reversible tokens), format-preserving encryption (encrypt data while keeping the same format), masking (hide parts of data for display), redaction (permanently remove sensitive data), and field-level encryption (encrypt individual JSON/document fields).</P>

    <H2>Key Concepts</H2>
    <H3>Tokenization</H3>
    <P>Replaces sensitive data (credit card numbers, SSNs) with random tokens. The mapping between real data and tokens is stored in a secure token vault. Useful for PCI-DSS compliance: tokenized data is out of scope for PCI audits because it's not actual cardholder data.</P>
    <H3>Format-Preserving Encryption (FPE)</H3>
    <P>Encrypts data while preserving its format and length. A 16-digit credit card number encrypts to another 16-digit number. A phone number encrypts to another valid phone number. Ideal when you can't change database column types or application validation logic.</P>
    <H3>Masking</H3>
    <P>Partially hides data for display purposes. "4532-XXXX-XXXX-1234" shows first/last 4 digits of a credit card. Useful for customer service representatives who need to verify identity without seeing full card numbers.</P>
    <H3>Envelope Encryption</H3>
    <P>A two-layer encryption scheme: data is encrypted with a random DEK (Data Encryption Key), and the DEK is encrypted with a KEK (Key Encryption Key) from the KMS. This allows encrypting large amounts of data without sending it all to the KMS — only the small DEK is managed by KMS.</P>
    <H3>Searchable Encryption</H3>
    <P>Encrypts data while preserving the ability to search. Uses blind indexing or deterministic encryption so you can query "find all records where email = X" without decrypting every record.</P>

    <H2>Use Cases</H2>
    <P>- PCI-DSS: Tokenize credit card numbers so your database is out of PCI scope</P>
    <P>- GDPR: Pseudonymize personal data using tokenization; redact data for deletion requests</P>
    <P>- Healthcare: Encrypt PHI at the field level in EHR databases while keeping non-sensitive fields queryable</P>
    <P>- Analytics: Mask/tokenize data before sending to analytics platforms so analysts never see real PII</P>
    <P>- Development: Create realistic test data by masking production data for development environments</P>

    <Collapse title="Tokenization" defaultOpen>
      <EndpointTable rows={[
        ["POST", "/tokenize", "Tokenize a single sensitive value"],
        ["POST", "/tokenize/batch", "Tokenize multiple values in one call"],
        ["POST", "/detokenize", "Retrieve the original value from a token"],
        ["POST", "/detokenize/batch", "Batch detokenization"],
        ["GET", "/token-vaults", "List token vaults (isolated token stores)"],
        ["POST", "/token-vaults", "Create a new token vault"],
      ]} />
    </Collapse>
    <Collapse title="Format-Preserving Encryption">
      <EndpointTable rows={[
        ["POST", "/fpe/encrypt", "FPE encrypt — output has same format as input"],
        ["POST", "/fpe/decrypt", "FPE decrypt — restore original value"],
      ]} />
    </Collapse>
    <Collapse title="Masking & Redaction">
      <EndpointTable rows={[
        ["POST", "/mask", "Mask sensitive data fields with configurable patterns"],
        ["POST", "/mask/preview", "Preview masking output without persisting"],
        ["POST", "/redact", "Permanently redact (remove) sensitive data"],
        ["POST", "/redact/detect", "Auto-detect PII/sensitive data in text for redaction"],
      ]} />
    </Collapse>
    <Collapse title="Application-Level Encryption">
      <EndpointTable rows={[
        ["POST", "/app/encrypt-fields", "Encrypt specific JSON fields in a document"],
        ["POST", "/app/decrypt-fields", "Decrypt specific encrypted fields"],
        ["POST", "/app/envelope-encrypt", "Envelope encrypt: DEK encrypts data, KEK wraps DEK"],
        ["POST", "/app/envelope-decrypt", "Envelope decrypt: unwrap DEK, decrypt data"],
        ["POST", "/app/searchable-encrypt", "Encrypt with searchable blind index"],
        ["POST", "/app/searchable-decrypt", "Decrypt searchable-encrypted data"],
      ]} />
    </Collapse>
    <Collapse title="Field Encryption SDK">
      <EndpointTable rows={[
        ["GET", "/field-encryption/wrappers", "List registered SDK wrappers (app clients)"],
        ["POST", "/field-encryption/register/init", "Begin SDK wrapper registration handshake"],
        ["POST", "/field-encryption/register/complete", "Complete registration and receive credentials"],
        ["POST", "/field-encryption/leases", "Issue a time-limited crypto lease for SDK operations"],
        ["POST", "/field-encryption/leases/{id}/revoke", "Revoke an active lease immediately"],
      ]} />
    </Collapse>

    <H2>Example: Tokenize a Credit Card Number</H2>
    <Code>{`# Tokenize a credit card
curl -X POST http://localhost:8200/tokenize \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{ "value": "4532015112830366", "format": "credit_card" }'
# Returns: { "token": "tok_a1b2c3d4e5f6g7h8", "vault_id": "default" }

# Later, detokenize to get the real value
curl -X POST http://localhost:8200/detokenize \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{ "token": "tok_a1b2c3d4e5f6g7h8" }'
# Returns: { "value": "4532015112830366" }

# FPE: encrypt a SSN while keeping the format
curl -X POST http://localhost:8200/fpe/encrypt \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{ "value": "123-45-6789", "tweak": "user-42", "key_id": "fpe-key-xxx" }'
# Returns: { "ciphertext": "847-29-3156" }  ← same format, different value`}</Code>
  </div>
);

const SectionApiPayment = () => (
  <div>
    <div style={S.h1}>API: Payment Cryptography</div>
    <P>Service: kms-payment | Port: 8170 (HTTP) / 18170 (gRPC) | Profile: payment_crypto</P>
    <Collapse title="TR-31 Key Blocks" defaultOpen>
      <EndpointTable rows={[
        ["POST", "/payment/tr31/create", "Create TR-31 key block"],
        ["POST", "/payment/tr31/parse", "Parse TR-31 block"],
        ["POST", "/payment/tr31/translate", "Translate TR-31 between KEKs"],
        ["POST", "/payment/tr31/validate", "Validate TR-31 block integrity"],
        ["GET", "/payment/tr31/key-usages", "Get supported TR-31 key usages"],
      ]} />
    </Collapse>
    <Collapse title="PIN Operations">
      <EndpointTable rows={[
        ["POST", "/payment/pin/translate", "Translate PIN block between keys"],
        ["POST", "/payment/pin/offset/generate", "Generate PIN offset"],
        ["POST", "/payment/pin/offset/verify", "Verify PIN offset"],
        ["POST", "/payment/pin/pvv/generate", "Generate PIN Verification Value"],
        ["POST", "/payment/pin/pvv/verify", "Verify PVV"],
        ["POST", "/payment/pin/cvv/compute", "Compute CVV/CVC"],
        ["POST", "/payment/pin/cvv/verify", "Verify CVV/CVC"],
      ]} />
    </Collapse>
    <Collapse title="MAC Operations">
      <EndpointTable rows={[
        ["POST", "/payment/mac/iso9797", "ISO 9797 MAC computation"],
        ["POST", "/payment/mac/cmac", "AES-CMAC computation"],
        ["POST", "/payment/mac/retail", "Retail MAC (ISO 9797-1 Algo 3)"],
        ["POST", "/payment/mac/verify", "Verify MAC value"],
      ]} />
    </Collapse>
    <Collapse title="ISO 20022">
      <EndpointTable rows={[
        ["POST", "/payment/iso20022/encrypt", "Encrypt ISO 20022 message"],
        ["POST", "/payment/iso20022/decrypt", "Decrypt ISO 20022 message"],
        ["POST", "/payment/iso20022/sign", "Sign ISO 20022 message"],
        ["POST", "/payment/iso20022/verify", "Verify ISO 20022 signature"],
        ["POST", "/payment/iso20022/lau/generate", "Generate LAU"],
        ["POST", "/payment/iso20022/lau/verify", "Verify LAU"],
      ]} />
    </Collapse>
    <Collapse title="Key Injection">
      <EndpointTable rows={[
        ["GET", "/payment/injection/terminals", "List registered terminals"],
        ["POST", "/payment/injection/terminals", "Register key injection terminal"],
        ["POST", "/payment/injection/terminals/{id}/challenge", "Challenge terminal"],
        ["POST", "/payment/injection/jobs", "Create injection job"],
      ]} />
    </Collapse>
  </div>
);

const SectionApiCloud = () => (
  <div>
    <div style={S.h1}>API: Cloud Key Control (BYOK)</div>
    <P>Service: kms-cloud | Port: 8080 (HTTP) / 18080 (gRPC) | Profile: cloud_byok</P>

    <H2>What is BYOK?</H2>
    <P>Bring Your Own Key (BYOK) lets you generate and manage encryption keys in your own KMS and then push those keys into cloud provider key management services (AWS KMS, Azure Key Vault, GCP KMS, Oracle Cloud Vault, Salesforce). This gives you control over key generation, lifecycle, and audit — the cloud provider never generates or sees your key material. If you leave a cloud provider, you retain the keys.</P>

    <H2>How BYOK Works</H2>
    <P>1. Register your cloud provider account with credentials (IAM role ARN, Azure tenant/client, GCP service account, etc.). 2. Create a key in Vecta KMS. 3. Create a "binding" that pushes the key material to the cloud provider's KMS. 4. The cloud provider uses your key for encrypting data (S3, EBS, RDS, Azure Storage, BigQuery, etc.). 5. Vecta tracks the binding and can rotate, sync, or revoke the cloud key from a single pane.</P>

    <H2>Use Cases</H2>
    <P>- Regulatory compliance: Regulations require you to control your own encryption keys, not let the cloud provider generate them</P>
    <P>- Multi-cloud key consistency: Manage keys for AWS, Azure, and GCP from one central KMS with unified policy and audit</P>
    <P>- Key lifecycle control: Rotate keys on your schedule, not the cloud provider's. Disable or destroy cloud keys instantly</P>
    <P>- Cloud exit strategy: If you leave a cloud provider, you still have the keys and can decrypt your data</P>

    <P>Supported providers: AWS KMS, Azure Key Vault, Google Cloud KMS, Oracle Cloud Vault, Salesforce Shield.</P>

    <Collapse title="BYOK Endpoints" defaultOpen>
      <EndpointTable rows={[
        ["GET", "/cloud/accounts", "List registered cloud provider accounts"],
        ["POST", "/cloud/accounts", "Register a cloud account with provider credentials"],
        ["DELETE", "/cloud/accounts/{id}", "Remove a cloud account registration"],
        ["GET", "/cloud/bindings", "List all key bindings (local KMS key ↔ cloud key)"],
        ["GET", "/cloud/bindings/{id}", "Get binding details (sync status, last rotation)"],
        ["POST", "/cloud/bindings/{id}/rotate", "Rotate the key in the cloud provider"],
        ["GET", "/cloud/inventory", "Discover all keys in your cloud accounts"],
        ["POST", "/cloud/import", "Import cloud keys into Vecta KMS"],
        ["POST", "/cloud/sync", "Sync binding state with cloud provider"],
        ["GET", "/cloud/region-mappings", "List region mappings for multi-region deployments"],
        ["POST", "/cloud/region-mappings", "Create a region mapping"],
      ]} />
    </Collapse>

    <H2>Example: BYOK to AWS KMS</H2>
    <Code>{`# Register AWS account
curl -X POST http://localhost:8080/cloud/accounts \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{
    "provider": "aws", "name": "prod-aws",
    "credentials": { "role_arn": "arn:aws:iam::123456789:role/kms-byok",
      "region": "us-east-1" }
  }'

# Push a local key to AWS KMS (creates binding)
curl -X POST http://localhost:8080/cloud/bindings \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{ "key_id": "key-xxx", "account_id": "acc-xxx", "alias": "prod-data-key" }'`}</Code>
  </div>
);

const SectionApiHyok = () => (
  <div>
    <div style={S.h1}>API: HYOK (Hold Your Own Key)</div>
    <P>Service: kms-hyok-proxy | Port: 8120 (HTTP) / 18120 (gRPC) | Profile: hyok_proxy</P>

    <H2>What is HYOK?</H2>
    <P>Hold Your Own Key (HYOK) goes beyond BYOK. Instead of pushing keys to the cloud, the key NEVER leaves your KMS. Cloud services call your KMS in real-time to encrypt/decrypt data — you hold the key, and the cloud asks permission every time it needs to use it. If you revoke access, the cloud service instantly loses the ability to decrypt your data. This gives you the ultimate control: you can cut off a cloud provider's access to your data with a single API call.</P>

    <H2>Supported HYOK Protocols</H2>
    <H3>Microsoft DKE (Double Key Encryption)</H3>
    <P>Microsoft 365 Double Key Encryption lets you protect the most sensitive Office documents (Word, Excel, Outlook) and Teams data with two keys: one held by Microsoft, one held by you in Vecta KMS. Both keys are required to decrypt — if you revoke your key, not even Microsoft can read the data. Ideal for law firms, government agencies, and financial institutions with strict data sovereignty requirements.</P>
    <H3>Salesforce Cache-Only Key Service</H3>
    <P>Salesforce Shield allows you to encrypt Salesforce data with your own key. In cache-only mode, Salesforce never persists your key — it requests it from your KMS each time and only holds it in memory. If you revoke, Salesforce data becomes inaccessible. Ideal for organizations with highly regulated Salesforce data (HIPAA, financial).</P>
    <H3>Google Cloud EKM (External Key Manager)</H3>
    <P>Google Cloud External Key Manager lets Google Cloud services (BigQuery, Compute Engine, Cloud Storage) use keys stored in your Vecta KMS. Google never has access to the key material. All crypto operations are performed through your KMS. You can monitor all access requests in real-time.</P>

    <H2>Use Cases</H2>
    <P>- Data sovereignty: Keys never leave your jurisdiction. Required for certain government and financial regulations</P>
    <P>- Instant revocation: Cut off cloud access to your encrypted data by disabling a single key</P>
    <P>- Real-time audit: Every encryption/decryption request from the cloud is logged in your KMS audit trail</P>
    <P>- Multi-cloud HYOK: Control keys for Microsoft 365, Salesforce, and Google Cloud from one KMS</P>

    <Collapse title="Microsoft DKE" defaultOpen>
      <EndpointTable rows={[
        ["GET", "/hyok/dke/v1/keys/{id}/publickey", "Serve DKE public key to Microsoft 365"],
        ["POST", "/hyok/dke/v1/keys/{id}/decrypt", "Decrypt data on behalf of Microsoft 365"],
      ]} />
    </Collapse>
    <Collapse title="Salesforce Cache-Only">
      <EndpointTable rows={[
        ["POST", "/hyok/salesforce/v1/keys/{id}/wrap", "Wrap a key for Salesforce Shield"],
        ["POST", "/hyok/salesforce/v1/keys/{id}/unwrap", "Unwrap a key from Salesforce"],
      ]} />
    </Collapse>
    <Collapse title="Google Cloud EKM">
      <EndpointTable rows={[
        ["POST", "/hyok/google/v1/keys/{id}/wrap", "Wrap key for Google Cloud EKM"],
        ["POST", "/hyok/google/v1/keys/{id}/unwrap", "Unwrap key from Google Cloud"],
      ]} />
    </Collapse>
    <Collapse title="Endpoint Management">
      <EndpointTable rows={[
        ["GET", "/hyok/v1/endpoints", "List all HYOK protocol endpoints with status"],
        ["PUT", "/hyok/v1/endpoints/{protocol}", "Configure a HYOK endpoint (DKE, Salesforce, Google)"],
        ["GET", "/hyok/v1/health", "Get HYOK service health and endpoint availability"],
        ["GET", "/hyok/v1/requests", "View the HYOK request log (every cloud access is logged)"],
      ]} />
    </Collapse>
  </div>
);

const SectionApiEkm = () => (
  <div>
    <div style={S.h1}>API: Enterprise Key Manager (EKM)</div>
    <P>Service: kms-ekm | Port: 8130 (HTTP) / 18130 (gRPC) | Profile: ekm_database</P>

    <H2>What is EKM?</H2>
    <P>Enterprise Key Manager extends Vecta KMS to manage encryption keys for databases (TDE — Transparent Data Encryption) and endpoint devices (BitLocker). Instead of each database server or Windows machine managing its own encryption keys, EKM centralizes key management so you have a single point of control, audit, and rotation for all data-at-rest encryption across your infrastructure.</P>

    <H2>Database TDE (Transparent Data Encryption)</H2>
    <P>TDE encrypts entire database files transparently — applications don't need to change. The database server encrypts data as it writes to disk and decrypts as it reads. Vecta manages the TDE master key: the database has a DEK (Data Encryption Key) that encrypts the data, and that DEK is wrapped by a KEK (Key Encryption Key) stored in Vecta. This way, if someone steals the database files, they can't decrypt without the KEK from your KMS.</P>
    <H3>Supported Databases</H3>
    <P>Microsoft SQL Server (EKM provider), Oracle Database (TDE with external keystore). An agent is deployed on the database server that communicates with Vecta KMS to fetch, rotate, and manage TDE keys.</P>

    <H2>BitLocker Management</H2>
    <P>Centrally manage Windows BitLocker full-disk encryption across your fleet. Register Windows clients, deploy agents, manage recovery keys, and control encryption operations (suspend, resume) from the KMS. Network scanning discovers BitLocker-capable endpoints. Recovery keys are securely escrowed in Vecta.</P>

    <H2>Use Cases</H2>
    <P>- Database encryption: Encrypt SQL Server and Oracle databases with centrally managed keys</P>
    <P>- Endpoint encryption: Manage BitLocker across hundreds of Windows machines from one dashboard</P>
    <P>- Key rotation compliance: Rotate TDE keys on a schedule to meet PCI-DSS and HIPAA requirements</P>
    <P>- Recovery key escrow: Centrally store and protect BitLocker recovery keys for IT helpdesk access</P>

    <Collapse title="EKM Agents (Database TDE)" defaultOpen>
      <EndpointTable rows={[
        ["GET", "/ekm/agents", "List all registered EKM agents with health status"],
        ["POST", "/ekm/agents/register", "Register a new EKM agent for MSSQL or Oracle"],
        ["GET", "/ekm/agents/{id}/deploy", "Download the agent deployment package"],
        ["GET", "/ekm/agents/{id}/health", "Get real-time agent health and connectivity status"],
        ["GET", "/ekm/agents/{id}/logs", "Get agent operation logs"],
        ["POST", "/ekm/agents/{id}/rotate", "Rotate the TDE key for this agent's database"],
        ["DELETE", "/ekm/agents/{id}", "Remove agent (database must have local key backup)"],
      ]} />
    </Collapse>
    <Collapse title="BitLocker">
      <EndpointTable rows={[
        ["GET", "/ekm/bitlocker/clients", "List registered Windows BitLocker clients"],
        ["POST", "/ekm/bitlocker/clients/register", "Register a Windows machine for BitLocker management"],
        ["POST", "/ekm/bitlocker/clients/{id}/operations", "Execute BitLocker operation (suspend, resume, rotate)"],
        ["GET", "/ekm/bitlocker/clients/{id}/deploy", "Download BitLocker agent installer for this client"],
        ["GET", "/ekm/bitlocker/recovery", "Get escrowed recovery keys"],
        ["POST", "/ekm/bitlocker/network/scan", "Scan network for BitLocker-capable endpoints"],
      ]} />
    </Collapse>
    <Collapse title="TDE Keys">
      <EndpointTable rows={[
        ["POST", "/ekm/tde/keys", "Create a new TDE encryption key"],
        ["POST", "/ekm/tde/keys/{id}/rotate", "Rotate TDE key and re-wrap DEK"],
        ["POST", "/ekm/tde/keys/{id}/wrap", "Wrap a TDE key for agent consumption"],
        ["POST", "/ekm/tde/keys/{id}/unwrap", "Unwrap a TDE key (agent-to-KMS operation)"],
      ]} />
    </Collapse>
  </div>
);

const SectionApiEkmBitlocker = () => (
  <div>
    <div style={S.h1}>API: BitLocker Management</div>
    <P>Service: kms-ekm | Endpoints: 13 | Agent mode: bitlocker</P>

    <H2>Overview</H2>
    <P>Vecta KMS provides centralized BitLocker management for Windows endpoints. The BitLocker subsystem handles client registration, encryption operations, recovery key escrow, network discovery, and job-based asynchronous operation execution.</P>

    <H2>Architecture</H2>
    <P>The BitLocker agent runs on Windows endpoints as a service (VectaEKMAgent with agent_mode=bitlocker). It registers with the KMS, sends periodic heartbeats, and polls for queued jobs. Operations like enabling encryption or rotating recovery passwords are queued by the dashboard and executed by the agent.</P>

    <H2>Job Queue Pattern</H2>
    <P>1. Dashboard or admin queues an operation via POST /ekm/bitlocker/clients/&#123;id&#125;/operations</P>
    <P>2. Agent polls GET /ekm/bitlocker/clients/&#123;id&#125;/jobs/next every 10 seconds</P>
    <P>3. Agent executes the operation locally (PowerShell cmdlets)</P>
    <P>4. Agent reports result via POST /ekm/bitlocker/clients/&#123;id&#125;/jobs/&#123;job_id&#125;/result</P>

    <Collapse title="Client Management" defaultOpen>
      <EndpointTable rows={[
        ["POST", "/ekm/bitlocker/clients/register", "Register Windows machine for BitLocker management"],
        ["GET", "/ekm/bitlocker/clients", "List all registered BitLocker clients"],
        ["GET", "/ekm/bitlocker/clients/{id}", "Get detailed client status (TPM, encryption %)"],
        ["GET", "/ekm/bitlocker/clients/{id}/delete-preview", "Preview deletion impact (orphaned recovery keys)"],
        ["DELETE", "/ekm/bitlocker/clients/{id}", "Remove client registration"],
        ["POST", "/ekm/bitlocker/clients/{id}/heartbeat", "Agent heartbeat with encryption status"],
      ]} />
    </Collapse>
    <Collapse title="Operations & Jobs">
      <EndpointTable rows={[
        ["POST", "/ekm/bitlocker/clients/{id}/operations", "Queue operation: enable, disable, suspend, resume, rotate_recovery, status, tpm_status"],
        ["GET", "/ekm/bitlocker/clients/{id}/jobs/next", "Agent polls for next pending job"],
        ["POST", "/ekm/bitlocker/clients/{id}/jobs/{job_id}/result", "Agent submits job result"],
      ]} />
    </Collapse>
    <Collapse title="Recovery & Discovery">
      <EndpointTable rows={[
        ["GET", "/ekm/bitlocker/recovery", "List escrowed recovery keys (admin only)"],
        ["POST", "/ekm/bitlocker/network/scan", "Scan subnet for BitLocker-capable endpoints"],
        ["GET", "/ekm/bitlocker/clients/{id}/deploy", "Download agent installer for this client"],
      ]} />
    </Collapse>

    <H2>Supported Operations</H2>
    <P>enable — Enable BitLocker with specified protector (TPM, recovery_password, tpm_and_pin)</P>
    <P>disable — Disable BitLocker encryption (decrypts volume)</P>
    <P>suspend — Temporarily suspend BitLocker protection (e.g., for BIOS updates)</P>
    <P>resume — Resume suspended BitLocker protection</P>
    <P>rotate_recovery — Remove old recovery passwords and generate a new one</P>
    <P>status — Query current BitLocker volume status</P>
    <P>tpm_status — Query TPM presence and readiness</P>
  </div>
);

const SectionApiEkmSdk = () => (
  <div>
    <div style={S.h1}>API: PKCS#11 &amp; JCA Providers</div>
    <P>SDK packages for integrating applications with Vecta KMS key operations</P>

    <H2>PKCS#11 Provider</H2>
    <P>A shared library (libvecta-pkcs11.so / .dll / .dylib) that implements the OASIS PKCS#11 v2.40 interface. Applications using PKCS#11 (OpenSSL, OpenSC, database EKM providers) can use Vecta KMS keys without code changes.</P>

    <H3>Supported Mechanisms</H3>
    <P>AES-GCM encrypt/decrypt (local cache or remote), RSA sign/verify (always remote), ECDSA sign/verify (always remote), key enumeration via C_FindObjects.</P>

    <H3>Installation</H3>
    <P>Linux: Copy libvecta-pkcs11.so to /opt/vecta/lib/ and set VECTA_* environment variables.</P>
    <P>Windows: Copy vecta-pkcs11.dll to C:\Program Files\Vecta\ and configure in registry.</P>
    <P>macOS: Copy libvecta-pkcs11.dylib to /usr/local/lib/vecta/.</P>

    <H2>JCA Provider</H2>
    <P>A Java Cryptography Architecture provider (vecta-jca-provider.jar) for Java 11+. No external dependencies — uses only java.net.http.</P>

    <H3>Registered Services</H3>
    <P>Cipher: AES/GCM/NoPadding — local cache if key is exportable, else remote KMS</P>
    <P>Signature: SHA256withRSA, SHA256withECDSA — always remote (asymmetric)</P>
    <P>KeyStore: VectaKMS — enumerate and load keys from KMS</P>
    <P>SecureRandom: VectaQRNG — quantum random bytes from QRNG endpoint, fallback to local</P>

    <H3>Setup</H3>
    <P>Programmatic: Security.addProvider(new VectaKMSProvider())</P>
    <P>Or add to java.security: security.provider.N=com.vecta.kms.VectaKMSProvider</P>

    <Collapse title="SDK Endpoints" defaultOpen>
      <EndpointTable rows={[
        ["GET", "/ekm/sdk/overview", "List available SDK packages with versions and platforms"],
        ["GET", "/ekm/sdk/download/{package}?platform={platform}", "Download SDK package binary"],
      ]} />
    </Collapse>

    <H2>Authentication</H2>
    <P>Both providers support the same multi-auth chain: mTLS (transport) → JWT (auto-refresh) → API Key (X-API-Key header) → Bearer token. Configure via environment variables: VECTA_BASE_URL, VECTA_TENANT_ID, VECTA_AUTH_TOKEN, VECTA_MTLS_CERT, VECTA_MTLS_KEY, VECTA_MTLS_CA, VECTA_API_KEY, VECTA_JWT_ENDPOINT.</P>

    <H2>Key Caching</H2>
    <P>Set VECTA_KEY_CACHE_TTL (seconds) to enable local caching. Exportable keys are cached in process memory for fast AES-GCM operations. Non-exportable keys always proxy to KMS. Cache TTL of 0 disables caching.</P>
  </div>
);

const SectionGuideAgentDeploy = () => (
  <div>
    <div style={S.h1}>Guide: EKM Agent Deployment</div>
    <P>Step-by-step guide for deploying Vecta EKM agents on database servers and Windows endpoints.</P>

    <H2>Prerequisites</H2>
    <P>1. Vecta KMS running with EKM service enabled (ekm_database feature)</P>
    <P>2. Network connectivity from the agent host to KMS (HTTPS port 443 or custom)</P>
    <P>3. Authentication credential: mTLS certificate, API key, or bearer token</P>
    <P>4. For TDE agents: database admin credentials for TDE state inspection</P>

    <H2>Step 1: Generate Authentication Credentials</H2>
    <P>Option A (mTLS): Generate a client certificate signed by the KMS CA:</P>
    <P>  openssl req -new -key agent.key -out agent.csr -subj "/CN=ekm-agent-01/O=vecta"</P>
    <P>  Submit CSR to KMS cert authority or use the Certificates tab to issue.</P>
    <P>Option B (API Key): Create an API key in the Admin tab with ekm-agent role.</P>
    <P>Option C (Bearer Token): Use a static token from the Auth settings.</P>

    <H2>Step 2: Configure Agent</H2>
    <P>Edit agent-config.json (or use environment variables):</P>
    <P>  tenant_id: Your tenant identifier</P>
    <P>  agent_id: Unique agent name (e.g., "mssql-prod-01")</P>
    <P>  api_base_url: KMS URL (e.g., "https://kms.example.com/svc/ekm")</P>
    <P>  db_engine: "mssql" or "oracle"</P>
    <P>  For mTLS: mtls_cert_path, mtls_key_path, mtls_ca_path</P>
    <P>  For key caching: key_cache_enabled=true, key_cache_ttl_sec=300</P>

    <H2>Step 3: Install on Windows</H2>
    <P>Run the PowerShell installer from an elevated prompt:</P>
    <P>  .\install-ekm-agent.ps1 -TenantId root -AgentId mssql-prod-01 -DbEngine mssql ...</P>
    <P>This creates the VectaEKMAgent Windows service.</P>

    <H2>Step 4: Verify</H2>
    <P>1. Check Windows Services: VectaEKMAgent should be Running</P>
    <P>2. In KMS Dashboard: EKM tab → Agents → agent should show "connected"</P>
    <P>3. Check heartbeat: Agent health should show TDE state and PKCS#11 readiness</P>

    <H2>MSSQL TDE Walkthrough</H2>
    <P>After agent registration, the agent inspects sys.dm_database_encryption_keys to report TDE state. To enable TDE: create a TDE key via the dashboard, assign it to the agent, and the agent will configure the database server's EKM provider to use the Vecta key for DEK wrapping.</P>

    <H2>Oracle TDE Walkthrough</H2>
    <P>For Oracle, the agent checks V$ENCRYPTION_WALLET for wallet status. Configure Oracle to use an external keystore pointing to the Vecta PKCS#11 provider: ALTER SYSTEM SET ENCRYPTION WALLET OPEN IDENTIFIED BY "vecta-external".</P>
  </div>
);

const SectionGuideKeyCache = () => (
  <div>
    <div style={S.h1}>Guide: Local Key Cache Architecture</div>
    <P>How Vecta agents optimize crypto performance with local key caching.</P>

    <H2>Export-or-Remote Pattern</H2>
    <P>When an agent starts or a key is assigned, it checks the key's export_allowed flag:</P>
    <P>- If exportable: The key material is exported from KMS (wrapped in transit), unwrapped locally, and stored in locked memory (mlock). Subsequent encrypt/decrypt operations use the local copy — no network round-trip.</P>
    <P>- If not exportable: All crypto operations are proxied to the KMS server. This is slower but ensures key material never leaves the KMS boundary.</P>

    <H2>Cache Behavior</H2>
    <P>TTL: Cached keys expire after key_cache_ttl_sec (default 300s). After expiry, the agent re-exports from KMS.</P>
    <P>Eviction: A background goroutine runs every 30s to remove expired entries.</P>
    <P>Shutdown: All cached material is zeroized (overwritten with zeros) and munlocked on agent shutdown.</P>

    <H2>Memory Security</H2>
    <P>Key material is stored in mlock'd pages — the OS kernel will not swap these pages to disk, preventing key exposure via swap files. On agent shutdown or cache eviction, material is explicitly zeroized before munlocking.</P>
    <P>Functions used: crypto.Mlock() (lock pages), crypto.Munlock() (unlock pages), crypto.Zeroize() (overwrite with zeros).</P>

    <H2>Supported Algorithms</H2>
    <P>Local cache operations currently support AES-GCM only (128/192/256-bit). Asymmetric operations (RSA, ECDSA) are always proxied to KMS regardless of cache settings.</P>

    <H2>When to Enable</H2>
    <P>Enable key caching (key_cache_enabled=true) when:</P>
    <P>- High-throughput encryption (hundreds of ops/sec)</P>
    <P>- Low latency requirements (sub-millisecond encrypt/decrypt)</P>
    <P>- Offline resilience (agent can continue encrypting during brief KMS outages within TTL window)</P>
    <P>Keep caching disabled when:</P>
    <P>- Compliance requires all crypto operations in the HSM/KMS boundary</P>
    <P>- Keys are marked non-exportable by policy</P>

    <H2>Tuning</H2>
    <P>key_cache_ttl_sec: Lower values = more frequent re-export (better security, higher latency). Higher values = fewer round-trips (better performance, longer key exposure window). Recommended: 300s for most workloads, 60s for high-security environments.</P>
  </div>
);

const SectionApiMpc = () => (
  <div>
    <div style={S.h1}>API: Multi-Party Computation (MPC)</div>
    <P>Service: kms-mpc | Port: 8190 (HTTP) / 18190 (gRPC) | Profile: mpc_engine</P>

    <H2>What is MPC?</H2>
    <P>Multi-Party Computation (MPC) allows multiple participants to jointly perform cryptographic operations without any single party ever having access to the complete private key. The key is split into "shares" distributed across participants, and a threshold number of shares (e.g., 3 of 5) must cooperate to sign a transaction or decrypt data. No single share — and no single compromised server — can reconstruct the full key.</P>

    <H2>Key Concepts</H2>
    <H3>DKG (Distributed Key Generation)</H3>
    <P>A ceremony where multiple participants collaboratively generate a shared key pair. Each participant receives a key share, and no one ever sees the complete private key — not even during generation. The public key is available to everyone for encryption and verification. DKG uses Shamir Secret Sharing and verifiable secret sharing protocols.</P>
    <H3>Threshold Signing (t-of-n)</H3>
    <P>To produce a digital signature, at least t participants (out of n total) must contribute their partial signatures. These partial signatures are mathematically combined into a valid signature indistinguishable from a standard single-key signature. For example, with a 3-of-5 threshold, any 3 of the 5 shareholders can sign, but 2 cannot.</P>
    <H3>Threshold Decryption</H3>
    <P>Similar to threshold signing, but for decryption. Data encrypted with the shared public key can only be decrypted when t participants contribute their decryption shares. This prevents any single party from accessing encrypted data alone.</P>

    <H2>Use Cases</H2>
    <P>- Cryptocurrency custody: Secure digital asset wallets where no single employee can move funds (exchanges, custodians, DAOs)</P>
    <P>- Root CA protection: Protect the root certificate authority key so no single admin can issue rogue certificates</P>
    <P>- Master key protection: Distribute the KMS master encryption key across multiple security officers</P>
    <P>- Regulatory key escrow: Hold keys in escrow where multiple parties must agree to release (legal, compliance)</P>
    <P>- Board-level approvals: Require multiple executives to authorize high-value transactions or key operations</P>
    <P>- Disaster recovery: Distribute recovery key shares across geographically separate locations</P>

    <Collapse title="DKG (Distributed Key Generation)" defaultOpen>
      <EndpointTable rows={[
        ["POST", "/mpc/dkg/initiate", "Start a DKG ceremony (specify participants, threshold)"],
        ["GET", "/mpc/dkg/{id}/status", "Get ceremony progress (waiting, in_progress, complete, failed)"],
        ["POST", "/mpc/dkg/{id}/contribute", "Submit a participant's contribution to the ceremony"],
        ["GET", "/mpc/dkg/{id}/result", "Get the generated public key and share metadata"],
      ]} />
    </Collapse>
    <Collapse title="Threshold Signing & Decryption">
      <EndpointTable rows={[
        ["POST", "/mpc/sign/initiate", "Start a threshold signing session with message hash"],
        ["POST", "/mpc/sign/{id}/contribute", "Submit a participant's partial signature"],
        ["GET", "/mpc/sign/{id}/result", "Get the combined final signature"],
        ["POST", "/mpc/decrypt/initiate", "Start a threshold decryption session with ciphertext"],
        ["POST", "/mpc/decrypt/{id}/contribute", "Submit a participant's decryption share"],
        ["GET", "/mpc/decrypt/{id}/result", "Get the decrypted plaintext"],
      ]} />
    </Collapse>
    <Collapse title="Participants & Policies">
      <EndpointTable rows={[
        ["POST", "/mpc/participants", "Register an MPC participant (person or service)"],
        ["GET", "/mpc/participants", "List all registered participants with status"],
        ["POST", "/mpc/policies", "Create MPC policy (threshold t, total n, timeout)"],
        ["GET", "/mpc/policies", "List MPC policies"],
        ["GET", "/mpc/keys", "List all MPC-generated keys with share distribution info"],
        ["GET", "/mpc/ceremonies", "List all DKG/signing/decryption ceremonies with status"],
      ]} />
    </Collapse>

    <H2>Example: 3-of-5 DKG Ceremony</H2>
    <Code>{`# Step 1: Create an MPC policy requiring 3-of-5 threshold
curl -X POST http://localhost:8190/mpc/policies \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{ "name": "root-ca-protection", "threshold": 3, "total_participants": 5 }'

# Step 2: Initiate DKG ceremony
curl -X POST http://localhost:8190/mpc/dkg/initiate \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{ "policy_id": "pol-xxx", "algorithm": "EC-P256", "name": "root-ca-key" }'
# Returns: { "ceremony_id": "cer-xxx", "status": "waiting_contributions" }

# Step 3: Each participant contributes (repeat for each of 5 participants)
curl -X POST http://localhost:8190/mpc/dkg/cer-xxx/contribute \\
  -H "Authorization: Bearer $PARTICIPANT_TOKEN" \\
  -d '{ "participant_id": "alice", "contribution": "base64..." }'

# Step 4: After all 5 contribute, get the shared public key
curl http://localhost:8190/mpc/dkg/cer-xxx/result \\
  -H "Authorization: Bearer $TOKEN"
# Returns: { "public_key": "base64...", "shares_distributed": 5 }`}</Code>
  </div>
);

const SectionApiQkd = () => (
  <div>
    <div style={S.h1}>API: Quantum Key Distribution (QKD)</div>
    <P>Service: kms-qkd | Port: 8150 (HTTP) / 18150 (gRPC) | Profile: qkd_interface</P>

    <H2>What is QKD?</H2>
    <P>Quantum Key Distribution (QKD) uses the principles of quantum mechanics to establish shared secret keys between two parties with provable security. Unlike classical key exchange (RSA, Diffie-Hellman) which relies on mathematical complexity, QKD's security is based on the laws of physics — any eavesdropping attempt disturbs the quantum state and is detectable. This makes QKD resistant to both current and future quantum computing attacks.</P>

    <H2>How QKD Works in Vecta KMS</H2>
    <P>Vecta KMS acts as a QKD Key Management layer, not a QKD hardware device. It integrates with external QKD networks and devices via the ETSI QKD 014 and ETSI QKD 004 standard APIs. When a QKD device generates a shared key between two nodes, Vecta receives and securely stores that key, making it available for use in encryption, signing, and key wrapping operations throughout the KMS platform.</P>
    <P>The flow works as follows: (1) A QKD source device (e.g., ID Quantique, Toshiba QKD, or a QKD network node) generates quantum-secure keys. (2) A Secure Application Entity (SAE) registered in Vecta pulls or receives the key via the ETSI API. (3) The key is injected into the KMS key store and can be used like any other cryptographic key. (4) Key distribution history and audit logs track every operation.</P>

    <H2>Key Concepts</H2>
    <H3>SAE (Secure Application Entity)</H3>
    <P>An SAE is a registered endpoint that can request and receive quantum keys. In Vecta, each SAE represents a QKD node or application that participates in quantum key distribution. SAEs are identified by a unique ID and are associated with a QKD link (the physical or network connection between two QKD devices).</P>
    <H3>Key Injection</H3>
    <P>QKD keys generated by external hardware are injected into the KMS key store. Once injected, a QKD key behaves like any other KMS key — it can be used for encryption, wrapping, or as seed material for key derivation. The metadata tags the key as QKD-sourced for compliance tracking.</P>
    <H3>Distribution</H3>
    <P>Key distribution is the process of sharing a quantum key between two SAEs. Vecta tracks all distributions including timestamps, participants, key IDs, and success/failure status.</P>

    <H2>Use Cases</H2>
    <P>- Government and defense organizations requiring quantum-safe key exchange for classified data protection</P>
    <P>- Financial institutions preparing for "harvest now, decrypt later" threats by protecting long-lived secrets with quantum-distributed keys</P>
    <P>- Healthcare systems encrypting patient records with quantum-safe keys to meet future-proof compliance requirements</P>
    <P>- Critical infrastructure (power grids, telecom backbone) using QKD for secure SCADA and control plane encryption</P>
    <P>- Research institutions and national labs requiring the highest assurance key exchange for sensitive IP</P>
    <P>- Organizations with QKD network hardware (ID Quantique, Toshiba, Cisco CKM) that need a centralized key management layer on top</P>

    <Collapse title="QKD Endpoints" defaultOpen>
      <EndpointTable rows={[
        ["GET", "/qkd/v1/config", "Get QKD configuration (mode, ETSI endpoints, polling interval)"],
        ["PUT", "/qkd/v1/config", "Update QKD configuration"],
        ["POST", "/qkd/v1/sae", "Register SAE (Secure Application Entity)"],
        ["GET", "/qkd/v1/sae", "List registered SAEs with status and last activity"],
        ["POST", "/qkd/v1/sae/{id}/distribute", "Distribute a quantum key via the specified SAE to a peer"],
        ["POST", "/qkd/v1/get_key", "Request a quantum-distributed key from the QKD network"],
        ["GET", "/qkd/v1/keys", "List all QKD keys with source, distribution status, and usage count"],
        ["POST", "/qkd/v1/keys/{id}/inject", "Inject a QKD-generated key into the KMS key store for general use"],
        ["GET", "/qkd/v1/distributions", "List distribution history with timestamps and participants"],
        ["GET", "/qkd/v1/overview", "Get QKD system overview (active SAEs, key count, distribution stats)"],
        ["GET", "/qkd/v1/logs", "Get QKD operation logs for auditing"],
        ["POST", "/qkd/v1/test/generate", "Generate a simulated QKD key for testing (not quantum-secure)"],
      ]} />
    </Collapse>

    <H2>Example: Register an SAE and Distribute a Key</H2>
    <Code>{`# Step 1: Register a QKD SAE (Secure Application Entity)
curl -X POST http://localhost:8150/qkd/v1/sae \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "datacenter-east-qkd",
    "sae_id": "sae-east-01",
    "endpoint": "https://qkd-node-east.internal:9100",
    "protocol": "etsi_014",
    "description": "QKD node in East datacenter"
  }'

# Step 2: Request a quantum key
curl -X POST http://localhost:8150/qkd/v1/get_key \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{ "sae_id": "sae-east-01", "key_size": 256 }'
# Returns: { "key_id": "qkd-...", "key_material": "base64...", "source": "etsi_014" }

# Step 3: Inject the QKD key into the KMS key store
curl -X POST http://localhost:8150/qkd/v1/keys/qkd-xxxx/inject \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{ "name": "qkd-east-aes256", "tags": ["quantum-safe", "east-dc"] }'
# The key is now available via /keys API for encrypt/decrypt/wrap operations`}</Code>

    <H2>Supported QKD Protocols</H2>
    <P>ETSI QKD 014 (RESTful key delivery), ETSI QKD 004 (application interface), Cisco CKM (Cisco Key Manager integration), and relay mode (for multi-hop QKD networks where keys traverse intermediate nodes).</P>

    <H2>QRNG (Quantum Random Number Generation)</H2>
    <P>QRNG provides true randomness derived from quantum phenomena (photon detection, vacuum fluctuations) rather than algorithmic pseudo-randomness. Vecta can integrate with hardware QRNG devices or cloud QRNG services to seed its entropy pool, ensuring that every cryptographic key, nonce, IV, and salt generated by the platform uses quantum-grade randomness.</P>
    <H3>How QRNG is Used</H3>
    <P>Register a QRNG entropy source (hardware device or API service) in the QKD/Advanced tab. Configure pull mode (KMS periodically fetches entropy) or push mode (device pushes entropy to KMS). The QRNG entropy is mixed into the platform's random number generator pool. All subsequent key generation, nonce creation, and random operations benefit from quantum-grade randomness without any code changes.</P>
    <H3>QRNG Use Cases</H3>
    <P>- High-security environments requiring true randomness for key generation (not PRNG)</P>
    <P>- Compliance requirements mandating hardware entropy sources (FIPS 140-3 SP 800-90B)</P>
    <P>- Lottery and gaming systems requiring provably random number generation</P>
    <P>- Certificate serial number and nonce generation for maximum unpredictability</P>
  </div>
);

const SectionApiCompliance = () => (
  <div>
    <div style={S.h1}>API: Compliance</div>
    <P>Service: kms-compliance | Port: 8110 (HTTP) / 18110 (gRPC) | Profile: compliance_dashboard</P>

    <H2>What is Compliance Management?</H2>
    <P>The Compliance service continuously monitors your KMS deployment against industry regulatory frameworks and standards. It evaluates your cryptographic practices — key rotation schedules, algorithm strength, access controls, audit completeness — and produces a compliance posture score with actionable findings. Instead of manually auditing your key management practices before each compliance review, the system does it automatically and continuously.</P>

    <H2>Supported Compliance Frameworks</H2>
    <H3>PCI-DSS (Payment Card Industry Data Security Standard)</H3>
    <P>Evaluates cryptographic key management controls required for processing, storing, or transmitting credit card data. Checks include: key rotation frequency (Requirement 3.6.4), dual control and split knowledge for key management (3.6.6), secure key storage (3.5), strong cryptography for cardholder data encryption (3.4), and audit trail completeness (10.x). Essential for merchants, payment processors, and financial service providers.</P>
    <H3>HIPAA (Health Insurance Portability and Accountability Act)</H3>
    <P>Evaluates encryption controls for Protected Health Information (PHI). Checks: encryption at rest and in transit, access controls and audit logging for key operations, key lifecycle management, and backup encryption. Required for healthcare providers, health plans, clearinghouses, and business associates handling patient data.</P>
    <H3>SOC 2 (Service Organization Control Type 2)</H3>
    <P>Evaluates trust service criteria: Security, Availability, Processing Integrity, Confidentiality, and Privacy. Checks: access control policies, encryption key management procedures, change management, monitoring and alerting, and incident response readiness. Required for SaaS providers, cloud services, and any organization demonstrating security controls to customers.</P>
    <H3>ISO 27001 (Information Security Management System)</H3>
    <P>Evaluates cryptographic controls per Annex A.10 (Cryptography). Checks: cryptographic policy existence, key management procedures, algorithm appropriateness, key protection measures, and lifecycle management. Required for organizations seeking ISO 27001 certification or maintaining an ISMS.</P>

    <H2>Use Cases</H2>
    <P>- Preparing for compliance audits by running assessments in advance and remediating gaps before the auditor arrives</P>
    <P>- Continuous compliance monitoring to catch drift (e.g., someone creates a key with a weak algorithm or disables rotation)</P>
    <P>- Generating compliance evidence reports for auditors showing key management controls are in place</P>
    <P>- Identifying orphaned keys (keys with no active usage or owner) that represent security risk and waste</P>
    <P>- Key hygiene tracking: ensuring all keys are rotated on schedule, use approved algorithms, and have proper expiry dates</P>
    <P>- Anomaly detection in audit logs to catch suspicious behavior (bulk key exports, unusual access patterns)</P>

    <H2>How It Works</H2>
    <P>1. Select a compliance framework (or run all). 2. The assessment engine queries key metadata, audit logs, policy configs, and access controls. 3. Each framework control is evaluated as Pass, Fail, or Warning. 4. A compliance score (0-100%) is computed. 5. Control gaps are listed with specific remediation steps. 6. Results are stored in assessment history for trend tracking.</P>
    <P>The latest implementation also exposes a dedicated delta read model for the UI's "What Changed Since Last Scan" panel. That response compares the most recent two real assessments and highlights newly added findings, resolved findings, recovered or regressed domains, and newly failing connectors.</P>

    <Collapse title="Compliance Endpoints" defaultOpen>
      <EndpointTable rows={[
        ["GET", "/compliance/posture", "Get overall compliance posture score and breakdown by framework"],
        ["GET", "/compliance/assessment", "Get the latest completed non-auto assessment for the selected template scope"],
        ["GET", "/compliance/assessment/delta", "Compare the latest and previous assessments to drive the delta panel in the Compliance tab"],
        ["POST", "/compliance/assessment/run", "Run a compliance assessment (specify framework or 'all')"],
        ["GET", "/compliance/assessment/history", "View past assessment results and score trends over time"],
        ["GET", "/compliance/templates", "List saved compliance templates used for executive or operations scoring views"],
        ["GET", "/compliance/frameworks", "List available compliance frameworks with descriptions"],
        ["GET", "/compliance/frameworks/{id}/gaps", "Get control gaps for a specific framework with remediation guidance"],
        ["GET", "/compliance/keys/hygiene", "Key hygiene report: rotation compliance, algorithm strength, expiry status"],
        ["GET", "/compliance/keys/orphaned", "Find orphaned keys with no recent usage or assigned owner"],
        ["GET", "/compliance/audit/anomalies", "Detect anomalies in audit logs (unusual patterns, bulk operations)"],
      ]} />
    </Collapse>

    <H2>Example: Run a PCI-DSS Assessment</H2>
    <Code>{`# Run a PCI-DSS compliance assessment
curl -X POST http://localhost:8110/compliance/assessment/run \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{ "framework": "pci-dss" }'
# Returns: { "score": 87, "total_controls": 24, "passed": 21, "failed": 3, "gaps": [...] }

# View the specific control gaps
curl http://localhost:8110/compliance/frameworks/pci-dss/gaps \\
  -H "Authorization: Bearer $TOKEN"
# Returns gaps like: "3.6.4: 5 keys have not been rotated in >365 days"

# Check key hygiene across all keys
curl http://localhost:8110/compliance/keys/hygiene \\
  -H "Authorization: Bearer $TOKEN"
# Returns: rotation_overdue: 5, weak_algorithm: 2, no_expiry: 12, expired: 1`}</Code>
  </div>
);

const SectionApiSbom = () => (
  <div>
    <div style={S.h1}>API: SBOM / CBOM</div>
    <P>Service: kms-sbom | Port: 8180 (HTTP) / 18180 (gRPC) | Profile: sbom_cbom</P>

    <H2>What is SBOM?</H2>
    <P>A Software Bill of Materials (SBOM) is a complete inventory of all software components, libraries, and dependencies used in the KMS platform. Like a nutrition label for software, it tells you exactly what's inside — which Go modules, JavaScript packages, Docker base images, and system libraries make up your deployment. SBOMs are increasingly required by regulations (US Executive Order 14028, EU Cyber Resilience Act) and are essential for supply chain security.</P>

    <H2>What is CBOM?</H2>
    <P>A Cryptographic Bill of Materials (CBOM) is a specialized inventory of all cryptographic algorithms, protocols, key sizes, and cryptographic libraries used across the platform. While SBOM tells you "what software do I have?", CBOM tells you "what cryptography am I using?" This is critical for post-quantum migration planning — you need to know every place where RSA, ECDSA, or Diffie-Hellman is used before you can plan the migration to quantum-safe alternatives.</P>

    <H2>Use Cases</H2>
    <P>- Supply chain security: Know exactly what's in your KMS deployment. If a CVE is announced for a library, instantly check if you're affected</P>
    <P>- Regulatory compliance: Provide SBOM to auditors as required by EO 14028, NIST SP 800-218, EU CRA</P>
    <P>- Vulnerability management: Cross-reference SBOM components against CVE databases to find known vulnerabilities</P>
    <P>- Version tracking: Diff SBOM between releases to see exactly what changed (added, removed, updated dependencies)</P>
    <P>- PQC migration planning: Use CBOM to identify all classical cryptographic algorithms that need migration to post-quantum alternatives</P>
    <P>- Procurement: Share SBOM/CBOM with customers who need to validate your security posture before purchasing</P>

    <H2>Supported Formats</H2>
    <P>SBOM: CycloneDX (JSON/XML) and SPDX (JSON/TV). CycloneDX is the default and recommended format. CBOM: CycloneDX crypto extension format, which adds cryptographic component type, algorithm identifiers, key sizes, and protocol details to the standard BOM format.</P>

    <Collapse title="SBOM Endpoints" defaultOpen>
      <EndpointTable rows={[
        ["POST", "/sbom/generate", "Generate a new SBOM from current deployment state"],
        ["GET", "/sbom/latest", "Get the most recently generated SBOM"],
        ["GET", "/sbom/{id}/export", "Export SBOM in CycloneDX or SPDX format"],
        ["GET", "/sbom/vulnerabilities", "Cross-reference SBOM components against known CVEs"],
        ["GET", "/sbom/diff", "Compare two SBOM versions to see what changed"],
      ]} />
    </Collapse>
    <Collapse title="CBOM Endpoints">
      <EndpointTable rows={[
        ["POST", "/cbom/generate", "Generate a CBOM cataloging all cryptographic usage"],
        ["GET", "/cbom/latest", "Get the most recently generated CBOM"],
        ["GET", "/cbom/summary", "Algorithm summary: counts by algorithm family and key size"],
        ["GET", "/cbom/{id}/export", "Export CBOM in CycloneDX crypto extension format"],
        ["GET", "/cbom/pqc-readiness", "Analyze CBOM for PQC migration readiness score and action items"],
      ]} />
    </Collapse>

    <H2>Example: Generate and Analyze CBOM</H2>
    <Code>{`# Generate a CBOM
curl -X POST http://localhost:8180/cbom/generate \\
  -H "Authorization: Bearer $TOKEN"
# Returns: { "id": "cbom-2026-03-05", "components": 47, "algorithms": 12 }

# Get algorithm summary
curl http://localhost:8180/cbom/summary \\
  -H "Authorization: Bearer $TOKEN"
# Returns: { "AES-256-GCM": 234, "RSA-2048": 12, "EC-P256": 45, "ML-KEM-768": 3, ... }

# Check PQC readiness
curl http://localhost:8180/cbom/pqc-readiness \\
  -H "Authorization: Bearer $TOKEN"
# Returns: { "score": 72, "quantum_safe_keys": 3, "classical_keys": 291,
#   "action_items": ["Migrate 12 RSA-2048 keys to ML-DSA-65", ...] }`}</Code>
  </div>
);

const SectionApiPosture = () => (
  <div>
    <div style={S.h1}>API: Security Posture Management</div>
    <P>Service: kms-posture | Port: 8220 (HTTP) / 18220 (gRPC) | Profile: posture_management</P>

    <H2>What is Security Posture Management?</H2>
    <P>Security Posture Management provides a holistic, real-time view of your KMS platform's security health. It continuously scans all integrated systems — BYOK cloud accounts, HYOK endpoints, EKM database agents, KMIP clients, BitLocker deployments, SDK wrappers — and produces a risk score with specific findings and remediation actions. Think of it as a security dashboard that tells you "here's what's strong, here's what's weak, and here's exactly how to fix it."</P>

    <H2>How Posture Management Works</H2>
    <P>The posture engine evaluates security across multiple domains:</P>
    <H3>Risk Domains</H3>
    <P>- BYOK Risk: Are cloud key bindings healthy? Are credentials rotated? Is sync current?</P>
    <P>- HYOK Risk: Are HYOK endpoints accessible? Are DKE/Salesforce/Google integrations healthy?</P>
    <P>- EKM Risk: Are database TDE agents reporting healthy? Are TDE keys rotated?</P>
    <P>- KMIP Risk: Are KMIP client certificates expiring? Are interop targets verified?</P>
    <P>- BitLocker Risk: Are Windows endpoints encrypted? Are recovery keys backed up?</P>
    <P>- SDK Risk: Are field encryption wrappers registered and active? Are leases current?</P>

    <H3>Risk Scoring</H3>
    <P>Each domain gets a score from 0 (critical) to 100 (excellent). The overall posture score is a weighted average. Scores update in real-time as findings are discovered or remediated. History tracking shows trends over time — are you improving or degrading?</P>

    <H2>Use Cases</H2>
    <P>- CISO dashboard: Get a single-pane-of-glass view of cryptographic security health across all systems</P>
    <P>- Proactive risk management: Identify weak points (expiring certs, unhealthy agents, stale cloud bindings) before they become incidents</P>
    <P>- Automated remediation: Execute fix actions directly from findings (e.g., "rotate this key", "renew this certificate", "resync this cloud binding")</P>
    <P>- Audit preparation: Demonstrate to auditors that security posture is continuously monitored and tracked</P>
    <P>- Incident response: When investigating a security event, quickly assess which systems might be affected</P>
    <P>The enriched dashboard payload also supports two operator styles directly from the API: an executive read with score/trend/top drivers, and an operations read with findings, remediation groups, blast radius, validation badges, and scenario simulation.</P>

    <Collapse title="Posture Endpoints" defaultOpen>
      <EndpointTable rows={[
        ["GET", "/posture/dashboard", "Get posture dashboard with risk drivers, remediation cockpit groups, blast radius hotspots, validation badges, scenario simulator, and SLA overview"],
        ["GET", "/posture/health", "Get security health status for all integrated systems"],
        ["GET", "/posture/risk", "Get risk metrics by domain (BYOK, HYOK, EKM, KMIP, BitLocker, SDK)"],
        ["GET", "/posture/risk/history", "Risk score history over time for trend analysis"],
        ["GET", "/posture/findings", "List security findings enriched with risk-driver explainers and blast-radius metadata"],
        ["PUT", "/posture/findings/{id}/status", "Update finding status (open, in_progress, resolved, accepted)"],
        ["GET", "/posture/actions", "List remediation actions grouped in the UI as safe auto-fix, approval-required, and manual, including rollback hints and impact estimates"],
        ["POST", "/posture/actions/{id}/execute", "Execute a remediation action (e.g., rotate key, renew cert) once safety or approval requirements are met"],
        ["POST", "/posture/scan", "Trigger a manual posture scan across all domains"],
      ]} />
    </Collapse>

    <H2>Example: Run a Posture Scan and Remediate</H2>
    <Code>{`# Trigger a posture scan
curl -X POST http://localhost:8220/posture/scan \\
  -H "Authorization: Bearer $TOKEN"

# Get the overall dashboard
curl http://localhost:8220/posture/dashboard \\
  -H "Authorization: Bearer $TOKEN"
# Returns: { "overall_score": 78, "domains": { "byok": 92, "hyok": 85, "ekm": 60, ... } }

# List findings that need attention
curl "http://localhost:8220/posture/findings?status=open&severity=high" \\
  -H "Authorization: Bearer $TOKEN"
# Returns: [{ "id": "f-123", "domain": "ekm", "severity": "high",
#   "title": "EKM agent unhealthy: mssql-prod-01",
#   "remediation": "Check agent connectivity and rotate TDE key" }]

# Execute a remediation action
curl -X POST http://localhost:8220/posture/actions/a-456/execute \\
  -H "Authorization: Bearer $TOKEN"`}</Code>
  </div>
);

const SectionApiReporting = () => (
  <div>
    <div style={S.h1}>API: Reporting & Alerting</div>
    <P>Service: kms-reporting | Port: 8140 (HTTP) / 18140 (gRPC) | Profile: reporting_alerting</P>
    <P>Reporting now backs the Compliance evidence-export flow as well. The <IC>evidence_pack</IC> template bundles posture findings, remediation actions, approval-required actions, incidents, and timing metrics into one exportable artifact.</P>
    <Collapse title="Alerts" defaultOpen>
      <EndpointTable rows={[
        ["GET", "/alerts", "List alerts (filterable by severity, status)"],
        ["GET", "/alerts/unread", "Get unread alert count"],
        ["PUT", "/alerts/", "Update alert (acknowledge, resolve)"],
        ["POST", "/alerts/bulk/acknowledge", "Bulk acknowledge alerts"],
        ["GET", "/alerts/stats", "Alert statistics"],
        ["GET", "/alerts/stats/mttd", "Mean time to detect by severity, used by the Compliance timing widgets"],
        ["GET", "/alerts/stats/mttr", "Mean time to resolution"],
        ["GET", "/alerts/stats/top-sources", "Top actors, IPs, and services contributing to alert volume"],
      ]} />
    </Collapse>
    <Collapse title="Reports">
      <EndpointTable rows={[
        ["GET", "/reports/templates", "List report templates, including posture_summary, compliance_audit, and evidence_pack"],
        ["POST", "/reports/generate", "Generate report from template; use evidence_pack for one-click audit exports"],
        ["GET", "/reports/jobs", "List generated report jobs and their status"],
        ["GET", "/reports/jobs/{id}/download", "Download generated report"],
        ["POST", "/reports/scheduled", "Create scheduled report"],
      ]} />
    </Collapse>
    <Collapse title="Incidents">
      <EndpointTable rows={[
        ["GET", "/incidents", "List security incidents"],
        ["PUT", "/incidents/{id}/status", "Update incident status"],
        ["PUT", "/incidents/{id}/assign", "Assign incident to user"],
      ]} />
    </Collapse>
  </div>
);

const SectionApiCluster = () => (
  <div>
    <div style={S.h1}>API: Cluster Management</div>
    <P>Service: kms-cluster-manager | Port: 8210 (HTTP) / 18210 (gRPC) | Profile: clustering</P>
    <EndpointTable rows={[
      ["GET", "/cluster/overview", "Get cluster overview (nodes, health, roles)"],
      ["GET", "/cluster/nodes", "List cluster nodes"],
      ["POST", "/cluster/nodes", "Add node to cluster"],
      ["DELETE", "/cluster/nodes/{id}", "Remove node from cluster"],
      ["POST", "/cluster/nodes/{id}/role", "Change node role (leader/follower/replica)"],
      ["POST", "/cluster/nodes/{id}/heartbeat", "Node heartbeat (internal)"],
      ["GET", "/cluster/profiles", "List deployment profiles"],
      ["POST", "/cluster/profiles", "Create deployment profile"],
      ["GET", "/cluster/sync/checkpoint", "Get sync checkpoint"],
      ["GET", "/cluster/sync/events", "Get sync events"],
      ["POST", "/cluster/join/request", "Request to join cluster"],
      ["GET", "/cluster/logs", "Get cluster operation logs"],
    ]} />
  </div>
);

const SectionApiPqc = () => (
  <div>
    <div style={S.h1}>API: Post-Quantum Cryptography (PQC)</div>
    <P>Service: kms-pqc | Port: 8060 (HTTP) / 18060 (gRPC) | Profile: pqc_migration</P>

    <H2>Why Post-Quantum?</H2>
    <P>Quantum computers will eventually break RSA, ECDSA, and Diffie-Hellman — the algorithms that protect most of today's encrypted data. The threat isn't just future: adversaries are harvesting encrypted data today ("harvest now, decrypt later") to decrypt once quantum computers are available. NIST has finalized new quantum-resistant algorithms that Vecta KMS supports. The PQC service helps you plan and execute the migration from classical to quantum-safe cryptography.</P>

    <H2>How PQC Migration Works</H2>
    <P>1. Scan: The PQC scanner audits all your existing keys, certificates, and cryptographic operations to identify classical algorithms that need migration. 2. Plan: Based on scan results, create a migration plan that maps each classical key/algorithm to its quantum-safe replacement. 3. Execute: The migration engine creates new PQC keys, re-encrypts data, re-signs certificates, and updates references. 4. Rollback: If anything goes wrong, roll back to the classical keys.</P>

    <H2>Supported PQC Algorithms</H2>
    <H3>ML-KEM (formerly Kyber) — Key Encapsulation</H3>
    <P>Replaces RSA key exchange and ECDH. Used for encrypting symmetric keys for transport. Sizes: ML-KEM-512 (128-bit security), ML-KEM-768 (192-bit, recommended), ML-KEM-1024 (256-bit). Use KEM encapsulate/decapsulate operations from the Keys tab.</P>
    <H3>ML-DSA (formerly Dilithium) — Digital Signatures</H3>
    <P>Replaces RSA and ECDSA signatures. Used for code signing, certificate signing, and document signing. Sizes: ML-DSA-44 (128-bit), ML-DSA-65 (192-bit, recommended), ML-DSA-87 (256-bit).</P>
    <H3>SLH-DSA (formerly SPHINCS+) — Hash-Based Signatures</H3>
    <P>Stateless hash-based signature scheme. Conservative choice backed only by hash function security. Larger signatures but highest confidence in security. Sizes: SLH-DSA-128s/128f, SLH-DSA-192s/192f, SLH-DSA-256s/256f (s=small signature, f=fast signing).</P>

    <H2>Use Cases</H2>
    <P>- Government and defense agencies mandated to migrate to PQC by specific deadlines (NSA CNSA 2.0)</P>
    <P>- Financial institutions protecting long-lived data (mortgage records, pension data) that must remain confidential for decades</P>
    <P>- Healthcare organizations with patient records that have lifetime confidentiality requirements</P>
    <P>- Any organization beginning PQC planning to get ahead of regulatory requirements</P>

    <Collapse title="PQC Endpoints" defaultOpen>
      <EndpointTable rows={[
        ["POST", "/pqc/scan", "Start a PQC readiness scan across all keys and crypto operations"],
        ["GET", "/pqc/scans", "List completed scans with results"],
        ["GET", "/pqc/readiness", "Get overall PQC readiness score and breakdown"],
        ["POST", "/pqc/migration/plans", "Create a migration plan (maps classical → PQC algorithms)"],
        ["GET", "/pqc/migration/plans", "List migration plans with status"],
        ["POST", "/pqc/migration/plans/{id}/execute", "Execute a migration plan"],
        ["POST", "/pqc/migration/plans/{id}/rollback", "Rollback a migration to classical algorithms"],
        ["GET", "/pqc/timeline", "Get projected migration timeline with milestones"],
        ["GET", "/pqc/cbom/export", "Export CBOM showing all cryptographic algorithm usage"],
      ]} />
    </Collapse>

    <H2>Example: PQC Readiness Scan</H2>
    <Code>{`# Run a PQC readiness scan
curl -X POST http://localhost:8060/pqc/scan \\
  -H "Authorization: Bearer $TOKEN"

# Check readiness score
curl http://localhost:8060/pqc/readiness \\
  -H "Authorization: Bearer $TOKEN"
# Returns: { "score": 15, "classical_keys": 245, "pqc_keys": 3,
#   "recommendations": [
#     "Migrate 45 RSA-2048 keys to ML-KEM-768 for key exchange",
#     "Migrate 12 EC-P256 signing keys to ML-DSA-65",
#     "Create PQC keys for 3 KMIP clients"
#   ] }

# Create a migration plan
curl -X POST http://localhost:8060/pqc/migration/plans \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{ "name": "Q1-2026-migration", "scope": "all_rsa_keys",
    "target_algorithm": "ML-KEM-768" }'`}</Code>
  </div>
);

const SectionApiDiscovery = () => (
  <div>
    <div style={S.h1}>API: Cryptographic Discovery</div>
    <P>Service: kms-discovery | Port: 8100 (HTTP) / 18100 (gRPC) | Profile: crypto_discovery</P>

    <H2>What is Crypto Discovery?</H2>
    <P>Cryptographic Discovery scans your infrastructure to find all cryptographic assets — keys, certificates, encrypted connections, algorithm usage — across your environment. Many organizations don't know what cryptography they're using, where keys are stored, or how many certificates exist across their infrastructure. Discovery solves this visibility problem by automatically finding and cataloging everything.</P>

    <H2>Use Cases</H2>
    <P>- Shadow crypto detection: Find encryption keys and certificates that exist outside the KMS (in application configs, cloud services, containers)</P>
    <P>- PQC migration preparation: Before you can migrate to quantum-safe algorithms, you need a complete inventory of what classical crypto you're using</P>
    <P>- Certificate sprawl: Discover all TLS certificates across servers, load balancers, and cloud services to prevent surprise expirations</P>
    <P>- Compliance evidence: Demonstrate to auditors that you have complete visibility into cryptographic asset usage</P>
    <P>- Risk assessment: Identify weak algorithms (MD5, SHA-1, DES, 1024-bit RSA) still in use</P>

    <Collapse title="Discovery Endpoints" defaultOpen>
      <EndpointTable rows={[
        ["POST", "/discovery/scan", "Start a cryptographic asset discovery scan"],
        ["GET", "/discovery/scans", "List completed scans with statistics"],
        ["GET", "/discovery/assets", "List all discovered cryptographic assets"],
        ["PUT", "/discovery/assets/{id}/classify", "Classify a discovered asset (managed, external, deprecated)"],
        ["GET", "/discovery/summary", "Summary: total assets, by type, by algorithm, risk breakdown"],
        ["GET", "/discovery/posture", "Crypto posture score based on discovery findings"],
      ]} />
    </Collapse>

    <H2>Example</H2>
    <Code>{`# Run a discovery scan
curl -X POST http://localhost:8100/discovery/scan \\
  -H "Authorization: Bearer $TOKEN" \\
  -d '{ "scope": "all" }'

# View discovered assets
curl http://localhost:8100/discovery/assets \\
  -H "Authorization: Bearer $TOKEN"
# Returns: [{ "type": "certificate", "algorithm": "RSA-2048",
#   "location": "10.0.1.50:443", "expiry": "2026-06-15", "risk": "medium" }, ...]`}</Code>
  </div>
);

const SectionApiAi = () => (
  <div>
    <div style={S.h1}>API: AI / LLM Integration</div>
    <P>Service: kms-ai | Port: 8090 (HTTP) / 18090 (gRPC) | Profile: ai_llm</P>

    <H2>What is AI Integration?</H2>
    <P>The AI service connects Vecta KMS to a Large Language Model (LLM) to provide natural-language interaction with the platform. Ask questions about your security posture in plain English, get AI-powered analysis of security incidents, receive intelligent recommendations for improving your cryptographic practices, and get plain-language explanations of complex policies.</P>

    <H2>Use Cases</H2>
    <P>- Ask "Which keys haven't been rotated in 6 months?" in plain English instead of writing API queries</P>
    <P>- Incident triage: Feed a security alert to the AI and get an analysis of impact, affected resources, and recommended response</P>
    <P>- Policy explanation: Have the AI explain what a complex governance or access policy actually means in plain language</P>
    <P>- Posture recommendations: Get actionable suggestions for improving your security posture score</P>

    <Collapse title="AI Endpoints" defaultOpen>
      <EndpointTable rows={[
        ["POST", "/ai/query", "Natural language query about your KMS data and configuration"],
        ["POST", "/ai/analyze/incident", "AI analysis of a security incident with impact assessment"],
        ["POST", "/ai/recommend/posture", "AI-powered posture improvement recommendations"],
        ["POST", "/ai/explain/policy", "Plain-language explanation of a policy or configuration"],
        ["GET", "/ai/config", "Get current AI provider configuration"],
        ["PUT", "/ai/config", "Update AI provider (OpenAI, Anthropic, Azure OpenAI, local model)"],
      ]} />
    </Collapse>
  </div>
);

/* ─── UI GUIDE SECTIONS ─── */

const SectionUIDashboard = () => (
  <div>
    <div style={S.h1}>UI Guide: Dashboard (Home)</div>
    <P>The dashboard is the landing page showing a high-level overview of the KMS platform.</P>
    <H2>Stats Panel</H2>
    <P>Displays key metrics: total keys, total secrets, total certificates, pending approvals, open alerts, compliance score, cluster nodes, and operations per day. Each stat card shows the current value and week-over-week change.</P>
    <H2>Alert Summary</H2>
    <P>Shows unread alerts grouped by severity (critical, high, medium, low). Click an alert to navigate to the Alerts tab for details.</P>
    <H2>Certificate Expiry Tracker</H2>
    <P>Lists certificates expiring within 30/60/90 days. Click to navigate to the Certificates tab.</P>
    <H2>Compliance Score</H2>
    <P>Shows overall compliance posture as a percentage with breakdown by framework.</P>
  </div>
);

const SectionUIKeys = () => (
  <div>
    <div style={S.h1}>UI Guide: Keys</div>
    <P>The Keys tab is the primary interface for managing cryptographic keys.</P>
    <H2>Key List</H2>
    <P>Displays all keys in a sortable, filterable table with columns: Name, Algorithm, Size/Curve, Status, Destroy At, FIPS, KCV, Version, Operations, Tags, Actions. Use the column visibility button to show/hide columns.</P>
    <H2>Buttons & Actions</H2>
    <H3>Create Key</H3>
    <P>Opens the key creation modal. Select algorithm (AES, RSA, EC, ED25519, ML-KEM, ML-DSA, SLH-DSA, ChaCha20-Poly1305, HMAC), key size/curve, name, allowed operations, tags, and optional expiry date.</P>
    <H3>Import Key</H3>
    <P>Import external key material. Paste the base64-encoded key material, select the algorithm and size, assign a name and tags.</P>
    <H3>Generate PQC Key</H3>
    <P>Quick-create a post-quantum key. Select from ML-KEM-768, ML-KEM-1024, ML-DSA-65, ML-DSA-87, SLH-DSA-128f, SLH-DSA-256f.</P>
    <H3>Key Actions (per-key)</H3>
    <P>Each key row has an actions menu with: Rotate (creates new version), Export (downloads key material if policy allows), Edit Policy (modify access policy), Activate/Deactivate (toggle active state), Disable (prevent operations), Destroy (schedule irreversible deletion).</P>
    <H2>Key Detail Panel</H2>
    <P>Click a key name to open the detail panel showing: full metadata, version history, usage statistics, access policy, tags, and audit trail.</P>
    <H2>Tags</H2>
    <P>Tags are key-value labels attached to keys for organization and policy binding. Create, edit, and delete tags from the tag management panel.</P>
  </div>
);

const SectionUIWorkbench = () => (
  <div>
    <div style={S.h1}>UI Guide: Workbench</div>
    <P>The Workbench provides interactive tools for cryptographic operations.</P>
    <H2>Sub-Panes</H2>
    <H3>Crypto Console</H3>
    <P>Interactive cryptographic operations interface. Select a key from the catalog, choose an operation (Encrypt, Decrypt, Sign, Verify, Hash, Random, KEM Encap/Decap, Derive), enter input data (plaintext or base64), and execute. Results display inline with copy-to-clipboard support. Supports FIPS mode validation.</P>
    <H3>REST API Explorer</H3>
    <P>Browse all REST API endpoints organized by service. Select an endpoint, fill in parameters, and execute authenticated requests. Includes cURL preview generation, custom JWT authentication option, and request/response inspection panel.</P>
    <H3>Tokenize / Mask / Redact</H3>
    <P>Interactive tokenization, masking, and redaction tool. Enter sensitive data, select the operation type, configure options (vault-based vs vaultless, format-preserving, masking pattern), and execute. Preview mode available for masking.</P>
    <H3>Data Encryption</H3>
    <P>Field-level and envelope encryption interface. Select encryption mode (field, envelope, searchable), choose a key, enter data, and encrypt/decrypt.</P>
    <H3>Payment Crypto</H3>
    <P>Payment cryptography operations: TR-31 key block creation/parsing/translation, PIN translation/verification, CVV computation, MAC generation, ISO 20022 message encryption/signing, LAU generation, and key injection terminal management.</P>
  </div>
);

const SectionUIVault = () => (
  <div>
    <div style={S.h1}>UI Guide: Vault (Secrets)</div>
    <P>The Vault tab is your encrypted credential store. It securely holds all non-key sensitive data: passwords, API tokens, SSH keys, certificates, connection strings, and any other secrets your applications need.</P>

    <H2>Stats Row</H2>
    <P>At the top you see: Total Secrets count, breakdown by category, Envelope Encryption toggle (AES-256-GCM on/off), and vault health status.</P>

    <H2>Envelope Encryption Toggle</H2>
    <P>The envelope encryption toggle controls whether secrets are double-encrypted using a two-layer scheme (DEK wrapped by KEK). When enabled (recommended), each secret is encrypted with a unique Data Encryption Key, which is itself wrapped by the KMS master key. This means even if the database is compromised, secrets remain encrypted.</P>

    <H2>Secret Categories</H2>
    <P>Secrets are organized by type for easy management:</P>
    <P>- Credentials: Username/password pairs, database connection strings, service account credentials</P>
    <P>- SSH Keys: Public/private SSH keypairs for server access (RSA, ED25519)</P>
    <P>- PGP Keys: PGP encryption and signing keys for email security and file encryption</P>
    <P>- X.509 Certificates: TLS certificates and private keys for services that need cert+key bundles</P>
    <P>- Tokens: API keys, OAuth tokens, JWTs, bearer tokens for external service authentication</P>
    <P>- Key Material: Raw cryptographic key bytes for custom applications</P>

    <H2>Creating Secrets</H2>
    <P>Click "Create Secret" to open the creation modal. Enter a descriptive name, select the category, paste the secret value, and optionally add metadata tags (environment, team, expiry date). The secret is immediately encrypted and stored.</P>
    <P>Click "Generate Key Pair" to have the KMS generate an RSA, EC, or ED25519 keypair and store both the public and private key as a single secret. Useful for creating SSH deploy keys or TLS client certificates.</P>

    <H2>Managing Secrets</H2>
    <P>- View Value: Click the eye icon to reveal a secret's value. Every view is logged in the audit trail so you can track who accessed what</P>
    <P>- Copy: Click copy to put the value on your clipboard without displaying it on screen</P>
    <P>- Rotate: Click rotate to update a secret to a new value. The old version is preserved in version history for rollback</P>
    <P>- Version History: View all previous values with timestamps and who made the change</P>
    <P>- Audit Log: See the complete access history for this specific secret</P>
    <P>- Delete: Soft-delete a secret (recoverable within the retention period)</P>
  </div>
);

const SectionUICerts = () => (
  <div>
    <div style={S.h1}>UI Guide: Certificates & PKI</div>
    <P>The Certificates tab provides a complete Private PKI (Public Key Infrastructure). Create your own Certificate Authorities, issue certificates, and manage the full lifecycle — all from the dashboard.</P>

    <H2>Certificate Operations Sub-Pane</H2>
    <P>This is the main workspace for managing certificates.</P>
    <H3>Creating a CA (Certificate Authority):</H3>
    <P>Click "Create CA" to set up a root or intermediate Certificate Authority. Select algorithm (RSA-2048/4096, EC-P256/P384, ED25519), set validity period (typically 10 years for root, 5 for intermediate), and provide subject details (Organization, Country, etc.). Root CAs are self-signed; intermediate CAs are signed by a root.</P>
    <H3>Issuing Certificates:</H3>
    <P>Click "Issue Certificate" to create a new cert from one of your CAs. Enter the Common Name (e.g., api.myorg.com), add Subject Alternative Names (DNS names, IP addresses), set validity period, and select key usage (server auth, client auth, code signing, email). Download in PEM, DER, or PKCS12 format.</P>
    <H3>Certificate Lifecycle:</H3>
    <P>- Renew: Extend a certificate's validity before it expires (same subject, new dates)</P>
    <P>- Revoke: Mark a certificate as compromised. It's added to the CRL (Certificate Revocation List)</P>
    <P>- Upload Third-Party: Import certificates from external CAs for inventory tracking and expiry monitoring</P>
    <P>- Inventory: View all certificates with expiry countdown, chain visualization, and health status</P>

    <H2>Enrollment Protocols Sub-Pane</H2>
    <P>Configure automated certificate enrollment so devices and services can request certificates without manual intervention.</P>
    <P>- ACME: Compatible with certbot, cert-manager, Caddy, and other ACME clients. Supports HTTP-01, DNS-01, and TLS-ALPN-01 challenges</P>
    <P>- EST: Modern TLS-based enrollment for enterprise devices and IoT</P>
    <P>- SCEP: Legacy protocol for MDM platforms (Intune, Jamf) and network equipment (Cisco, Juniper)</P>
    <P>- CMPv2: Full-featured protocol for telecom and high-security PKI environments</P>

    <H2>Merkle Transparency</H2>
    <P>Provides cryptographic proof that certificates were properly issued and logged. Build Merkle epochs periodically, then request inclusion proofs for any certificate. Auditors can verify that no rogue certificates were issued outside the logging system.</P>
  </div>
);

const SectionUIDataprotect = () => (
  <div>
    <div style={S.h1}>UI Guide: Data Protection</div>
    <H2>Sub-Panes</H2>
    <H3>Field Encryption</H3>
    <P>Register SDK wrappers for application-level field encryption. Manage crypto leases (issue, renew, revoke). View wrapper telemetry and client usage statistics.</P>
    <H3>Data Encryption Policy</H3>
    <P>Configure policies for field-level encryption. Define which fields get encrypted, with which keys, and under what conditions.</P>
    <H3>Token / Mask / Redact Policy</H3>
    <P>Configure tokenization policies (vault-based, vaultless, format-preserving), masking policies (patterns, partial masking), and redaction policies (auto-detection, rule-based).</P>
    <H3>Payment Policy</H3>
    <P>Configure payment cryptography policies: allowed operations, key usage restrictions, terminal authentication requirements.</P>
    <H3>PKCS#11 / JCA</H3>
    <P>View SDK provider registrations and client telemetry. Monitor PKCS#11 and JCA provider usage, connection health, and operation statistics.</P>
  </div>
);

const SectionUICloud = () => (
  <div>
    <div style={S.h1}>UI Guide: Cloud Key Control</div>
    <P>The Cloud Control tab manages encryption keys across multiple cloud providers from a single dashboard. It has two major sections: BYOK and HYOK.</P>

    <H2>BYOK Sub-Pane (Bring Your Own Key)</H2>
    <P>BYOK lets you generate keys in Vecta and push them to cloud provider key services.</P>
    <H3>How to use BYOK:</H3>
    <P>1. Click "Add Account" to register a cloud provider. Select the provider (AWS, Azure, GCP, Oracle, Salesforce) and enter credentials (IAM role ARN, tenant/client ID, service account JSON, etc.)</P>
    <P>2. Once the account is connected, browse the Cloud Inventory to see what keys exist in the cloud</P>
    <P>3. Create a "Binding" to push a Vecta key to a cloud provider. The key material is securely transferred</P>
    <P>4. Use "Sync" to verify the binding state matches between Vecta and the cloud. "Rotate" to update the key in both places</P>
    <P>5. Region Mappings let you control which cloud regions keys are deployed to for multi-region setups</P>

    <H2>HYOK Sub-Pane (Hold Your Own Key)</H2>
    <P>HYOK keeps keys in Vecta and serves them to cloud providers on demand. The key never leaves your KMS.</P>
    <H3>How to configure HYOK:</H3>
    <P>- Microsoft DKE: Enable the DKE endpoint, bind a key, and configure Microsoft 365 to use your KMS URL as the DKE provider. Documents encrypted with Double Key Encryption require both Microsoft's key and your Vecta key to decrypt</P>
    <P>- Salesforce Cache-Only: Enable the Salesforce endpoint, bind a key. Salesforce Shield calls your KMS to wrap/unwrap the tenant key. If you disable the key, Salesforce loses access to encrypted data immediately</P>
    <P>- Google Cloud EKM: Enable the Google endpoint, bind a key. Google Cloud services (BigQuery, GCE, GCS) use your Vecta key for all encryption operations</P>
    <P>- Generic HYOK: Configure custom wrap/unwrap/encrypt/decrypt endpoints for other cloud or SaaS integrations</P>
    <P>- HYOK Request Log: View every request the cloud made to your KMS — full audit trail of who accessed which key and when</P>
  </div>
);

const SectionUIEkm = () => (
  <div>
    <div style={S.h1}>UI Guide: EKM (Enterprise Key Manager)</div>
    <P>The EKM tab centralizes encryption key management for databases, Windows endpoints, and KMIP-compatible devices.</P>

    <H2>EKM for DBs Sub-Pane</H2>
    <P>Manages Transparent Data Encryption (TDE) keys for database servers.</P>
    <H3>How to use:</H3>
    <P>1. Click "Register Agent" to add a database server (MSSQL or Oracle). Enter the server hostname, database type, and connectivity details</P>
    <P>2. Download the agent deployment package and install it on the database server</P>
    <P>3. The agent connects to Vecta and fetches the TDE master key. Database encrypts all data files transparently</P>
    <P>4. Monitor agent health (green/red status indicators), view logs, and rotate TDE keys on schedule</P>
    <P>5. If an agent goes unhealthy, investigate via the logs panel or re-deploy the agent</P>

    <H2>BitLocker Sub-Pane</H2>
    <P>Centrally manages Windows BitLocker full-disk encryption across your fleet.</P>
    <H3>How to use:</H3>
    <P>1. Click "Scan Network" to discover Windows machines that support BitLocker</P>
    <P>2. Register discovered machines or manually add clients</P>
    <P>3. Download and deploy the agent on each Windows machine</P>
    <P>4. View encryption status for all machines, manage recovery keys (securely escrowed in Vecta)</P>
    <P>5. Execute operations: suspend BitLocker (for maintenance), resume encryption, rotate protection keys</P>

    <H2>KMIP Sub-Pane</H2>
    <P>Manages the KMIP (Key Management Interoperability Protocol) server for devices that speak KMIP.</P>
    <H3>What KMIP is for:</H3>
    <P>KMIP is an industry standard protocol (OASIS) used by storage arrays, databases, backup systems, and encryption appliances to manage keys. Devices like NetApp, VMware vSAN, Dell PowerScale, MongoDB, and MySQL can connect to Vecta's KMIP server for centralized key management.</P>
    <H3>How to use:</H3>
    <P>1. Create a Client Profile — defines the CA for issuing client certificates, role assignments, and certificate settings</P>
    <P>2. Register KMIP Clients — either internally (Vecta issues the client certificate) or externally (upload an existing client cert)</P>
    <P>3. Set the preferred KMIP Protocol Version using the version toggle (supports 1.0 through 3.2)</P>
    <P>4. Configure Interop Targets to validate connectivity with external KMIP servers (for interoperability testing)</P>
    <P>5. View Server Capabilities: supported KMIP versions, implemented operations, object types, and authentication modes</P>
  </div>
);

const SectionUIHsm = () => (
  <div>
    <div style={S.h1}>UI Guide: HSM</div>
    <P>The HSM tab configures the cryptographic backend for key storage and operations.</P>
    <H2>Supported HSM Vendors</H2>
    <H3>AWS CloudHSM</H3>
    <P>Configure cluster endpoint, credentials, and slot mapping for AWS CloudHSM Classic or CloudHSMv2.</P>
    <H3>Azure Managed HSM</H3>
    <P>Configure endpoint, authentication, and PKCS#11 bridge for Azure Managed HSM or Azure Dedicated HSM.</P>
    <H3>Thales Luna HSM</H3>
    <P>Configure NTLS endpoint, Luna slot, partition label, and client certificate for Thales Luna Network HSM.</P>
    <H3>Utimaco HSM</H3>
    <P>Configure CryptoServer endpoint, slot, and authentication for Utimaco CryptoServer Se/Ce series.</P>
    <H3>Entrust nShield HSM</H3>
    <P>Configure Security World connector, module protection, and PKCS#11 settings for Entrust nShield Connect/Solo.</P>
    <H3>Vecta KMS HSM</H3>
    <P>Configure provider API and partition for Vecta KMS Primus HSM.</P>
    <H3>Generic PKCS#11</H3>
    <P>Vendor-neutral PKCS#11 onboarding. Specify library path, slot ID/label, PIN, and key attributes.</P>
    <H2>HSM Operations</H2>
    <P>Generate keys in HSM, discover partition slots, view HSM health status, SSH into HSM CLI (via port 2222), install PKCS#11 providers.</P>
  </div>
);

const SectionUIAdvanced = () => (
  <div>
    <div style={S.h1}>UI Guide: Advanced (QKD, QRNG, MPC)</div>
    <P>The Advanced tab contains next-generation cryptographic technologies: quantum key distribution, quantum random number generation, and multi-party computation. These features are for organizations with advanced security requirements.</P>

    <H2>QKD Tab — Quantum Key Distribution</H2>
    <P>This tab is the management interface for your QKD network integration.</P>
    <H3>What customers see:</H3>
    <P>- Stats row: Active SAEs, total QKD keys, distributions completed, last activity timestamp</P>
    <P>- Configuration panel: Set QKD mode (ETSI 014, ETSI 004, Cisco CKM, Relay), endpoint URLs, polling intervals</P>
    <P>- SAE Management: Register new Secure Application Entities (your QKD hardware nodes), view their status, trigger key distribution</P>
    <P>- Key Inventory: Browse all quantum-distributed keys with source SAE, creation date, injection status. Inject keys into KMS for general use</P>
    <P>- Distribution History: Complete log of every key distribution operation with timestamps, participants, and success/failure</P>
    <P>- Test Tools: Generate test QKD keys (software-simulated, not quantum-secure) for development and integration testing</P>
    <H3>How to use:</H3>
    <P>1. Click "Configure" to set your QKD mode and endpoint. 2. Click "Register SAE" to add your QKD hardware nodes. 3. Once SAEs are connected, use "Distribute" to share quantum keys between nodes. 4. Click "Inject" on any QKD key to make it available as a standard KMS key for encryption operations.</P>

    <H2>QRNG Tab — Quantum Random Number Generator</H2>
    <P>This tab manages hardware and cloud-based quantum entropy sources that feed true randomness into the KMS.</P>
    <H3>What customers see:</H3>
    <P>- Entropy Pool Status: Current entropy level, health, and source count</P>
    <P>- Registered Sources: List of QRNG devices/services with connection status, last fetch time, bytes delivered</P>
    <P>- Configuration: Pull mode (KMS fetches entropy on schedule) vs Push mode (device sends entropy). Set polling interval and minimum entropy threshold</P>
    <P>- Health Events: Log of entropy source health events (connected, disconnected, low entropy warnings)</P>
    <H3>How to use:</H3>
    <P>1. Click "Add Source" to register a QRNG device or cloud service (ID Quantique Quantis, ANU QRNG API, etc.). 2. Configure pull or push mode. 3. Set the minimum entropy threshold — if the pool drops below this level, the system alerts you. 4. Once configured, all KMS key generation automatically uses quantum-grade entropy. No code changes needed.</P>

    <H2>MPC Tab — Multi-Party Computation</H2>
    <P>This tab manages distributed key operations where multiple parties must cooperate.</P>
    <H3>What customers see:</H3>
    <P>- Overview: Active ceremonies, MPC keys, participant count, recent activity</P>
    <P>- Operations: Start DKG (distributed key generation), threshold signing, or threshold decryption workflows. Monitor ceremony progress as participants contribute</P>
    <P>- Key Management: View all MPC-generated keys with share distribution, threshold (t-of-n), and usage count. Revoke keys or manage groups</P>
    <P>- Configuration: Register participants (people or services), create policies (define threshold requirements, timeout, quorum rules)</P>
    <H3>How to use:</H3>
    <P>1. Register at least 3 participants in Configuration. 2. Create a policy (e.g., "3-of-5 threshold"). 3. Start a DKG ceremony — each participant submits their contribution. 4. Once complete, the shared key appears in Key Management. 5. To sign or decrypt, start a ceremony and wait for threshold participants to contribute.</P>
  </div>
);

const SectionUIGovernance = () => (
  <div>
    <div style={S.h1}>UI Guide: Governance & Approvals</div>
    <P>The Governance tab implements multi-party approval workflows. Use it to ensure sensitive operations require authorization from multiple people before execution.</P>

    <H2>Requests Tab</H2>
    <P>The central view for approval workflow management.</P>
    <H3>What you see:</H3>
    <P>- Request list with status badges: Pending (amber), Approved (green), Denied (red), Expired (gray)</P>
    <P>- Each request shows: who requested it, what operation, which resource, which policy triggered, and a countdown timer to expiry</P>
    <P>- Click a request to open the detail view with full description, vote history, and approve/deny buttons</P>
    <H3>How to use:</H3>
    <P>1. When someone requests a sensitive operation (e.g., key destruction), it appears here as "Pending". 2. Eligible approvers see the request and review the details. 3. Click "Approve" or "Deny" with an optional comment. 4. When enough approvers vote (meeting the quorum), the operation is automatically executed or rejected.</P>

    <H2>Policies Tab</H2>
    <P>Define what operations require approval and how many approvers are needed.</P>
    <H3>Creating a policy:</H3>
    <P>1. Click "+ Add Policy" and give it a name (e.g., "Key Destruction Approval"). 2. Select the scope: which operations trigger this policy (key destroy, key export, tenant delete, user role change, etc.). 3. Set the quorum: how many approvers must vote "approve" (e.g., 2 of 3). 4. Set the timeout: how long the request stays open before auto-expiring (e.g., 24 hours). 5. Optionally restrict which roles or specific users can be approvers.</P>

    <H2>Settings Tab</H2>
    <P>Configure how approvers are notified when a new request needs their attention.</P>
    <P>- SMTP Email: Configure email server (host, port, from address, TLS). Approvers receive an email with request details and a link to the dashboard</P>
    <P>- Slack Webhook: Paste a Slack incoming webhook URL. Approval requests are posted to your Slack channel</P>
    <P>- Custom Webhook: Send approval requests to any HTTP endpoint for integration with ticketing systems (Jira, ServiceNow)</P>
    <P>- Use "Test" buttons to verify each channel is working before going live</P>
    <P>- Toggle "External Notifications" to enable/disable external delivery. When disabled, approvals are managed entirely through the KMS dashboard</P>
  </div>
);

const SectionUIMonitoring = () => (
  <div>
    <div style={S.h1}>UI Guide: Monitoring (Alerts, Audit, Posture, Compliance, SBOM)</div>
    <P>The Monitoring tab is your security operations center for the KMS. It combines alerting, audit logging, security posture, compliance, and software inventory into sub-panes you can switch between.</P>

    <H2>Alerts Sub-Pane</H2>
    <P>The Alerts sub-pane shows all security alerts across the platform. Alerts are generated automatically when the system detects issues — expiring certificates, failed login attempts, policy violations, unhealthy agents, etc.</P>
    <H3>What you can do:</H3>
    <P>- Filter by severity (Critical, High, Medium, Low) and status (New, Open, Acknowledged, Resolved)</P>
    <P>- Bulk acknowledge alerts to clear the queue after review</P>
    <P>- Escalate critical alerts to incident response teams</P>
    <P>- View alert statistics: Mean Time To Resolution (MTTR), top alert sources, severity distribution</P>
    <P>- Configure alert rules to define what triggers alerts and at what severity</P>

    <H2>Audit Log Sub-Pane</H2>
    <P>Every operation in the KMS is recorded in an immutable audit trail secured by Merkle hash trees.</P>
    <H3>Events Tab:</H3>
    <P>Search and filter audit events by service (keycore, auth, secrets, certs, etc.), result (success, failure, denied), severity, time range, and user. Each event shows who did what, when, from where, and the result. Export events as CSV or CEF for SIEM integration.</P>
    <H3>Chain Verification Tab:</H3>
    <P>The audit log uses Merkle hash trees to guarantee immutability. Build Merkle epochs (periodic hash checkpoints), request inclusion proofs for any event (prove an event was logged and hasn't been tampered with), and verify the entire chain integrity. This is critical for regulatory audits that require provable, tamper-evident logging.</P>

    <H2>Posture Sub-Pane</H2>
    <P>The Posture sub-pane gives you a CISO-level dashboard of cryptographic security health.</P>
    <H3>What you see:</H3>
    <P>- Overall Risk Score: 0-100 with color coding (green, amber, red)</P>
    <P>- Domain Breakdown: Individual scores for BYOK, HYOK, EKM, KMIP, BitLocker, SDK integrations</P>
    <P>- Findings List: Specific security issues with severity, affected resource, and one-click remediation</P>
    <P>- Scan Button: Trigger a manual posture scan. Scans run automatically on a schedule</P>
    <P>- Trend Charts: See how your posture score has changed over time</P>

    <H2>Compliance Sub-Pane</H2>
    <P>The Compliance sub-pane evaluates your KMS against regulatory frameworks.</P>
    <H3>What you can do:</H3>
    <P>- Select a framework (PCI-DSS, HIPAA, SOC 2, ISO 27001) and click "Run Assessment"</P>
    <P>- View the compliance score as a percentage with control-by-control breakdown</P>
    <P>- See specific control gaps with remediation guidance ("Rotate 5 keys that haven't been rotated in 365+ days")</P>
    <P>- View key hygiene reports: rotation compliance, algorithm strength analysis, expiry tracking</P>
    <P>- Find orphaned keys (keys with no usage) that represent security risk</P>
    <P>- Schedule automated assessments (daily, weekly, monthly)</P>

    <H2>SBOM / CBOM Sub-Pane</H2>
    <P>The SBOM/CBOM sub-pane provides software and cryptographic inventory.</P>
    <H3>SBOM (Software Bill of Materials):</H3>
    <P>Click "Generate" to create a current SBOM. View all components (Go modules, npm packages, Docker images). Check for known vulnerabilities (CVEs). Export in CycloneDX or SPDX format for compliance. Diff between versions to see what changed between releases.</P>
    <H3>CBOM (Cryptographic Bill of Materials):</H3>
    <P>Click "Generate" to create a CBOM. View all cryptographic algorithms in use with counts and key sizes. Check PQC readiness (which algorithms need migration to quantum-safe alternatives). Export for compliance evidence.</P>
  </div>
);

const SectionUICluster = () => (
  <div>
    <div style={S.h1}>UI Guide: Cluster</div>
    <P>The Cluster tab is available when the clustering profile is enabled.</P>
    <H2>Sub-Panes</H2>
    <H3>Topology</H3>
    <P>Visual cluster map showing nodes, connections, health status, and roles (leader, follower, replica).</P>
    <H3>Node Management</H3>
    <P>Detailed view of each node: CPU/memory/disk metrics, service components, role, health. Actions: add node, remove node, change role.</P>
    <H3>Deploy Profiles</H3>
    <P>Replication profiles with deployment tier presets (Core, Standard, Security Suite, Full). Each profile defines which services run on which nodes.</P>
    <H3>Sync Monitor</H3>
    <P>Real-time sync events, checkpoints, and replication lag metrics. View pending sync items and acknowledged events.</P>
    <H3>Cluster Logs</H3>
    <P>Filterable cluster operation audit log showing joins, departures, role changes, sync events, and failures.</P>
  </div>
);

const SectionUIAdmin = () => (
  <div>
    <div style={S.h1}>UI Guide: Administration</div>
    <P>The Administration section is where platform administrators manage the KMS infrastructure, tenants, users, and system configuration.</P>

    <H2>System Administration</H2>
    <P>The System Admin sub-pane provides platform-level controls.</P>
    <H3>What you can do:</H3>
    <P>- Service Health Dashboard: See real-time heartbeat status for all 26+ microservices. Green = healthy, Red = down, Amber = degraded</P>
    <P>- FIPS Mode: Toggle between Strict (FIPS 140-3 compliant) and Standard modes. Strict mode blocks non-FIPS algorithms</P>
    <P>- Runtime Hardening: Configure FIPS runtime policy, entropy source visibility, TLS runtime mode, and request-interface TLS certificate defaults</P>
    <P>- CLI Status: View the SSH CLI daemon status. Connect via <IC>ssh cli-user@host -p 2222</IC> for HSM operations</P>
    <P>- HSM Configuration: Configure the cryptographic backend (software vault, hardware HSM, or auto mode)</P>
    <P>- Alert Rules: Create rules that trigger alerts based on events (e.g., "alert on any key destruction", "alert on failed logins exceeding threshold")</P>

    <H2>Tenant Administration</H2>
    <P>Tenants are isolated organizational units within the KMS. Each tenant has its own keys, secrets, certificates, users, and policies. A bank might have tenants for "retail-banking", "trading", and "hr". Each tenant's data is cryptographically isolated.</P>
    <H3>What you can do:</H3>
    <P>- Create Tenant: Add a new organizational tenant. Each tenant gets its own isolated key store, user base, and policies</P>
    <P>- Tenant Overview: View each tenant's status, resource counts (keys, secrets, certs, users), and usage statistics</P>
    <P>- Disable/Enable: Temporarily suspend a tenant (all API calls from that tenant are rejected) without deleting data</P>
    <P>- Delete Tenant: Permanently remove a tenant. A readiness check ensures no active keys or dependencies exist before deletion</P>
    <P>- Per-Tenant Settings: Each tenant can have its own password policy (min length, complexity, expiry), security policy (MFA, session timeout, IP allowlist), HSM configuration, and backup schedule</P>
    <H3>Use cases:</H3>
    <P>- Multi-tenant SaaS: Provide isolated key management to each customer from a single KMS deployment</P>
    <P>- Department isolation: Separate key management for different business units with independent policies</P>
    <P>- Environment separation: Create tenants for dev, staging, and production with different security policies</P>

    <H2>User Management</H2>
    <P>Manage who can access the KMS and what they can do.</P>
    <H3>Roles explained:</H3>
    <P>- admin: Full system access across all tenants. Can manage other admins, configure system settings, and access all resources</P>
    <P>- tenant-admin: Full access within their assigned tenant. Can create users, keys, secrets, and configure tenant settings</P>
    <P>- approver: Can vote on governance approval requests. Cannot create or modify resources directly</P>
    <P>- operator: Day-to-day key operations — create, rotate, encrypt, decrypt. Cannot destroy keys or manage users</P>
    <P>- auditor: Read-only access to audit logs, compliance reports, and security posture. Cannot modify anything</P>
    <P>- viewer: Read-only access to key metadata and dashboards. Cannot see key material or secret values</P>
    <P>- cli-user: SSH CLI access for HSM operations (slot discovery, key generation, provider installation)</P>
    <H3>Identity Providers:</H3>
    <P>Connect external identity sources: LDAP/Active Directory (sync users and groups), SAML 2.0 (SSO with Okta, Azure AD, PingIdentity), OIDC (SSO with Google, Auth0, Keycloak). Users authenticate via their corporate identity provider and are mapped to KMS roles.</P>
  </div>
);

/* ─── CONFIG SECTIONS ─── */

const SectionConfigEnv = () => (
  <div>
    <div style={S.h1}>Configuration: Environment Variables</div>
    <H2>Database</H2>
    <EnvTable rows={[
      ["POSTGRES_DSN", "postgres://postgres:postgres@postgres:5432/vecta?sslmode=disable", "Primary database connection string"],
      ["POSTGRES_RO_DSN", "(empty)", "Read replica DSN (optional)"],
      ["DB_MAX_OPEN", "25", "Maximum open database connections"],
      ["DB_MAX_IDLE", "10", "Maximum idle database connections"],
      ["DB_CONN_MAX_IDLE_TIME_SEC", "300", "Max idle time before closing (seconds)"],
      ["DB_CONN_MAX_LIFETIME_SEC", "1800", "Max connection lifetime (seconds)"],
    ]} />
    <H2>Rate Limiting</H2>
    <EnvTable rows={[
      ["RATE_LIMIT_RPS", "100", "Requests per second per tenant"],
      ["RATE_LIMIT_BURST", "200", "Burst size for rate limiter"],
    ]} />
    <H2>Infrastructure</H2>
    <EnvTable rows={[
      ["NATS_URL", "nats://nats:4222", "NATS JetStream URL (optional)"],
      ["REDIS_URL", "redis://valkey:6379", "Valkey/Redis cache URL (optional)"],
      ["CONSUL_HTTP_ADDR", "consul:8500", "Consul address (optional)"],
    ]} />
    <H2>JWT & Security</H2>
    <EnvTable rows={[
      ["JWT_ISSUER", "vecta-auth", "JWT token issuer"],
      ["JWT_AUDIENCE", "vecta-services", "JWT token audience"],
      ["JWT_PUBLIC_KEY_PATH", "certs/jwt_public.pem", "Path to JWT public key"],
    ]} />
    <H2>Auth Bootstrap</H2>
    <EnvTable rows={[
      ["AUTH_BOOTSTRAP_TENANT_ID", "root", "Default tenant ID"],
      ["AUTH_BOOTSTRAP_ADMIN_USERNAME", "admin", "Bootstrap admin username"],
      ["AUTH_BOOTSTRAP_ADMIN_PASSWORD", "<your-password>", "Bootstrap admin password"],
      ["AUTH_BOOTSTRAP_ADMIN_ROLE", "tenant-admin", "Bootstrap admin role"],
      ["AUTH_BOOTSTRAP_FORCE_PASSWORD_CHANGE", "true", "Force password change on first login"],
      ["AUTH_BOOTSTRAP_CLI_ENABLED", "true", "Enable CLI user"],
      ["AUTH_BOOTSTRAP_CLI_USERNAME", "cli-user", "CLI user name"],
      ["AUTH_BOOTSTRAP_CLI_PASSWORD", "<your-cli-password>", "CLI user password"],
    ]} />
    <H2>PostgreSQL Tuning</H2>
    <EnvTable rows={[
      ["PG_SHARED_BUFFERS", "256MB", "Shared buffer pool size"],
      ["PG_EFFECTIVE_CACHE", "768MB", "Effective cache size hint for planner"],
      ["PG_WORK_MEM", "8MB", "Work memory per operation"],
      ["PG_MAINT_WORK_MEM", "128MB", "Maintenance work memory"],
      ["PG_MAX_CONN", "200", "Max database connections"],
      ["PG_WAL_BUFFERS", "32MB", "WAL buffer size"],
      ["PG_MAX_WAL_SIZE", "2GB", "Max WAL size before checkpoint"],
    ]} />
  </div>
);

const SectionConfigFips = () => (
  <div>
    <div style={S.h1}>Configuration: FIPS Mode</div>
    <P>FIPS mode controls the cryptographic boundary of the platform. Two modes are available:</P>
    <H2>Strict Mode (FIPS 140-3)</H2>
    <P>Blocks non-FIPS algorithms, enforces Go BoringCrypto, requires FIPS-approved TLS ciphers, rejects non-FIPS key imports, enforces minimum key sizes (RSA 2048, EC 224).</P>
    <H3>Allowed Algorithms in Strict Mode</H3>
    <EnvTable rows={[
      ["Hashes", "SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256", "FIPS-approved hash functions"],
      ["Symmetric", "AES-128, AES-192, AES-256, 3DES", "FIPS-approved symmetric ciphers"],
      ["TLS Ciphers", "TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384", "TLS 1.3 cipher suites"],
      ["Min RSA", "2048 bits", "Minimum RSA key size"],
      ["Min EC", "224 bits", "Minimum EC key size"],
    ]} />

    <H2>Standard Mode</H2>
    <P>Allows legacy algorithms with warnings. Tags non-FIPS keys. Default TLS version 1.2. Useful for development, testing, and gradual migration to FIPS compliance.</P>

    <H2>Enabling FIPS Mode</H2>
    <P>FIPS mode is toggled in System Administration. The Runtime Crypto dialog shows the effective runtime library, entropy health, entropy rate in bits per byte, sample size, read latency, RNG mode, and whether runtime enforcement is enabled. When switching from Standard to Strict, the system validates all existing keys and blocks the transition if non-compliant keys are active.</P>
  </div>
);

const SectionConfigHsm = () => (
  <div>
    <div style={S.h1}>Configuration: HSM</div>
    <H2>HSM Mode</H2>
    <EnvTable rows={[
      ["HSM_MODE", "software", "software, hardware, or auto"],
      ["HSM_ENDPOINT", "hsm-connector:18430", "HSM connector gRPC endpoint"],
      ["KEYCORE_MEK_B64", "(empty)", "Master Encryption Key (base64, for software mode)"],
      ["KEYCORE_MEK_FILE", "/app/data/mek.b64", "MEK file path"],
      ["KEYCORE_MEK_IN_HSM", "false", "Store MEK in hardware HSM"],
      ["KEYCORE_MEK_LOGICAL_ID", "(empty)", "HSM logical ID for MEK"],
    ]} />
    <H2>Software Vault</H2>
    <EnvTable rows={[
      ["SOFTWARE_VAULT_PASSPHRASE", "vecta-dev-passphrase", "Software vault encryption passphrase"],
      ["SOFTWARE_VAULT_MLOCK_REQUIRED", "false", "Lock vault memory (prevents swapping)"],
    ]} />
    <H2>Hardware HSM Providers</H2>
    <P>Supported: AWS CloudHSM, Azure Managed HSM, Thales Luna, Utimaco CryptoServer, Entrust nShield, Vecta KMS Primus, Generic PKCS#11. Each provider is configured via the HSM tab in the dashboard with vendor-specific parameters (endpoint, slot, partition, credentials, library path).</P>
    <H2>CLI SSH Access</H2>
    <Code>{`# Enable CLI user
AUTH_BOOTSTRAP_CLI_ENABLED=true

# Connect via SSH
ssh cli-user@localhost -p 2222
# Password: <your-cli-password>

# HSM CLI commands available in the SSH session
# Slot discovery, key generation, provider installation`}</Code>
  </div>
);

const SectionConfigNetwork = () => (
  <div>
    <div style={S.h1}>Configuration: Networking</div>
    <H2>Network Interfaces</H2>
    <EnvTable rows={[
      ["Management (eth0)", "10.0.1.100/24", "Primary interface for dashboard, API, and client traffic"],
      ["Cluster (eth1)", "172.16.0.100/24", "Optional dedicated cluster replication traffic"],
      ["HSM (eth2)", "(unconfigured)", "Optional dedicated HSM communication"],
    ]} />
    <H2>TLS Configuration</H2>
    <P>Runtime Crypto controls the TLS runtime mode and the authoritative certificate binding for request interfaces. Interfaces controls which request endpoints are exposed, the bind address, the port, and whether a listener uses HTTP, HTTPS, TLS 1.3, or mTLS.</P>
    <P>When a request-handling interface uses HTTPS, TLS 1.3, or mTLS, the certificate source selected in Runtime Crypto takes precedence over any per-interface certificate fields. The interface layer inherits one shared certificate binding from either the internal CA, a CA from the PKI tab, or an uploaded certificate from the PKI tab.</P>
    <Code>{`# TLS paths
CERTS_RUNTIME_MATERIALIZER_ENABLED=true
CERTS_RUNTIME_MATERIALIZER_DIR=/run/vecta/certs
CERTS_RUNTIME_MATERIALIZER_INTERVAL=5m
CERTS_RUNTIME_ENVOY_CN=vecta-envoy
CERTS_RUNTIME_ENVOY_SANS=localhost,envoy,127.0.0.1`}</Code>
    <H2>Runtime TLS APIs</H2>
    <P>Use <IC>GET /svc/keycore/access/interface-tls-config?tenant_id=root</IC> to read the current interface TLS binding and <IC>PUT /svc/keycore/access/interface-tls-config</IC> to change it. Use <IC>GET /svc/keycore/access/interface-ports?tenant_id=root</IC> to inspect the effective request interfaces after TLS defaults are applied.</P>
    <H2>Firewall</H2>
    <P>Built-in firewall with port allowlists per interface: management (443, 5696, 9443), cluster (2379, 2380, 5432, 4222, 8160), hsm (2300, 2310).</P>
    <H2>Syslog</H2>
    <P>Forward logs to remote syslog via TCP+TLS or UDP. Configure server address and protocol in the network configuration.</P>
  </div>
);

const SectionConfigCluster = () => (
  <div>
    <div style={S.h1}>Configuration: Clustering</div>
    <P>Enable clustering via the <IC>clustering</IC> Docker profile. This starts etcd for consensus and the cluster-manager service.</P>
    <H2>Cluster Environment Variables</H2>
    <EnvTable rows={[
      ["CLUSTER_URL", "http://cluster-manager:8210", "Cluster manager endpoint"],
      ["CLUSTER_NODE_ID", "vecta-kms-01", "Unique node identifier"],
      ["CLUSTER_NODE_ROLE", "leader", "Node role: leader, follower, or replica"],
      ["CLUSTER_NODE_ENDPOINT", "10.0.1.100", "Advertised node endpoint IP"],
      ["CLUSTER_SYNC_SHARED_SECRET", "(empty)", "Shared secret for sync authentication"],
      ["CLUSTER_SYNC_ANTI_REPLAY_SEC", "120", "Anti-replay window (seconds)"],
      ["CLUSTER_SYNC_REQUIRE_MTLS", "false", "Require mTLS for sync"],
    ]} />
    <H2>Cluster TLS</H2>
    <EnvTable rows={[
      ["CLUSTER_HTTP_TLS_ENABLE", "false", "Enable TLS for cluster HTTP"],
      ["CLUSTER_HTTP_TLS_CERT_FILE", "(empty)", "Cluster TLS certificate"],
      ["CLUSTER_HTTP_TLS_KEY_FILE", "(empty)", "Cluster TLS key"],
      ["CLUSTER_HTTP_TLS_CLIENT_CA_FILE", "(empty)", "Client CA for mTLS"],
    ]} />
    <H2>Node Roles</H2>
    <P>Leader: accepts writes, coordinates replication. Follower: receives replicated data, can serve reads. Replica: read-only copy for horizontal read scaling. Roles can be changed dynamically via the Cluster tab or API.</P>
    <Code>{`docker compose --profile clustering up -d

# Verify cluster
curl http://localhost:8210/cluster/overview`}</Code>
  </div>
);

const SectionConfigBackup = () => (
  <div>
    <div style={S.h1}>Configuration: Backup & Restore</div>
    <H2>Backup Features</H2>
    <P>Scope: system-wide or tenant-specific. Format: JSON GZip compressed with AES-256-GCM encryption. Artifacts use .vbk extension with separate .key.json key package.</P>
    <P>Backups now carry explicit <IC>backup_coverage</IC> metadata in the artifact/key package so operators can see which capability classes were preserved. When the related service tables exist, posture findings, compliance assessments, reporting jobs, incidents, and evidence-pack source data are included in the encrypted snapshot.</P>
    <H2>Creating a Backup</H2>
    <Code>{`# Via API
curl -X POST http://localhost:8050/governance/backups \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"scope": "system", "description": "Daily backup"}'

# Download artifact
curl -O http://localhost:8050/governance/backups/{id}/artifact \\
  -H "Authorization: Bearer $TOKEN"

# Download encryption key
curl -O http://localhost:8050/governance/backups/{id}/key \\
  -H "Authorization: Bearer $TOKEN"`}</Code>
    <H2>Restoring</H2>
    <Code>{`curl -X POST http://localhost:8050/governance/backups/restore \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"backup_id": "...", "scope": "system"}'`}</Code>
    <H2>HSM-Bound Backups</H2>
    <P>Optional HSM binding wraps the backup encryption key using HSM metadata (provider, slot, partition, fingerprint). Requires matching HSM binding on restore for additional security.</P>
    <EnvTable rows={[
      ["BACKUP_HSM_WRAP_SECRET", "vecta-backup-wrap-secret-change-me", "HSM backup wrap secret"],
      ["BACKUP_HSM_PARTITION_LABEL", "(empty)", "HSM partition for backup key"],
    ]} />
    <H2>Excluded Tables</H2>
    <P>Backup excludes: governance_backup_jobs, audit logs, alert runtime tables, and operational log tables. These are regenerated or are point-in-time data. Reporting incidents and report jobs remain included; live alert feeds and audit partitions do not.</P>
  </div>
);

const SectionConfigProfiles = () => (
  <div>
    <div style={S.h1}>Configuration: Docker Profiles</div>
    <P>Docker profiles control which services are started. Core services (auth, keycore, policy, audit, postgres, envoy, dashboard) always run. Optional services are gated by profiles.</P>
    <Code>{`# Start with specific profiles
docker compose --profile secrets --profile governance --profile cloud_byok up -d

# Start all profiles
docker compose --profile '*' up -d

# List running services
docker compose ps`}</Code>
    <H2>Available Profiles</H2>
    <EnvTable rows={[
      ["connection_pooling", "pgbouncer", "PgBouncer connection pooler"],
      ["event_streaming", "nats", "NATS JetStream event bus"],
      ["distributed_cache", "valkey", "Valkey/Redis cache"],
      ["service_discovery", "consul", "Consul service registry"],
      ["clustering", "etcd, cluster-manager", "Multi-node clustering"],
      ["secrets", "kms-secrets", "Secrets vault"],
      ["certs", "kms-certs", "Certificate PKI"],
      ["governance", "kms-governance", "Governance and approvals"],
      ["cloud_byok", "kms-cloud", "Cloud BYOK integration"],
      ["hyok_proxy", "kms-hyok-proxy", "HYOK proxy"],
      ["kmip_server", "kms-kmip", "KMIP 2.1 server"],
      ["qkd_interface", "kms-qkd", "Quantum key distribution"],
      ["ekm_database", "kms-ekm", "Enterprise key manager"],
      ["payment_crypto", "kms-payment", "Payment cryptography"],
      ["compliance_dashboard", "kms-compliance", "Compliance reporting"],
      ["sbom_cbom", "kms-sbom", "SBOM/CBOM generation"],
      ["reporting_alerting", "kms-reporting", "Reporting and alerting"],
      ["posture_management", "kms-posture", "Security posture"],
      ["ai_llm", "kms-ai", "AI/LLM integration"],
      ["pqc_migration", "kms-pqc", "Post-quantum crypto"],
      ["crypto_discovery", "kms-discovery", "Crypto discovery"],
      ["mpc_engine", "kms-mpc", "Multi-party computation"],
      ["data_protection", "kms-dataprotect", "Data protection"],
      ["hsm_cli", "hsm-integration", "HSM CLI SSH access"],
      ["hsm_hardware", "hsm-connector", "Hardware HSM connector"],
      ["hsm_software", "software-vault", "Software HSM vault"],
    ]} />
    <H2>Resource Limits</H2>
    <P>Default service limits: 0.5 CPU / 256M memory. Auth and Keycore override: 1.0 CPU / 512M memory. PostgreSQL: 2.0 CPU / 2G memory. PgBouncer: 0.25 CPU / 64M memory.</P>
  </div>
);

const SectionTroubleshooting = () => (
  <div>
    <div style={S.h1}>Troubleshooting</div>
    <H2>Service Won't Start</H2>
    <Code>{`# Check logs for a specific service
docker compose logs keycore --tail 50

# Check health
docker compose ps

# Restart a service
docker compose restart keycore`}</Code>

    <H2>Authentication Failures</H2>
    <P>Verify the JWT_ISSUER and JWT_AUDIENCE match across all services. Check that the JWT public key file exists at the configured path. Ensure the auth service is healthy before other services start.</P>

    <H2>Database Connection Errors</H2>
    <Code>{`# Verify PostgreSQL is accepting connections
docker compose exec postgres pg_isready

# Check connection pool stats
docker compose logs keycore 2>&1 | grep "pool"

# If using PgBouncer, verify it's running
docker compose --profile connection_pooling ps pgbouncer`}</Code>

    <H2>FIPS Mode Issues</H2>
    <P>If switching to Strict mode fails, check for non-FIPS keys (e.g., ChaCha20, ED25519 without FIPS approval). Disable or destroy non-compliant keys before enabling Strict mode.</P>

    <H2>HSM Connection Issues</H2>
    <P>Verify HSM library path exists, slot/partition is accessible, PIN is correct. For network HSMs, verify the HSM network interface is configured and the firewall allows HSM ports (2300, 2310).</P>

    <H2>Cluster Sync Lag</H2>
    <P>Check cluster sync events in the Sync Monitor tab. Verify NATS is running (if event_streaming profile is enabled). Check network connectivity between nodes on the cluster interface. Verify CLUSTER_SYNC_SHARED_SECRET matches on all nodes.</P>

    <H2>Performance Issues</H2>
    <Code>{`# Enable PgBouncer for connection pooling
docker compose --profile connection_pooling up -d pgbouncer

# Enable Redis for caching
docker compose --profile distributed_cache up -d valkey

# Scale keycore replicas
KEYCORE_REPLICAS=3 docker compose up -d keycore

# Monitor resource usage
docker stats`}</Code>

    <H2>Log Locations</H2>
    <P>All service logs are available via <IC>docker compose logs [service]</IC>. Audit logs are persisted in PostgreSQL and available via the Audit tab or API. Cluster logs are in the Cluster Logs sub-pane.</P>
  </div>
);

const SectionConfigFastInstall = () => (
  <div>
    <div style={S.h1}>Config: Fast Installation Mode</div>
    <P>Fast install mode provides a streamlined script-driven deployment path that gets the baseline KMS running with minimal prompts. Additional modules can be enabled later by editing <IC>infra/deployment/deployment.yaml</IC> and rerunning the installer or the runtime start script.</P>

    <H2>Usage</H2>
    <Code>{`# Fast install with defaults
./install.sh --fast

# Fast install with explicit IPs
./install.sh --fast --mgmt-ip=10.0.1.100 --cluster-ip=10.0.1.101 --bind-ip=0.0.0.0

# Standard interactive install (default)
./install.sh`}</Code>

    <H2>What Gets Deployed</H2>
    <P>In fast mode, the installer writes a deployment file from the built-in baseline template and starts that service set directly. The baseline includes the core platform services plus certificate management, while other optional modules remain off until the deployment file is changed.</P>

    <H2>Changing Features Later</H2>
    <P>Feature enablement remains file-driven. Edit <IC>infra/deployment/deployment.yaml</IC>, then rerun <IC>./install.sh --fast</IC> or start the stack with <IC>./infra/scripts/start-kms.sh</IC> so Docker Compose recalculates the active profiles.</P>

    <Collapse title="deployment.yaml metadata">
      <Code>{`apiVersion: kms.vecta.com/v1
kind: DeploymentConfig
metadata:
  install_mode: fast    # "fast" or "interactive"
spec:
  hsm_mode: auto
  features:
    secrets: false
    certs: false
    # ... all features default to false in fast mode`}</Code>
    </Collapse>

  </div>
);

const SectionApiFde = () => (
  <div>
    <div style={S.h1}>API: Disk Encryption (FDE)</div>
    <P>Service: kms-governance | Prefix: /governance/system/fde</P>
    <P>Full-disk encryption management endpoints for monitoring LUKS volume status, running integrity checks, rotating volume keys, and testing Shamir recovery shares. All endpoints require system admin privileges.</P>

    <Collapse title="FDE Endpoints" defaultOpen>
      <EndpointTable rows={[
        ["GET", "/governance/system/fde/status", "Get FDE status (algorithm, LUKS version, key slots, storage usage)"],
        ["POST", "/governance/system/fde/integrity-check", "Run LUKS integrity verification on encrypted volume"],
        ["POST", "/governance/system/fde/rotate-key", "Initiate online LUKS volume key rotation"],
        ["POST", "/governance/system/fde/test-recovery", "Validate Shamir recovery shares without unlocking"],
        ["GET", "/governance/system/fde/recovery-shares", "Get recovery share distribution and verification status"],
      ]} />
    </Collapse>

    <Collapse title="FDE Status Response">
      <Code>{`GET /svc/governance/governance/system/fde/status?tenant_id=root

{
  "enabled": true,
  "algorithm": "aes-xts-plain64",
  "luks_version": "2",
  "key_derivation": "argon2id",
  "device": "/dev/sda2",
  "unlock_method": "passphrase",
  "recovery_shares": 5,
  "recovery_threshold": 3,
  "key_slots": [
    { "slot": 0, "status": "active", "type": "passphrase" },
    { "slot": 1, "status": "active", "type": "recovery" }
  ],
  "volume_size_gb": 500,
  "used_gb": 120,
  "integrity_last_check": "2026-03-04T08:00:00Z",
  "integrity_status": "passed"
}`}</Code>
    </Collapse>

    <Collapse title="Integrity Check">
      <Code>{`POST /svc/governance/governance/system/fde/integrity-check
{ "tenant_id": "root" }

Response:
{
  "passed": true,
  "mode": "dm-integrity",
  "checked_at": "2026-03-05T10:30:00Z",
  "errors": []
}`}</Code>
      <P>Runs a non-destructive integrity verification using dm-integrity. Safe to run on a live system.</P>
    </Collapse>

    <Collapse title="Volume Key Rotation">
      <Code>{`POST /svc/governance/governance/system/fde/rotate-key
{
  "tenant_id": "root",
  "confirm": true,
  "reason": "scheduled-rotation"
}

Response:
{
  "status": "rotating",
  "job_id": "fde-rot-001",
  "started_at": "2026-03-05T10:35:00Z",
  "estimated_duration_minutes": 15
}`}</Code>
      <P>Online volume key rotation using LUKS2 reencryption. The volume remains accessible during rotation. Estimated duration depends on volume size.</P>
    </Collapse>

    <Collapse title="Recovery Share Testing">
      <Code>{`POST /svc/governance/governance/system/fde/test-recovery
{
  "tenant_id": "root",
  "shares": ["share-hex-1...", "share-hex-2...", "share-hex-3..."]
}

Response:
{
  "valid": true,
  "shares_provided": 3,
  "threshold_required": 3,
  "tested_at": "2026-03-05T10:40:00Z"
}`}</Code>
      <P>Validates that the provided Shamir shares can reconstruct the recovery key. Does not actually unlock or modify the volume. Use this to verify your disaster recovery procedure.</P>
    </Collapse>
  </div>
);

/* ───────── Crypto Inventory Guide ───────── */
const SectionGuideCryptoInventory = () => (
  <div>
    <div style={S.h1}>Cryptographic Inventory (KeyInsight)</div>
    <P>The Crypto Inventory feature provides Fortanix KeyInsight-style visibility into all cryptographic assets across your organization. Access it via Compliance → Crypto Inventory tab.</P>
    <H2>Inventory Score</H2>
    <P>A composite score (0-100) calculated from risk findings across keys and certificates. Critical findings reduce the score by 15 points per affected asset, high by 8, and warnings by 3. Target: 80+ for healthy posture.</P>
    <H2>Risk Detection Rules</H2>
    <table style={S.table}>
      <thead><tr><th style={S.th}>Finding</th><th style={S.th}>Severity</th><th style={S.th}>Applies To</th></tr></thead>
      <tbody>
        {[
          ["Weak algorithm (RSA-1024, DES, 3DES, RC4)", "Critical", "Keys"],
          ["Key status compromised/destroyed", "Critical", "Keys"],
          ["Certificate expired", "Critical", "Certificates"],
          ["Weak signing (SHA-1, MD5)", "Critical", "Certificates"],
          ["Key older than 1 year without rotation", "High", "Keys"],
          ["Certificate expiring within 30 days", "High", "Certificates"],
          ["Certificate expiring within 90 days", "Warning", "Certificates"],
          ["Key is exportable without HSM protection", "Warning", "Keys"],
        ].map(([finding, sev, type], i) => (
          <tr key={i}><td style={{...S.td, fontFamily: "inherit"}}>{finding}</td><td style={S.td}>{sev}</td><td style={S.td}>{type}</td></tr>
        ))}
      </tbody>
    </table>
    <H2>PQC Readiness</H2>
    <P>Keys are classified into three categories: PQC Native (ML-KEM, ML-DSA, SLH-DSA, Kyber, Dilithium), Hybrid (combined classical + PQC), and Classical (AES, RSA, ECDSA). The donut chart shows your quantum readiness breakdown.</P>
    <H2>Charts</H2>
    <P>Algorithm Distribution (horizontal bar), Key Age Distribution (vertical bar), PQC Readiness (donut), Certificate Expiry Timeline (stacked bar with color coding: red=expired, amber=within 30d, green=safe).</P>
  </div>
);

/* ───────── Vault Hierarchy Guide ───────── */
const SectionGuideVaultHierarchy = () => (
  <div>
    <div style={S.h1}>Vault Hierarchy & OpenBao Compatibility</div>
    <P>The Secret Vault supports path-based folder hierarchy for organizing secrets by department, project, or environment. This is compatible with HashiCorp Vault and OpenBao path-based access policies.</P>
    <H2>Path Structure</H2>
    <Code>{`/ (root)
├── engineering/
│   ├── api-keys/
│   │   ├── stripe-prod-key
│   │   └── sendgrid-key
│   └── database/
│       ├── prod-postgres-creds
│       └── staging-redis-password
├── finance/
│   └── payment-gateway-secret
├── devops/
│   ├── ci-cd-tokens/
│   └── infrastructure/
│       ├── aws-access-keys
│       └── gcp-service-account
└── shared/
    └── tls-certificates/`}</Code>
    <H2>Path Derivation</H2>
    <P>Secrets are assigned to paths via their <IC>labels.path</IC> or <IC>metadata.folder</IC> field. Secrets with slash-delimited names (e.g., <IC>engineering/api-keys/stripe</IC>) are automatically organized into the corresponding folder. Create folders from the UI to navigate and store secrets in specific paths.</P>
    <H2>OpenBao API Compatibility</H2>
    <EndpointTable rows={[
      ["GET", "/v1/secret/data/{path}", "Read secret at path (KV v2)"],
      ["POST", "/v1/secret/data/{path}", "Create/update secret at path"],
      ["GET", "/v1/secret/metadata/{path}", "Read secret metadata and versions"],
      ["POST", "/v1/secret/delete/{path}", "Soft delete secret versions"],
      ["POST", "/v1/secret/undelete/{path}", "Restore soft-deleted versions"],
      ["GET", "/v1/secret/metadata/?list=true", "List secrets and folders at path"],
      ["GET", "/v1/sys/mounts/secret", "Mount configuration for secret engine"],
    ]} />
    <H2>Event Hooks</H2>
    <P>OpenBao-compatible event hooks fire on secret lifecycle events. Configure webhook endpoints in Administration → Event Hooks to receive notifications.</P>
    <table style={S.table}>
      <thead><tr><th style={S.th}>Hook</th><th style={S.th}>Trigger</th></tr></thead>
      <tbody>
        {[
          ["secret.created", "New secret stored at any path"],
          ["secret.updated", "Secret value modified"],
          ["secret.rotated", "Version rotation completed"],
          ["secret.deleted", "Soft or hard delete"],
          ["secret.accessed", "Secret value read (for audit)"],
          ["secret.expired", "TTL/lease expired — cleanup trigger"],
          ["folder.policy_changed", "Path ACL policy modified"],
        ].map(([hook, trigger], i) => (
          <tr key={i}><td style={S.td}>{hook}</td><td style={{...S.td, fontFamily: "inherit"}}>{trigger}</td></tr>
        ))}
      </tbody>
    </table>
    <H2>Path-Based ACL Policies</H2>
    <Code>{`# Example: engineering team can read/write their path
path "secret/data/engineering/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Finance team: read-only access to shared secrets
path "secret/data/shared/*" {
  capabilities = ["read", "list"]
}

# Deny access to other departments
path "secret/data/finance/*" {
  capabilities = ["deny"]
}`}</Code>
  </div>
);

/* ───────── HSM Certificate Storage Guide ───────── */
const SectionGuideHsmCerts = () => (
  <div>
    <div style={S.h1}>HSM Certificate Storage</div>
    <P>Certificates and their private keys can be stored inside the HSM, ensuring private key material never leaves the hardware boundary. The KMS holds metadata references while the HSM performs all signing operations.</P>
    <H2>HSM-Backed Certificate Authority</H2>
    <P>When creating a CA, set <IC>key_backend: "hsm"</IC> and provide the <IC>key_ref</IC> pointing to a key already generated inside the HSM. All signing operations are performed via PKCS#11.</P>
    <Code>{`POST /svc/certs/cas
{
  "name": "Production Root CA",
  "algorithm": "ECDSA-P384",
  "key_backend": "hsm",
  "key_ref": "hsm-key-id-001",
  "subject": "CN=Production Root CA,O=Acme Corp",
  "ca_level": "root",
  "validity_years": 10
}`}</Code>
    <H2>Key Export Conditions</H2>
    <P>An HSM key can only be exported when ALL of the following conditions are met:</P>
    <table style={S.table}>
      <thead><tr><th style={S.th}>Condition</th><th style={S.th}>Field</th><th style={S.th}>Where</th></tr></thead>
      <tbody>
        {[
          ["KMS export policy allows it", "export_allowed = true", "Key policy"],
          ["HSM extractable attribute set", "CKA_EXTRACTABLE = true", "HSM key generation"],
          ["HSM non-exportable label not set", 'hsm_non_exportable != "true"', "Key labels"],
          ["Wrapping key available for secure transport", "wrapping_key_id required", "Export request"],
          ["Quorum approvals granted (if policy attached)", "M-of-N approvals", "Governance workflow"],
        ].map(([cond, field, where], i) => (
          <tr key={i}><td style={{...S.td, fontFamily: "inherit"}}>{cond}</td><td style={S.td}>{field}</td><td style={{...S.td, fontFamily: "inherit"}}>{where}</td></tr>
        ))}
      </tbody>
    </table>
    <H2>Cluster Sync Behavior</H2>
    <Code>{`// Non-exportable keys:
key_material_sync = "metadata_only"
// → Only key ID, algorithm, status, and HSM references are synced

// Exportable keys:
key_material_sync = "wrapped_blob_allowed"
// → Wrapped key material can be replicated across cluster nodes`}</Code>
    <H2>Certificate Object Storage on HSM</H2>
    <P>Beyond private keys, the full X.509 certificate can be stored as a PKCS#11 <IC>CKO_CERTIFICATE</IC> object on the HSM. This enables the HSM to serve as the complete trust store.</P>
    <Code>{`// PKCS#11 certificate object attributes:
CKA_CLASS           = CKO_CERTIFICATE
CKA_CERTIFICATE_TYPE = CKC_X_509
CKA_SUBJECT         = <DER-encoded subject>
CKA_VALUE           = <DER-encoded certificate>
CKA_TRUSTED         = CK_TRUE    // for CA certificates
CKA_CERTIFICATE_CATEGORY = 2     // CA certificate
CKA_ID              = <matching key ID for association>`}</Code>
  </div>
);

/* ───────── SECTION MAP ───────── */
const SectionApiOpenAPI = () => {
  const [selected, setSelected] = useState<"ai" | "sbom" | "posture" | "compliance" | "reporting">("ai");
  const current = {
    ai: {
      title: "AI Service",
      description: "AI configuration, provider authentication, MCP compatibility, and assistant workflows.",
      viewer: "/openapi/ai.html",
      yaml: "/openapi/ai.openapi.yaml",
      json: "/openapi/ai.openapi.json",
    },
    sbom: {
      title: "SBOM / CBOM Service",
      description: "SBOM generation, OSV and Trivy correlation, manual offline advisories, exports, and CBOM PQC readiness.",
      viewer: "/openapi/sbom.html",
      yaml: "/openapi/sbom.openapi.yaml",
      json: "/openapi/sbom.openapi.json",
    },
    posture: {
      title: "Security Posture Service",
      description: "Posture dashboard, risk drivers, remediation cockpit, blast radius, scenario simulation, and action execution.",
      viewer: "/openapi/posture.html",
      yaml: "/openapi/posture.openapi.yaml",
      json: "/openapi/posture.openapi.json",
    },
    compliance: {
      title: "Compliance Service",
      description: "Compliance posture, assessment runs/history, delta views, and template-backed scoring workflows.",
      viewer: "/openapi/compliance.html",
      yaml: "/openapi/compliance.openapi.yaml",
      json: "/openapi/compliance.openapi.json",
    },
    reporting: {
      title: "Reporting Service",
      description: "Evidence-pack generation, report jobs, alert timing analytics, MTTD, and MTTR workflows.",
      viewer: "/openapi/reporting.html",
      yaml: "/openapi/reporting.openapi.yaml",
      json: "/openapi/reporting.openapi.json",
    },
  }[selected];

  return (
    <div>
      <div style={S.h1}>OpenAPI / Swagger Specs</div>
      <P>Generated OpenAPI 3.0.3 contracts are published directly from the dashboard under <IC>/openapi</IC>. The embedded viewer below uses a local Swagger UI bundle, so it works without external CDN dependencies.</P>
      <H2>Available Specs</H2>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 10, marginBottom: 14 }}>
        {[
          { id: "ai", label: "AI Service", detail: "Provider config, auth modes, MCP, assistant actions" },
          { id: "sbom", label: "SBOM / CBOM", detail: "Vulnerability findings, offline advisories, CBOM readiness" },
          { id: "posture", label: "Security Posture", detail: "Risk drivers, cockpit groups, blast radius, scenarios" },
          { id: "compliance", label: "Compliance", detail: "Assessments, delta view, templates, posture history" },
          { id: "reporting", label: "Reporting", detail: "Evidence packs, report jobs, MTTD / MTTR statistics" },
        ].map((item) => {
          const active = selected === item.id;
          return (
            <Card
              key={item.id}
              onClick={() => setSelected(item.id as "ai" | "sbom" | "posture" | "compliance" | "reporting")}
              style={{
                padding: 12,
                cursor: "pointer",
                border: `1px solid ${active ? C.accent : C.border}`,
                background: active ? C.accentDim : C.card,
              }}
            >
              <div style={{ fontSize: 12, fontWeight: 700, color: active ? C.accent : C.text, marginBottom: 4 }}>{item.label}</div>
              <div style={{ fontSize: 10, color: C.dim, lineHeight: 1.5 }}>{item.detail}</div>
            </Card>
          );
        })}
      </div>

      <H2>{current.title}</H2>
      <P>{current.description}</P>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
        {[
          ["Open Full Viewer", current.viewer],
          ["Download YAML", current.yaml],
          ["Download JSON", current.json],
        ].map(([label, href]) => (
          <a
            key={label}
            href={href}
            target="_blank"
            rel="noreferrer"
            style={{
              fontSize: 10,
              fontWeight: 600,
              color: C.accent,
              textDecoration: "none",
              border: `1px solid ${C.border}`,
              background: C.card,
              borderRadius: 8,
              padding: "8px 10px",
            }}
          >
            {label}
          </a>
        ))}
      </div>

      <Code>{`# Regenerate and validate OpenAPI artifacts
npm.cmd --prefix web/dashboard run generate:openapi
npm.cmd --prefix web/dashboard run validate:openapi`}</Code>

      <div style={{ border: `1px solid ${C.border}`, borderRadius: 14, overflow: "hidden", background: C.card }}>
        <iframe
          key={current.viewer}
          title={`${current.title} Swagger Viewer`}
          src={current.viewer}
          style={{ width: "100%", height: "78vh", border: 0, background: C.bg }}
        />
      </div>
    </div>
  );
};

const SECTIONS: Record<string, () => JSX.Element> = {
  overview: SectionOverview,
  deploy: SectionDeploy,
  credentials: SectionCredentials,
  architecture: SectionArchitecture,
  services: SectionServiceRef,
  "api-auth": SectionApiAuth,
  "api-keycore": SectionApiKeycore,
  "api-secrets": SectionApiSecrets,
  "api-certs": SectionApiCerts,
  "api-audit": SectionApiAudit,
  "api-policy": SectionApiPolicy,
  "api-governance": SectionApiGovernance,
  "api-dataprotect": SectionApiDataprotect,
  "api-payment": SectionApiPayment,
  "api-cloud": SectionApiCloud,
  "api-hyok": SectionApiHyok,
  "api-ekm": SectionApiEkm,
  "api-ekm-bitlocker": SectionApiEkmBitlocker,
  "api-ekm-sdk": SectionApiEkmSdk,
  "guide-agent-deploy": SectionGuideAgentDeploy,
  "guide-key-cache": SectionGuideKeyCache,
  "api-mpc": SectionApiMpc,
  "api-qkd": SectionApiQkd,
  "api-compliance": SectionApiCompliance,
  "api-sbom": SectionApiSbom,
  "api-posture": SectionApiPosture,
  "api-reporting": SectionApiReporting,
  "api-cluster": SectionApiCluster,
  "api-pqc": SectionApiPqc,
  "api-discovery": SectionApiDiscovery,
  "api-ai": SectionApiAi,
  "api-openapi": SectionApiOpenAPI,
  "ui-guide": SectionUIDashboard,
  "ui-keys": SectionUIKeys,
  "ui-workbench": SectionUIWorkbench,
  "ui-vault": SectionUIVault,
  "ui-certs": SectionUICerts,
  "ui-dataprotect": SectionUIDataprotect,
  "ui-cloud": SectionUICloud,
  "ui-ekm": SectionUIEkm,
  "ui-hsm": SectionUIHsm,
  "ui-advanced": SectionUIAdvanced,
  "ui-governance": SectionUIGovernance,
  "ui-monitoring": SectionUIMonitoring,
  "ui-cluster": SectionUICluster,
  "ui-admin": SectionUIAdmin,
  "config-env": SectionConfigEnv,
  "config-fips": SectionConfigFips,
  "config-hsm": SectionConfigHsm,
  "config-network": SectionConfigNetwork,
  "config-cluster": SectionConfigCluster,
  "config-backup": SectionConfigBackup,
  "config-profiles": SectionConfigProfiles,
  "config-fastinstall": SectionConfigFastInstall,
  "api-fde": SectionApiFde,
  "guide-crypto-inventory": SectionGuideCryptoInventory,
  "guide-vault-hierarchy": SectionGuideVaultHierarchy,
  "guide-hsm-certs": SectionGuideHsmCerts,
  troubleshooting: SectionTroubleshooting,
};

/* ───────── MAIN COMPONENT ───────── */
export const DocsTab = () => {
  const [active, setActive] = useState("overview");
  const [search, setSearch] = useState("");

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return NAV;
    return NAV.filter((n) => n.label.toLowerCase().includes(q));
  }, [search]);

  const Renderer = SECTIONS[active] || SectionOverview;

  return (
    <div style={S.wrap}>
      {/* Sidebar nav */}
      <div style={S.nav}>
        <div style={{ padding: "0 10px 8px" }}>
          <Inp placeholder="Search docs..." value={search} onChange={(e) => setSearch(e.target.value)} style={{ fontSize: 10 }} />
        </div>
        {/* Group labels */}
        {[
          { label: "Getting Started", ids: ["overview", "deploy", "credentials", "architecture", "services"] },
          { label: "REST API Reference", ids: NAV.filter((n) => n.id.startsWith("api-")).map((n) => n.id) },
          { label: "UI Guide", ids: NAV.filter((n) => n.id.startsWith("ui-")).map((n) => n.id) },
          { label: "Configuration", ids: NAV.filter((n) => n.id.startsWith("config-")).map((n) => n.id) },
          { label: "Operations", ids: ["troubleshooting"] },
        ].map((group) => {
          const items = filtered.filter((n) => group.ids.includes(n.id));
          if (!items.length) return null;
          return (
            <div key={group.label}>
              <div style={{ fontSize: 9, fontWeight: 700, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, padding: "10px 14px 4px" }}>{group.label}</div>
              {items.map((n) => (
                <div
                  key={n.id}
                  onClick={() => setActive(n.id)}
                  style={{
                    ...S.navItem,
                    color: active === n.id ? C.accent : C.dim,
                    borderLeftColor: active === n.id ? C.accent : "transparent",
                    background: active === n.id ? C.accentDim : "transparent",
                  }}
                >
                  {n.label}
                </div>
              ))}
            </div>
          );
        })}
      </div>

      {/* Content area */}
      <div style={S.content}>
        <Renderer />
        <div style={{ height: 40 }} />
        <div style={{ fontSize: 9, color: C.muted, borderTop: `1px solid ${C.border}`, paddingTop: 10 }}>
          Vecta KMS Documentation — Generated from platform source. For support, contact your system administrator.
        </div>
      </div>
    </div>
  );
};
