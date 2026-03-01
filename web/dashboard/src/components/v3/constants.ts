export const DOC_COMPONENTS = [
  { name: "kms-auth", group: "Core", purpose: "Authentication, tenant RBAC, token lifecycle.", customer: "Controls who can access keys, APIs, and admin workflows." },
  { name: "kms-keycore", group: "Core", purpose: "Key lifecycle engine: create, rotate, retire, policy binding.", customer: "Primary key management service for customer workloads." },
  { name: "kms-policy", group: "Core", purpose: "Policy decision point for permissions and controls.", customer: "Enforces governance and approved usage patterns." },
  { name: "kms-audit", group: "Core", purpose: "Immutable operational audit trail.", customer: "Supports investigations and compliance evidence." },
  { name: "kms-secrets", group: "Security", purpose: "Secret storage and retrieval APIs.", customer: "Protects application credentials and sensitive secrets." },
  { name: "kms-certs", group: "Security", purpose: "Certificate issuance and PKI-related operations.", customer: "Manages TLS and certificate lifecycle for trust." },
  { name: "kms-dataprotect", group: "Data Protection", purpose: "Tokenization, masking, and field protection.", customer: "Protects regulated/sensitive business data." },
  { name: "kms-payment", group: "Data Protection", purpose: "Payment cryptography operations.", customer: "Secures card/payment data flows and operations." },
  { name: "kms-cloud", group: "Cloud", purpose: "Cloud BYOK and external KMS integrations.", customer: "Lets customers control keys across cloud providers." },
  { name: "kms-hyok-proxy", group: "Cloud", purpose: "Hold-your-own-key proxy integration path.", customer: "Keeps key ownership boundary with the customer." },
  { name: "kms-ekm", group: "Cloud", purpose: "External key manager bridge service.", customer: "Connects external consumers to managed key services." },
  { name: "kms-governance", group: "Governance", purpose: "Approval workflows and governance controls.", customer: "Implements multi-party approval and segregation of duties." },
  { name: "kms-compliance", group: "Governance", purpose: "Compliance posture and control reporting.", customer: "Provides compliance visibility and gap tracking." },
  { name: "kms-reporting", group: "Governance", purpose: "Operational and security reporting.", customer: "Exposes metrics and reports for business/security teams." },
  { name: "kms-qkd", group: "Advanced", purpose: "Quantum key distribution interface integration.", customer: "Supports advanced future-proof key exchange scenarios." },
  { name: "kms-pqc", group: "Advanced", purpose: "Post-quantum cryptography operations.", customer: "Enables migration paths to PQC algorithms." },
  { name: "kms-kmip", group: "Advanced", purpose: "KMIP interoperability service.", customer: "Integrates external KMIP clients and appliances." },
  { name: "kms-software-vault", group: "HSM", purpose: "Software-backed cryptographic key vault.", customer: "Provides protected key operations without external HSM hardware." },
  { name: "kms-mpc", group: "Advanced", purpose: "Multi-party computation service.", customer: "Supports distributed cryptographic trust models." },
  { name: "kms-sbom", group: "Supply Chain", purpose: "Software/crypto bill of materials outputs.", customer: "Supports supply chain transparency and audit needs." },
  { name: "PostgreSQL", group: "Infrastructure", purpose: "Primary persistent database.", customer: "Stores system state, metadata, and policy data." },
  { name: "Valkey", group: "Infrastructure", purpose: "Low-latency cache/session data.", customer: "Improves performance and short-lived state handling." },
  { name: "NATS JetStream", group: "Infrastructure", purpose: "Event bus and durable streams.", customer: "Carries internal service events and async workflows." },
  { name: "consul", group: "Infrastructure", purpose: "Service discovery and health registry.", customer: "Lets platform components find and validate each other." },
  { name: "etcd", group: "Infrastructure", purpose: "Consensus/coordination backend (cluster profile).", customer: "Supports distributed coordination when clustering is enabled." },
  { name: "envoy", group: "Edge", purpose: "Ingress/egress edge proxy.", customer: "Front-door traffic security, routing, and TLS termination." },
  { name: "dashboard", group: "UI", purpose: "Web management interface.", customer: "Operational UI for administrators and operators." }
];

export const DOC_CAPABILITIES = [
  { name: "First-Boot Wizard", domain: "Provisioning", summary: "Guided bootstrap for FDE, FIPS mode, network, feature enablement, HSM mode, and license activation.", customer: "Provides secure and consistent Day-0 setup." },
  { name: "Selective Feature Enablement", domain: "Platform", summary: "Enable or disable KMS modules based on approved deployment profile.", customer: "Reduces attack surface and simplifies operations." },
  { name: "FDE (LUKS2) Boot Protection", domain: "Security", summary: "Full-disk encryption controls with recovery workflow support.", customer: "Protects data at rest on appliance nodes." },
  { name: "FIPS Operating Mode", domain: "Compliance", summary: "Runtime cryptographic boundary and approved-mode behavior.", customer: "Supports regulated workloads and certification objectives." },
  { name: "Key Lifecycle Management", domain: "Core Crypto", summary: "Create, rotate, disable, retire, and recover keys with policy controls.", customer: "Maintains key hygiene and crypto governance." },
  { name: "Cryptographic Operations", domain: "Core Crypto", summary: "Encrypt, decrypt, sign, verify, MAC, and random generation operations.", customer: "Delivers secure cryptographic primitives for applications." },
  { name: "Secret Vault", domain: "Secrets", summary: "Centralized secret storage with scoped access controls.", customer: "Protects service credentials and application secrets." },
  { name: "Certificate and PKI Services", domain: "PKI", summary: "Certificate issuance, renewal, and trust chain operations.", customer: "Supports TLS, mTLS, and machine identity workflows." },
  { name: "Tokenization and Masking", domain: "Data Protection", summary: "Data de-identification using tokenization, masking, and redaction controls.", customer: "Lowers exposure of regulated data fields." },
  { name: "Payment Cryptography", domain: "Payments", summary: "Payment-key and cryptographic workflows aligned to card environments.", customer: "Supports secure payment processing integrations." },
  { name: "BYOK and HYOK Integration", domain: "Cloud", summary: "Bring-your-own-key and hold-your-own-key integration patterns.", customer: "Preserves enterprise control of key ownership." },
  { name: "External KMS / EKM Interop", domain: "Integration", summary: "Connectors for external key consumers and provider-managed workflows.", customer: "Extends KMS controls across external platforms." },
  { name: "KMIP 2.1 Service", domain: "Integration", summary: "Standards-based KMIP endpoint for client/application interoperability.", customer: "Simplifies migration from legacy key managers." },
  { name: "HSM Mode", domain: "Hardware Security", summary: "Hardware-backed cryptographic boundary and key operation offload.", customer: "Raises assurance for high-trust environments." },
  { name: "Approvals and Governance", domain: "Governance", summary: "Multi-step authorization and role-based approval flows.", customer: "Enforces separation of duties and controlled change." },
  { name: "Audit Logging", domain: "Governance", summary: "Tamper-evident audit capture for security and operations activity.", customer: "Supports investigation and compliance evidence." },
  { name: "Compliance and Reporting", domain: "Governance", summary: "Control-mapped reporting and posture visibility.", customer: "Tracks adherence to internal and external requirements." },
  { name: "SBOM / CBOM Visibility", domain: "Supply Chain", summary: "Software and cryptographic bill-of-materials output for transparency.", customer: "Strengthens supply-chain risk management." },
  { name: "Cluster and Service Discovery", domain: "Infrastructure", summary: "Multi-service coordination, health discovery, and internal routing.", customer: "Improves resilience and horizontal scalability." },
  { name: "Backup and Restore", domain: "Operations", summary: "Scheduled backup, encrypted backup sets, and restore procedures.", customer: "Protects against accidental loss and disaster events." },
  { name: "OVA Packaging Pipeline", domain: "Delivery", summary: "Repeatable virtual appliance image build and packaging process.", customer: "Accelerates deployment in virtualized enterprise environments." }
];

export const KEY_TABLE_COLUMNS = [
  { id: "name", label: "Name" },
  { id: "algorithm", label: "Algorithm" },
  { id: "sizeCurve", label: "Size / Curve" },
  { id: "status", label: "Status" },
  { id: "destroyAt", label: "Destroy At" },
  { id: "fips", label: "FIPS" },
  { id: "kcv", label: "KCV" },
  { id: "version", label: "Version" },
  { id: "operations", label: "Operations" },
  { id: "tags", label: "Tags" },
  { id: "actions", label: "Actions" }
];

export const DEFAULT_KEY_COLUMN_VISIBILITY = {
  name: true,
  algorithm: true,
  sizeCurve: true,
  status: true,
  destroyAt: true,
  fips: true,
  kcv: true,
  version: true,
  operations: true,
  tags: true,
  actions: true
};

export const KEY_ACCESS_OPERATION_OPTIONS = [
  { id: "encrypt", label: "Encrypt" },
  { id: "decrypt", label: "Decrypt" },
  { id: "wrap", label: "Wrap" },
  { id: "unwrap", label: "Unwrap" },
  { id: "sign", label: "Sign" },
  { id: "verify", label: "Verify" },
  { id: "mac", label: "MAC" },
  { id: "derive", label: "Derive" },
  { id: "kem-encapsulate", label: "KEM Encap" },
  { id: "kem-decapsulate", label: "KEM Decap" },
  { id: "export", label: "Export" }
];

export const DATA_ENCRYPTION_INTERFACE_OPTIONS = ["rest", "pkcs11", "jca", "ekm", "kmip", "hyok", "byok"];
