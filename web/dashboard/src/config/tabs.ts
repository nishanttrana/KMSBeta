import type { LucideIcon } from "lucide-react";
import {
  Activity,
  BellRing,
  Blocks,
  Building2,
  Cloud,
  Cpu,
  Database,
  FileCheck2,
  FileLock2,
  Fingerprint,
  GlobeLock,
  KeyRound,
  Landmark,
  Layers3,
  Library,
  Lock,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
  Wallet,
  Waypoints,
  Workflow,
  Atom
} from "lucide-react";

export type FeatureKey =
  | "secrets"
  | "certs"
  | "governance"
  | "cloud_byok"
  | "hyok_proxy"
  | "kmip_server"
  | "qkd_interface"
  | "ekm_database"
  | "payment_crypto"
  | "autokey_provisioning"
  | "workload_identity"
  | "confidential_compute"
  | "compliance_dashboard"
  | "sbom_cbom"
  | "reporting_alerting"
  | "ai_llm"
  | "pqc_migration"
  | "crypto_discovery"
  | "mpc_engine"
  | "data_protection"
  | "clustering"
  | "hsm_hardware"
  | "hsm_software"
  | "qrng_generator";

export type TabId =
  | "dashboard"
  | "keys"
  | "crypto_console"
  | "vault"
  | "certificates"
  | "tokenize_mask"
  | "payment"
  | "autokey"
  | "pqc"
  | "byok"
  | "hyok"
  | "ekm"
  | "kmip"
  | "hsm_primus"
  | "qkd"
  | "qrng"
  | "mpc"
  | "cluster"
  | "approvals"
  | "alert_center"
  | "audit_log"
  | "compliance"
  | "sbom_cbom"
  | "pkcs11_jca"
  | "administration";

export type GroupId =
  | "core"
  | "secrets_certs"
  | "data_protection"
  | "cloud_integration"
  | "infrastructure"
  | "governance_compliance"
  | "admin";

export type TabConfig = {
  id: TabId;
  label: string;
  shortLabel: string;
  group: GroupId;
  description: string;
  icon: LucideIcon;
  emoji: string;
  requiredAnyFeatures?: FeatureKey[];
};

export const groupLabels: Record<GroupId, string> = {
  core: "CORE",
  secrets_certs: "SECRETS & CERTS",
  data_protection: "DATA PROTECTION",
  cloud_integration: "CLOUD & INTEGRATION",
  infrastructure: "INFRASTRUCTURE",
  governance_compliance: "GOVERNANCE",
  admin: "ADMIN"
};

export const tabConfig: TabConfig[] = [
  {
    id: "dashboard",
    label: "Dashboard",
    shortLabel: "Dashboard",
    group: "core",
    description: "Operational and compliance posture overview",
    icon: Activity,
    emoji: "D"
  },
  {
    id: "keys",
    label: "Keys",
    shortLabel: "Keys",
    group: "core",
    description: "Key inventory and lifecycle management",
    icon: KeyRound,
    emoji: "K"
  },
  {
    id: "crypto_console",
    label: "Crypto Console",
    shortLabel: "Console",
    group: "core",
    description: "Ad-hoc cryptographic operation simulator",
    icon: SlidersHorizontal,
    emoji: "C"
  },
  {
    id: "audit_log",
    label: "Audit Log",
    shortLabel: "Audit",
    group: "core",
    description: "Real-time and historical audit streams",
    icon: FileLock2,
    emoji: "L"
  },
  {
    id: "vault",
    label: "Vault",
    shortLabel: "Vault",
    group: "secrets_certs",
    description: "Universal secret store",
    icon: Lock,
    emoji: "V",
    requiredAnyFeatures: ["secrets"]
  },
  {
    id: "certificates",
    label: "Certificates",
    shortLabel: "Certificates",
    group: "secrets_certs",
    description: "Internal mini PKI and protocol operations",
    icon: FileCheck2,
    emoji: "C",
    requiredAnyFeatures: ["certs"]
  },
  {
    id: "tokenize_mask",
    label: "Tokenize/Mask",
    shortLabel: "Tokenize/Mask",
    group: "data_protection",
    description: "Tokenization, masking, and field-level encryption",
    icon: Shield,
    emoji: "T",
    requiredAnyFeatures: ["data_protection"]
  },
  {
    id: "payment",
    label: "Payment",
    shortLabel: "Payment",
    group: "data_protection",
    description: "TR-31, PIN blocks, and ISO 20022 signing",
    icon: Wallet,
    emoji: "P",
    requiredAnyFeatures: ["payment_crypto"]
  },
  {
    id: "autokey",
    label: "Autokey",
    shortLabel: "Autokey",
    group: "data_protection",
    description: "Policy-driven key handle provisioning and approval workflows",
    icon: Layers3,
    emoji: "A",
    requiredAnyFeatures: ["autokey_provisioning"]
  },
  {
    id: "pqc",
    label: "Post-Quantum Crypto",
    shortLabel: "PQC",
    group: "data_protection",
    description: "ML-KEM, ML-DSA, SLH-DSA policy, readiness, and migration",
    icon: Atom,
    emoji: "Q",
    requiredAnyFeatures: ["pqc_migration"]
  },
  {
    id: "pkcs11_jca",
    label: "PKCS#11/JCA",
    shortLabel: "PKCS#11/JCA",
    group: "data_protection",
    description: "Client SDK and mechanism telemetry",
    icon: Fingerprint,
    emoji: "P"
  },
  {
    id: "byok",
    label: "BYOK",
    shortLabel: "BYOK",
    group: "cloud_integration",
    description: "Cloud external key management",
    icon: Cloud,
    emoji: "B",
    requiredAnyFeatures: ["cloud_byok"]
  },
  {
    id: "hyok",
    label: "HYOK",
    shortLabel: "HYOK",
    group: "cloud_integration",
    description: "Hold-your-own-key proxy flows",
    icon: GlobeLock,
    emoji: "H",
    requiredAnyFeatures: ["hyok_proxy"]
  },
  {
    id: "ekm",
    label: "EKM",
    shortLabel: "EKM",
    group: "cloud_integration",
    description: "Database encryption key manager integrations",
    icon: Database,
    emoji: "E",
    requiredAnyFeatures: ["ekm_database"]
  },
  {
    id: "kmip",
    label: "KMIP",
    shortLabel: "KMIP",
    group: "cloud_integration",
    description: "KMIP client and object operations",
    icon: Waypoints,
    emoji: "K",
    requiredAnyFeatures: ["kmip_server"]
  },
  {
    id: "hsm_primus",
    label: "HSM",
    shortLabel: "HSM",
    group: "infrastructure",
    description: "Hardware and software vault provider plane",
    icon: Cpu,
    emoji: "H",
    requiredAnyFeatures: ["hsm_hardware", "hsm_software"]
  },
  {
    id: "qkd",
    label: "QKD",
    shortLabel: "QKD",
    group: "infrastructure",
    description: "Quantum key distribution interface status",
    icon: Workflow,
    emoji: "Q",
    requiredAnyFeatures: ["qkd_interface"]
  },
  {
    id: "qrng",
    label: "QRNG",
    shortLabel: "QRNG",
    group: "infrastructure",
    description: "Quantum random number generator entropy sources",
    icon: Atom,
    emoji: "Q",
    requiredAnyFeatures: ["qrng_generator"]
  },
  {
    id: "mpc",
    label: "MPC",
    shortLabel: "MPC",
    group: "infrastructure",
    description: "Threshold signing and ceremony orchestration",
    icon: Blocks,
    emoji: "M",
    requiredAnyFeatures: ["mpc_engine"]
  },
  {
    id: "cluster",
    label: "Cluster",
    shortLabel: "Cluster",
    group: "infrastructure",
    description: "Node topology, health, and leader state",
    icon: Layers3,
    emoji: "C",
    requiredAnyFeatures: ["clustering"]
  },
  {
    id: "approvals",
    label: "Approvals",
    shortLabel: "Approvals",
    group: "governance_compliance",
    description: "Multi-quorum governance requests",
    icon: ShieldAlert,
    emoji: "A",
    requiredAnyFeatures: ["governance"]
  },
  {
    id: "alert_center",
    label: "Alert Center",
    shortLabel: "Alerts",
    group: "governance_compliance",
    description: "Alerting channels and active incidents",
    icon: BellRing,
    emoji: "!",
    requiredAnyFeatures: ["reporting_alerting"]
  },
  {
    id: "compliance",
    label: "Compliance",
    shortLabel: "Compliance",
    group: "governance_compliance",
    description: "Posture scoring and framework gap analysis",
    icon: Landmark,
    emoji: "C",
    requiredAnyFeatures: ["compliance_dashboard"]
  },
  {
    id: "sbom_cbom",
    label: "SBOM/CBOM",
    shortLabel: "SBOM/CBOM",
    group: "governance_compliance",
    description: "Software and crypto BOM intelligence",
    icon: Library,
    emoji: "S",
    requiredAnyFeatures: ["sbom_cbom"]
  },
  {
    id: "administration",
    label: "Administration",
    shortLabel: "Admin",
    group: "admin",
    description: "Tenant, feature, network, FIPS, and license controls",
    icon: Building2,
    emoji: "A"
  }
];

export const tabOrder: TabId[] = tabConfig.map((t) => t.id);
