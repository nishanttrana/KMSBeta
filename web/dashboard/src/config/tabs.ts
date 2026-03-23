import type { LucideIcon } from "lucide-react";
import {
  Activity,
  Atom,
  BellRing,
  Blocks,
  Building2,
  Cloud,
  Cpu,
  Database,
  FileCheck2,
  FileLock2,
  Fingerprint,
  KeyRound,
  Landmark,
  Layers3,
  Library,
  Lock,
  ScrollText,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Users,
  Wallet,
  Waypoints,
  Workflow,
  Gauge
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
  | "artifact_signing"
  | "key_access_justifications"
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
  | "audit_log"
  | "vault"
  | "certificates"
  | "pqc"
  | "tokenize_mask"
  | "payment"
  | "autokey"
  | "key_access_justifications"
  | "artifact_signing"
  | "workload_identity"
  | "confidential_compute"
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
  | "posture"
  | "compliance"
  | "sbom_cbom"
  | "pkcs11_jca"
  | "ai_assistant"
  | "administration";

export type GroupId =
  | "core"
  | "crypto_pki"
  | "data_policy"
  | "cloud_identity"
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
};

export const groupLabels: Record<GroupId, string> = {
  core: "CORE",
  crypto_pki: "CRYPTO & PKI",
  data_policy: "DATA & POLICY",
  cloud_identity: "CLOUD & IDENTITY",
  infrastructure: "INFRASTRUCTURE",
  governance_compliance: "GOVERNANCE",
  admin: "ADMIN"
};

export const tabConfig: TabConfig[] = [
  // ── CORE ────────────────────────────────────────────────────────────
  { id: "dashboard",    label: "Dashboard",        shortLabel: "Dashboard", group: "core",                  description: "Operational and compliance posture overview",                                                              icon: Activity,          emoji: "D"  },
  { id: "keys",         label: "Keys",             shortLabel: "Keys",      group: "core",                  description: "Key inventory, lifecycle management, auto-provisioning, and access policy",                              icon: KeyRound,          emoji: "K"  },
  { id: "vault",        label: "Vault",            shortLabel: "Vault",     group: "core",                  description: "Universal secret store",                                                                                 icon: Lock,              emoji: "V"  },
  { id: "audit_log",    label: "Audit Log",        shortLabel: "Audit",     group: "core",                  description: "Real-time and historical audit streams",                                                                 icon: FileLock2,         emoji: "L"  },

  // ── CRYPTO & PKI ────────────────────────────────────────────────────
  { id: "certificates", label: "Certificates / PKI", shortLabel: "Certs",   group: "crypto_pki",            description: "Internal mini PKI and protocol operations",                                                              icon: FileCheck2,        emoji: "C"  },
  { id: "pqc",          label: "Post-Quantum Crypto", shortLabel: "PQC",    group: "crypto_pki",            description: "ML-KEM, ML-DSA, SLH-DSA readiness scanning, migration plans, and per-asset timeline",                   icon: Atom,              emoji: "Q"  },
  { id: "crypto_console", label: "Crypto Console", shortLabel: "Console",   group: "crypto_pki",            description: "Ad-hoc cryptographic operation simulator",                                                               icon: SlidersHorizontal, emoji: "C"  },

  // ── DATA & POLICY ───────────────────────────────────────────────────
  { id: "tokenize_mask", label: "Tokenize / Mask", shortLabel: "Tokenize",  group: "data_policy",           description: "Tokenization, masking, and field-level encryption",                                                      icon: Shield,            emoji: "T"  },
  { id: "payment",       label: "Payment",         shortLabel: "Payment",   group: "data_policy",           description: "TR-31, PIN blocks, and ISO 20022 signing",                                                               icon: Wallet,            emoji: "P"  },
  { id: "autokey",       label: "Auto-Provisioning", shortLabel: "Autokey", group: "data_policy",           description: "Policy-driven key handle provisioning — request keys via templates, track handles and approval workflows", icon: Layers3,           emoji: "A"  },
  { id: "key_access_justifications", label: "Access Justifications", shortLabel: "Key Access", group: "data_policy", description: "Justification codes, time-window rules, and access audit decisions for key operations",           icon: ShieldCheck,       emoji: "J"  },
  { id: "pkcs11_jca",    label: "PKCS#11 / JCA",   shortLabel: "PKCS#11",  group: "data_policy",           description: "Client SDK providers and mechanism telemetry",                                                            icon: Fingerprint,       emoji: "P"  },

  // ── CLOUD & IDENTITY ────────────────────────────────────────────────
  { id: "byok",          label: "Cloud Keys (BYOK/HYOK)", shortLabel: "Cloud Keys", group: "cloud_identity", description: "Cloud external key management — BYOK import/sync and HYOK hold-your-own-key proxy",                      icon: Cloud,             emoji: "B"  },
  { id: "ekm",           label: "EKM",             shortLabel: "EKM",       group: "cloud_identity",        description: "Database and endpoint encryption key manager integrations",                                               icon: Database,          emoji: "E"  },
  { id: "kmip",          label: "KMIP",            shortLabel: "KMIP",      group: "cloud_identity",        description: "KMIP protocol client and object operations",                                                             icon: Waypoints,         emoji: "K"  },
  { id: "artifact_signing", label: "Signing",      shortLabel: "Signing",   group: "cloud_identity",        description: "Artifact, blob, and Git signing with identity constraints, branch policy, and transparency log",          icon: Library,           emoji: "S"  },
  { id: "workload_identity", label: "Workload Identity", shortLabel: "Workload", group: "cloud_identity",   description: "SPIFFE/SVID workload identity — register workloads, issue SVIDs, token exchange, rotation alerts",        icon: Users,             emoji: "W"  },
  { id: "confidential_compute", label: "Confidential Compute", shortLabel: "Confidential", group: "cloud_identity", description: "Attested key release for TEE/enclave workloads",                                                icon: Fingerprint,       emoji: "C"  },

  // ── INFRASTRUCTURE ──────────────────────────────────────────────────
  { id: "hsm_primus",    label: "HSM",             shortLabel: "HSM",       group: "infrastructure",        description: "Hardware and software vault provider plane",                                                             icon: Cpu,               emoji: "H"  },
  { id: "qkd",           label: "QKD",             shortLabel: "QKD",       group: "infrastructure",        description: "Quantum key distribution interface status",                                                              icon: Workflow,          emoji: "Q"  },
  { id: "qrng",          label: "QRNG",            shortLabel: "QRNG",      group: "infrastructure",        description: "Quantum random number generator entropy sources",                                                        icon: Atom,              emoji: "Q"  },
  { id: "mpc",           label: "MPC / FROST",     shortLabel: "MPC",       group: "infrastructure",        description: "Threshold signing, FROST-style quorum workflows, and ceremony orchestration",                            icon: Blocks,            emoji: "M"  },
  { id: "cluster",       label: "Cluster",         shortLabel: "Cluster",   group: "infrastructure",        description: "Node topology, health, and leader state",                                                                icon: Layers3,           emoji: "C"  },

  // ── GOVERNANCE ──────────────────────────────────────────────────────
  { id: "approvals",     label: "Approvals",       shortLabel: "Approvals", group: "governance_compliance", description: "Multi-quorum governance requests",                                                                       icon: ShieldAlert,       emoji: "A"  },
  { id: "alert_center",  label: "Alert Center",    shortLabel: "Alerts",    group: "governance_compliance", description: "Alerting channels, active incidents, and SVID rotation alerts",                                          icon: BellRing,          emoji: "!"  },
  { id: "posture",       label: "Posture",         shortLabel: "Posture",   group: "governance_compliance", description: "Risk detection, drift findings, and remediation actions",                                                icon: Gauge,             emoji: "P"  },
  { id: "compliance",    label: "Compliance",      shortLabel: "Compliance", group: "governance_compliance", description: "Posture scoring, framework gap analysis, and SBOM/CBOM intelligence",                                  icon: Landmark,          emoji: "C"  },
  { id: "sbom_cbom",     label: "SBOM / CBOM",     shortLabel: "SBOM",      group: "governance_compliance", description: "Software and crypto BOM intelligence for PQC readiness and compliance",                                 icon: ScrollText,        emoji: "S"  },

  // ── ADMIN ────────────────────────────────────────────────────────────
  { id: "ai_assistant",  label: "AI Assistant",    shortLabel: "AI",        group: "admin",                 description: "AI-powered key management guidance and policy recommendations",                                          icon: Sparkles,          emoji: "AI" },
  { id: "administration", label: "Administration", shortLabel: "Admin",     group: "admin",                 description: "Tenant, feature, network, FIPS, and license controls",                                                  icon: Building2,         emoji: "A"  }
];

export const tabOrder: TabId[] = tabConfig.map((t) => t.id);
