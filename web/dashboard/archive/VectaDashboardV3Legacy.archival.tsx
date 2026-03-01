// @ts-nocheck
import { useState, useEffect, useMemo, useRef } from "react";
import {
  Home as HomeIcon,
  KeyRound,
  Plus,
  ArrowDownToLine,
  PenTool,
  Zap,
  Lock,
  FileText,
  Building2,
  Atom,
  Clock3,
  Gauge,
  Radio as RadioIcon,
  VenetianMask,
  CreditCard,
  Cloud,
  ShieldCheck,
  Database,
  Link,
  Cpu,
  GitBranch,
  CheckCircle2,
  Bell,
  ScrollText,
  ClipboardCheck,
  BarChart3,
  Plug,
  Settings,
  Cog,
  MoreVertical,
  X,
  Check,
  RefreshCcw,
  ExternalLink,
  Users,  ChevronsLeft,
  ChevronsRight,
  LayoutGrid,
  List
} from "lucide-react";
import { refreshSession, saveSession, type AuthSession } from "../lib/auth";
import {
  activateKey,
  createKey,
  deactivateKey,
  decodeOutputFromBase64,
  decryptData,
  deleteTag,
  deriveKey,
  destroyKey,
  disableKey,
  encryptData,
  exportKey,
  formKey,
  hashData,
  importKey,
  kemDecapsulate,
  kemEncapsulate,
  listKeyAccessGroups,
  listKeys,
  listKeyVersions,
  listTags,
  randomBytes,
  rotateKey,
  getKeyAccessPolicy,
  getKeyAccessSettings,
  listKeyInterfacePolicies,
  listKeyInterfacePorts,
  setKeyAccessGroupMembers,
  setKeyAccessPolicy,
  updateKeyAccessSettings,
  upsertKeyInterfacePolicy,
  upsertKeyInterfacePort,
  deleteKeyInterfacePolicy,
  deleteKeyInterfacePort,
  setKeyExportPolicy,
  setKeyUsageLimit,
  createKeyAccessGroup,
  deleteKeyAccessGroup,
  signData,
  updateKeyActivation,
  upsertTag,
  verifyData
} from "../lib/keycore";
import {
  acmeChallengeComplete,
  acmeFinalize,
  acmeNewAccount,
  acmeNewOrder,
  cmpv2Request,
  createCA,
  deleteCA,
  deleteCertificate,
  downloadCertificateAsset,
  estServerKeygen,
  getCertExpiryAlertPolicy,
  getCertSecurityStatus,
  getCRL,
  getOCSP,
  issueCertificate,
  listCAs,
  listCertificates,
  listInventory,
  listProfiles,
  listProtocolConfigs,
  listProtocolSchemas,
  renewCertificate,
  revokeCertificate,
  scepEnroll,
  signCertificateCSR,
  updateCertExpiryAlertPolicy,
  updateProtocolConfig,
  uploadThirdPartyCertificate
} from "../lib/certs";
import {
  createSecret,
  deleteSecret as deleteVaultSecret,
  generateKeyPairSecret,
  getSecretValue,
  listSecrets
} from "../lib/secrets";
import {
  appDecryptFields,
  appEncryptFields,
  appEnvelopeDecrypt,
  appEnvelopeEncrypt,
  appSearchableDecrypt,
  appSearchableEncrypt,
  applyMask,
  completeFieldEncryptionWrapperRegistration,
  createMaskingPolicy,
  createRedactionPolicy,
  deleteTokenVault,
  downloadTokenVaultExternalSchema,
  downloadFieldEncryptionWrapperSDK,
  getDataProtectionPolicy,
  initFieldEncryptionWrapperRegistration,
  issueFieldEncryptionLease,
  createTokenVault,
  detokenizeValues,
  fpeDecrypt,
  fpeEncrypt,
  listFieldEncryptionLeases,
  listFieldEncryptionWrappers,
  listMaskingPolicies,
  listRedactionPolicies,
  listTokenVaults,
  redactContent,
  revokeFieldEncryptionLease,
  submitFieldEncryptionUsageReceipt,
  updateDataProtectionPolicy,
  tokenizeValues
} from "../lib/dataprotect";
import {
  listPaymentKeys,
  computeCVV,
  computeMAC,
  createInjectionJob,
  createTR31,
  decryptISO20022,
  encryptISO20022,
  generateLAU,
  generatePVV,
  getPaymentPolicy,
  issueInjectionChallenge,
  listInjectionJobs,
  listInjectionTerminals,
  registerInjectionTerminal,
  signISO20022,
  translatePIN,
  translateTR31,
  updatePaymentPolicy,
  validateTR31,
  verifyInjectionChallenge,
  verifyCVV,
  verifyISO20022,
  verifyLAU,
  verifyMAC,
  verifyPVV
} from "../lib/payment";
import {
  deleteCloudAccount,
  discoverCloudInventory,
  importKeyToCloud,
  listCloudAccounts,
  listCloudBindings,
  normalizeCloudProvider,
  registerCloudAccount,
  rotateCloudBinding,
  syncCloudKeys,
  type CloudAccount,
  type DeleteCloudAccountResult,
  type CloudKeyBinding,
  type CloudProvider,
  type CloudSyncJob
} from "../lib/cloud";
import {
  configureHYOKEndpoint,
  deleteHYOKEndpoint,
  getHYOKDKEPublicKey,
  getHYOKHealth,
  hyokCrypto,
  listHYOKEndpoints,
  listHYOKRequests
} from "../lib/hyok";
import {
  deleteClusterProfile,
  getClusterOverview,
  removeClusterNode,
  updateClusterNodeRole,
  upsertClusterNode,
  upsertClusterProfile
} from "../lib/cluster";
import {
  deleteBitLockerClient,
  getBitLockerDeployPackage,
  getBitLockerClient,
  getBitLockerDeletePreview,
  listBitLockerClients,
  listBitLockerJobs,
  listBitLockerRecoveryKeys,
  deleteEKMAgent,
  getEKMAgentHealth,
  getEKMAgentStatus,
  getEKMDeployPackage,
  getEKMTDEPublicKey,
  listEKMAgentLogs,
  listEKMAgents,
  queueBitLockerOperation,
  registerBitLockerClient,
  registerEKMAgent,
  scanBitLockerWindows,
  rotateEKMAgentKey
} from "../lib/ekm";
import {
  acknowledgeAlertsBulk,
  acknowledgeAlert,
  createReportingScheduledReport,
  createReportingRule,
  deleteReportingReportJob,
  downloadReportingReport,
  escalateAlert,
  getReportingAlertStats,
  getReportingMTTR,
  getReportingReportJob,
  getUnreadAlertCounts,
  listReportingAlerts,
  listReportingChannels,
  listReportingReportJobs,
  listReportingReportTemplates,
  listReportingRules,
  listReportingScheduledReports,
  generateReportingReport
} from "../lib/reporting";
import {
  getComplianceAssessment,
  getComplianceAssessmentSchedule,
  listComplianceFrameworkCatalog,
  listComplianceAssessmentHistory,
  listComplianceTemplates,
  runComplianceAssessment,
  upsertComplianceTemplate,
  deleteComplianceTemplate,
  updateComplianceAssessmentSchedule
} from "../lib/compliance";
import { HSM_VENDOR_PROFILES, inferHSMVendor, normalizeHSMVendorView } from "../modules/hsm/vendorProfiles";
import {
  createAuthTenant,
  createAuthUser,
  deleteAuthGroupRoleBinding,
  disableAuthTenant,
  deleteAuthTenant,
  getAuthCLIHSMConfig,
  getAuthCLIStatus,
  listAuthCLIHSMPartitions,
  getAuthTenantDeleteReadiness,
  getAuthPasswordPolicy,
  getAuthSecurityPolicy,
  listAuthGroupRoleBindings,
  listAuthTenants,
  listAuthUsers,  resetAuthUserPassword,
  upsertAuthCLIHSMConfig,
  upsertAuthGroupRoleBinding,
  updateAuthPasswordPolicy,
  updateAuthSecurityPolicy,
  updateAuthUserRole,
  updateAuthUserStatus
} from "../lib/authAdmin";
import { canAccessModule, isSystemAdminSession } from "../config/moduleRegistry";
import {
  createGovernanceBackup,
  createGovernanceRequest,
  createGovernancePolicy,
  deleteGovernanceBackup,
  downloadGovernanceBackupArtifact,
  downloadGovernanceBackupKey,
  getGovernanceRequest,
  getGovernanceSettings,
  getGovernanceSystemState,
  listGovernanceBackups,
  listGovernancePolicies,
  listGovernanceRequests,
  restoreGovernanceBackup,
  testGovernanceSMTP,
  testGovernanceWebhook,
  updateGovernancePolicy,
  updateGovernanceSettings,
  voteGovernanceRequest
} from "../lib/governance";
import type { FeatureKey } from "../config/tabs";
import type { LiveEvent } from "../store/live";
import {
  DATA_ENCRYPTION_INTERFACE_OPTIONS,
  DEFAULT_KEY_COLUMN_VISIBILITY,
  DOC_CAPABILITIES,
  DOC_COMPONENTS,
  KEY_ACCESS_OPERATION_OPTIONS,
  KEY_TABLE_COLUMNS
} from "../components/v3/constants";
import { errMsg, isFipsModeEnabled, normalizeFipsModeValue, TabErrorBoundary } from "../components/v3/runtimeUtils";
import { C } from "../components/v3/theme";
import { B, Bar, Btn, Card, Chk, FG, Inp, Modal, Radio, Row2, Row3, Section, Sel, Stat, Tabs, Txt, usePromptDialog } from "../components/v3/legacyPrimitives";
import { RestAPITab } from "../components/v3/tabs/RestAPITab";
import { VaultTab } from "../components/v3/tabs/VaultTab";
import { DashboardTab } from "../components/v3/tabs/DashboardTab";
import { GovernanceTab } from "../components/v3/tabs/GovernanceTab";
import { ClusterTab } from "../components/v3/tabs/ClusterTab";
import { AlertsTab } from "../components/v3/tabs/AlertsTab";
import { AdminTab } from "../components/v3/tabs/AdminTab";
import { KeysTab } from "../components/v3/tabs/KeysTab";
import { CryptoTab } from "../components/v3/tabs/CryptoTab";
import { CertsTab } from "../components/v3/tabs/CertsTab";
import { DataEncryptionTab, DataProtectionTab, TokenizeTab } from "../components/v3/tabs/DataProtectionTabs";
import { PaymentTab } from "../components/v3/tabs/PaymentTab";
import { BYOKTab } from "../components/v3/tabs/BYOKTab";
import { CloudKeyControlTab } from "../components/v3/tabs/CloudKeyControlTab";
import { HYOKTab } from "../components/v3/tabs/HYOKTab";
import { EKMTab } from "../components/v3/tabs/EKMTab";
import { HSMTab } from "../components/v3/tabs/HSMTab";
import { KMIPTab } from "../components/v3/tabs/KMIPTab";
import { ComplianceTab } from "../components/v3/tabs/ComplianceTab";
import { SBOMTab } from "../components/v3/tabs/SBOMTab";
import { MPCTab } from "../components/v3/tabs/MPCTab";
import { QKDTab } from "../components/v3/tabs/QKDTab";
import { PKCS11Tab } from "../components/v3/tabs/PKCS11Tab";
import { WorkbenchTab } from "../components/v3/tabs/WorkbenchTab";
import { AuditLogTab } from "../components/v3/tabs/AuditLogTab";
import { PostureTab } from "../components/v3/tabs/PostureTab";

// 
// VECTA KMS DASHBOARD v3 - FULLY INTERACTIVE BUILD REFERENCE
// Every button opens real forms. Every form shows all options.
// This dashboard IS the development spec.
// 

const TAB_FEATURES = {
  vault: "secrets",
  certs: "certs",
  dataprotection: ["data_protection", "payment_crypto"],
  tokenize: "data_protection",
  dataenc: "data_protection",
  payment: "payment_crypto",
  cloudctl: ["cloud_byok", "hyok_proxy"],
  byok: "cloud_byok",
  hyok: "hyok_proxy",
  ekm: ["ekm_database", "kmip_server"],
  kmip: "kmip_server",
  hsm: "hsm_hardware_or_software",
  qkd: "qkd_interface",
  mpc: "mpc_engine",
  cluster: "clustering",
  approvals: "governance",
  alerts: "reporting_alerting",
  posture: ["governance", "compliance_dashboard"],
  compliance: "compliance_dashboard",
  sbom: "sbom_cbom"
};


function formatAgo(value: unknown): string {
  const raw = String(value || "").trim();
  if (!raw) {
    return "-";
  }
  const ts = new Date(raw);
  if (Number.isNaN(ts.getTime())) {
    return "-";
  }
  const diffSec = Math.max(0, Math.floor((Date.now() - ts.getTime()) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}d ago`;
}

function sanitizeDisplayText(value: unknown): string {
  return String(value || "")
    .replace(/\uFFFD/g, " ")
    .replace(/[\u2013\u2014]/g, "-")
    .replace(/\u2192/g, "->")
    .replace(/[\u2022\u00B7]/g, " | ")
    .replace(/[^\x20-\x7E]/g, "")
    .replace(/\s{2,}/g, " ")
    .trim();
}

function normalizeKeyState(state: string): string {
  const raw = String(state || "").toLowerCase().trim();
  if (raw === "destroyed" || raw === "deleted") {
    return "deleted";
  }
  if (raw === "destroy-pending" || raw === "delete-pending" || raw === "deletion-pending") {
    return "destroy-pending";
  }
  if (raw === "preactive" || raw === "pre-active") {
    return "pre-active";
  }
  if (raw === "retired" || raw === "deactivated") {
    return "deactivated";
  }
  if (raw === "generation" || raw === "generated") {
    return "pre-active";
  }
  return raw || "unknown";
}

function keyStateLabel(state: string): string {
  const norm = normalizeKeyState(state);
  switch (norm) {
    case "pre-active":
      return "Pre-active";
    case "active":
      return "Active";
    case "disabled":
      return "Disabled";
    case "deactivated":
      return "Deactivated (Retired)";
    case "destroy-pending":
      return "Delete Pending";
    case "deleted":
      return "Deleted";
    default:
      return norm.split("-").map((part)=>part?part[0].toUpperCase()+part.slice(1):part).join(" ");
  }
}

function keyStateTone(state: string): "green" | "amber" | "red" | "blue" | "muted" {
  const norm = normalizeKeyState(state);
  if (norm === "active") {
    return "green";
  }
  if (norm === "pre-active" || norm === "deactivated") {
    return "amber";
  }
  if (norm === "deleted") {
    return "muted";
  }
  if (norm === "destroy-pending" || norm === "disabled") {
    return "red";
  }
  return "blue";
}

function normalizeUserStatus(status: string): "active" | "inactive" {
  const raw = String(status || "").toLowerCase().trim();
  if (!raw) {
    return "active";
  }
  if (raw === "disabled" || raw === "inactive" || raw === "suspended" || raw === "blocked") {
    return "inactive";
  }
  return "active";
}

function toViewKey(k: any) {
  const ver = Number(k.current_version || 0);
  const labels = (k && typeof k.labels === "object" && k.labels) ? k.labels : {};
  const componentRole = String(labels.component_role || labels.component || "").toLowerCase();
  const algoDisplay = keyInventoryAlgorithmDisplay(String(k.algorithm || "unknown"));
  return {
    id: String(k.id || ""),
    name: String(k.name || "unnamed-key"),
    algo: String(k.algorithm || "unknown"),
    algoFamily: algoDisplay.family,
    algoSizeCurve: algoDisplay.sizeCurve,
    keyType: String(k.key_type || ""),
    state: normalizeKeyState(String(k.status || "unknown")),
    ver: ver > 0 ? `v${ver}` : "v1",
    kcv: String(k.kcv || ""),
    ops: String(k.ops_total || 0),
    created: String(k.created_at || "-"),
    rotated: String(k.updated_at || "-"),
    expires: String(k.expires_at || k.destroy_date || "Never"),
    destroyAt: String(k.destroy_date || ""),
    activationAt: String(k.activation_date || ""),
    tags: Array.isArray(k.tags)?k.tags.map((t)=>String(t)):[],
    exportAllowed: Boolean(k.export_allowed),
    tenant: String(k.tenant_id || ""),
    purpose: String(k.purpose || "encrypt-decrypt"),
    labels,
    pairId: String(labels.pair_id || ""),
    componentRole: componentRole === "public" ? "public" : componentRole === "private" ? "private" : "",
    ivMode: String(k.iv_mode || "-"),
    opsLimit: k.ops_limit ? String(k.ops_limit) : "inf",
    opsWindow: String(k.ops_limit_window || "total"),
    approvalReq: Boolean(k.approval_required)
  };
}

function canSeeFeature(need: any, enabledFeatures: Set<FeatureKey>, session?: any): boolean {
  if (isSystemAdminSession(session)) {
    return true;
  }
  if (!need) {
    return true;
  }
  if (Array.isArray(need)) {
    return need.some((item) => canSeeFeature(item, enabledFeatures, session));
  }
  if (need === "hsm_hardware_or_software") {
    return enabledFeatures.has("hsm_hardware") || enabledFeatures.has("hsm_software");
  }
  return enabledFeatures.has(need as FeatureKey);
}

function canSeeTab(tab: string, enabledFeatures: Set<FeatureKey>, session?: any): boolean {
  return canAccessModule(tab, enabledFeatures, session);
}

function toneForSeverity(sev: string): string {
  const s = (sev || "").toLowerCase();
  if (s === "critical" || s === "high") {
    return "red";
  }
  if (s === "warning" || s === "medium") {
    return "amber";
  }
  return "green";
}

function keyChoicesFromCatalog(keyCatalog: any[]): any[] {
  if (!Array.isArray(keyCatalog)) {
    return [];
  }
  return keyCatalog.filter((k) => normalizeKeyState(String(k?.state || "")) !== "deleted");
}

function isFipsAlgorithm(algorithm: string): boolean {
  const v = String(algorithm || "").toUpperCase();
  if (!v) {
    return false;
  }
  if (
    v.includes("CHACHA20") ||
    v.includes("CAMELLIA") ||
    v.includes("ECIES") ||
    v.includes("BRAINPOOL") ||
    v.includes("KECCAK") ||
    v.includes("RIPEMD") ||
    v.includes("BLAKE") ||
    v.includes("POLY1305") ||
    (v.includes("AES") && v.includes("ECB"))
  ) {
    return false;
  }
  return (
    v.includes("AES") ||
    v.includes("RSA") ||
    v.includes("ECDSA") ||
    v.includes("ECDH") ||
    v.includes("HMAC") ||
    v.includes("CMAC") ||
    v.includes("GMAC") ||
    v.includes("ML-KEM") ||
    v.includes("ML-DSA") ||
    v.includes("SLH-DSA")
  );
}

function isFipsHashAlgorithm(algorithm: string): boolean {
  const v = String(algorithm || "").toLowerCase().trim();
  return v === "sha-256" || v === "sha-384" || v === "sha-512" || v === "sha3-256" || v === "sha3-384" || v === "sha3-512";
}

function isFipsRandomSource(source: string): boolean {
  const v = String(source || "").toLowerCase().trim();
  return v === "kms-csprng" || v === "hsm-trng";
}

function isFipsMechanism(name: string): boolean {
  const v = String(name || "").toUpperCase();
  if (!v) {
    return false;
  }
  if (
    v.includes("CHACHA20") ||
    v.includes("CAMELLIA") ||
    v.includes("ECIES") ||
    v.includes("BRAINPOOL") ||
    v.includes("KECCAK") ||
    v.includes("RIPEMD") ||
    v.includes("BLAKE") ||
    v.includes("POLY1305") ||
    (v.includes("AES") && v.includes("ECB"))
  ) {
    return false;
  }
  return (
    v.includes("AES") ||
    v.includes("RSA") ||
    v.includes("ECDSA") ||
    v.includes("ECDH") ||
    v.includes("HMAC") ||
    v.includes("CMAC") ||
    v.includes("GMAC") ||
    v.includes("ML-KEM") ||
    v.includes("ML-DSA") ||
    v.includes("SLH-DSA") ||
    v.includes("SHA-256") ||
    v.includes("SHA-384") ||
    v.includes("SHA-512") ||
    v.includes("SHA3")
  );
}

function isAsymmetricKeyLike(key: any): boolean {
  const keyType = String(key?.keyType || "").toLowerCase();
  if (keyType.includes("asymmetric") || keyType.includes("public") || keyType.includes("private")) {
    return true;
  }
  const algo = String(key?.algo || "").toUpperCase();
  return (
    algo.includes("RSA") ||
    algo.includes("ECDSA") ||
    algo.includes("ED25519") ||
    algo.includes("ED448") ||
    algo.includes("X25519") ||
    algo.includes("X448") ||
    algo.includes("ECDH")
  );
}

function isPublicComponentLike(key: any): boolean {
  const role = String(key?.componentRole || "").toLowerCase();
  if (role === "public") {
    return true;
  }
  const keyType = String(key?.keyType || "").toLowerCase();
  return keyType.includes("public");
}

function isAEADAlgorithm(algorithm: string): boolean {
  const v = String(algorithm || "").toUpperCase();
  return (
    v.includes("GCM") ||
    v.includes("CCM") ||
    v.includes("POLY1305")
  );
}

function usesIVAlgorithm(algorithm: string): boolean {
  const v = String(algorithm || "").toUpperCase();
  if (!v || v.includes("ECB")) {
    return false;
  }
  return (
    isAEADAlgorithm(v) ||
    v.includes("CBC") ||
    v.includes("CTR") ||
    v.includes("CFB") ||
    v.includes("OFB") ||
    v.includes("XTS") ||
    v.includes("CHACHA20")
  );
}

function isHMACAlgorithm(algorithm: string): boolean {
  return String(algorithm || "").toUpperCase().includes("HMAC");
}

function isMLKEMAlgorithm(algorithm: string): boolean {
  return String(algorithm || "").toUpperCase().includes("ML-KEM");
}

function isRSAAlgorithm(algorithm: string): boolean {
  return String(algorithm || "").toUpperCase().includes("RSA");
}

function isECDSAAlgorithm(algorithm: string): boolean {
  const v = String(algorithm || "").toUpperCase();
  return v.includes("ECDSA") || v.includes("BRAINPOOL");
}

function isEd25519Algorithm(algorithm: string): boolean {
  return String(algorithm || "").toUpperCase().includes("ED25519");
}

function isSupportedSymmetricCipherAlgorithm(algorithm: string): boolean {
  const v = String(algorithm || "").toUpperCase();
  if (!v.includes("AES") && !v.includes("3DES") && !v.includes("TDES") && !v.includes("DES") && !v.includes("CHACHA20") && !v.includes("CAMELLIA")) {
    return false;
  }
  if (v.includes("CHACHA20") || v.includes("CAMELLIA")) {
    return true;
  }
  if (v.includes("AES")) {
    if (v.includes("ECB") || v.includes("CCM") || v.includes("CFB") || v.includes("OFB") || v.includes("XTS")) {
      return false;
    }
    return true;
  }
  if (v.includes("3DES") || v.includes("TDES")) {
    return v.includes("CBC");
  }
  return false;
}

function isVaultCapableKeyChoice(key: any): boolean {
  const algo = String(key?.algo || "").toUpperCase();
  const keyType = String(key?.keyType || "").toLowerCase();
  const state = String(key?.state || "").toLowerCase();
  if (state && state !== "active") {
    return false;
  }
  if (isPublicComponentLike(key)) {
    return false;
  }
  if (keyType && keyType !== "symmetric") {
    return false;
  }
  if (algo.includes("HMAC") || algo.includes("CMAC") || algo.includes("GMAC")) {
    return false;
  }
  return isSupportedSymmetricCipherAlgorithm(algo);
}

function supportedOpsForKey(key: any): string[] {
  const algo = String(key?.algo || "");
  const keyType = String(key?.keyType || "").toLowerCase();
  const ops = new Set<string>(["Hash", "Random"]);
  if (isSupportedSymmetricCipherAlgorithm(algo)) {
    ops.add("Encrypt");
    ops.add("Decrypt");
    ops.add("Wrap");
    ops.add("Unwrap");
    ops.add("Key Derive");
  }
  if (isHMACAlgorithm(algo)) {
    ops.add("Sign");
    ops.add("Verify");
    ops.add("MAC");
    ops.add("Key Derive");
  }
  if (isRSAAlgorithm(algo)) {
    ops.add("Encrypt");
    ops.add("Wrap");
    ops.add("Verify");
    if (!keyType.includes("public")) {
      ops.add("Decrypt");
      ops.add("Unwrap");
      ops.add("Sign");
    }
  }
  if (isECDSAAlgorithm(algo) || isEd25519Algorithm(algo)) {
    ops.add("Verify");
    if (!keyType.includes("public")) {
      ops.add("Sign");
    }
  }
  if (isMLKEMAlgorithm(algo)) {
    ops.add("KEM Encapsulate");
    if (!keyType.includes("public")) {
      ops.add("KEM Decapsulate");
    }
  }
  return Array.from(ops);
}

function supportsOperationForKey(key: any, op: string): boolean {
  const keyRequired = op !== "Hash" && op !== "Random";
  if (!keyRequired) {
    return true;
  }
  return supportedOpsForKey(key).includes(op);
}

function preferredKEMAlgorithmForKey(key: any): "ml-kem-768" | "ml-kem-1024" {
  const algo = String(key?.algo || "").toUpperCase();
  return algo.includes("1024") ? "ml-kem-1024" : "ml-kem-768";
}

function algorithmFamilyLabel(algorithm: string): string {
  const v = String(algorithm || "").toUpperCase();
  if (!v) {
    return "Other";
  }
  if (v.includes("AES")) {
    return "AES";
  }
  if (v.includes("RSA")) {
    return "RSA";
  }
  if (
    v.includes("ECDSA") ||
    v.includes("ECDH") ||
    v.includes("ECIES") ||
    v.includes("BRAINPOOL") ||
    v.includes("ED25519") ||
    v.includes("ED448") ||
    v.includes("X25519") ||
    v.includes("X448")
  ) {
    return "ECC";
  }
  if (
    v.includes("ML-KEM") ||
    v.includes("ML-DSA") ||
    v.includes("SLH-DSA") ||
    v.includes("HSS-LMS") ||
    v.includes("XMSS")
  ) {
    return "ML";
  }
  if (v.includes("HMAC")) {
    return "HMAC";
  }
  if (v.includes("CMAC") || v.includes("GMAC") || v.includes("POLY1305")) {
    return "MAC";
  }
  if (v.includes("DSA")) {
    return "DSA";
  }
  if (v.includes("3DES") || v.includes("DES")) {
    return "3DES";
  }
  if (v.includes("CHACHA20")) {
    return "ChaCha20";
  }
  if (v.includes("CAMELLIA")) {
    return "Camellia";
  }
  return "Other";
}

function keyInventoryAlgorithmDisplay(algorithm: string): { family: string; sizeCurve: string } {
  const raw = String(algorithm || "").trim();
  const upper = raw.toUpperCase();
  const family = algorithmFamilyLabel(raw);
  let sizeCurve = "-";

  if (family === "AES") {
    const match = upper.match(/AES[-_ ]?(\d{3})/);
    if (match?.[1]) {
      sizeCurve = match[1];
    }
  } else if (family === "RSA") {
    const match = upper.match(/RSA[-_ ]?(?:OAEP[-_ ]?)?(\d{3,4})/) || upper.match(/RSA[-_ ]?(\d{3,4})/);
    if (match?.[1]) {
      sizeCurve = match[1];
    }
  } else if (family === "ECC") {
    const fixed = ["ED25519", "ED448", "X25519", "X448"].find((name) => upper.includes(name));
    if (fixed) {
      sizeCurve = fixed;
    } else {
      const namedCurve =
        upper.match(/(P-?256|P-?384|P-?521)/)?.[1] ||
        upper.match(/(BRAINPOOL-?P?256R1|BRAINPOOL-?P?384R1)/)?.[1] ||
        upper.match(/(SECP256R1|SECP384R1|SECP521R1)/)?.[1];
      if (namedCurve) {
        sizeCurve = namedCurve
          .replace(/^P(?=\d)/, "P-")
          .replace(/^BRAINPOOLP/i, "BRAINPOOL-P");
      } else {
        const ecdsa = upper.match(/ECD(?:SA|H)?[-_ ]?P[-_ ]?(\d{3})/)?.[1];
        if (ecdsa) {
          sizeCurve = `P-${ecdsa}`;
        }
      }
    }
  } else if (family === "ML") {
    const match =
      upper.match(/(ML-KEM-\d+)/)?.[1] ||
      upper.match(/(ML-DSA-\d+)/)?.[1] ||
      upper.match(/(SLH-DSA-[0-9A-Z]+)/)?.[1] ||
      upper.match(/(HSS\/LMS)/)?.[1] ||
      upper.match(/(XMSS)/)?.[1];
    if (match) {
      sizeCurve = match;
    }
  } else if (family === "HMAC") {
    const match = upper.match(/(SHA3?-?\d{3})/)?.[1];
    if (match) {
      sizeCurve = match.replace(/^SHA(?=\d)/, "SHA-");
    }
  } else if (family === "DSA") {
    const match = upper.match(/DSA[-_ ]?(\d{3,4})/)?.[1];
    if (match) {
      sizeCurve = match;
    }
  }

  return { family, sizeCurve };
}

function composeCreateAlgorithm(
  algoType: string,
  family: string,
  keySpec: string,
  cipherMode: string
): string {
  const type = String(algoType || "").toLowerCase();
  const fam = String(family || "").toUpperCase();
  const spec = String(keySpec || "").trim();
  const mode = String(cipherMode || "GCM").toUpperCase();
  if (type === "symmetric") {
    if (fam === "AES") {
      return `AES-${spec || "256"}-${mode}`;
    }
    if (fam === "CHACHA20") {
      return "ChaCha20-Poly1305";
    }
    if (fam === "CAMELLIA") {
      return `Camellia-${spec || "256"}-${mode}`;
    }
    if (fam === "3DES") {
      return "3DES-CBC";
    }
    return `AES-${spec || "256"}-${mode}`;
  }
  if (type === "asymmetric") {
    if (fam === "RSA") {
      return `RSA-${spec || "2048"}`;
    }
    if (fam === "ECC") {
      if (spec === "Brainpool-P256r1" || spec === "Brainpool-P384r1") {
        return spec;
      }
      if (spec === "P-384") {
        return "ECDSA-P384";
      }
      if (spec === "P-521") {
        return "ECDSA-P521";
      }
      return "ECDSA-P256";
    }
    if (fam === "EDDSA") {
      return spec === "Ed448" ? "Ed448" : "Ed25519";
    }
    if (fam === "ECDH") {
      if (spec === "X25519" || spec === "X448") {
        return spec;
      }
      if (spec === "P-384") {
        return "ECDH-P384";
      }
      return "ECDH-P256";
    }
    if (fam === "DSA") {
      return "DSA-3072";
    }
    return `RSA-${spec || "2048"}`;
  }
  if (type === "pqc") {
    if (fam === "ML-KEM") {
      return `ML-KEM-${spec || "768"}`;
    }
    if (fam === "ML-DSA") {
      return `ML-DSA-${spec || "65"}`;
    }
    if (fam === "SLH-DSA") {
      return `SLH-DSA-${spec || "128s"}`;
    }
    if (fam === "HSS/LMS") {
      return `HSS-LMS-${spec || "SHA256-H10"}`;
    }
    if (fam === "XMSS") {
      return `XMSS-${spec || "SHA256-H10"}`;
    }
    if (fam === "HYBRID") {
      return spec || "ECDSA-P384 + ML-DSA-65";
    }
    return `ML-KEM-${spec || "768"}`;
  }
  if (fam === "CMAC") {
    return "CMAC-AES-256";
  }
  return `HMAC-${spec || "SHA256"}`;
}

function publicPurposeFromPrivate(purpose: string): string {
  const p = String(purpose || "").trim().toLowerCase();
  if (p === "sign-verify") {
    return "verify";
  }
  if (p === "encrypt-decrypt") {
    return "encrypt";
  }
  if (p === "key-agreement") {
    return "key-agreement";
  }
  return p || "verify";
}

function formatOpsValue(value: number): string {
  const n = Number(value || 0);
  if (n >= 1_000_000_000) {
    return `${(n / 1_000_000_000).toFixed(1).replace(/\.0$/, "")}B`;
  }
  if (n >= 1_000_000) {
    return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
  }
  if (n >= 1_000) {
    return `${(n / 1_000).toFixed(1).replace(/\.0$/, "")}K`;
  }
  return String(n);
}

function formatDestroyAt(value: string): string {
  const raw = String(value || "").trim();
  if (!raw) {
    return "-";
  }
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) {
    return raw;
  }
  return dt.toLocaleString();
}

function tagColorByName(tagCatalog: any[], name: string): string {
  const match=(Array.isArray(tagCatalog)?tagCatalog:[]).find((t)=>String(t?.name||"")===String(name||""));
  return String(match?.color||C.blue);
}

function toISODateTime(localValue: string): string | undefined {
  const raw = String(localValue || "").trim();
  if (!raw) {
    return undefined;
  }
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) {
    return undefined;
  }
  return dt.toISOString();
}

function toLocalDateTime(isoValue: string): string {
  const raw = String(isoValue || "").trim();
  if (!raw) {
    return "";
  }
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) {
    return "";
  }
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}T${pad(dt.getHours())}:${pad(dt.getMinutes())}`;
}

function renderKeyOptions(keyChoices: any[]): any[] {
  if (!keyChoices.length) {
    return [<option key="no-customer-keys" value="">No customer keys available</option>];
  }
  return keyChoices.map((k) => (
    <option key={k.id} value={k.id}>
      {k.name} {k.algo ? `(${k.algo})` : ""}
    </option>
  ));
}

const NAV=[
  {g:"CORE",items:[{id:"home",icon:HomeIcon,label:"Dashboard"},{id:"keys",icon:KeyRound,label:"Key Management"},{id:"certs",icon:FileText,label:"Certificates / PKI"},{id:"cloudctl",icon:Cloud,label:"Cloud Key Control"},{id:"ekm",icon:Database,label:"Enterprise Key Management"},{id:"vault",icon:Lock,label:"Secret Vault"},{id:"dataprotection",icon:ShieldCheck,label:"Data Protection"}]},
  {g:"WORKBENCH",items:[{id:"workbench",icon:LayoutGrid,label:"Workbench"}]},
  {g:"INFRASTRUCTURE",items:[{id:"hsm",icon:Cpu,label:"HSM"},{id:"qkd",icon:GitBranch,label:"QKD Interface"},{id:"mpc",icon:Cpu,label:"MPC Engine"},{id:"cluster",icon:GitBranch,label:"Cluster"}]},
  {g:"GOVERNANCE",items:[{id:"approvals",icon:CheckCircle2,label:"Approvals"},{id:"alerts",icon:Bell,label:"Alert Center"},{id:"audit",icon:ScrollText,label:"Audit Log"},{id:"posture",icon:Gauge,label:"Posture Management"},{id:"compliance",icon:ClipboardCheck,label:"Compliance"},{id:"sbom",icon:BarChart3,label:"SBOM / CBOM"}]},
  {g:"ADMIN",items:[{id:"admin",icon:Settings,label:"Administration"}]},
];

// 
// TAB: KEY MANAGEMENT (fully interactive)
// 
const Keys=KeysTab;

// 
// TAB: CRYPTO CONSOLE (interactive encrypt/decrypt/sign/verify)
// 
const Crypto=CryptoTab;

const Workbench=WorkbenchTab;

// 
// TAB: SECRET VAULT (interactive)
// 
// 
// 
// TAB: CERTIFICATES / PKI (interactive with PQC)
// 
const Certs=CertsTab;

const Tokenize=TokenizeTab;
const DataEncryption=DataEncryptionTab;

const DataProtection=DataProtectionTab;

// TAB: PAYMENT CRYPTO (interactive)
// 
const Payment=PaymentTab;

// 
// REMAINING TABS (interactive stubs with modals)
// 
// 
const BYOK=BYOKTab;

const HYOK=HYOKTab;

const CloudKeyControl=CloudKeyControlTab;

const EKM=EKMTab;

const HSM=HSMTab;

const QKD=QKDTab;

const MPC=MPCTab;

const KMIP=KMIPTab;

// Approvals tab extracted to components/v3/tabs/GovernanceTab.tsx
const AuditLog=AuditLogTab;

const Compliance=ComplianceTab;
const Posture=PostureTab;

const SBOM=SBOMTab;

const PKCS11=PKCS11Tab;

const TABS={home:DashboardTab,keys:Keys,workbench:Workbench,crypto:Crypto,restapi:RestAPITab,vault:VaultTab,certs:Certs,dataprotection:DataProtection,tokenize:Tokenize,dataenc:DataEncryption,payment:Payment,cloudctl:CloudKeyControl,byok:BYOK,hyok:HYOK,ekm:EKM,hsm:HSM,qkd:QKD,mpc:MPC,cluster:ClusterTab,approvals:GovernanceTab,alerts:AlertsTab,audit:AuditLog,posture:Posture,compliance:Compliance,sbom:SBOM,pkcs11:PKCS11,admin:AdminTab};
const TITLES={home:"Dashboard",keys:"Key Management",workbench:"Workbench",crypto:"Crypto Console",restapi:"REST API",vault:"Secret Vault",certs:"Certificates / PKI",dataprotection:"Data Protection",tokenize:"Tokenize / Mask / Redact",dataenc:"Data Encryption",payment:"Payment Crypto",cloudctl:"Cloud Key Control",byok:"BYOK",hyok:"HYOK",ekm:"Enterprise Key Management",hsm:"HSM",qkd:"QKD Interface",mpc:"MPC Engine",cluster:"Cluster",approvals:"Approvals",alerts:"Alert Center",audit:"Audit Log",posture:"Posture Management",compliance:"Compliance",sbom:"SBOM / CBOM",pkcs11:"PKCS#11 / JCA",admin:"Administration"};
const UI_BUILD_ID="nav-restore-CLI-TOP-01";
const SYSTEM_ADMIN_OPEN_CLI_KEY="vecta_system_admin_open_cli";
const DASHBOARD_TAB_QUERY_KEY="tab";
const DASHBOARD_SUB_QUERY_KEY="sub";
type DashboardLocationState={tab:string;sub:string};
const readDashboardLocationState=():DashboardLocationState=>{
  try{
    const qp=new URLSearchParams(window.location.search);
    return {
      tab:String(qp.get(DASHBOARD_TAB_QUERY_KEY)||"").trim().toLowerCase(),
      sub:String(qp.get(DASHBOARD_SUB_QUERY_KEY)||"").trim()
    };
  }catch{
    return {tab:"",sub:""};
  }
};
const SUB_PANES={
  workbench:[
    {id:"crypto",label:"Crypto Console",hint:"Interactive cryptographic operations and algorithm console",icon:Zap},
    {id:"restapi",label:"REST API",hint:"Authenticated API explorer and endpoint documentation",icon:FileText},
    {id:"tokenize",label:"Tokenize / Mask / Redact",hint:"Vault and vaultless tokenization with masking/redaction",icon:VenetianMask,feature:"data_protection"},
    {id:"dataenc",label:"Data Encryption",hint:"Field-level, envelope, searchable and FPE crypto",icon:Database,feature:"data_protection"},
    {id:"payment",label:"Payment Crypto",hint:"TR-31, PIN, CVV, MAC and ISO20022 operations",icon:CreditCard,feature:"payment_crypto"}
  ],
  dataprotection:[
    {id:"fieldenc",label:"Field Encryption",hint:"Wrapper registration, challenge-response and local crypto lease control",icon:KeyRound,feature:"data_protection"},
    {id:"dataenc-policy",label:"Data Encryption Policy",hint:"Policy controls only for data encryption interfaces",icon:List,feature:"data_protection"},
    {id:"token-policy",label:"Token / Mask / Redact Policy",hint:"Policy controls only for tokenization, masking and redaction",icon:VenetianMask,feature:"data_protection"},
    {id:"payment-policy",label:"Payment Policy",hint:"Policy controls only for payment cryptography operations",icon:CreditCard,feature:"payment_crypto"},
    {id:"pkcs11",label:"PKCS#11 / JCA",hint:"SDK providers, mechanism usage and client telemetry",icon:Plug}
  ],
  cloudctl:[
    {id:"byok",label:"BYOK",hint:"Cloud provider key import and sync",icon:Cloud,feature:"cloud_byok"},
    {id:"hyok",label:"HYOK",hint:"Hold-your-own-key policy and cryptographic controls",icon:ShieldCheck,feature:"hyok_proxy"}
  ],
  ekm:[
    {id:"db",label:"EKM for DBs",hint:"MSSQL / Oracle TDE agents",icon:Database,feature:"ekm_database"},
    {id:"bitlocker",label:"BitLocker",hint:"Windows endpoint key lifecycle",icon:Lock,feature:"ekm_database"},
    {id:"kmip",label:"KMIP",hint:"Profiles, clients, mTLS onboarding",icon:Link,feature:"kmip_server"}
  ],
  certs:[
    {id:"cert-overview",label:"Certificate Operations",hint:"CA hierarchy, issuance, signing and certificate lifecycle",icon:FileText,feature:"certs"},
    {id:"cert-enrollment",label:"Enrollment Protocols",hint:"ACME, EST, SCEP, CMPv2 and runtime mTLS enrollment settings",icon:Link,feature:"certs"}
  ],
  hsm:[
    {id:"hsm-aws",label:"AWS CloudHSM",hint:"Cluster endpoint, slot mapping and crypto user binding",icon:Cloud,feature:"hsm_hardware_or_software"},
    {id:"hsm-azure",label:"Azure Managed HSM",hint:"Managed HSM endpoint mapping and PKCS#11 bridge profile",icon:Cloud,feature:"hsm_hardware_or_software"},
    {id:"hsm-thales",label:"Thales Luna HSM",hint:"NTLS endpoint, Luna slot and partition settings",icon:Cpu,feature:"hsm_hardware_or_software"},
    {id:"hsm-utimaco",label:"Utimaco HSM",hint:"CryptoServer slot/partition profile and provider settings",icon:Cpu,feature:"hsm_hardware_or_software"},
    {id:"hsm-entrust",label:"Entrust nShield HSM",hint:"Security World connector, slot profile and token mapping",icon:ShieldCheck,feature:"hsm_hardware_or_software"},
    {id:"hsm-securosys",label:"Securosys HSM",hint:"Securosys provider, slot and partition configuration",icon:ShieldCheck,feature:"hsm_hardware_or_software"},
    {id:"hsm-generic",label:"Generic PKCS#11 HSM",hint:"Vendor-neutral PKCS#11 library onboarding profile",icon:Plug,feature:"hsm_hardware_or_software"}
  ],
  cluster:[
    {id:"settings",label:"Cluster Settings",hint:"Replication profiles and existing-instance node controls",icon:Settings,feature:"clustering"},
    {id:"health",label:"Cluster Health",hint:"Live node health view with selective component sync status",icon:Gauge,feature:"clustering"}
  ],
  admin:[
    {id:"system",label:"System Administration",hint:"Platform health, runtime hardening, FIPS and governance settings",icon:Settings},
    {id:"tenant",label:"Tenant Administration",hint:"Tenant lifecycle, disable/delete workflow, and quorum-governed administration",icon:Building2},
    {id:"users",label:"User Management",hint:"User and group administration with role assignments",icon:Users},
    {id:"docs",label:"Documentation",hint:"Static component and capability documentation",icon:ScrollText}
  ]
};

export default function VectaDashboard(props){
  const {session:sessionBase,enabledFeatures,alerts,audit,unreadAlerts,onLogout,markAlertsRead}=props;
  const locationState=useMemo(()=>readDashboardLocationState(),[]);
  const restApiSessionFlag=useMemo(()=>{
    try{
      return sessionStorage.getItem("vecta_open_restapi")==="1";
    }catch{
      return false;
    }
  },[]);
  const restApiQueryMode=useMemo(()=>{
    try{
      const qp=new URLSearchParams(window.location.search);
      return qp.get("restapi")==="1"||restApiSessionFlag;
    }catch{
      return restApiSessionFlag;
    }
  },[restApiSessionFlag]);
  const initialTab=useMemo(()=>{
    const requestedTab=String(locationState.tab||"").trim();
    if(requestedTab&&Object.prototype.hasOwnProperty.call(TABS,requestedTab)){
      return requestedTab;
    }
    return restApiQueryMode?"workbench":"home";
  },[locationState.tab,restApiQueryMode]);
  const [tab,setTab]=useState(initialTab);
  const [collapsed,setCollapsed]=useState(false);
  const [t,setT]=useState(new Date());
  const [toast,setToast]=useState("");
  const [keyCatalog,setKeyCatalog]=useState([]);
  const [tagCatalog,setTagCatalog]=useState([]);
  const [subPaneSelection,setSubPaneSelection]=useState(()=>{
    const defaults={workbench:restApiQueryMode?"restapi":"crypto",dataprotection:"fieldenc",cloudctl:"byok",ekm:"db",certs:"cert-overview",hsm:"hsm-generic",cluster:"settings",admin:"system"};
    const requestedSub=String(locationState.sub||"").trim();
    if(requestedSub&&initialTab){
      return {...defaults,[initialTab]:requestedSub};
    }
    return defaults;
  });
  const [fipsMode,setFipsMode]=useState<"enabled"|"disabled">("disabled");
  const [reportedUnread,setReportedUnread]=useState(Number(unreadAlerts||0));
  const [tenantOptions,setTenantOptions]=useState<Array<{id:string;name:string;status?:string}>>([]);
  const [tenantScope,setTenantScope]=useState(String(sessionBase?.tenantId||""));
  const session=useMemo(()=>({
    ...sessionBase,
    tenantId:String(tenantScope||sessionBase?.tenantId||"").trim()||String(sessionBase?.tenantId||"")
  }),[sessionBase,tenantScope]);
  const restOnlyMode=restApiQueryMode;

  useEffect(()=>{
    setTenantScope(String(sessionBase?.tenantId||""));
  },[sessionBase?.tenantId,sessionBase?.token]);

  useEffect(()=>{
    if(!sessionBase?.token){
      setTenantOptions([]);
      return;
    }
    let cancelled=false;
    (async()=>{
      try{
        const items=await listAuthTenants(sessionBase);
        if(cancelled){
          return;
        }
        const rows=(Array.isArray(items)?items:[])
          .map((item:any)=>({
            id:String(item?.id||"").trim(),
            name:String(item?.name||item?.id||"").trim(),
            status:String(item?.status||"active").trim()
          }))
          .filter((item)=>Boolean(item.id));
        if(rows.length){
          const baseTenant=String(sessionBase?.tenantId||"").trim();
          const normalized=rows.some((item)=>item.id===baseTenant)
            ? rows
            : (baseTenant?[{id:baseTenant,name:baseTenant,status:"active"},...rows]:rows);
          setTenantOptions(normalized);
          const currentScope=String(tenantScope||"").trim();
          if(!currentScope){
            if(baseTenant){
              setTenantScope(baseTenant);
            }else if(normalized[0]?.id){
              setTenantScope(normalized[0].id);
            }
          }else if(!normalized.some((item)=>item.id===currentScope)){
            if(baseTenant){
              setTenantScope(baseTenant);
            }else if(normalized[0]?.id){
              setTenantScope(normalized[0].id);
            }
          }
          return;
        }
      }catch{
        // Fallback to token tenant when tenant catalog is not permitted.
      }
      if(!cancelled){
        const fallbackID=String(sessionBase?.tenantId||"").trim();
        setTenantOptions(fallbackID?[{id:fallbackID,name:fallbackID,status:"active"}]:[]);
        if(fallbackID){
          setTenantScope(fallbackID);
        }
      }
    })();
    return()=>{cancelled=true;};
  },[sessionBase?.token,sessionBase?.tenantId,tenantScope]);

  useEffect(()=>{
    const i=setInterval(()=>setT(new Date()),1000);
    return()=>clearInterval(i);
  },[]);

  useEffect(()=>{
    let stop=false;
    (async()=>{
      try{
        const items=await listKeys(session,{includeDeleted:true});
        if(!stop){
          setKeyCatalog(items.map(toViewKey));
        }
      }catch{
        // Keep customer-entered key names.
      }
      try{
        const tags=await listTags(session);
        if(!stop){
          setTagCatalog(tags);
        }
      }catch{
        // Tag catalog remains empty until admin refresh.
      }
      try{
        const out=await getGovernanceSystemState(session);
        if(!stop){
          setFipsMode(normalizeFipsModeValue(String(out?.state?.fips_mode||"disabled")));
        }
      }catch{
        if(!stop){
          setFipsMode("disabled");
        }
      }
    })();
    return()=>{stop=true;};
  },[session]);

  useEffect(()=>{
    if(!toast){
      return;
    }
    const id=setTimeout(()=>setToast(""),4000);
    return()=>clearTimeout(id);
  },[toast]);

  useEffect(()=>{
    if(!session?.token){
      setReportedUnread(0);
      return;
    }
    let cancelled=false;
    const pullUnread=async()=>{
      try{
        const counts=await getUnreadAlertCounts(session);
        if(cancelled){
          return;
        }
        const total=Object.values(counts||{}).reduce((sum,val)=>sum+Math.max(0,Number(val||0)),0);
        setReportedUnread(total);
      }catch{
        if(!cancelled){
          setReportedUnread(Number(unreadAlerts||0));
        }
      }
    };
    void pullUnread();
    const id=setInterval(()=>{void pullUnread();},10000);
    return()=>{
      cancelled=true;
      clearInterval(id);
    };
  },[session?.token,session?.tenantId,unreadAlerts]);

  const navGroups=useMemo(()=>NAV,[]);
  const visibleNavTabIDs=useMemo(
    ()=>navGroups.flatMap((g:any)=>Array.isArray(g?.items)?g.items.map((it:any)=>String(it?.id||"")).filter(Boolean):[]),
    [navGroups]
  );
  useEffect(()=>{
    const current=String(tab||"");
    if(visibleNavTabIDs.includes(current)){
      return;
    }
    setTab(String(visibleNavTabIDs[0]||"home"));
  },[tab,visibleNavTabIDs]);
  const allActiveSubPaneItems=Array.isArray((SUB_PANES as any)[tab])?(SUB_PANES as any)[tab]:[];
  const activeSubPaneItems=allActiveSubPaneItems.filter((item:any)=>canSeeFeature(item?.feature,enabledFeatures||new Set(),session));
  const selectedSubPaneRaw=String((subPaneSelection as any)[tab]||"");
  const activeSubPaneSelection=String(
    activeSubPaneItems.some((item:any)=>String(item.id)===selectedSubPaneRaw)
      ? selectedSubPaneRaw
      : (activeSubPaneItems[0]?.id||"")
  );
  const globalFipsEnabled=isFipsModeEnabled(fipsMode);
  useEffect(()=>{
    if(!restApiQueryMode){
      return;
    }
    try{
      sessionStorage.removeItem("vecta_open_restapi");
    }catch{
      // ignore storage errors
    }
  },[restApiQueryMode]);
  const openRestApiWindow=()=>{
    const url=new URL(window.location.href);
    url.pathname="/";
    url.search=`?${DASHBOARD_TAB_QUERY_KEY}=workbench&${DASHBOARD_SUB_QUERY_KEY}=restapi`;
    url.hash="";
    const opened=window.open(url.toString(),"_blank");
    if(!opened){
      // Popup blocked fallback: open in current tab.
      window.location.assign(url.toString());
    }
  };
  const selectTab=(nextTab:string)=>{
    setTab(nextTab);
    const paneItems=(Array.isArray((SUB_PANES as any)[nextTab])?(SUB_PANES as any)[nextTab]:[])
      .filter((item:any)=>canSeeFeature(item?.feature,enabledFeatures||new Set(),session));
    if(paneItems.length){
      setSubPaneSelection((prev:any)=>({
        ...prev,
        [nextTab]:String(prev?.[nextTab]||paneItems[0].id)
      }));
    }
  };

  useEffect(()=>{
    if(restOnlyMode){
      return;
    }
    try{
      const currentTab=String(tab||"").trim();
      if(!currentTab){
        return;
      }
      const qp=new URLSearchParams(window.location.search);
      qp.set(DASHBOARD_TAB_QUERY_KEY,currentTab);
      const currentSub=String(activeSubPaneSelection||"").trim();
      if(currentSub){
        qp.set(DASHBOARD_SUB_QUERY_KEY,currentSub);
      }else{
        qp.delete(DASHBOARD_SUB_QUERY_KEY);
      }
      qp.delete("restapi");
      const qs=qp.toString();
      const nextURL=qs?`${window.location.pathname}?${qs}`:window.location.pathname;
      const currentURL=`${window.location.pathname}${window.location.search}`;
      if(nextURL!==currentURL){
        window.history.replaceState(window.history.state,"",nextURL);
      }
    }catch{
      // Ignore URL/state sync errors.
    }
  },[activeSubPaneSelection,restOnlyMode,tab]);

  const openCliFromHeader=()=>{
    try{
      localStorage.setItem(SYSTEM_ADMIN_OPEN_CLI_KEY,"1");
    }catch{
      // ignore storage errors
    }
    setSubPaneSelection((prev:any)=>({...prev,admin:"system"}));
    selectTab("admin");
  };

  const Tab=TABS[tab]||Home;
  if(restOnlyMode){
    return(
      <div style={{minHeight:"100vh",background:C.bg,fontFamily:"'IBM Plex Sans',-apple-system,sans-serif",color:C.text,display:"flex",flexDirection:"column"}}>
        <style>{`@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
          @keyframes syncDotPulseLive{0%,100%{opacity:.95;transform:scale(1)}50%{opacity:.52;transform:scale(.8)}}
          @keyframes syncDotPulseWarn{0%,100%{opacity:.9;transform:scale(1)}50%{opacity:.62;transform:scale(.86)}}
          .sync-dot{display:inline-block;transform-origin:center}
          .sync-dot--online{animation:syncDotPulseLive 1.8s ease-in-out infinite}
          .sync-dot--degraded{animation:syncDotPulseWarn 2.4s ease-in-out infinite}
          .sync-dot--down{animation:none;opacity:.95}
          .sync-dot--unknown{animation:none;opacity:.65}
          *::-webkit-scrollbar{width:5px;height:5px} *::-webkit-scrollbar-track{background:transparent} *::-webkit-scrollbar-thumb{background:${C.border};border-radius:3px}`}</style>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"0 20px",height:48,borderBottom:`1px solid ${C.border}`,background:C.surface}}>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <div style={{width:24,height:24,borderRadius:6,background:`linear-gradient(135deg,${C.accent},${C.purple})`,display:"inline-flex",alignItems:"center",justifyContent:"center",fontSize:12,fontWeight:700,color:C.bg}}>V</div>
            <span style={{fontSize:13,fontWeight:700,letterSpacing:.3}}>VECTA KMS - REST API</span>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <B c={globalFipsEnabled?"green":"blue"} pulse={globalFipsEnabled}>{globalFipsEnabled?"FIPS STRICT":"STANDARD MODE"}</B>
            <div style={{display:"flex",alignItems:"center",gap:6}}>
              <span style={{fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:.8}}>Tenant</span>
              <Sel
                w={180}
                value={String(session?.tenantId||"")}
                onChange={(e)=>setTenantScope(String(e.target.value||""))}
                style={{height:28,borderRadius:8,padding:"4px 24px 4px 8px",fontSize:10}}
              >
                {(Array.isArray(tenantOptions)&&tenantOptions.length?tenantOptions:[{id:String(session?.tenantId||""),name:String(session?.tenantId||""),status:"active"}])
                  .filter((item:any)=>Boolean(String(item?.id||"").trim()))
                  .map((item:any)=><option key={String(item.id)} value={String(item.id)}>{`${String(item.name||item.id)} (${String(item.id)})`}</option>)}
              </Sel>
            </div>
            <Btn small onClick={()=>window.location.href=window.location.pathname}>Open Full UI</Btn>
            <Btn small onClick={onLogout}>Logout</Btn>
          </div>
        </div>
        <div style={{flex:1,overflowY:"auto",padding:16}}>
          <TabErrorBoundary resetKey="restapi">
            <RestAPI
              session={session}
              keyCatalog={keyCatalog}
              onToast={setToast}
            />
          </TabErrorBoundary>
        </div>
        {toast&&<div style={{position:"fixed",right:16,bottom:16,background:C.surface,border:`1px solid ${C.borderHi}`,borderRadius:8,padding:"10px 12px",fontSize:11,color:C.text,zIndex:1200,maxWidth:380}}>{toast}</div>}
      </div>
    );
  }
  return(
    <div style={{display:"flex",height:"100vh",background:C.bg,fontFamily:"'IBM Plex Sans',-apple-system,sans-serif",color:C.text,overflow:"hidden"}}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}
        @keyframes syncDotPulseLive{0%,100%{opacity:.95;transform:scale(1)}50%{opacity:.52;transform:scale(.8)}}
        @keyframes syncDotPulseWarn{0%,100%{opacity:.9;transform:scale(1)}50%{opacity:.62;transform:scale(.86)}}
        .sync-dot{display:inline-block;transform-origin:center}
        .sync-dot--online{animation:syncDotPulseLive 1.8s ease-in-out infinite}
        .sync-dot--degraded{animation:syncDotPulseWarn 2.4s ease-in-out infinite}
        .sync-dot--down{animation:none;opacity:.95}
        .sync-dot--unknown{animation:none;opacity:.65}
        *::-webkit-scrollbar{width:5px;height:5px} *::-webkit-scrollbar-track{background:transparent} *::-webkit-scrollbar-thumb{background:${C.border};border-radius:3px}`}</style>
      <div style={{width:collapsed?56:210,background:C.sidebar,borderRight:`1px solid ${C.border}`,display:"flex",flexDirection:"column",transition:"width .2s",flexShrink:0,overflow:"hidden"}}>
        <div style={{padding:collapsed?"8px 6px":"8px 10px 8px 14px",borderBottom:`1px solid ${C.border}`,display:"flex",alignItems:"center",gap:collapsed?6:8,minHeight:collapsed?66:44,justifyContent:collapsed?"center":"space-between",flexDirection:collapsed?"column":"row"}}>
          <div style={{display:"flex",alignItems:"center",gap:8,minWidth:0,justifyContent:"center",width:collapsed?"100%":"auto"}}>
          <div style={{width:28,height:28,borderRadius:7,background:`linear-gradient(135deg,${C.accent},${C.purple})`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:14,fontWeight:700,color:C.bg,flexShrink:0}}>V</div>
          {!collapsed&&<span style={{fontSize:13,fontWeight:700,letterSpacing:1.5,color:C.text}}>VECTA KMS</span>}
          </div>
          <button
            onClick={()=>setCollapsed((v)=>!v)}
            title={collapsed?"Expand sidebar":"Collapse sidebar"}
            style={{
              width:collapsed?20:24,
              height:collapsed?20:24,
              borderRadius:6,
              border:`1px solid ${C.border}`,
              background:"transparent",
              color:C.dim,
              display:"inline-flex",
              alignItems:"center",
              justifyContent:"center",
              cursor:"pointer",
              flexShrink:0
            }}
          >
            {collapsed?<ChevronsRight size={13} strokeWidth={2}/>:<ChevronsLeft size={13} strokeWidth={2}/>}
          </button>
        </div>
        <div style={{flex:1,overflowY:"auto",padding:"6px 0"}}>
          {navGroups.map(g=><div key={g.g}>
            {!collapsed&&<div style={{padding:"8px 14px 3px",fontSize:8,fontWeight:700,color:C.muted,textTransform:"uppercase",letterSpacing:1.5}}>{g.g}</div>}
            {g.items.map(it=><div key={it.id} onClick={()=>{
              if(it.id==="restapi"){
                openRestApiWindow();
                return;
              }
              selectTab(it.id);
            }} style={{display:"flex",alignItems:"center",gap:8,padding:collapsed?"8px":"6px 14px",cursor:"pointer",background:tab===it.id?C.accentDim:"transparent",borderLeft:tab===it.id?`2px solid ${C.accent}`:"2px solid transparent",transition:"all .15s"}} title={it.label}>
              <span style={{display:"inline-flex",alignItems:"center",justifyContent:collapsed?"center":"flex-start",color:tab===it.id?C.text:C.dim,flexShrink:0,width:collapsed?"100%":"auto"}}>
                <it.icon size={collapsed?16:14} strokeWidth={2}/>
              </span>
              {!collapsed&&<span style={{fontSize:11,color:tab===it.id?C.text:C.dim,fontWeight:tab===it.id?600:400,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{it.label}</span>}
            </div>)}
          </div>)}
        </div>
      </div>
      <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"0 20px",height:44,borderBottom:`1px solid ${C.border}`,flexShrink:0,background:C.surface}}>
          <span style={{fontSize:14,fontWeight:700,color:C.text,letterSpacing:-.3}}>{TITLES[tab]}</span>
          <div style={{display:"flex",alignItems:"center",gap:12}}>
            <B c={globalFipsEnabled?"green":"blue"} pulse={globalFipsEnabled}>{globalFipsEnabled?"FIPS STRICT":"STANDARD MODE"}</B>
            <div style={{display:"flex",alignItems:"center",gap:6}}>
              <span style={{fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:.8}}>Tenant</span>
              <Sel
                w={170}
                value={String(session?.tenantId||"")}
                onChange={(e)=>setTenantScope(String(e.target.value||""))}
                style={{height:28,borderRadius:8,padding:"4px 24px 4px 8px",fontSize:10}}
              >
                {(Array.isArray(tenantOptions)&&tenantOptions.length?tenantOptions:[{id:String(session?.tenantId||""),name:String(session?.tenantId||""),status:"active"}])
                  .filter((item:any)=>Boolean(String(item?.id||"").trim()))
                  .map((item:any)=><option key={String(item.id)} value={String(item.id)}>{`${String(item.name||item.id)} (${String(item.id)})`}</option>)}
              </Sel>
            </div>
            <Btn small onClick={openCliFromHeader}>CLI</Btn>
            <span style={{fontSize:11,color:C.accent,fontFamily:"'JetBrains Mono',monospace"}}>{t.toLocaleTimeString()}</span>
            <span style={{fontSize:9,color:C.muted,fontFamily:"'JetBrains Mono',monospace"}}>{UI_BUILD_ID}</span>
            <span onClick={()=>{
              selectTab("alerts");
              markAlertsRead?.();
            }} style={{display:"inline-flex",alignItems:"center",justifyContent:"center",cursor:"pointer",position:"relative",color:C.dim}}>
              <Bell size={14} strokeWidth={2}/>
              <span style={{position:"absolute",top:-4,right:-6,background:C.red,color:C.white,fontSize:8,borderRadius:6,padding:"1px 4px",fontWeight:700}}>{String(reportedUnread||0)}</span>
            </span>
            <div style={{width:26,height:26,borderRadius:6,background:C.accentDim,display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,fontWeight:700,color:C.accent}}>{(session?.username||"NA").slice(0,2).toUpperCase()}</div>
            <Btn small onClick={onLogout}>Logout</Btn>
          </div>
        </div>
        <div style={{flex:1,display:"flex",overflow:"hidden"}}>
          {activeSubPaneItems.length>0&&<div style={{width:220,flexShrink:0,background:C.surface,borderRight:`1px solid ${C.border}`,padding:"12px 10px",overflowY:"auto"}}>
            <div style={{fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1,marginBottom:10}}>{`${TITLES[tab]} Modules`}</div>
            <div style={{display:"grid",gap:6}}>
              {activeSubPaneItems.map((item:any)=>{
                const isActive=String(activeSubPaneSelection)===String(item.id);
                const ItemIcon=item.icon||null;
                return(
                  <div
                    key={String(item.id)}
                    onClick={()=>{
                      if(tab==="workbench"&&String(item.id)==="restapi"){
                        openRestApiWindow();
                        return;
                      }
                      setSubPaneSelection((prev:any)=>({...prev,[tab]:String(item.id)}));
                    }}
                    style={{
                      border:`1px solid ${isActive?C.accent:C.border}`,
                      background:isActive?C.accentDim:"transparent",
                      borderRadius:8,
                      padding:"10px 10px",
                      cursor:"pointer"
                    }}
                  >
                    <div style={{display:"flex",alignItems:"center",gap:8}}>
                      {ItemIcon&&<span style={{
                        width:20,
                        height:20,
                        borderRadius:999,
                        border:`1px solid ${isActive?C.accent:C.border}`,
                        background:isActive?C.accentDim:"transparent",
                        display:"inline-flex",
                        alignItems:"center",
                        justifyContent:"center",
                        color:isActive?C.accent:C.dim
                      }}><ItemIcon size={12} strokeWidth={2}/></span>}
                      <div style={{fontSize:11,color:isActive?C.text:C.dim,fontWeight:isActive?700:600,lineHeight:1.2}}>{String(item.label||item.id)}</div>
                    </div>
                    {item.hint&&<div style={{fontSize:9,color:C.muted,marginTop:4,lineHeight:1.3}}>{String(item.hint)}</div>}
                  </div>
                );
              })}
            </div>
          </div>}
          <div style={{flex:1,overflowY:"auto",padding:16}}>
            <TabErrorBoundary resetKey={`${tab}:${activeSubPaneSelection}`}>
              <Tab
                session={session}
                keyCatalog={keyCatalog}
                setKeyCatalog={setKeyCatalog}
                tagCatalog={tagCatalog}
                setTagCatalog={setTagCatalog}
                alerts={alerts}
                audit={audit}
                onToast={setToast}
                onLogout={onLogout}
                fipsMode={fipsMode}
                onFipsModeChange={setFipsMode}
                onUnreadSync={setReportedUnread}
                subView={activeSubPaneSelection}
                onSubViewChange={(next:string)=>setSubPaneSelection((prev:any)=>({...prev,[tab]:String(next||"")}))}
              />
            </TabErrorBoundary>
          </div>
        </div>
        {toast&&<div style={{position:"fixed",right:16,bottom:16,background:C.surface,border:`1px solid ${C.borderHi}`,borderRadius:8,padding:"10px 12px",fontSize:11,color:C.text,zIndex:1200,maxWidth:380}}>{toast}</div>}
      </div>
    </div>
  );
}







































