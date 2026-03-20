import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  getAuthCLIHSMConfig,
  getAuthCLIStatus,
  getAuthPasswordPolicy,
  getAuthSecurityPolicy,
  getAuthSystemHealth,
  listAuthCLIHSMPartitions,
  openAuthCLISession,
  restartAuthSystemService,
  updateAuthPasswordPolicy,
  updateAuthSecurityPolicy,
  upsertAuthCLIHSMConfig,
  type AuthSystemHealthSnapshot,
  type CLIHSMPartitionSlot,
  type CLIStatus,
  type HSMProviderConfig
} from "../../lib/authAdmin";
import {
  getCertSecurityStatus,
  listCAs,
  listCertificates,
  type CertCA,
  type CertificateItem
} from "../../lib/certs";
import {
  createGovernanceBackup,
  deleteGovernanceBackup,
  downloadGovernanceBackupArtifact,
  downloadGovernanceBackupKey,
  getGovernanceSystemState,
  getGovernanceSettings,
  listGovernanceBackups,
  patchGovernanceSystemState,
  restoreGovernanceBackup,
  testGovernanceSystemSNMP,
  testGovernanceSMTP,
  testGovernanceWebhook,
  updateGovernanceSettings,
  listGovernancePolicies,
  createGovernancePolicy,
  updateGovernancePolicy,
  applyNetworkConfig,
  type GovernanceBackupJob,
  type GovernanceSettings
} from "../../lib/governance";
import {
  listReportingRules,
  createReportingRule,
  updateReportingRule,
  deleteReportingRule,
  listReportingChannels,
  type ReportingAlertRule
} from "../../lib/reporting";
import {
  B,
  Btn,
  Card,
  Chk,
  FG,
  Inp,
  Modal,
  Row2,
  Row3,
  Section,
  Sel,
  Stat,
  Tabs,
  usePromptDialog
} from "../../components/v3/legacyPrimitives";
import {
  deleteKeyInterfacePort,
  deleteTag,
  getKeyAccessSettings,
  getKeyInterfaceTLSConfig,
  listKeyInterfacePorts,
  listTags,
  updateKeyInterfaceTLSConfig,
  updateKeyAccessSettings,
  upsertKeyInterfacePort,
  upsertTag,
  type KeyInterfaceTLSConfig
} from "../../lib/keycore";
import { errMsg } from "../../components/v3/runtimeUtils";
import { C } from "../../components/v3/theme";
import type { AdminTabProps } from "./types";
import {
  getFDEStatus,
  runFDEIntegrityCheck,
  rotateFDEVolumeKey,
  testFDERecoveryShares,
  getFDERecoveryShareStatus,
  type FDEStatus as FDEStatusT
} from "../../lib/fde";

const tone=(status:string):"green"|"amber"|"red"|"blue"=>{
  const s=String(status||"").toLowerCase();
  if(s==="running") return "green";
  if(s==="restarting") return "amber";
  if(s==="degraded") return "amber";
  if(s==="down") return "red";
  return "blue";
};

const heartbeatToneClass=(status:string):string=>{
  const s=String(status||"").toLowerCase();
  if(s==="running") return "vecta-hb-running";
  if(s==="restarting") return "vecta-hb-degraded";
  if(s==="degraded") return "vecta-hb-degraded";
  if(s==="down") return "vecta-hb-down";
  return "vecta-hb-unknown";
};

const interfaceTone=(status:string):"green"|"amber"|"red"|"blue"=>{
  const s=String(status||"").toLowerCase();
  if(s==="listening"||s==="running") return "green";
  if(s==="starting"||s==="restarting") return "amber";
  if(s==="stopped"||s==="down"||s==="failed"||s==="disabled"||s==="not detected") return "red";
  return "blue";
};

const RESTART_BLOCKED_TARGETS = new Set([
  "audit",
  "auth",
  "cluster-manager",
  "consul",
  "dashboard",
  "envoy",
  "etcd",
  "hsm-connector",
  "keycore",
  "nats",
  "policy",
  "postgres",
  "valkey"
]);

const toRestartTarget=(serviceName:string):string=>{
  const name=String(serviceName||"").trim().toLowerCase();
  if(!name) return "";
  if(name==="postgresql") return "postgres";
  if(name==="nats jetstream") return "nats";
  if(name==="valkey"||name==="consul"||name==="etcd"||name==="dashboard"||name==="envoy") return name;
  if(name.startsWith("kms-")){
    const raw=name.slice(4);
    return raw==="hyok-proxy"?"hyok":raw;
  }
  return name;
};

const restartAllowedFor=(service:{name?:string;restart_allowed?:boolean}):boolean=>{
  if(typeof service?.restart_allowed==="boolean") return service.restart_allowed;
  const target=toRestartTarget(String(service?.name||""));
  if(!target) return false;
  return !RESTART_BLOCKED_TARGETS.has(target);
};

const dl=(name:string,b64:string,type:string)=>{
  const raw=atob(String(b64||""));
  const bytes=new Uint8Array(raw.length);
  for(let i=0;i<raw.length;i+=1){bytes[i]=raw.charCodeAt(i);}  
  const blob=new Blob([bytes],{type:type||"application/octet-stream"});
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a");
  a.href=url; a.download=String(name||"download.bin");
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
};

const GOV_DEFAULT={
  approval_expiry_minutes:60,
  expiry_check_interval_seconds:60,
  approval_delivery_mode:"kms_only",
  notify_dashboard:true,
  notify_email:false,
  notify_slack:false,
  notify_teams:false,
  smtp_host:"",
  smtp_port:"587",
  smtp_username:"",
  smtp_password:"",
  smtp_from:"",
  smtp_starttls:true,
  slack_webhook_url:"",
  teams_webhook_url:"",
  delivery_webhook_timeout_seconds:10,
  challenge_response_enabled:false
};

const HSM_DEFAULT:Partial<HSMProviderConfig>={
  provider_name:"generic-pkcs11",
  integration_service:"",
  library_path:"",
  slot_id:"",
  partition_label:"",
  token_label:"",
  pin_env_var:"HSM_PIN",
  read_only:true,
  enabled:false
};

const BACKUP_ARTIFACT_EXTENSION = ".vbk";
const BACKUP_KEY_EXTENSION = ".key.json";

const fileToBase64 = (file: File): Promise<string> =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("failed to read file"));
    reader.onload = () => {
      const raw = String(reader.result || "");
      const idx = raw.indexOf(",");
      resolve(idx >= 0 ? raw.slice(idx + 1) : raw);
    };
    reader.readAsDataURL(file);
  });

const formatBackupFileSize = (bytes: number): string => {
  const size = Math.max(0, Number(bytes || 0));
  if (size >= 1024 * 1024) {
    return `${(size / (1024 * 1024)).toFixed(1).replace(/\.0$/, "")} MB`;
  }
  if (size >= 1024) {
    return `${Math.max(1, Math.round(size / 1024))} KB`;
  }
  return `${size} B`;
};

const BackupRestoreFilePicker = ({
  accept,
  file,
  onFileChange,
  emptyLabel,
  hint
}: {
  accept: string;
  file: File | null;
  onFileChange: (file: File | null) => void;
  emptyLabel: string;
  hint: string;
}) => {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const hasFile = Boolean(file);

  return (
    <div style={{ display: "grid", gap: 8 }}>
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        onChange={(e) => onFileChange((e.target.files && e.target.files[0]) ? e.target.files[0] : null)}
        style={{ display: "none" }}
      />
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          minHeight: 72,
          padding: "12px 14px",
          borderRadius: 12,
          border: `1px solid ${hasFile ? C.accent : C.borderHi}`,
          background: hasFile
            ? `linear-gradient(135deg, ${C.accentDim}, ${C.blueDim})`
            : `linear-gradient(180deg, ${C.surface}, ${C.bg})`,
          boxShadow: hasFile
            ? `0 0 0 1px ${C.glow} inset, 0 12px 28px rgba(2,8,23,.35)`
            : `0 10px 22px rgba(2,8,23,.22)`,
          boxSizing: "border-box"
        }}
      >
        <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
          <Btn
            type="button"
            small
            primary
            onClick={() => inputRef.current?.click()}
            style={{
              padding: "8px 14px",
              borderRadius: 10,
              boxShadow: `0 0 18px ${C.glowStrong}`
            }}
          >
            {hasFile ? "Replace" : "Upload"}
          </Btn>
          {hasFile ? (
            <Btn
              type="button"
              small
              onClick={() => {
                onFileChange(null);
                if (inputRef.current) {
                  inputRef.current.value = "";
                }
              }}
              style={{
                borderColor: C.borderHi,
                color: C.dim,
                background: "rgba(15,21,33,.72)",
                borderRadius: 10,
                padding: "8px 12px"
              }}
            >
              Clear
            </Btn>
          ) : null}
        </div>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div
            style={{
              fontSize: 11,
              color: hasFile ? C.text : C.dim,
              fontWeight: hasFile ? 700 : 500,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap"
            }}
          >
            {hasFile ? file?.name : emptyLabel}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6, flexWrap: "wrap" }}>
            <B c={hasFile ? "accent" : "blue"}>{hasFile ? formatBackupFileSize(file?.size || 0) : accept}</B>
            <span style={{ fontSize: 9, color: C.muted }}>{hint}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

const SYSTEM_STATE_DEFAULT = {
  fips_mode: "disabled",
  fips_mode_policy: "standard",
  fips_tls_profile: "tls1.2_fips",
  fips_rng_mode: "ctr_drbg",
  fips_entropy_source: "software",
  mgmt_ip: "",
  cluster_ip: "",
  dns_servers: "",
  ntp_servers: "",
  tls_mode: "internal_ca",
  backup_schedule: "daily@02:00",
  backup_target: "local",
  backup_retention_days: 30,
  backup_encrypted: true,
  proxy_endpoint: "",
  snmp_target: "",
  snmp_transport: "udp",
  snmp_host: "",
  snmp_port: 162,
  snmp_version: "v2c",
  snmp_community: "public",
  snmp_timeout_sec: 3,
  snmp_retries: 1,
  snmp_trap_oid: ".1.3.6.1.4.1.53864.1.0.1",
  snmp_v3_user: "",
  snmp_v3_security_level: "authPriv",
  snmp_v3_auth_proto: "sha256",
  snmp_v3_auth_pass: "",
  snmp_v3_priv_proto: "aes",
  snmp_v3_priv_pass: "",
  snmp_siem_vendor: "",
  snmp_siem_source: "vecta-kms",
  snmp_siem_facility: "security",
  posture_force_quorum_destructive_ops: false,
  posture_require_step_up_auth: false,
  posture_pause_connector_sync: false,
  posture_guardrail_policy_required: false
};

const INTERFACE_TLS_CONFIG_DEFAULT: KeyInterfaceTLSConfig = {
  tenant_id: "",
  certificate_source: "internal_ca",
  ca_id: "",
  certificate_id: ""
};

type ConfigurableInterfaceDefinition = {
  key: string;
  label: string;
  description: string;
  service: string;
  defaultBindAddress: string;
  defaultPort: number;
  defaultProtocol: InterfaceProtocol;
  defaultCertSource: InterfaceCertSource;
  allowedProtocols: InterfaceProtocol[];
};

type InterfaceProtocol = "http" | "https" | "tls13" | "mtls" | "tcp";
type InterfaceCertSource = "none" | "internal_ca" | "pki_ca" | "uploaded_certificate";
type InterfacePQCMode = "inherit" | "classical" | "hybrid" | "pqc_only";
type InterfaceTLSBinding = {
  certSource: InterfaceCertSource;
  caID: string;
  certificateID: string;
};

const INTERFACE_PROTOCOL_LABELS: Record<InterfaceProtocol, string> = {
  http: "HTTP",
  https: "HTTPS",
  tls13: "TLS 1.3",
  mtls: "Mutual TLS (mTLS)",
  tcp: "TCP"
};

const INTERFACE_CERT_SOURCE_LABELS: Record<InterfaceCertSource, string> = {
  none: "None",
  internal_ca: "Internal CA (auto-issue)",
  pki_ca: "CA from Certificates / PKI",
  uploaded_certificate: "Uploaded certificate from PKI"
};

const INTERFACE_PQC_MODE_LABELS: Record<InterfacePQCMode, string> = {
  inherit: "Inherit PQC Policy",
  classical: "Classical Only",
  hybrid: "Hybrid PQC",
  pqc_only: "PQC Only"
};

const TLS_CERT_MODE_OPTIONS: Array<{ value: InterfaceCertSource; label: string }> = [
  { value: "internal_ca", label: INTERFACE_CERT_SOURCE_LABELS.internal_ca },
  { value: "pki_ca", label: INTERFACE_CERT_SOURCE_LABELS.pki_ca },
  { value: "uploaded_certificate", label: INTERFACE_CERT_SOURCE_LABELS.uploaded_certificate }
];

const interfaceProtocolUsesCertificate = (protocol:string): boolean => {
  const value = String(protocol || "").trim().toLowerCase();
  return value==="https" || value==="tls13" || value==="mtls";
};

const normalizeInterfacePQCMode = (raw:string, protocol:string): InterfacePQCMode => {
  if(!interfaceProtocolUsesCertificate(protocol)){
    return "classical";
  }
  switch(String(raw || "").trim().toLowerCase()){
    case "":
    case "inherit":
    case "default":
      return "inherit";
    case "classical":
    case "legacy":
      return "classical";
    case "hybrid":
      return "hybrid";
    case "pqc":
    case "pqc_only":
    case "pqc-only":
      return "pqc_only";
    default:
      return "inherit";
  }
};

const normalizeInterfaceProtocol = (raw:string, fallback: InterfaceProtocol = "http"): InterfaceProtocol => {
  const value = String(raw || "").trim().toLowerCase();
  switch (value) {
    case "http":
      return "http";
    case "https":
      return "https";
    case "tls":
    case "tls13":
    case "tls-1.3":
    case "tls_1_3":
      return "tls13";
    case "mtls":
    case "m-tls":
    case "mutual-tls":
      return "mtls";
    case "tcp":
      return "tcp";
    default:
      return fallback;
  }
};

const normalizeInterfaceCertSource = (raw:string, protocol:string, fallback: InterfaceCertSource = "internal_ca"): InterfaceCertSource => {
  if(!interfaceProtocolUsesCertificate(protocol)){
    return "none";
  }
  const value = String(raw || "").trim().toLowerCase();
  switch (value) {
    case "":
    case "internal":
    case "internal-ca":
    case "internal_ca":
    case "auto":
      return "internal_ca";
    case "pki":
    case "ca":
    case "pki-ca":
    case "pki_ca":
      return "pki_ca";
    case "uploaded":
    case "certificate":
    case "uploaded-certificate":
    case "uploaded_certificate":
    case "external":
      return "uploaded_certificate";
    default:
      return fallback;
  }
};

const buildInterfaceTLSBinding = (
  protocol:string,
  certSourceRaw:string,
  caIDRaw:string,
  certificateIDRaw:string,
  fallback: InterfaceCertSource = "internal_ca"
): InterfaceTLSBinding => {
  const certSource = normalizeInterfaceCertSource(certSourceRaw, protocol, fallback);
  return {
    certSource,
    caID: certSource==="pki_ca" ? String(caIDRaw || "").trim() : "",
    certificateID: certSource==="uploaded_certificate" ? String(certificateIDRaw || "").trim() : ""
  };
};

const tlsBindingSignature = (binding: InterfaceTLSBinding): string => (
  `${binding.certSource}|${binding.caID}|${binding.certificateID}`
);

const CONFIGURABLE_INTERFACE_DEFS: ConfigurableInterfaceDefinition[] = [
  {
    key: "dashboard-ui",
    label: "dashboard-ui",
    description: "Direct Web Dashboard UI",
    service: "dashboard",
    defaultBindAddress: "0.0.0.0",
    defaultPort: 5173,
    defaultProtocol: "http",
    defaultCertSource: "none",
    allowedProtocols: ["http","https"]
  },
  {
    key: "rest",
    label: "rest-api",
    description: "Primary REST API",
    service: "envoy",
    defaultBindAddress: "0.0.0.0",
    defaultPort: 443,
    defaultProtocol: "https",
    defaultCertSource: "internal_ca",
    allowedProtocols: ["https","tls13","mtls"]
  },
  {
    key: "kmip",
    label: "kmip-tls",
    description: "KMIP Protocol Interface",
    service: "kmip",
    defaultBindAddress: "0.0.0.0",
    defaultPort: 5696,
    defaultProtocol: "mtls",
    defaultCertSource: "internal_ca",
    allowedProtocols: ["tls13","mtls"]
  },
  {
    key: "ekm",
    label: "ekm-data",
    description: "EKM / TDE Endpoint",
    service: "ekm",
    defaultBindAddress: "0.0.0.0",
    defaultPort: 8130,
    defaultProtocol: "http",
    defaultCertSource: "none",
    allowedProtocols: ["http","https","tls13"]
  },
  {
    key: "payment-tcp",
    label: "payment-tcp",
    description: "Payment Crypto TCP",
    service: "payment",
    defaultBindAddress: "0.0.0.0",
    defaultPort: 9170,
    defaultProtocol: "tcp",
    defaultCertSource: "none",
    allowedProtocols: ["tcp"]
  },
  {
    key: "hyok",
    label: "hyok-api",
    description: "HYOK API",
    service: "hyok",
    defaultBindAddress: "0.0.0.0",
    defaultPort: 8120,
    defaultProtocol: "http",
    defaultCertSource: "none",
    allowedProtocols: ["http","https","tls13"]
  }
];

const INTERFACE_OPTIONS = CONFIGURABLE_INTERFACE_DEFS.map((item)=>item.key);
const INTERFACE_DEF_MAP = CONFIGURABLE_INTERFACE_DEFS.reduce<Record<string, ConfigurableInterfaceDefinition>>((acc, item)=>{
  acc[item.key] = item;
  return acc;
}, {});
const INTERFACE_ORDER = CONFIGURABLE_INTERFACE_DEFS.reduce<Record<string, number>>((acc, item, index)=>{
  acc[item.key] = index;
  return acc;
}, {});

const normalizeConfigurableInterfaceName = (raw:string): string => {
  const value = String(raw || "").trim().toLowerCase().replace(/_/g, "-");
  switch (value) {
    case "dashboard":
    case "dashboard-ui":
    case "dashboard-ui-http":
      return "dashboard-ui";
    case "rest":
    case "api":
    case "rest-api":
      return "rest";
    case "kmip":
    case "kmip-tls":
      return "kmip";
    case "ekm":
    case "tde":
    case "ekm-data":
      return "ekm";
    case "payment":
    case "paymenttcp":
    case "payment-tcp":
    case "paytcp":
      return "payment-tcp";
    case "hyok":
    case "hyok-api":
      return "hyok";
    default:
      return value;
  }
};

const interfaceStatusRank = (status:string):number => {
  const value = String(status || "").trim().toLowerCase();
  if (value === "listening" || value === "running") return 4;
  if (value === "starting" || value === "restarting") return 3;
  if (value === "configured" || value === "unknown") return 2;
  if (value === "disabled" || value === "stopped") return 1;
  return 0;
};

type SystemAdminPanel =
  | "health"
  | "runtime"
  | "network"
  | "snmp"
  | "license"
  | "tags"
  | "password"
  | "login"
  | "keyaccess"
  | "interfaces"
  | "platform"
  | "cli"
  | "governance"
  | "backup"
  | "alertrules"
  | "approvals"
  | "diskencryption";
const SYSTEM_ADMIN_OPEN_CLI_KEY = "vecta_system_admin_open_cli";
const SYSTEM_ADMIN_TABS: Array<{label:string;panel:SystemAdminPanel}> = [
  { label:"Health", panel:"health" },
  { label:"Runtime Crypto", panel:"runtime" },
  { label:"Network", panel:"network" },
  { label:"SNMP", panel:"snmp" },
  { label:"License", panel:"license" },
  { label:"Tags", panel:"tags" },
  { label:"Password Policy", panel:"password" },
  { label:"Login Security", panel:"login" },
  { label:"Key Access Hardening", panel:"keyaccess" },
  { label:"Interfaces", panel:"interfaces" },
  { label:"CLI / HSM", panel:"cli" },
  { label:"Governance", panel:"governance" },
  { label:"Backup", panel:"backup" },
  { label:"Alert Rules", panel:"alertrules" },
  { label:"Approval Policies", panel:"approvals" },
  { label:"Disk Encryption", panel:"diskencryption" }
];

const parseSNMPTargetToState = (rawTarget:string): Record<string, any> => {
  const raw = String(rawTarget || "").trim();
  if (!raw) {
    return {};
  }
  try {
    const normalized = raw.includes("://") ? raw : `udp://${raw}`;
    const parsed = new URL(normalized);
    const q = parsed.searchParams;
    const versionRaw = String(q.get("version") || "v2c").toLowerCase();
    const isV3 = versionRaw === "3" || versionRaw === "v3";
    const version = isV3 ? "v3" : (versionRaw === "1" || versionRaw === "v1" ? "v1" : "v2c");
    return {
      snmp_transport: String(parsed.protocol || "udp:").replace(":", "") || "udp",
      snmp_host: String(parsed.hostname || ""),
      snmp_port: Number(parsed.port || 162),
      snmp_version: version,
      snmp_community: String(q.get("community") || "public"),
      snmp_timeout_sec: Math.max(1, Number(q.get("timeout_sec") || 3)),
      snmp_retries: Math.max(0, Number(q.get("retries") || 1)),
      snmp_trap_oid: String(q.get("trap_oid") || ".1.3.6.1.4.1.53864.1.0.1"),
      snmp_v3_user: String(q.get("user") || ""),
      snmp_v3_security_level: String(q.get("security_level") || "authPriv"),
      snmp_v3_auth_proto: String(q.get("auth_proto") || "sha256"),
      snmp_v3_auth_pass: String(q.get("auth_pass") || ""),
      snmp_v3_priv_proto: String(q.get("priv_proto") || "aes"),
      snmp_v3_priv_pass: String(q.get("priv_pass") || ""),
      snmp_siem_vendor: String(q.get("siem_vendor") || ""),
      snmp_siem_source: String(q.get("source") || "vecta-kms"),
      snmp_siem_facility: String(q.get("facility") || "security")
    };
  } catch {
    return {};
  }
};

const buildSNMPTargetFromState = (state: Record<string, any>): string => {
  const transport = String(state?.snmp_transport || "udp").toLowerCase();
  const host = String(state?.snmp_host || "").trim();
  const port = Math.max(1, Math.min(65535, Number(state?.snmp_port || 162)));
  if (!host) {
    return "";
  }
  const version = String(state?.snmp_version || "v2c").toLowerCase();
  const qp = new URLSearchParams();
  qp.set("version", version);
  qp.set("timeout_sec", String(Math.max(1, Number(state?.snmp_timeout_sec || 3))));
  qp.set("retries", String(Math.max(0, Number(state?.snmp_retries || 1))));
  qp.set("trap_oid", String(state?.snmp_trap_oid || ".1.3.6.1.4.1.53864.1.0.1"));
  const siemVendor = String(state?.snmp_siem_vendor || "").trim();
  const siemSource = String(state?.snmp_siem_source || "").trim();
  const siemFacility = String(state?.snmp_siem_facility || "").trim();
  if (siemVendor) qp.set("siem_vendor", siemVendor);
  if (siemSource) qp.set("source", siemSource);
  if (siemFacility) qp.set("facility", siemFacility);
  if (version === "v3") {
    qp.set("user", String(state?.snmp_v3_user || "").trim());
    qp.set("security_level", String(state?.snmp_v3_security_level || "authPriv"));
    qp.set("auth_proto", String(state?.snmp_v3_auth_proto || "sha256"));
    qp.set("auth_pass", String(state?.snmp_v3_auth_pass || ""));
    qp.set("priv_proto", String(state?.snmp_v3_priv_proto || "aes"));
    qp.set("priv_pass", String(state?.snmp_v3_priv_pass || ""));
  } else {
    qp.set("community", String(state?.snmp_community || "public"));
  }
  return `${transport}://${host}:${port}?${qp.toString()}`;
};

export const SystemAdminTab=({session,onToast,onLogout,fipsMode,onFipsModeChange,tagCatalog,setTagCatalog}:AdminTabProps)=>{
  const promptDialog=usePromptDialog();
  const [health,setHealth]=useState<AuthSystemHealthSnapshot>({services:[],summary:{}});
  const [healthLoading,setHealthLoading]=useState(false);
  const [restartBusy,setRestartBusy]=useState("");
  const [restartAllBusy,setRestartAllBusy]=useState(false);
  const [serviceStatusOverride,setServiceStatusOverride]=useState<Record<string,string>>({});

  const [gov,setGov]=useState(GOV_DEFAULT);
  const [govLoading,setGovLoading]=useState(false);
  const [govSaving,setGovSaving]=useState(false);
  const [smtpTo,setSmtpTo]=useState("");
  const [smtpTesting,setSmtpTesting]=useState(false);
  const [webhookTesting,setWebhookTesting]=useState<{slack:boolean;teams:boolean}>({slack:false,teams:false});
  const [systemState,setSystemState]=useState<Record<string,any>>(SYSTEM_STATE_DEFAULT);
  const [systemStateLoading,setSystemStateLoading]=useState(false);
  const [systemStateSaving,setSystemStateSaving]=useState(false);
  const [snmpTesting,setSnmpTesting]=useState(false);

  const [jobs,setJobs]=useState<GovernanceBackupJob[]>([]);
  const [jobsLoading,setJobsLoading]=useState(false);
  const [backupCreating,setBackupCreating]=useState(false);
  const [backupDeleting,setBackupDeleting]=useState("");
  const [backupDownloading,setBackupDownloading]=useState("");
  const [backupScope,setBackupScope]=useState<"system"|"tenant">("system");
  const [backupTenant,setBackupTenant]=useState("");
  const [backupBindToHsm,setBackupBindToHsm]=useState(true);
  const [backupRestoreArtifactFile,setBackupRestoreArtifactFile]=useState<File|null>(null);
  const [backupRestoreKeyFile,setBackupRestoreKeyFile]=useState<File|null>(null);
  const [backupRestoring,setBackupRestoring]=useState(false);

  const [cliStatus,setCliStatus]=useState<CLIStatus|null>(null);
  const [cliLoading,setCliLoading]=useState(false);
  const [cliUser,setCliUser]=useState("cli-user");
  const [cliPass,setCliPass]=useState("");
  const [cliOpening,setCliOpening]=useState(false);
  const [cliSession,setCliSession]=useState("");
  const [cliSsh,setCliSsh]=useState("");

  const [hsm,setHsm]=useState<Partial<HSMProviderConfig>>(HSM_DEFAULT);
  const [hsmLoading,setHsmLoading]=useState(false);
  const [hsmSaving,setHsmSaving]=useState(false);
  const [slots,setSlots]=useState<CLIHSMPartitionSlot[]>([]);
  const [slotsLoading,setSlotsLoading]=useState(false);
  const [slotHint,setSlotHint]=useState("");
  const [slotRaw,setSlotRaw]=useState("");
  const [panel,setPanel]=useState<SystemAdminPanel>("health");
  const [modal,setModal]=useState("");
  const [certSecurity,setCertSecurity]=useState<Record<string,any>|null>(null);
  const [certSecurityLoading,setCertSecurityLoading]=useState(false);
  const [passwordPolicy,setPasswordPolicy]=useState<Record<string,any>|null>(null);
  const [passwordPolicyLoading,setPasswordPolicyLoading]=useState(false);
  const [passwordPolicySaving,setPasswordPolicySaving]=useState(false);
  const [securityPolicy,setSecurityPolicy]=useState<Record<string,any>|null>(null);
  const [securityPolicyLoading,setSecurityPolicyLoading]=useState(false);
  const [securityPolicySaving,setSecurityPolicySaving]=useState(false);
  const INHERIT_KEY="vecta_sys_inheritance_policy";
  const [inheritancePolicy,setInheritancePolicyRaw]=useState<Record<string,string>>(()=>{
    try{return JSON.parse(localStorage.getItem(INHERIT_KEY)||"{}")||{};}catch{return {};}
  });
  const setInheritancePolicy=useCallback((next:Record<string,string>)=>{
    setInheritancePolicyRaw(next);
    try{localStorage.setItem(INHERIT_KEY,JSON.stringify(next));}catch{}
  },[]);
  const toggleScope=(key:string)=>{
    const cur=inheritancePolicy[key]||"kms_wide";
    setInheritancePolicy({...inheritancePolicy,[key]:cur==="kms_wide"?"tenant_specific":"kms_wide"});
  };
  const ScopeBanner=({section}:{section:string})=>{
    const isWide=(inheritancePolicy[section]||"kms_wide")==="kms_wide";
    return(
      <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:12,padding:"8px 14px",background:isWide?`${C.accent}18`:`${C.amber}18`,borderRadius:8,border:`1px solid ${isWide?C.accent:C.amber}44`}}>
        <span style={{fontSize:14}}>{isWide?"\u{1F512}":"\u{1F513}"}</span>
        <span style={{flex:1,fontSize:12,color:C.text}}>{isWide?"KMS-Wide (Uniform) — All tenants inherit these settings":"Tenant-Specific — Tenants may override these settings"}</span>
        <button onClick={()=>toggleScope(section)} style={{fontSize:11,padding:"4px 10px",borderRadius:6,border:`1px solid ${C.border}`,background:C.surface,color:C.text,cursor:"pointer"}}>{isWide?"Allow Tenant Override":"Enforce KMS-Wide"}</button>
      </div>
    );
  };
  const [accessSettings,setAccessSettings]=useState<Record<string,any>|null>(null);
  const [accessSettingsLoading,setAccessSettingsLoading]=useState(false);
  const [accessSettingsSaving,setAccessSettingsSaving]=useState(false);
  const [interfacePorts,setInterfacePorts]=useState<Array<Record<string,any>>>([]);
  const [interfaceConfigLoading,setInterfaceConfigLoading]=useState(false);
  const [interfaceTLSConfig,setInterfaceTLSConfig]=useState<KeyInterfaceTLSConfig>(INTERFACE_TLS_CONFIG_DEFAULT);
  const [interfaceTLSConfigLoading,setInterfaceTLSConfigLoading]=useState(false);
  type NetIface = {
    id: string;
    interface_name: string;
    name: string;
    description: string;
    service: string;
    protocol: InterfaceProtocol;
    protocol_label: string;
    pqc_mode: InterfacePQCMode;
    pqc_label: string;
    cert_source: InterfaceCertSource;
    cert_label: string;
    ca_id: string;
    certificate_id: string;
    auto_create_cert: boolean;
    bind_address: string;
    port: number;
    enabled: boolean;
    status: string;
    runtime_bind_address: string|undefined;
    runtime_port: number|undefined;
    runtime_source: string|undefined;
    updated_at: string|undefined;
  };
  const [netIfModalOpen,setNetIfModalOpen]=useState(false);
  const [editingNetIf,setEditingNetIf]=useState<NetIface|null>(null);
  const [ifName,setIfName]=useState(INTERFACE_OPTIONS[0] || "rest");
  const [ifDesc,setIfDesc]=useState("");
  const [ifProtocol,setIfProtocol]=useState<InterfaceProtocol>("https");
  const [ifPQCMode,setIfPQCMode]=useState<InterfacePQCMode>("inherit");
  const [ifCertSource,setIfCertSource]=useState<InterfaceCertSource>("internal_ca");
  const [ifCAID,setIfCAID]=useState("");
  const [ifCertificateID,setIfCertificateID]=useState("");
  const [ifBindAddr,setIfBindAddr]=useState("0.0.0.0");
  const [ifPort,setIfPort]=useState("443");
  const [ifEnabled,setIfEnabled]=useState(true);
  const [fipsConfigModalOpen,setFipsConfigModalOpen]=useState(false);
  const [tlsConfigModalOpen,setTlsConfigModalOpen]=useState(false);
  const [tlsCatalogLoading,setTlsCatalogLoading]=useState(false);
  const [caOptions,setCAOptions]=useState<CertCA[]>([]);
  const [certificateOptions,setCertificateOptions]=useState<CertificateItem[]>([]);

  // ── Disk Encryption state ──
  const [fdeStatus,setFdeStatus]=useState<FDEStatusT|null>(null);
  const [fdeLoading,setFdeLoading]=useState(false);
  const [fdeIntegrityRunning,setFdeIntegrityRunning]=useState(false);
  const [fdeKeyRotating,setFdeKeyRotating]=useState(false);
  const [fdeRecoveryTesting,setFdeRecoveryTesting]=useState(false);
  const [fdeRecoveryShares,setFdeRecoveryShares]=useState<any>(null);
  const [fdeTestShareInputs,setFdeTestShareInputs]=useState<string[]>([]);

  // ── Approval Policies state ──
  const ADMIN_OPS=["user.create","user.delete","user.role_change","tenant.create","tenant.disable","tenant.delete","system.backup","system.restore","system.config_change","hsm.config_change","governance.policy_change","license.update"];
  const KEY_OPS=["key.create","key.delete","key.rotate","key.export","key.import","key.bulk_delete","key.bulk_rotate","key.state_change","key.metadata_change","secret.create","secret.delete","secret.rotate","cert.create","cert.revoke","cert.ca_create","cert.enrollment"];
  const ALL_GOV_SCOPES=[{v:"keys",l:"Key Operations"},{v:"secrets",l:"Secret Operations"},{v:"certs",l:"Certificate Operations"},{v:"users",l:"User Management"},{v:"system",l:"System Administration"},{v:"all",l:"All Operations"}];
  const [govPolicies,setGovPolicies]=useState<any[]>([]);
  const [govPoliciesLoading,setGovPoliciesLoading]=useState(false);
  const [govPolicyModal,setGovPolicyModal]=useState(false);
  const [govEditPolicy,setGovEditPolicy]=useState<any>(null);
  const [gpName,setGpName]=useState("");
  const [gpDesc,setGpDesc]=useState("");
  const [gpScope,setGpScope]=useState("keys");
  const [gpTriggers,setGpTriggers]=useState<string[]>([]);
  const [gpQuorum,setGpQuorum]=useState("threshold");
  const [gpRequired,setGpRequired]=useState(2);
  const [gpTotal,setGpTotal]=useState(3);
  const [gpApprovers,setGpApprovers]=useState("");
  const [gpTimeout,setGpTimeout]=useState(48);
  const [gpRetry,setGpRetry]=useState(3);
  const [gpChannels,setGpChannels]=useState<string[]>(["dashboard"]);
  const [gpEnforceHold,setGpEnforceHold]=useState(true);
  const [gpStatus,setGpStatus]=useState("active");
  const [gpSaving,setGpSaving]=useState(false);

  const loadFDEStatus=useCallback(async()=>{
    if(!session?.token){setFdeStatus(null);return;}
    setFdeLoading(true);
    try{
      const [status,shares]=await Promise.all([getFDEStatus(session),getFDERecoveryShareStatus(session)]);
      setFdeStatus(status||null);
      setFdeRecoveryShares(shares||null);
    }catch(error){onToast(`FDE status load failed: ${errMsg(error)}`);}
    finally{setFdeLoading(false);}
  },[onToast,session]);

  const doFDEIntegrityCheck=useCallback(async()=>{
    if(!session?.token)return;
    setFdeIntegrityRunning(true);
    try{const r=await runFDEIntegrityCheck(session);onToast(r.passed?"Integrity check passed.":"Integrity check FAILED — review logs.");await loadFDEStatus();}
    catch(error){onToast(`Integrity check failed: ${errMsg(error)}`);}
    finally{setFdeIntegrityRunning(false);}
  },[loadFDEStatus,onToast,session]);

  const doFDERotateKey=useCallback(async()=>{
    if(!session?.token)return;
    setFdeKeyRotating(true);
    try{const r=await rotateFDEVolumeKey(session);onToast(`Key rotation started (job ${r.job_id}). Estimated ${r.estimated_duration_minutes} min.`);}
    catch(error){onToast(`Key rotation failed: ${errMsg(error)}`);}
    finally{setFdeKeyRotating(false);}
  },[onToast,session]);

  const doFDETestRecovery=useCallback(async()=>{
    if(!session?.token)return;
    const shares=fdeTestShareInputs.filter((s)=>s.trim());
    if(shares.length<(fdeRecoveryShares?.threshold||3)){onToast(`Provide at least ${fdeRecoveryShares?.threshold||3} shares.`);return;}
    setFdeRecoveryTesting(true);
    try{const r=await testFDERecoveryShares(session,shares);onToast(r.valid?"Recovery shares are VALID.":"Recovery shares are INVALID.");}
    catch(error){onToast(`Recovery test failed: ${errMsg(error)}`);}
    finally{setFdeRecoveryTesting(false);}
  },[fdeRecoveryShares?.threshold,fdeTestShareInputs,onToast,session]);

  const loadGovPolicies=useCallback(async()=>{
    if(!session?.token) return;
    setGovPoliciesLoading(true);
    try{const items=await listGovernancePolicies(session,{}); setGovPolicies(Array.isArray(items)?items:[]);}
    catch(error){onToast(`Policy load failed: ${errMsg(error)}`);}
    finally{setGovPoliciesLoading(false);}
  },[session,onToast]);

  const openGovPolicyModal=(policy?:any)=>{
    if(policy){
      setGovEditPolicy(policy);
      setGpName(policy.name||"");setGpDesc(policy.description||"");setGpScope(policy.scope||"keys");
      setGpTriggers(Array.isArray(policy.trigger_actions)?policy.trigger_actions:[]);
      setGpQuorum(policy.quorum_mode||"threshold");setGpRequired(policy.required_approvals||2);setGpTotal(policy.total_approvers||3);
      setGpApprovers((Array.isArray(policy.approver_users)?policy.approver_users:[]).join(", "));
      setGpTimeout(policy.timeout_hours||48);setGpChannels(Array.isArray(policy.notification_channels)?policy.notification_channels:["dashboard"]);
      setGpStatus(policy.status||"active");setGpEnforceHold(true);
    }else{
      setGovEditPolicy(null);setGpName("");setGpDesc("");setGpScope("keys");setGpTriggers([]);
      setGpQuorum("threshold");setGpRequired(2);setGpTotal(3);setGpApprovers("");setGpTimeout(48);
      setGpChannels(["dashboard"]);setGpStatus("active");setGpEnforceHold(true);
    }
    setGovPolicyModal(true);
  };

  const saveGovPolicy=async()=>{
    if(!session?.token) return;
    if(!gpName.trim()){onToast("Policy name is required.");return;}
    if(!gpTriggers.length){onToast("Select at least one trigger action.");return;}
    const approverList=String(gpApprovers||"").split(",").map((a)=>a.trim()).filter(Boolean);
    if(!approverList.length){onToast("At least one approver is required.");return;}
    setGpSaving(true);
    const payload={
      name:gpName.trim(),description:gpDesc.trim(),scope:gpScope,
      trigger_actions:gpTriggers,quorum_mode:gpQuorum,
      required_approvals:Math.max(1,gpRequired),total_approvers:Math.max(gpRequired,gpTotal),
      approver_users:approverList,timeout_hours:Math.max(1,gpTimeout),
      notification_channels:gpChannels,status:gpStatus
    };
    try{
      if(govEditPolicy){await updateGovernancePolicy(session,govEditPolicy.id,payload); onToast("Policy updated.");}
      else{await createGovernancePolicy(session,payload); onToast("Policy created.");}
      setGovPolicyModal(false);
      await loadGovPolicies();
    }catch(error){if(!sessionGuard(error)) onToast(`Policy save failed: ${errMsg(error)}`);}
    finally{setGpSaving(false);}
  };

  const toggleGpTrigger=(op:string)=>{setGpTriggers((prev)=>prev.includes(op)?prev.filter((t)=>t!==op):[...prev,op]);};
  const toggleGpChannel=(ch:string)=>{setGpChannels((prev)=>prev.includes(ch)?prev.filter((c)=>c!==ch):[...prev,ch]);};

  const [newTagName,setNewTagName]=useState("");
  const [newTagColor,setNewTagColor]=useState(C.teal);
  const [tagSaving,setTagSaving]=useState(false);
  const initialLoadTokenRef=useRef("");

  const [alertRules,setAlertRules]=useState<ReportingAlertRule[]>([]);
  const [alertRulesLoading,setAlertRulesLoading]=useState(false);
  const [ruleModalOpen,setRuleModalOpen]=useState(false);
  const [editingRule,setEditingRule]=useState<ReportingAlertRule|null>(null);
  const [ruleName,setRuleName]=useState("");
  const [ruleCondition,setRuleCondition]=useState<"threshold"|"expression">("threshold");
  const [rulePattern,setRulePattern]=useState("");
  const [ruleSeverity,setRuleSeverity]=useState("warning");
  const [ruleThreshold,setRuleThreshold]=useState(1);
  const [ruleWindowSeconds,setRuleWindowSeconds]=useState(300);
  const [ruleExpression,setRuleExpression]=useState("");
  const [ruleChannels,setRuleChannels]=useState<string[]>(["screen"]);
  const [ruleChannelsAvail,setRuleChannelsAvail]=useState<string[]>(["screen","email","slack","teams","webhook"]);
  const [ruleSaving,setRuleSaving]=useState(false);

  const isDeprecatedChannel=useCallback((name:string)=>{
    const n=String(name||"").trim().toLowerCase();
    return n==="pager"||n==="pagerduty";
  },[]);

  const sanitizeRuleChannels=useCallback((channels:string[])=>{
    return Array.from(new Set((Array.isArray(channels)?channels:[])
      .map((ch)=>String(ch||"").trim().toLowerCase())
      .filter((ch)=>Boolean(ch)&&!isDeprecatedChannel(ch))));
  },[isDeprecatedChannel]);

  const sessionGuard=useCallback((error:unknown)=>{
    const msg=errMsg(error).toLowerCase();
    if(msg.includes("invalid token")||msg.includes("unauthorized")){
      onToast("Session expired. Please login again.");
      onLogout();
      return true;
    }
    return false;
  },[onLogout,onToast]);

  const loadTLSCatalog=useCallback(async()=>{
    if(!session?.token){
      setCAOptions([]);
      setCertificateOptions([]);
      return;
    }
    setTlsCatalogLoading(true);
    try{
      const [cas,certs]=await Promise.all([
        listCAs(session),
        listCertificates(session,{ status: "active", limit: 200 })
      ]);
      setCAOptions(Array.isArray(cas)?cas.filter((item)=>String(item?.status||"").toLowerCase()==="active"):[]);
      setCertificateOptions(Array.isArray(certs)?certs.filter((item)=>String(item?.status||"").toLowerCase()==="active"):[]);
    }catch(error){
      if(!sessionGuard(error)) onToast(`TLS catalog load failed: ${errMsg(error)}`);
    }finally{
      setTlsCatalogLoading(false);
    }
  },[onToast,session,sessionGuard]);

  const refreshAlertRules=useCallback(async()=>{
    if(!session?.token) return;
    setAlertRulesLoading(true);
    try{
      const [rulesOut,channelsOut]=await Promise.all([listReportingRules(session),listReportingChannels(session)]);
      setAlertRules(rulesOut);
      const names=channelsOut
        .filter((ch)=>ch.enabled&&!isDeprecatedChannel(String(ch.name||"")))
        .map((ch)=>String(ch.name||"").trim().toLowerCase())
        .filter(Boolean);
      if(names.length) setRuleChannelsAvail(names);
    }catch(error){if(!sessionGuard(error)) onToast(`Alert rules load failed: ${errMsg(error)}`);}
    finally{setAlertRulesLoading(false);}
  },[session,sessionGuard,onToast,isDeprecatedChannel]);

  const openRuleModal=useCallback((rule?:ReportingAlertRule)=>{
    if(rule){
      setEditingRule(rule);
      setRuleName(rule.name||"");
      const cond=String(rule.condition||"").toLowerCase();
      setRuleCondition(cond==="expression"?"expression":"threshold");
      setRulePattern(rule.event_pattern||"");
      setRuleSeverity(rule.severity||"warning");
      setRuleThreshold(Math.max(1,Number(rule.threshold||1)));
      setRuleWindowSeconds(Math.max(1,Number(rule.window_seconds||300)));
      setRuleExpression(rule.expression||"");
      const cleanChannels=sanitizeRuleChannels(Array.isArray(rule.channels)?[...rule.channels]:["screen"]);
      setRuleChannels(cleanChannels.length?cleanChannels:["screen"]);
    }else{
      setEditingRule(null);
      setRuleName("");setRuleCondition("threshold");setRulePattern("");setRuleSeverity("warning");
      setRuleThreshold(1);setRuleWindowSeconds(300);setRuleExpression("");setRuleChannels(["screen"]);
    }
    setRuleModalOpen(true);
  },[sanitizeRuleChannels]);

  const handleSaveRule=useCallback(async()=>{
    if(!session?.token) return;
    const name=String(ruleName||"").trim();
    if(!name){onToast("Rule name is required."); return;}
    if(ruleCondition==="threshold"&&!String(rulePattern||"").trim()){onToast("Event pattern is required for threshold rules."); return;}
    if(ruleCondition==="expression"&&!String(ruleExpression||"").trim()){onToast("Expression is required for expression rules."); return;}
    setRuleSaving(true);
    try{
      const body:ReportingAlertRule={
        name,
        condition:ruleCondition,
        severity:ruleSeverity,
        event_pattern:ruleCondition==="threshold"?String(rulePattern||"").trim():"*",
        threshold:ruleCondition==="threshold"?Math.max(1,Math.trunc(ruleThreshold)):1,
        window_seconds:ruleCondition==="threshold"?Math.max(1,Math.trunc(ruleWindowSeconds)):60,
        expression:ruleCondition==="expression"?String(ruleExpression||"").trim():"",
        channels:sanitizeRuleChannels(ruleChannels),
        enabled:editingRule?.enabled!==false
      };
      if(editingRule?.id){
        await updateReportingRule(session,editingRule.id,body);
        onToast("Alert rule updated.");
      }else{
        await createReportingRule(session,body);
        onToast("Alert rule created.");
      }
      setRuleModalOpen(false);
      await refreshAlertRules();
    }catch(error){if(!sessionGuard(error)) onToast(`Alert rule save failed: ${errMsg(error)}`);}
    finally{setRuleSaving(false);}
  },[session,ruleName,ruleCondition,rulePattern,ruleSeverity,ruleThreshold,ruleWindowSeconds,ruleExpression,ruleChannels,editingRule,refreshAlertRules,sessionGuard,onToast,sanitizeRuleChannels]);

  const toggleRuleChannel=useCallback((ch:string)=>{
    setRuleChannels((prev)=>prev.includes(ch)?prev.filter((c)=>c!==ch):[...prev,ch]);
  },[]);

  const loadHealth=useCallback(async()=>{
    if(!session?.token){setHealth({services:[],summary:{}});return;}
    setHealthLoading(true);
    try{
      setHealth(await getAuthSystemHealth(session));
      setServiceStatusOverride({});
    }
    catch(error){if(!sessionGuard(error)) onToast(`System health load failed: ${errMsg(error)}`);} 
    finally{setHealthLoading(false);} 
  },[onToast,session,sessionGuard]);

  const restartSvc=useCallback(async(name:string)=>{
    if(!session?.token||!name) return;
    setRestartBusy(name);
    setServiceStatusOverride((prev)=>({ ...prev, [name]: "restarting" }));
    try{
      await restartAuthSystemService(session,name);
      onToast(`Restart requested: ${name}`);
    }catch(error){
      setServiceStatusOverride((prev)=>{
        const next={...prev};
        delete next[name];
        return next;
      });
      if(!sessionGuard(error)) onToast(`Service restart failed: ${errMsg(error)}`);
    } 
    finally{setRestartBusy("");}
  },[onToast,session,sessionGuard]);

  const loadGov=useCallback(async()=>{
    if(!session?.token){setGov(GOV_DEFAULT);return;}
    setGovLoading(true);
    try{const s=(await getGovernanceSettings(session)) as GovernanceSettings; setGov({...GOV_DEFAULT,...s,smtp_password:""});}
    catch(error){if(!sessionGuard(error)) onToast(`Governance settings load failed: ${errMsg(error)}`);} 
    finally{setGovLoading(false);} 
  },[onToast,session,sessionGuard]);

  const loadSystemState=useCallback(async()=>{
    if(!session?.token){setSystemState({...SYSTEM_STATE_DEFAULT});return;}
    setSystemStateLoading(true);
    try{
      const out=await getGovernanceSystemState(session);
      const state=(out?.state&&typeof out.state==="object")?out.state:{};
      const parsedSnmp = parseSNMPTargetToState(String((state as Record<string, any>)?.snmp_target || ""));
      setSystemState((prev)=>({...SYSTEM_STATE_DEFAULT,...prev,...state,...parsedSnmp}));
    }catch(error){
      if(!sessionGuard(error)) onToast(`System state load failed: ${errMsg(error)}`);
    }finally{
      setSystemStateLoading(false);
    }
  },[onToast,session,sessionGuard]);

  const loadCertSecurity=useCallback(async()=>{
    if(!session?.token){setCertSecurity(null);return;}
    setCertSecurityLoading(true);
    try{
      const out=await getCertSecurityStatus(session);
      setCertSecurity((out&&typeof out==="object")?out:null);
    }catch(error){
      if(!sessionGuard(error)) onToast(`Certificate security load failed: ${errMsg(error)}`);
    }finally{
      setCertSecurityLoading(false);
    }
  },[onToast,session,sessionGuard]);

  const loadPasswordPolicy=useCallback(async()=>{
    if(!session?.token){setPasswordPolicy(null);return;}
    setPasswordPolicyLoading(true);
    try{
      const out=await getAuthPasswordPolicy(session);
      setPasswordPolicy((out&&typeof out==="object")?out:null);
    }catch(error){
      if(!sessionGuard(error)) onToast(`Password policy load failed: ${errMsg(error)}`);
    }finally{
      setPasswordPolicyLoading(false);
    }
  },[onToast,session,sessionGuard]);

  const savePasswordPolicy=useCallback(async()=>{
    if(!session?.token||!passwordPolicy){return;}
    setPasswordPolicySaving(true);
    try{
      const out=await updateAuthPasswordPolicy(session,{
        ...passwordPolicy,
        min_length:Math.max(8,Number(passwordPolicy?.min_length||12)),
        max_length:Math.max(8,Number(passwordPolicy?.max_length||128)),
        min_unique_chars:Math.max(0,Number(passwordPolicy?.min_unique_chars||6))
      });
      setPasswordPolicy((out&&typeof out==="object")?out:null);
      onToast("Password policy updated.");
    }catch(error){
      if(!sessionGuard(error)) onToast(`Password policy save failed: ${errMsg(error)}`);
    }finally{
      setPasswordPolicySaving(false);
    }
  },[onToast,passwordPolicy,session,sessionGuard]);

  const loadSecurityPolicy=useCallback(async()=>{
    if(!session?.token){setSecurityPolicy(null);return;}
    setSecurityPolicyLoading(true);
    try{
      const out=await getAuthSecurityPolicy(session);
      setSecurityPolicy((out&&typeof out==="object")?out:null);
    }catch(error){
      if(!sessionGuard(error)) onToast(`Security policy load failed: ${errMsg(error)}`);
    }finally{
      setSecurityPolicyLoading(false);
    }
  },[onToast,session,sessionGuard]);

  const saveSecurityPolicy=useCallback(async()=>{
    if(!session?.token||!securityPolicy){return;}
    setSecurityPolicySaving(true);
    try{
      const out=await updateAuthSecurityPolicy(session,{
        ...securityPolicy,
        max_failed_attempts:Math.max(3,Number(securityPolicy?.max_failed_attempts||5)),
        lockout_minutes:Math.max(1,Number(securityPolicy?.lockout_minutes||15)),
        idle_timeout_minutes:Math.max(1,Number(securityPolicy?.idle_timeout_minutes||15))
      });
      setSecurityPolicy((out&&typeof out==="object")?out:null);
      onToast("Login security policy updated.");
    }catch(error){
      if(!sessionGuard(error)) onToast(`Security policy save failed: ${errMsg(error)}`);
    }finally{
      setSecurityPolicySaving(false);
    }
  },[onToast,securityPolicy,session,sessionGuard]);

  const loadAccessHardening=useCallback(async()=>{
    if(!session?.token){
      setAccessSettings(null);
      setInterfacePorts([]);
      setInterfaceTLSConfig(INTERFACE_TLS_CONFIG_DEFAULT);
      return;
    }
    setAccessSettingsLoading(true);
    setInterfaceConfigLoading(true);
    setInterfaceTLSConfigLoading(true);
    try{
      const [settings,ports,tlsConfig]=await Promise.all([
        getKeyAccessSettings(session),
        listKeyInterfacePorts(session),
        getKeyInterfaceTLSConfig(session)
      ]);
      setAccessSettings((settings&&typeof settings==="object")?settings:null);
      setInterfacePorts(Array.isArray(ports)?ports:[]);
      setInterfaceTLSConfig((tlsConfig&&typeof tlsConfig==="object")?tlsConfig:INTERFACE_TLS_CONFIG_DEFAULT);
    }catch(error){
      if(!sessionGuard(error)) onToast(`Key access hardening load failed: ${errMsg(error)}`);
    }finally{
      setAccessSettingsLoading(false);
      setInterfaceConfigLoading(false);
      setInterfaceTLSConfigLoading(false);
    }
  },[onToast,session,sessionGuard]);

  const saveAccessHardening=useCallback(async()=>{
    if(!session?.token||!accessSettings){return;}
    setAccessSettingsSaving(true);
    try{
      const out=await updateKeyAccessSettings(session,{
        ...accessSettings,
        grant_default_ttl_minutes:Math.max(0,Number(accessSettings?.grant_default_ttl_minutes||0)),
        grant_max_ttl_minutes:Math.max(0,Number(accessSettings?.grant_max_ttl_minutes||0)),
        replay_window_seconds:Math.max(30,Number(accessSettings?.replay_window_seconds||300)),
        nonce_ttl_seconds:Math.max(30,Number(accessSettings?.nonce_ttl_seconds||900))
      });
      setAccessSettings((out&&typeof out==="object")?out:null);
      onToast("Key access hardening policy updated.");
    }catch(error){
      if(!sessionGuard(error)) onToast(`Key access hardening save failed: ${errMsg(error)}`);
    }finally{
      setAccessSettingsSaving(false);
    }
  },[accessSettings,onToast,session,sessionGuard]);

  const loadTags=useCallback(async()=>{
    if(!session?.token){setTagCatalog([]);return;}
    try{
      const items=await listTags(session);
      setTagCatalog(Array.isArray(items)?(items as unknown[]):[]);
    }catch(error){
      if(!sessionGuard(error)) onToast(`Tag catalog load failed: ${errMsg(error)}`);
    }
  },[onToast,session,sessionGuard,setTagCatalog]);

  const addTag=useCallback(async()=>{
    if(!session?.token){return;}
    const name=String(newTagName||"").trim();
    if(!name){onToast("Tag name is required.");return;}
    setTagSaving(true);
    try{
      await upsertTag(session,name,String(newTagColor||C.teal));
      setNewTagName("");
      await loadTags();
      onToast("Tag saved.");
    }catch(error){
      if(!sessionGuard(error)) onToast(`Tag save failed: ${errMsg(error)}`);
    }finally{
      setTagSaving(false);
    }
  },[loadTags,newTagColor,newTagName,onToast,session,sessionGuard]);

  const removeTag=useCallback(async(name:string, usageCount:number)=>{
    if(!session?.token||!String(name||"").trim()){return;}
    if(Number(usageCount||0)>0){
      onToast(`Tag "${String(name)}" is assigned to ${Number(usageCount)} active key(s). Remove assignments first.`);
      return;
    }
    const ok=await promptDialog.confirm({
      title:"Delete Tag",
      message:`Delete tag "${String(name)}"?`,
      confirmLabel:"Delete",
      cancelLabel:"Cancel",
      danger:true
    });
    if(!ok){return;}
    try{
      await deleteTag(session,String(name).trim());
      await loadTags();
      onToast("Tag deleted.");
    }catch(error){
      if(!sessionGuard(error)) onToast(`Tag delete failed: ${errMsg(error)}`);
    }
  },[loadTags,onToast,promptDialog,session,sessionGuard]);

  const saveSystemState=useCallback(async()=>{
    if(!session?.token) return;
    setSystemStateSaving(true);
    try{
      const snmpTarget = buildSNMPTargetFromState(systemState as Record<string, any>);
      const payload={
        ...SYSTEM_STATE_DEFAULT,
        ...systemState,
        tenant_id: session.tenantId,
        backup_retention_days: Math.max(1,Math.trunc(Number(systemState?.backup_retention_days||30))),
        backup_encrypted: Boolean(systemState?.backup_encrypted),
        snmp_target: snmpTarget,
        posture_force_quorum_destructive_ops: Boolean(systemState?.posture_force_quorum_destructive_ops),
        posture_require_step_up_auth: Boolean(systemState?.posture_require_step_up_auth),
        posture_pause_connector_sync: Boolean(systemState?.posture_pause_connector_sync),
        posture_guardrail_policy_required: Boolean(systemState?.posture_guardrail_policy_required)
      };
      const out=await patchGovernanceSystemState(session,payload);
      const state=(out?.state&&typeof out.state==="object")?out.state:{};
      const parsedSnmp = parseSNMPTargetToState(String((state as Record<string, any>)?.snmp_target || snmpTarget));
      setSystemState((prev)=>({...SYSTEM_STATE_DEFAULT,...prev,...state,...parsedSnmp,snmp_target:snmpTarget}));
      onToast("System administration platform settings updated.");
      return true;
    }catch(error){
      if(!sessionGuard(error)) onToast(`System state save failed: ${errMsg(error)}`);
      return false;
    }finally{
      setSystemStateSaving(false);
    }
  },[onToast,session,sessionGuard,systemState]);

  const loadJobs=useCallback(async()=>{
    if(!session?.token){setJobs([]);return;}
    setJobsLoading(true);
    try{setJobs(await listGovernanceBackups(session,{limit:100}));}
    catch(error){if(!sessionGuard(error)) onToast(`Backup list load failed: ${errMsg(error)}`);} 
    finally{setJobsLoading(false);} 
  },[onToast,session,sessionGuard]);

  const restoreBackup=useCallback(async()=>{
    if(!session?.token){return;}
    if(!backupRestoreArtifactFile||!backupRestoreKeyFile){
      onToast("Select backup artifact and backup key package.");
      return;
    }
    const artifactName=String(backupRestoreArtifactFile.name||"").trim();
    const keyName=String(backupRestoreKeyFile.name||"").trim();
    if(!artifactName.toLowerCase().endsWith(BACKUP_ARTIFACT_EXTENSION)){
      onToast(`Artifact must use ${BACKUP_ARTIFACT_EXTENSION} extension.`);
      return;
    }
    if(!keyName.toLowerCase().endsWith(BACKUP_KEY_EXTENSION)){
      onToast(`Key package must use ${BACKUP_KEY_EXTENSION} extension.`);
      return;
    }
    setBackupRestoring(true);
    try{
      const [artifactB64,keyB64]=await Promise.all([fileToBase64(backupRestoreArtifactFile),fileToBase64(backupRestoreKeyFile)]);
      const out=await restoreGovernanceBackup(session,{
        artifact_file_name:artifactName,
        artifact_content_base64:artifactB64,
        key_file_name:keyName,
        key_content_base64:keyB64,
        created_by:session.username
      });
      setBackupRestoreArtifactFile(null);
      setBackupRestoreKeyFile(null);
      onToast(`Backup restored. Rows: ${Number(out.rows_restored||0)} | Tables: ${Number(out.tables_processed||0)}.`);
      await Promise.all([loadJobs(),loadSystemState()]);
    }catch(error){
      if(!sessionGuard(error)) onToast(`Backup restore failed: ${errMsg(error)}`);
    }finally{
      setBackupRestoring(false);
    }
  },[backupRestoreArtifactFile,backupRestoreKeyFile,loadJobs,loadSystemState,onToast,session,sessionGuard]);

  const saveSnmpSettings = useCallback(async()=>{
    if(!session?.token){return;}
    const target = buildSNMPTargetFromState(systemState as Record<string, any>);
    if(!target){
      onToast("SNMP host is required.");
      return;
    }
    setSystemStateSaving(true);
    try{
      const out = await patchGovernanceSystemState(session,{
        tenant_id: session.tenantId,
        snmp_target: target
      });
      const state=(out?.state&&typeof out.state==="object")?out.state:{};
      const parsed = parseSNMPTargetToState(String((state as Record<string, any>)?.snmp_target || target));
      setSystemState((prev)=>({...SYSTEM_STATE_DEFAULT,...prev,...state,...parsed,snmp_target:target}));
      onToast("SNMP settings updated.");
    }catch(error){
      if(!sessionGuard(error)) onToast(`SNMP settings save failed: ${errMsg(error)}`);
    }finally{
      setSystemStateSaving(false);
    }
  },[onToast,session,sessionGuard,systemState]);

  const testSnmpSettings = useCallback(async()=>{
    if(!session?.token){return;}
    const target = buildSNMPTargetFromState(systemState as Record<string, any>);
    if(!target){
      onToast("SNMP host is required.");
      return;
    }
    setSnmpTesting(true);
    try{
      await testGovernanceSystemSNMP(session,target);
      onToast("SNMP test succeeded.");
    }catch(error){
      if(!sessionGuard(error)) onToast(`SNMP test failed: ${errMsg(error)}`);
    }finally{
      setSnmpTesting(false);
    }
  },[onToast,session,sessionGuard,systemState]);

  const loadCli=useCallback(async()=>{
    if(!session?.token){setCliStatus(null);return;}
    setCliLoading(true);
    try{const s=await getAuthCLIStatus(session); setCliStatus(s); setCliUser(String(s?.cli_username||"cli-user"));}
    catch(error){if(!sessionGuard(error)) onToast(`CLI status load failed: ${errMsg(error)}`);} 
    finally{setCliLoading(false);} 
  },[onToast,session,sessionGuard]);

  const loadHsm=useCallback(async()=>{
    if(!session?.token){setHsm(HSM_DEFAULT);return;}
    setHsmLoading(true);
    try{
      const cfg=await getAuthCLIHSMConfig(session);
      setHsm((p)=>({...p,...cfg}));
    }
    catch(error){if(!sessionGuard(error)) onToast(`HSM config load failed: ${errMsg(error)}`);} 
    finally{setHsmLoading(false);} 
  },[onToast,session,sessionGuard]);

  const openCli=useCallback(async()=>{
    if(!session?.token) return;
    if(!String(cliUser||"").trim()||!String(cliPass||"").trim()){onToast("CLI username and password are required."); return;}
    setCliOpening(true);
    try{
      const opened=await openAuthCLISession(session,{username:String(cliUser||"").trim(),password:String(cliPass||"")});
      setCliSession(String(opened?.cli_session_id||""));
      setCliSsh(String(opened?.ssh_command||""));
      if(String(opened?.putty_uri||"").trim()) window.open(String(opened.putty_uri),"_blank","noopener,noreferrer");
      setCliPass("");
      onToast("CLI session opened.");
      await loadCli();
    }catch(error){if(!sessionGuard(error)) onToast(`CLI open failed: ${errMsg(error)}`);} 
    finally{setCliOpening(false);} 
  },[cliPass,cliUser,loadCli,onToast,session,sessionGuard]);

  useEffect(()=>{
    const token = String(session?.token||"");
    if(!token){
      initialLoadTokenRef.current = "";
      return;
    }
    if(initialLoadTokenRef.current===token){
      return;
    }
    initialLoadTokenRef.current = token;
    void loadHealth();
    void loadSystemState();
    void loadGov();
    void loadJobs();
    void loadCli();
    void loadHsm();
    void loadCertSecurity();
    void loadPasswordPolicy();
    void loadSecurityPolicy();
    void loadAccessHardening();
    void loadTLSCatalog();
    void loadTags();
  },[
    session?.token,
    loadAccessHardening,
    loadCertSecurity,
    loadCli,
    loadGov,
    loadHealth,
    loadHsm,
    loadJobs,
    loadPasswordPolicy,
    loadSecurityPolicy,
    loadSystemState,
    loadTLSCatalog,
    loadTags
  ]);
  useEffect(()=>{
    try{
      if(localStorage.getItem(SYSTEM_ADMIN_OPEN_CLI_KEY)==="1"){
        setPanel("cli");
        localStorage.removeItem(SYSTEM_ADMIN_OPEN_CLI_KEY);
      }
    }catch{}
  },[]);

  useEffect(()=>{
    if(panel==="alertrules"&&session?.token) void refreshAlertRules();
    if(panel==="approvals"&&session?.token) void loadGovPolicies();
    if(panel==="diskencryption"&&session?.token) void loadFDEStatus();
    if((panel==="interfaces"||panel==="runtime")&&session?.token&&(caOptions.length===0&&certificateOptions.length===0)) void loadTLSCatalog();
  },[caOptions.length,certificateOptions.length,loadFDEStatus,loadGovPolicies,loadTLSCatalog,panel,refreshAlertRules,session?.token]);

  useEffect(()=>{
    setSystemState((prev)=>({
      ...prev,
      fips_mode: fipsMode==="enabled" ? "enabled" : "disabled"
    }));
  },[fipsMode]);

  const restartableServiceNames = useMemo(
    ()=> (health.services||[])
      .filter((svc)=>restartAllowedFor(svc))
      .map((svc)=>String(svc?.name||"").trim())
      .filter(Boolean),
    [health.services]
  );

  const liveInterfaces = useMemo(
    ()=> Array.isArray(health?.interfaces) ? health.interfaces : [],
    [health?.interfaces]
  );

  const hiddenConfiguredInterfaceCount = useMemo(
    ()=> (Array.isArray(interfacePorts) ? interfacePorts : []).filter((item)=>!INTERFACE_DEF_MAP[normalizeConfigurableInterfaceName(String(item?.interface_name||""))]).length,
    [interfacePorts]
  );

  const configuredPortRecords = useMemo<Array<Record<string,any>>>(
    ()=> (Array.isArray(interfacePorts) && interfacePorts.length
      ? interfacePorts
      : CONFIGURABLE_INTERFACE_DEFS.map((item)=>({
          interface_name: item.key,
          bind_address: item.defaultBindAddress,
          port: item.defaultPort,
          protocol: item.defaultProtocol,
          pqc_mode: interfaceProtocolUsesCertificate(item.defaultProtocol) ? "inherit" : "classical",
          certificate_source: item.defaultCertSource,
          enabled: true,
          description: item.description
        }))),
    [interfacePorts]
  );

  const persistedTLSBinding = useMemo<InterfaceTLSBinding>(
    ()=> buildInterfaceTLSBinding(
      "https",
      String(interfaceTLSConfig?.certificate_source||"internal_ca"),
      String(interfaceTLSConfig?.ca_id||""),
      String(interfaceTLSConfig?.certificate_id||""),
      "internal_ca"
    ),
    [interfaceTLSConfig?.ca_id,interfaceTLSConfig?.certificate_id,interfaceTLSConfig?.certificate_source]
  );

  const tlsDefaultsOutOfSync = useMemo(
    ()=> {
      const expected = tlsBindingSignature(persistedTLSBinding);
      return configuredPortRecords.some((raw)=>{
        const interfaceName = normalizeConfigurableInterfaceName(String(raw?.interface_name||""));
        const meta = INTERFACE_DEF_MAP[interfaceName];
        if(!meta){
          return false;
        }
        const protocol = normalizeInterfaceProtocol(String(raw?.protocol||""), meta.defaultProtocol);
        if(!interfaceProtocolUsesCertificate(protocol)){
          return false;
        }
        return tlsBindingSignature(buildInterfaceTLSBinding(
          protocol,
          String(raw?.certificate_source||""),
          String(raw?.ca_id||""),
          String(raw?.certificate_id||""),
          meta.defaultCertSource
        )) !== expected;
      });
    },
    [configuredPortRecords,persistedTLSBinding]
  );

  const systemTLSCertSource = useMemo(
    ()=> persistedTLSBinding.certSource,
    [persistedTLSBinding.certSource]
  );

  const systemTLSCAID = useMemo(
    ()=> systemTLSCertSource==="pki_ca" ? persistedTLSBinding.caID : "",
    [persistedTLSBinding.caID,systemTLSCertSource]
  );

  const systemTLSCertificateID = useMemo(
    ()=> systemTLSCertSource==="uploaded_certificate" ? persistedTLSBinding.certificateID : "",
    [persistedTLSBinding.certificateID,systemTLSCertSource]
  );

  const configuredInterfaces = useMemo<NetIface[]>(
    ()=> configuredPortRecords
      .reduce<NetIface[]>((items,raw)=>{
        const interfaceName = normalizeConfigurableInterfaceName(String(raw?.interface_name||""));
        const meta = INTERFACE_DEF_MAP[interfaceName];
        if(!meta){
          return items;
        }
        const desiredPort = Number(raw?.port||meta.defaultPort);
        const configuredProtocol = normalizeInterfaceProtocol(String(raw?.protocol||""), meta.defaultProtocol);
        const configuredPQCMode = normalizeInterfacePQCMode(String(raw?.pqc_mode||""), configuredProtocol);
        const effectiveTLSBinding = interfaceProtocolUsesCertificate(configuredProtocol)
          ? {
              certSource: persistedTLSBinding.certSource,
              caID: persistedTLSBinding.caID,
              certificateID: persistedTLSBinding.certificateID
            }
          : {
              certSource: "none" as InterfaceCertSource,
              caID: "",
              certificateID: ""
            };
        const configuredCertSource = effectiveTLSBinding.certSource;
        const caID = effectiveTLSBinding.caID;
        const certificateID = effectiveTLSBinding.certificateID;
        const runtimeMatch = [...liveInterfaces]
          .filter((item)=>{
            const runtimeName = normalizeConfigurableInterfaceName(String(item?.name||""));
            return runtimeName === interfaceName || Number(item?.port||0) === desiredPort;
          })
          .sort((a,b)=>interfaceStatusRank(String(b?.status||""))-interfaceStatusRank(String(a?.status||"")))[0];
        const enabled = Boolean(raw?.enabled);
        const status = enabled
          ? String(runtimeMatch?.status||"not detected")
          : "disabled";
        const caName = caOptions.find((item)=>String(item?.id||"")===caID)?.name;
        const certificateName = certificateOptions.find((item)=>String(item?.id||"")===certificateID)?.subject_cn;
        const certificateLabel = configuredCertSource==="internal_ca"
          ? "Internal CA (auto-issue)"
          : configuredCertSource==="pki_ca"
            ? (caName ? `CA: ${caName}` : "CA from Certificates / PKI")
            : configuredCertSource==="uploaded_certificate"
              ? (certificateName ? `Certificate: ${certificateName}` : "Uploaded certificate from PKI")
              : "None";
        items.push({
          id: interfaceName,
          interface_name: interfaceName,
          name: meta.label,
          description: String(raw?.description||"").trim() || meta.description,
          service: meta.service,
          protocol: configuredProtocol,
          protocol_label: INTERFACE_PROTOCOL_LABELS[configuredProtocol],
          pqc_mode: configuredPQCMode,
          pqc_label: INTERFACE_PQC_MODE_LABELS[configuredPQCMode],
          cert_source: configuredCertSource,
          cert_label: certificateLabel,
          ca_id: caID,
          certificate_id: certificateID,
          auto_create_cert: configuredCertSource==="internal_ca" || configuredCertSource==="pki_ca",
          bind_address: String(raw?.bind_address||meta.defaultBindAddress).trim() || meta.defaultBindAddress,
          port: desiredPort,
          enabled,
          status,
          runtime_bind_address: runtimeMatch?.bind_address,
          runtime_port: runtimeMatch?.port,
          runtime_source: runtimeMatch?.source,
          updated_at: String(raw?.updated_at||"").trim() || undefined
        });
        return items;
      },[])
      .sort((a,b)=>(INTERFACE_ORDER[a.interface_name]??999)-(INTERFACE_ORDER[b.interface_name]??999)),
    [caOptions,certificateOptions,configuredPortRecords,liveInterfaces,persistedTLSBinding.caID,persistedTLSBinding.certSource,persistedTLSBinding.certificateID]
  );

  const availableInterfaceDefs = useMemo(
    ()=> CONFIGURABLE_INTERFACE_DEFS.filter((item)=>item.key===editingNetIf?.interface_name || !configuredInterfaces.some((iface)=>iface.interface_name===item.key)),
    [configuredInterfaces,editingNetIf?.interface_name]
  );

  const selectedInterfaceDef = useMemo(
    ()=> INTERFACE_DEF_MAP[normalizeConfigurableInterfaceName(ifName)] || availableInterfaceDefs[0] || CONFIGURABLE_INTERFACE_DEFS[0],
    [availableInterfaceDefs,ifName]
  );

  const availableProtocolOptions = useMemo<InterfaceProtocol[]>(
    ()=> Array.isArray(selectedInterfaceDef?.allowedProtocols) && selectedInterfaceDef.allowedProtocols.length
      ? selectedInterfaceDef.allowedProtocols
      : ["http"],
    [selectedInterfaceDef]
  );

  const interfaceTLSRequired = useMemo(
    ()=> interfaceProtocolUsesCertificate(ifProtocol),
    [ifProtocol]
  );

  const selectedTLSCAName = useMemo(
    ()=> caOptions.find((item)=>String(item?.id||"")===String(ifCAID||""))?.name || "",
    [caOptions,ifCAID]
  );

  const selectedTLSCertificateName = useMemo(
    ()=> certificateOptions.find((item)=>String(item?.id||"")===String(ifCertificateID||""))?.subject_cn || "",
    [certificateOptions,ifCertificateID]
  );

  const systemTLSCAName = useMemo(
    ()=> caOptions.find((item)=>String(item?.id||"")===systemTLSCAID)?.name || "",
    [caOptions,systemTLSCAID]
  );

  const systemTLSCertificateName = useMemo(
    ()=> certificateOptions.find((item)=>String(item?.id||"")===systemTLSCertificateID)?.subject_cn || "",
    [certificateOptions,systemTLSCertificateID]
  );

  const interfaceCardStats = useMemo(
    ()=>({
      total: configuredInterfaces.length,
      enabled: configuredInterfaces.filter((item)=>item.enabled).length,
      listening: configuredInterfaces.filter((item)=>String(item.status||"").toLowerCase()==="listening").length,
      external: configuredInterfaces.filter((item)=>String(item.bind_address||"").trim()!=="127.0.0.1").length
    }),
    [configuredInterfaces]
  );

  const applyInterfaceSelection = useCallback((rawName:string)=>{
    const nextName = normalizeConfigurableInterfaceName(rawName);
    const meta = INTERFACE_DEF_MAP[nextName];
    if(!meta){
      return;
    }
    const protocol = meta.defaultProtocol;
    const usesCertificate = interfaceProtocolUsesCertificate(protocol);
    const certSource = usesCertificate ? systemTLSCertSource : "none";
    const pqcMode = normalizeInterfacePQCMode(String(meta.defaultProtocol==="http"||meta.defaultProtocol==="tcp" ? "classical" : "inherit"), protocol);
    setIfName(meta.key);
    setIfDesc(meta.description);
    setIfBindAddr(meta.defaultBindAddress);
    setIfPort(String(meta.defaultPort));
    setIfProtocol(protocol);
    setIfPQCMode(pqcMode);
    setIfCertSource(certSource);
    setIfCAID(certSource==="pki_ca" ? systemTLSCAID : "");
    setIfCertificateID(certSource==="uploaded_certificate" ? systemTLSCertificateID : "");
  },[systemTLSCAID,systemTLSCertSource,systemTLSCertificateID]);

  useEffect(()=>{
    if(!availableProtocolOptions.includes(ifProtocol)){
      const fallback = availableProtocolOptions[0] || selectedInterfaceDef?.defaultProtocol || "http";
      setIfProtocol(fallback);
      return;
    }
    if(!interfaceTLSRequired){
      if(ifPQCMode!=="classical") setIfPQCMode("classical");
      if(ifCertSource!=="none") setIfCertSource("none");
      if(ifCAID) setIfCAID("");
      if(ifCertificateID) setIfCertificateID("");
      return;
    }
    if(ifPQCMode==="classical"){
      // allow explicit classical override
    } else if(!["inherit","hybrid","pqc_only"].includes(ifPQCMode)){
      setIfPQCMode("inherit");
    }
    if(ifCertSource!==systemTLSCertSource){
      setIfCertSource(systemTLSCertSource);
    }
    if(systemTLSCertSource==="pki_ca"){
      if(ifCAID!==systemTLSCAID){
        setIfCAID(systemTLSCAID);
      }
      if(ifCertificateID){
        setIfCertificateID("");
      }
      return;
    }
    if(systemTLSCertSource==="uploaded_certificate"){
      if(ifCertificateID!==systemTLSCertificateID){
        setIfCertificateID(systemTLSCertificateID);
      }
      if(ifCAID){
        setIfCAID("");
      }
      return;
    }
    if(ifCAID){
      setIfCAID("");
    }
    if(ifCertificateID){
      setIfCertificateID("");
    }
  },[
    availableProtocolOptions,
    ifCAID,
    ifCertSource,
    ifCertificateID,
    ifPQCMode,
    ifProtocol,
    interfaceTLSRequired,
    systemTLSCertSource,
    systemTLSCAID,
    systemTLSCertificateID
  ]);

  const openNetIfModal = useCallback((iface?:NetIface)=>{
    void loadTLSCatalog();
    if(iface){
      setEditingNetIf(iface);
      setIfName(iface.interface_name);
      setIfDesc(iface.description);
      setIfProtocol(iface.protocol);
      setIfPQCMode(iface.pqc_mode);
      setIfCertSource(interfaceProtocolUsesCertificate(iface.protocol) ? systemTLSCertSource : "none");
      setIfCAID(interfaceProtocolUsesCertificate(iface.protocol) && systemTLSCertSource==="pki_ca" ? systemTLSCAID : "");
      setIfCertificateID(interfaceProtocolUsesCertificate(iface.protocol) && systemTLSCertSource==="uploaded_certificate" ? systemTLSCertificateID : "");
      setIfBindAddr(iface.bind_address);
      setIfPort(String(iface.port));
      setIfEnabled(iface.enabled);
      setNetIfModalOpen(true);
      return;
    }
    const fallback = availableInterfaceDefs[0] || CONFIGURABLE_INTERFACE_DEFS[0];
    const fallbackProtocol = fallback?.defaultProtocol || "http";
    const fallbackUsesTLS = interfaceProtocolUsesCertificate(fallbackProtocol);
    const fallbackCertSource = fallbackUsesTLS ? systemTLSCertSource : "none";
    setEditingNetIf(null);
    setIfName(fallback?.key||"rest");
    setIfDesc(fallback?.description||"");
    setIfProtocol(fallbackProtocol);
    setIfPQCMode(normalizeInterfacePQCMode(fallbackUsesTLS ? "inherit" : "classical", fallbackProtocol));
    setIfCertSource(fallbackCertSource);
    setIfCAID(fallbackCertSource==="pki_ca" ? systemTLSCAID : "");
    setIfCertificateID(fallbackCertSource==="uploaded_certificate" ? systemTLSCertificateID : "");
    setIfBindAddr(fallback?.defaultBindAddress||"0.0.0.0");
    setIfPort(String(fallback?.defaultPort||443));
    setIfEnabled(true);
    setNetIfModalOpen(true);
  },[availableInterfaceDefs,loadTLSCatalog,systemTLSCAID,systemTLSCertSource,systemTLSCertificateID]);

  const saveNetIf = useCallback(async()=>{
    if(!session?.token){
      return;
    }
    const interfaceName = normalizeConfigurableInterfaceName(ifName);
    const meta = INTERFACE_DEF_MAP[interfaceName];
    if(!meta){
      onToast("Select a valid interface.");
      return;
    }
    const bindAddress = String(ifBindAddr||"").trim() || meta.defaultBindAddress;
    const portNum = Number(ifPort||0);
    const protocol = normalizeInterfaceProtocol(ifProtocol, meta.defaultProtocol);
    const pqcMode = normalizeInterfacePQCMode(ifPQCMode, protocol);
    if(!meta.allowedProtocols.includes(protocol)){
      onToast("Select a valid protocol for this interface.");
      return;
    }
    const certSource = interfaceProtocolUsesCertificate(protocol) ? systemTLSCertSource : "none";
    const effectiveCAID = certSource==="pki_ca" ? systemTLSCAID : "";
    const effectiveCertificateID = certSource==="uploaded_certificate" ? systemTLSCertificateID : "";
    if(!Number.isFinite(portNum)||portNum<1||portNum>65535){
      onToast("Port must be 1-65535.");
      return;
    }
    if(interfaceProtocolUsesCertificate(protocol) && certSource==="pki_ca" && !effectiveCAID){
      onToast("Configure TLS first and select a CA from Certificates / PKI.");
      return;
    }
    if(interfaceProtocolUsesCertificate(protocol) && certSource==="uploaded_certificate" && !effectiveCertificateID){
      onToast("Configure TLS first and select an uploaded certificate from Certificates / PKI.");
      return;
    }
    try{
      await upsertKeyInterfacePort(session,{
        interface_name: interfaceName,
        bind_address: bindAddress,
        port: portNum,
        protocol,
        pqc_mode: pqcMode,
        certificate_source: certSource,
        ca_id: effectiveCAID,
        certificate_id: effectiveCertificateID,
        enabled: ifEnabled,
        description: String(ifDesc||"").trim() || meta.description
      });
      onToast(editingNetIf?"Interface updated.":"Interface created.");
      setNetIfModalOpen(false);
      setEditingNetIf(null);
      await loadAccessHardening();
    }catch(error){
      if(!sessionGuard(error)) onToast(`Interface save failed: ${errMsg(error)}`);
    }
  },[editingNetIf,ifBindAddr,ifDesc,ifEnabled,ifName,ifPQCMode,ifPort,ifProtocol,loadAccessHardening,onToast,session,sessionGuard,systemTLSCAID,systemTLSCertSource,systemTLSCertificateID]);

  const deleteNetIf = useCallback(async(interfaceName:string)=>{
    if(!session?.token){
      return;
    }
    const normalizedName = normalizeConfigurableInterfaceName(interfaceName);
    const meta = INTERFACE_DEF_MAP[normalizedName];
    const ok = await promptDialog.confirm({
      title: "Delete Interface",
      message: `Remove ${meta?.label||normalizedName} from the configurable interface list?`,
      confirmLabel: "Delete",
      cancelLabel: "Cancel",
      danger: true
    });
    if(!ok){
      return;
    }
    try{
      await deleteKeyInterfacePort(session,normalizedName);
      onToast("Interface removed.");
      await loadAccessHardening();
    }catch(error){
      if(!sessionGuard(error)) onToast(`Interface delete failed: ${errMsg(error)}`);
    }
  },[loadAccessHardening,onToast,promptDialog,session,sessionGuard]);

  const toggleNetIfEnabled = useCallback(async(iface:NetIface)=>{
    if(!session?.token){
      return;
    }
    try{
      await upsertKeyInterfacePort(session,{
        interface_name: iface.interface_name,
        bind_address: iface.bind_address,
        port: iface.port,
        protocol: iface.protocol,
        pqc_mode: iface.pqc_mode,
        certificate_source: iface.cert_source,
        ca_id: iface.ca_id,
        certificate_id: iface.certificate_id,
        enabled: !iface.enabled,
        description: iface.description
      });
      onToast(!iface.enabled ? "Interface enabled." : "Interface disabled.");
      await loadAccessHardening();
    }catch(error){
      if(!sessionGuard(error)) onToast(`Interface update failed: ${errMsg(error)}`);
    }
  },[loadAccessHardening,onToast,session,sessionGuard]);

  const saveFipsConfig = useCallback(async()=>{
    const nextMode = String(systemState?.fips_mode||"disabled")==="enabled" ? "enabled" : "disabled";
    onFipsModeChange(nextMode);
    const ok = await saveSystemState();
    if(ok){
      setFipsConfigModalOpen(false);
    }
  },[onFipsModeChange,saveSystemState,systemState?.fips_mode]);

  const saveTLSConfig = useCallback(async()=>{
    const certSource = systemTLSCertSource;
    if(certSource==="pki_ca" && !systemTLSCAID){
      onToast("Select a CA from Certificates / PKI for TLS issuance.");
      return;
    }
    if(certSource==="uploaded_certificate" && !systemTLSCertificateID){
      onToast("Select an uploaded certificate from Certificates / PKI.");
      return;
    }
    const ok = await saveSystemState();
    if(!ok){
      return;
    }
    try{
      await updateKeyInterfaceTLSConfig(session!,{
        certificate_source: certSource,
        ca_id: certSource==="pki_ca" ? systemTLSCAID : "",
        certificate_id: certSource==="uploaded_certificate" ? systemTLSCertificateID : ""
      });
      await loadAccessHardening();
      onToast("TLS defaults updated and applied to TLS-enabled interfaces.");
      setTlsConfigModalOpen(false);
    }catch(error){
      if(!sessionGuard(error)) onToast(`TLS configuration save failed: ${errMsg(error)}`);
    }
  },[loadAccessHardening,onToast,saveSystemState,session,sessionGuard,systemTLSCAID,systemTLSCertSource,systemTLSCertificateID]);

  const restartAllAllowedServices = useCallback(async()=>{
    if(!session?.token){
      return;
    }
    if(!restartableServiceNames.length){
      onToast("No restart-allowed services available.");
      return;
    }
    const confirmText = `Restart ${restartableServiceNames.length} allowed services? Restricted services will be skipped.`;
    const ok=await promptDialog.confirm({
      title:"Restart Allowed Services",
      message:confirmText,
      confirmLabel:"Restart",
      cancelLabel:"Cancel",
      danger:true
    });
    if(!ok){
      return;
    }
    setRestartAllBusy(true);
    const failed:string[]=[];
    try{
      for(const name of restartableServiceNames){
        setRestartBusy(name);
        setServiceStatusOverride((prev)=>({ ...prev, [name]: "restarting" }));
        try{
          await restartAuthSystemService(session,name);
        }catch(error){
          failed.push(name);
          setServiceStatusOverride((prev)=>{
            const next={...prev};
            delete next[name];
            return next;
          });
          if(sessionGuard(error)){
            break;
          }
        }finally{
          setRestartBusy("");
        }
      }
      if(failed.length){
        onToast(`Restart completed with failures: ${failed.join(", ")}`);
      }else{
        onToast(`Restart requested for ${restartableServiceNames.length} services.`);
      }
    }finally{
      setRestartAllBusy(false);
    }
  },[onToast,promptDialog,restartableServiceNames,session,sessionGuard]);

  const sortedJobs=useMemo(()=>[...jobs].sort((a,b)=>new Date(String(b.created_at||0)).getTime()-new Date(String(a.created_at||0)).getTime()),[jobs]);
  const totalServices=Number(health.summary?.total||health.services?.length||0);
  const runtimeModeLabel=String(systemState?.fips_mode_policy||"standard")==="strict"?"Strict":"Standard";
  const runtimeTlsLabel=String(systemState?.fips_tls_profile||"tls1.2_fips")
    .replace("tls13_only","TLS 1.3 only")
    .replace("tls1.2_fips","TLS 1.2+ FIPS");
  const runtimeRngLabel=String(systemState?.fips_rng_mode||"ctr_drbg").toUpperCase();
  const entropyBits=Number(systemState?.fips_entropy_bits_per_byte||0);
  const entropySampleBytes=Math.max(0,Number(systemState?.fips_entropy_sample_bytes||4096));
  const entropySampleMicros=Math.max(0,Number(systemState?.fips_entropy_read_micros||0));
  const runtimeAllOk = Number(health.summary?.degraded||0)===0 && Number(health.summary?.down||0)===0;
  const runtimeLibraryLine = `Library: ${String(systemState?.fips_crypto_library||"Go std crypto")} (${String(systemState?.go_runtime_version||"go1.26.0")}, GOEXPERIMENT=${String(systemState?.goexperiment||"none")}, CGO=${String(systemState?.cgo_enabled||"0")}, x/crypto=${String(systemState?.xcrypto_version||"v0.47.0")}, ${String(systemState?.fips_module_version||"fips140-latest")} enabled=${String(systemState?.fips_runtime_enabled===true)} enforced=${String(systemState?.fips_runtime_enforced===true)}) ${Boolean(systemState?.fips_validated)?"":"(not validated)"} | Sample: ${entropySampleBytes} bytes in ${entropySampleMicros} us`;
  const certSecuritySummary = certSecurityLoading
    ? "loading..."
    : `${String(certSecurity?.storage||"db_encrypted")} / ${String(certSecurity?.hsm_mode||"software")} / ${String(certSecurity?.status||"ready")}`;
  const tlsPolicyLabel = String(systemState?.tls_mode||"internal_ca")
    .replace("internal_ca","TLS defaults")
    .replace("custom","Custom TLS")
    .replace("tls13_only","TLS 1.3 only")
    .replace("tls13_hybrid_ui","TLS 1.3 + Hybrid PQC (WebUI)")
    .replace("tls13_hybrid_kms","TLS 1.3 + Hybrid PQC (KMS internal)");
  const tlsDefaultCertSummary = systemTLSCertSource==="internal_ca"
    ? "Internal CA auto-issue"
    : systemTLSCertSource==="pki_ca"
      ? (systemTLSCAName ? `CA: ${systemTLSCAName}` : "CA from Certificates / PKI")
      : (systemTLSCertificateName ? `Certificate: ${systemTLSCertificateName}` : "Uploaded certificate from PKI");
  const networkSummary = [
    String(systemState?.mgmt_ip||"IP"),
    String(systemState?.dns_servers||"DNS"),
    String(systemState?.ntp_servers||"NTP"),
    String(systemState?.proxy_endpoint||"Proxy")
  ].join(", ");
  const backupSummary = `${String(systemState?.backup_schedule||"daily@02:00")} / ${String(systemState?.backup_target||"local")} / retention ${Number(systemState?.backup_retention_days||30)}d`;
  const passwordSummary = passwordPolicyLoading
    ? "loading..."
    : `Min ${Number(passwordPolicy?.min_length||12)}-${Number(passwordPolicy?.max_length||128)}, unique ${Number(passwordPolicy?.min_unique_chars||6)}, rules: ${[
      Boolean(passwordPolicy?.require_upper) ? "upper" : "",
      Boolean(passwordPolicy?.require_lower) ? "lower" : "",
      Boolean(passwordPolicy?.require_digit) ? "digit" : "",
      Boolean(passwordPolicy?.require_special) ? "special" : "",
      Boolean(passwordPolicy?.require_no_whitespace) ? "no-space" : "",
      Boolean(passwordPolicy?.deny_username) ? "no-username" : "",
      Boolean(passwordPolicy?.deny_email_local_part) ? "no-email-local" : ""
    ].filter(Boolean).join(", ") || "none"}`;
  const loginSummary = securityPolicyLoading
    ? "loading..."
    : `${Number(securityPolicy?.max_failed_attempts||5)} fails / ${Number(securityPolicy?.lockout_minutes||15)}m lock / idle ${Number(securityPolicy?.idle_timeout_minutes||15)}m`;
  const governanceSummary = `${String(gov.approval_delivery_mode||"kms_only")} / notifications: ${[
    gov.notify_dashboard ? "dashboard" : "",
    gov.notify_email ? "email" : "",
    gov.notify_slack ? "slack" : "",
    gov.notify_teams ? "teams" : ""
  ].filter(Boolean).join(", ") || "none"}`;
  const smtpSummary = String(gov.smtp_host||"").trim()
    ? `${String(gov.smtp_host)}:${String(gov.smtp_port||"587")}`
    : "SMTP not configured";
  const hardeningSummary = accessSettingsLoading
    ? "loading..."
    : `${String(accessSettings?.grant_default_type||"creator-default")} / replay ${Number(accessSettings?.replay_window_seconds||300)}s / interface ${Boolean(accessSettings?.interface_binding_required)?"required":"optional"}`;
  const activeTabLabel = SYSTEM_ADMIN_TABS.find((item)=>item.panel===panel)?.label || "Health";
  return <div style={{display:"grid",gap:8}}>
    <style>{`
      @keyframes vectaStatusPulse {
        0% { transform: scale(1); opacity: 0.85; box-shadow: 0 0 0 0 ${C.teal}59; }
        70% { transform: scale(1.08); opacity: 1; box-shadow: 0 0 0 5px ${C.teal}00; }
        100% { transform: scale(1); opacity: 0.85; box-shadow: 0 0 0 0 ${C.teal}00; }
      }
      .vecta-hb-dot {
        display:inline-block;
        width:7px;
        height:7px;
        border-radius:999px;
        margin-right:6px;
        vertical-align:middle;
      }
      .vecta-hb-running { background:${C.teal}; animation:vectaStatusPulse 1.8s ease-in-out infinite; }
      .vecta-hb-degraded { background:${C.amber}; animation:vectaStatusPulse 2.2s ease-in-out infinite; }
      .vecta-hb-down { background:${C.red}; animation:none; opacity:0.95; }
      .vecta-hb-unknown { background:${C.blue}; animation:vectaStatusPulse 2.6s ease-in-out infinite; }
    `}</style>
    <Tabs
      tabs={SYSTEM_ADMIN_TABS.map((item)=>item.label)}
      active={activeTabLabel}
      onChange={(tabLabel)=>{
        const next = SYSTEM_ADMIN_TABS.find((item)=>item.label===tabLabel)?.panel || "health";
        setPanel(next);
      }}
    />
    {panel==="health"&&<>
    <Section
      title="System Health"
      actions={<div style={{display:"flex",gap:8}}>
        <Btn
          small
          onClick={()=>void restartAllAllowedServices()}
          disabled={restartAllBusy||!restartableServiceNames.length}
        >
          {restartAllBusy?"Restarting...":"Restart All"}
        </Btn>
        <Btn small onClick={()=>void loadHealth()}>{healthLoading?"Refreshing...":"Refresh Health"}</Btn>
      </div>}
    >
      <Card style={{padding:10,borderRadius:8}}>
        <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:8}}>
          <span style={{fontSize:11,color:C.blue,background:C.bg,border:`1px solid ${C.border}`,padding:"3px 8px",borderRadius:999}}>{`${totalServices} Total`}</span>
          <span style={{fontSize:11,color:C.green,background:C.bg,border:`1px solid ${C.border}`,padding:"3px 8px",borderRadius:999}}>{`${Number(health.summary?.running||0)} Running`}</span>
          <span style={{fontSize:11,color:C.amber,background:C.bg,border:`1px solid ${C.border}`,padding:"3px 8px",borderRadius:999}}>{`${Number(health.summary?.degraded||0)} Degraded`}</span>
          <span style={{fontSize:11,color:C.red,background:C.bg,border:`1px solid ${C.border}`,padding:"3px 8px",borderRadius:999}}>{`${Number(health.summary?.down||0)} Down`}</span>
          <span style={{fontSize:11,color:C.blue,background:C.bg,border:`1px solid ${C.border}`,padding:"3px 8px",borderRadius:999}}>{`${Number(health.summary?.unknown||0)} Unknown`}</span>
          <span style={{fontSize:11,color:runtimeAllOk?C.green:C.amber,background:C.bg,border:`1px solid ${C.border}`,padding:"3px 8px",borderRadius:999,fontWeight:700}}>{runtimeAllOk?"ALL OK":"ATTN"}</span>
        </div>
        <div style={{maxHeight:420,overflowY:"auto",paddingRight:2}}>
          {(health.services||[]).map((svc)=>{
            const name=String(svc?.name||"unknown");
            const status=String(serviceStatusOverride[name]||svc?.status||"unknown");
            const restartAllowed=restartAllowedFor(svc);
            const restartBlockReason=String(svc?.restart_block_reason||"Restart is restricted for this service.");
            return <div key={name} style={{display:"grid",gridTemplateColumns:"1fr auto auto",gap:8,alignItems:"center",borderBottom:`1px solid ${C.border}`,padding:"7px 0"}}>
              <div style={{minWidth:0}}>
                <div style={{fontSize:11,color:C.text,fontWeight:700}}>{name}</div>
                <div style={{fontSize:10,color:C.dim,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}} title={String(svc?.output||svc?.source||"-")}>{String(svc?.output||svc?.source||"-")}</div>
              </div>
              <span style={{fontSize:11,color:C[tone(status)],textTransform:"capitalize",fontWeight:700,border:`1px solid ${C.border}`,background:C.bg,borderRadius:999,padding:"4px 10px"}}>
                <span className={`vecta-hb-dot ${heartbeatToneClass(status)}`} />
                {status}
              </span>
              <div style={{display:"flex",justifyContent:"flex-end"}}>
                {restartAllowed ? (
                  <Btn small onClick={()=>void restartSvc(name)} disabled={restartBusy===name||restartAllBusy}>{restartBusy===name?"...":"Restart"}</Btn>
                ) : (
                  <span style={{fontSize:9,color:C.muted}} title={restartBlockReason}>Restricted</span>
                )}
              </div>
            </div>;
          })}
          {!(health.services||[]).length?<div style={{fontSize:10,color:C.muted,paddingTop:8}}>No health data available.</div>:null}
        </div>
        <div style={{fontSize:10,color:C.dim,marginTop:8}}>Live status from backend service discovery and health checks.</div>
      </Card>
    </Section>
    </>}

    {panel==="runtime"&&<>
    <Section
      title="Runtime Crypto Mode"
      actions={<div style={{display:"flex",gap:8}}>
        <Btn small onClick={()=>void loadSystemState()} disabled={systemStateLoading}>{systemStateLoading?"Refreshing...":"Refresh Mode"}</Btn>
        <Btn small onClick={()=>{void Promise.all([loadTLSCatalog(),loadAccessHardening()]);setTlsConfigModalOpen(true);}}>Configure TLS</Btn>
        <Btn small onClick={()=>setFipsConfigModalOpen(true)}>Configure FIPS</Btn>
      </div>}
    >
      <Card style={{padding:10,borderRadius:8}}>
        <div style={{fontSize:11,color:C.dim,marginBottom:8}}>Enforced policy for approved algorithms, TLS profile, RNG mode, and entropy health.</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8}}>
          <div><span style={{fontSize:10,color:C.muted}}>Mode:</span><span style={{fontSize:13,color:C.text,fontWeight:700,marginLeft:4}}>{runtimeModeLabel}</span></div>
          <div style={{textAlign:"right"}}><span style={{fontSize:10,color:C.muted}}>TLS:</span><span style={{fontSize:13,color:C.text,fontWeight:700,marginLeft:4}}>{runtimeTlsLabel}</span></div>
          <div><span style={{fontSize:10,color:C.muted}}>RNG:</span><span style={{fontSize:13,color:C.text,fontWeight:700,marginLeft:4}}>{runtimeRngLabel}</span></div>
          <div style={{textAlign:"right"}}><span style={{fontSize:10,color:C.muted}}>Entropy:</span><span style={{fontSize:13,color:C.text,fontWeight:700,marginLeft:4}}>{`${entropyBits.toFixed(3)} bits/byte`}</span></div>
        </div>
        <div style={{display:"flex",gap:8,flexWrap:"wrap",marginTop:8}}>
          <Btn small primary={fipsMode!=="enabled"} onClick={()=>{setSystemState((p)=>({...p,fips_mode:"enabled"}));onFipsModeChange("enabled");}}>Enable FIPS</Btn>
          <Btn small primary={fipsMode!=="disabled"} onClick={()=>{setSystemState((p)=>({...p,fips_mode:"disabled"}));onFipsModeChange("disabled");}}>Disable FIPS</Btn>
          <span style={{fontSize:11,color:C.green,fontWeight:700,border:`1px solid ${C.border}`,background:C.bg,borderRadius:999,padding:"4px 9px",alignSelf:"center"}}>
            <span className={`vecta-hb-dot ${heartbeatToneClass(fipsMode==="enabled"?"running":"unknown")}`} />
            OK
          </span>
        </div>
        <div style={{display:"flex",gap:8,flexWrap:"wrap",marginTop:10}}>
          <B c="blue">{tlsPolicyLabel}</B>
          <B c="accent">{tlsDefaultCertSummary}</B>
        </div>
        <div style={{fontSize:10,color:C.dim,marginTop:8}}>{runtimeLibraryLine}</div>
      </Card>
    </Section>
    </>}

    <Modal open={fipsConfigModalOpen} onClose={()=>setFipsConfigModalOpen(false)} title="Configure FIPS Runtime">
      <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:10}}>
        <B c="blue">{runtimeModeLabel}</B>
        <B c="accent">{runtimeTlsLabel}</B>
        <B c={String(systemState?.fips_entropy_health||"ok").toLowerCase()==="ok"?"green":"amber"}>{`${entropyBits.toFixed(3)} bits/byte`}</B>
      </div>
      <Row2>
        <FG label="FIPS Policy">
          <Sel value={String(systemState?.fips_mode_policy||"standard")} onChange={(e)=>setSystemState((p)=>({...p,fips_mode_policy:String(e.target.value||"standard"),fips_mode:String(e.target.value)==="strict"?"enabled":"disabled"}))}>
            <option value="strict">Strict (non-approved blocked)</option>
            <option value="standard">Standard (log-only)</option>
          </Sel>
        </FG>
        <FG label="FIPS Mode">
          <Inp value={String(systemState?.fips_mode||"disabled")} readOnly />
        </FG>
      </Row2>
      <Row2>
        <FG label="TLS Profile">
          <Sel value={String(systemState?.fips_tls_profile||"tls12_fips_suites")} onChange={(e)=>setSystemState((p)=>({...p,fips_tls_profile:String(e.target.value||"tls12_fips_suites")}))}>
            <option value="tls12_fips_suites">TLS 1.2+ FIPS suites</option>
            <option value="tls13_only">TLS 1.3 only</option>
          </Sel>
        </FG>
        <FG label="RNG Mode">
          <Sel value={String(systemState?.fips_rng_mode||"ctr_drbg")} onChange={(e)=>setSystemState((p)=>({...p,fips_rng_mode:String(e.target.value||"ctr_drbg")}))}>
            <option value="ctr_drbg">CTR_DRBG</option>
            <option value="hmac_drbg">HMAC_DRBG</option>
            <option value="hsm_trng">HSM_TRNG</option>
          </Sel>
        </FG>
      </Row2>
      <FG label="Entropy Source">
        <Sel value={String(systemState?.fips_entropy_source||"os-csprng")} onChange={(e)=>setSystemState((p)=>({...p,fips_entropy_source:String(e.target.value||"os-csprng")}))}>
          <option value="os-csprng">OS CSPRNG</option>
          <option value="software">Software</option>
          <option value="hsm-trng">HSM TRNG</option>
        </Sel>
      </FG>
      <div style={{
        display:"grid",
        gap:4,
        fontSize:10,
        color:C.dim,
        marginTop:8,
        padding:"10px 12px",
        border:`1px solid ${C.border}`,
        borderRadius:10,
        background:C.bg
      }}>
        <div>{`Entropy health: ${String(systemState?.fips_entropy_health||"unknown")} | ${entropyBits.toFixed(3)} bits/byte`}</div>
        <div>{`Sample: ${entropySampleBytes} bytes in ${entropySampleMicros} us`}</div>
        <div>{`Runtime: enabled=${Boolean(systemState?.fips_runtime_enabled)} enforced=${Boolean(systemState?.fips_runtime_enforced)}`}</div>
        <div>{runtimeLibraryLine}</div>
      </div>
      <div style={{fontSize:10,color:C.dim,marginTop:8}}>
        Runtime Crypto stays on this tab. Network addresses live under Network, and certificate issuance for exposed TLS interfaces is governed from Configure TLS.
      </div>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn small onClick={()=>setFipsConfigModalOpen(false)}>Cancel</Btn>
        <Btn small primary onClick={()=>void saveFipsConfig()} disabled={systemStateSaving}>{systemStateSaving?"Saving...":"Save FIPS"}</Btn>
      </div>
    </Modal>

    <Modal open={tlsConfigModalOpen} onClose={()=>{setTlsConfigModalOpen(false);void loadAccessHardening();}} title="Configure TLS Defaults">
      <FG label="TLS Runtime Policy">
        <Sel value={String(systemState?.tls_mode||"internal_ca")} onChange={(e)=>setSystemState((p)=>({...p,tls_mode:String(e.target.value||"internal_ca")}))}>
          <option value="internal_ca">Standard TLS defaults</option>
          <option value="custom">Custom TLS</option>
          <option value="tls13_only">TLS 1.3 only</option>
          <option value="tls13_hybrid_ui">TLS 1.3 + Hybrid PQC (WebUI)</option>
          <option value="tls13_hybrid_kms">TLS 1.3 + Hybrid PQC (KMS internal)</option>
        </Sel>
      </FG>
      <FG label="Default Certificate Source">
        <Sel value={systemTLSCertSource} onChange={(e)=>setInterfaceTLSConfig((p)=>({
          ...p,
          certificate_source: String(e.target.value||"internal_ca"),
          ca_id: String(e.target.value)==="pki_ca" ? String(p?.ca_id||"") : "",
          certificate_id: String(e.target.value)==="uploaded_certificate" ? String(p?.certificate_id||"") : ""
        }))} disabled={interfaceTLSConfigLoading}>
          {TLS_CERT_MODE_OPTIONS.map((item)=><option key={item.value} value={item.value}>{item.label}</option>)}
        </Sel>
      </FG>
      {systemTLSCertSource==="pki_ca"&&<FG label="Default Issuing CA">
        <Sel value={systemTLSCAID} onChange={(e)=>setInterfaceTLSConfig((p)=>({...p,ca_id:String(e.target.value||"")}))} disabled={tlsCatalogLoading||interfaceTLSConfigLoading}>
          <option value="">{tlsCatalogLoading?"Loading CAs...":"Select CA"}</option>
          {caOptions.map((item)=><option key={item.id} value={item.id}>{item.name}</option>)}
        </Sel>
      </FG>}
      {systemTLSCertSource==="uploaded_certificate"&&<FG label="Default Certificate">
        <Sel value={systemTLSCertificateID} onChange={(e)=>setInterfaceTLSConfig((p)=>({...p,certificate_id:String(e.target.value||"")}))} disabled={tlsCatalogLoading||interfaceTLSConfigLoading}>
          <option value="">{tlsCatalogLoading?"Loading certificates...":"Select certificate"}</option>
          {certificateOptions.map((item)=><option key={item.id} value={item.id}>{item.subject_cn}</option>)}
        </Sel>
      </FG>}
      <div style={{display:"flex",gap:8,flexWrap:"wrap",marginTop:6}}>
        <B c="blue">{tlsPolicyLabel}</B>
        <B c="accent">{tlsDefaultCertSummary}</B>
      </div>
      {tlsDefaultsOutOfSync&&<div style={{fontSize:10,color:C.amber,marginTop:8}}>
        TLS-capable interfaces are currently using mixed certificate bindings. Saving here will normalize REST, KMIP, and other TLS endpoints to this one shared TLS configuration.
      </div>}
      <div style={{fontSize:10,color:C.dim,marginTop:6}}>
        Interface ports, bind addresses, and HTTP versus HTTPS/TLS exposure are configured in the Interfaces tab. The certificate source selected here is authoritative and is applied across all TLS-enabled interfaces.
      </div>
      <div style={{display:"flex",justifyContent:"space-between",gap:8,marginTop:12}}>
        <Btn small onClick={()=>{setTlsConfigModalOpen(false);setPanel("interfaces");void loadAccessHardening();}}>Open Interfaces</Btn>
        <div style={{display:"flex",gap:8}}>
          <Btn small onClick={()=>{setTlsConfigModalOpen(false);void loadAccessHardening();}}>Cancel</Btn>
          <Btn small primary onClick={()=>void saveTLSConfig()} disabled={systemStateSaving||interfaceTLSConfigLoading}>{systemStateSaving?"Saving...":"Save TLS"}</Btn>
        </div>
      </div>
    </Modal>

    {panel==="network"&&<>
    <Section title="Network" actions={<div style={{display:"flex",gap:8}}>
      <Btn small onClick={()=>void loadSystemState()} disabled={systemStateLoading}>{systemStateLoading?"Refreshing...":"Refresh"}</Btn>
      <Btn small primary onClick={()=>void saveSystemState()} disabled={systemStateLoading||systemStateSaving}>{systemStateSaving?"Saving...":"Save"}</Btn>
      <Btn small onClick={async()=>{try{const r=await applyNetworkConfig(session!);onToast(r?.message||"Network config applied.");}catch(e){onToast(`Apply failed: ${errMsg(e)}`);}}} disabled={!session?.token||systemStateSaving}>Apply Network Config</Btn>
    </div>}>
      <Card style={{padding:10,borderRadius:8}}>
        <Row2>
          <FG label="Management IP"><Inp value={String(systemState?.mgmt_ip||"")} onChange={(e)=>setSystemState((p)=>({...p,mgmt_ip:e.target.value}))} placeholder="10.0.1.100"/></FG>
          <FG label="Cluster IP"><Inp value={String(systemState?.cluster_ip||"")} onChange={(e)=>setSystemState((p)=>({...p,cluster_ip:e.target.value}))} placeholder="172.16.0.100"/></FG>
        </Row2>
        <Row2>
          <FG label="DNS Servers"><Inp value={String(systemState?.dns_servers||"")} onChange={(e)=>setSystemState((p)=>({...p,dns_servers:e.target.value}))} placeholder="8.8.8.8,1.1.1.1"/></FG>
          <FG label="NTP Servers"><Inp value={String(systemState?.ntp_servers||"")} onChange={(e)=>setSystemState((p)=>({...p,ntp_servers:e.target.value}))} placeholder="pool.ntp.org"/></FG>
        </Row2>
        <Row2>
          <FG label="Proxy Endpoint"><Inp value={String(systemState?.proxy_endpoint||"")} onChange={(e)=>setSystemState((p)=>({...p,proxy_endpoint:e.target.value}))} placeholder="https://proxy.bank.local:8443"/></FG>
          <FG label="Routing Note"><Inp value="TLS listener and certificate settings are managed from Runtime Crypto and Interfaces." readOnly /></FG>
        </Row2>
        <div style={{fontSize:10,color:C.dim,marginTop:8}}>{networkSummary}</div>
      </Card>
      <Card style={{padding:8,borderRadius:8,marginTop:8,background:`${C.amber}11`,border:`1px solid ${C.amber}33`}}>
        <div style={{fontSize:10,color:C.amber,fontWeight:600}}>Changing the management or cluster IP will update Docker network bindings on next restart. This may cause a brief connectivity disruption. Ensure you can reach the appliance on the new IP before applying.</div>
      </Card>
    </Section>
    </>}

    {panel==="snmp"&&<>
    <Section title="SNMP / SIEM Integration" actions={<div style={{display:"flex",gap:8}}>
      <Btn small onClick={()=>void loadSystemState()} disabled={systemStateLoading}>{systemStateLoading?"Refreshing...":"Refresh"}</Btn>
      <Btn small onClick={()=>void testSnmpSettings()} disabled={snmpTesting}>{snmpTesting?"Testing...":"Test SNMP"}</Btn>
      <Btn small primary onClick={()=>void saveSnmpSettings()} disabled={systemStateSaving}>{systemStateSaving?"Saving...":"Save SNMP"}</Btn>
    </div>}>
      <Card style={{padding:10,borderRadius:8}}>
        <Row3>
          <FG label="Transport">
            <Sel value={String(systemState?.snmp_transport||"udp")} onChange={(e)=>setSystemState((p)=>({...p,snmp_transport:String(e.target.value||"udp")}))}>
              <option value="udp">UDP</option>
              <option value="tcp">TCP</option>
            </Sel>
          </FG>
          <FG label="Host / SIEM Collector"><Inp value={String(systemState?.snmp_host||"")} onChange={(e)=>setSystemState((p)=>({...p,snmp_host:e.target.value}))} placeholder="siem.bank.local"/></FG>
          <FG label="Port"><Inp type="number" value={String(systemState?.snmp_port||162)} onChange={(e)=>setSystemState((p)=>({...p,snmp_port:Math.max(1,Math.min(65535,Number(e.target.value||162)))}))}/></FG>
        </Row3>
        <Row3>
          <FG label="SNMP Version">
            <Sel value={String(systemState?.snmp_version||"v2c")} onChange={(e)=>setSystemState((p)=>({...p,snmp_version:String(e.target.value||"v2c")}))}>
              <option value="v1">v1</option>
              <option value="v2c">v2c</option>
              <option value="v3">v3</option>
            </Sel>
          </FG>
          <FG label="Timeout (sec)"><Inp type="number" value={String(systemState?.snmp_timeout_sec||3)} onChange={(e)=>setSystemState((p)=>({...p,snmp_timeout_sec:Math.max(1,Number(e.target.value||3))}))}/></FG>
          <FG label="Retries"><Inp type="number" value={String(systemState?.snmp_retries||1)} onChange={(e)=>setSystemState((p)=>({...p,snmp_retries:Math.max(0,Number(e.target.value||1))}))}/></FG>
        </Row3>
        <FG label="Trap OID"><Inp value={String(systemState?.snmp_trap_oid||".1.3.6.1.4.1.53864.1.0.1")} onChange={(e)=>setSystemState((p)=>({...p,snmp_trap_oid:e.target.value}))} placeholder=".1.3.6.1.4.1.53864.1.0.1"/></FG>

        {String(systemState?.snmp_version||"v2c")==="v3" ? <>
          <Row3>
            <FG label="SNMPv3 User"><Inp value={String(systemState?.snmp_v3_user||"")} onChange={(e)=>setSystemState((p)=>({...p,snmp_v3_user:e.target.value}))}/></FG>
            <FG label="Security Level">
              <Sel value={String(systemState?.snmp_v3_security_level||"authPriv")} onChange={(e)=>setSystemState((p)=>({...p,snmp_v3_security_level:e.target.value}))}>
                <option value="noAuthNoPriv">noAuthNoPriv</option>
                <option value="authNoPriv">authNoPriv</option>
                <option value="authPriv">authPriv</option>
              </Sel>
            </FG>
            <FG label="Auth Protocol">
              <Sel value={String(systemState?.snmp_v3_auth_proto||"sha256")} onChange={(e)=>setSystemState((p)=>({...p,snmp_v3_auth_proto:e.target.value}))}>
                <option value="md5">MD5</option>
                <option value="sha">SHA1</option>
                <option value="sha224">SHA224</option>
                <option value="sha256">SHA256</option>
                <option value="sha384">SHA384</option>
                <option value="sha512">SHA512</option>
              </Sel>
            </FG>
          </Row3>
          <Row2>
            <FG label="Auth Passphrase"><Inp type="password" value={String(systemState?.snmp_v3_auth_pass||"")} onChange={(e)=>setSystemState((p)=>({...p,snmp_v3_auth_pass:e.target.value}))}/></FG>
            <FG label="Privacy Protocol">
              <Sel value={String(systemState?.snmp_v3_priv_proto||"aes")} onChange={(e)=>setSystemState((p)=>({...p,snmp_v3_priv_proto:e.target.value}))}>
                <option value="des">DES</option>
                <option value="aes">AES128</option>
                <option value="aes192">AES192</option>
                <option value="aes192c">AES192C</option>
                <option value="aes256">AES256</option>
                <option value="aes256c">AES256C</option>
              </Sel>
            </FG>
          </Row2>
          <FG label="Privacy Passphrase"><Inp type="password" value={String(systemState?.snmp_v3_priv_pass||"")} onChange={(e)=>setSystemState((p)=>({...p,snmp_v3_priv_pass:e.target.value}))}/></FG>
        </> : <>
          <FG label="Community String"><Inp value={String(systemState?.snmp_community||"public")} onChange={(e)=>setSystemState((p)=>({...p,snmp_community:e.target.value}))}/></FG>
        </>}

        <div style={{marginTop:8,borderTop:`1px solid ${C.border}`,paddingTop:8}}>
          <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:8}}>SIEM Mapping</div>
          <Row3>
            <FG label="SIEM Vendor"><Inp value={String(systemState?.snmp_siem_vendor||"")} onChange={(e)=>setSystemState((p)=>({...p,snmp_siem_vendor:e.target.value}))} placeholder="Splunk / QRadar / ArcSight"/></FG>
            <FG label="Event Source"><Inp value={String(systemState?.snmp_siem_source||"vecta-kms")} onChange={(e)=>setSystemState((p)=>({...p,snmp_siem_source:e.target.value}))}/></FG>
            <FG label="Facility"><Inp value={String(systemState?.snmp_siem_facility||"security")} onChange={(e)=>setSystemState((p)=>({...p,snmp_siem_facility:e.target.value}))}/></FG>
          </Row3>
        </div>

        <div style={{fontSize:10,color:C.dim,marginTop:8,wordBreak:"break-all"}}>
          {`Target: ${buildSNMPTargetFromState(systemState as Record<string, any>) || "not configured"}`}
        </div>
      </Card>
    </Section>
    </>}

    {panel==="license"&&<>
    <Section title="License" actions={<Btn small primary onClick={()=>void saveSystemState()} disabled={systemStateSaving}>{systemStateSaving?"Saving...":"Save"}</Btn>}>
      <Card style={{padding:10,borderRadius:8}}>
        <FG label="License Status"><Inp value={String(systemState?.license_status||"inactive")} onChange={(e)=>setSystemState((p)=>({...p,license_status:e.target.value}))}/></FG>
        <FG label="License Key / Activation Token"><Inp value={String(systemState?.license_key||"")} onChange={(e)=>setSystemState((p)=>({...p,license_key:e.target.value}))} placeholder="paste activation token"/></FG>
        <Row2>
          <FG label="Licensed Tenants"><Inp type="number" value={String(systemState?.license_tenants||0)} onChange={(e)=>setSystemState((p)=>({...p,license_tenants:Math.max(0,Number(e.target.value||0))}))}/></FG>
          <FG label="Licensed Ops/Day"><Inp type="number" value={String(systemState?.license_ops_per_day||0)} onChange={(e)=>setSystemState((p)=>({...p,license_ops_per_day:Math.max(0,Number(e.target.value||0))}))}/></FG>
        </Row2>
      </Card>
    </Section>
    </>}

    {panel==="tags"&&<>
    <Section title="Tags" actions={<Btn small onClick={()=>void loadTags()}>Refresh</Btn>}>
      <Card style={{padding:10,borderRadius:8}}>
        <div style={{display:"flex",gap:8,alignItems:"end",flexWrap:"wrap"}}>
          <FG label="Tag Name"><Inp value={newTagName} onChange={(e)=>setNewTagName(e.target.value)} placeholder="tag-name"/></FG>
          <FG label="Color"><Inp type="color" value={newTagColor} onChange={(e)=>setNewTagColor(e.target.value)} w={90}/></FG>
          <Btn small primary onClick={()=>void addTag()} disabled={tagSaving}>{tagSaving?"Saving...":"Add Tag"}</Btn>
        </div>
        <div style={{marginTop:10,display:"grid",gap:6}}>
          {(Array.isArray(tagCatalog)?tagCatalog:[]).map((tag:any)=>{
            const name=String(tag?.name||"");
            const color=String(tag?.color||C.teal);
            const usageCount=Math.max(0,Number(tag?.usage_count||0));
            return <div key={name} style={{display:"flex",justifyContent:"space-between",alignItems:"center",borderBottom:`1px solid ${C.border}`,paddingBottom:6}}>
              <div style={{display:"flex",alignItems:"center",gap:8}}>
                <span style={{display:"inline-block",width:12,height:12,borderRadius:999,background:color,border:`1px solid ${C.border}`}} />
                <span style={{fontSize:12,color:C.text,fontWeight:700}}>{name}</span>
                <span style={{fontSize:10,color:usageCount>0?C.amber:C.muted}}>
                  {usageCount>0?`${usageCount} active key(s)`:"unused"}
                </span>
              </div>
              <Btn small danger onClick={()=>void removeTag(name,usageCount)} disabled={usageCount>0}>Delete</Btn>
            </div>;
          })}
          {!(Array.isArray(tagCatalog)?tagCatalog:[]).length?<div style={{fontSize:10,color:C.muted}}>No tags defined.</div>:null}
        </div>
      </Card>
    </Section>
    </>}

    {panel==="password"&&<>
    <Section title="Password Policy" actions={<div style={{display:"flex",gap:8}}><Btn small onClick={()=>void loadPasswordPolicy()} disabled={passwordPolicyLoading||passwordPolicySaving}>{passwordPolicyLoading?"Reloading...":"Reload Policy"}</Btn><Btn small primary onClick={()=>void savePasswordPolicy()} disabled={passwordPolicyLoading||passwordPolicySaving||!passwordPolicy}>{passwordPolicySaving?"Saving...":"Save Policy"}</Btn></div>}>
      <ScopeBanner section="passwordPolicy"/>
      <Card style={{padding:10,borderRadius:8}}>
        <Row2>
          <FG label="Min Length"><Inp type="number" value={String(passwordPolicy?.min_length||12)} onChange={(e)=>setPasswordPolicy((p)=>({...p,min_length:Math.max(8,Number(e.target.value||12))}))}/></FG>
          <FG label="Max Length"><Inp type="number" value={String(passwordPolicy?.max_length||128)} onChange={(e)=>setPasswordPolicy((p)=>({...p,max_length:Math.max(8,Number(e.target.value||128))}))}/></FG>
        </Row2>
        <Row2>
          <FG label="Min Unique"><Inp type="number" value={String(passwordPolicy?.min_unique_chars||6)} onChange={(e)=>setPasswordPolicy((p)=>({...p,min_unique_chars:Math.max(0,Number(e.target.value||6))}))}/></FG>
        </Row2>
        <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8}}>
          <Chk label="Require uppercase letters" checked={Boolean(passwordPolicy?.require_upper)} onChange={()=>setPasswordPolicy((p)=>({...p,require_upper:!Boolean(p?.require_upper)}))}/>
          <Chk label="Require lowercase letters" checked={Boolean(passwordPolicy?.require_lower)} onChange={()=>setPasswordPolicy((p)=>({...p,require_lower:!Boolean(p?.require_lower)}))}/>
          <Chk label="Require digits" checked={Boolean(passwordPolicy?.require_digit)} onChange={()=>setPasswordPolicy((p)=>({...p,require_digit:!Boolean(p?.require_digit)}))}/>
          <Chk label="Require special characters" checked={Boolean(passwordPolicy?.require_special)} onChange={()=>setPasswordPolicy((p)=>({...p,require_special:!Boolean(p?.require_special)}))}/>
          <Chk label="Disallow whitespace" checked={Boolean(passwordPolicy?.require_no_whitespace)} onChange={()=>setPasswordPolicy((p)=>({...p,require_no_whitespace:!Boolean(p?.require_no_whitespace)}))}/>
          <Chk label="Disallow username in password" checked={Boolean(passwordPolicy?.deny_username)} onChange={()=>setPasswordPolicy((p)=>({...p,deny_username:!Boolean(p?.deny_username)}))}/>
          <Chk label="Disallow email local-part in password" checked={Boolean(passwordPolicy?.deny_email_local_part)} onChange={()=>setPasswordPolicy((p)=>({...p,deny_email_local_part:!Boolean(p?.deny_email_local_part)}))}/>
        </div>
        <div style={{fontSize:10,color:C.dim,marginTop:8}}>{passwordSummary}</div>
      </Card>
    </Section>
    </>}

    {panel==="login"&&<>
    <Section title="Login Security" actions={<Btn small primary onClick={()=>void saveSecurityPolicy()} disabled={securityPolicyLoading||securityPolicySaving||!securityPolicy}>{securityPolicySaving?"Saving...":"Save"}</Btn>}>
      <ScopeBanner section="loginSecurity"/>
      <Card style={{padding:10,borderRadius:8}}>
        <Row3>
          <FG label="Max Failed Attempts"><Inp type="number" value={String(securityPolicy?.max_failed_attempts||5)} onChange={(e)=>setSecurityPolicy((p)=>({...p,max_failed_attempts:Math.max(3,Number(e.target.value||5))}))}/></FG>
          <FG label="Lockout Minutes"><Inp type="number" value={String(securityPolicy?.lockout_minutes||15)} onChange={(e)=>setSecurityPolicy((p)=>({...p,lockout_minutes:Math.max(1,Number(e.target.value||15))}))}/></FG>
          <FG label="Idle Timeout Minutes"><Inp type="number" value={String(securityPolicy?.idle_timeout_minutes||15)} onChange={(e)=>setSecurityPolicy((p)=>({...p,idle_timeout_minutes:Math.max(1,Number(e.target.value||15))}))}/></FG>
        </Row3>
        <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8}}>
          <Chk label="Require MFA for privileged actions" checked={Boolean(securityPolicy?.require_mfa_for_privileged_actions)} onChange={()=>setSecurityPolicy((p)=>({...p,require_mfa_for_privileged_actions:!Boolean(p?.require_mfa_for_privileged_actions)}))}/>
          <Chk label="Force re-auth for sensitive operations" checked={Boolean(securityPolicy?.require_reauth_sensitive)} onChange={()=>setSecurityPolicy((p)=>({...p,require_reauth_sensitive:!Boolean(p?.require_reauth_sensitive)}))}/>
        </div>
        <div style={{fontSize:10,color:C.dim,marginTop:8}}>{loginSummary}</div>
      </Card>
    </Section>
    </>}

    {panel==="keyaccess"&&<>
    <Section title="Key Access Hardening" actions={<div style={{display:"flex",gap:8}}>
      <Btn small onClick={()=>void loadAccessHardening()} disabled={accessSettingsLoading||interfaceConfigLoading}>{accessSettingsLoading||interfaceConfigLoading?"Refreshing...":"Refresh"}</Btn>
      <Btn small primary onClick={()=>void saveAccessHardening()} disabled={accessSettingsSaving||!accessSettings}>{accessSettingsSaving?"Saving...":"Save"}</Btn>
    </div>}>
      <Card style={{padding:10,borderRadius:8}}>
        <Row3>
          <FG label="Default Grant Type">
            <Sel value={String(accessSettings?.grant_default_type||"creator-default")} onChange={(e)=>setAccessSettings((p)=>({...p,grant_default_type:e.target.value}))}>
              <option value="creator-default">Creator Default</option>
              <option value="admin-only">Admin Only</option>
              <option value="assigned-only">Assigned Only</option>
            </Sel>
          </FG>
          <FG label="Default TTL (min)"><Inp type="number" value={String(accessSettings?.grant_default_ttl_minutes||60)} onChange={(e)=>setAccessSettings((p)=>({...p,grant_default_ttl_minutes:Math.max(0,Number(e.target.value||60))}))}/></FG>
          <FG label="Max TTL (min)"><Inp type="number" value={String(accessSettings?.grant_max_ttl_minutes||1440)} onChange={(e)=>setAccessSettings((p)=>({...p,grant_max_ttl_minutes:Math.max(0,Number(e.target.value||1440))}))}/></FG>
        </Row3>
        <Row3>
          <FG label="Replay Window (sec)"><Inp type="number" value={String(accessSettings?.replay_window_seconds||300)} onChange={(e)=>setAccessSettings((p)=>({...p,replay_window_seconds:Math.max(30,Number(e.target.value||300))}))}/></FG>
          <FG label="Nonce TTL (sec)"><Inp type="number" value={String(accessSettings?.nonce_ttl_seconds||900)} onChange={(e)=>setAccessSettings((p)=>({...p,nonce_ttl_seconds:Math.max(30,Number(e.target.value||900))}))}/></FG>
          <FG label="Profile"><Inp value={hardeningSummary} readOnly /></FG>
        </Row3>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8}}>
          <Chk label="Require mTLS" checked={Boolean(accessSettings?.require_mtls)} onChange={()=>setAccessSettings((p)=>({...p,require_mtls:!Boolean(p?.require_mtls)}))}/>
          <Chk label="Require Signed Nonce" checked={Boolean(accessSettings?.require_signed_nonce)} onChange={()=>setAccessSettings((p)=>({...p,require_signed_nonce:!Boolean(p?.require_signed_nonce)}))}/>
          <Chk label="Interface Binding Required" checked={Boolean(accessSettings?.interface_binding_required)} onChange={()=>setAccessSettings((p)=>({...p,interface_binding_required:!Boolean(p?.interface_binding_required)}))}/>
        </div>
      </Card>

    </Section>
    </>}

    {panel==="interfaces"&&<>
    <Section title="Network Interfaces" actions={<div style={{display:"flex",gap:8}}>
      <Btn small onClick={()=>void Promise.all([loadAccessHardening(),loadHealth()])} disabled={interfaceConfigLoading||healthLoading}>{interfaceConfigLoading||healthLoading?"Refreshing...":"Refresh"}</Btn>
      <Btn small primary onClick={()=>openNetIfModal()} disabled={!availableInterfaceDefs.length}>+ Add Interface</Btn>
    </div>}>
      <div style={{fontSize:11,color:C.dim,marginBottom:14}}>
        Only user-configurable request-handling endpoints are shown here. Internal service ports and runtime-only listeners are intentionally hidden from this view. TLS certificate issuance and certificate binding come from Runtime Crypto -&gt; Configure TLS and apply to every TLS-enabled interface here.
      </div>
      {String(health?.warning||"").trim()&&<div style={{fontSize:10,color:C.amber,marginBottom:12}}>{String(health.warning)}</div>}
      {hiddenConfiguredInterfaceCount>0&&<div style={{fontSize:10,color:C.dim,marginBottom:12}}>{`${hiddenConfiguredInterfaceCount} internal or legacy interface entr${hiddenConfiguredInterfaceCount===1?"y is":"ies are"} hidden from this panel.`}</div>}

      <div style={{display:"flex",gap:10,marginBottom:16,flexWrap:"wrap"}}>
        <Stat l="Configured" v={interfaceCardStats.total} c="accent"/>
        <Stat l="Enabled" v={interfaceCardStats.enabled} c="green"/>
        <Stat l="Listening" v={interfaceCardStats.listening} c="blue"/>
        <Stat l="External Bind" v={interfaceCardStats.external} c="purple"/>
      </div>

      <div style={{display:"grid",gap:8}}>
        {configuredInterfaces.map((iface)=>{
          const statusTone = interfaceTone(String(iface.status||""));
          const statusColor = statusTone==="green"?C.green:statusTone==="amber"?C.amber:statusTone==="red"?C.red:C.dim;
          return(
            <Card key={iface.id} style={{padding:"10px 14px"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:8,gap:10}}>
                <div>
                  <div style={{display:"flex",alignItems:"center",gap:8,flexWrap:"wrap"}}>
                    <span style={{fontSize:13,fontWeight:700,color:C.text}}>{iface.name}</span>
                    <B c={iface.enabled?"green":"red"}>{iface.enabled?"Active":"Disabled"}</B>
                    <B c="blue">{iface.service}</B>
                  </div>
                  <div style={{fontSize:10,color:C.muted,marginTop:2}}>{iface.description}</div>
                </div>
                <div style={{display:"flex",gap:6,flexWrap:"wrap",justifyContent:"flex-end"}}>
                  <Btn small onClick={()=>void toggleNetIfEnabled(iface)}>{iface.enabled?"Disable":"Enable"}</Btn>
                  <Btn small onClick={()=>openNetIfModal(iface)}>Edit</Btn>
                  <Btn small danger onClick={()=>void deleteNetIf(iface.interface_name)}>Delete</Btn>
                </div>
              </div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(7,1fr)",gap:8}}>
                <div><div style={{fontSize:8,color:C.muted,textTransform:"uppercase",letterSpacing:0.6}}>Protocol</div><div style={{fontSize:10,color:C.text,fontWeight:600,marginTop:2}}>{iface.protocol_label}</div></div>
                <div><div style={{fontSize:8,color:C.muted,textTransform:"uppercase",letterSpacing:0.6}}>Quantum Mode</div><div style={{fontSize:10,color:C.text,fontWeight:600,marginTop:2}}>{iface.pqc_label}</div></div>
                <div><div style={{fontSize:8,color:C.muted,textTransform:"uppercase",letterSpacing:0.6}}>Certificate</div><div style={{fontSize:10,color:C.text,fontWeight:600,marginTop:2}}>{iface.cert_label}</div></div>
                <div><div style={{fontSize:8,color:C.muted,textTransform:"uppercase",letterSpacing:0.6}}>Configured Endpoint</div><div style={{fontSize:10,color:C.text,fontWeight:600,marginTop:2}}>{`${iface.bind_address}:${iface.port}`}</div></div>
                <div><div style={{fontSize:8,color:C.muted,textTransform:"uppercase",letterSpacing:0.6}}>Runtime Endpoint</div><div style={{fontSize:10,color:iface.runtime_bind_address?C.text:C.dim,fontWeight:600,marginTop:2}}>{iface.runtime_bind_address?`${iface.runtime_bind_address}:${String(iface.runtime_port||iface.port)}`:"Not detected"}</div></div>
                <div><div style={{fontSize:8,color:C.muted,textTransform:"uppercase",letterSpacing:0.6}}>Auto-Cert</div><div style={{fontSize:10,color:iface.auto_create_cert?C.green:C.dim,fontWeight:600,marginTop:2}}>{iface.auto_create_cert?"Yes":"No"}</div></div>
                <div><div style={{fontSize:8,color:C.muted,textTransform:"uppercase",letterSpacing:0.6}}>Status</div><div style={{fontSize:10,color:statusColor,fontWeight:600,marginTop:2,textTransform:"capitalize"}}>{iface.status}</div></div>
              </div>
            </Card>
          );
        })}
        {!configuredInterfaces.length&&<div style={{textAlign:"center",padding:24,color:C.muted,fontSize:11}}>No user-facing interfaces are configured yet. Add one to expose a request-handling endpoint.</div>}
      </div>

    </Section>

    <Modal open={netIfModalOpen} onClose={()=>{setNetIfModalOpen(false);setEditingNetIf(null);}} title={editingNetIf?"Edit Interface":"Add Interface"}>
      <FG label="Interface">
        <Sel value={ifName} onChange={(e)=>applyInterfaceSelection(e.target.value)} disabled={Boolean(editingNetIf)}>
          {availableInterfaceDefs.map((item)=><option key={item.key} value={item.key}>{item.label}</option>)}
        </Sel>
      </FG>
      <FG label="Description"><Inp value={ifDesc} onChange={(e)=>setIfDesc(e.target.value)} placeholder={selectedInterfaceDef?.description||"Interface description"}/></FG>
      <Row2>
        <FG label="Bind Address"><Inp value={ifBindAddr} onChange={(e)=>setIfBindAddr(e.target.value)} placeholder={selectedInterfaceDef?.defaultBindAddress||"0.0.0.0"}/></FG>
        <FG label="Port"><Inp type="number" value={ifPort} onChange={(e)=>setIfPort(e.target.value)} placeholder={String(selectedInterfaceDef?.defaultPort||443)}/></FG>
      </Row2>
      <Row3>
        <FG label="Service"><Inp value={selectedInterfaceDef?.service||""} readOnly/></FG>
        <FG label="Protocol">
          <Sel value={ifProtocol} onChange={(e)=>setIfProtocol(normalizeInterfaceProtocol(e.target.value, selectedInterfaceDef?.defaultProtocol||"http"))}>
            {availableProtocolOptions.map((protocol)=><option key={protocol} value={protocol}>{INTERFACE_PROTOCOL_LABELS[protocol]}</option>)}
          </Sel>
        </FG>
        <FG label="Quantum Mode">
          <Sel value={ifPQCMode} onChange={(e)=>setIfPQCMode(normalizeInterfacePQCMode(e.target.value, ifProtocol))} disabled={!interfaceTLSRequired}>
            {(interfaceTLSRequired ? (["inherit","classical","hybrid","pqc_only"] as InterfacePQCMode[]) : (["classical"] as InterfacePQCMode[])).map((mode)=><option key={mode} value={mode}>{INTERFACE_PQC_MODE_LABELS[mode]}</option>)}
          </Sel>
        </FG>
      </Row3>
      <Row3>
        <FG label="Certificate Source">
          <Inp value={interfaceTLSRequired ? INTERFACE_CERT_SOURCE_LABELS[ifCertSource] : "Not required"} readOnly/>
        </FG>
        <FG label="Hybrid TLS Guidance"><Inp value={interfaceTLSRequired ? (ifPQCMode==="hybrid" ? "Classical + PQC handshake path enabled" : ifPQCMode==="pqc_only" ? "PQC-only handshake target" : ifPQCMode==="classical" ? "Legacy TLS only" : "Uses tenant PQC policy default") : "Not applicable"} readOnly/></FG>
        <FG label="Policy Source"><Inp value={interfaceTLSRequired ? (ifPQCMode==="inherit" ? "Inherited from Post-Quantum Crypto policy" : "Interface override") : "Classical only"} readOnly/></FG>
      </Row3>
      {interfaceTLSRequired&&<>
        <FG label="TLS Binding Source"><Inp value="Managed by Runtime Crypto -> Configure TLS" readOnly/></FG>
        {ifCertSource==="pki_ca"&&<FG label="Issuing CA"><Inp value={selectedTLSCAName||"Select in Configure TLS"} readOnly/></FG>}
        {ifCertSource==="uploaded_certificate"&&<FG label="Certificate"><Inp value={selectedTLSCertificateName||"Select in Configure TLS"} readOnly/></FG>}
        <div style={{fontSize:10,color:C.dim,marginTop:6}}>
          {ifCertSource==="internal_ca"
            ? "This interface will auto-issue its TLS certificate from the internal CA selected in Configure TLS."
            : ifCertSource==="pki_ca"
              ? `This interface will request or renew a certificate from ${selectedTLSCAName||"the CA selected in Configure TLS"}.`
              : `This interface will bind ${selectedTLSCertificateName||"the certificate selected in Configure TLS"}.`}
        </div>
        <div style={{fontSize:10,color:C.dim,marginTop:4}}>
          {ifPQCMode==="hybrid"
            ? "Hybrid mode keeps a classical compatibility path while advertising PQC migration intent for this listener."
            : ifPQCMode==="pqc_only"
              ? "PQC-only mode marks this listener as migration-complete and removes classical fallback from readiness reporting."
              : ifPQCMode==="classical"
                ? "Classical-only mode will be reported as non-migrated in PQC readiness and compliance views."
                : "Inherit mode follows the tenant PQC policy profile from the Post-Quantum Crypto tab."}
        </div>
        <div style={{fontSize:10,color:C.amber,marginTop:4}}>
          Interface-level TLS certificate overrides are disabled. Change certificate source, issuing CA, or uploaded certificate from Runtime Crypto -&gt; Configure TLS.
        </div>
      </>}
      <Chk label="Enable this interface" checked={ifEnabled} onChange={()=>setIfEnabled((value)=>!value)}/>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn small onClick={()=>{setNetIfModalOpen(false);setEditingNetIf(null);}}>Cancel</Btn>
        <Btn small primary onClick={()=>void saveNetIf()}>{editingNetIf?"Update Interface":"Create Interface"}</Btn>
      </div>
    </Modal>
    </>}

    {panel==="platform"&&<>
    <Section title="Platform Hardening, Crypto and Interfaces" actions={<div style={{display:"flex",gap:6}}><Btn small onClick={()=>void loadSystemState()} disabled={systemStateLoading}>{systemStateLoading?"Refreshing...":"Refresh"}</Btn><Btn small primary onClick={()=>void saveSystemState()} disabled={systemStateLoading||systemStateSaving}>{systemStateSaving?"Saving...":"Save"}</Btn></div>}>
      <Row2>
        <Card style={{padding:10,borderRadius:8}}>
          <div style={{fontSize:10,color:C.muted,marginBottom:8}}>Hardening / Crypto Runtime</div>
          <Row2>
            <FG label="FIPS Policy">
              <Sel value={String(systemState?.fips_mode_policy||"standard")} onChange={(e)=>setSystemState((p)=>({...p,fips_mode_policy:String(e.target.value||"standard"),fips_mode:String(e.target.value==="strict"?"enabled":"disabled")}))}>
                <option value="strict">Strict (non-approved blocked)</option>
                <option value="standard">Standard (log-only)</option>
              </Sel>
            </FG>
            <FG label="FIPS Mode">
              <Inp value={String(systemState?.fips_mode||"disabled")} readOnly />
            </FG>
          </Row2>
          <Row2>
            <FG label="TLS Profile">
              <Sel value={String(systemState?.fips_tls_profile||"tls12_fips_suites")} onChange={(e)=>setSystemState((p)=>({...p,fips_tls_profile:String(e.target.value||"tls12_fips_suites")}))}>
                <option value="tls12_fips_suites">TLS 1.2+ FIPS suites</option>
                <option value="tls13_only">TLS 1.3 only</option>
              </Sel>
            </FG>
            <FG label="RNG Mode">
              <Sel value={String(systemState?.fips_rng_mode||"ctr_drbg")} onChange={(e)=>setSystemState((p)=>({...p,fips_rng_mode:String(e.target.value||"ctr_drbg")}))}>
                <option value="ctr_drbg">CTR_DRBG</option>
                <option value="hmac_drbg">HMAC_DRBG</option>
                <option value="hsm_trng">HSM_TRNG</option>
              </Sel>
            </FG>
          </Row2>
          <FG label="Entropy Source">
            <Sel value={String(systemState?.fips_entropy_source||"os-csprng")} onChange={(e)=>setSystemState((p)=>({...p,fips_entropy_source:String(e.target.value||"os-csprng")}))}>
              <option value="os-csprng">OS CSPRNG</option>
              <option value="hsm-trng">HSM TRNG</option>
            </Sel>
          </FG>
          <div style={{fontSize:10,color:C.dim,display:"grid",gap:2}}>
            <div>{`Entropy health: ${String(systemState?.fips_entropy_health||"unknown")} | ${Number(systemState?.fips_entropy_bits_per_byte||0).toFixed(3)} bits/byte`}</div>
            <div>{`Sample: ${Number(systemState?.fips_entropy_sample_bytes||0)} bytes in ${Number(systemState?.fips_entropy_read_micros||0)} us`}</div>
            <div>{`Runtime: enabled=${Boolean(systemState?.fips_runtime_enabled)} enforced=${Boolean(systemState?.fips_runtime_enforced)}`}</div>
          </div>
        </Card>

        <Card style={{padding:10,borderRadius:8}}>
          <div style={{fontSize:10,color:C.muted,marginBottom:8}}>KMS Rules / Platform Policy</div>
          <Chk label="Force quorum for destructive operations" checked={Boolean(systemState?.posture_force_quorum_destructive_ops)} onChange={()=>setSystemState((p)=>({...p,posture_force_quorum_destructive_ops:!p.posture_force_quorum_destructive_ops}))}/>
          <Chk label="Require step-up auth for risky operations" checked={Boolean(systemState?.posture_require_step_up_auth)} onChange={()=>setSystemState((p)=>({...p,posture_require_step_up_auth:!p.posture_require_step_up_auth}))}/>
          <Chk label="Pause connector sync when posture risk is high" checked={Boolean(systemState?.posture_pause_connector_sync)} onChange={()=>setSystemState((p)=>({...p,posture_pause_connector_sync:!p.posture_pause_connector_sync}))}/>
          <Chk label="Require guardrail policy for remediation actions" checked={Boolean(systemState?.posture_guardrail_policy_required)} onChange={()=>setSystemState((p)=>({...p,posture_guardrail_policy_required:!p.posture_guardrail_policy_required}))}/>
          <FG label="License Status"><Inp value={String(systemState?.license_status||"inactive")} onChange={(e)=>setSystemState((p)=>({...p,license_status:e.target.value}))}/></FG>
        </Card>
      </Row2>

      <Row2>
        <Card style={{padding:10,borderRadius:8}}>
          <div style={{fontSize:10,color:C.muted,marginBottom:8}}>QRNG Entropy Source</div>
          <Chk label="Enable QRNG entropy integration" checked={Boolean(systemState?.qrng_enabled)} onChange={()=>setSystemState((p:any)=>({...p,qrng_enabled:!p.qrng_enabled}))}/>
          <div style={{marginTop:8}}>
            <FG label="Default QRNG Source ID"><Inp value={String(systemState?.qrng_default_source||"")} onChange={(e:any)=>setSystemState((p:any)=>({...p,qrng_default_source:e.target.value}))} placeholder="qrng_xxxxxxxxxxxxxxxx"/></FG>
          </div>
          <div style={{marginTop:8}}>
            <FG label="Minimum Entropy (bits/byte)"><Inp value={String(systemState?.qrng_min_entropy_bpb||"7.0")} onChange={(e:any)=>setSystemState((p:any)=>({...p,qrng_min_entropy_bpb:parseFloat(e.target.value)||7.0}))} placeholder="7.0"/></FG>
          </div>
          <div style={{fontSize:9,color:C.muted,marginTop:6}}>
            When enabled, KeyCore uses QRNG-seeded CSPRNG for key generation. External QRNG sources inject quantum entropy
            that is XOR-mixed with OS CSPRNG for defense-in-depth. NIST SP 800-90B health tests run on every ingest.
          </div>
        </Card>
        <Card style={{padding:10,borderRadius:8}}>
          <div style={{fontSize:10,color:C.muted,marginBottom:8}}>QRNG Integration Status</div>
          <div style={{fontSize:11,color:C.text,lineHeight:1.7}}>
            <div>Status: <span style={{color:Boolean(systemState?.qrng_enabled)?C.green:C.dim,fontWeight:600}}>{Boolean(systemState?.qrng_enabled)?"ENABLED":"DISABLED"}</span></div>
            <div>Default Source: <span style={{color:C.accent}}>{String(systemState?.qrng_default_source||"none")}</span></div>
            <div>Min Entropy: <span style={{color:C.text}}>{Number(systemState?.qrng_min_entropy_bpb||7.0).toFixed(1)} bpb</span></div>
            <div style={{marginTop:8,fontSize:9,color:C.muted}}>
              Supported vendors: ID Quantique Quantis, QuintessenceLabs qStream, Toshiba QRNG, AWS CloudHSM QRNG, Azure Quantum, Custom.
              QRNG is NOT FIPS 140-3 approved — under FIPS mode, the system falls back to KMS-CSPRNG automatically.
            </div>
          </div>
        </Card>
      </Row2>

      <Row2>
        <Card style={{padding:10,borderRadius:8}}>
          <div style={{fontSize:10,color:C.muted,marginBottom:8}}>TLS / Interface Governance</div>
          <div style={{display:"grid",gap:8}}>
            <div style={{fontSize:11,color:C.text,fontWeight:700}}>{tlsPolicyLabel}</div>
            <div style={{fontSize:10,color:C.dim}}>
              Network addresses stay on the Network tab. User-facing listeners, HTTP versus HTTPS/TLS, mTLS, and certificate attachment stay on Interfaces.
            </div>
            <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
              <B c="blue">{tlsPolicyLabel}</B>
              <B c="accent">{tlsDefaultCertSummary}</B>
            </div>
            <div style={{display:"flex",gap:8,flexWrap:"wrap",marginTop:4}}>
              <Btn small onClick={()=>setPanel("network")}>Open Network</Btn>
              <Btn small primary onClick={()=>setPanel("interfaces")}>Open Interfaces</Btn>
            </div>
          </div>
        </Card>

      </Row2>
    </Section>
    </>}

    {panel==="cli"&&<>
    <Section title="CLI / HSM Onboarding" actions={<Btn small onClick={()=>{void loadCli(); void loadHsm();}}>{cliLoading||hsmLoading?"Refreshing...":"Refresh"}</Btn>}>
      <Row2>
        <Card style={{padding:10,borderRadius:8}}>
          <div style={{fontSize:10,color:C.muted}}>CLI Status</div>
          <div style={{marginTop:6,display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}><span style={{color:C.text,fontSize:12,fontWeight:700}}>{cliStatus?.enabled?"Enabled":"Disabled"}</span><span style={{color:C.dim,fontSize:10}}>{`${String(cliStatus?.host||"127.0.0.1")}:${Number(cliStatus?.port||22)}`}</span><span style={{color:C.muted,fontSize:10}}>{String(cliStatus?.transport||"ssh")}</span></div>
          <FG label="CLI Username"><Inp value={cliUser} onChange={(e)=>setCliUser(e.target.value)}/></FG>
          <FG label="CLI Password"><Inp type="password" value={cliPass} onChange={(e)=>setCliPass(e.target.value)}/></FG>
          <div style={{display:"flex",justifyContent:"flex-end"}}><Btn small primary onClick={()=>void openCli()} disabled={cliOpening}>{cliOpening?"Opening...":"Open CLI Session"}</Btn></div>
          {String(cliSession||"").trim()?<div style={{marginTop:8,fontSize:10,color:C.muted}}>{`Session ID: ${cliSession}`}</div>:null}
          {String(cliSsh||"").trim()?<div style={{marginTop:4,fontSize:10,color:C.text,fontFamily:"'JetBrains Mono', monospace"}}>{cliSsh}</div>:null}
        </Card>
        <Card style={{padding:10,borderRadius:8}}>
          <div style={{fontSize:10,color:C.muted}}>PKCS#11 Provider Configuration</div>
          <FG label="Provider Name"><Inp value={String(hsm.provider_name||"")} onChange={(e)=>setHsm((p)=>({...p,provider_name:e.target.value}))}/></FG>
          <FG label="Integration Service"><Inp value={String(hsm.integration_service||"")} onChange={(e)=>setHsm((p)=>({...p,integration_service:e.target.value}))}/></FG>
          <FG label="PKCS#11 Library Path"><Inp value={String(hsm.library_path||"")} onChange={(e)=>setHsm((p)=>({...p,library_path:e.target.value}))} placeholder="/opt/hsm/lib/your-pkcs11.so"/></FG>
          <Row2><FG label="Slot ID"><Inp value={String(hsm.slot_id||"")} onChange={(e)=>setHsm((p)=>({...p,slot_id:e.target.value}))}/></FG><FG label="PIN Env Var"><Inp value={String(hsm.pin_env_var||"HSM_PIN")} onChange={(e)=>setHsm((p)=>({...p,pin_env_var:e.target.value}))}/></FG></Row2>
          <Row2><FG label="Partition Label"><Inp value={String(hsm.partition_label||"")} onChange={(e)=>setHsm((p)=>({...p,partition_label:e.target.value}))}/></FG><FG label="Token Label"><Inp value={String(hsm.token_label||"")} onChange={(e)=>setHsm((p)=>({...p,token_label:e.target.value}))}/></FG></Row2>
          <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8,marginBottom:8}}><Chk label="Read-only mode" checked={Boolean(hsm.read_only)} onChange={()=>setHsm((p)=>({...p,read_only:!p.read_only}))}/><Chk label="Enabled" checked={Boolean(hsm.enabled)} onChange={()=>setHsm((p)=>({...p,enabled:!p.enabled}))}/></div>
          <div style={{display:"flex",justifyContent:"space-between",gap:8}}>
            <Btn
              small
              onClick={async()=>{
                if(!session?.token) return;
                setHsmSaving(true);
                try{
                  const payload={
                    ...hsm,
                    provider_name:String(hsm.provider_name||"generic-pkcs11"),
                    integration_service:String(hsm.integration_service||""),
                    library_path:String(hsm.library_path||""),
                    slot_id:String(hsm.slot_id||""),
                    partition_label:String(hsm.partition_label||""),
                    token_label:String(hsm.token_label||""),
                    pin_env_var:String(hsm.pin_env_var||"HSM_PIN"),
                    read_only:Boolean(hsm.read_only),
                    enabled:Boolean(hsm.enabled)
                  };
                  const updated=await upsertAuthCLIHSMConfig(session,payload);
                  setHsm((p)=>({...p,...updated}));
                  onToast("HSM provider config updated.");
                }catch(error){
                  if(!sessionGuard(error)) onToast(`HSM config save failed: ${errMsg(error)}`);
                }finally{
                  setHsmSaving(false);
                }
              }}
              disabled={hsmSaving}
            >
              {hsmSaving?"Saving...":"Save HSM Config"}
            </Btn>
            <Btn small onClick={async()=>{if(!session?.token) return; const lib=String(hsm.library_path||"").trim(); if(!lib){onToast("PKCS#11 library path is required before partition fetch."); return;} setSlotsLoading(true); try{const listing=await listAuthCLIHSMPartitions(session,lib,String(slotHint||"").trim()); setSlots(Array.isArray(listing.items)?listing.items:[]); setSlotRaw(String(listing.raw_output||"")); onToast("HSM partitions fetched.");}catch(error){if(!sessionGuard(error)) onToast(`Partition fetch failed: ${errMsg(error)}`);} finally{setSlotsLoading(false);}}} disabled={slotsLoading}>{slotsLoading?"Fetching...":"Fetch Partitions"}</Btn>
          </div>
          <div style={{marginTop:8,display:"flex",gap:8}}><Inp w={180} placeholder="slot filter (optional)" value={slotHint} onChange={(e)=>setSlotHint(e.target.value)}/></div>
          <div style={{display:"grid",gap:8,marginTop:8}}>{slots.map((slot:CLIHSMPartitionSlot)=>{const key=`${String(slot.slot_id||"")}:${String(slot.partition||slot.token_label||slot.slot_name||"")}`; return <div key={key} style={{borderBottom:`1px solid ${C.border}`,paddingBottom:8}}><div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}><div><div style={{fontSize:12,color:C.text,fontWeight:700}}>{`${String(slot.slot_name||"slot")} (${String(slot.slot_id||"-")})`}</div><div style={{fontSize:10,color:C.dim}}>{`partition: ${String(slot.partition||"-")} | token: ${String(slot.token_label||"-")} | serial: ${String(slot.serial_number||"-")}`}</div></div><Btn small onClick={()=>setHsm((p)=>({...p,slot_id:String(slot.slot_id||""),partition_label:String(slot.partition||slot.slot_name||""),token_label:String(slot.token_label||slot.slot_name||"")}))}>Use</Btn></div></div>;})}{!slots.length?<div style={{fontSize:10,color:C.muted}}>No partitions loaded yet.</div>:null}{String(slotRaw||"").trim()?<div style={{fontSize:9,color:C.muted,fontFamily:"'JetBrains Mono', monospace",whiteSpace:"pre-wrap"}}>{slotRaw}</div>:null}</div>
        </Card>
      </Row2>
    </Section>
    </>}

    {panel==="governance"&&<>
    <Section title="Governance Delivery" actions={<Btn small primary onClick={async()=>{if(!session?.token) return; setGovSaving(true); try{await updateGovernanceSettings(session,{...gov,approval_expiry_minutes:Math.max(1,Math.trunc(Number(gov.approval_expiry_minutes||60))),expiry_check_interval_seconds:Math.max(5,Math.trunc(Number(gov.expiry_check_interval_seconds||60))),delivery_webhook_timeout_seconds:Math.max(2,Math.trunc(Number(gov.delivery_webhook_timeout_seconds||10)))}); onToast("Governance delivery settings updated."); await loadGov();}catch(error){if(!sessionGuard(error)) onToast(`Governance settings save failed: ${errMsg(error)}`);} finally{setGovSaving(false);}}} disabled={govLoading||govSaving}>{govSaving?"Saving...":"Save"}</Btn>}>
      <Row2><FG label="Approval Expiry (minutes)"><Inp type="number" value={String(gov.approval_expiry_minutes)} onChange={(e)=>setGov((p)=>({...p,approval_expiry_minutes:Math.max(1,Number(e.target.value||60))}))}/></FG><FG label="Expiry Check Interval (seconds)"><Inp type="number" value={String(gov.expiry_check_interval_seconds)} onChange={(e)=>setGov((p)=>({...p,expiry_check_interval_seconds:Math.max(5,Number(e.target.value||60))}))}/></FG></Row2>
      <Row2><FG label="Delivery Mode"><Sel value={String(gov.approval_delivery_mode||"kms_only")} onChange={(e)=>setGov((p)=>({...p,approval_delivery_mode:String(e.target.value||"kms_only")}))}><option value="kms_only">KMS only</option><option value="notify">Notify + KMS queue</option></Sel></FG><FG label="Webhook Timeout (seconds)"><Inp type="number" value={String(gov.delivery_webhook_timeout_seconds)} onChange={(e)=>setGov((p)=>({...p,delivery_webhook_timeout_seconds:Math.max(2,Number(e.target.value||10))}))}/></FG></Row2>
      <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8}}><Chk label="Dashboard approvals" checked={Boolean(gov.notify_dashboard)} onChange={()=>setGov((p)=>({...p,notify_dashboard:!p.notify_dashboard}))}/><Chk label="Email notifications" checked={Boolean(gov.notify_email)} onChange={()=>setGov((p)=>({...p,notify_email:!p.notify_email}))}/><Chk label="Slack notifications" checked={Boolean(gov.notify_slack)} onChange={()=>setGov((p)=>({...p,notify_slack:!p.notify_slack}))}/><Chk label="Teams notifications" checked={Boolean(gov.notify_teams)} onChange={()=>setGov((p)=>({...p,notify_teams:!p.notify_teams}))}/></div>
      <Row2><FG label="SMTP Host"><Inp value={String(gov.smtp_host||"")} onChange={(e)=>setGov((p)=>({...p,smtp_host:e.target.value}))}/></FG><FG label="SMTP Port"><Inp value={String(gov.smtp_port||"")} onChange={(e)=>setGov((p)=>({...p,smtp_port:e.target.value}))}/></FG></Row2>
      <Row2><FG label="SMTP Username"><Inp value={String(gov.smtp_username||"")} onChange={(e)=>setGov((p)=>({...p,smtp_username:e.target.value}))}/></FG><FG label="SMTP Password (optional)"><Inp type="password" value={String(gov.smtp_password||"")} onChange={(e)=>setGov((p)=>({...p,smtp_password:e.target.value}))}/></FG></Row2>
      <Row2><FG label="SMTP From"><Inp value={String(gov.smtp_from||"")} onChange={(e)=>setGov((p)=>({...p,smtp_from:e.target.value}))}/></FG><FG label="SMTP Test Recipient"><div style={{display:"flex",gap:8}}><Inp value={smtpTo} onChange={(e)=>setSmtpTo(e.target.value)} placeholder="admin@domain.tld"/><Btn small onClick={async()=>{if(!session?.token||!String(smtpTo||"").trim()){onToast("Provide SMTP test recipient email."); return;} setSmtpTesting(true); try{await testGovernanceSMTP(session,String(smtpTo||"").trim()); onToast("SMTP test sent.");}catch(error){if(!sessionGuard(error)) onToast(`SMTP test failed: ${errMsg(error)}`);} finally{setSmtpTesting(false);}}} disabled={smtpTesting}>{smtpTesting?"Testing...":"Send"}</Btn></div></FG></Row2>
      <FG label="Slack Webhook URL"><div style={{display:"flex",gap:8}}><Inp value={String(gov.slack_webhook_url||"")} onChange={(e)=>setGov((p)=>({...p,slack_webhook_url:e.target.value}))}/><Btn small onClick={async()=>{if(!session?.token) return; setWebhookTesting((p)=>({...p,slack:true})); try{await testGovernanceWebhook(session,"slack",String(gov.slack_webhook_url||"")); onToast("SLACK webhook test sent.");}catch(error){if(!sessionGuard(error)) onToast(`SLACK webhook test failed: ${errMsg(error)}`);} finally{setWebhookTesting((p)=>({...p,slack:false}));}}} disabled={webhookTesting.slack}>{webhookTesting.slack?"Testing...":"Test"}</Btn></div></FG>
      <FG label="Teams Webhook URL"><div style={{display:"flex",gap:8}}><Inp value={String(gov.teams_webhook_url||"")} onChange={(e)=>setGov((p)=>({...p,teams_webhook_url:e.target.value}))}/><Btn small onClick={async()=>{if(!session?.token) return; setWebhookTesting((p)=>({...p,teams:true})); try{await testGovernanceWebhook(session,"teams",String(gov.teams_webhook_url||"")); onToast("TEAMS webhook test sent.");}catch(error){if(!sessionGuard(error)) onToast(`TEAMS webhook test failed: ${errMsg(error)}`);} finally{setWebhookTesting((p)=>({...p,teams:false}));}}} disabled={webhookTesting.teams}>{webhookTesting.teams?"Testing...":"Test"}</Btn></div></FG>
    </Section>
    </>}

    {panel==="backup"&&<>
    <Section title="Encrypted Backups" actions={<div style={{display:"flex",gap:6}}><Btn small onClick={()=>void loadJobs()}>{jobsLoading?"Refreshing...":"Refresh Jobs"}</Btn><Btn small primary onClick={()=>void saveSystemState()} disabled={systemStateLoading||systemStateSaving}>{systemStateSaving?"Saving...":"Save Backup Policy"}</Btn></div>}>
      <ScopeBanner section="backupPolicy"/>
      <Card style={{padding:10,borderRadius:8,marginBottom:8}}>
        <div style={{fontSize:10,color:C.muted,marginBottom:8}}>Backup Policy</div>
        <Row2>
          <FG label="Backup Schedule"><Inp value={String(systemState?.backup_schedule||"daily@02:00")} onChange={(e)=>setSystemState((p)=>({...p,backup_schedule:e.target.value}))}/></FG>
          <FG label="Backup Target"><Inp value={String(systemState?.backup_target||"local")} onChange={(e)=>setSystemState((p)=>({...p,backup_target:e.target.value}))}/></FG>
        </Row2>
        <Row2>
          <FG label="Backup Retention (days)"><Inp type="number" value={String(systemState?.backup_retention_days||30)} onChange={(e)=>setSystemState((p)=>({...p,backup_retention_days:Math.max(1,Number(e.target.value||30))}))}/></FG>
        </Row2>
        <Chk label="Encrypt backup artifacts" checked={Boolean(systemState?.backup_encrypted)} onChange={()=>setSystemState((p)=>({...p,backup_encrypted:!p.backup_encrypted}))}/>
      </Card>
      <Card style={{padding:10,borderRadius:8,marginBottom:8}}>
        <div style={{fontSize:10,color:C.muted,marginBottom:8}}>Create Backup</div>
        <Row2><FG label="Scope"><Sel value={backupScope} onChange={(e)=>setBackupScope(String(e.target.value||"system") as "system"|"tenant")}><option value="system">System</option><option value="tenant">Tenant</option></Sel></FG><FG label="Target Tenant ID (tenant scope)"><Inp value={backupTenant} onChange={(e)=>setBackupTenant(e.target.value)} placeholder="tenant-id"/></FG></Row2>
        <Chk label="Bind backup key package to HSM (when configured)" checked={backupBindToHsm} onChange={()=>setBackupBindToHsm((v)=>!v)}/>
        <div style={{display:"flex",justifyContent:"flex-end",alignItems:"center",marginTop:10}}><Btn small primary onClick={async()=>{if(!session?.token) return; if(backupScope==="tenant"&&!String(backupTenant||"").trim()){onToast("Provide target tenant ID for tenant scope backup."); return;} setBackupCreating(true); try{await createGovernanceBackup(session,{scope:backupScope,target_tenant_id:backupScope==="tenant"?String(backupTenant||"").trim():"",bind_to_hsm:backupBindToHsm,created_by:session.username}); onToast("Backup job created."); await loadJobs();}catch(error){if(!sessionGuard(error)) onToast(`Backup create failed: ${errMsg(error)}`);} finally{setBackupCreating(false);}}} disabled={backupCreating}>{backupCreating?"Creating...":"Create Backup"}</Btn></div>
      </Card>
      <Card style={{padding:10,borderRadius:8,marginBottom:8}}>
        <div style={{fontSize:10,color:C.muted,marginBottom:8}}>Restore Backup</div>
        <Row2>
          <FG label={`Artifact (${BACKUP_ARTIFACT_EXTENSION})`}>
            <BackupRestoreFilePicker
              accept={BACKUP_ARTIFACT_EXTENSION}
              file={backupRestoreArtifactFile}
              onFileChange={setBackupRestoreArtifactFile}
              emptyLabel="Upload encrypted backup artifact"
              hint="Encrypted Vecta backup bundle"
            />
          </FG>
          <FG label={`Key Package (${BACKUP_KEY_EXTENSION})`}>
            <BackupRestoreFilePicker
              accept=".json,.key.json"
              file={backupRestoreKeyFile}
              onFileChange={setBackupRestoreKeyFile}
              emptyLabel="Upload companion key package"
              hint="JSON key material envelope"
            />
          </FG>
        </Row2>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginTop:10,gap:10}}>
          <div style={{fontSize:10,color:C.dim,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{`${backupRestoreArtifactFile?.name||"artifact not selected"} | ${backupRestoreKeyFile?.name||"key package not selected"}`}</div>
          <Btn small primary onClick={()=>void restoreBackup()} disabled={backupRestoring}>{backupRestoring?"Restoring...":"Restore Backup"}</Btn>
        </div>
      </Card>
      <Card style={{marginTop:8,padding:10,borderRadius:8}}>
        <div style={{display:"grid",gridTemplateColumns:"1.2fr 0.8fr 0.8fr 0.8fr 1fr",gap:8,paddingBottom:8,borderBottom:`1px solid ${C.border}`}}>{["Backup","Scope","Status","Rows","Actions"].map((h)=><div key={h} style={{fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>{h}</div>)}</div>
        {sortedJobs.map((job)=>{const id=String(job.id||""); const st=String(job.status||"unknown"); return <div key={id} style={{display:"grid",gridTemplateColumns:"1.2fr 0.8fr 0.8fr 0.8fr 1fr",gap:8,alignItems:"center",borderBottom:`1px solid ${C.border}`,padding:"9px 0"}}><div style={{minWidth:0}}><div style={{fontSize:12,color:C.text,fontWeight:700,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{id}</div><div style={{fontSize:10,color:C.dim}}>{String(job.created_at||"-")}</div></div><div style={{fontSize:11,color:C.text}}>{String(job.scope||"-")}</div><div style={{fontSize:11,color:C[tone(st)]}}>{st}</div><div style={{fontSize:11,color:C.text}}>{Number(job.row_count_total||0)}</div><div style={{display:"flex",gap:6,flexWrap:"wrap",justifyContent:"flex-end"}}><Btn small onClick={async()=>{if(!session?.token||!id) return; setBackupDownloading(`${id}:artifact`); try{const p=await downloadGovernanceBackupArtifact(session,id); dl(p.file_name,p.content_base64,p.content_type); onToast("Backup artifact downloaded.");}catch(error){if(!sessionGuard(error)) onToast(`Backup download failed: ${errMsg(error)}`);} finally{setBackupDownloading("");}}} disabled={backupDownloading===`${id}:artifact`}>Artifact</Btn><Btn small onClick={async()=>{if(!session?.token||!id) return; setBackupDownloading(`${id}:key`); try{const p=await downloadGovernanceBackupKey(session,id); dl(p.file_name,p.content_base64,p.content_type); onToast("Backup key package downloaded.");}catch(error){if(!sessionGuard(error)) onToast(`Backup download failed: ${errMsg(error)}`);} finally{setBackupDownloading("");}}} disabled={backupDownloading===`${id}:key`}>Key</Btn><Btn small danger onClick={async()=>{if(!session?.token||!id) return; setBackupDeleting(id); try{await deleteGovernanceBackup(session,id,session.username); onToast("Backup deleted."); await loadJobs();}catch(error){if(!sessionGuard(error)) onToast(`Backup delete failed: ${errMsg(error)}`);} finally{setBackupDeleting("");}}} disabled={backupDeleting===id}>Delete</Btn></div></div>;})}
        {!sortedJobs.length?<div style={{fontSize:10,color:C.muted,paddingTop:10}}>No backups found.</div>:null}
      </Card>
    </Section>
    </>}
    {panel==="alertrules"&&<>
    <Section title={<>{`Alert Rules`}<span style={{fontWeight:400,fontSize:11,color:C.muted,marginLeft:8}}>{alertRulesLoading?"loading...": `${alertRules.length} rule${alertRules.length!==1?"s":""}`}</span></>} actions={<div style={{display:"flex",gap:6}}><Btn small onClick={()=>void refreshAlertRules()} disabled={alertRulesLoading}>{alertRulesLoading?"Refreshing...":"Refresh"}</Btn><Btn small primary onClick={()=>openRuleModal()}>Create Rule</Btn></div>}>
      {alertRules.map((rule)=>{const id=String(rule.id||""); const cond=String(rule.condition||"threshold"); return <Card key={id} style={{padding:10,borderRadius:8,marginBottom:8}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
          <div style={{minWidth:0,flex:1}}>
            <div style={{fontSize:13,color:C.text,fontWeight:700}}>{rule.name||"Unnamed Rule"}</div>
            <div style={{fontSize:10,color:C.dim,marginTop:2}}>
              {cond==="expression"
                ?<span>Expression: <span style={{fontFamily:"'JetBrains Mono', monospace",color:C.text}}>{rule.expression||"-"}</span></span>
                :<span>Pattern: <span style={{fontFamily:"'JetBrains Mono', monospace",color:C.text}}>{rule.event_pattern||"*"}</span> | Threshold: {rule.threshold||1} in {rule.window_seconds||300}s</span>}
            </div>
            <div style={{display:"flex",gap:8,marginTop:4,fontSize:10}}>
              <span style={{color:rule.severity==="critical"?C.red:rule.severity==="high"?C.orange:rule.severity==="warning"?C.amber:C.blue}}>{rule.severity||"warning"}</span>
              <span style={{color:C.muted}}>channels: {(rule.channels||[]).join(", ")||"none"}</span>
              <span style={{color:rule.enabled!==false?C.green:C.muted}}>{rule.enabled!==false?"enabled":"disabled"}</span>
            </div>
          </div>
          <div style={{display:"flex",gap:6,flexShrink:0,marginLeft:8}}>
            <Btn small onClick={async()=>{if(!session?.token||!id) return; try{await updateReportingRule(session,id,{enabled:rule.enabled===false}); onToast(rule.enabled===false?"Rule enabled.":"Rule disabled."); await refreshAlertRules();}catch(error){if(!sessionGuard(error)) onToast(`Toggle failed: ${errMsg(error)}`);}}}>
              {rule.enabled!==false?"Disable":"Enable"}
            </Btn>
            <Btn small onClick={()=>openRuleModal(rule)}>Edit</Btn>
            <Btn small danger onClick={async()=>{if(!session?.token||!id) return; try{await deleteReportingRule(session,id); onToast("Rule deleted."); await refreshAlertRules();}catch(error){if(!sessionGuard(error)) onToast(`Delete failed: ${errMsg(error)}`);}}}>Delete</Btn>
          </div>
        </div>
      </Card>;})}
      {!alertRules.length&&!alertRulesLoading?<div style={{fontSize:11,color:C.muted,padding:"16px 0",textAlign:"center"}}>No alert rules configured. Create a rule to generate alerts for specific event patterns or expressions.</div>:null}
    </Section>

    <Modal open={ruleModalOpen} onClose={()=>setRuleModalOpen(false)} title={editingRule?"Edit Alert Rule":"Create Alert Rule"}>
      <FG label="Rule Name"><Inp value={ruleName} onChange={(e)=>setRuleName(e.target.value)} placeholder="e.g. brute_force_detection"/></FG>
      <FG label="Condition Type">
        <Sel value={ruleCondition} onChange={(e)=>setRuleCondition(e.target.value as "threshold"|"expression")}>
          <option value="threshold">Pattern Match (Threshold)</option>
          <option value="expression">Expression</option>
        </Sel>
      </FG>
      {ruleCondition==="threshold"&&<>
        <FG label="Event Pattern (glob)"><Inp value={rulePattern} onChange={(e)=>setRulePattern(e.target.value)} placeholder="e.g. auth.login_failed or key.*"/></FG>
        <Row2>
          <FG label="Threshold (count)"><Inp type="number" value={String(ruleThreshold)} onChange={(e)=>setRuleThreshold(Math.max(1,Number(e.target.value||1)))}/></FG>
          <FG label="Window (seconds)"><Inp type="number" value={String(ruleWindowSeconds)} onChange={(e)=>setRuleWindowSeconds(Math.max(1,Number(e.target.value||300)))}/></FG>
        </Row2>
      </>}
      {ruleCondition==="expression"&&<>
        <FG label="Expression">
          <Inp value={ruleExpression} onChange={(e)=>setRuleExpression(e.target.value)} placeholder={'e.g. action == "key.exported" AND actor_id != "admin"'}/>
        </FG>
        <div style={{fontSize:9,color:C.muted,marginTop:4,lineHeight:1.5,fontFamily:"'JetBrains Mono', monospace"}}>
          <div><B>Fields:</B> action, severity, actor_id, source_ip, service, target_type, target_id</div>
          <div><B>Operators:</B> == != contains startsWith matches</div>
          <div><B>Combinators:</B> AND OR ( )</div>
          <div style={{marginTop:4}}><B>Examples:</B></div>
          <div>action == "key.exported" AND severity != "info"</div>
          <div>source_ip startsWith "10.0." OR service == "auth"</div>
          <div>(action matches "key.*" OR action matches "cert.*") AND actor_id != "admin"</div>
        </div>
      </>}
      <FG label="Severity">
        <Sel value={ruleSeverity} onChange={(e)=>setRuleSeverity(e.target.value)}>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="warning">Warning</option>
          <option value="info">Info</option>
        </Sel>
      </FG>
      <FG label="Notification Channels">
        <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
          {ruleChannelsAvail.map((ch)=><Chk key={ch} label={ch} checked={ruleChannels.includes(ch)} onChange={()=>toggleRuleChannel(ch)}/>)}
        </div>
      </FG>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn small onClick={()=>setRuleModalOpen(false)}>Cancel</Btn>
        <Btn small primary onClick={()=>void handleSaveRule()} disabled={ruleSaving}>{ruleSaving?"Saving...":(editingRule?"Update Rule":"Create Rule")}</Btn>
      </div>
    </Modal>
    </>}

    {panel==="approvals"&&<>
    <Section title="Approval Policies" actions={<div style={{display:"flex",gap:6}}>
      <Btn small onClick={()=>void loadGovPolicies()} disabled={govPoliciesLoading}>{govPoliciesLoading?"Refreshing...":"Refresh"}</Btn>
      <Btn small primary onClick={()=>openGovPolicyModal()}>+ Create Policy</Btn>
    </div>}>
      <div style={{fontSize:11,color:C.dim,marginBottom:14}}>
        Define quorum-based approval policies for every administrative and key operation in the KMS. Operations matching a policy will be held until the required approvals are granted via dashboard, email, Slack, or Teams within the configured timeout window.
      </div>

      {/* Stats */}
      <div style={{display:"flex",gap:10,marginBottom:16,flexWrap:"wrap"}}>
        <Stat l="Total Policies" v={govPolicies.length} c="accent"/>
        <Stat l="Active" v={govPolicies.filter((p)=>p.status==="active").length} c="green"/>
        <Stat l="Key Ops" v={govPolicies.filter((p)=>p.scope==="keys").length} c="blue"/>
        <Stat l="Admin Ops" v={govPolicies.filter((p)=>p.scope==="system"||p.scope==="users").length} c="purple"/>
        <Stat l="All Scopes" v={govPolicies.filter((p)=>p.scope==="all").length} c="amber"/>
      </div>

      {/* Policy List */}
      <div style={{display:"grid",gap:8}}>
        {govPolicies.map((policy)=>{
          const qMode=String(policy.quorum_mode||"threshold");
          const qLabel=qMode==="and"?"Unanimous (AND)":qMode==="or"?"Any Single (OR)":`${policy.required_approvals}-of-${policy.total_approvers} (Threshold)`;
          const scopeLabel=ALL_GOV_SCOPES.find((s)=>s.v===policy.scope)?.l||policy.scope;
          const triggers=Array.isArray(policy.trigger_actions)?policy.trigger_actions:[];
          const channels=Array.isArray(policy.notification_channels)?policy.notification_channels:[];
          const approvers=Array.isArray(policy.approver_users)?policy.approver_users:[];
          return(
            <Card key={policy.id} style={{borderLeft:`3px solid ${policy.status==="active"?C.green:C.dim}`,padding:"12px 14px"}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:8}}>
                <div>
                  <div style={{display:"flex",alignItems:"center",gap:8}}>
                    <span style={{fontSize:13,fontWeight:700,color:C.text}}>{policy.name}</span>
                    <B c={policy.status==="active"?"green":"orange"}>{policy.status}</B>
                    <B c="blue">{scopeLabel}</B>
                  </div>
                  {policy.description&&<div style={{fontSize:10,color:C.muted,marginTop:2}}>{policy.description}</div>}
                </div>
                <div style={{display:"flex",gap:6}}>
                  <button onClick={()=>openGovPolicyModal(policy)} style={{fontSize:10,padding:"3px 8px",borderRadius:5,border:`1px solid ${C.border}`,background:C.surface,color:C.text,cursor:"pointer"}}>Edit</button>
                  <button onClick={async()=>{if(!session?.token) return; try{await updateGovernancePolicy(session,policy.id,{status:policy.status==="active"?"inactive":"active"}); onToast(policy.status==="active"?"Policy disabled.":"Policy activated."); await loadGovPolicies();}catch(e){onToast(`Toggle failed: ${errMsg(e)}`);}}} style={{fontSize:10,padding:"3px 8px",borderRadius:5,border:`1px solid ${policy.status==="active"?C.amber:C.green}44`,background:policy.status==="active"?`${C.amber}11`:`${C.green}11`,color:policy.status==="active"?C.amber:C.green,cursor:"pointer"}}>{policy.status==="active"?"Disable":"Enable"}</button>
                </div>
              </div>

              <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:8}}>
                <div><div style={{fontSize:8,color:C.muted,textTransform:"uppercase",letterSpacing:0.6}}>Quorum Mode</div><div style={{fontSize:10,color:C.text,fontWeight:600,marginTop:2}}>{qLabel}</div></div>
                <div><div style={{fontSize:8,color:C.muted,textTransform:"uppercase",letterSpacing:0.6}}>Timeout</div><div style={{fontSize:10,color:C.text,fontWeight:600,marginTop:2}}>{policy.timeout_hours||48}h</div></div>
                <div><div style={{fontSize:8,color:C.muted,textTransform:"uppercase",letterSpacing:0.6}}>Channels</div><div style={{fontSize:10,color:C.text,fontWeight:600,marginTop:2}}>{channels.join(", ")||"dashboard"}</div></div>
                <div><div style={{fontSize:8,color:C.muted,textTransform:"uppercase",letterSpacing:0.6}}>Hold State</div><div style={{fontSize:10,color:C.green,fontWeight:600,marginTop:2}}>Enforced</div></div>
              </div>

              <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                {triggers.slice(0,8).map((t:string)=><span key={t} style={{fontSize:9,padding:"2px 6px",background:`${C.blue}18`,border:`1px solid ${C.blue}33`,borderRadius:4,color:C.blue}}>{t}</span>)}
                {triggers.length>8&&<span style={{fontSize:9,color:C.muted}}>+{triggers.length-8} more</span>}
              </div>
              {approvers.length>0&&<div style={{marginTop:6,fontSize:9,color:C.dim}}>Approvers: {approvers.join(", ")}</div>}
            </Card>
          );
        })}
        {!govPolicies.length&&!govPoliciesLoading&&<div style={{textAlign:"center",padding:24,color:C.muted,fontSize:11,background:C.surface,borderRadius:10,border:`1px solid ${C.border}`}}>
          No approval policies configured. Create a policy to enforce quorum-based approvals for key operations, user management, or system administration tasks.
        </div>}
      </div>
    </Section>

    {/* Create/Edit Approval Policy Modal */}
    {govPolicyModal&&<Modal open={govPolicyModal} title={govEditPolicy?"Edit Approval Policy":"Create Approval Policy"} onClose={()=>setGovPolicyModal(false)} wide>
      <div style={{display:"grid",gap:12}}>
        <Row2>
          <FG label="Policy Name"><Inp value={gpName} onChange={(e)=>setGpName(e.target.value)} placeholder="e.g. Key Deletion Requires 2-of-3"/></FG>
          <FG label="Description"><Inp value={gpDesc} onChange={(e)=>setGpDesc(e.target.value)} placeholder="Approval required before sensitive key operations"/></FG>
        </Row2>

        <Row2>
          <FG label="Scope">
            <Sel value={gpScope} onChange={(e)=>setGpScope(e.target.value)}>
              {ALL_GOV_SCOPES.map((s)=><option key={s.v} value={s.v}>{s.l}</option>)}
            </Sel>
          </FG>
          <FG label="Quorum Mode">
            <Sel value={gpQuorum} onChange={(e)=>setGpQuorum(e.target.value)}>
              <option value="threshold">Threshold (M-of-N)</option>
              <option value="and">Unanimous (AND) — All must approve</option>
              <option value="or">Any Single (OR) — One approval suffices</option>
            </Sel>
          </FG>
        </Row2>

        {gpQuorum==="threshold"&&<Row2>
          <FG label="Required Approvals (M)"><Inp type="number" value={String(gpRequired)} onChange={(e)=>setGpRequired(Math.max(1,Number(e.target.value||2)))}/></FG>
          <FG label="Total Approvers in Group (N)"><Inp type="number" value={String(gpTotal)} onChange={(e)=>setGpTotal(Math.max(gpRequired,Number(e.target.value||3)))}/></FG>
        </Row2>}

        <FG label="Approver Emails (comma-separated — group members, any member can approve per quorum)">
          <Inp value={gpApprovers} onChange={(e)=>setGpApprovers(e.target.value)} placeholder="admin@vecta.local, security-lead@corp.com, ops@corp.com"/>
        </FG>

        {/* Trigger Actions */}
        <div>
          <div style={{fontSize:11,fontWeight:700,color:C.text,marginBottom:8}}>Trigger Actions — Operations requiring approval</div>
          {(gpScope==="keys"||gpScope==="secrets"||gpScope==="certs"||gpScope==="all")&&<>
            <div style={{fontSize:9,color:C.muted,marginBottom:4,textTransform:"uppercase",letterSpacing:0.6}}>Key / Secret / Certificate Operations</div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:6,marginBottom:10}}>
              {KEY_OPS.map((op)=><Chk key={op} label={op.replace("key.","").replace("secret.","").replace("cert.","")} checked={gpTriggers.includes(op)} onChange={()=>toggleGpTrigger(op)}/>)}
            </div>
          </>}
          {(gpScope==="system"||gpScope==="users"||gpScope==="all")&&<>
            <div style={{fontSize:9,color:C.muted,marginBottom:4,textTransform:"uppercase",letterSpacing:0.6}}>Administrative Operations</div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:6,marginBottom:10}}>
              {ADMIN_OPS.map((op)=><Chk key={op} label={op.replace("user.","").replace("tenant.","").replace("system.","").replace("governance.","").replace("hsm.","").replace("license.","")} checked={gpTriggers.includes(op)} onChange={()=>toggleGpTrigger(op)}/>)}
            </div>
          </>}
          <div style={{display:"flex",gap:8}}>
            <Btn small onClick={()=>{const ops=gpScope==="keys"||gpScope==="secrets"||gpScope==="certs"?KEY_OPS:gpScope==="system"||gpScope==="users"?ADMIN_OPS:[...KEY_OPS,...ADMIN_OPS]; setGpTriggers(ops);}}>Select All</Btn>
            <Btn small onClick={()=>setGpTriggers([])}>Clear All</Btn>
          </div>
        </div>

        <Row2>
          <FG label="Timeout Window (hours) — approval must be given within this time">
            <Inp type="number" value={String(gpTimeout)} onChange={(e)=>setGpTimeout(Math.max(1,Number(e.target.value||48)))}/>
          </FG>
          <FG label="Status">
            <Sel value={gpStatus} onChange={(e)=>setGpStatus(e.target.value)}>
              <option value="active">Active — Enforcing</option>
              <option value="inactive">Inactive — Paused</option>
            </Sel>
          </FG>
        </Row2>

        {/* Notification Channels */}
        <div>
          <div style={{fontSize:11,fontWeight:700,color:C.text,marginBottom:8}}>Notification Channels — How approvers receive approval requests</div>
          <div style={{display:"flex",gap:12,flexWrap:"wrap"}}>
            <Chk label="Dashboard (on-screen)" checked={gpChannels.includes("dashboard")} onChange={()=>toggleGpChannel("dashboard")}/>
            <Chk label="Email (SMTP)" checked={gpChannels.includes("email")} onChange={()=>toggleGpChannel("email")}/>
            <Chk label="Slack (Webhook)" checked={gpChannels.includes("slack")} onChange={()=>toggleGpChannel("slack")}/>
            <Chk label="Teams (Webhook)" checked={gpChannels.includes("teams")} onChange={()=>toggleGpChannel("teams")}/>
          </div>
        </div>

        {/* Hold State Enforcement */}
        <div style={{padding:"10px 14px",background:`${C.green}12`,border:`1px solid ${C.green}33`,borderRadius:8}}>
          <Chk label="Enforce Hold State — Operations are held (queued) until approval is granted or timeout expires. Denied or timed-out operations are rejected." checked={gpEnforceHold} onChange={()=>setGpEnforceHold((v)=>!v)}/>
          <div style={{fontSize:9,color:C.dim,marginTop:4,marginLeft:24}}>
            When enabled: the KMS suspends the operation, notifies all approvers via configured channels, and waits for quorum. The operation proceeds only after sufficient approvals. If the timeout expires without quorum, the operation is automatically denied.
          </div>
        </div>

        {/* Quorum explanation */}
        <div style={{padding:"8px 12px",borderRadius:8,background:`${C.blue}12`,border:`1px solid ${C.blue}33`,fontSize:10,color:C.dim}}>
          {gpQuorum==="threshold"&&`Threshold (M-of-N): ${gpRequired} out of ${gpTotal} designated approvers must approve. Any group member can cast their vote. ${gpTotal-gpRequired+1} denials will reject the operation.`}
          {gpQuorum==="and"&&"Unanimous (AND): ALL designated approvers must vote to approve. A single denial from any approver immediately rejects the operation."}
          {gpQuorum==="or"&&"Any Single (OR): ONE approval from any designated approver is sufficient to proceed. All approvers must deny to reject."}
        </div>

        <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:8}}>
          <Btn small onClick={()=>setGovPolicyModal(false)}>Cancel</Btn>
          <Btn small primary onClick={()=>void saveGovPolicy()} disabled={gpSaving}>{gpSaving?"Saving...":(govEditPolicy?"Update Policy":"Create Policy")}</Btn>
        </div>
      </div>
    </Modal>}
    </>}

    {panel==="diskencryption"&&<>
    <Section title="Full Disk Encryption" actions={<div style={{display:"flex",gap:8}}>
      <Btn small onClick={()=>void loadFDEStatus()} disabled={fdeLoading}>{fdeLoading?"Refreshing...":"Refresh"}</Btn>
    </div>}>
      <Card style={{padding:10,borderRadius:8,marginBottom:10}}>
        <div style={{display:"flex",gap:10,marginBottom:12,flexWrap:"wrap"}}>
          <Stat l="Status" v={fdeStatus?.enabled?"Encrypted":"Not Encrypted"} c={fdeStatus?.enabled?"green":"red"}/>
          <Stat l="Algorithm" v={fdeStatus?.algorithm||"-"} c="accent"/>
          <Stat l="LUKS Version" v={fdeStatus?.luks_version||"-"} c="blue"/>
          <Stat l="Key Derivation" v={fdeStatus?.key_derivation||"-"} c="purple"/>
        </div>
        <Row2>
          <FG label="Device"><Inp value={String(fdeStatus?.device||"-")} readOnly/></FG>
          <FG label="Unlock Method"><Inp value={String(fdeStatus?.unlock_method||"-")} readOnly/></FG>
        </Row2>
        <div style={{marginTop:8,height:6,borderRadius:3,background:C.surface,overflow:"hidden"}}>
          <div style={{height:"100%",borderRadius:3,background:C.accent,width:`${fdeStatus?.volume_size_gb?Math.min(100,(fdeStatus.used_gb/fdeStatus.volume_size_gb)*100):0}%`,transition:"width .3s ease"}}/>
        </div>
        <div style={{fontSize:10,color:C.dim,marginTop:4}}>{`${fdeStatus?.used_gb||0} / ${fdeStatus?.volume_size_gb||0} GB used`}</div>
      </Card>

      <Card style={{padding:10,borderRadius:8,marginBottom:10}}>
        <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:8}}>Key Slots</div>
        <div style={{display:"grid",gap:6}}>
          {(fdeStatus?.key_slots||[]).map((slot:any)=>
            <div key={slot.slot} style={{display:"flex",gap:8,alignItems:"center"}}>
              <B c={slot.status==="active"?"green":"dim"}>Slot {slot.slot}</B>
              <span style={{fontSize:10,color:C.dim}}>{slot.type} — {slot.status}</span>
            </div>
          )}
          {!(fdeStatus?.key_slots||[]).length&&<div style={{fontSize:10,color:C.muted}}>No key slot data available.</div>}
        </div>
      </Card>

      <Row2>
        <Card style={{padding:10,borderRadius:8}}>
          <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:8}}>Integrity Check</div>
          <div style={{fontSize:10,color:C.dim,marginBottom:8}}>Last check: {fdeStatus?.integrity_last_check||"Never"} | Status: <B c={fdeStatus?.integrity_status==="healthy"?"green":"amber"}>{fdeStatus?.integrity_status||"Unknown"}</B></div>
          <Btn small primary onClick={()=>void doFDEIntegrityCheck()} disabled={fdeIntegrityRunning}>{fdeIntegrityRunning?"Checking...":"Run Integrity Check"}</Btn>
        </Card>
        <Card style={{padding:10,borderRadius:8}}>
          <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:8}}>Volume Key Rotation</div>
          <div style={{fontSize:10,color:C.dim,marginBottom:8}}>Re-encrypt the volume with a new master key. This is a long-running operation and cannot be interrupted.</div>
          <Btn small danger onClick={()=>void doFDERotateKey()} disabled={fdeKeyRotating}>{fdeKeyRotating?"Rotating...":"Rotate Volume Key"}</Btn>
        </Card>
      </Row2>

      <Card style={{padding:10,borderRadius:8,marginTop:10}}>
        <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:8}}>Recovery Shares (Shamir {fdeRecoveryShares?.threshold||"?"}-of-{fdeRecoveryShares?.total||"?"})</div>
        <div style={{display:"grid",gap:6,marginBottom:10}}>
          {(fdeRecoveryShares?.shares||[]).map((share:any)=>
            <div key={share.index} style={{display:"flex",gap:8,alignItems:"center"}}>
              <B c={share.verified?"green":"amber"}>Share {share.index}</B>
              <span style={{fontSize:10,color:C.dim}}>{share.label} | {share.verified?`Verified ${share.last_verified||""}`:"Not verified"}</span>
            </div>
          )}
          {!(fdeRecoveryShares?.shares||[]).length&&<div style={{fontSize:10,color:C.muted}}>No recovery share data.</div>}
        </div>
        <div style={{fontSize:10,color:C.dim,marginBottom:8}}>Test recovery by providing {fdeRecoveryShares?.threshold||3} share values:</div>
        {Array.from({length:fdeRecoveryShares?.threshold||3}).map((_,i)=>
          <FG key={i} label={`Share ${i+1}`}>
            <Inp type="password" value={fdeTestShareInputs[i]||""} onChange={(e)=>setFdeTestShareInputs((prev)=>{const next=[...prev];next[i]=e.target.value;return next;})} placeholder="Paste recovery share hex value"/>
          </FG>
        )}
        <Btn small primary onClick={()=>void doFDETestRecovery()} disabled={fdeRecoveryTesting} style={{marginTop:8}}>{fdeRecoveryTesting?"Testing...":"Test Recovery Shares"}</Btn>
      </Card>
    </Section>
    </>}

    {promptDialog.ui}
  </div>;
};
