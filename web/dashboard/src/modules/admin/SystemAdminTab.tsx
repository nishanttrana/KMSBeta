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
import { getCertSecurityStatus } from "../../lib/certs";
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
  type GovernanceBackupJob,
  type GovernanceSettings
} from "../../lib/governance";
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
  Tabs,
  usePromptDialog
} from "../../components/v3/legacyPrimitives";
import {
  deleteKeyInterfacePolicy,
  deleteKeyInterfacePort,
  deleteTag,
  getKeyAccessSettings,
  listKeyInterfacePolicies,
  listKeyInterfacePorts,
  listTags,
  updateKeyAccessSettings,
  upsertKeyInterfacePolicy,
  upsertKeyInterfacePort,
  upsertTag
} from "../../lib/keycore";
import { errMsg } from "../../components/v3/runtimeUtils";
import { C } from "../../components/v3/theme";
import type { AdminTabProps } from "./types";

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

const RESTART_BLOCKED_TARGETS = new Set([
  "audit",
  "auth",
  "cluster-manager",
  "consul",
  "dashboard",
  "envoy",
  "etcd",
  "firstboot",
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

const KEY_ACCESS_OPERATION_OPTIONS = [
  { id: "encrypt", label: "Encrypt" },
  { id: "decrypt", label: "Decrypt" },
  { id: "sign", label: "Sign" },
  { id: "verify", label: "Verify" },
  { id: "wrap", label: "Wrap" },
  { id: "unwrap", label: "Unwrap" },
  { id: "derive", label: "Derive" },
  { id: "export", label: "Export" }
];

const INTERFACE_OPTIONS = ["rest","ekm","payment-tcp","pkcs11","jca","kmip","hyok","byok"];

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
  | "platform"
  | "cli"
  | "governance"
  | "backup";
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
  { label:"CLI / HSM", panel:"cli" },
  { label:"Governance", panel:"governance" },
  { label:"Backup", panel:"backup" }
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
  const [accessSettings,setAccessSettings]=useState<Record<string,any>|null>(null);
  const [accessSettingsLoading,setAccessSettingsLoading]=useState(false);
  const [accessSettingsSaving,setAccessSettingsSaving]=useState(false);
  const [interfacePolicies,setInterfacePolicies]=useState<Array<Record<string,any>>>([]);
  const [interfacePorts,setInterfacePorts]=useState<Array<Record<string,any>>>([]);
  const [interfaceConfigLoading,setInterfaceConfigLoading]=useState(false);
  const [newInterfacePolicy,setNewInterfacePolicy]=useState<Record<string,any>>({
    interface_name:"rest",
    subject_type:"user",
    subject_id:"",
    operations:["encrypt"],
    enabled:true
  });
  const [newInterfacePort,setNewInterfacePort]=useState<Record<string,any>>({
    interface_name:"rest",
    bind_address:"0.0.0.0",
    port:443,
    enabled:true,
    description:""
  });
  const [newTagName,setNewTagName]=useState("");
  const [newTagColor,setNewTagColor]=useState("#14B8A6");
  const [tagSaving,setTagSaving]=useState(false);
  const initialLoadTokenRef=useRef("");

  const sessionGuard=useCallback((error:unknown)=>{
    const msg=errMsg(error).toLowerCase();
    if(msg.includes("invalid token")||msg.includes("unauthorized")){
      onToast("Session expired. Please login again.");
      onLogout();
      return true;
    }
    return false;
  },[onLogout,onToast]);

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
      setInterfacePolicies([]);
      setInterfacePorts([]);
      return;
    }
    setAccessSettingsLoading(true);
    setInterfaceConfigLoading(true);
    try{
      const [settings,policies,ports]=await Promise.all([
        getKeyAccessSettings(session),
        listKeyInterfacePolicies(session),
        listKeyInterfacePorts(session)
      ]);
      setAccessSettings((settings&&typeof settings==="object")?settings:null);
      setInterfacePolicies(Array.isArray(policies)?policies:[]);
      setInterfacePorts(Array.isArray(ports)?ports:[]);
    }catch(error){
      if(!sessionGuard(error)) onToast(`Key access hardening load failed: ${errMsg(error)}`);
    }finally{
      setAccessSettingsLoading(false);
      setInterfaceConfigLoading(false);
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

  const addInterfacePolicy=useCallback(async()=>{
    if(!session?.token){return;}
    const subject=String(newInterfacePolicy?.subject_id||"").trim();
    const ops=Array.isArray(newInterfacePolicy?.operations)?newInterfacePolicy.operations:[];
    if(!subject){onToast("Subject ID is required.");return;}
    if(!ops.length){onToast("Select at least one operation.");return;}
    try{
      await upsertKeyInterfacePolicy(session,{
        interface_name:String(newInterfacePolicy?.interface_name||"rest"),
        subject_type:String(newInterfacePolicy?.subject_type||"user")==="group"?"group":"user",
        subject_id:subject,
        operations:ops,
        enabled:Boolean(newInterfacePolicy?.enabled)
      });
      onToast("Interface subject policy saved.");
      await loadAccessHardening();
    }catch(error){
      if(!sessionGuard(error)) onToast(`Interface subject policy save failed: ${errMsg(error)}`);
    }
  },[loadAccessHardening,newInterfacePolicy,onToast,session,sessionGuard]);

  const removeInterfacePolicy=useCallback(async(id:string)=>{
    if(!session?.token||!String(id||"").trim()){return;}
    try{
      await deleteKeyInterfacePolicy(session,String(id).trim());
      onToast("Interface subject policy deleted.");
      await loadAccessHardening();
    }catch(error){
      if(!sessionGuard(error)) onToast(`Interface subject policy delete failed: ${errMsg(error)}`);
    }
  },[loadAccessHardening,onToast,session,sessionGuard]);

  const addInterfacePort=useCallback(async()=>{
    if(!session?.token){return;}
    const iface=String(newInterfacePort?.interface_name||"").trim();
    const bind=String(newInterfacePort?.bind_address||"").trim()||"0.0.0.0";
    const port=Number(newInterfacePort?.port||0);
    if(!iface){onToast("Interface is required.");return;}
    if(!Number.isFinite(port)||port<=0||port>65535){onToast("Valid port (1-65535) is required.");return;}
    try{
      await upsertKeyInterfacePort(session,{
        interface_name:iface,
        bind_address:bind,
        port,
        enabled:Boolean(newInterfacePort?.enabled),
        description:String(newInterfacePort?.description||"").trim()
      });
      onToast("Interface port mapping saved.");
      await loadAccessHardening();
    }catch(error){
      if(!sessionGuard(error)) onToast(`Interface port save failed: ${errMsg(error)}`);
    }
  },[loadAccessHardening,newInterfacePort,onToast,session,sessionGuard]);

  const removeInterfacePort=useCallback(async(interfaceName:string)=>{
    if(!session?.token||!String(interfaceName||"").trim()){return;}
    try{
      await deleteKeyInterfacePort(session,String(interfaceName).trim());
      onToast("Interface port mapping deleted.");
      await loadAccessHardening();
    }catch(error){
      if(!sessionGuard(error)) onToast(`Interface port delete failed: ${errMsg(error)}`);
    }
  },[loadAccessHardening,onToast,session,sessionGuard]);

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
      await upsertTag(session,name,String(newTagColor||"#14B8A6"));
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
    }catch(error){
      if(!sessionGuard(error)) onToast(`System state save failed: ${errMsg(error)}`);
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

  const restartableServiceNames = useMemo(
    ()=> (health.services||[])
      .filter((svc)=>restartAllowedFor(svc))
      .map((svc)=>String(svc?.name||"").trim())
      .filter(Boolean),
    [health.services]
  );

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
  const networkSummary = [
    String(systemState?.mgmt_ip||"IP"),
    String(systemState?.dns_servers||"DNS"),
    String(systemState?.ntp_servers||"NTP"),
    String(systemState?.tls_mode||"TLS")
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
        0% { transform: scale(1); opacity: 0.85; box-shadow: 0 0 0 0 rgba(20,184,166,0.35); }
        70% { transform: scale(1.08); opacity: 1; box-shadow: 0 0 0 5px rgba(20,184,166,0); }
        100% { transform: scale(1); opacity: 0.85; box-shadow: 0 0 0 0 rgba(20,184,166,0); }
      }
      .vecta-hb-dot {
        display:inline-block;
        width:7px;
        height:7px;
        border-radius:999px;
        margin-right:6px;
        vertical-align:middle;
      }
      .vecta-hb-running { background:#14B8A6; animation:vectaStatusPulse 1.8s ease-in-out infinite; }
      .vecta-hb-degraded { background:#F59E0B; animation:vectaStatusPulse 2.2s ease-in-out infinite; }
      .vecta-hb-down { background:#EF4444; animation:none; opacity:0.95; }
      .vecta-hb-unknown { background:#3B82F6; animation:vectaStatusPulse 2.6s ease-in-out infinite; }
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
        <Btn small onClick={()=>setPanel("platform")}>Configure FIPS</Btn>
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
          <Btn small primary={fipsMode!=="enabled"} onClick={()=>onFipsModeChange("enabled")}>Enable FIPS</Btn>
          <Btn small primary={fipsMode!=="disabled"} onClick={()=>onFipsModeChange("disabled")}>Disable FIPS</Btn>
          <span style={{fontSize:11,color:C.green,fontWeight:700,border:`1px solid ${C.border}`,background:C.bg,borderRadius:999,padding:"4px 9px",alignSelf:"center"}}>
            <span className={`vecta-hb-dot ${heartbeatToneClass(fipsMode==="enabled"?"running":"unknown")}`} />
            OK
          </span>
        </div>
        <div style={{fontSize:10,color:C.dim,marginTop:8}}>{runtimeLibraryLine}</div>
      </Card>
    </Section>
    </>}

    {panel==="network"&&<>
    <Section title="Network" actions={<div style={{display:"flex",gap:8}}>
      <Btn small onClick={()=>void loadSystemState()} disabled={systemStateLoading}>{systemStateLoading?"Refreshing...":"Refresh"}</Btn>
      <Btn small primary onClick={()=>void saveSystemState()} disabled={systemStateLoading||systemStateSaving}>{systemStateSaving?"Saving...":"Save"}</Btn>
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
          <FG label="TLS Mode">
            <Sel value={String(systemState?.tls_mode||"internal_ca")} onChange={(e)=>setSystemState((p)=>({...p,tls_mode:e.target.value}))}>
              <option value="internal_ca">Internal CA</option>
              <option value="custom">Custom</option>
              <option value="tls13_only">TLS 1.3 only</option>
              <option value="tls13_hybrid_ui">TLS 1.3 + Hybrid PQC (WebUI)</option>
              <option value="tls13_hybrid_kms">TLS 1.3 + Hybrid PQC (KMS Internal)</option>
            </Sel>
          </FG>
          <FG label="Proxy Endpoint"><Inp value={String(systemState?.proxy_endpoint||"")} onChange={(e)=>setSystemState((p)=>({...p,proxy_endpoint:e.target.value}))} placeholder="https://proxy.bank.local:8443"/></FG>
        </Row2>
        <div style={{fontSize:10,color:C.dim,marginTop:8}}>{networkSummary}</div>
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
            const color=String(tag?.color||"#14B8A6");
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

      <Row2>
        <Card style={{padding:10,borderRadius:8}}>
          <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:8}}>Interface Subject Policies</div>
          <Row3>
            <FG label="Interface">
              <Sel value={String(newInterfacePolicy?.interface_name||"rest")} onChange={(e)=>setNewInterfacePolicy((p)=>({...p,interface_name:e.target.value}))}>
                {INTERFACE_OPTIONS.map((opt)=><option key={opt} value={opt}>{opt}</option>)}
              </Sel>
            </FG>
            <FG label="Subject Type">
              <Sel value={String(newInterfacePolicy?.subject_type||"user")} onChange={(e)=>setNewInterfacePolicy((p)=>({...p,subject_type:e.target.value}))}>
                <option value="user">user</option>
                <option value="group">group</option>
              </Sel>
            </FG>
            <FG label="Subject ID"><Inp value={String(newInterfacePolicy?.subject_id||"")} onChange={(e)=>setNewInterfacePolicy((p)=>({...p,subject_id:e.target.value}))}/></FG>
          </Row3>
          <div style={{display:"grid",gridTemplateColumns:"repeat(4,minmax(0,1fr))",gap:8,marginBottom:8}}>
            {KEY_ACCESS_OPERATION_OPTIONS.map((op)=>{
              const selected = Array.isArray(newInterfacePolicy?.operations) && newInterfacePolicy.operations.includes(op.id);
              return <Chk key={op.id} label={op.label} checked={selected} onChange={()=>{
                setNewInterfacePolicy((p)=>{
                  const ops = Array.isArray(p?.operations)?[...p.operations]:[];
                  const next = ops.includes(op.id) ? ops.filter((item)=>item!==op.id) : [...ops, op.id];
                  return {...p,operations:next};
                });
              }}/>;
            })}
          </div>
          <div style={{display:"flex",justifyContent:"space-between",gap:8,marginBottom:8}}>
            <Chk label="Enabled" checked={Boolean(newInterfacePolicy?.enabled)} onChange={()=>setNewInterfacePolicy((p)=>({...p,enabled:!Boolean(p?.enabled)}))}/>
            <Btn small primary onClick={()=>void addInterfacePolicy()}>Save Policy</Btn>
          </div>
          <div style={{display:"grid",gap:6}}>
            {interfacePolicies.map((policy:any)=>{
              const id=String(policy?.id||"");
              return <div key={id} style={{display:"grid",gridTemplateColumns:"1fr auto",gap:8,borderBottom:`1px solid ${C.border}`,paddingBottom:6}}>
                <div style={{fontSize:10,color:C.dim}}>{`${String(policy?.interface_name||"-")} / ${String(policy?.subject_type||"-")} / ${String(policy?.subject_id||"-")} / ${(Array.isArray(policy?.operations)?policy.operations:[]).join(",")}`}</div>
                <Btn small danger onClick={()=>void removeInterfacePolicy(id)}>Delete</Btn>
              </div>;
            })}
            {!interfacePolicies.length?<div style={{fontSize:10,color:C.muted}}>No subject policies.</div>:null}
          </div>
        </Card>

        <Card style={{padding:10,borderRadius:8}}>
          <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:8}}>Interface Ports</div>
          <Row2>
            <FG label="Interface">
              <Sel value={String(newInterfacePort?.interface_name||"rest")} onChange={(e)=>setNewInterfacePort((p)=>({...p,interface_name:e.target.value}))}>
                {INTERFACE_OPTIONS.map((opt)=><option key={opt} value={opt}>{opt}</option>)}
              </Sel>
            </FG>
            <FG label="Bind Address"><Inp value={String(newInterfacePort?.bind_address||"0.0.0.0")} onChange={(e)=>setNewInterfacePort((p)=>({...p,bind_address:e.target.value}))}/></FG>
          </Row2>
          <Row2>
            <FG label="Port"><Inp type="number" value={String(newInterfacePort?.port||443)} onChange={(e)=>setNewInterfacePort((p)=>({...p,port:Math.max(1,Math.min(65535,Number(e.target.value||443)))}))}/></FG>
            <FG label="Description"><Inp value={String(newInterfacePort?.description||"")} onChange={(e)=>setNewInterfacePort((p)=>({...p,description:e.target.value}))}/></FG>
          </Row2>
          <div style={{display:"flex",justifyContent:"space-between",gap:8,marginBottom:8}}>
            <Chk label="Enabled" checked={Boolean(newInterfacePort?.enabled)} onChange={()=>setNewInterfacePort((p)=>({...p,enabled:!Boolean(p?.enabled)}))}/>
            <Btn small primary onClick={()=>void addInterfacePort()}>Save Port</Btn>
          </div>
          <div style={{display:"grid",gap:6}}>
            {interfacePorts.map((port:any)=>{
              const iface=String(port?.interface_name||"");
              return <div key={iface} style={{display:"grid",gridTemplateColumns:"1fr auto",gap:8,borderBottom:`1px solid ${C.border}`,paddingBottom:6}}>
                <div style={{fontSize:10,color:C.dim}}>{`${iface} ${String(port?.bind_address||"0.0.0.0")}:${Number(port?.port||0)} ${Boolean(port?.enabled)?"enabled":"disabled"}`}</div>
                <Btn small danger onClick={()=>void removeInterfacePort(iface)}>Delete</Btn>
              </div>;
            })}
            {!interfacePorts.length?<div style={{fontSize:10,color:C.muted}}>No interface ports.</div>:null}
          </div>
        </Card>
      </Row2>
    </Section>
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
          <div style={{fontSize:10,color:C.muted,marginBottom:8}}>Interfaces / Network</div>
          <Row2>
            <FG label="Management IP"><Inp value={String(systemState?.mgmt_ip||"")} onChange={(e)=>setSystemState((p)=>({...p,mgmt_ip:e.target.value}))} placeholder="10.0.1.100"/></FG>
            <FG label="Cluster IP"><Inp value={String(systemState?.cluster_ip||"")} onChange={(e)=>setSystemState((p)=>({...p,cluster_ip:e.target.value}))} placeholder="172.16.0.100"/></FG>
          </Row2>
          <Row2>
            <FG label="DNS Servers"><Inp value={String(systemState?.dns_servers||"")} onChange={(e)=>setSystemState((p)=>({...p,dns_servers:e.target.value}))} placeholder="8.8.8.8,1.1.1.1"/></FG>
            <FG label="NTP Servers"><Inp value={String(systemState?.ntp_servers||"")} onChange={(e)=>setSystemState((p)=>({...p,ntp_servers:e.target.value}))} placeholder="pool.ntp.org"/></FG>
          </Row2>
          <Row2>
            <FG label="TLS Mode">
              <Sel value={String(systemState?.tls_mode||"internal_ca")} onChange={(e)=>setSystemState((p)=>({...p,tls_mode:e.target.value}))}>
                <option value="internal_ca">Internal CA</option>
                <option value="custom">Custom</option>
                <option value="tls13_only">TLS 1.3 only</option>
                <option value="tls13_hybrid_ui">TLS 1.3 + Hybrid PQC (WebUI)</option>
                <option value="tls13_hybrid_kms">TLS 1.3 + Hybrid PQC (KMS Internal)</option>
              </Sel>
            </FG>
            <FG label="Proxy Endpoint"><Inp value={String(systemState?.proxy_endpoint||"")} onChange={(e)=>setSystemState((p)=>({...p,proxy_endpoint:e.target.value}))} placeholder="https://proxy.bank.local:8443"/></FG>
          </Row2>
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
            <input
              type="file"
              accept={BACKUP_ARTIFACT_EXTENSION}
              onChange={(e)=>setBackupRestoreArtifactFile((e.target.files&&e.target.files[0])?e.target.files[0]:null)}
              style={{width:"100%",padding:"8px 10px",borderRadius:8,border:`1px solid ${C.border}`,background:C.bg,color:C.text}}
            />
          </FG>
          <FG label={`Key Package (${BACKUP_KEY_EXTENSION})`}>
            <input
              type="file"
              accept=".json,.key.json"
              onChange={(e)=>setBackupRestoreKeyFile((e.target.files&&e.target.files[0])?e.target.files[0]:null)}
              style={{width:"100%",padding:"8px 10px",borderRadius:8,border:`1px solid ${C.border}`,background:C.bg,color:C.text}}
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
    {promptDialog.ui}
  </div>;
};

