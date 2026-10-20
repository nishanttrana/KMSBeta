import { useCallback, useEffect, useRef, useState } from "react";
import {
  getAuthCLIHSMConfig,
  getAuthCLIStatus,
  getAuthPasswordPolicy,
  getAuthSecurityPolicy,
  getAuthSystemHealth,
  listAuthCLIHSMPartitions,
  openAuthCLISession,
  updateAuthPasswordPolicy,
  updateAuthSecurityPolicy,
  upsertAuthCLIHSMConfig,
  type AuthSystemHealthSnapshot,
  type CLIHSMPartitionSlot,
  type CLIStatus,
  type HSMProviderConfig
} from "../../lib/authAdmin";
import {
  getCertSecurityStatus
} from "../../lib/certs";
import {
  fetchHeartbeats,
  fetchIncidents,
  fetchReconcilerStatus,
  type Incident,
  type ReconcilerStatus,
  type ServiceState
} from "../../lib/health";
import {
  getGovernanceSystemState,
  getGovernanceSettings,
  patchGovernanceSystemState,
  testGovernanceSystemSNMP,
  testGovernanceSMTP,
  testGovernanceWebhook,
  listNotifyConnections,
  type NotifyConnection,
  updateGovernanceSettings,
  type GovernanceSettings
} from "../../lib/governance";
import {
  listReportingRules,
  createReportingRule,
  updateReportingRule,
  testReportingRule,
  type RuleCheck,
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
  usePromptDialog
} from "../../components/v3/legacyPrimitives";
import {
  deleteTag,
  getKeyAccessSettings,
  listTags,
  updateKeyAccessSettings,
  upsertTag
} from "../../lib/keycore";
import { CredentialPicker } from "../../components/v3/CredentialPicker";
import { errMsg } from "../../components/v3/runtimeUtils";
import { C } from "../../components/v3/theme";
import type { AdminTabProps } from "./types";
import { FipsModePanel } from "./FipsModePanel";

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

// A health list the panel loaded, or the error that stopped it: a failed call
// shows as "unavailable", never as an empty list.
type HealthList<T>={items:T[];error:string;loaded:boolean};
const emptyHealthList={items:[],error:"",loaded:false};
const settleHealthList=<T,>(r:PromiseSettledResult<T[]>):HealthList<T>=>
  r.status==="fulfilled"?{items:r.value,error:"",loaded:true}:{items:[],error:errMsg(r.reason),loaded:true};

function HealthListBody<T>({list,empty,children}:{list:HealthList<T>;empty:string;children:React.ReactNode}){
  if(!list.loaded) return <div style={{fontSize:10,color:C.muted}}>Loading...</div>;
  if(list.error) return <div style={{fontSize:10,color:C.redFg}}>{`Unavailable: ${list.error}`}</div>;
  if(!list.items.length) return <div style={{fontSize:10,color:C.muted}}>{empty}</div>;
  return <>{children}</>;
}

const INTERNAL_TLS_POLICY="TLS 1.3 · internal mTLS · key exchange per service (hybrid ML-KEM by default)";


const GOV_DEFAULT={
  approval_expiry_minutes:60,
  expiry_check_interval_seconds:60,
  approval_delivery_mode:"kms_only",
  notify_dashboard:true,
  notify_email:false,
  notify_slack:false,
  notify_teams:false,
  smtp_connection_id:"",
  smtp_host:"",
  smtp_port:"",
  smtp_username:"",
  smtp_from:"",
  slack_connection_id:"",
  teams_connection_id:"",
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


const SYSTEM_STATE_DEFAULT = {
  fips_mode: "disabled",
  fips_mode_policy: "standard",
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

type SystemAdminPanel =
  | "health"
  | "runtime"
  | "snmp"
  | "tags"
  | "password"
  | "login"
  | "keyaccess"
  | "platform"
  | "cli"
  | "governance"
  | "alertrules";
const SYSTEM_ADMIN_TABS: Array<{label:string;panel:SystemAdminPanel}> = [
  { label:"Health", panel:"health" },
  { label:"Runtime Crypto", panel:"runtime" },
  { label:"SNMP", panel:"snmp" },
  { label:"Tags", panel:"tags" },
  { label:"Password Policy", panel:"password" },
  { label:"Login Security", panel:"login" },
  { label:"Key Access Hardening", panel:"keyaccess" },
  { label:"CLI / HSM", panel:"cli" },
  { label:"Governance", panel:"governance" },
  { label:"Alert Rules", panel:"alertrules" }
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

export const SystemAdminTab=({session,onToast,onLogout,fipsMode,onFipsModeChange,tagCatalog,setTagCatalog,subView}:AdminTabProps)=>{
  const promptDialog=usePromptDialog();
  const [health,setHealth]=useState<AuthSystemHealthSnapshot>({services:[],summary:{}});
  const [healthLoading,setHealthLoading]=useState(false);
  const [heartbeats,setHeartbeats]=useState<HealthList<ServiceState>>(emptyHealthList);
  const [incidents,setIncidents]=useState<HealthList<Incident>>(emptyHealthList);
  const [reconcilers,setReconcilers]=useState<HealthList<ReconcilerStatus>>(emptyHealthList);

  const [gov,setGov]=useState(GOV_DEFAULT);
  // Slack/Teams connections approval notices can go through (Playbooks → Connections).
  const [govConns,setGovConns]=useState<NotifyConnection[]|null>(null);
  const [govConnsErr,setGovConnsErr]=useState("");
  const [govLoading,setGovLoading]=useState(false);
  const [govSaving,setGovSaving]=useState(false);
  const [smtpTo,setSmtpTo]=useState("");
  const [smtpTesting,setSmtpTesting]=useState(false);
  const [webhookTesting,setWebhookTesting]=useState<{slack:boolean;teams:boolean}>({slack:false,teams:false});
  const [systemState,setSystemState]=useState<Record<string,any>>(SYSTEM_STATE_DEFAULT);
  const [systemStateLoading,setSystemStateLoading]=useState(false);
  const [systemStateSaving,setSystemStateSaving]=useState(false);
  const [snmpTesting,setSnmpTesting]=useState(false);


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
  // The section is the sidebar sub-option (13.23.0-beta).
  const panel:SystemAdminPanel=SYSTEM_ADMIN_TABS.some((item)=>item.panel===subView)?subView as SystemAdminPanel:"health";
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
  const [fipsConfigModalOpen,setFipsConfigModalOpen]=useState(false);

  // ── Disk Encryption state ──


  const [newTagName,setNewTagName]=useState("");
  const [newTagColor,setNewTagColor]=useState(C.teal);
  const [tagSaving,setTagSaving]=useState(false);
  const initialLoadTokenRef=useRef("");

  const [alertRules,setAlertRules]=useState<ReportingAlertRule[]>([]);
  const [alertRulesLoading,setAlertRulesLoading]=useState(false);
  const [ruleModalOpen,setRuleModalOpen]=useState(false);
  const [ruleCheck,setRuleCheck]=useState<RuleCheck|null>(null);
  const [ruleChecking,setRuleChecking]=useState(false);
  const [ruleReplayHours,setRuleReplayHours]=useState(24);
  const [editingRule,setEditingRule]=useState<ReportingAlertRule|null>(null);
  const [ruleName,setRuleName]=useState("");
  const [ruleCondition,setRuleCondition]=useState<"threshold"|"expression">("threshold");
  const [rulePattern,setRulePattern]=useState("");
  const [ruleSeverity,setRuleSeverity]=useState("warning");
  const [ruleThreshold,setRuleThreshold]=useState(1);
  const [ruleWindowSeconds,setRuleWindowSeconds]=useState(300);
  const [ruleExpression,setRuleExpression]=useState("");
  const [ruleChannels,setRuleChannels]=useState<string[]>(["screen"]);
  // Reporting delivers alerts only to the dashboard ("screen"); the list comes
  // from the service. Other notifications go through Playbooks connections.
  const [ruleChannelsAvail,setRuleChannelsAvail]=useState<string[]>(["screen"]);
  const [ruleSaving,setRuleSaving]=useState(false);

  const sanitizeRuleChannels=useCallback((channels:string[])=>{
    return Array.from(new Set((Array.isArray(channels)?channels:[])
      .map((ch)=>String(ch||"").trim().toLowerCase())
      .filter((ch)=>ruleChannelsAvail.includes(ch))));
  },[ruleChannelsAvail]);

  const sessionGuard=useCallback((error:unknown)=>{
    const msg=errMsg(error).toLowerCase();
    if(msg.includes("invalid token")||msg.includes("unauthorized")){
      onToast("Session expired. Please login again.");
      onLogout();
      return true;
    }
    return false;
  },[onLogout,onToast]);

  const refreshAlertRules=useCallback(async()=>{
    if(!session?.token) return;
    setAlertRulesLoading(true);
    try{
      const [rulesOut,channelsOut]=await Promise.all([listReportingRules(session),listReportingChannels(session)]);
      setAlertRules(rulesOut);
      const names=channelsOut
        .filter((ch)=>ch.enabled)
        .map((ch)=>String(ch.name||"").trim().toLowerCase())
        .filter(Boolean);
      if(names.length) setRuleChannelsAvail(names);
    }catch(error){if(!sessionGuard(error)) onToast(`Alert rules load failed: ${errMsg(error)}`);}
    finally{setAlertRulesLoading(false);}
  },[session,sessionGuard,onToast]);

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
    setRuleCheck(null);
    setRuleModalOpen(true);
  },[sanitizeRuleChannels]);

  const ruleBody=useCallback(():ReportingAlertRule=>({
    name:String(ruleName||"").trim(),
    condition:ruleCondition,
    severity:ruleSeverity,
    event_pattern:ruleCondition==="threshold"?String(rulePattern||"").trim():"*",
    threshold:ruleCondition==="threshold"?Math.max(1,Math.trunc(ruleThreshold)):1,
    window_seconds:ruleCondition==="threshold"?Math.max(1,Math.trunc(ruleWindowSeconds)):60,
    expression:ruleCondition==="expression"?String(ruleExpression||"").trim():"",
    channels:sanitizeRuleChannels(ruleChannels),
    enabled:editingRule?.enabled!==false
  }),[ruleName,ruleCondition,ruleSeverity,rulePattern,ruleThreshold,ruleWindowSeconds,ruleExpression,ruleChannels,sanitizeRuleChannels,editingRule]);

  // Test runs the rule without saving it: validity, then a replay over the
  // tenant's real audit events from the chosen period.
  const handleTestRule=useCallback(async()=>{
    if(!session?.token) return;
    setRuleChecking(true);
    try{setRuleCheck(await testReportingRule(session,ruleBody(),{replayHours:ruleReplayHours}));}
    catch(error){setRuleCheck(null); if(!sessionGuard(error)) onToast(`Rule test failed: ${errMsg(error)}`);}
    finally{setRuleChecking(false);}
  },[session,ruleBody,ruleReplayHours,sessionGuard,onToast]);

  const handleSaveRule=useCallback(async()=>{
    if(!session?.token) return;
    const name=String(ruleName||"").trim();
    if(!name){onToast("Rule name is required."); return;}
    if(ruleCondition==="threshold"&&!String(rulePattern||"").trim()){onToast("Event pattern is required for threshold rules."); return;}
    if(ruleCondition==="expression"&&!String(ruleExpression||"").trim()){onToast("Expression is required for expression rules."); return;}
    setRuleSaving(true);
    try{
      const body=ruleBody();
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
  },[session,ruleName,ruleCondition,rulePattern,ruleExpression,editingRule,ruleBody,refreshAlertRules,sessionGuard,onToast]);

  const toggleRuleChannel=useCallback((ch:string)=>{
    setRuleChannels((prev)=>prev.includes(ch)?prev.filter((c)=>c!==ch):[...prev,ch]);
  },[]);

  const loadHealth=useCallback(async()=>{
    if(!session?.token){setHealth({services:[],summary:{}});return;}
    setHealthLoading(true);
    // Watchdog and reconciler are separate services: each section shows its
    // own error without holding up the service list.
    void Promise.allSettled([fetchHeartbeats(session),fetchIncidents(session),fetchReconcilerStatus(session)]).then(([hb,inc,rec])=>{
      setHeartbeats(settleHealthList(hb));
      setIncidents(settleHealthList(inc));
      setReconcilers(settleHealthList(rec));
    });
    try{
      setHealth(await getAuthSystemHealth(session));
    }
    catch(error){if(!sessionGuard(error)) onToast(`System health load failed: ${errMsg(error)}`);} 
    finally{setHealthLoading(false);} 
  },[onToast,session,sessionGuard]);

  const loadGov=useCallback(async()=>{
    if(!session?.token){setGov(GOV_DEFAULT);return;}
    setGovLoading(true);
    listNotifyConnections(session).then((c)=>{setGovConns(c);setGovConnsErr("");}).catch((e)=>{setGovConns(null);setGovConnsErr(errMsg(e));});
    try{const s=(await getGovernanceSettings(session)) as GovernanceSettings; setGov({...GOV_DEFAULT,...s});}
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
      return;
    }
    setAccessSettingsLoading(true);
    try{
      const settings=await getKeyAccessSettings(session);
      setAccessSettings((settings&&typeof settings==="object")?settings:null);
    }catch(error){
      if(!sessionGuard(error)) onToast(`Key access hardening load failed: ${errMsg(error)}`);
    }finally{
      setAccessSettingsLoading(false);
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
      // Only fields the server stores and enforces.
      const payload={
        tenant_id: session.tenantId,
        fips_mode: String(systemState?.fips_mode||"disabled"),
        fips_mode_policy: String(systemState?.fips_mode_policy||"standard"),
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
    loadPasswordPolicy,
    loadSecurityPolicy,
    loadSystemState,
    loadTags
  ]);

  useEffect(()=>{
    if(panel==="alertrules"&&session?.token) void refreshAlertRules();
  },[panel,refreshAlertRules,session?.token]);

  useEffect(()=>{
    setSystemState((prev)=>({
      ...prev,
      fips_mode: fipsMode==="enabled" ? "enabled" : "disabled"
    }));
  },[fipsMode]);

  const saveFipsConfig = useCallback(async()=>{
    const nextMode = String(systemState?.fips_mode||"disabled")==="enabled" ? "enabled" : "disabled";
    onFipsModeChange(nextMode);
    const ok = await saveSystemState();
    if(ok){
      setFipsConfigModalOpen(false);
    }
  },[onFipsModeChange,saveSystemState,systemState?.fips_mode]);

  const totalServices=Number(health.summary?.total||health.services?.length||0);
  const runtimeModeLabel=String(systemState?.fips_mode_policy||"standard")==="strict"?"Strict":"Standard";
  // Values the service did not report show as "not reported", never a guess.
  const runtimeTlsLabel=String(systemState?.fips_tls_profile||"not reported")
    .replace("tls13_only","TLS 1.3 only")
    .replace("tls1.2_fips","TLS 1.2+ FIPS");
  const runtimeRngLabel=systemState?.fips_rng_mode?String(systemState.fips_rng_mode).toUpperCase():"not reported";
  const entropySampleBytes=Math.max(0,Number(systemState?.fips_entropy_sample_bytes||0));
  const entropySampleMicros=Math.max(0,Number(systemState?.fips_entropy_read_micros||0));
  const runtimeAllOk = Number(health.summary?.degraded||0)===0 && Number(health.summary?.down||0)===0;
  // Runtime mode comes from the Go runtime (VECTA_FIPS_MODE at deploy time); never guess it.
  const fipsRuntimeMode = systemState?.fips_runtime_enforced===true ? "only (strict)" : systemState?.fips_runtime_enabled===true ? "on" : "off";
  const runtimeLibraryLine = `Module: ${String(systemState?.fips_crypto_library||"not reported")} | ${systemState?.fips_library_validated===true ? `certified Go Cryptographic Module ${String(systemState?.fips_module_version||"")} in FIPS mode` : "not running a validated module in FIPS mode"}`;
  // The certs root wrapping key as the certs service reports it; nothing is
  // assumed when it doesn't answer (rotation: docs/SECURITY/SECRET_ROTATION.md).
  const certSecuritySummary = certSecurityLoading
    ? "loading..."
    : !certSecurity
      ? "not reported"
      : `${String(certSecurity.storage_mode||"unknown")} / ${String(certSecurity.root_key_mode||"unknown")} / ${String(certSecurity.state||"unknown")}${certSecurity.key_version?` (${String(certSecurity.key_version)})`:""}${certSecurity.rotation_pending?" · passphrase rotation pending: CA signers being rewrapped":""}${certSecurity.last_error?` · ${String(certSecurity.last_error)}`:""}`;
  // The enforced policy: every service link is TLS 1.3 mTLS from the
  // internal-services Sub CA. Key exchange is set per service (hybrid ML-KEM
  // by default) under Certificates / PKI > Service mTLS (pkg/svctls).
  const tlsPolicyLabel = INTERNAL_TLS_POLICY;
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
  const smtpSummary = gov.smtp_connection_id ? "SMTP credential set"
    : String(gov.smtp_host||"").trim() ? `${String(gov.smtp_host)} (moving to Credentials)` : "SMTP not configured";
  const hardeningSummary = accessSettingsLoading
    ? "loading..."
    : `${String(accessSettings?.grant_default_type||"creator-default")} / replay ${Number(accessSettings?.replay_window_seconds||300)}s / interface ${Boolean(accessSettings?.interface_binding_required)?"required":"optional"}`;
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
    {panel==="health"&&<>
    <Section
      title="System Health"
      actions={<Btn small onClick={()=>void loadHealth()}>{healthLoading?"Refreshing...":"Refresh Health"}</Btn>}
    >
      <Card style={{padding:10,borderRadius:4}}>
        <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:8}}>
          <span style={{fontSize:11,color:C.blueFg,background:C.bg,border:`1px solid ${C.border}`,padding:"3px 8px",borderRadius:4}}>{`${totalServices} Total`}</span>
          <span style={{fontSize:11,color:C.greenFg,background:C.bg,border:`1px solid ${C.border}`,padding:"3px 8px",borderRadius:4}}>{`${Number(health.summary?.running||0)} Running`}</span>
          <span style={{fontSize:11,color:C.amberFg,background:C.bg,border:`1px solid ${C.border}`,padding:"3px 8px",borderRadius:4}}>{`${Number(health.summary?.degraded||0)} Degraded`}</span>
          <span style={{fontSize:11,color:C.redFg,background:C.bg,border:`1px solid ${C.border}`,padding:"3px 8px",borderRadius:4}}>{`${Number(health.summary?.down||0)} Down`}</span>
          <span style={{fontSize:11,color:C.blueFg,background:C.bg,border:`1px solid ${C.border}`,padding:"3px 8px",borderRadius:4}}>{`${Number(health.summary?.unknown||0)} Unknown`}</span>
          {totalServices>0 && <span style={{fontSize:11,color:runtimeAllOk?C.greenFg:C.amberFg,background:C.bg,border:`1px solid ${C.border}`,padding:"3px 8px",borderRadius:4,fontWeight:700}}>{runtimeAllOk?"ALL OK":"ATTN"}</span>}
        </div>
        <div style={{maxHeight:420,overflowY:"auto",paddingRight:2}}>
          {(health.services||[]).map((svc)=>{
            const name=String(svc?.name||"unknown");
            const status=String(svc?.status||"unknown");
            return <div key={name} style={{display:"grid",gridTemplateColumns:"1fr auto",gap:8,alignItems:"center",borderBottom:`1px solid ${C.border}`,padding:"7px 0"}}>
              <div style={{minWidth:0}}>
                <div style={{fontSize:11,color:C.text,fontWeight:700}}>{name}</div>
                <div style={{fontSize:10,color:C.dim,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}} title={String(svc?.output||svc?.source||"-")}>{String(svc?.output||svc?.source||"-")}</div>
              </div>
              <span style={{fontSize:11,color:C[tone(status)],textTransform:"capitalize",fontWeight:700,border:`1px solid ${C.border}`,background:C.bg,borderRadius:4,padding:"4px 10px"}}>
                <span className={`vecta-hb-dot ${heartbeatToneClass(status)}`} />
                {status}
              </span>
            </div>;
          })}
          {!(health.services||[]).length?<div style={{fontSize:10,color:C.muted,paddingTop:8}}>No health data available.</div>:null}
        </div>
        <div className="vk-fold" tabIndex={0} style={{fontSize:10,color:C.dim,marginTop:8}}>Each component is listed from service discovery or a successful connection to its port; one that is not deployed is not listed.</div>
      </Card>
    </Section>
    <Section title="Heartbeats & Watchdog">
      <Card style={{padding:10,borderRadius:4}}>
        <div className="vk-fold" tabIndex={0} style={{fontSize:10,color:C.dim,marginBottom:8}}>Liveness each service reports over NATS every 30s. The watchdog marks a service unhealthy after 90s of silence or a degraded report, and raises an audited incident. It alerts; it does not remediate.</div>
        <HealthListBody list={heartbeats} empty="No service has published a heartbeat yet.">
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(180px,1fr))",gap:6}}>
            {heartbeats.items.map((h)=>{
              const status=h.healthy?"running":h.state==="degraded"?"degraded":"down";
              return <div key={h.service} style={{border:`1px solid ${C.border}`,background:C.bg,borderRadius:4,padding:"6px 9px"}}>
                <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:6}}>
                  <span style={{fontSize:11,color:C.text,fontWeight:700}}>{h.service}</span>
                  <span style={{fontSize:10,color:C[tone(status)],fontWeight:700}}><span className={`vecta-hb-dot ${heartbeatToneClass(status)}`} />{h.healthy?"alive":"silent"}</span>
                </div>
                <div style={{fontSize:10,color:C.dim,marginTop:2}}>{`${h.state||"unknown"} · last seen ${h.silence_seconds}s ago`}</div>
              </div>;
            })}
          </div>
        </HealthListBody>
        <div style={{fontSize:11,color:C.text,fontWeight:700,margin:"12px 0 6px"}}>Recent incidents</div>
        <HealthListBody list={incidents} empty="No incidents in the rolling window.">
          <div style={{maxHeight:220,overflowY:"auto"}}>
            {incidents.items.slice(-20).reverse().map((i)=><div key={i.id} style={{display:"grid",gridTemplateColumns:"150px 110px 1fr",gap:8,borderBottom:`1px solid ${C.border}`,padding:"5px 0",fontSize:10}}>
              <span style={{color:C.dim}}>{new Date(i.timestamp).toLocaleString()}</span>
              <span style={{color:C.text,fontWeight:700}}>{i.service}</span>
              <span style={{color:C.text}}>{i.reason}{i.recommendation?<span style={{color:C.dim}}>{` · ${i.recommendation}`}</span>:null}</span>
            </div>)}
          </div>
        </HealthListBody>
      </Card>
    </Section>
    <Section title="Reconciler Controllers">
      <Card style={{padding:10,borderRadius:4}}>
        <div style={{fontSize:10,color:C.dim,marginBottom:8}}>Control loops that converge live state (tenants, key lifecycle, KMIP clients, quotas) to the declared manifest.</div>
        <HealthListBody list={reconcilers} empty="No reconciler controllers registered.">
          {reconcilers.items.map((r)=>{
            const status=r.last_error?"down":r.last_run_at?"running":"unknown";
            return <div key={r.name} style={{display:"grid",gridTemplateColumns:"1fr auto",gap:8,alignItems:"center",borderBottom:`1px solid ${C.border}`,padding:"6px 0"}}>
              <div style={{minWidth:0}}>
                <div style={{fontSize:11,color:C.text,fontWeight:700}}>{r.name}</div>
                <div style={{fontSize:10,color:r.last_error?C.redFg:C.dim,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}} title={r.last_error||""}>{r.last_error?`error: ${r.last_error}`:r.last_run_at?`last pass ${new Date(r.last_run_at).toLocaleString()}`:"not run yet"}</div>
              </div>
              <span style={{fontSize:10,color:C[tone(status)],fontWeight:700}}><span className={`vecta-hb-dot ${heartbeatToneClass(status)}`} />{r.last_error?"error":r.last_run_at?"ok":"pending"}</span>
            </div>;
          })}
        </HealthListBody>
      </Card>
    </Section>
    </>}

    {panel==="runtime"&&<>
    <Section
      title="Runtime Crypto Mode"
      actions={<div style={{display:"flex",gap:8}}>
        <Btn small onClick={()=>void loadSystemState()} disabled={systemStateLoading}>{systemStateLoading?"Refreshing...":"Refresh Mode"}</Btn>
        <Btn small onClick={()=>setFipsConfigModalOpen(true)}>Configure FIPS</Btn>
      </div>}
    >
      <Card style={{padding:10,borderRadius:4}}>
        <div style={{fontSize:11,color:C.dim,marginBottom:8}}>The tenant algorithm policy, and the TLS minimum and random-number generator this platform actually runs with.</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8}}>
          <div><span style={{fontSize:10,color:C.muted}}>Mode:</span><span style={{fontSize:13,color:C.text,fontWeight:700,marginLeft:4}}>{runtimeModeLabel}</span></div>
          <div style={{textAlign:"right"}}><span style={{fontSize:10,color:C.muted}}>TLS:</span><span style={{fontSize:13,color:C.text,fontWeight:700,marginLeft:4}}>{runtimeTlsLabel}</span></div>
          <div><span style={{fontSize:10,color:C.muted}}>RNG:</span><span style={{fontSize:13,color:C.text,fontWeight:700,marginLeft:4}}>{runtimeRngLabel}</span></div>
          <div style={{textAlign:"right"}}><span style={{fontSize:10,color:C.muted}}>RNG read:</span><span style={{fontSize:13,color:C.text,fontWeight:700,marginLeft:4}}>{String(systemState?.fips_entropy_health||"not reported")}</span></div>
        </div>
        <div style={{display:"flex",gap:8,flexWrap:"wrap",marginTop:8}}>
          <Btn small primary={fipsMode!=="enabled"} onClick={()=>{setSystemState((p)=>({...p,fips_mode:"enabled"}));onFipsModeChange("enabled");}}>Enable FIPS</Btn>
          <Btn small primary={fipsMode!=="disabled"} onClick={()=>{setSystemState((p)=>({...p,fips_mode:"disabled"}));onFipsModeChange("disabled");}}>Disable FIPS</Btn>
          <span style={{fontSize:11,color:C.greenFg,fontWeight:700,border:`1px solid ${C.border}`,background:C.bg,borderRadius:4,padding:"4px 9px",alignSelf:"center"}}>
            <span className={`vecta-hb-dot ${heartbeatToneClass(fipsMode==="enabled"?"running":"unknown")}`} />
            OK
          </span>
        </div>
        <div style={{display:"flex",gap:8,flexWrap:"wrap",marginTop:10}}>
          <B c="blue">{tlsPolicyLabel}</B>
        </div>
        <div style={{fontSize:10,color:C.dim,marginTop:8}}>{runtimeLibraryLine}</div>
      </Card>
    </Section>
    </>}

    <Modal open={fipsConfigModalOpen} onClose={()=>setFipsConfigModalOpen(false)} title="Configure FIPS Runtime">
      <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:10}}>
        <B c="blue">{runtimeModeLabel}</B>
        <B c="accent">{runtimeTlsLabel}</B>
        <B c={String(systemState?.fips_entropy_health||"").toLowerCase()==="ok"?"green":"amber"}>{`RNG read ${String(systemState?.fips_entropy_health||"not reported")}`}</B>
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
      <div className="vk-fold" tabIndex={0} style={{fontSize:10,color:C.dim,marginTop:6}}>TLS is 1.3 minimum on every platform listener; randomness is Go's crypto/rand (the certified module's CTR_DRBG in FIPS mode, otherwise the OS CSPRNG). Neither is a setting.</div>
      <div style={{
        display:"grid",
        gap:4,
        fontSize:10,
        color:C.dim,
        marginTop:8,
        padding:"10px 12px",
        border:`1px solid ${C.border}`,
        borderRadius:4,
        background:C.bg
      }}>
        <div>{`RNG: ${String(systemState?.fips_rng_mode||"not reported")} from ${String(systemState?.fips_entropy_source||"not reported")}; last read ${String(systemState?.fips_entropy_health||"not reported")}`}</div>
        <div>{`Sample: ${entropySampleBytes} bytes in ${entropySampleMicros} us`}</div>
        <div>{`This service runs FIPS mode: ${fipsRuntimeMode}`}</div>
        <div>{runtimeLibraryLine}</div>
        <div>{`Certs root wrapping key: ${certSecuritySummary}`}</div>
        <div>FIPS Policy above adds per-tenant algorithm rules on top of the platform mode below.</div>
      </div>
      <div style={{marginTop:8}}><FipsModePanel session={session} onToast={onToast}/></div>
      <div style={{fontSize:10,color:C.dim,marginTop:8}}>
        The key exchange the HTTPS edge and KMIP accept is set under Certificates / PKI &gt; Service mTLS.
      </div>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn small onClick={()=>setFipsConfigModalOpen(false)}>Cancel</Btn>
        <Btn small primary onClick={()=>void saveFipsConfig()} disabled={systemStateSaving}>{systemStateSaving?"Saving...":"Save FIPS"}</Btn>
      </div>
    </Modal>


    {panel==="snmp"&&<>
    <Section title="SNMP / SIEM Integration" actions={<div style={{display:"flex",gap:8}}>
      <Btn small onClick={()=>void loadSystemState()} disabled={systemStateLoading}>{systemStateLoading?"Refreshing...":"Refresh"}</Btn>
      <Btn small onClick={()=>void testSnmpSettings()} disabled={snmpTesting}>{snmpTesting?"Testing...":"Test SNMP"}</Btn>
      <Btn small primary onClick={()=>void saveSnmpSettings()} disabled={systemStateSaving}>{systemStateSaving?"Saving...":"Save SNMP"}</Btn>
    </div>}>
      <Card style={{padding:10,borderRadius:4}}>
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

    {panel==="tags"&&<>
    <Section title="Tags" actions={<Btn small onClick={()=>void loadTags()}>Refresh</Btn>}>
      <Card style={{padding:10,borderRadius:4}}>
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
                <span style={{fontSize:10,color:usageCount>0?C.amberFg:C.muted}}>
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
      <Card style={{padding:10,borderRadius:4}}>
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
      <Card style={{padding:10,borderRadius:4}}>
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
      <Btn small onClick={()=>void loadAccessHardening()} disabled={accessSettingsLoading}>{accessSettingsLoading?"Refreshing...":"Refresh"}</Btn>
      <Btn small primary onClick={()=>void saveAccessHardening()} disabled={accessSettingsSaving||!accessSettings}>{accessSettingsSaving?"Saving...":"Save"}</Btn>
    </div>}>
      <Card style={{padding:10,borderRadius:4}}>
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

    {panel==="platform"&&<>
    <Section title="Platform Hardening and Crypto" actions={<div style={{display:"flex",gap:6}}><Btn small onClick={()=>void loadSystemState()} disabled={systemStateLoading}>{systemStateLoading?"Refreshing...":"Refresh"}</Btn><Btn small primary onClick={()=>void saveSystemState()} disabled={systemStateLoading||systemStateSaving}>{systemStateSaving?"Saving...":"Save"}</Btn></div>}>
      <Row2>
        <Card style={{padding:10,borderRadius:4}}>
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
            <div>{`RNG: ${String(systemState?.fips_rng_mode||"not reported")}; last read ${String(systemState?.fips_entropy_health||"not reported")}`}</div>
            <div>{`Sample: ${Number(systemState?.fips_entropy_sample_bytes||0)} bytes in ${Number(systemState?.fips_entropy_read_micros||0)} us`}</div>
            <div>{`Runtime mode: ${fipsRuntimeMode} (change it in Runtime Crypto)`}</div>
            <div>{runtimeLibraryLine}</div>
          </div>
        </Card>

        <Card style={{padding:10,borderRadius:4}}>
          <div style={{fontSize:10,color:C.muted,marginBottom:8}}>KMS Rules / Platform Policy</div>
          <Chk label="Force quorum for destructive operations" checked={Boolean(systemState?.posture_force_quorum_destructive_ops)} onChange={()=>setSystemState((p)=>({...p,posture_force_quorum_destructive_ops:!p.posture_force_quorum_destructive_ops}))}/>
          <Chk label="Require step-up auth for risky operations" checked={Boolean(systemState?.posture_require_step_up_auth)} onChange={()=>setSystemState((p)=>({...p,posture_require_step_up_auth:!p.posture_require_step_up_auth}))}/>
          <Chk label="Pause connector sync when posture risk is high" checked={Boolean(systemState?.posture_pause_connector_sync)} onChange={()=>setSystemState((p)=>({...p,posture_pause_connector_sync:!p.posture_pause_connector_sync}))}/>
          <Chk label="Require guardrail policy for remediation actions" checked={Boolean(systemState?.posture_guardrail_policy_required)} onChange={()=>setSystemState((p)=>({...p,posture_guardrail_policy_required:!p.posture_guardrail_policy_required}))}/>
        </Card>
      </Row2>


      <Row2>
        <Card style={{padding:10,borderRadius:4}}>
          <div style={{fontSize:10,color:C.muted,marginBottom:8}}>TLS / Interface Governance</div>
          <div style={{display:"grid",gap:8}}>
            <div style={{fontSize:11,color:C.text,fontWeight:700}}>{tlsPolicyLabel}</div>
            <div className="vk-fold" tabIndex={0} style={{fontSize:10,color:C.dim}}>
              Listeners, ports and bind addresses are set by the deployment. Certificates and key exchange: Certificates / PKI &gt; Service mTLS.
            </div>
            <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
              <B c="blue">{tlsPolicyLabel}</B>
                </div>
          </div>
        </Card>

      </Row2>
    </Section>
    </>}

    {panel==="cli"&&<>
    <Section title="CLI / HSM Onboarding" actions={<Btn small onClick={()=>{void loadCli(); void loadHsm();}}>{cliLoading||hsmLoading?"Refreshing...":"Refresh"}</Btn>}>
      <Row2>
        <Card style={{padding:10,borderRadius:4}}>
          <div style={{fontSize:10,color:C.muted}}>CLI Status</div>
          <div style={{marginTop:6,display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}><span style={{color:C.text,fontSize:12,fontWeight:700}}>{cliStatus?.enabled?"Enabled":"Disabled"}</span><span style={{color:C.dim,fontSize:10}}>{`${String(cliStatus?.host||"127.0.0.1")}:${Number(cliStatus?.port||22)}`}</span><span style={{color:C.muted,fontSize:10}}>{String(cliStatus?.transport||"ssh")}</span></div>
          <FG label="CLI Username"><Inp value={cliUser} onChange={(e)=>setCliUser(e.target.value)}/></FG>
          <FG label="CLI Password"><Inp type="password" value={cliPass} onChange={(e)=>setCliPass(e.target.value)}/></FG>
          <div style={{display:"flex",justifyContent:"flex-end"}}><Btn small primary onClick={()=>void openCli()} disabled={cliOpening}>{cliOpening?"Opening...":"Open CLI Session"}</Btn></div>
          {String(cliSession||"").trim()?<div style={{marginTop:8,fontSize:10,color:C.muted}}>{`Session ID: ${cliSession}`}</div>:null}
          {String(cliSsh||"").trim()?<div style={{marginTop:4,fontSize:10,color:C.text,fontFamily:"var(--font-mono)"}}>{cliSsh}</div>:null}
        </Card>
        <Card style={{padding:10,borderRadius:4}}>
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
          <div style={{display:"grid",gap:8,marginTop:8}}>{slots.map((slot:CLIHSMPartitionSlot)=>{const key=`${String(slot.slot_id||"")}:${String(slot.partition||slot.token_label||slot.slot_name||"")}`; return <div key={key} style={{borderBottom:`1px solid ${C.border}`,paddingBottom:8}}><div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}><div><div style={{fontSize:12,color:C.text,fontWeight:700}}>{`${String(slot.slot_name||"slot")} (${String(slot.slot_id||"-")})`}</div><div style={{fontSize:10,color:C.dim}}>{`partition: ${String(slot.partition||"-")} | token: ${String(slot.token_label||"-")} | serial: ${String(slot.serial_number||"-")}`}</div></div><Btn small onClick={()=>setHsm((p)=>({...p,slot_id:String(slot.slot_id||""),partition_label:String(slot.partition||slot.slot_name||""),token_label:String(slot.token_label||slot.slot_name||"")}))}>Use</Btn></div></div>;})}{!slots.length?<div style={{fontSize:10,color:C.muted}}>No partitions loaded yet.</div>:null}{String(slotRaw||"").trim()?<div style={{fontSize: 10,color:C.muted,fontFamily:"var(--font-mono)",whiteSpace:"pre-wrap"}}>{slotRaw}</div>:null}</div>
        </Card>
      </Row2>
    </Section>
    </>}

    {panel==="governance"&&<>
    <Section title="Governance Delivery" actions={<Btn small primary onClick={async()=>{if(!session?.token) return; setGovSaving(true); try{await updateGovernanceSettings(session,{...gov,approval_expiry_minutes:Math.max(1,Math.trunc(Number(gov.approval_expiry_minutes||60))),expiry_check_interval_seconds:Math.max(5,Math.trunc(Number(gov.expiry_check_interval_seconds||60))),delivery_webhook_timeout_seconds:Math.max(2,Math.trunc(Number(gov.delivery_webhook_timeout_seconds||10)))}); onToast("Governance delivery settings updated."); await loadGov();}catch(error){if(!sessionGuard(error)) onToast(`Governance settings save failed: ${errMsg(error)}`);} finally{setGovSaving(false);}}} disabled={govLoading||govSaving}>{govSaving?"Saving...":"Save"}</Btn>}>
      <Row2><FG label="Approval Expiry (minutes)"><Inp type="number" value={String(gov.approval_expiry_minutes)} onChange={(e)=>setGov((p)=>({...p,approval_expiry_minutes:Math.max(1,Number(e.target.value||60))}))}/></FG><FG label="Expiry Check Interval (seconds)"><Inp type="number" value={String(gov.expiry_check_interval_seconds)} onChange={(e)=>setGov((p)=>({...p,expiry_check_interval_seconds:Math.max(5,Number(e.target.value||60))}))}/></FG></Row2>
      <Row2><FG label="Delivery Mode"><Sel value={String(gov.approval_delivery_mode||"kms_only")} onChange={(e)=>setGov((p)=>({...p,approval_delivery_mode:String(e.target.value||"kms_only")}))}><option value="kms_only">KMS only</option><option value="notify">Notify + KMS queue</option></Sel></FG><FG label="Webhook Timeout (seconds)"><Inp type="number" value={String(gov.delivery_webhook_timeout_seconds)} onChange={(e)=>setGov((p)=>({...p,delivery_webhook_timeout_seconds:Math.max(2,Number(e.target.value||10))}))}/></FG></Row2>
      <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8}}><Chk label="Dashboard approvals" checked={Boolean(gov.notify_dashboard)} onChange={()=>setGov((p)=>({...p,notify_dashboard:!p.notify_dashboard}))}/><Chk label="Email notifications" checked={Boolean(gov.notify_email)} onChange={()=>setGov((p)=>({...p,notify_email:!p.notify_email}))}/><Chk label="Slack notifications" checked={Boolean(gov.notify_slack)} onChange={()=>setGov((p)=>({...p,notify_slack:!p.notify_slack}))}/><Chk label="Teams notifications" checked={Boolean(gov.notify_teams)} onChange={()=>setGov((p)=>({...p,notify_teams:!p.notify_teams}))}/></div>
      <FG label="Mail relay (SMTP credential)" hint={!gov.smtp_connection_id&&gov.smtp_host?`Now using ${String(gov.smtp_host)}, stored here by an earlier release; it is moved into Credentials automatically.`:"Mail is always sent over TLS."}><CredentialPicker session={session} type="smtp" value={String(gov.smtp_connection_id||"")} onChange={(id:string)=>setGov((p)=>({...p,smtp_connection_id:id}))}/></FG>
      <Row2><FG label="SMTP Test Recipient"><div style={{display:"flex",gap:8}}><Inp value={smtpTo} onChange={(e)=>setSmtpTo(e.target.value)} placeholder="admin@domain.tld"/><Btn small onClick={async()=>{if(!session?.token||!String(smtpTo||"").trim()){onToast("Provide SMTP test recipient email."); return;} setSmtpTesting(true); try{await testGovernanceSMTP(session,String(smtpTo||"").trim()); onToast("SMTP test sent.");}catch(error){if(!sessionGuard(error)) onToast(`SMTP test failed: ${errMsg(error)}`);} finally{setSmtpTesting(false);}}} disabled={smtpTesting}>{smtpTesting?"Testing...":"Send"}</Btn></div></FG></Row2>
      {govConnsErr&&<div style={{fontSize:11,color:C.redFg,marginBottom:8}}>Connections unavailable: {govConnsErr}</div>}
      {([["slack","Slack","slack_connection_id"],["teams","Teams","teams_connection_id"]] as const).map(([ch,label,field])=>(
        <FG key={ch} label={`${label} connection`} hint="Approval notices go through this connection; its webhook URL is sealed under Playbooks → Connections"><div style={{display:"flex",gap:8}}>
          <Sel value={String((gov as any)[field]||"")} onChange={(e)=>setGov((p)=>({...p,[field]:e.target.value}))}>
            <option value="">{(govConns||[]).some((c)=>c.type===ch)?"none":`no ${label} connection: add one under Playbooks → Connections`}</option>
            {(govConns||[]).filter((c)=>c.type===ch).map((c)=><option key={c.id} value={c.id}>{c.name} ({c.endpoint})</option>)}
          </Sel>
          <Btn small onClick={async()=>{if(!session?.token) return; setWebhookTesting((p)=>({...p,[ch]:true})); try{await testGovernanceWebhook(session,ch); onToast(`${label} test sent through the saved connection.`);}catch(error){if(!sessionGuard(error)) onToast(`${label} test failed: ${errMsg(error)}`);} finally{setWebhookTesting((p)=>({...p,[ch]:false}));}}} disabled={(webhookTesting as any)[ch]}>{(webhookTesting as any)[ch]?"Testing...":"Test"}</Btn>
        </div></FG>
      ))}
    </Section>
    </>}

    {panel==="alertrules"&&<>
    <Section title={<>{`Alert Rules`}<span style={{fontWeight:400,fontSize:11,color:C.muted,marginLeft:8}}>{alertRulesLoading?"loading...": `${alertRules.length} rule${alertRules.length!==1?"s":""}`}</span></>} actions={<div style={{display:"flex",gap:6}}><Btn small onClick={()=>void refreshAlertRules()} disabled={alertRulesLoading}>{alertRulesLoading?"Refreshing...":"Refresh"}</Btn><Btn small primary onClick={()=>openRuleModal()}>Create Rule</Btn></div>}>
      {alertRules.map((rule)=>{const id=String(rule.id||""); const cond=String(rule.condition||"threshold"); return <Card key={id} style={{padding:10,borderRadius:4,marginBottom:8}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start"}}>
          <div style={{minWidth:0,flex:1}}>
            <div style={{fontSize:13,color:C.text,fontWeight:700}}>{rule.name||"Unnamed Rule"}</div>
            <div style={{fontSize:10,color:C.dim,marginTop:2}}>
              {cond==="expression"
                ?<span>Expression: <span style={{fontFamily:"var(--font-mono)",color:C.text}}>{rule.expression||"-"}</span></span>
                :<span>Pattern: <span style={{fontFamily:"var(--font-mono)",color:C.text}}>{rule.event_pattern||"*"}</span> | Threshold: {rule.threshold||1} in {rule.window_seconds||300}s</span>}
            </div>
            <div style={{display:"flex",gap:8,marginTop:4,fontSize:10}}>
              <span style={{color:rule.severity==="critical"?C.redFg:rule.severity==="high"?C.orangeFg:rule.severity==="warning"?C.amberFg:C.blueFg}}>{rule.severity||"warning"}</span>
              <span style={{color:C.muted}}>channels: {(rule.channels||[]).join(", ")||"none"}</span>
              <span style={{color:rule.enabled!==false?C.greenFg:C.muted}}>{rule.enabled!==false?"enabled":"disabled"}</span>
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
        <FG label="Event Pattern (glob)"><Inp value={rulePattern} onChange={(e)=>setRulePattern(e.target.value)} placeholder="e.g. audit.auth.login_failed or audit.key.*"/></FG>
        <Row2>
          <FG label="Threshold (count)"><Inp type="number" value={String(ruleThreshold)} onChange={(e)=>setRuleThreshold(Math.max(1,Number(e.target.value||1)))}/></FG>
          <FG label="Window (seconds)"><Inp type="number" value={String(ruleWindowSeconds)} onChange={(e)=>setRuleWindowSeconds(Math.max(1,Number(e.target.value||300)))}/></FG>
        </Row2>
      </>}
      {ruleCondition==="expression"&&<>
        <FG label="Expression">
          <Inp value={ruleExpression} onChange={(e)=>setRuleExpression(e.target.value)} placeholder={'e.g. action == "audit.key.export" AND actor_id != "backup-svc"'}/>
        </FG>
        <div style={{fontSize: 10,color:C.muted,marginTop:4,lineHeight:1.5,fontFamily:"var(--font-mono)"}}>
          <div><B>Fields:</B> action, severity, actor_id, source_ip, service, target_type, target_id</div>
          <div><B>Operators:</B> == != contains startsWith matches</div>
          <div><B>Combinators:</B> AND OR ( )</div>
          <div style={{marginTop:4}}><B>Examples:</B></div>
          <div>action == "audit.key.export" AND severity != "info"</div>
          <div>action startsWith "audit.auth." AND source_ip contains "203.0.113."</div>
          <div>(service == "keycore" OR service == "hsm") AND actor_id != "backup-svc"</div>
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
      <div style={{border:`1px solid ${C.border}`,borderRadius:4,padding:10,marginTop:8}}>
        <div style={{display:"flex",alignItems:"center",gap:8,flexWrap:"wrap"}}>
          <span style={{fontSize:11,color:C.dim}}>Test against the audit events of the last</span>
          <Sel value={String(ruleReplayHours)} onChange={(e)=>setRuleReplayHours(Number(e.target.value))} style={{width:110}}>
            {[1,24,72,168].map((h)=><option key={h} value={h}>{h===1?"1 hour":h<48?`${h} hours`:`${h/24} days`}</option>)}
          </Sel>
          <Btn small onClick={()=>void handleTestRule()} disabled={ruleChecking}>{ruleChecking?"Testing...":"Test rule"}</Btn>
        </div>
        {ruleCheck&&(!ruleCheck.valid
          ?<div style={{fontSize:11,color:C.redFg,marginTop:8}}>Not valid: {ruleCheck.error}</div>
          :ruleCheck.replay_error
            ?<div style={{fontSize:11,color:C.amberFg,marginTop:8}}>Valid. Replay not assessed: {ruleCheck.replay_error}</div>
            :ruleCheck.replay&&<div style={{fontSize:11,color:C.text,marginTop:8,lineHeight:1.6}}>
              <div>Valid. Over {ruleCheck.replay.events_scanned} audit events{ruleCheck.replay.truncated?` (only since ${new Date(ruleCheck.replay.from).toLocaleString()}: the audit service returned its maximum)`:""}: <B>{ruleCheck.replay.matched}</B> matched, the rule would have fired <B>{ruleCheck.replay.fired}</B> time{ruleCheck.replay.fired===1?"":"s"}.</div>
              {ruleCheck.replay.samples.map((s)=><div key={s.event_id} style={{fontFamily:"var(--font-mono)",fontSize:10,color:C.dim}}>{new Date(s.timestamp).toLocaleString()} · {s.action} · {s.actor_id||"—"}</div>)}
              <div style={{fontSize:10,color:C.muted,marginTop:4}}>{ruleCheck.replay.basis}.</div>
            </div>)}
      </div>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn small onClick={()=>setRuleModalOpen(false)}>Cancel</Btn>
        <Btn small primary onClick={()=>void handleSaveRule()} disabled={ruleSaving}>{ruleSaving?"Saving...":(editingRule?"Update Rule":"Create Rule")}</Btn>
      </div>
    </Modal>
    </>}


    {promptDialog.ui}
  </div>;
};
