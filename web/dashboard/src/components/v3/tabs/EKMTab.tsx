// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { useEffect, useMemo, useRef, useState } from "react";
import { LayoutGrid, List, MoreVertical, RefreshCcw } from "lucide-react";
import { B, Btn, Card, Chk, FG, Inp, Modal, Row2, Sel, usePromptDialog } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
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
  listEKMDatabases,
  registerEKMDatabase,
  queueBitLockerOperation,
  registerBitLockerClient,
  registerEKMAgent,
  scanBitLockerWindows,
  rotateEKMAgentKey,
  revokeDatabaseTDE,
  validateAgentDeployment,
  listAzureEKMConfigs,
  createAzureEKMConfig,
  deleteAzureEKMConfig,
  testAzureConnection,
  syncAzureKeys,
  listAzureKeyMappings,
  createAzureKeyMapping,
  deleteAzureKeyMapping,
  importKeyToAzure,
  rotateAzureKey,
  wrapAzureKey,
  unwrapAzureKey,
  listGoogleCSEConfigs,
  createGoogleCSEConfig,
  deleteGoogleCSEConfig,
  listGoogleCSEKeys,
  createGoogleCSEKey,
  deleteGoogleCSEKey
} from "../../../lib/ekm";
import type { AzureEKMConfig, AzureKeyMapping } from "../../../lib/ekm";
import { KMIPTab } from "./KMIPTab";

/* ── Setup guide content per DB engine ── */
const SETUP_GUIDES: Record<string, { title: string; steps: string[] }> = {
  mssql: {
    title: "SQL Server TDE with Vecta EKM",
    steps: [
      "1. Register an EKM agent from this dashboard (Deploy Agent button).",
      "2. Download the deploy package (agent.env + install script + heartbeat script).",
      "3. Copy files to the SQL Server host and run the install script as administrator.",
      "4. In SQL Server, enable EKM:\n   sp_configure 'EKM provider enabled', 1;\n   RECONFIGURE;",
      "5. Create an EKM provider pointing to the Vecta PKCS#11 module:\n   CREATE CRYPTOGRAPHIC PROVIDER VectaEKM FROM FILE = 'C:\\vecta-ekm\\libvecta-pkcs11.dll';",
      "6. Create a credential mapped to the Vecta agent:\n   CREATE CREDENTIAL VectaCred WITH IDENTITY = '<agent_id>', SECRET = '<auth_token>';",
      "7. Create an asymmetric key from the EKM provider:\n   CREATE ASYMMETRIC KEY TDE_Key FROM PROVIDER VectaEKM WITH ALGORITHM = RSA_2048;",
      "8. Create a database encryption key and enable TDE:\n   USE <database>;\n   CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 ENCRYPTION BY SERVER ASYMMETRIC KEY TDE_Key;\n   ALTER DATABASE <database> SET ENCRYPTION ON;",
      "9. Verify TDE status: SELECT * FROM sys.dm_database_encryption_keys;",
      "10. Schedule key rotation via the dashboard or automate with cron/Task Scheduler."
    ]
  },
  oracle: {
    title: "Oracle TDE with Vecta EKM",
    steps: [
      "1. Register an EKM agent from this dashboard (Deploy Agent button).",
      "2. Download the deploy package and deploy on the Oracle DB host.",
      "3. Configure Oracle wallet location in sqlnet.ora:\n   ENCRYPTION_WALLET_LOCATION = (SOURCE = (METHOD = HSM))",
      "4. Configure the PKCS#11 library in the Oracle environment:\n   export ORACLE_PKCS11_LIB=/etc/vecta-ekm/libvecta-pkcs11.so",
      "5. Open the TDE keystore:\n   ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY \"HSM\";",
      "6. Set the TDE master encryption key:\n   ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY \"HSM\" WITH BACKUP;",
      "7. Enable TDE on tablespace or column level:\n   ALTER TABLESPACE users ENCRYPTION ONLINE ENCRYPT;",
      "8. Verify: SELECT * FROM V$ENCRYPTION_WALLET;",
      "9. Schedule key rotation via the dashboard Rotate button.",
      "10. Monitor agent health and TDE state from the dashboard."
    ]
  },
  postgresql: {
    title: "PostgreSQL TDE with Vecta EKM (pg_tde)",
    steps: [
      "1. Register an EKM agent from this dashboard (Deploy Agent button).",
      "2. Download the deploy package and deploy on the PostgreSQL host.",
      "3. Install the pg_tde extension:\n   CREATE EXTENSION pg_tde;",
      "4. Configure the PKCS#11 provider in postgresql.conf:\n   pg_tde.keyring_provider = 'pkcs11'\n   pg_tde.pkcs11_library = '/etc/vecta-ekm/libvecta-pkcs11.so'",
      "5. Set the TDE master key:\n   SELECT pg_tde_set_master_key('vecta-master-key', 'pkcs11');",
      "6. Enable encryption on a table:\n   CREATE TABLE sensitive_data (...) USING tde_heap;",
      "7. Or enable TDE on an existing tablespace:\n   ALTER TABLESPACE pg_default SET (tde = on);",
      "8. Verify status:\n   SELECT * FROM pg_tde_master_key_info();",
      "9. Rotate the master key via the dashboard or:\n   SELECT pg_tde_rotate_master_key('vecta-new-key', 'pkcs11');",
      "10. Monitor agent health and TDE state from the dashboard."
    ]
  },
  mysql: {
    title: "MySQL / MariaDB TDE with Vecta EKM (keyring_pkcs11)",
    steps: [
      "1. Register an EKM agent from this dashboard (Deploy Agent button).",
      "2. Download the deploy package and deploy on the MySQL/MariaDB host.",
      "3. Install the keyring_pkcs11 plugin in my.cnf:\n   [mysqld]\n   early-plugin-load=keyring_pkcs11=keyring_pkcs11.so\n   keyring_pkcs11_lib_path=/etc/vecta-ekm/libvecta-pkcs11.so",
      "4. Restart MySQL to load the plugin:\n   systemctl restart mysqld",
      "5. Verify keyring plugin is active:\n   SELECT PLUGIN_NAME, PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME='keyring_pkcs11';",
      "6. Enable encryption on an InnoDB tablespace:\n   ALTER TABLE sensitive_data ENCRYPTION='Y';",
      "7. Enable general tablespace encryption:\n   CREATE TABLESPACE ts_encrypted ADD DATAFILE 'ts_encrypted.ibd' ENCRYPTION='Y';",
      "8. Enable redo/undo log encryption (MySQL 8.0+):\n   SET GLOBAL innodb_redo_log_encrypt = ON;\n   SET GLOBAL innodb_undo_log_encrypt = ON;",
      "9. Verify encryption status:\n   SELECT NAME, ENCRYPTION FROM INFORMATION_SCHEMA.INNODB_TABLESPACES WHERE ENCRYPTION='Y';",
      "10. Rotate master key:\n   ALTER INSTANCE ROTATE INNODB MASTER KEY;"
    ]
  },
  db2: {
    title: "IBM DB2 TDE with Vecta EKM",
    steps: [
      "1. Register an EKM agent from this dashboard (Deploy Agent button).",
      "2. Download the deploy package and deploy on the DB2 host.",
      "3. Configure the keystore in the DB2 instance:\n   gsk8capicmd_64 -keydb -create -db /etc/vecta-ekm/db2keystore.kdb -pw <password> -type pkcs12",
      "4. Set the PKCS#11 library path:\n   db2 UPDATE DBM CFG USING KEYSTORE_TYPE PKCS11\n   db2 UPDATE DBM CFG USING KEYSTORE_LOCATION /etc/vecta-ekm/libvecta-pkcs11.so",
      "5. Create an encrypted database:\n   db2 CREATE DATABASE mydb ENCRYPT",
      "6. Or enable encryption on an existing database:\n   db2 ALTER DATABASE mydb ENCRYPT",
      "7. Set the master key label:\n   db2 \"CALL SYSPROC.ADMIN_ROTATE_MASTER_KEY('vecta-master-key')\"",
      "8. Verify encryption status:\n   db2 \"SELECT * FROM TABLE(SYSPROC.ADMIN_GET_ENCRYPTION_INFO())\"",
      "9. Rotate the master key via the dashboard or:\n   db2 \"CALL SYSPROC.ADMIN_ROTATE_MASTER_KEY('vecta-new-key')\"",
      "10. Monitor agent health and TDE state from the dashboard."
    ]
  }
};

export const EKMTab=({session,onToast,subView,onSubViewChange}:any)=>{
  const [loading,setLoading]=useState(false);
  const [agents,setAgents]=useState([]);
  const [statusByID,setStatusByID]=useState({});
  const [healthByID,setHealthByID]=useState({});
  const [keyMetaByID,setKeyMetaByID]=useState({});
  const [databases,setDatabases]=useState([]);
  const [modal,setModal]=useState(null);
  const [selectedAgent,setSelectedAgent]=useState(null);
  const [logs,setLogs]=useState([]);
  const [logsLoading,setLogsLoading]=useState(false);
  const [deploying,setDeploying]=useState(false);
  const [rotatingAgentID,setRotatingAgentID]=useState("");
  const [deletingAgentID,setDeletingAgentID]=useState("");
  const [deployPackage,setDeployPackage]=useState(null);
  const [deployForm,setDeployForm]=useState({
    name:"",
    db_engine:"mssql",
    host:"",
    version:"",
    target_os:"linux",
    heartbeat_interval_sec:30,
    rotation_cycle_days:90
  });
  const [expandedAgent,setExpandedAgent]=useState("");
  const [guideEngine,setGuideEngine]=useState("mssql");
  const [dbRegForm,setDbRegForm]=useState({ agent_id:"", name:"", engine:"mssql", host:"", port:1433, database_name:"", rotation_policy:"90" });
  const [dbRegistering,setDbRegistering]=useState(false);
  const [revokingDbId,setRevokingDbId]=useState("");
  const [deployModalTab,setDeployModalTab]=useState<"download"|"guide"|"verify">("download");
  const [verifyingAgentId,setVerifyingAgentId]=useState("");
  const [verifyResult,setVerifyResult]=useState<any>(null);
  const [expandedTdeGuide,setExpandedTdeGuide]=useState<Record<string,boolean>>({});
  const [agentLogsPanel,setAgentLogsPanel]=useState<Record<string,any[]>>({});
  const [agentLogsPanelLoading,setAgentLogsPanelLoading]=useState("");

  /* ── BitLocker state ── */
  const [bitLockerClients,setBitLockerClients]=useState([]);
  const [bitLockerDeployPackage,setBitLockerDeployPackage]=useState(null);
  const [bitLockerDeploying,setBitLockerDeploying]=useState(false);
  const [bitLockerOpClientID,setBitLockerOpClientID]=useState("");
  const [bitLockerDeletingClientID,setBitLockerDeletingClientID]=useState("");
  const [bitLockerJobs,setBitLockerJobs]=useState([]);
  const [bitLockerRecovery,setBitLockerRecovery]=useState([]);
  const [bitLockerLoadingDetail,setBitLockerLoadingDetail]=useState(false);
  const [bitLockerDeleteTarget,setBitLockerDeleteTarget]=useState(null);
  const [bitLockerDeletePreview,setBitLockerDeletePreview]=useState(null);
  const [bitLockerDeleteLoading,setBitLockerDeleteLoading]=useState(false);
  const [bitLockerDeleteSubmitting,setBitLockerDeleteSubmitting]=useState(false);
  const [bitLockerDeleteConfirmBackup,setBitLockerDeleteConfirmBackup]=useState(false);
  const [bitLockerForm,setBitLockerForm]=useState({
    name:"",
    host:"",
    os_version:"Windows 11 / Server 2022",
    mount_point:"C:",
    heartbeat_interval_sec:30
  });
  const [bitLockerScanForm,setBitLockerScanForm]=useState({
    ip_range:"",
    max_hosts:256,
    concurrency:32,
    port_timeout_ms:350,
    require_winrm:true
  });
  const [bitLockerScanRunning,setBitLockerScanRunning]=useState(false);
  const [bitLockerScanResult,setBitLockerScanResult]=useState<any>(null);
  const [bitLockerScanCandidates,setBitLockerScanCandidates]=useState<any[]>([]);
  const [bitLockerScanSelected,setBitLockerScanSelected]=useState<Record<string,boolean>>({});
  const [bitLockerOnboarding,setBitLockerOnboarding]=useState(false);
  const [dbView,setDbView]=useState<"cards"|"list">("cards");
  const [bitLockerView,setBitLockerView]=useState<"cards"|"list">("cards");
  const [dbSearch,setDbSearch]=useState("");
  const [bitLockerSearch,setBitLockerSearch]=useState("");
  const [dbMenu,setDbMenu]=useState("");
  const deployingRef=useRef(false);
  const promptDialog=usePromptDialog();

  /* ── Azure EKM state ── */
  const [azureConfigs,setAzureConfigs]=useState<AzureEKMConfig[]>([]);
  const [azureMappings,setAzureMappings]=useState<AzureKeyMapping[]>([]);
  const [azureLoading,setAzureLoading]=useState(false);
  const [azureConfigForm,setAzureConfigForm]=useState({
    azure_tenant_id:"", subscription_id:"", resource_group:"", vault_name:"", vault_url:"",
    managed_hsm_name:"", managed_hsm_url:"", client_id:"", client_secret:"", auth_mode:"client_secret"
  });
  const [azureMappingForm,setAzureMappingForm]=useState({ config_id:"", vecta_key_id:"", azure_key_name:"", purpose:"tde" });
  const [azureTestResults,setAzureTestResults]=useState<Record<string,{connected:boolean;error?:string}>>({});
  const [azureSyncing,setAzureSyncing]=useState("");
  const [azureOpLoading,setAzureOpLoading]=useState("");

  /* ── Google CSE state ── */
  const [googleCSEConfigs,setGoogleCSEConfigs]=useState<any[]>([]);
  const [googleCSEKeys,setGoogleCSEKeys]=useState<any[]>([]);
  const [googleCSELoading,setGoogleCSELoading]=useState(false);
  const [googleCSEConfigForm,setGoogleCSEConfigForm]=useState({
    google_workspace_customer_id:"", service_account_email:"", service_account_key_json:"",
    allowed_domains:"", kacls_endpoint:""
  });
  const [googleCSEKeyForm,setGoogleCSEKeyForm]=useState({ config_id:"", key_name:"", vecta_key_id:"", purpose:"drive" });
  const [googleCSEOpLoading,setGoogleCSEOpLoading]=useState("");

  /* ── Helpers ── */
  const formatAgo=(value:any)=>{
    const ts=new Date(String(value||"")).getTime();
    if(!Number.isFinite(ts)) return "n/a";
    const diff=Math.max(0,Date.now()-ts);
    const sec=Math.floor(diff/1000);
    if(sec<60) return `${sec}s ago`;
    const min=Math.floor(sec/60);
    if(min<60) return `${min}m ago`;
    const hr=Math.floor(min/60);
    if(hr<24) return `${hr}h ago`;
    const day=Math.floor(hr/24);
    return `${day}d ago`;
  };

  const parseAgentMeta=(agent)=>{
    try{ return JSON.parse(String(agent?.metadata_json||"{}")); }catch{ return {}; }
  };

  const rotationDaysFor=(agent)=>{
    const meta=parseAgentMeta(agent);
    const n=Number(meta?.rotation_cycle_days||90);
    return Number.isFinite(n)&&n>0?Math.trunc(n):90;
  };

  const normalizeAgentIDPart=(value,maxLen)=>{
    const normalized=String(value||"").trim().toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-+|-+$/g,"");
    return normalized.slice(0,Math.max(4,Math.trunc(Number(maxLen)||16)))||"na";
  };

  const deriveEKMAgentID=(name,dbEngine,host)=>{
    return `agent-${normalizeAgentIDPart(dbEngine,12)}-${normalizeAgentIDPart(host,40)}-${normalizeAgentIDPart(name,24)}`.slice(0,96);
  };

  const visibleDeployFiles=useMemo(()=>{
    const pkg=deployPackage;
    if(!pkg) return [];
    const target=String(pkg.target_os||"").toLowerCase();
    const files=Array.isArray(pkg.files)?pkg.files:[];
    if(target==="linux") return files.filter((f)=>!String(f?.path||"").toLowerCase().endsWith(".ps1"));
    if(target==="windows") return files.filter((f)=>!String(f?.path||"").toLowerCase().endsWith(".sh"));
    return files;
  },[deployPackage]);

  const safeFileName=(name)=>String(name||"file").replace(/[^a-zA-Z0-9._-]/g,"_");
  const downloadText=(name,content)=>{
    const blob=new Blob([String(content||"")],{type:"text/plain;charset=utf-8"});
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url;a.download=safeFileName(name);document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);
  };

  /* ── Summary stats (computed) ── */
  const dbStats=useMemo(()=>{
    const total=agents.length;
    let active=0,degraded=0,down=0,tdeEnabled=0,managedDBs=0;
    for(const agent of agents){
      const h=String(healthByID[agent.id]?.health||"").toLowerCase();
      const s=String(agent.status||"").toLowerCase();
      if(h==="down"||s==="disconnected") down++;
      else if(h==="degraded"||s==="degraded") degraded++;
      else active++;
      const st=statusByID[agent.id];
      if(st){
        managedDBs+=Number(st.managed_databases||0);
        tdeEnabled+=Number(st.tde_enabled_databases||0);
      }
    }
    return {total,active,degraded,down,managedDBs,tdeEnabled};
  },[agents,healthByID,statusByID]);

  const blStats=useMemo(()=>{
    const total=bitLockerClients.length;
    let protected_=0,suspended=0,down=0,tpmReady=0;
    for(const c of bitLockerClients){
      const ps=String(c.protection_status||"").toLowerCase();
      const st=String(c.status||"").toLowerCase();
      if(st==="disconnected"||String(c.health||"").toLowerCase()==="down") down++;
      else if(ps==="protected"||ps==="on") protected_++;
      else suspended++;
      if(c.tpm_present&&c.tpm_ready) tpmReady++;
    }
    return {total,protected:protected_,suspended,down,tpmReady};
  },[bitLockerClients]);

  /* ── Rotation compliance ── */
  const rotationCompliance=(agent)=>{
    const keyID=String(agent?.assigned_key_id||"").trim();
    if(!keyID) return {label:"No key",color:C.textDim,daysSince:0,policyDays:90};
    const meta=parseAgentMeta(agent);
    const policyDays=rotationDaysFor(agent);
    const lastRotated=agent.updated_at||agent.created_at||"";
    const ts=new Date(String(lastRotated||"")).getTime();
    if(!Number.isFinite(ts)) return {label:"Unknown",color:C.textDim,daysSince:0,policyDays};
    const daysSince=Math.floor((Date.now()-ts)/(86400000));
    if(daysSince<=policyDays*0.7) return {label:`${daysSince}d / ${policyDays}d`,color:C.green,daysSince,policyDays};
    if(daysSince<=policyDays) return {label:`${daysSince}d / ${policyDays}d`,color:C.amber,daysSince,policyDays};
    return {label:`${daysSince}d / ${policyDays}d (overdue)`,color:C.red,daysSince,policyDays};
  };

  /* ── Database status badge ── */
  const dbStatusBadge=(db:any)=>{
    const state=String(db?.tde_state||"").toLowerCase();
    if(state==="key_revoked") return {label:"Key Revoked",bg:C.redDim,fg:C.red};
    if(state==="error") return {label:"Error",bg:C.amberDim,fg:C.amber};
    if(state==="tde_enabled"||db?.tde_enabled) return {label:"TDE Enabled",bg:C.greenDim,fg:C.green};
    if(state==="tde_disabled") return {label:"TDE Disabled",bg:"transparent",fg:C.muted};
    if(state==="registered") return {label:"Registered",bg:C.blueDim,fg:C.blue};
    return {label:state||"Unknown",bg:"transparent",fg:C.muted};
  };

  /* ── Rotation compliance for database ── */
  const dbRotationCompliance=(db:any)=>{
    const meta=(() => { try { return JSON.parse(String(db?.metadata_json||"{}")); } catch { return {}; } })();
    const policyStr=String(meta?.rotation_policy_days||"0");
    const policyDays=Number(policyStr);
    if(!policyDays||policyDays<=0) return {label:"No policy",color:C.textDim,policyDays:0};
    const lastRotated=db.updated_at||db.created_at||"";
    const ts=new Date(String(lastRotated||"")).getTime();
    if(!Number.isFinite(ts)) return {label:"Unknown",color:C.textDim,policyDays};
    const daysSince=Math.floor((Date.now()-ts)/86400000);
    if(daysSince<=policyDays*0.7) return {label:`${daysSince}d / ${policyDays}d`,color:C.green,policyDays};
    if(daysSince<=policyDays) return {label:`${daysSince}d / ${policyDays}d`,color:C.amber,policyDays};
    return {label:`${daysSince}d / ${policyDays}d (overdue)`,color:C.red,policyDays};
  };

  /* ── Revoke TDE for database ── */
  const runRevokeTDE=async(db:any)=>{
    const dbId=String(db?.id||"").trim();
    if(!dbId) return;
    const confirmed=await promptDialog.confirm({
      title:"Revoke TDE Key",
      message:`WARNING: This will revoke the TDE encryption key for database "${db.name}".\n\nThe database will become inaccessible until a new key is provisioned. This action should only be performed in emergency situations (e.g., suspected key compromise).\n\nAre you sure you want to proceed?`,
      confirmLabel:"Revoke TDE Key",
      danger:true
    });
    if(!confirmed) return;
    setRevokingDbId(dbId);
    try{
      await revokeDatabaseTDE(session,dbId);
      onToast?.(`TDE key revoked for database "${db.name}". Database is now locked.`);
      await refresh(true);
    }catch(e){ onToast?.(`Revoke failed: ${errMsg(e)}`); }finally{ setRevokingDbId(""); }
  };

  /* ── Load key access logs for an agent ── */
  const loadAgentKeyAccessLogs=async(agentId:string)=>{
    if(agentLogsPanelLoading===agentId) return;
    setAgentLogsPanelLoading(agentId);
    try{
      const items=await listEKMAgentLogs(session,agentId,20);
      setAgentLogsPanel(prev=>({...prev,[agentId]:items}));
    }catch(e){ onToast?.(`Failed to load key access logs: ${errMsg(e)}`); }finally{ setAgentLogsPanelLoading(""); }
  };

  /* ── Data fetching ── */
  const refresh=async(silent=false)=>{
    if(!silent) setLoading(true);
    try{
      const items=await listEKMAgents(session);
      setAgents(items);
      const statuses={};
      const healthMap={};
      await Promise.all(items.map(async(agent)=>{
        try{ statuses[agent.id]=await getEKMAgentStatus(session,agent.id); }catch{ statuses[agent.id]={status:"unknown"}; }
        try{ healthMap[agent.id]=await getEKMAgentHealth(session,agent.id); }catch{ healthMap[agent.id]={}; }
      }));
      setStatusByID(statuses);
      setHealthByID(healthMap);
      try{ const dbItems=await listEKMDatabases(session); setDatabases(Array.isArray(dbItems)?dbItems:[]); }catch{ setDatabases([]); }
      try{ const blItems=await listBitLockerClients(session,1000); setBitLockerClients(Array.isArray(blItems)?blItems:[]); }catch{ setBitLockerClients([]); }
      try{ const azCfgs=await listAzureEKMConfigs(session); setAzureConfigs(Array.isArray(azCfgs)?azCfgs:[]); }catch{ setAzureConfigs([]); }
      try{ const azMaps=await listAzureKeyMappings(session); setAzureMappings(Array.isArray(azMaps)?azMaps:[]); }catch{ setAzureMappings([]); }
      try{ const gcseC=await listGoogleCSEConfigs(session); setGoogleCSEConfigs(Array.isArray(gcseC)?gcseC:[]); }catch{ setGoogleCSEConfigs([]); }
      try{ const gcseK=await listGoogleCSEKeys(session); setGoogleCSEKeys(Array.isArray(gcseK)?gcseK:[]); }catch{ setGoogleCSEKeys([]); }
      const keyIDs=[...new Set(items.map((a)=>String(a.assigned_key_id||"").trim()).filter(Boolean))];
      const keyMeta={};
      await Promise.all(keyIDs.map(async(keyID)=>{
        try{ keyMeta[keyID]=await getEKMTDEPublicKey(session,keyID); }catch{ keyMeta[keyID]={algorithm:"",key_version:""}; }
      }));
      setKeyMetaByID(keyMeta);
    }catch(error){
      onToast?.(`EKM load failed: ${errMsg(error)}`);
    }finally{
      if(!silent) setLoading(false);
    }
  };

  useEffect(()=>{
    let stop=false;
    const run=async(silent=false)=>{ if(!stop) await refresh(silent); };
    void run(false);
    const id=setInterval(()=>{void run(true);},15000);
    return()=>{ stop=true; clearInterval(id); };
  // eslint-disable-next-line react-hooks/exhaustive-deps -- grandfathered; effect deps to be audited as a follow-up
  },[session?.token,session?.tenantId]);

  /* ── Agent actions ── */
  const openLogs=async(agent)=>{
    setSelectedAgent(agent);setModal("logs");setLogs([]);setLogsLoading(true);
    try{ const items=await listEKMAgentLogs(session,agent.id,60); setLogs(items); }catch(e){ onToast?.(`Agent logs failed: ${errMsg(e)}`); }finally{ setLogsLoading(false); }
  };

  const openHealthDetail=(agent)=>{
    setSelectedAgent(agent);
    setModal("health-detail");
  };

  const runRotate=async(agent)=>{
    if(!String(agent?.assigned_key_id||"").trim()){ onToast?.("No TDE key assigned to this agent."); return; }
    const rc=rotationCompliance(agent);
    const confirmed=await promptDialog.confirm({
      title:"Rotate TDE Key",
      message:`Rotate the TDE master key for agent "${agent.name}"?\n\nCurrent rotation: ${rc.label}\nPolicy: every ${rc.policyDays} days\n\nThis will generate a new key version in KeyCore and notify all affected agents. You must also run the DB-side TDE key re-encryption per your engine's procedure.`,
      confirmLabel:"Rotate Key",
      danger:false
    });
    if(!confirmed) return;
    setRotatingAgentID(agent.id);
    try{
      await rotateEKMAgentKey(session,agent.id,"manual-dashboard");
      onToast?.(`TDE key rotation queued for ${agent.name}. Run DB-side TDE key switch per engine policy.`);
      await refresh(true);
    }catch(e){ onToast?.(`Rotate failed: ${errMsg(e)}`); }finally{ setRotatingAgentID(""); }
  };

  const runDelete=async(agent)=>{
    const agentID=String(agent?.id||"").trim();
    const agentName=String(agent?.name||agentID).trim();
    if(!agentID){ onToast?.("Invalid agent id."); return; }
    const agentDBs=databases.filter(d=>d.agent_id===agentID);
    const confirmed=await promptDialog.confirm({
      title:"Delete EKM Agent",
      message:`Delete agent "${agentName}"?\n\nThis will permanently remove:\n- The agent registration\n- ${agentDBs.length} linked database(s)\n- All linked TDE keys (destroyed in KeyCore)\n- All key access logs\n\nThis action cannot be undone.`,
      confirmLabel:"Delete Agent",
      danger:true
    });
    if(!confirmed) return;
    setDeletingAgentID(agentID);
    try{
      const out=await deleteEKMAgent(session,agentID,"manual-dashboard-delete");
      onToast?.(`Agent deleted: ${Number(out?.deleted_databases||0)} DBs, ${Number(out?.deleted_keys||0)} keys, ${Number(out?.deleted_logs||0)} logs removed.`);
      if(selectedAgent&&String(selectedAgent.id||"")===agentID){ setModal(null); setSelectedAgent(null); }
      await refresh(true);
    }catch(e){ onToast?.(`Delete failed: ${errMsg(e)}`); }finally{ setDeletingAgentID(""); }
  };

  /* ── Deploy agent ── */
  const submitDeploy=async()=>{
    if(deployingRef.current||deploying) return;
    const name=String(deployForm.name||"").trim();
    const host=String(deployForm.host||"").trim();
    if(!name||!host){ onToast?.("Agent name and host are required."); return; }
    deployingRef.current=true; setDeploying(true);
    try{
      const metadataJSON=JSON.stringify({
        target_os:deployForm.target_os,
        rotation_cycle_days:Math.max(1,Math.trunc(Number(deployForm.rotation_cycle_days||90))),
        pkcs11_profile:`${deployForm.db_engine}-tde-pkcs11`,
        deployed_from:"dashboard"
      });
      const agent=await registerEKMAgent(session,{
        agent_id:deriveEKMAgentID(name,deployForm.db_engine,host),
        name,db_engine:deployForm.db_engine,host,
        version:String(deployForm.version||"").trim(),
        heartbeat_interval_sec:Math.max(5,Math.trunc(Number(deployForm.heartbeat_interval_sec||30))),
        metadata_json:metadataJSON,auto_provision_tde:true
      });
      const pkg=await getEKMDeployPackage(session,agent.id,deployForm.target_os);
      setDeployPackage(pkg);
      onToast?.(`Agent ${agent.name} registered. Download package files and deploy on ${deployForm.target_os}.`);
      await refresh(true);
    }catch(e){ onToast?.(`Deploy failed: ${errMsg(e)}`); }finally{ deployingRef.current=false; setDeploying(false); }
  };

  const openDeploy=()=>{
    deployingRef.current=false; setDeployPackage(null);
    setDeployForm({name:"",db_engine:"mssql",host:"",version:"",target_os:"linux",heartbeat_interval_sec:30,rotation_cycle_days:90});
    setDeployModalTab("download"); setVerifyResult(null);
    setModal("deploy");
  };

  /* ── Register database ── */
  const openDbRegister=()=>{
    setDbRegForm({agent_id:agents.length?agents[0].id:"",name:"",engine:"mssql",host:"",port:1433,database_name:"",rotation_policy:"90"});
    setModal("db-register");
  };

  const submitDbRegister=async()=>{
    const agentId=String(dbRegForm.agent_id||"").trim();
    const name=String(dbRegForm.name||"").trim();
    if(!agentId||!name){ onToast?.("Agent and database name are required."); return; }
    setDbRegistering(true);
    try{
      // Default port by engine
      const defaultPorts:Record<string,number>={mssql:1433,oracle:1521,postgresql:5432,mysql:3306,db2:50000};
      const port=Number(dbRegForm.port)||defaultPorts[dbRegForm.engine]||1433;
      await registerEKMDatabase(session,{
        agent_id:agentId, name, engine:dbRegForm.engine,
        host:String(dbRegForm.host||"").trim(),
        port,
        database_name:String(dbRegForm.database_name||"").trim(),
        tde_enabled:true, auto_provision_key:true
      });
      onToast?.(`Database "${name}" registered and TDE key auto-provisioned.`);
      setModal(null); await refresh(true);
    }catch(e){ onToast?.(`Register DB failed: ${errMsg(e)}`); }finally{ setDbRegistering(false); }
  };

  /* ── BitLocker actions ── */
  const openBitLockerDeploy=()=>{
    setBitLockerDeployPackage(null);
    setBitLockerForm({name:"",host:"",os_version:"Windows 11 / Server 2022",mount_point:"C:",heartbeat_interval_sec:30});
    setModal("bitlocker-deploy");
  };

  const submitBitLockerDeploy=async()=>{
    const name=String(bitLockerForm.name||"").trim();
    const host=String(bitLockerForm.host||"").trim();
    if(!name||!host){ onToast?.("BitLocker client name and host are required."); return; }
    const normalizedHost=host.toLowerCase();
    const normalizedName=name.toLowerCase();
    const duplicate=(bitLockerClients||[]).find((row:any)=>{
      const rh=String(row?.host||"").trim().toLowerCase();
      const rn=String(row?.name||"").trim().toLowerCase();
      return (rh!==""&&rh===normalizedHost)||(rn!==""&&rn===normalizedName);
    });
    if(duplicate){ onToast?.(`BitLocker client already exists (${duplicate?.name}). Duplicate host/name not allowed.`); return; }
    setBitLockerDeploying(true);
    try{
      const client=await registerBitLockerClient(session,{
        name,host,os_version:String(bitLockerForm.os_version||"windows").trim(),
        mount_point:String(bitLockerForm.mount_point||"C:").trim()||"C:",
        heartbeat_interval_sec:Math.max(5,Math.trunc(Number(bitLockerForm.heartbeat_interval_sec||30))),
        metadata_json:JSON.stringify({managed_by:"vecta-ekm",feature:"bitlocker"})
      });
      const pkg=await getBitLockerDeployPackage(session,client.id,"windows");
      setBitLockerDeployPackage(pkg);
      onToast?.(`BitLocker client ${client.name} registered. Download package and deploy.`);
      await refresh(true);
    }catch(e){ onToast?.(`BitLocker deploy failed: ${errMsg(e)}`); }finally{ setBitLockerDeploying(false); }
  };

  const runBitLockerOperation=async(client,operation)=>{
    const clientID=String(client?.id||"").trim();
    if(!clientID) return;
    setBitLockerOpClientID(`${clientID}:${operation}`);
    try{
      await queueBitLockerOperation(session,clientID,operation,{mount_point:String(client?.mount_point||"C:").trim()||"C:"});
      onToast?.(`BitLocker operation queued: ${operation} (${client.name}).`);
      await refresh(true);
    }catch(e){ onToast?.(`BitLocker operation failed: ${errMsg(e)}`); }finally{ setBitLockerOpClientID(""); }
  };

  const openBitLockerDelete=async(client)=>{
    const clientID=String(client?.id||"").trim();
    if(!clientID){ onToast?.("Invalid BitLocker client."); return; }
    setBitLockerDeleteTarget(client);setBitLockerDeletePreview(null);setBitLockerDeleteConfirmBackup(false);setBitLockerDeleteLoading(true);setModal("bitlocker-delete");
    try{ const preview=await getBitLockerDeletePreview(session,clientID); setBitLockerDeletePreview(preview||null); }catch(e){ onToast?.(`Delete preview failed: ${errMsg(e)}`); }finally{ setBitLockerDeleteLoading(false); }
  };

  const submitBitLockerDelete=async()=>{
    const target=bitLockerDeleteTarget;
    const clientID=String(target?.id||"").trim();
    if(!clientID){ onToast?.("Invalid BitLocker client."); return; }
    if(!bitLockerDeleteConfirmBackup){ onToast?.("Please confirm backup of recovery key before deleting."); return; }
    setBitLockerDeleteSubmitting(true);setBitLockerDeletingClientID(clientID);
    try{
      const out=await deleteBitLockerClient(session,clientID,{reason:"manual-dashboard-delete",confirm_backup:true});
      onToast?.(`BitLocker client deleted: jobs ${Number(out?.deleted_jobs||0)}, recovery ${Number(out?.deleted_recovery_keys||0)}.`);
      if(selectedAgent&&String(selectedAgent?.id||"")===clientID) setSelectedAgent(null);
      setModal(null);setBitLockerDeleteTarget(null);setBitLockerDeletePreview(null);
      await refresh(true);
    }catch(e){ onToast?.(`Delete failed: ${errMsg(e)}`); }finally{ setBitLockerDeleteSubmitting(false);setBitLockerDeletingClientID(""); }
  };

  const openBitLockerScan=()=>{
    setBitLockerScanResult(null);setBitLockerScanCandidates([]);setBitLockerScanSelected({});setModal("bitlocker-scan");
  };

  const runBitLockerScan=async()=>{
    const range=String(bitLockerScanForm.ip_range||"").trim();
    if(!range){ onToast?.("IP range is required."); return; }
    setBitLockerScanRunning(true);
    try{
      const scan=await scanBitLockerWindows(session,{
        ip_range:range,max_hosts:Number(bitLockerScanForm.max_hosts||256),
        concurrency:Number(bitLockerScanForm.concurrency||32),
        port_timeout_ms:Number(bitLockerScanForm.port_timeout_ms||350),
        require_winrm:Boolean(bitLockerScanForm.require_winrm)
      });
      setBitLockerScanResult(scan||null);
      setBitLockerScanCandidates(Array.isArray(scan?.candidates)?scan.candidates:[]);
      setBitLockerScanSelected({});
      onToast?.(`Scan complete: ${Number(scan?.windows_hosts||0)} Windows hosts found.`);
    }catch(e){ onToast?.(`Network scan failed: ${errMsg(e)}`); }finally{ setBitLockerScanRunning(false); }
  };

  const toggleBitLockerCandidate=(ip:string)=>{
    const key=String(ip||"").trim();
    if(!key) return;
    setBitLockerScanSelected((prev)=>({...prev,[key]:!Boolean(prev?.[key])}));
  };

  const onboardScannedBitLocker=async()=>{
    const selectedIPs=Object.entries(bitLockerScanSelected||{}).filter(([,v])=>Boolean(v)).map(([k])=>String(k).trim()).filter(Boolean);
    if(!selectedIPs.length){ onToast?.("Select at least one Windows host to onboard."); return; }
    const byIP=new Map((bitLockerScanCandidates||[]).map((row:any)=>[String(row?.ip||"").trim(),row]));
    const existingHosts=new Set((bitLockerClients||[]).map((r:any)=>String(r?.host||"").trim().toLowerCase()).filter(Boolean));
    const existingNames=new Set((bitLockerClients||[]).map((r:any)=>String(r?.name||"").trim().toLowerCase()).filter(Boolean));
    setBitLockerOnboarding(true);
    let created=0,skipped=0,failed=0;
    for(const ip of selectedIPs){
      const row:any=byIP.get(ip);
      if(!row){ skipped++; continue; }
      const host=String(row?.host||ip).trim();
      if(existingHosts.has(host.toLowerCase())||existingHosts.has(ip.toLowerCase())){ skipped++; continue; }
      const baseName=String(host||ip).split(".")[0].replace(/[^a-zA-Z0-9_-]/g,"-");
      const suggestedName=(baseName||`WIN-${ip.replace(/\./g,"-")}`).slice(0,48);
      if(existingNames.has(suggestedName.toLowerCase())){ skipped++; continue; }
      try{
        await registerBitLockerClient(session,{
          client_id:`scan-${ip.replace(/[^0-9]/g,"-")}`,name:suggestedName,host:ip,
          os_version:String(row?.os_guess||"Windows (discovered)"),mount_point:"C:",heartbeat_interval_sec:30,
          metadata_json:JSON.stringify({managed_by:"vecta-ekm",source:"network-scan",scan_confidence:String(row?.confidence||""),scan_ports_open:Array.isArray(row?.ports_open)?row.ports_open:[]})
        });
        existingHosts.add(ip.toLowerCase());existingNames.add(suggestedName.toLowerCase());created++;
      }catch{ failed++; }
    }
    setBitLockerOnboarding(false);
    onToast?.(`Onboard complete: added ${created}, skipped ${skipped}, failed ${failed}.`);
    if(created>0) await refresh(true);
  };

  const openBitLockerActivity=async(client)=>{
    const clientID=String(client?.id||"").trim();
    if(!clientID) return;
    let selected=client;
    try{ selected=await getBitLockerClient(session,clientID); }catch { /* ignored */ }
    setSelectedAgent(selected);setModal("bitlocker-activity");setBitLockerJobs([]);setBitLockerRecovery([]);setBitLockerLoadingDetail(true);
    try{
      const [jobs,recovery]=await Promise.all([listBitLockerJobs(session,clientID,80),listBitLockerRecoveryKeys(session,clientID,80)]);
      setBitLockerJobs(Array.isArray(jobs)?jobs:[]);setBitLockerRecovery(Array.isArray(recovery)?recovery:[]);
    }catch(e){ onToast?.(`BitLocker activity load failed: ${errMsg(e)}`); }finally{ setBitLockerLoadingDetail(false); }
  };

  const openBitLockerOptions=(client)=>{ setSelectedAgent(client||null); setModal("bitlocker-options"); };

  /* ── Status badges ── */
  const statusBadge=(agent)=>{
    const health=String(healthByID[agent.id]?.health||"").toLowerCase();
    const baseStatus=String(agent.status||"").toLowerCase();
    const tdeState=String(agent.tde_state||"").toLowerCase();
    if(health==="down"||baseStatus==="disconnected") return {label:"Down",bg:C.redDim,fg:C.red};
    if(health==="degraded"||baseStatus==="degraded") return {label:"Degraded",bg:C.amberDim,fg:C.amber};
    if(tdeState==="enabled") return {label:"Active",bg:C.greenDim,fg:C.green};
    if(baseStatus==="connected") return {label:"Standby",bg:C.blueDim,fg:C.blue};
    return {label:"Unknown",bg:"transparent",fg:C.muted};
  };

  const bitLockerStatusBadge=(client)=>{
    const protection=String(client?.protection_status||"").toLowerCase();
    const health=String(client?.health||"").toLowerCase();
    const status=String(client?.status||"").toLowerCase();
    if(health==="down"||status==="disconnected") return {label:"Down",bg:C.redDim,fg:C.red};
    if(protection==="protected"||protection==="on") return {label:"Protected",bg:C.greenDim,fg:C.green};
    if(protection==="suspended"||health==="degraded") return {label:"Suspended",bg:C.amberDim,fg:C.amber};
    return {label:"Unknown",bg:"transparent",fg:C.muted};
  };

  /* ── Filtered lists ── */
  const filteredAgents=useMemo(()=>{
    if(!dbSearch.trim()) return agents;
    const q=dbSearch.trim().toLowerCase();
    return agents.filter((a)=>String(a.name||"").toLowerCase().includes(q)||String(a.host||"").toLowerCase().includes(q)||String(a.db_engine||"").toLowerCase().includes(q)||String(a.id||"").toLowerCase().includes(q));
  },[agents,dbSearch]);

  const filteredBitLocker=useMemo(()=>{
    if(!bitLockerSearch.trim()) return bitLockerClients;
    const q=bitLockerSearch.trim().toLowerCase();
    return bitLockerClients.filter((c)=>String(c.name||"").toLowerCase().includes(q)||String(c.host||"").toLowerCase().includes(q)||String(c.id||"").toLowerCase().includes(q));
  },[bitLockerClients,bitLockerSearch]);

  /* ──────────── RENDER ──────────── */
  return (<div>
    {/* ═══════════════════════ DB SUBTAB ═══════════════════════ */}
    {subView==="db"&&(<div>
      {/* ── Summary stats bar ── */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(150px,1fr))",gap:10,marginBottom:16}}>
        {[
          {label:"Total Agents",value:dbStats.total},
          {label:"Active",value:dbStats.active,color:C.green},
          {label:"Degraded",value:dbStats.degraded,color:C.amber},
          {label:"Down",value:dbStats.down,color:C.red},
          {label:"Managed DBs",value:dbStats.managedDBs},
          {label:"TDE Enabled",value:dbStats.tdeEnabled,color:C.green}
        ].map((s,i)=>(<Card key={i}><div style={{textAlign:"center"}}><div style={{fontSize:22,fontWeight:700,color:s.color||C.text}}>{s.value}</div><div style={{fontSize:11,color:C.textDim}}>{s.label}</div></div></Card>))}
      </div>

      {/* ── Toolbar ── */}
      <div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap",alignItems:"center"}}>
        <Inp placeholder="Search agents..." value={dbSearch} onChange={(e)=>setDbSearch(e.target.value)} style={{flex:1,minWidth:180,maxWidth:320}}/>
        <Btn onClick={()=>setDbView(dbView==="cards"?"list":"cards")} style={{padding:"6px 10px"}}>{dbView==="cards"?<List size={15}/>:<LayoutGrid size={15}/>}</Btn>
        <Btn onClick={openDeploy}>Deploy Agent</Btn>
        <Btn onClick={openDbRegister}>Register Database</Btn>
        <Btn onClick={()=>setModal("setup-guide")}>Setup Guide</Btn>
        <Btn onClick={()=>refresh(false)} disabled={loading}><RefreshCcw size={14} style={loading?{animation:"spin 1s linear infinite"}:{}}/></Btn>
      </div>

      {loading&&!agents.length?(<div style={{color:C.textDim,padding:20,textAlign:"center",fontSize:12}}>Loading agents...</div>):(
        filteredAgents.length===0?(<Card><div style={{textAlign:"center",color:C.textDim,padding:32,fontSize:12}}>No EKM agents registered.{" "}<span style={{color:C.accent,cursor:"pointer"}} onClick={openDeploy}>Deploy your first agent</span></div></Card>):(
          dbView==="cards"?(
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(320px,1fr))",gap:12}}>
              {filteredAgents.map((agent)=>{
                const badge=statusBadge(agent);
                const st=statusByID[agent.id]||{};
                const h=healthByID[agent.id]||{};
                const km=keyMetaByID[String(agent.assigned_key_id||"").trim()];
                const rc=rotationCompliance(agent);
                const meta=parseAgentMeta(agent);
                const agentDBs=databases.filter(d=>d.agent_id===agent.id);
                return (<Card key={agent.id} style={{position:"relative"}}>
                  {/* Menu button */}
                  <div style={{position:"absolute",top:8,right:8,cursor:"pointer",color:C.textDim}} onClick={(e)=>{e.stopPropagation();setDbMenu(dbMenu===agent.id?"":agent.id);}}>
                    <MoreVertical size={16}/>
                    {dbMenu===agent.id&&(<div style={{position:"absolute",right:0,top:20,background:C.surface,border:"1px solid "+C.border,borderRadius:6,padding:4,zIndex:10,minWidth:140}} onClick={(e)=>e.stopPropagation()}>
                      <div style={{padding:"5px 10px",cursor:"pointer",fontSize:12}} onClick={()=>{setDbMenu("");openLogs(agent);}}>View Logs</div>
                      <div style={{padding:"5px 10px",cursor:"pointer",fontSize:12}} onClick={()=>{setDbMenu("");openHealthDetail(agent);}}>Health Details</div>
                      <div style={{padding:"5px 10px",cursor:"pointer",fontSize:12}} onClick={()=>{setDbMenu("");runRotate(agent);}}>Rotate Key</div>
                      <div style={{padding:"5px 10px",cursor:"pointer",fontSize:12,color:C.red}} onClick={()=>{setDbMenu("");runDelete(agent);}}>Delete</div>
                    </div>)}
                  </div>

                  <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
                    <span style={{padding:"2px 8px",borderRadius:4,fontSize:11,fontWeight:600,background:badge.bg,color:badge.fg}}>{badge.label}</span>
                    <B style={{fontSize:14}}>{agent.name}</B>
                  </div>
                  <div style={{fontSize:12,color:C.textDim,marginBottom:4}}>{agent.host} | {String(agent.db_engine||"").toUpperCase()} | {agent.role}</div>
                  <div style={{fontSize:12,color:C.textDim,marginBottom:4}}>Heartbeat: {formatAgo(agent.last_heartbeat_at)}</div>

                  {/* TDE Key info */}
                  {agent.assigned_key_id&&(<div style={{fontSize:12,marginBottom:4}}>
                    <span style={{color:C.textDim}}>TDE Key: </span>
                    <span style={{fontFamily:"monospace",fontSize:11}}>{String(agent.assigned_key_id).slice(0,20)}</span>
                    {km&&(<span style={{color:C.textDim}}> ({km.algorithm} {km.key_version})</span>)}
                  </div>)}

                  {/* Rotation compliance */}
                  <div style={{fontSize:12,marginBottom:4}}>
                    <span style={{color:C.textDim}}>Rotation: </span>
                    <span style={{color:rc.color,fontWeight:500}}>{rc.label}</span>
                  </div>

                  {/* Databases under this agent */}
                  {agentDBs.length>0&&(<div style={{fontSize:11,color:C.textDim,marginTop:4}}>
                    Databases: {agentDBs.map(d=>d.name).join(", ")}
                  </div>)}

                  {/* Health metrics summary */}
                  {h?.metrics&&(<div style={{display:"flex",gap:12,marginTop:8,fontSize:11,color:C.textDim}}>
                    {h.metrics.cpu_usage_pct>0&&(<span>CPU {h.metrics.cpu_usage_pct.toFixed(0)}%</span>)}
                    {h.metrics.memory_usage_pct>0&&(<span>MEM {h.metrics.memory_usage_pct.toFixed(0)}%</span>)}
                    {h.metrics.disk_usage_pct>0&&(<span>DISK {h.metrics.disk_usage_pct.toFixed(0)}%</span>)}
                  </div>)}

                  {/* Actions */}
                  <div style={{display:"flex",gap:6,marginTop:10,flexWrap:"wrap"}}>
                    <Btn onClick={()=>runRotate(agent)} disabled={rotatingAgentID===agent.id||!agent.assigned_key_id} style={{fontSize:11,padding:"3px 8px"}}>{rotatingAgentID===agent.id?"Rotating...":"Rotate Key"}</Btn>
                    <Btn onClick={()=>openLogs(agent)} style={{fontSize:11,padding:"3px 8px"}}>Logs</Btn>
                    <Btn onClick={()=>openHealthDetail(agent)} style={{fontSize:11,padding:"3px 8px"}}>Health</Btn>
                  </div>
                </Card>);
              })}
            </div>
          ):(
            /* ── List view ── */
            <div style={{border:"1px solid "+C.border,borderRadius:8,overflow:"hidden"}}>
              <div style={{display:"grid",gridTemplateColumns:"2fr 1fr 1fr 1fr 1fr 1.5fr 120px",padding:"8px 12px",background:C.surface,fontSize:11,fontWeight:600,color:C.textDim,borderBottom:"1px solid "+C.border}}>
                <span>Agent</span><span>Engine</span><span>Status</span><span>Heartbeat</span><span>DBs</span><span>Rotation</span><span>Actions</span>
              </div>
              {filteredAgents.map((agent)=>{
                const badge=statusBadge(agent);
                const st=statusByID[agent.id]||{};
                const rc=rotationCompliance(agent);
                const isExpanded=expandedAgent===agent.id;
                const h=healthByID[agent.id]||{};
                const agentDBs=databases.filter(d=>d.agent_id===agent.id);
                return (<div key={agent.id}>
                  <div style={{display:"grid",gridTemplateColumns:"2fr 1fr 1fr 1fr 1fr 1.5fr 120px",padding:"8px 12px",fontSize:12,borderBottom:"1px solid "+C.border,cursor:"pointer",background:isExpanded?C.surface+"88":"transparent"}} onClick={()=>setExpandedAgent(isExpanded?"":agent.id)}>
                    <span><B>{agent.name}</B><br/><span style={{fontSize:11,color:C.textDim}}>{agent.host}</span></span>
                    <span>{String(agent.db_engine||"").toUpperCase()}</span>
                    <span><span style={{padding:"2px 6px",borderRadius:4,fontSize:10,fontWeight:600,background:badge.bg,color:badge.fg}}>{badge.label}</span></span>
                    <span style={{color:C.textDim}}>{formatAgo(agent.last_heartbeat_at)}</span>
                    <span>{Number(st.managed_databases||0)} ({Number(st.tde_enabled_databases||0)} TDE)</span>
                    <span style={{color:rc.color,fontWeight:500,fontSize:11}}>{rc.label}</span>
                    <span style={{display:"flex",gap:4}}>
                      <Btn onClick={(e)=>{e.stopPropagation();runRotate(agent);}} disabled={rotatingAgentID===agent.id||!agent.assigned_key_id} style={{fontSize:10,padding:"2px 6px"}}>Rotate</Btn>
                      <Btn onClick={(e)=>{e.stopPropagation();openLogs(agent);}} style={{fontSize:10,padding:"2px 6px"}}>Logs</Btn>
                    </span>
                  </div>
                  {/* Expanded detail */}
                  {isExpanded&&(<div style={{padding:"12px 16px",background:C.surface+"44",borderBottom:"1px solid "+C.border,fontSize:12}}>
                    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:12}}>
                      <div>
                        <div style={{fontWeight:600,marginBottom:4}}>Agent Details</div>
                        <div style={{color:C.textDim}}>ID: <span style={{fontFamily:"monospace"}}>{agent.id}</span></div>
                        <div style={{color:C.textDim}}>Role: {agent.role}</div>
                        <div style={{color:C.textDim}}>Version: {agent.version||"n/a"}</div>
                        <div style={{color:C.textDim}}>Config v{agent.config_version} (ack: {agent.config_version_ack})</div>
                      </div>
                      <div>
                        <div style={{fontWeight:600,marginBottom:4}}>TDE Key</div>
                        {agent.assigned_key_id?(<>
                          <div style={{color:C.textDim}}>Key ID: <span style={{fontFamily:"monospace",fontSize:11}}>{agent.assigned_key_id}</span></div>
                          <div style={{color:C.textDim}}>Version: {agent.assigned_key_version||"v1"}</div>
                          {keyMetaByID[agent.assigned_key_id]&&(<div style={{color:C.textDim}}>Algorithm: {keyMetaByID[agent.assigned_key_id].algorithm}</div>)}
                        </>):(<div style={{color:C.textDim}}>No key assigned</div>)}
                      </div>
                      <div>
                        <div style={{fontWeight:600,marginBottom:4}}>Health</div>
                        {h?.metrics?(<>
                          <div style={{color:C.textDim}}>Hostname: {h.metrics.hostname||"n/a"}</div>
                          <div style={{color:C.textDim}}>OS: {h.metrics.os_name} {h.metrics.os_version}</div>
                          <div style={{color:C.textDim}}>CPU: {h.metrics.cpu_usage_pct?.toFixed(1)}% | MEM: {h.metrics.memory_usage_pct?.toFixed(1)}% | DISK: {h.metrics.disk_usage_pct?.toFixed(1)}%</div>
                        </>):(<div style={{color:C.textDim}}>No metrics</div>)}
                        {Array.isArray(h?.warnings)&&h.warnings.length>0&&(<div style={{color:C.amber,marginTop:4}}>{h.warnings.join("; ")}</div>)}
                      </div>
                    </div>
                    {agentDBs.length>0&&(<div style={{marginTop:8}}>
                      <div style={{fontWeight:600,marginBottom:4}}>Managed Databases ({agentDBs.length})</div>
                      {agentDBs.map(db=>(<div key={db.id} style={{fontSize:11,color:C.textDim,padding:"2px 0"}}>
                        {db.name} ({db.engine.toUpperCase()}) on {db.host}:{db.port} - TDE: <span style={{color:db.tde_enabled?C.green:C.red,fontWeight:500}}>{db.tde_state||"unknown"}</span>
                      </div>))}
                    </div>)}
                    <div style={{display:"flex",gap:6,marginTop:8}}>
                      <Btn onClick={()=>openHealthDetail(agent)} style={{fontSize:11,padding:"3px 8px"}}>Full Health</Btn>
                      <Btn onClick={()=>runDelete(agent)} disabled={deletingAgentID===agent.id} style={{fontSize:11,padding:"3px 8px",color:C.red}}>{deletingAgentID===agent.id?"Deleting...":"Delete"}</Btn>
                    </div>
                  </div>)}
                </div>);
              })}
            </div>
          )
        )
      )}

      {/* ── Database Inventory section ── */}
      {databases.length>0&&(<div style={{marginTop:20}}>
        <B style={{fontSize:14,marginBottom:8,display:"block"}}>Database Inventory ({databases.length})</B>
        <div style={{border:"1px solid "+C.border,borderRadius:8,overflow:"hidden"}}>
          <div style={{display:"grid",gridTemplateColumns:"2fr 1fr 1fr 1fr 1fr 1fr 1fr 100px",padding:"8px 12px",background:C.surface,fontSize:11,fontWeight:600,color:C.textDim,borderBottom:"1px solid "+C.border}}>
            <span>Database</span><span>Engine</span><span>Agent</span><span>Host</span><span>TDE State</span><span>Rotation</span><span>Last Seen</span><span>Actions</span>
          </div>
          {databases.map(db=>{
            const badge=dbStatusBadge(db);
            const rotComp=dbRotationCompliance(db);
            return (<div key={db.id}>
              <div style={{display:"grid",gridTemplateColumns:"2fr 1fr 1fr 1fr 1fr 1fr 1fr 100px",padding:"8px 12px",fontSize:12,borderBottom:"1px solid "+C.border,alignItems:"center"}}>
                <span><B>{db.name}</B>{db.database_name&&db.database_name!==db.name&&(<span style={{color:C.textDim,fontSize:11}}> ({db.database_name})</span>)}</span>
                <span>{db.engine.toUpperCase()}</span>
                <span style={{fontSize:11,color:C.textDim}}>{agents.find(a=>a.id===db.agent_id)?.name||db.agent_id}</span>
                <span style={{color:C.textDim}}>{db.host}{db.port>0?`:${db.port}`:""}</span>
                <span><span style={{padding:"2px 6px",borderRadius:4,fontSize:10,fontWeight:600,background:badge.bg,color:badge.fg}}>{badge.label}</span></span>
                <span style={{color:rotComp.color,fontSize:11,fontWeight:500}}>{rotComp.label}</span>
                <span style={{color:C.textDim}}>{formatAgo(db.last_seen_at)}</span>
                <span style={{display:"flex",gap:4}}>
                  <Btn onClick={()=>setExpandedTdeGuide(prev=>({...prev,[db.id]:!prev[db.id]}))} style={{fontSize:10,padding:"2px 6px"}}>Guide</Btn>
                  <Btn onClick={()=>runRevokeTDE(db)} disabled={revokingDbId===db.id||badge.label==="Key Revoked"} style={{fontSize:10,padding:"2px 6px",color:C.red}}>{revokingDbId===db.id?"...":"Revoke"}</Btn>
                </span>
              </div>
              {/* Collapsible TDE Setup Guide */}
              {expandedTdeGuide[db.id]&&(<div style={{padding:"12px 16px",background:C.surface+"44",borderBottom:"1px solid "+C.border,fontSize:12}}>
                <B style={{fontSize:12,marginBottom:6,display:"block"}}>TDE Setup Guide for {db.engine.toUpperCase()}</B>
                {SETUP_GUIDES[db.engine]?(
                  <div>{SETUP_GUIDES[db.engine].steps.map((step,i)=>(<div key={i} style={{fontSize:11,marginBottom:6,whiteSpace:"pre-wrap",fontFamily:step.includes("  ")?"monospace":"inherit",color:step.includes("  ")?C.accent:C.text,background:step.includes("  ")?C.surface:"transparent",padding:step.includes("  ")?"4px 8px":0,borderRadius:4}}>{step}</div>))}</div>
                ):(<div style={{color:C.textDim}}>No setup guide available for {db.engine.toUpperCase()}.</div>)}
              </div>)}
            </div>);
          })}
        </div>
      </div>)}

      {/* ── Key Access Logs Panel (per expanded agent) ── */}
      {expandedAgent&&(<div style={{marginTop:20}}>
        <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
          <B style={{fontSize:14}}>Recent Key Access - {agents.find(a=>a.id===expandedAgent)?.name||expandedAgent}</B>
          <Btn onClick={()=>loadAgentKeyAccessLogs(expandedAgent)} disabled={agentLogsPanelLoading===expandedAgent} style={{fontSize:11,padding:"3px 8px"}}>{agentLogsPanelLoading===expandedAgent?"Loading...":"Load Logs"}</Btn>
        </div>
        {agentLogsPanel[expandedAgent]&&agentLogsPanel[expandedAgent].length>0?(
          <div style={{border:"1px solid "+C.border,borderRadius:8,overflow:"hidden"}}>
            <div style={{display:"grid",gridTemplateColumns:"130px 90px 80px 1fr 1fr 80px",padding:"6px 10px",background:C.surface,fontSize:11,fontWeight:600,color:C.textDim,borderBottom:"1px solid "+C.border}}>
              <span>Timestamp</span><span>Operation</span><span>Status</span><span>Key ID</span><span>Database</span><span>Latency</span>
            </div>
            {agentLogsPanel[expandedAgent].slice(0,20).map((log,i)=>(<div key={log.id||i} style={{display:"grid",gridTemplateColumns:"130px 90px 80px 1fr 1fr 80px",padding:"4px 10px",fontSize:11,borderBottom:"1px solid "+C.border}}>
              <span style={{color:C.textDim}}>{formatAgo(log.created_at)}</span>
              <span style={{fontWeight:500}}>{log.operation}</span>
              <span style={{color:log.status==="success"?C.green:C.red}}>{log.status}</span>
              <span style={{fontFamily:"monospace",fontSize:10,color:C.textDim}}>{String(log.key_id||"").slice(0,16)}</span>
              <span style={{fontSize:10,color:C.textDim}}>{databases.find(d=>d.id===log.database_id)?.name||String(log.database_id||"").slice(0,16)||"n/a"}</span>
              <span style={{color:C.textDim}}>{log.error_message||"--"}</span>
            </div>))}
          </div>
        ):(agentLogsPanel[expandedAgent]?.length===0?(
          <div style={{color:C.textDim,fontSize:12,padding:12,textAlign:"center"}}>No key access logs found for this agent.</div>
        ):null)}
      </div>)}
    </div>)}

    {/* ═══════════════════════ BITLOCKER SUBTAB ═══════════════════════ */}
    {subView==="bitlocker"&&(<div>
      {/* ── Summary stats bar ── */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(140px,1fr))",gap:10,marginBottom:16}}>
        {[
          {label:"Total Clients",value:blStats.total},
          {label:"Protected",value:blStats.protected,color:C.green},
          {label:"Suspended",value:blStats.suspended,color:C.amber},
          {label:"Down",value:blStats.down,color:C.red},
          {label:"TPM Ready",value:blStats.tpmReady,color:C.blue}
        ].map((s,i)=>(<Card key={i}><div style={{textAlign:"center"}}><div style={{fontSize:22,fontWeight:700,color:s.color||C.text}}>{s.value}</div><div style={{fontSize:11,color:C.textDim}}>{s.label}</div></div></Card>))}
      </div>

      {/* ── Toolbar ── */}
      <div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap",alignItems:"center"}}>
        <Inp placeholder="Search clients..." value={bitLockerSearch} onChange={(e)=>setBitLockerSearch(e.target.value)} style={{flex:1,minWidth:180,maxWidth:320}}/>
        <Btn onClick={()=>setBitLockerView(bitLockerView==="cards"?"list":"cards")} style={{padding:"6px 10px"}}>{bitLockerView==="cards"?<List size={15}/>:<LayoutGrid size={15}/>}</Btn>
        <Btn onClick={openBitLockerDeploy}>Register Client</Btn>
        <Btn onClick={openBitLockerScan}>Network Scan</Btn>
        <Btn onClick={()=>refresh(false)} disabled={loading}><RefreshCcw size={14}/></Btn>
      </div>

      {filteredBitLocker.length===0?(<Card><div style={{textAlign:"center",color:C.textDim,padding:32,fontSize:12}}>No BitLocker clients registered.{" "}<span style={{color:C.accent,cursor:"pointer"}} onClick={openBitLockerDeploy}>Register a client</span> or <span style={{color:C.accent,cursor:"pointer"}} onClick={openBitLockerScan}>scan your network</span></div></Card>):(
        bitLockerView==="cards"?(
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(300px,1fr))",gap:12}}>
            {filteredBitLocker.map((client)=>{
              const badge=bitLockerStatusBadge(client);
              return (<Card key={client.id}>
                <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
                  <span style={{padding:"2px 8px",borderRadius:4,fontSize:11,fontWeight:600,background:badge.bg,color:badge.fg}}>{badge.label}</span>
                  <B style={{fontSize:14}}>{client.name}</B>
                </div>
                <div style={{fontSize:12,color:C.textDim,marginBottom:2}}>{client.host} | {client.os_version||"Windows"}</div>
                <div style={{fontSize:12,color:C.textDim,marginBottom:2}}>Volume: {client.mount_point||"C:"} | Encryption: {(client.encryption_percentage||0).toFixed(0)}%</div>
                <div style={{fontSize:12,color:C.textDim,marginBottom:2}}>TPM: {client.tpm_present?"Present":"Missing"} {client.tpm_ready?"(Ready)":"(Not ready)"}</div>
                <div style={{fontSize:12,color:C.textDim,marginBottom:6}}>Heartbeat: {formatAgo(client.last_heartbeat_at)}</div>

                {/* Encryption progress bar */}
                <div style={{background:C.border,borderRadius:4,height:6,marginBottom:8}}>
                  <div style={{background:client.encryption_percentage>=100?C.green:C.blue,borderRadius:4,height:6,width:`${Math.min(100,client.encryption_percentage||0)}%`,transition:"width 0.3s"}}/>
                </div>

                <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                  {["enable","disable","pause","resume","rotate","fetch_recovery"].map((op)=>(<Btn key={op} onClick={()=>runBitLockerOperation(client,op)} disabled={bitLockerOpClientID===`${client.id}:${op}`} style={{fontSize:10,padding:"2px 6px",textTransform:"capitalize"}}>{bitLockerOpClientID===`${client.id}:${op}`?"...":op.replace("_"," ")}</Btn>))}
                  <Btn onClick={()=>openBitLockerActivity(client)} style={{fontSize:10,padding:"2px 6px"}}>Activity</Btn>
                  <Btn onClick={()=>openBitLockerDelete(client)} style={{fontSize:10,padding:"2px 6px",color:C.red}}>Delete</Btn>
                </div>
              </Card>);
            })}
          </div>
        ):(
          /* ── List view ── */
          <div style={{border:"1px solid "+C.border,borderRadius:8,overflow:"hidden"}}>
            <div style={{display:"grid",gridTemplateColumns:"2fr 1.5fr 1fr 1fr 1fr 1fr 140px",padding:"8px 12px",background:C.surface,fontSize:11,fontWeight:600,color:C.textDim,borderBottom:"1px solid "+C.border}}>
              <span>Client</span><span>Host</span><span>Status</span><span>Encryption</span><span>TPM</span><span>Heartbeat</span><span>Actions</span>
            </div>
            {filteredBitLocker.map((client)=>{
              const badge=bitLockerStatusBadge(client);
              return (<div key={client.id} style={{display:"grid",gridTemplateColumns:"2fr 1.5fr 1fr 1fr 1fr 1fr 140px",padding:"8px 12px",fontSize:12,borderBottom:"1px solid "+C.border}}>
                <span><B>{client.name}</B></span>
                <span style={{color:C.textDim}}>{client.host}</span>
                <span><span style={{padding:"2px 6px",borderRadius:4,fontSize:10,fontWeight:600,background:badge.bg,color:badge.fg}}>{badge.label}</span></span>
                <span>{(client.encryption_percentage||0).toFixed(0)}%</span>
                <span>{client.tpm_present&&client.tpm_ready?"Ready":client.tpm_present?"Present":"N/A"}</span>
                <span style={{color:C.textDim}}>{formatAgo(client.last_heartbeat_at)}</span>
                <span style={{display:"flex",gap:4}}>
                  <Btn onClick={()=>openBitLockerActivity(client)} style={{fontSize:10,padding:"2px 6px"}}>Activity</Btn>
                  <Btn onClick={()=>openBitLockerOptions(client)} style={{fontSize:10,padding:"2px 6px"}}>Ops</Btn>
                  <Btn onClick={()=>openBitLockerDelete(client)} style={{fontSize:10,padding:"2px 6px",color:C.red}}>Del</Btn>
                </span>
              </div>);
            })}
          </div>
        )
      )}
    </div>)}

    {/* ═══════════════════════ AZURE EKM SUBTAB ═══════════════════════ */}
    {subView==="azure"&&(<div>
      {/* ── Summary stats bar ── */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(140px,1fr))",gap:10,marginBottom:16}}>
        {[
          {label:"Vault Configs",value:azureConfigs.length,color:C.accent},
          {label:"Key Mappings",value:azureMappings.length,color:C.blue||C.accent},
          {label:"Synced",value:azureMappings.filter(m=>m.sync_status==="synced").length,color:C.green},
          {label:"Pending",value:azureMappings.filter(m=>m.sync_status==="pending").length,color:C.amber},
          {label:"Errors",value:azureMappings.filter(m=>m.sync_status==="error").length,color:C.red}
        ].map(s=>(<Card key={s.label} style={{padding:"10px 14px",textAlign:"center"}}>
          <div style={{fontSize:20,fontWeight:700,color:s.color}}>{s.value}</div>
          <div style={{fontSize:11,color:C.textDim}}>{s.label}</div>
        </Card>))}
      </div>

      {/* ── Action bar ── */}
      <div style={{display:"flex",gap:8,marginBottom:16,flexWrap:"wrap"}}>
        <Btn onClick={()=>setModal("azure-add-config")}>+ Add Azure Vault</Btn>
        <Btn onClick={()=>setModal("azure-add-mapping")}>+ Add Key Mapping</Btn>
        <Btn onClick={()=>refresh(true)} disabled={loading}><RefreshCcw size={14}/> Refresh</Btn>
      </div>

      {/* ── Vault Configs Table ── */}
      <B style={{fontSize:14,marginBottom:8,display:"block"}}>Azure Key Vault Configurations</B>
      {azureConfigs.length===0?(<div style={{color:C.textDim,fontSize:12,padding:16,textAlign:"center"}}>No Azure vault configurations. Click "+ Add Azure Vault" to connect.</div>):(
        <div style={{border:"1px solid "+C.border,borderRadius:8,overflow:"hidden",marginBottom:24}}>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 100px 80px 180px",padding:"8px 12px",fontSize:11,fontWeight:600,color:C.textDim,borderBottom:"1px solid "+C.border,background:C.surface}}>
            <span>Vault Name</span><span>Azure Tenant</span><span>Auth Mode</span><span>Mappings</span><span>Status</span><span>Actions</span>
          </div>
          {azureConfigs.map(cfg=>(<div key={cfg.id} style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 100px 80px 180px",padding:"8px 12px",fontSize:12,borderBottom:"1px solid "+C.border,alignItems:"center"}}>
            <div>
              <div style={{fontWeight:600}}>{cfg.vault_name}</div>
              <div style={{fontSize:10,color:C.textDim,fontFamily:"monospace"}}>{cfg.vault_url}</div>
              {cfg.managed_hsm_name&&(<div style={{fontSize:10,color:C.accent}}>HSM: {cfg.managed_hsm_name}</div>)}
            </div>
            <span style={{fontFamily:"monospace",fontSize:10,color:C.textDim}}>{cfg.azure_tenant_id}</span>
            <span>{cfg.auth_mode}</span>
            <span>{cfg.key_mappings}</span>
            <span style={{color:cfg.status==="active"?C.green:C.red}}>{cfg.status}</span>
            <div style={{display:"flex",gap:4,flexWrap:"wrap"}}>
              <Btn onClick={async()=>{
                setAzureTestResults(prev=>({...prev,[cfg.id]:{connected:false}}));
                try{
                  const res=await testAzureConnection(session,cfg.id);
                  setAzureTestResults(prev=>({...prev,[cfg.id]:res}));
                  onToast?.(res.connected?"Connection successful":"Connection failed: "+(res.error||"unknown"));
                }catch(e){setAzureTestResults(prev=>({...prev,[cfg.id]:{connected:false,error:errMsg(e)}}));onToast?.(`Test failed: ${errMsg(e)}`);}
              }} style={{fontSize:10,padding:"3px 8px"}}>Test</Btn>
              <Btn onClick={async()=>{
                setAzureSyncing(cfg.id);
                try{
                  const res=await syncAzureKeys(session,cfg.id);
                  onToast?.(`Synced ${res.synced}/${res.total} keys`);
                  await refresh(true);
                }catch(e){onToast?.(`Sync failed: ${errMsg(e)}`);}finally{setAzureSyncing("");}
              }} disabled={azureSyncing===cfg.id} style={{fontSize:10,padding:"3px 8px"}}>{azureSyncing===cfg.id?"Syncing...":"Sync"}</Btn>
              <Btn onClick={async()=>{
                if(!confirm("Delete this Azure vault configuration?")) return;
                try{await deleteAzureEKMConfig(session,cfg.id);onToast?.("Config deleted");await refresh(true);}catch(e){onToast?.(`Delete failed: ${errMsg(e)}`);}
              }} style={{fontSize:10,padding:"3px 8px",color:C.red}}>Delete</Btn>
            </div>
          </div>))}
        </div>
      )}

      {/* ── Test results ── */}
      {Object.keys(azureTestResults).length>0&&(<div style={{marginBottom:16}}>
        {Object.entries(azureTestResults).map(([cfgId,res])=>{
          const cfg=azureConfigs.find(c=>c.id===cfgId);
          return (<div key={cfgId} style={{fontSize:12,padding:"6px 10px",background:res.connected?C.green+"15":C.red+"15",borderRadius:6,marginBottom:4}}>
            <span style={{fontWeight:600}}>{cfg?.vault_name||cfgId}:</span>{" "}
            <span style={{color:res.connected?C.green:C.red}}>{res.connected?"Connected":"Failed"}</span>
            {res.error&&(<span style={{color:C.red,marginLeft:8,fontSize:11}}>{res.error}</span>)}
          </div>);
        })}
      </div>)}

      {/* ── Key Mappings Table ── */}
      <B style={{fontSize:14,marginBottom:8,display:"block"}}>Key Mappings (Vecta KMS to Azure)</B>
      {azureMappings.length===0?(<div style={{color:C.textDim,fontSize:12,padding:16,textAlign:"center"}}>No key mappings. Click "+ Add Key Mapping" to map a Vecta key to Azure.</div>):(
        <div style={{border:"1px solid "+C.border,borderRadius:8,overflow:"hidden"}}>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 100px 80px 200px",padding:"8px 12px",fontSize:11,fontWeight:600,color:C.textDim,borderBottom:"1px solid "+C.border,background:C.surface}}>
            <span>Azure Key</span><span>Vecta Key</span><span>Azure Key ID</span><span>Purpose</span><span>Sync</span><span>Actions</span>
          </div>
          {azureMappings.map(m=>(<div key={m.id} style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 100px 80px 200px",padding:"8px 12px",fontSize:12,borderBottom:"1px solid "+C.border,alignItems:"center"}}>
            <span style={{fontWeight:600}}>{m.azure_key_name}</span>
            <span style={{fontFamily:"monospace",fontSize:10,color:C.textDim}}>{m.vecta_key_id.slice(0,20)}</span>
            <span style={{fontFamily:"monospace",fontSize:10,color:C.textDim}}>{m.azure_key_id?m.azure_key_id.split("/").slice(-2).join("/"):"(not imported)"}</span>
            <span style={{textTransform:"uppercase",fontSize:10}}>{m.purpose}</span>
            <span style={{color:m.sync_status==="synced"?C.green:m.sync_status==="error"?C.red:C.amber,fontSize:11}}>{m.sync_status}</span>
            <div style={{display:"flex",gap:4,flexWrap:"wrap"}}>
              <Btn onClick={async()=>{
                setAzureOpLoading(`import-${m.id}`);
                try{const res=await importKeyToAzure(session,m.id);onToast?.(`Imported: ${res.azure_key_id}`);await refresh(true);}catch(e){onToast?.(`Import failed: ${errMsg(e)}`);}finally{setAzureOpLoading("");}
              }} disabled={azureOpLoading===`import-${m.id}`} style={{fontSize:10,padding:"3px 6px"}}>{azureOpLoading===`import-${m.id}`?"...":"Import"}</Btn>
              <Btn onClick={async()=>{
                setAzureOpLoading(`rotate-${m.id}`);
                try{const res=await rotateAzureKey(session,m.id);onToast?.(`Rotated: v${res.new_version}`);await refresh(true);}catch(e){onToast?.(`Rotate failed: ${errMsg(e)}`);}finally{setAzureOpLoading("");}
              }} disabled={azureOpLoading===`rotate-${m.id}`} style={{fontSize:10,padding:"3px 6px"}}>{azureOpLoading===`rotate-${m.id}`?"...":"Rotate"}</Btn>
              <Btn onClick={()=>{setModal("azure-wrap");setAzureMappingForm(prev=>({...prev,config_id:m.id}));}} style={{fontSize:10,padding:"3px 6px"}}>Wrap</Btn>
              <Btn onClick={()=>{setModal("azure-unwrap");setAzureMappingForm(prev=>({...prev,config_id:m.id}));}} style={{fontSize:10,padding:"3px 6px"}}>Unwrap</Btn>
              <Btn onClick={async()=>{
                if(!confirm("Delete this key mapping?")) return;
                try{await deleteAzureKeyMapping(session,m.id);onToast?.("Mapping deleted");await refresh(true);}catch(e){onToast?.(`Delete failed: ${errMsg(e)}`);}
              }} style={{fontSize:10,padding:"3px 6px",color:C.red}}>Del</Btn>
            </div>
          </div>))}
        </div>
      )}
    </div>)}

    {/* ═══════════════════════ GOOGLE CSE SUBTAB ═══════════════════════ */}
    {subView==="google-cse"&&(<div>
      {/* ── Summary stats bar ── */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(140px,1fr))",gap:10,marginBottom:16}}>
        {[
          {label:"CSE Configs",value:googleCSEConfigs.length,color:C.accent},
          {label:"CSE Keys",value:googleCSEKeys.length,color:C.blue||C.accent},
          {label:"Active Keys",value:googleCSEKeys.filter(k=>k.status==="active").length,color:C.green||"#4ade80"},
          {label:"Total Wraps",value:googleCSEKeys.reduce((s,k)=>s+(k.wrap_count||0),0),color:C.purple||C.accent},
          {label:"Total Unwraps",value:googleCSEKeys.reduce((s,k)=>s+(k.unwrap_count||0),0),color:C.orange||C.accent}
        ].map(s=>(<Card key={s.label} style={{padding:"10px 14px",textAlign:"center"}}>
          <div style={{fontSize:20,fontWeight:700,color:s.color}}>{s.value}</div>
          <div style={{fontSize:10,color:C.textMuted,marginTop:2}}>{s.label}</div>
        </Card>))}
      </div>

      {/* ── Add CSE Config ── */}
      <Card style={{padding:14,marginBottom:14}}>
        <B style={{fontSize:13,marginBottom:8,display:"block"}}>Add Google Workspace CSE Config</B>
        <Row2>
          <FG label="Workspace Customer ID"><Inp value={googleCSEConfigForm.google_workspace_customer_id} onChange={e=>setGoogleCSEConfigForm(p=>({...p,google_workspace_customer_id:e.target.value}))} placeholder="C0xxxxxxx"/></FG>
          <FG label="Service Account Email"><Inp value={googleCSEConfigForm.service_account_email} onChange={e=>setGoogleCSEConfigForm(p=>({...p,service_account_email:e.target.value}))} placeholder="cse-service@project.iam.gserviceaccount.com"/></FG>
        </Row2>
        <Row2>
          <FG label="Allowed Domains (comma-separated)"><Inp value={googleCSEConfigForm.allowed_domains} onChange={e=>setGoogleCSEConfigForm(p=>({...p,allowed_domains:e.target.value}))} placeholder="company.com, subsidiary.com"/></FG>
          <FG label="KACLS Endpoint URL"><Inp value={googleCSEConfigForm.kacls_endpoint} onChange={e=>setGoogleCSEConfigForm(p=>({...p,kacls_endpoint:e.target.value}))} placeholder="https://kacls.example.com/ekm/kacls"/></FG>
        </Row2>
        <FG label="Service Account Key JSON"><Inp value={googleCSEConfigForm.service_account_key_json} onChange={e=>setGoogleCSEConfigForm(p=>({...p,service_account_key_json:e.target.value}))} placeholder='{"type":"service_account",...}' style={{fontFamily:"monospace",fontSize:11}}/></FG>
        <Btn disabled={googleCSELoading||!googleCSEConfigForm.google_workspace_customer_id} onClick={async()=>{
          setGoogleCSELoading(true);
          try{
            const domains=googleCSEConfigForm.allowed_domains.split(",").map(d=>d.trim()).filter(Boolean);
            await createGoogleCSEConfig(session,{
              google_workspace_customer_id:googleCSEConfigForm.google_workspace_customer_id,
              service_account_email:googleCSEConfigForm.service_account_email,
              service_account_key_json:googleCSEConfigForm.service_account_key_json,
              allowed_domains:domains,
              kacls_endpoint:googleCSEConfigForm.kacls_endpoint
            });
            onToast?.("Google CSE config created");
            setGoogleCSEConfigForm({google_workspace_customer_id:"",service_account_email:"",service_account_key_json:"",allowed_domains:"",kacls_endpoint:""});
            await refresh(true);
          }catch(e){onToast?.(`Failed: ${errMsg(e)}`);}finally{setGoogleCSELoading(false);}
        }} style={{marginTop:8}}>{googleCSELoading?"Creating...":"Create Config"}</Btn>
      </Card>

      {/* ── CSE Configs list ── */}
      {googleCSEConfigs.length>0&&(<Card style={{padding:14,marginBottom:14}}>
        <B style={{fontSize:13,marginBottom:8,display:"block"}}>Workspace Configurations</B>
        <div style={{display:"flex",flexDirection:"column",gap:8}}>
          {googleCSEConfigs.map(cfg=>(<div key={cfg.id} style={{background:C.surface,borderRadius:8,padding:10,border:`1px solid ${C.border}`}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <div>
                <div style={{fontSize:12,fontWeight:600}}>{cfg.google_workspace_customer_id}</div>
                <div style={{fontSize:10,color:C.textMuted}}>{cfg.service_account_email||"No service account"} &middot; {(cfg.allowed_domains||[]).join(", ")}</div>
                <div style={{fontSize:10,color:C.textMuted}}>KACLS: {cfg.kacls_endpoint||"Not configured"} &middot; Keys: {cfg.key_count||0} &middot; Status: <span style={{color:cfg.status==="active"?C.green||"#4ade80":C.red}}>{cfg.status}</span></div>
                {cfg.last_activity_at&&(<div style={{fontSize:10,color:C.textMuted}}>Last activity: {formatAgo(cfg.last_activity_at)}</div>)}
              </div>
              <div style={{display:"flex",gap:4}}>
                <Btn onClick={async()=>{
                  if(!confirm("Delete this Google CSE config?")) return;
                  try{await deleteGoogleCSEConfig(session,cfg.id);onToast?.("Config deleted");await refresh(true);}catch(e){onToast?.(`Delete failed: ${errMsg(e)}`);}
                }} style={{fontSize:10,padding:"3px 6px",color:C.red}}>Delete</Btn>
              </div>
            </div>
          </div>))}
        </div>
      </Card>)}

      {/* ── Add CSE Key ── */}
      {googleCSEConfigs.length>0&&(<Card style={{padding:14,marginBottom:14}}>
        <B style={{fontSize:13,marginBottom:8,display:"block"}}>Create CSE Key</B>
        <Row2>
          <FG label="Config"><Sel value={googleCSEKeyForm.config_id} onChange={e=>setGoogleCSEKeyForm(p=>({...p,config_id:e.target.value}))}>
            <option value="">Select config...</option>
            {googleCSEConfigs.map(c=>(<option key={c.id} value={c.id}>{c.google_workspace_customer_id}</option>))}
          </Sel></FG>
          <FG label="Key Name"><Inp value={googleCSEKeyForm.key_name} onChange={e=>setGoogleCSEKeyForm(p=>({...p,key_name:e.target.value}))} placeholder="gmail-cse-key-1"/></FG>
        </Row2>
        <Row2>
          <FG label="Vecta Key ID"><Inp value={googleCSEKeyForm.vecta_key_id} onChange={e=>setGoogleCSEKeyForm(p=>({...p,vecta_key_id:e.target.value}))} placeholder="key_xxxxxxxx"/></FG>
          <FG label="Purpose"><Sel value={googleCSEKeyForm.purpose} onChange={e=>setGoogleCSEKeyForm(p=>({...p,purpose:e.target.value}))}>
            <option value="drive">Google Drive</option>
            <option value="gmail">Gmail</option>
            <option value="calendar">Calendar</option>
            <option value="meet">Meet</option>
          </Sel></FG>
        </Row2>
        <Btn disabled={googleCSELoading||!googleCSEKeyForm.config_id||!googleCSEKeyForm.key_name||!googleCSEKeyForm.vecta_key_id} onClick={async()=>{
          setGoogleCSELoading(true);
          try{
            await createGoogleCSEKey(session,{
              config_id:googleCSEKeyForm.config_id,
              key_name:googleCSEKeyForm.key_name,
              vecta_key_id:googleCSEKeyForm.vecta_key_id,
              purpose:googleCSEKeyForm.purpose
            });
            onToast?.("CSE key created");
            setGoogleCSEKeyForm({config_id:"",key_name:"",vecta_key_id:"",purpose:"drive"});
            await refresh(true);
          }catch(e){onToast?.(`Failed: ${errMsg(e)}`);}finally{setGoogleCSELoading(false);}
        }} style={{marginTop:8}}>{googleCSELoading?"Creating...":"Create Key"}</Btn>
      </Card>)}

      {/* ── CSE Keys list ── */}
      {googleCSEKeys.length>0&&(<Card style={{padding:14,marginBottom:14}}>
        <B style={{fontSize:13,marginBottom:8,display:"block"}}>CSE Keys</B>
        <div style={{display:"flex",flexDirection:"column",gap:6}}>
          {googleCSEKeys.map(k=>(<div key={k.id} style={{background:C.surface,borderRadius:8,padding:10,border:`1px solid ${C.border}`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <div>
              <div style={{fontSize:12,fontWeight:600}}>{k.key_name} <span style={{fontSize:10,fontWeight:400,color:C.textMuted}}>({k.purpose})</span></div>
              <div style={{fontSize:10,color:C.textMuted}}>Vecta Key: {k.vecta_key_id} &middot; Status: <span style={{color:k.status==="active"?C.green||"#4ade80":C.red}}>{k.status}</span></div>
              <div style={{fontSize:10,color:C.textMuted}}>Wraps: {k.wrap_count||0} &middot; Unwraps: {k.unwrap_count||0}{k.last_used_at?` \u00b7 Last used: ${formatAgo(k.last_used_at)}`:""}</div>
              <div style={{fontSize:9,color:C.textMuted,fontFamily:"monospace",marginTop:2}}>URI: {k.google_key_uri}</div>
            </div>
            <div style={{display:"flex",gap:4}}>
              <Btn onClick={async()=>{
                if(!confirm("Delete this CSE key?")) return;
                try{await deleteGoogleCSEKey(session,k.id);onToast?.("Key deleted");await refresh(true);}catch(e){onToast?.(`Delete failed: ${errMsg(e)}`);}
              }} style={{fontSize:10,padding:"3px 6px",color:C.red}}>Delete</Btn>
            </div>
          </div>))}
        </div>
      </Card>)}

      {/* ── KACLS Endpoint Info ── */}
      <Card style={{padding:14}}>
        <B style={{fontSize:13,marginBottom:8,display:"block"}}>KACLS Endpoint Information</B>
        <div style={{fontSize:11,color:C.textMuted,lineHeight:1.6}}>
          <div>Google CSE calls the following KACLS API endpoints on this Vecta KMS instance:</div>
          <div style={{fontFamily:"monospace",fontSize:10,marginTop:6,background:C.surface,padding:8,borderRadius:6,border:`1px solid ${C.border}`}}>
            <div>GET  /ekm/kacls/status &mdash; KACLS health check</div>
            <div>POST /ekm/kacls/wrap &mdash; Wrap DEK for encryption</div>
            <div>POST /ekm/kacls/unwrap &mdash; Unwrap DEK for decryption</div>
            <div>POST /ekm/kacls/privilegedunwrap &mdash; Admin/legal hold unwrap</div>
          </div>
          <div style={{marginTop:8}}>Configure these endpoints in your Google Workspace Admin Console under <b>Security &gt; Client-side encryption &gt; External key service</b>.</div>
        </div>
      </Card>
    </div>)}

    {/* ═══════════════════════ KMIP SUBTAB ═══════════════════════ */}
    {subView==="kmip"&&(<KMIPTab session={session} onToast={onToast}/>)}


    {/* ═══════════════════════ MODALS ═══════════════════════ */}

    {/* ── Setup Guide Modal ── */}
    {modal==="setup-guide"&&(<Modal open={true} title="EKM Setup Guide" onClose={()=>setModal(null)}>
      <div style={{display:"flex",gap:8,marginBottom:12}}>
        {Object.keys(SETUP_GUIDES).map(eng=>(<Btn key={eng} onClick={()=>setGuideEngine(eng)} style={{fontSize:12,padding:"4px 12px",background:guideEngine===eng?C.accent+"22":"transparent",color:guideEngine===eng?C.accent:C.text}}>{eng.toUpperCase()}</Btn>))}
      </div>
      <B>{SETUP_GUIDES[guideEngine]?.title}</B>
      <div style={{marginTop:12}}>
        {SETUP_GUIDES[guideEngine]?.steps.map((step,i)=>(<div key={i} style={{fontSize:12,marginBottom:10,whiteSpace:"pre-wrap",fontFamily:step.includes("  ")?"monospace":"inherit",color:step.includes("  ")?C.accent:C.text,background:step.includes("  ")?C.surface:"transparent",padding:step.includes("  ")?"6px 10px":0,borderRadius:4}}>{step}</div>))}
      </div>
    </Modal>)}

    {/* ── Health Detail Modal ── */}
    {modal==="health-detail"&&selectedAgent&&(()=>{
      const h=healthByID[selectedAgent.id]||{};
      const m=h?.metrics||{};
      const meta=parseAgentMeta(selectedAgent);
      return (<Modal open={true} title={`Health: ${selectedAgent.name}`} onClose={()=>setModal(null)}>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
          <div>
            <B style={{fontSize:13,marginBottom:6,display:"block"}}>System Metrics</B>
            <div style={{fontSize:12,color:C.textDim}}>Hostname: {m.hostname||"n/a"}</div>
            <div style={{fontSize:12,color:C.textDim}}>OS: {m.os_name} {m.os_version}</div>
            <div style={{fontSize:12,color:C.textDim}}>Kernel: {m.kernel||"n/a"}</div>
            <div style={{fontSize:12,color:C.textDim}}>Architecture: {m.arch||"n/a"}</div>
            <div style={{fontSize:12,color:C.textDim}}>Uptime: {m.uptime_sec>0?`${Math.floor(m.uptime_sec/3600)}h ${Math.floor((m.uptime_sec%3600)/60)}m`:"n/a"}</div>
            <div style={{fontSize:12,color:C.textDim}}>Agent Runtime: {m.agent_runtime_sec>0?`${Math.floor(m.agent_runtime_sec/3600)}h ${Math.floor((m.agent_runtime_sec%3600)/60)}m`:"n/a"}</div>
          </div>
          <div>
            <B style={{fontSize:13,marginBottom:6,display:"block"}}>Resource Usage</B>
            {[{label:"CPU",value:m.cpu_usage_pct},{label:"Memory",value:m.memory_usage_pct},{label:"Disk",value:m.disk_usage_pct}].map(r=>(<div key={r.label} style={{marginBottom:8}}>
              <div style={{fontSize:12,color:C.textDim,marginBottom:2}}>{r.label}: {(r.value||0).toFixed(1)}%</div>
              <div style={{background:C.border,borderRadius:4,height:8}}>
                <div style={{background:(r.value||0)>90?C.red:(r.value||0)>70?C.amber:C.green,borderRadius:4,height:8,width:`${Math.min(100,r.value||0)}%`}}/>
              </div>
            </div>))}
          </div>
        </div>
        <div style={{marginTop:16}}>
          <B style={{fontSize:13,marginBottom:6,display:"block"}}>PKCS#11 Status</B>
          <div style={{fontSize:12,color:C.textDim}}>Module Path: {meta.pkcs11_module_path||"n/a"}</div>
          <div style={{fontSize:12,color:meta.pkcs11_ready?C.green:C.red}}>Ready: {meta.pkcs11_ready?"Yes":"No"}{meta.pkcs11_reason&&` (${meta.pkcs11_reason})`}</div>
        </div>
        <div style={{marginTop:16}}>
          <B style={{fontSize:13,marginBottom:6,display:"block"}}>Health Status: <span style={{color:String(h.health||"")=="healthy"?C.green:String(h.health||"")=="degraded"?C.amber:C.red}}>{String(h.health||"unknown")}</span></B>
          {Array.isArray(h.warnings)&&h.warnings.length>0&&(<div style={{fontSize:12}}>
            {h.warnings.map((w,i)=>(<div key={i} style={{color:C.amber,marginBottom:2}}>- {w}</div>))}
          </div>)}
        </div>
      </Modal>);
    })()}

    {/* ── Register Database Modal ── */}
    {modal==="db-register"&&(<Modal open={true} title="Register Database" onClose={()=>setModal(null)}>
      <FG label="Agent"><Sel value={dbRegForm.agent_id} onChange={(e)=>setDbRegForm({...dbRegForm,agent_id:e.target.value})}>
        {agents.map(a=>(<option key={a.id} value={a.id}>{a.name} ({a.host})</option>))}
      </Sel></FG>
      <Row2>
        <FG label="Database Name"><Inp value={dbRegForm.name} onChange={(e)=>setDbRegForm({...dbRegForm,name:e.target.value})} placeholder="mydb_prod"/></FG>
        <FG label="Engine"><Sel value={dbRegForm.engine} onChange={(e)=>{
          const eng=e.target.value;
          const defaultPorts:Record<string,number>={mssql:1433,oracle:1521,postgresql:5432,mysql:3306,db2:50000};
          setDbRegForm({...dbRegForm,engine:eng,port:defaultPorts[eng]||1433});
        }}>
          <option value="mssql">Microsoft SQL Server</option>
          <option value="oracle">Oracle Database</option>
          <option value="postgresql">PostgreSQL</option>
          <option value="mysql">MySQL / MariaDB</option>
          <option value="db2">IBM DB2</option>
        </Sel></FG>
      </Row2>
      <Row2>
        <FG label="Host"><Inp value={dbRegForm.host} onChange={(e)=>setDbRegForm({...dbRegForm,host:e.target.value})} placeholder="db-server.local"/></FG>
        <FG label="Port"><Inp type="number" value={dbRegForm.port} onChange={(e)=>setDbRegForm({...dbRegForm,port:Number(e.target.value)})}/></FG>
      </Row2>
      <Row2>
        <FG label="Catalog / SID / Database"><Inp value={dbRegForm.database_name} onChange={(e)=>setDbRegForm({...dbRegForm,database_name:e.target.value})} placeholder="AdventureWorks"/></FG>
        <FG label="Key Rotation Policy"><Sel value={dbRegForm.rotation_policy} onChange={(e)=>setDbRegForm({...dbRegForm,rotation_policy:e.target.value})}>
          <option value="0">None</option>
          <option value="30">Every 30 days</option>
          <option value="90">Every 90 days</option>
          <option value="180">Every 180 days</option>
          <option value="365">Every 365 days</option>
        </Sel></FG>
      </Row2>
      <div style={{fontSize:11,color:C.textDim,marginTop:4}}>A TDE key will be auto-provisioned via KeyCore for this database.{dbRegForm.rotation_policy!=="0"&&` Key rotation policy: every ${dbRegForm.rotation_policy} days.`}</div>
      <div style={{display:"flex",gap:8,marginTop:12}}>
        <Btn onClick={submitDbRegister} disabled={dbRegistering}>{dbRegistering?"Registering...":"Register Database"}</Btn>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
      </div>
    </Modal>)}

    {/* ── Deploy Agent Modal ── */}
    {modal==="deploy"&&(<Modal open={true} title="Deploy EKM Agent" onClose={()=>setModal(null)}>
      {!deployPackage?(<>
        <Row2>
          <FG label="Agent Name"><Inp value={deployForm.name} onChange={(e)=>setDeployForm({...deployForm,name:e.target.value})} placeholder="prod-sql-01"/></FG>
          <FG label="DB Engine"><Sel value={deployForm.db_engine} onChange={(e)=>setDeployForm({...deployForm,db_engine:e.target.value})}>
            <option value="mssql">Microsoft SQL Server</option>
            <option value="oracle">Oracle Database</option>
            <option value="postgresql">PostgreSQL</option>
            <option value="mysql">MySQL / MariaDB</option>
            <option value="db2">IBM DB2</option>
          </Sel></FG>
        </Row2>
        <Row2>
          <FG label="Host / IP"><Inp value={deployForm.host} onChange={(e)=>setDeployForm({...deployForm,host:e.target.value})} placeholder="10.0.0.50"/></FG>
          <FG label="Version (optional)"><Inp value={deployForm.version} onChange={(e)=>setDeployForm({...deployForm,version:e.target.value})} placeholder="SQL Server 2022"/></FG>
        </Row2>
        <Row2>
          <FG label="Target OS"><Sel value={deployForm.target_os} onChange={(e)=>setDeployForm({...deployForm,target_os:e.target.value})}>
            <option value="linux">Linux</option><option value="windows">Windows</option>
          </Sel></FG>
          <FG label="Heartbeat (sec)"><Inp type="number" value={deployForm.heartbeat_interval_sec} onChange={(e)=>setDeployForm({...deployForm,heartbeat_interval_sec:Number(e.target.value)})}/></FG>
        </Row2>
        <FG label="Rotation Cycle (days)"><Inp type="number" value={deployForm.rotation_cycle_days} onChange={(e)=>setDeployForm({...deployForm,rotation_cycle_days:Number(e.target.value)})}/></FG>
        <div style={{fontSize:11,color:C.textDim,marginTop:4}}>This will register the agent, auto-provision a TDE key via KeyCore, and generate a deploy package with install scripts and configuration files.</div>
        <div style={{display:"flex",gap:8,marginTop:12}}>
          <Btn onClick={submitDeploy} disabled={deploying}>{deploying?"Deploying...":"Deploy Agent"}</Btn>
          <Btn onClick={()=>setModal(null)}>Cancel</Btn>
        </div>
      </>):(<>
        {/* Tabbed deploy modal */}
        <div style={{display:"flex",gap:0,marginBottom:12,borderBottom:"1px solid "+C.border}}>
          {([["download","Download Scripts"],["guide","Setup Guide"],["verify","Verify Connection"]] as const).map(([key,label])=>(
            <div key={key} onClick={()=>setDeployModalTab(key)} style={{padding:"8px 16px",cursor:"pointer",fontSize:12,fontWeight:deployModalTab===key?600:400,color:deployModalTab===key?C.accent:C.textDim,borderBottom:deployModalTab===key?`2px solid ${C.accent}`:"2px solid transparent"}}>{label}</div>
          ))}
        </div>

        {deployModalTab==="download"&&(<>
          <div style={{color:C.green,marginBottom:8,fontSize:12}}>Agent registered. Download and deploy these files on the target host:</div>
          {visibleDeployFiles.map((file,i)=>(<Card key={i} style={{marginBottom:8}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:4}}>
              <B style={{fontSize:13}}>{file.path}</B>
              <Btn onClick={()=>downloadText(file.path,file.content)} style={{fontSize:11,padding:"3px 8px"}}>Download</Btn>
            </div>
            <pre style={{fontSize:11,maxHeight:160,overflow:"auto",background:C.surface,padding:8,borderRadius:4,whiteSpace:"pre-wrap"}}>{String(file.content||"").slice(0,2000)}</pre>
          </Card>))}
        </>)}

        {deployModalTab==="guide"&&(<>
          <B style={{marginBottom:8,display:"block"}}>{SETUP_GUIDES[deployForm.db_engine]?.title||"Setup Guide"}</B>
          {SETUP_GUIDES[deployForm.db_engine]?(
            <div>{SETUP_GUIDES[deployForm.db_engine].steps.map((step,i)=>(<div key={i} style={{fontSize:12,marginBottom:8,whiteSpace:"pre-wrap",fontFamily:step.includes("  ")?"monospace":"inherit",color:step.includes("  ")?C.accent:C.text,background:step.includes("  ")?C.surface:"transparent",padding:step.includes("  ")?"6px 10px":0,borderRadius:4}}>{step}</div>))}</div>
          ):(<div style={{color:C.textDim,fontSize:12}}>No setup guide available for this engine. Please refer to vendor documentation.</div>)}
        </>)}

        {deployModalTab==="verify"&&(<>
          <div style={{fontSize:12,color:C.textDim,marginBottom:12}}>Verify that the deployed agent can connect to Vecta KMS and the PKCS#11 module is operational.</div>
          <Btn onClick={async()=>{
            const agentId=String(deployPackage?.agent_id||"").trim();
            if(!agentId){ onToast?.("No agent ID available."); return; }
            setVerifyingAgentId(agentId);setVerifyResult(null);
            try{
              const result=await validateAgentDeployment(session,agentId);
              setVerifyResult(result);
              onToast?.(result?.valid?"Agent verified successfully":"Verification returned issues");
            }catch(e){ setVerifyResult({valid:false,error:errMsg(e)}); onToast?.(`Verify failed: ${errMsg(e)}`); }finally{ setVerifyingAgentId(""); }
          }} disabled={!!verifyingAgentId}>{verifyingAgentId?"Verifying...":"Verify Connection"}</Btn>
          {verifyResult&&(<div style={{marginTop:12,padding:10,borderRadius:6,background:verifyResult.valid?C.green+"15":C.red+"15",border:`1px solid ${verifyResult.valid?C.green:C.red}44`}}>
            <div style={{fontSize:12,fontWeight:600,color:verifyResult.valid?C.green:C.red,marginBottom:4}}>{verifyResult.valid?"Verification Successful":"Verification Failed"}</div>
            {verifyResult.error&&(<div style={{fontSize:11,color:C.red}}>{verifyResult.error}</div>)}
            {verifyResult.agent_status&&(<div style={{fontSize:11,color:C.textDim}}>Agent Status: {verifyResult.agent_status}</div>)}
            {verifyResult.pkcs11_status&&(<div style={{fontSize:11,color:C.textDim}}>PKCS#11: {verifyResult.pkcs11_status}</div>)}
            {verifyResult.heartbeat_age_sec!=null&&(<div style={{fontSize:11,color:C.textDim}}>Last Heartbeat: {verifyResult.heartbeat_age_sec}s ago</div>)}
          </div>)}
        </>)}
      </>)}
    </Modal>)}

    {/* ── Logs Modal ── */}
    {modal==="logs"&&selectedAgent&&(<Modal open={true} title={`Access Logs: ${selectedAgent.name}`} onClose={()=>setModal(null)}>
      {logsLoading?(<div style={{textAlign:"center",color:C.textDim,fontSize:12}}>Loading logs...</div>):(
        logs.length===0?(<div style={{textAlign:"center",color:C.textDim,fontSize:12}}>No access logs found.</div>):(
          <div style={{maxHeight:400,overflow:"auto"}}>
            <div style={{display:"grid",gridTemplateColumns:"120px 80px 80px 1fr 1fr",padding:"6px 8px",fontSize:11,fontWeight:600,color:C.textDim,borderBottom:"1px solid "+C.border}}>
              <span>Time</span><span>Operation</span><span>Status</span><span>Key ID</span><span>Error</span>
            </div>
            {logs.map((log,i)=>(<div key={log.id||i} style={{display:"grid",gridTemplateColumns:"120px 80px 80px 1fr 1fr",padding:"4px 8px",fontSize:11,borderBottom:"1px solid "+C.border}}>
              <span style={{color:C.textDim}}>{formatAgo(log.created_at)}</span>
              <span>{log.operation}</span>
              <span style={{color:log.status==="success"?C.green:C.red}}>{log.status}</span>
              <span style={{fontFamily:"monospace",fontSize:10,color:C.textDim}}>{String(log.key_id||"").slice(0,16)}</span>
              <span style={{color:C.red,fontSize:10}}>{log.error_message||""}</span>
            </div>))}
          </div>
        )
      )}
    </Modal>)}

    {/* ── BitLocker Deploy Modal ── */}
    {modal==="bitlocker-deploy"&&(<Modal open={true} title="Register BitLocker Client" onClose={()=>setModal(null)}>
      {!bitLockerDeployPackage?(<>
        <Row2>
          <FG label="Client Name"><Inp value={bitLockerForm.name} onChange={(e)=>setBitLockerForm({...bitLockerForm,name:e.target.value})} placeholder="DESKTOP-WIN01"/></FG>
          <FG label="Host / IP"><Inp value={bitLockerForm.host} onChange={(e)=>setBitLockerForm({...bitLockerForm,host:e.target.value})} placeholder="10.0.0.100"/></FG>
        </Row2>
        <Row2>
          <FG label="OS Version"><Inp value={bitLockerForm.os_version} onChange={(e)=>setBitLockerForm({...bitLockerForm,os_version:e.target.value})}/></FG>
          <FG label="Volume"><Inp value={bitLockerForm.mount_point} onChange={(e)=>setBitLockerForm({...bitLockerForm,mount_point:e.target.value})}/></FG>
        </Row2>
        <FG label="Heartbeat (sec)"><Inp type="number" value={bitLockerForm.heartbeat_interval_sec} onChange={(e)=>setBitLockerForm({...bitLockerForm,heartbeat_interval_sec:Number(e.target.value)})}/></FG>
        <div style={{display:"flex",gap:8,marginTop:12}}>
          <Btn onClick={submitBitLockerDeploy} disabled={bitLockerDeploying}>{bitLockerDeploying?"Registering...":"Register Client"}</Btn>
          <Btn onClick={()=>setModal(null)}>Cancel</Btn>
        </div>
      </>):(<>
        <div style={{color:C.green,marginBottom:8,fontSize:12}}>Client registered. Download and deploy on the Windows host:</div>
        {Array.isArray(bitLockerDeployPackage.files)&&bitLockerDeployPackage.files.map((file,i)=>(<Card key={i} style={{marginBottom:8}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:4}}>
            <B style={{fontSize:13}}>{file.path}</B>
            <Btn onClick={()=>downloadText(file.path,file.content)} style={{fontSize:11,padding:"3px 8px"}}>Download</Btn>
          </div>
          <pre style={{fontSize:11,maxHeight:160,overflow:"auto",background:C.surface,padding:8,borderRadius:4,whiteSpace:"pre-wrap"}}>{String(file.content||"").slice(0,2000)}</pre>
        </Card>))}
      </>)}
    </Modal>)}

    {/* ── BitLocker Delete Modal ── */}
    {modal==="bitlocker-delete"&&bitLockerDeleteTarget&&(<Modal open={true} title={`Delete: ${bitLockerDeleteTarget.name}`} onClose={()=>setModal(null)}>
      {bitLockerDeleteLoading?(<div style={{textAlign:"center",color:C.textDim,fontSize:12}}>Loading preview...</div>):(<>
        {bitLockerDeletePreview&&(<div style={{marginBottom:12}}>
          <div style={{fontSize:12,color:C.textDim}}>Host: {bitLockerDeletePreview.host}</div>
          <div style={{fontSize:12,color:C.textDim}}>Recovery keys available: {bitLockerDeletePreview.recovery_keys_available}</div>
          {bitLockerDeletePreview.latest_recovery_key_masked&&(<div style={{fontSize:12,color:C.amber}}>Latest recovery key (masked): {bitLockerDeletePreview.latest_recovery_key_masked}</div>)}
          {bitLockerDeletePreview.latest_recovery_key&&(<div style={{fontSize:12,color:C.red,fontFamily:"monospace",background:C.surface,padding:6,borderRadius:4,marginTop:4}}>Full key: {bitLockerDeletePreview.latest_recovery_key}</div>)}
        </div>)}
        <Chk label="I confirm that the recovery key has been backed up securely" checked={bitLockerDeleteConfirmBackup} onChange={(e)=>setBitLockerDeleteConfirmBackup(e.target.checked)}/>
        <div style={{display:"flex",gap:8,marginTop:12}}>
          <Btn onClick={submitBitLockerDelete} disabled={bitLockerDeleteSubmitting||!bitLockerDeleteConfirmBackup} style={{color:C.red}}>{bitLockerDeleteSubmitting?"Deleting...":"Delete Client"}</Btn>
          <Btn onClick={()=>setModal(null)}>Cancel</Btn>
        </div>
      </>)}
    </Modal>)}

    {/* ── BitLocker Network Scan Modal ── */}
    {modal==="bitlocker-scan"&&(<Modal open={true} title="Network Scan for Windows Endpoints" onClose={()=>setModal(null)}>
      <Row2>
        <FG label="IP Range (CIDR or start-end)"><Inp value={bitLockerScanForm.ip_range} onChange={(e)=>setBitLockerScanForm({...bitLockerScanForm,ip_range:e.target.value})} placeholder="10.0.0.0/24 or 10.0.0.1-10.0.0.254"/></FG>
        <FG label="Max Hosts"><Inp type="number" value={bitLockerScanForm.max_hosts} onChange={(e)=>setBitLockerScanForm({...bitLockerScanForm,max_hosts:Number(e.target.value)})}/></FG>
      </Row2>
      <Row2>
        <FG label="Concurrency"><Inp type="number" value={bitLockerScanForm.concurrency} onChange={(e)=>setBitLockerScanForm({...bitLockerScanForm,concurrency:Number(e.target.value)})}/></FG>
        <FG label="Port Timeout (ms)"><Inp type="number" value={bitLockerScanForm.port_timeout_ms} onChange={(e)=>setBitLockerScanForm({...bitLockerScanForm,port_timeout_ms:Number(e.target.value)})}/></FG>
      </Row2>
      <Chk label="Require WinRM (higher confidence)" checked={bitLockerScanForm.require_winrm} onChange={(e)=>setBitLockerScanForm({...bitLockerScanForm,require_winrm:e.target.checked})}/>
      <div style={{display:"flex",gap:8,marginTop:12}}>
        <Btn onClick={runBitLockerScan} disabled={bitLockerScanRunning}>{bitLockerScanRunning?"Scanning...":"Run Scan"}</Btn>
      </div>

      {bitLockerScanResult&&(<div style={{marginTop:16}}>
        <div style={{fontSize:12,color:C.textDim,marginBottom:8}}>Scanned {bitLockerScanResult.scanned_hosts} hosts in {bitLockerScanResult.duration_ms}ms. Found {bitLockerScanResult.windows_hosts} Windows endpoint(s).</div>
        {bitLockerScanCandidates.length>0&&(<>
          <div style={{border:"1px solid "+C.border,borderRadius:8,overflow:"hidden",maxHeight:300,overflowY:"auto"}}>
            {bitLockerScanCandidates.map((row,i)=>(<div key={i} style={{display:"flex",alignItems:"center",gap:8,padding:"6px 10px",borderBottom:"1px solid "+C.border,fontSize:12}}>
              <Chk checked={Boolean(bitLockerScanSelected[row.ip])} onChange={()=>toggleBitLockerCandidate(row.ip)}/>
              <span style={{fontFamily:"monospace",minWidth:120}}>{row.ip}</span>
              <span style={{flex:1,color:C.textDim}}>{row.host}</span>
              <span style={{fontSize:11}}>{row.os_guess}</span>
              <span style={{fontSize:11,color:row.confidence==="high"?C.green:C.amber}}>{row.confidence}</span>
            </div>))}
          </div>
          <div style={{display:"flex",gap:8,marginTop:8}}>
            <Btn onClick={onboardScannedBitLocker} disabled={bitLockerOnboarding}>{bitLockerOnboarding?"Onboarding...":"Onboard Selected"}</Btn>
            <Btn onClick={()=>{const all={};bitLockerScanCandidates.forEach(r=>{all[r.ip]=true;});setBitLockerScanSelected(all);}}>Select All</Btn>
          </div>
        </>)}
      </div>)}
    </Modal>)}

    {/* ── BitLocker Activity Modal ── */}
    {modal==="bitlocker-activity"&&selectedAgent&&(<Modal open={true} title={`Activity: ${selectedAgent.name}`} onClose={()=>setModal(null)}>
      {bitLockerLoadingDetail?(<div style={{textAlign:"center",color:C.textDim,fontSize:12}}>Loading...</div>):(<>
        <B style={{fontSize:13,marginBottom:8,display:"block"}}>Jobs ({bitLockerJobs.length})</B>
        {bitLockerJobs.length===0?(<div style={{color:C.textDim,fontSize:12}}>No jobs found.</div>):(
          <div style={{maxHeight:250,overflow:"auto",marginBottom:16}}>
            {bitLockerJobs.map((job,i)=>(<div key={job.id||i} style={{padding:"6px 0",borderBottom:"1px solid "+C.border,fontSize:12}}>
              <div><B>{job.operation}</B> - <span style={{color:job.status==="succeeded"?C.green:job.status==="failed"?C.red:C.amber}}>{job.status}</span></div>
              <div style={{color:C.textDim,fontSize:11}}>Requested: {formatAgo(job.requested_at)} by {job.requested_by}</div>
              {job.error_message&&(<div style={{color:C.red,fontSize:11}}>{job.error_message}</div>)}
            </div>))}
          </div>
        )}
        <B style={{fontSize:13,marginBottom:8,display:"block"}}>Recovery Keys ({bitLockerRecovery.length})</B>
        {bitLockerRecovery.length===0?(<div style={{color:C.textDim,fontSize:12}}>No recovery keys stored.</div>):(
          <div style={{maxHeight:200,overflow:"auto"}}>
            {bitLockerRecovery.map((rec,i)=>(<div key={rec.id||i} style={{padding:"6px 0",borderBottom:"1px solid "+C.border,fontSize:12}}>
              <div style={{fontFamily:"monospace",fontSize:11}}>{rec.key_masked||rec.key_fingerprint}</div>
              <div style={{color:C.textDim,fontSize:11}}>Volume: {rec.volume_mount_point} | Protector: {rec.protector_id||"n/a"} | {formatAgo(rec.created_at)}</div>
            </div>))}
          </div>
        )}
      </>)}
    </Modal>)}

    {/* ── BitLocker Operations Modal ── */}
    {modal==="bitlocker-options"&&selectedAgent&&(<Modal open={true} title={`Operations: ${selectedAgent.name}`} onClose={()=>setModal(null)}>
      <div style={{fontSize:12,color:C.textDim,marginBottom:12}}>Queue a BitLocker operation for {selectedAgent.name} ({selectedAgent.host}):</div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
        {[
          {op:"enable",desc:"Enable BitLocker encryption"},
          {op:"disable",desc:"Disable BitLocker encryption"},
          {op:"pause",desc:"Pause encryption/decryption"},
          {op:"resume",desc:"Resume encryption/decryption"},
          {op:"rotate",desc:"Rotate BitLocker protectors"},
          {op:"fetch_recovery",desc:"Fetch and store recovery key"}
        ].map(({op,desc})=>(<Btn key={op} onClick={()=>{setModal(null);runBitLockerOperation(selectedAgent,op);}} disabled={bitLockerOpClientID===`${selectedAgent.id}:${op}`} style={{textAlign:"left",padding:"8px 12px"}}>
          <B style={{fontSize:12,textTransform:"capitalize"}}>{op.replace("_"," ")}</B>
          <div style={{fontSize:11,color:C.textDim}}>{desc}</div>
        </Btn>))}
      </div>
    </Modal>)}

    {/* ── Azure Add Config Modal ── */}
    {modal==="azure-add-config"&&(<Modal open={true} title="Add Azure Key Vault Connection" onClose={()=>setModal(null)}>
      <FG label="Azure AD Tenant ID"><Inp value={azureConfigForm.azure_tenant_id} onChange={(e)=>setAzureConfigForm({...azureConfigForm,azure_tenant_id:e.target.value})} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"/></FG>
      <Row2>
        <FG label="Vault Name"><Inp value={azureConfigForm.vault_name} onChange={(e)=>setAzureConfigForm({...azureConfigForm,vault_name:e.target.value})} placeholder="my-keyvault"/></FG>
        <FG label="Vault URL (auto-generated if empty)"><Inp value={azureConfigForm.vault_url} onChange={(e)=>setAzureConfigForm({...azureConfigForm,vault_url:e.target.value})} placeholder="https://my-keyvault.vault.azure.net"/></FG>
      </Row2>
      <Row2>
        <FG label="Subscription ID"><Inp value={azureConfigForm.subscription_id} onChange={(e)=>setAzureConfigForm({...azureConfigForm,subscription_id:e.target.value})}/></FG>
        <FG label="Resource Group"><Inp value={azureConfigForm.resource_group} onChange={(e)=>setAzureConfigForm({...azureConfigForm,resource_group:e.target.value})}/></FG>
      </Row2>
      <Row2>
        <FG label="Managed HSM Name (optional)"><Inp value={azureConfigForm.managed_hsm_name} onChange={(e)=>setAzureConfigForm({...azureConfigForm,managed_hsm_name:e.target.value})}/></FG>
        <FG label="Managed HSM URL (optional)"><Inp value={azureConfigForm.managed_hsm_url} onChange={(e)=>setAzureConfigForm({...azureConfigForm,managed_hsm_url:e.target.value})}/></FG>
      </Row2>
      <FG label="Auth Mode"><Sel value={azureConfigForm.auth_mode} onChange={(e)=>setAzureConfigForm({...azureConfigForm,auth_mode:e.target.value})}>
        <option value="client_secret">Client Secret</option><option value="managed_identity">Managed Identity</option><option value="certificate">Certificate</option>
      </Sel></FG>
      <Row2>
        <FG label="Client ID (App Registration)"><Inp value={azureConfigForm.client_id} onChange={(e)=>setAzureConfigForm({...azureConfigForm,client_id:e.target.value})}/></FG>
        <FG label="Client Secret"><Inp type="password" value={azureConfigForm.client_secret} onChange={(e)=>setAzureConfigForm({...azureConfigForm,client_secret:e.target.value})}/></FG>
      </Row2>
      <div style={{fontSize:11,color:C.textDim,marginTop:4}}>Vecta KMS will authenticate to Azure AD and manage keys in the specified Key Vault as an external key provider.</div>
      <div style={{display:"flex",gap:8,marginTop:12}}>
        <Btn onClick={async()=>{
          setAzureLoading(true);
          try{
            await createAzureEKMConfig(session,azureConfigForm);
            onToast?.("Azure vault config created");
            setModal(null);
            setAzureConfigForm({azure_tenant_id:"",subscription_id:"",resource_group:"",vault_name:"",vault_url:"",managed_hsm_name:"",managed_hsm_url:"",client_id:"",client_secret:"",auth_mode:"client_secret"});
            await refresh(true);
          }catch(e){onToast?.(`Failed: ${errMsg(e)}`);}finally{setAzureLoading(false);}
        }} disabled={azureLoading||!azureConfigForm.azure_tenant_id||!azureConfigForm.vault_name}>{azureLoading?"Creating...":"Create Config"}</Btn>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
      </div>
    </Modal>)}

    {/* ── Azure Add Mapping Modal ── */}
    {modal==="azure-add-mapping"&&(<Modal open={true} title="Add Key Mapping" onClose={()=>setModal(null)}>
      <FG label="Vault Config"><Sel value={azureMappingForm.config_id} onChange={(e)=>setAzureMappingForm({...azureMappingForm,config_id:e.target.value})}>
        <option value="">Select a vault...</option>
        {azureConfigs.map(c=>(<option key={c.id} value={c.id}>{c.vault_name} ({c.vault_url})</option>))}
      </Sel></FG>
      <Row2>
        <FG label="Vecta Key ID"><Inp value={azureMappingForm.vecta_key_id} onChange={(e)=>setAzureMappingForm({...azureMappingForm,vecta_key_id:e.target.value})} placeholder="key-xxxxxxxxxx"/></FG>
        <FG label="Azure Key Name"><Inp value={azureMappingForm.azure_key_name} onChange={(e)=>setAzureMappingForm({...azureMappingForm,azure_key_name:e.target.value})} placeholder="vecta-tde-key-01"/></FG>
      </Row2>
      <FG label="Purpose"><Sel value={azureMappingForm.purpose} onChange={(e)=>setAzureMappingForm({...azureMappingForm,purpose:e.target.value})}>
        <option value="tde">TDE (Database Encryption)</option><option value="always_encrypted">Always Encrypted</option><option value="storage">Azure Storage Encryption</option><option value="disk">Azure Disk Encryption</option>
      </Sel></FG>
      <div style={{fontSize:11,color:C.textDim,marginTop:4}}>Maps a Vecta KMS key to an Azure Key Vault key. Use "Import" after creation to push the key to Azure.</div>
      <div style={{display:"flex",gap:8,marginTop:12}}>
        <Btn onClick={async()=>{
          setAzureLoading(true);
          try{
            await createAzureKeyMapping(session,azureMappingForm);
            onToast?.("Key mapping created");
            setModal(null);
            setAzureMappingForm({config_id:"",vecta_key_id:"",azure_key_name:"",purpose:"tde"});
            await refresh(true);
          }catch(e){onToast?.(`Failed: ${errMsg(e)}`);}finally{setAzureLoading(false);}
        }} disabled={azureLoading||!azureMappingForm.config_id||!azureMappingForm.vecta_key_id||!azureMappingForm.azure_key_name}>{azureLoading?"Creating...":"Create Mapping"}</Btn>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
      </div>
    </Modal>)}

    {/* ── Azure Wrap Key Modal ── */}
    {modal==="azure-wrap"&&(<Modal open={true} title="Wrap Key (Azure Key Vault)" onClose={()=>setModal(null)}>
      <FG label="Plaintext (Base64)"><Inp value={azureMappingForm.vecta_key_id} onChange={(e)=>setAzureMappingForm({...azureMappingForm,vecta_key_id:e.target.value})} placeholder="Base64-encoded plaintext"/></FG>
      <div style={{display:"flex",gap:8,marginTop:12}}>
        <Btn onClick={async()=>{
          setAzureLoading(true);
          try{
            const res=await wrapAzureKey(session,azureMappingForm.config_id,azureMappingForm.vecta_key_id);
            onToast?.("Wrapped successfully");
            setAzureMappingForm(prev=>({...prev,azure_key_name:res.wrapped}));
          }catch(e){onToast?.(`Wrap failed: ${errMsg(e)}`);}finally{setAzureLoading(false);}
        }} disabled={azureLoading}>{azureLoading?"Wrapping...":"Wrap"}</Btn>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
      </div>
      {azureMappingForm.azure_key_name&&azureMappingForm.azure_key_name.length>20&&(<div style={{marginTop:12}}>
        <B style={{fontSize:12}}>Wrapped Result:</B>
        <pre style={{fontSize:10,background:C.surface,padding:8,borderRadius:4,maxHeight:120,overflow:"auto",wordBreak:"break-all"}}>{azureMappingForm.azure_key_name}</pre>
      </div>)}
    </Modal>)}

    {/* ── Azure Unwrap Key Modal ── */}
    {modal==="azure-unwrap"&&(<Modal open={true} title="Unwrap Key (Azure Key Vault)" onClose={()=>setModal(null)}>
      <FG label="Ciphertext (Base64)"><Inp value={azureMappingForm.vecta_key_id} onChange={(e)=>setAzureMappingForm({...azureMappingForm,vecta_key_id:e.target.value})} placeholder="Base64-encoded ciphertext"/></FG>
      <div style={{display:"flex",gap:8,marginTop:12}}>
        <Btn onClick={async()=>{
          setAzureLoading(true);
          try{
            const res=await unwrapAzureKey(session,azureMappingForm.config_id,azureMappingForm.vecta_key_id);
            onToast?.("Unwrapped successfully");
            setAzureMappingForm(prev=>({...prev,azure_key_name:res.unwrapped}));
          }catch(e){onToast?.(`Unwrap failed: ${errMsg(e)}`);}finally{setAzureLoading(false);}
        }} disabled={azureLoading}>{azureLoading?"Unwrapping...":"Unwrap"}</Btn>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
      </div>
      {azureMappingForm.azure_key_name&&azureMappingForm.azure_key_name.length>20&&(<div style={{marginTop:12}}>
        <B style={{fontSize:12}}>Unwrapped Result:</B>
        <pre style={{fontSize:10,background:C.surface,padding:8,borderRadius:4,maxHeight:120,overflow:"auto",wordBreak:"break-all"}}>{azureMappingForm.azure_key_name}</pre>
      </div>)}
    </Modal>)}

    {promptDialog.ui}
  </div>);
};
