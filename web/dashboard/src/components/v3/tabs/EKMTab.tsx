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
  rotateEKMAgentKey
} from "../../../lib/ekm";
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
  const [dbRegForm,setDbRegForm]=useState({ agent_id:"", name:"", engine:"mssql", host:"", port:1433, database_name:"" });
  const [dbRegistering,setDbRegistering]=useState(false);

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
    setModal("deploy");
  };

  /* ── Register database ── */
  const openDbRegister=()=>{
    setDbRegForm({agent_id:agents.length?agents[0].id:"",name:"",engine:"mssql",host:"",port:1433,database_name:""});
    setModal("db-register");
  };

  const submitDbRegister=async()=>{
    const agentId=String(dbRegForm.agent_id||"").trim();
    const name=String(dbRegForm.name||"").trim();
    if(!agentId||!name){ onToast?.("Agent and database name are required."); return; }
    setDbRegistering(true);
    try{
      await registerEKMDatabase(session,{
        agent_id:agentId, name, engine:dbRegForm.engine,
        host:String(dbRegForm.host||"").trim(),
        port:Number(dbRegForm.port)||1433,
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
    try{ selected=await getBitLockerClient(session,clientID); }catch{}
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
          <div style={{display:"grid",gridTemplateColumns:"2fr 1fr 1fr 1fr 1fr 1fr",padding:"8px 12px",background:C.surface,fontSize:11,fontWeight:600,color:C.textDim,borderBottom:"1px solid "+C.border}}>
            <span>Database</span><span>Engine</span><span>Agent</span><span>Host</span><span>TDE State</span><span>Last Seen</span>
          </div>
          {databases.map(db=>(<div key={db.id} style={{display:"grid",gridTemplateColumns:"2fr 1fr 1fr 1fr 1fr 1fr",padding:"8px 12px",fontSize:12,borderBottom:"1px solid "+C.border}}>
            <span><B>{db.name}</B>{db.database_name&&db.database_name!==db.name&&(<span style={{color:C.textDim,fontSize:11}}> ({db.database_name})</span>)}</span>
            <span>{db.engine.toUpperCase()}</span>
            <span style={{fontSize:11,color:C.textDim}}>{agents.find(a=>a.id===db.agent_id)?.name||db.agent_id}</span>
            <span style={{color:C.textDim}}>{db.host}{db.port>0?`:${db.port}`:""}</span>
            <span><span style={{padding:"2px 6px",borderRadius:4,fontSize:10,fontWeight:600,background:db.tde_enabled?C.greenDim:"transparent",color:db.tde_enabled?C.green:C.muted}}>{db.tde_state||"unknown"}</span></span>
            <span style={{color:C.textDim}}>{formatAgo(db.last_seen_at)}</span>
          </div>))}
        </div>
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
        <FG label="Engine"><Sel value={dbRegForm.engine} onChange={(e)=>setDbRegForm({...dbRegForm,engine:e.target.value})}>
          <option value="mssql">MSSQL</option><option value="oracle">Oracle</option>
        </Sel></FG>
      </Row2>
      <Row2>
        <FG label="Host"><Inp value={dbRegForm.host} onChange={(e)=>setDbRegForm({...dbRegForm,host:e.target.value})} placeholder="db-server.local"/></FG>
        <FG label="Port"><Inp type="number" value={dbRegForm.port} onChange={(e)=>setDbRegForm({...dbRegForm,port:Number(e.target.value)})}/></FG>
      </Row2>
      <FG label="Catalog / SID"><Inp value={dbRegForm.database_name} onChange={(e)=>setDbRegForm({...dbRegForm,database_name:e.target.value})} placeholder="AdventureWorks"/></FG>
      <div style={{fontSize:11,color:C.textDim,marginTop:4}}>A TDE key will be auto-provisioned via KeyCore for this database.</div>
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
            <option value="mssql">MSSQL</option><option value="oracle">Oracle</option>
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
        <div style={{color:C.green,marginBottom:8,fontSize:12}}>Agent registered. Download and deploy these files on the target host:</div>
        {visibleDeployFiles.map((file,i)=>(<Card key={i} style={{marginBottom:8}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:4}}>
            <B style={{fontSize:13}}>{file.path}</B>
            <Btn onClick={()=>downloadText(file.path,file.content)} style={{fontSize:11,padding:"3px 8px"}}>Download</Btn>
          </div>
          <pre style={{fontSize:11,maxHeight:160,overflow:"auto",background:C.surface,padding:8,borderRadius:4,whiteSpace:"pre-wrap"}}>{String(file.content||"").slice(0,2000)}</pre>
        </Card>))}
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

    {promptDialog.ui}
  </div>);
};
