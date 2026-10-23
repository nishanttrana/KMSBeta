// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { useEffect, useMemo, useState } from "react";
import { Cpu, LayoutGrid, List, Monitor, PauseCircle, RefreshCcw, ShieldCheck, WifiOff } from "lucide-react";
import { B, Btn, Card, Chk, FG, Inp, Modal, Row2, Sel, Stat, usePromptDialog } from "../legacyPrimitives";
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
  listEKMAgents,
  listEKMDatabases,
  registerEKMDatabase,
  queueBitLockerOperation,
  registerBitLockerClient,
  scanBitLockerWindows,
  revokeDatabaseTDE,
  listGoogleCSEConfigs,
  createGoogleCSEConfig,
  deleteGoogleCSEConfig,
  updateGoogleCSEConfig,
  listGoogleCSEKeys,
  createGoogleCSEKey,
  deleteGoogleCSEKey
} from "../../../lib/ekm";
import { EKMClients } from "./ekm/Clients";
import { KMIPTab } from "./KMIPTab";
import { Kubernetes } from "./ekm/Kubernetes";
import { EdgeDevices } from "./ekm/EdgeDevices";

/* ── Setup guide content per DB engine ── */
/* ── Setup guide per DB engine ──
   Vecta holds a TDE master key only through its KMIP server (mTLS, port 5696).
   Engines without a KMIP key manager have no Vecta integration and say so. */
const splitList=(v:string)=>v.split(",").map(x=>x.trim()).filter(Boolean);
const KMIP_PREREQ = "1. Register a KMIP client in the KMIP tab: it issues the client certificate and key. Trust the Vecta internal CA; connect to <kms-host>:5696.";
const NOT_SUPPORTED_NOTE = "The EKM agent still reports this database's TDE state; add it with Add client to monitor it.";
const SETUP_GUIDES: Record<string, { title: string; steps: string[] }> = {
  mssql: {
    title: "SQL Server TDE: not supported by Vecta",
    steps: [
      "SQL Server keeps a TDE key in an external manager only through an EKM provider DLL implementing its EKM interface. Vecta ships none, so SQL Server TDE keys are not held in Vecta.",
      NOT_SUPPORTED_NOTE
    ]
  },
  oracle: {
    title: "Oracle TDE: not supported by Vecta",
    steps: [
      "Oracle TDE keeps its master key in a software keystore, Oracle Key Vault, or an HSM through a PKCS#11 library. Vecta provides none of these, so Oracle TDE keys are not held in Vecta.",
      NOT_SUPPORTED_NOTE
    ]
  },
  postgresql: {
    title: "PostgreSQL TDE with Percona pg_tde (KMIP)",
    steps: [
      KMIP_PREREQ,
      "2. Register a KMIP key provider in pg_tde pointing at <kms-host>:5696 with the client certificate, key and Vecta internal CA.",
      "3. Make it the principal key provider for the database (function names differ between pg_tde releases; use your version's documentation).",
      "Community PostgreSQL has no built-in TDE."
    ]
  },
  mysql: {
    title: "MySQL Enterprise TDE with keyring_okv (KMIP)",
    steps: [
      KMIP_PREREQ,
      "2. In my.cnf:\n   [mysqld]\n   early-plugin-load=keyring_okv.so\n   keyring_okv_conf_dir=/usr/local/mysql/mysql-keyring-okv",
      "3. In keyring_okv_conf_dir create okvclient.ora containing SERVER=<kms-host>:5696, and an ssl/ directory with CA.pem (Vecta internal CA), cert.pem and key.pem (the KMIP client certificate and key).",
      "4. Restart mysqld, then encrypt: ALTER TABLE sensitive_data ENCRYPTION='Y';",
      "MariaDB's key plugins do not speak KMIP, so MariaDB is not supported."
    ]
  },
  db2: {
    title: "Db2 native encryption with a KMIP key manager",
    steps: [
      KMIP_PREREQ,
      "2. Configure Db2 native encryption with KEYSTORE_TYPE KMIP and a KMIP configuration file naming <kms-host>:5696, the client certificate, key and Vecta internal CA (see IBM's documentation for your Db2 release)."
    ]
  }
};

export const EKMTab=({session,onToast,subView,onSubViewChange,onNavigate,keyCatalog}:any)=>{
  const [loading,setLoading]=useState(false);
  const [agents,setAgents]=useState([]);
  const [databases,setDatabases]=useState([]);
  const [modal,setModal]=useState(null);
  const [selectedAgent,setSelectedAgent]=useState(null);
  const [guideEngine,setGuideEngine]=useState("mssql");
  const [dbRegForm,setDbRegForm]=useState({ agent_id:"", name:"", engine:"mssql", host:"", port:1433, database_name:"", rotation_policy:"90" });
  const [dbRegistering,setDbRegistering]=useState(false);
  const [revokingDbId,setRevokingDbId]=useState("");
  const [expandedTdeGuide,setExpandedTdeGuide]=useState<Record<string,boolean>>({});

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
  const [bitLockerView,setBitLockerView]=useState<"cards"|"list">("cards");
  const [bitLockerSearch,setBitLockerSearch]=useState("");
  const promptDialog=usePromptDialog();


  /* ── Google CSE state ── */
  const [googleCSEConfigs,setGoogleCSEConfigs]=useState<any[]>([]);
  const [googleCSEKeys,setGoogleCSEKeys]=useState<any[]>([]);
  const [googleCSELoading,setGoogleCSELoading]=useState(false);
  const [googleCSEConfigForm,setGoogleCSEConfigForm]=useState({
    google_workspace_customer_id:"", service_account_email:"",
    allowed_domains:"", authentication_client_ids:"", kacls_endpoint:""
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

  const safeFileName=(name)=>String(name||"file").replace(/[^a-zA-Z0-9._-]/g,"_");
  const downloadText=(name,content)=>{
    const blob=new Blob([String(content||"")],{type:"text/plain;charset=utf-8"});
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url;a.download=safeFileName(name);document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);
  };

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
    if(!policyDays||policyDays<=0) return {label:"No policy",color:C.dim,policyDays:0};
    const lastRotated=db.updated_at||db.created_at||"";
    const ts=new Date(String(lastRotated||"")).getTime();
    if(!Number.isFinite(ts)) return {label:"Unknown",color:C.dim,policyDays};
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

  /* ── Data fetching ── */
  const refresh=async(silent=false)=>{
    if(!silent) setLoading(true);
    try{
      const items=await listEKMAgents(session);
      setAgents(items);
      try{ const dbItems=await listEKMDatabases(session); setDatabases(Array.isArray(dbItems)?dbItems:[]); }catch{ setDatabases([]); }
      try{ const blItems=await listBitLockerClients(session,1000); setBitLockerClients(Array.isArray(blItems)?blItems:[]); }catch{ setBitLockerClients([]); }
      try{ const gcseC=await listGoogleCSEConfigs(session); setGoogleCSEConfigs(Array.isArray(gcseC)?gcseC:[]); }catch{ setGoogleCSEConfigs([]); }
      try{ const gcseK=await listGoogleCSEKeys(session); setGoogleCSEKeys(Array.isArray(gcseK)?gcseK:[]); }catch{ setGoogleCSEKeys([]); }
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
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: intentional refetch on listed keys / run-once-on-mount; the only omitted dep is a per-render load/refresh closure (wrap in useCallback to drop this suppression). behaviour verified correct.
  },[session?.token,session?.tenantId]);

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
  const filteredBitLocker=useMemo(()=>{
    if(!bitLockerSearch.trim()) return bitLockerClients;
    const q=bitLockerSearch.trim().toLowerCase();
    return bitLockerClients.filter((c)=>String(c.name||"").toLowerCase().includes(q)||String(c.host||"").toLowerCase().includes(q)||String(c.id||"").toLowerCase().includes(q));
  },[bitLockerClients,bitLockerSearch]);

  /* ──────────── RENDER ──────────── */
  return (<div>
    {/* ═══════════════════════ DB SUBTAB ═══════════════════════ */}
    {subView==="db"&&(<div>
      <EKMClients session={session} onToast={onToast} onChanged={()=>{void refresh(true);}}/>

      {/* ── Database Inventory section ── */}
      <div style={{marginTop:24}}>
        <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8,flexWrap:"wrap"}}>
          <span style={{fontSize:14,fontWeight:600,color:C.text}}>Database Inventory ({databases.length})</span>
          <span style={{flex:1}}/>
          <Btn small onClick={openDbRegister} disabled={!agents.length}>Register Database</Btn>
          <Btn small onClick={()=>setModal("setup-guide")}>Setup Guide</Btn>
        </div>
        {databases.length===0&&(<Card><div style={{textAlign:"center",color:C.dim,padding:20,fontSize:12}}>No databases registered.</div></Card>)}
        {databases.length>0&&(<div style={{border:"1px solid "+C.border,borderRadius:4,overflow:"hidden"}}>
          <div style={{display:"grid",gridTemplateColumns:"2fr 1fr 1fr 1fr 1fr 1fr 1fr 100px",padding:"8px 12px",background:C.surface,fontSize:11,fontWeight:600,color:C.dim,borderBottom:"1px solid "+C.border}}>
            <span>Database</span><span>Engine</span><span>Agent</span><span>Host</span><span>TDE State</span><span>Rotation</span><span>Last Seen</span><span>Actions</span>
          </div>
          {databases.map(db=>{
            const badge=dbStatusBadge(db);
            const rotComp=dbRotationCompliance(db);
            return (<div key={db.id}>
              <div style={{display:"grid",gridTemplateColumns:"2fr 1fr 1fr 1fr 1fr 1fr 1fr 100px",padding:"8px 12px",fontSize:12,borderBottom:"1px solid "+C.border,alignItems:"center"}}>
                <span><B>{db.name}</B>{db.database_name&&db.database_name!==db.name&&(<span style={{color:C.dim,fontSize:11}}> ({db.database_name})</span>)}</span>
                <span>{db.engine.toUpperCase()}</span>
                <span style={{fontSize:11,color:C.dim}}>{agents.find(a=>a.id===db.agent_id)?.name||db.agent_id}</span>
                <span style={{color:C.dim}}>{db.host}{db.port>0?`:${db.port}`:""}</span>
                <span><span style={{padding:"2px 6px",borderRadius:4,fontSize:10,fontWeight:600,background:badge.bg,color:badge.fg}}>{badge.label}</span></span>
                <span style={{color:rotComp.color,fontSize:11,fontWeight:500}}>{rotComp.label}</span>
                <span style={{color:C.dim}}>{formatAgo(db.last_seen_at)}</span>
                <span style={{display:"flex",gap:4}}>
                  <Btn onClick={()=>setExpandedTdeGuide(prev=>({...prev,[db.id]:!prev[db.id]}))} style={{fontSize:10,padding:"2px 6px"}}>Guide</Btn>
                  <Btn onClick={()=>runRevokeTDE(db)} disabled={revokingDbId===db.id||badge.label==="Key Revoked"} style={{fontSize:10,padding:"2px 6px",color:C.redFg}}>{revokingDbId===db.id?"...":"Revoke"}</Btn>
                </span>
              </div>
              {/* Collapsible TDE Setup Guide */}
              {expandedTdeGuide[db.id]&&(<div style={{padding:"12px 16px",background:C.surface+"44",borderBottom:"1px solid "+C.border,fontSize:12}}>
                <B style={{fontSize:12,marginBottom:6,display:"block"}}>TDE Setup Guide for {db.engine.toUpperCase()}</B>
                {SETUP_GUIDES[db.engine]?(
                  <div>{SETUP_GUIDES[db.engine].steps.map((step,i)=>(<div key={i} style={{fontSize:11,marginBottom:6,whiteSpace:"pre-wrap",fontFamily:step.includes("  ")?"monospace":"inherit",color:step.includes("  ")?C.accentFg:C.text,background:step.includes("  ")?C.surface:"transparent",padding:step.includes("  ")?"4px 8px":0,borderRadius:4}}>{step}</div>))}</div>
                ):(<div style={{color:C.dim}}>No setup guide available for {db.engine.toUpperCase()}.</div>)}
              </div>)}
            </div>);
          })}
        </div>)}
      </div>

    </div>)}

    {/* ═══════════════════════ BITLOCKER SUBTAB ═══════════════════════ */}
    {subView==="bitlocker"&&(<div>
      {/* ── Summary stats bar ── */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))",gap:10,marginBottom:16}}>
        <Stat l="Clients" v={blStats.total} i={Monitor}/>
        <Stat l="Protected" v={blStats.protected} i={ShieldCheck}/>
        <Stat l="Suspended" v={blStats.suspended} c={blStats.suspended>0?"amber":"accent"} i={PauseCircle}/>
        <Stat l="Down" v={blStats.down} c={blStats.down>0?"red":"accent"} i={WifiOff}/>
        <Stat l="TPM ready" v={blStats.tpmReady} i={Cpu}/>
      </div>

      {/* ── Toolbar ── */}
      <div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap",alignItems:"center"}}>
        <Inp placeholder="Search clients..." value={bitLockerSearch} onChange={(e)=>setBitLockerSearch(e.target.value)} style={{flex:1,minWidth:180,maxWidth:320}}/>
        <Btn onClick={()=>setBitLockerView(bitLockerView==="cards"?"list":"cards")} style={{padding:"6px 10px"}}>{bitLockerView==="cards"?<List size={15}/>:<LayoutGrid size={15}/>}</Btn>
        <Btn onClick={openBitLockerDeploy}>Register Client</Btn>
        <Btn onClick={openBitLockerScan}>Network Scan</Btn>
        <Btn onClick={()=>refresh(false)} disabled={loading}><RefreshCcw size={14}/></Btn>
      </div>

      {filteredBitLocker.length===0?(<Card><div style={{textAlign:"center",color:C.dim,padding:32,fontSize:12}}>No BitLocker clients registered.{" "}<span style={{color:C.accentFg,cursor:"pointer"}} onClick={openBitLockerDeploy}>Register a client</span> or <span style={{color:C.accentFg,cursor:"pointer"}} onClick={openBitLockerScan}>scan your network</span></div></Card>):(
        bitLockerView==="cards"?(
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(300px,1fr))",gap:12}}>
            {filteredBitLocker.map((client)=>{
              const badge=bitLockerStatusBadge(client);
              return (<Card key={client.id}>
                <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
                  <span style={{padding:"2px 8px",borderRadius:4,fontSize:11,fontWeight:600,background:badge.bg,color:badge.fg}}>{badge.label}</span>
                  <B style={{fontSize:14}}>{client.name}</B>
                </div>
                <div style={{fontSize:12,color:C.dim,marginBottom:2}}>{client.host} | {client.os_version||"Windows"}</div>
                <div style={{fontSize:12,color:C.dim,marginBottom:2}}>Volume: {client.mount_point||"C:"} | Encryption: {(client.encryption_percentage||0).toFixed(0)}%</div>
                <div style={{fontSize:12,color:C.dim,marginBottom:2}}>TPM: {client.tpm_present?"Present":"Missing"} {client.tpm_ready?"(Ready)":"(Not ready)"}</div>
                <div style={{fontSize:12,color:C.dim,marginBottom:6}}>Heartbeat: {formatAgo(client.last_heartbeat_at)}</div>

                {/* Encryption progress bar */}
                <div style={{background:C.border,borderRadius:4,height:6,marginBottom:8}}>
                  <div style={{background:client.encryption_percentage>=100?C.green:C.blue,borderRadius:4,height:6,width:`${Math.min(100,client.encryption_percentage||0)}%`,transition:"width 0.3s"}}/>
                </div>

                <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                  {["enable","disable","pause","resume","rotate","fetch_recovery"].map((op)=>(<Btn key={op} onClick={()=>runBitLockerOperation(client,op)} disabled={bitLockerOpClientID===`${client.id}:${op}`} style={{fontSize:10,padding:"2px 6px",textTransform:"capitalize"}}>{bitLockerOpClientID===`${client.id}:${op}`?"...":op.replace("_"," ")}</Btn>))}
                  <Btn onClick={()=>openBitLockerActivity(client)} style={{fontSize:10,padding:"2px 6px"}}>Activity</Btn>
                  <Btn onClick={()=>openBitLockerDelete(client)} style={{fontSize:10,padding:"2px 6px",color:C.redFg}}>Delete</Btn>
                </div>
              </Card>);
            })}
          </div>
        ):(
          /* ── List view ── */
          <div style={{border:"1px solid "+C.border,borderRadius:4,overflow:"hidden"}}>
            <div style={{display:"grid",gridTemplateColumns:"2fr 1.5fr 1fr 1fr 1fr 1fr 140px",padding:"8px 12px",background:C.surface,fontSize:11,fontWeight:600,color:C.dim,borderBottom:"1px solid "+C.border}}>
              <span>Client</span><span>Host</span><span>Status</span><span>Encryption</span><span>TPM</span><span>Heartbeat</span><span>Actions</span>
            </div>
            {filteredBitLocker.map((client)=>{
              const badge=bitLockerStatusBadge(client);
              return (<div key={client.id} style={{display:"grid",gridTemplateColumns:"2fr 1.5fr 1fr 1fr 1fr 1fr 140px",padding:"8px 12px",fontSize:12,borderBottom:"1px solid "+C.border}}>
                <span><B>{client.name}</B></span>
                <span style={{color:C.dim}}>{client.host}</span>
                <span><span style={{padding:"2px 6px",borderRadius:4,fontSize:10,fontWeight:600,background:badge.bg,color:badge.fg}}>{badge.label}</span></span>
                <span>{(client.encryption_percentage||0).toFixed(0)}%</span>
                <span>{client.tpm_present&&client.tpm_ready?"Ready":client.tpm_present?"Present":"N/A"}</span>
                <span style={{color:C.dim}}>{formatAgo(client.last_heartbeat_at)}</span>
                <span style={{display:"flex",gap:4}}>
                  <Btn onClick={()=>openBitLockerActivity(client)} style={{fontSize:10,padding:"2px 6px"}}>Activity</Btn>
                  <Btn onClick={()=>openBitLockerOptions(client)} style={{fontSize:10,padding:"2px 6px"}}>Ops</Btn>
                  <Btn onClick={()=>openBitLockerDelete(client)} style={{fontSize:10,padding:"2px 6px",color:C.redFg}}>Del</Btn>
                </span>
              </div>);
            })}
          </div>
        )
      )}
    </div>)}

    {/* ═══════════════════════ GOOGLE CSE SUBTAB ═══════════════════════ */}
    {subView==="google-cse"&&(<div>
      {/* ── Summary stats bar ── */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(160px,1fr))",gap:10,marginBottom:16}}>
        <Stat l="CSE configs" v={googleCSEConfigs.length}/>
        <Stat l="CSE keys" v={googleCSEKeys.length}/>
        <Stat l="Active keys" v={googleCSEKeys.filter(k=>k.status==="active").length}/>
        <Stat l="Wraps" v={googleCSEKeys.reduce((s,k)=>s+(k.wrap_count||0),0)}/>
        <Stat l="Unwraps" v={googleCSEKeys.reduce((s,k)=>s+(k.unwrap_count||0),0)}/>
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
        <FG label="Authentication Client IDs (comma-separated)" hint="OAuth client ID(s) of the identity provider in your Workspace CSE settings. The authentication token's audience must be one of them."><Inp value={googleCSEConfigForm.authentication_client_ids} onChange={e=>setGoogleCSEConfigForm(p=>({...p,authentication_client_ids:e.target.value}))} placeholder="123456789-abc.apps.googleusercontent.com"/></FG>
        <Btn disabled={googleCSELoading||!googleCSEConfigForm.google_workspace_customer_id||!googleCSEConfigForm.authentication_client_ids.trim()} onClick={async()=>{
          setGoogleCSELoading(true);
          try{
            const domains=googleCSEConfigForm.allowed_domains.split(",").map(d=>d.trim()).filter(Boolean);
            await createGoogleCSEConfig(session,{
              google_workspace_customer_id:googleCSEConfigForm.google_workspace_customer_id,
              service_account_email:googleCSEConfigForm.service_account_email,
              allowed_domains:domains,
              authentication_client_ids:splitList(googleCSEConfigForm.authentication_client_ids),
              kacls_endpoint:googleCSEConfigForm.kacls_endpoint
            });
            onToast?.("Google CSE config created");
            setGoogleCSEConfigForm({google_workspace_customer_id:"",service_account_email:"",allowed_domains:"",authentication_client_ids:"",kacls_endpoint:""});
            await refresh(true);
          }catch(e){onToast?.(`Failed: ${errMsg(e)}`);}finally{setGoogleCSELoading(false);}
        }} style={{marginTop:8}}>{googleCSELoading?"Creating...":"Create Config"}</Btn>
      </Card>

      {/* ── CSE Configs list ── */}
      {googleCSEConfigs.length>0&&(<Card style={{padding:14,marginBottom:14}}>
        <B style={{fontSize:13,marginBottom:8,display:"block"}}>Workspace Configurations</B>
        <div style={{display:"flex",flexDirection:"column",gap:8}}>
          {googleCSEConfigs.map(cfg=>(<div key={cfg.id} style={{background:C.surface,borderRadius:4,padding:10,border:`1px solid ${C.border}`}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <div>
                <div style={{fontSize:12,fontWeight:600}}>{cfg.google_workspace_customer_id}</div>
                <div style={{fontSize:10,color:C.muted}}>{cfg.service_account_email||"No service account"} &middot; {(cfg.allowed_domains||[]).join(", ")}</div>
                <div style={{fontSize:10,color:(cfg.authentication_client_ids||[]).length?C.muted:C.redFg}}>Client IDs: {(cfg.authentication_client_ids||[]).join(", ")||"None: every authentication token is refused until set"}</div>
                <div style={{fontSize:10,color:C.muted}}>KACLS: {cfg.kacls_endpoint||"Not configured"} &middot; Keys: {cfg.key_count||0} &middot; Status: <span style={{color:cfg.status==="active"?C.greenFg||"#4ade80":C.redFg}}>{cfg.status}</span></div>
                {cfg.last_activity_at&&(<div style={{fontSize:10,color:C.muted}}>Last activity: {formatAgo(cfg.last_activity_at)}</div>)}
              </div>
              <div style={{display:"flex",gap:4}}>
                <Btn onClick={async()=>{
                  const v=await promptDialog.prompt({title:"Authentication Client IDs",message:"OAuth client ID(s) of your CSE identity provider, comma-separated.",defaultValue:(cfg.authentication_client_ids||[]).join(", "),confirmLabel:"Save",validate:(x:string)=>splitList(x).length?"":"Enter at least one client ID."});
                  if(v===null) return;
                  try{await updateGoogleCSEConfig(session,cfg.id,{authentication_client_ids:splitList(v)});onToast?.("Client IDs saved");await refresh(true);}catch(e){onToast?.(`Save failed: ${errMsg(e)}`);}
                }} style={{fontSize:10,padding:"3px 6px"}}>Client IDs</Btn>
                <Btn onClick={async()=>{
                  if(!confirm("Delete this Google CSE config?")) return;
                  try{await deleteGoogleCSEConfig(session,cfg.id);onToast?.("Config deleted");await refresh(true);}catch(e){onToast?.(`Delete failed: ${errMsg(e)}`);}
                }} style={{fontSize:10,padding:"3px 6px",color:C.redFg}}>Delete</Btn>
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
          {googleCSEKeys.map(k=>(<div key={k.id} style={{background:C.surface,borderRadius:4,padding:10,border:`1px solid ${C.border}`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
            <div>
              <div style={{fontSize:12,fontWeight:600}}>{k.key_name} <span style={{fontSize:10,fontWeight:400,color:C.muted}}>({k.purpose})</span></div>
              <div style={{fontSize:10,color:C.muted}}>Vecta Key: {k.vecta_key_id} &middot; Status: <span style={{color:k.status==="active"?C.greenFg||"#4ade80":C.redFg}}>{k.status}</span></div>
              <div style={{fontSize:10,color:C.muted}}>Wraps: {k.wrap_count||0} &middot; Unwraps: {k.unwrap_count||0}{k.last_used_at?` \u00b7 Last used: ${formatAgo(k.last_used_at)}`:""}</div>
              <div style={{fontSize: 10,color:C.muted,fontFamily:"var(--font-mono)",marginTop:2}}>URI: {k.google_key_uri}</div>
            </div>
            <div style={{display:"flex",gap:4}}>
              <Btn onClick={async()=>{
                if(!confirm("Delete this CSE key?")) return;
                try{await deleteGoogleCSEKey(session,k.id);onToast?.("Key deleted");await refresh(true);}catch(e){onToast?.(`Delete failed: ${errMsg(e)}`);}
              }} style={{fontSize:10,padding:"3px 6px",color:C.redFg}}>Delete</Btn>
            </div>
          </div>))}
        </div>
      </Card>)}

      {/* ── KACLS Endpoint Info ── */}
      <Card style={{padding:14}}>
        <B style={{fontSize:13,marginBottom:8,display:"block"}}>KACLS Endpoint Information</B>
        <div style={{fontSize:11,color:C.muted,lineHeight:1.6}}>
          <div>Google CSE calls the following KACLS API endpoints on this Vecta KMS instance:</div>
          <div style={{fontFamily:"var(--font-mono)",fontSize:10,marginTop:6,background:C.surface,padding:8,borderRadius:3,border:`1px solid ${C.border}`}}>
            <div>GET  /ekm/kacls/status &mdash; KACLS health check</div>
            <div>POST /ekm/kacls/wrap &mdash; Wrap DEK for encryption</div>
            <div>POST /ekm/kacls/unwrap &mdash; Unwrap DEK for decryption</div>
            <div>POST /ekm/kacls/privilegedunwrap &mdash; Admin/legal hold unwrap</div>
          </div>
          <div className="vk-fold" tabIndex={0} style={{marginTop:8}}>Configure these endpoints in your Google Workspace Admin Console under <b>Security &gt; Client-side encryption &gt; External key service</b>.</div>
        </div>
      </Card>
    </div>)}

    {/* ═══════════════════════ KMIP SUBTAB ═══════════════════════ */}
    {subView==="kmip"&&(<KMIPTab session={session} onToast={onToast}/>)}
    {subView==="kubernetes"&&(<Kubernetes session={session} keyCatalog={keyCatalog} onNavigate={onNavigate}/>)}
    {subView==="edge"&&(<EdgeDevices session={session}/>)}


    {/* ═══════════════════════ MODALS ═══════════════════════ */}

    {/* ── Setup Guide Modal ── */}
    {modal==="setup-guide"&&(<Modal open={true} title="EKM Setup Guide" onClose={()=>setModal(null)}>
      <div style={{display:"flex",gap:8,marginBottom:12}}>
        {Object.keys(SETUP_GUIDES).map(eng=>(<Btn key={eng} onClick={()=>setGuideEngine(eng)} style={{fontSize:12,padding:"4px 12px",background:guideEngine===eng?C.accent+"22":"transparent",color:guideEngine===eng?C.accentFg:C.text}}>{eng.toUpperCase()}</Btn>))}
      </div>
      <B>{SETUP_GUIDES[guideEngine]?.title}</B>
      <div style={{marginTop:12}}>
        {SETUP_GUIDES[guideEngine]?.steps.map((step,i)=>(<div key={i} style={{fontSize:12,marginBottom:10,whiteSpace:"pre-wrap",fontFamily:step.includes("  ")?"monospace":"inherit",color:step.includes("  ")?C.accentFg:C.text,background:step.includes("  ")?C.surface:"transparent",padding:step.includes("  ")?"6px 10px":0,borderRadius:4}}>{step}</div>))}
      </div>
    </Modal>)}

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
      <div style={{fontSize:11,color:C.dim,marginTop:4}}>A TDE key will be auto-provisioned via KeyCore for this database.{dbRegForm.rotation_policy!=="0"&&` Key rotation policy: every ${dbRegForm.rotation_policy} days.`}</div>
      <div style={{display:"flex",gap:8,marginTop:12}}>
        <Btn onClick={submitDbRegister} disabled={dbRegistering}>{dbRegistering?"Registering...":"Register Database"}</Btn>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
      </div>
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
        <div style={{color:C.greenFg,marginBottom:8,fontSize:12}}>Client registered. Download and deploy on the Windows host:</div>
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
      {bitLockerDeleteLoading?(<div style={{textAlign:"center",color:C.dim,fontSize:12}}>Loading preview...</div>):(<>
        {bitLockerDeletePreview&&(<div style={{marginBottom:12}}>
          <div style={{fontSize:12,color:C.dim}}>Host: {bitLockerDeletePreview.host}</div>
          <div style={{fontSize:12,color:C.dim}}>Recovery keys available: {bitLockerDeletePreview.recovery_keys_available}</div>
          {bitLockerDeletePreview.latest_recovery_key_masked&&(<div style={{fontSize:12,color:C.amberFg}}>Latest recovery key (masked): {bitLockerDeletePreview.latest_recovery_key_masked}</div>)}
          {bitLockerDeletePreview.latest_recovery_key&&(<div style={{fontSize:12,color:C.redFg,fontFamily:"var(--font-mono)",background:C.surface,padding:6,borderRadius:4,marginTop:4}}>Full key: {bitLockerDeletePreview.latest_recovery_key}</div>)}
        </div>)}
        <Chk label="I confirm that the recovery key has been backed up securely" checked={bitLockerDeleteConfirmBackup} onChange={(e)=>setBitLockerDeleteConfirmBackup(e.target.checked)}/>
        <div style={{display:"flex",gap:8,marginTop:12}}>
          <Btn onClick={submitBitLockerDelete} disabled={bitLockerDeleteSubmitting||!bitLockerDeleteConfirmBackup} style={{color:C.redFg}}>{bitLockerDeleteSubmitting?"Deleting...":"Delete Client"}</Btn>
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
        <div style={{fontSize:12,color:C.dim,marginBottom:8}}>Scanned {bitLockerScanResult.scanned_hosts} hosts in {bitLockerScanResult.duration_ms}ms. Found {bitLockerScanResult.windows_hosts} Windows endpoint(s).</div>
        {bitLockerScanCandidates.length>0&&(<>
          <div style={{border:"1px solid "+C.border,borderRadius:4,overflow:"hidden",maxHeight:300,overflowY:"auto"}}>
            {bitLockerScanCandidates.map((row,i)=>(<div key={i} style={{display:"flex",alignItems:"center",gap:8,padding:"6px 10px",borderBottom:"1px solid "+C.border,fontSize:12}}>
              <Chk checked={Boolean(bitLockerScanSelected[row.ip])} onChange={()=>toggleBitLockerCandidate(row.ip)}/>
              <span style={{fontFamily:"var(--font-mono)",minWidth:120}}>{row.ip}</span>
              <span style={{flex:1,color:C.dim}}>{row.host}</span>
              <span style={{fontSize:11}}>{row.os_guess}</span>
              <span style={{fontSize:11,color:row.confidence==="high"?C.greenFg:C.amberFg}}>{row.confidence}</span>
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
      {bitLockerLoadingDetail?(<div style={{textAlign:"center",color:C.dim,fontSize:12}}>Loading...</div>):(<>
        <B style={{fontSize:13,marginBottom:8,display:"block"}}>Jobs ({bitLockerJobs.length})</B>
        {bitLockerJobs.length===0?(<div style={{color:C.dim,fontSize:12}}>No jobs found.</div>):(
          <div style={{maxHeight:250,overflow:"auto",marginBottom:16}}>
            {bitLockerJobs.map((job,i)=>(<div key={job.id||i} style={{padding:"6px 0",borderBottom:"1px solid "+C.border,fontSize:12}}>
              <div><B>{job.operation}</B> - <span style={{color:job.status==="succeeded"?C.greenFg:job.status==="failed"?C.redFg:C.amberFg}}>{job.status}</span></div>
              <div style={{color:C.dim,fontSize:11}}>Requested: {formatAgo(job.requested_at)} by {job.requested_by}</div>
              {job.error_message&&(<div style={{color:C.redFg,fontSize:11}}>{job.error_message}</div>)}
            </div>))}
          </div>
        )}
        <B style={{fontSize:13,marginBottom:8,display:"block"}}>Recovery Keys ({bitLockerRecovery.length})</B>
        {bitLockerRecovery.length===0?(<div style={{color:C.dim,fontSize:12}}>No recovery keys stored.</div>):(
          <div style={{maxHeight:200,overflow:"auto"}}>
            {bitLockerRecovery.map((rec,i)=>(<div key={rec.id||i} style={{padding:"6px 0",borderBottom:"1px solid "+C.border,fontSize:12}}>
              <div style={{fontFamily:"var(--font-mono)",fontSize:11}}>{rec.key_masked||rec.key_fingerprint}</div>
              <div style={{color:C.dim,fontSize:11}}>Volume: {rec.volume_mount_point} | Protector: {rec.protector_id||"n/a"} | {formatAgo(rec.created_at)}</div>
            </div>))}
          </div>
        )}
      </>)}
    </Modal>)}

    {/* ── BitLocker Operations Modal ── */}
    {modal==="bitlocker-options"&&selectedAgent&&(<Modal open={true} title={`Operations: ${selectedAgent.name}`} onClose={()=>setModal(null)}>
      <div style={{fontSize:12,color:C.dim,marginBottom:12}}>Queue a BitLocker operation for {selectedAgent.name} ({selectedAgent.host}):</div>
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
          <div style={{fontSize:11,color:C.dim}}>{desc}</div>
        </Btn>))}
      </div>
    </Modal>)}

    {promptDialog.ui}
  </div>);
};
