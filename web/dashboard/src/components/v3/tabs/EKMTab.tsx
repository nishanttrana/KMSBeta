// @ts-nocheck
import { useEffect, useMemo, useRef, useState } from "react";
import { LayoutGrid, List, MoreVertical, RefreshCcw } from "lucide-react";
import { B, Btn, Card, Chk, FG, Inp, Modal, Row2, Section, Sel, Txt, usePromptDialog } from "../legacyPrimitives";
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
  queueBitLockerOperation,
  registerBitLockerClient,
  registerEKMAgent,
  scanBitLockerWindows,
  rotateEKMAgentKey
} from "../../../lib/ekm";
import { KMIPTab } from "./KMIPTab";
export const EKMTab=({session,onToast,subView,onSubViewChange}:any)=>{
  const [loading,setLoading]=useState(false);
  const [agents,setAgents]=useState([]);
  const [statusByID,setStatusByID]=useState({});
  const [healthByID,setHealthByID]=useState({});
  const [keyMetaByID,setKeyMetaByID]=useState({});
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
  const [ekmSubtab,setEkmSubtab]=useState("db");
  const [dbView,setDbView]=useState<"cards"|"list">("cards");
  const [bitLockerView,setBitLockerView]=useState<"cards"|"list">("cards");
  const [dbSearch,setDbSearch]=useState("");
  const [bitLockerSearch,setBitLockerSearch]=useState("");
  const [dbMenu,setDbMenu]=useState("");
  const deployingRef=useRef(false);
  const promptDialog=usePromptDialog();

  const formatAgo=(value:any)=>{
    const ts=new Date(String(value||"")).getTime();
    if(!Number.isFinite(ts)){
      return "n/a";
    }
    const diff=Math.max(0,Date.now()-ts);
    const sec=Math.floor(diff/1000);
    if(sec<60){
      return `${sec}s ago`;
    }
    const min=Math.floor(sec/60);
    if(min<60){
      return `${min}m ago`;
    }
    const hr=Math.floor(min/60);
    if(hr<24){
      return `${hr}h ago`;
    }
    const day=Math.floor(hr/24);
    return `${day}d ago`;
  };

  const parseAgentMeta=(agent)=>{
    try{
      return JSON.parse(String(agent?.metadata_json||"{}"));
    }catch{
      return {};
    }
  };

  const rotationDaysFor=(agent)=>{
    const meta=parseAgentMeta(agent);
    const n=Number(meta?.rotation_cycle_days||90);
    if(Number.isFinite(n)&&n>0){
      return Math.trunc(n);
    }
    return 90;
  };

  const normalizeAgentIDPart=(value,maxLen)=>{
    const normalized=String(value||"")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g,"-")
      .replace(/^-+|-+$/g,"");
    const sliced=normalized.slice(0,Math.max(4,Math.trunc(Number(maxLen)||16)));
    return sliced||"na";
  };

  const deriveEKMAgentID=(name,dbEngine,host)=>{
    const namePart=normalizeAgentIDPart(name,24);
    const enginePart=normalizeAgentIDPart(dbEngine,12);
    const hostPart=normalizeAgentIDPart(host,40);
    return `agent-${enginePart}-${hostPart}-${namePart}`.slice(0,96);
  };

  const visibleDeployFiles=useMemo(()=>{
    const pkg=deployPackage;
    if(!pkg){
      return [];
    }
    const target=String(pkg.target_os||"").toLowerCase();
    const files=Array.isArray(pkg.files)?pkg.files:[];
    if(target==="linux"){
      return files.filter((file)=>!String(file?.path||"").toLowerCase().endsWith(".ps1"));
    }
    if(target==="windows"){
      return files.filter((file)=>!String(file?.path||"").toLowerCase().endsWith(".sh"));
    }
    return files;
  },[deployPackage]);

  const safeFileName=(name)=>String(name||"file").replace(/[^a-zA-Z0-9._-]/g,"_");
  const downloadText=(name,content)=>{
    const blob=new Blob([String(content||"")],{type:"text/plain;charset=utf-8"});
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url;
    a.download=safeFileName(name);
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const refresh=async(silent=false)=>{
    if(!silent){
      setLoading(true);
    }
    try{
      const items=await listEKMAgents(session);
      setAgents(items);
      const statuses={};
      const healthMap={};
      await Promise.all(items.map(async(agent)=>{
        try{
          statuses[agent.id]=await getEKMAgentStatus(session,agent.id);
        }catch{
          statuses[agent.id]={status:"unknown"};
        }
        try{
          healthMap[agent.id]=await getEKMAgentHealth(session,agent.id);
        }catch{
          healthMap[agent.id]={};
        }
      }));
      setStatusByID(statuses);
      setHealthByID(healthMap);
      try{
        const blItems=await listBitLockerClients(session,1000);
        setBitLockerClients(Array.isArray(blItems)?blItems:[]);
      }catch{
        setBitLockerClients([]);
      }

      const keyIDs=[...new Set(items.map((agent)=>String(agent.assigned_key_id||"").trim()).filter(Boolean))];
      const keyMeta={};
      await Promise.all(keyIDs.map(async(keyID)=>{
        try{
          keyMeta[keyID]=await getEKMTDEPublicKey(session,keyID);
        }catch{
          keyMeta[keyID]={algorithm:"",key_version:""};
        }
      }));
      setKeyMetaByID(keyMeta);
    }catch(error){
      onToast?.(`EKM load failed: ${errMsg(error)}`);
    }finally{
      if(!silent){
        setLoading(false);
      }
    }
  };

  useEffect(()=>{
    let stop=false;
    const run=async(silent=false)=>{
      if(stop){
        return;
      }
      await refresh(silent);
    };
    void run(false);
    const id=setInterval(()=>{void run(true);},15000);
    return()=>{
      stop=true;
      clearInterval(id);
    };
  },[session?.token,session?.tenantId]);

  const openLogs=async(agent)=>{
    setSelectedAgent(agent);
    setModal("logs");
    setLogs([]);
    setLogsLoading(true);
    try{
      const items=await listEKMAgentLogs(session,agent.id,60);
      setLogs(items);
    }catch(error){
      onToast?.(`Agent logs failed: ${errMsg(error)}`);
    }finally{
      setLogsLoading(false);
    }
  };

  const runRotate=async(agent)=>{
    if(!String(agent?.assigned_key_id||"").trim()){
      onToast?.("No TDE key assigned to this agent.");
      return;
    }
    setRotatingAgentID(agent.id);
    try{
      await rotateEKMAgentKey(session,agent.id,"manual-dashboard");
      onToast?.(`KMS TDE key rotation queued for ${agent.name}. Run DB-side TDE key switch/re-encryption per engine policy.`);
      await refresh(true);
    }catch(error){
      onToast?.(`Rotate failed: ${errMsg(error)}`);
    }finally{
      setRotatingAgentID("");
    }
  };

  const runDelete=async(agent)=>{
    const agentID=String(agent?.id||"").trim();
    const agentName=String(agent?.name||agentID).trim();
    if(!agentID){
      onToast?.("Invalid agent id.");
      return;
    }
    const confirmed=await promptDialog.confirm({
      title:"Delete EKM Agent",
      message:`Delete agent "${agentName}"?\n\nThis will remove the agent, linked databases, linked TDE keys, and access logs.`,
      confirmLabel:"Delete Agent",
      danger:true
    });
    if(!confirmed){
      return;
    }
    setDeletingAgentID(agentID);
    try{
      const out=await deleteEKMAgent(session,agentID,"manual-dashboard-delete");
      onToast?.(
        `Agent deleted: DB ${Number(out?.deleted_databases||0)}, Keys ${Number(out?.deleted_keys||0)}, Logs ${Number(out?.deleted_logs||0)}.`
      );
      if(selectedAgent&&String(selectedAgent.id||"")===agentID){
        setModal(null);
        setSelectedAgent(null);
      }
      await refresh(true);
    }catch(error){
      onToast?.(`Delete failed: ${errMsg(error)}`);
    }finally{
      setDeletingAgentID("");
    }
  };

  const submitDeploy=async()=>{
    if(deployingRef.current||deploying){
      return;
    }
    const name=String(deployForm.name||"").trim();
    const host=String(deployForm.host||"").trim();
    const version=String(deployForm.version||"").trim();
    if(!name||!host){
      onToast?.("Agent name and host are required.");
      return;
    }
    deployingRef.current=true;
    setDeploying(true);
    try{
      const metadataJSON=JSON.stringify({
        target_os:deployForm.target_os,
        rotation_cycle_days:Math.max(1,Math.trunc(Number(deployForm.rotation_cycle_days||90))),
        pkcs11_profile:`${deployForm.db_engine}-tde-pkcs11`,
        deployed_from:"dashboard"
      });
      const agent=await registerEKMAgent(session,{
        agent_id:deriveEKMAgentID(name,deployForm.db_engine,host),
        name,
        db_engine:deployForm.db_engine,
        host,
        version,
        heartbeat_interval_sec:Math.max(5,Math.trunc(Number(deployForm.heartbeat_interval_sec||30))),
        metadata_json:metadataJSON,
        auto_provision_tde:true
      });
      const pkg=await getEKMDeployPackage(session,agent.id,deployForm.target_os);
      setDeployPackage(pkg);
      onToast?.(`Agent ${agent.name} registered. Download package files and deploy on ${deployForm.target_os}.`);
      await refresh(true);
    }catch(error){
      onToast?.(`Deploy failed: ${errMsg(error)}`);
    }finally{
      deployingRef.current=false;
      setDeploying(false);
    }
  };

  const openDeploy=()=>{
    deployingRef.current=false;
    setDeployPackage(null);
    setDeployForm({
      name:"",
      db_engine:"mssql",
      host:"",
      version:"",
      target_os:"linux",
      heartbeat_interval_sec:30,
      rotation_cycle_days:90
    });
    setModal("deploy");
  };

  const openBitLockerDeploy=()=>{
    setBitLockerDeployPackage(null);
    setBitLockerForm({
      name:"",
      host:"",
      os_version:"Windows 11 / Server 2022",
      mount_point:"C:",
      heartbeat_interval_sec:30
    });
    setModal("bitlocker-deploy");
  };

  const submitBitLockerDeploy=async()=>{
    const name=String(bitLockerForm.name||"").trim();
    const host=String(bitLockerForm.host||"").trim();
    if(!name||!host){
      onToast?.("BitLocker client name and host are required.");
      return;
    }
    const normalizedHost=host.toLowerCase();
    const normalizedName=name.toLowerCase();
    const duplicate=(bitLockerClients||[]).find((row:any)=>{
      const rowHost=String(row?.host||"").trim().toLowerCase();
      const rowName=String(row?.name||"").trim().toLowerCase();
      return (rowHost!==""&&rowHost===normalizedHost)||(rowName!==""&&rowName===normalizedName);
    });
    if(duplicate){
      onToast?.(`BitLocker client already exists (name: ${String(duplicate?.name||"-")}, host: ${String(duplicate?.host||"-")}). Duplicate host/name is not allowed.`);
      return;
    }
    setBitLockerDeploying(true);
    try{
      const client=await registerBitLockerClient(session,{
        name,
        host,
        os_version:String(bitLockerForm.os_version||"windows").trim(),
        mount_point:String(bitLockerForm.mount_point||"C:").trim()||"C:",
        heartbeat_interval_sec:Math.max(5,Math.trunc(Number(bitLockerForm.heartbeat_interval_sec||30))),
        metadata_json:JSON.stringify({managed_by:"vecta-ekm",feature:"bitlocker"})
      });
      const pkg=await getBitLockerDeployPackage(session,client.id,"windows");
      setBitLockerDeployPackage(pkg);
      onToast?.(`BitLocker client ${client.name} registered. Download package and deploy on Windows host.`);
      await refresh(true);
    }catch(error){
      onToast?.(`BitLocker deploy failed: ${errMsg(error)}`);
    }finally{
      setBitLockerDeploying(false);
    }
  };

  const runBitLockerOperation=async(client,operation)=>{
    const clientID=String(client?.id||"").trim();
    if(!clientID){
      return;
    }
    setBitLockerOpClientID(`${clientID}:${operation}`);
    try{
      await queueBitLockerOperation(session,clientID,operation,{
        mount_point:String(client?.mount_point||"C:").trim()||"C:"
      });
      onToast?.(`BitLocker operation queued: ${operation} (${client.name}).`);
      await refresh(true);
    }catch(error){
      onToast?.(`BitLocker operation failed: ${errMsg(error)}`);
    }finally{
      setBitLockerOpClientID("");
    }
  };

  const openBitLockerDelete=async(client)=>{
    const clientID=String(client?.id||"").trim();
    if(!clientID){
      onToast?.("Invalid BitLocker client.");
      return;
    }
    setBitLockerDeleteTarget(client);
    setBitLockerDeletePreview(null);
    setBitLockerDeleteConfirmBackup(false);
    setBitLockerDeleteLoading(true);
    setModal("bitlocker-delete");
    try{
      const preview=await getBitLockerDeletePreview(session,clientID);
      setBitLockerDeletePreview(preview||null);
    }catch(error){
      onToast?.(`Delete preview failed: ${errMsg(error)}`);
    }finally{
      setBitLockerDeleteLoading(false);
    }
  };

  const submitBitLockerDelete=async()=>{
    const target=bitLockerDeleteTarget;
    const clientID=String(target?.id||"").trim();
    if(!clientID){
      onToast?.("Invalid BitLocker client.");
      return;
    }
    if(!bitLockerDeleteConfirmBackup){
      onToast?.("Please confirm backup of recovery key before deleting.");
      return;
    }
    setBitLockerDeleteSubmitting(true);
    setBitLockerDeletingClientID(clientID);
    try{
      const out=await deleteBitLockerClient(session,clientID,{
        reason:"manual-dashboard-delete",
        confirm_backup:true
      });
      onToast?.(`BitLocker client deleted: jobs ${Number(out?.deleted_jobs||0)}, recovery ${Number(out?.deleted_recovery_keys||0)}.`);
      if(selectedAgent&&String(selectedAgent?.id||"")===clientID){
        setSelectedAgent(null);
      }
      setModal(null);
      setBitLockerDeleteTarget(null);
      setBitLockerDeletePreview(null);
      await refresh(true);
    }catch(error){
      onToast?.(`Delete client failed: ${errMsg(error)}`);
    }finally{
      setBitLockerDeleteSubmitting(false);
      setBitLockerDeletingClientID("");
    }
  };

  const openBitLockerScan=()=>{
    setBitLockerScanResult(null);
    setBitLockerScanCandidates([]);
    setBitLockerScanSelected({});
    setModal("bitlocker-scan");
  };

  const runBitLockerScan=async()=>{
    const range=String(bitLockerScanForm.ip_range||"").trim();
    if(!range){
      onToast?.("IP range is required.");
      return;
    }
    setBitLockerScanRunning(true);
    try{
      const scan=await scanBitLockerWindows(session,{
        ip_range:range,
        max_hosts:Number(bitLockerScanForm.max_hosts||256),
        concurrency:Number(bitLockerScanForm.concurrency||32),
        port_timeout_ms:Number(bitLockerScanForm.port_timeout_ms||350),
        require_winrm:Boolean(bitLockerScanForm.require_winrm)
      });
      const rows=Array.isArray(scan?.candidates)?scan.candidates:[];
      setBitLockerScanResult(scan||null);
      setBitLockerScanCandidates(rows);
      setBitLockerScanSelected({});
      onToast?.(`Scan complete: ${Number(scan?.windows_hosts||0)} Windows hosts found.`);
    }catch(error){
      onToast?.(`Network scan failed: ${errMsg(error)}`);
    }finally{
      setBitLockerScanRunning(false);
    }
  };

  const toggleBitLockerCandidate=(ip:string)=>{
    const key=String(ip||"").trim();
    if(!key){
      return;
    }
    setBitLockerScanSelected((prev)=>({
      ...prev,
      [key]:!Boolean(prev?.[key])
    }));
  };

  const onboardScannedBitLocker=async()=>{
    const selectedIPs=Object.entries(bitLockerScanSelected||{}).filter(([,v])=>Boolean(v)).map(([k])=>String(k||"").trim()).filter(Boolean);
    if(!selectedIPs.length){
      onToast?.("Select at least one Windows host to onboard.");
      return;
    }
    const byIP=new Map((bitLockerScanCandidates||[]).map((row:any)=>[String(row?.ip||"").trim(),row]));
    const existingHosts=new Set((bitLockerClients||[]).map((row:any)=>String(row?.host||"").trim().toLowerCase()).filter(Boolean));
    const existingNames=new Set((bitLockerClients||[]).map((row:any)=>String(row?.name||"").trim().toLowerCase()).filter(Boolean));
    setBitLockerOnboarding(true);
    let created=0;
    let skipped=0;
    let failed=0;
    for(const ip of selectedIPs){
      const row:any=byIP.get(ip);
      if(!row){
        skipped++;
        continue;
      }
      const host=String(row?.host||ip).trim();
      if(existingHosts.has(String(host).toLowerCase())||existingHosts.has(String(ip).toLowerCase())){
        skipped++;
        continue;
      }
      const baseName=String(host||ip).split(".")[0].replace(/[^a-zA-Z0-9_-]/g,"-");
      const suggestedName=(baseName||`WIN-${ip.replace(/\./g,"-")}`).slice(0,48);
      if(existingNames.has(String(suggestedName).toLowerCase())){
        skipped++;
        continue;
      }
      const suggestedClientID=`scan-${ip.replace(/[^0-9]/g,"-")}`;
      try{
        await registerBitLockerClient(session,{
          client_id:suggestedClientID,
          name:suggestedName,
          host:ip,
          os_version:String(row?.os_guess||"Windows (discovered)"),
          mount_point:"C:",
          heartbeat_interval_sec:30,
          metadata_json:JSON.stringify({
            managed_by:"vecta-ekm",
            source:"network-scan",
            scan_confidence:String(row?.confidence||""),
            scan_ports_open:Array.isArray(row?.ports_open)?row.ports_open:[]
          })
        });
        existingHosts.add(String(ip).toLowerCase());
        existingHosts.add(String(host).toLowerCase());
        existingNames.add(String(suggestedName).toLowerCase());
        created++;
      }catch{
        failed++;
      }
    }
    setBitLockerOnboarding(false);
    onToast?.(`Onboard complete: added ${created}, skipped ${skipped}, failed ${failed}.`);
    if(created>0){
      await refresh(true);
    }
  };

  const openBitLockerActivity=async(client)=>{
    const clientID=String(client?.id||"").trim();
    if(!clientID){
      return;
    }
    let selected=client;
    try{
      selected=await getBitLockerClient(session,clientID);
    }catch{
      // fall back to cached row
    }
    setSelectedAgent(selected);
    setModal("bitlocker-activity");
    setBitLockerJobs([]);
    setBitLockerRecovery([]);
    setBitLockerLoadingDetail(true);
    try{
      const [jobs,recovery]=await Promise.all([
        listBitLockerJobs(session,clientID,80),
        listBitLockerRecoveryKeys(session,clientID,80)
      ]);
      setBitLockerJobs(Array.isArray(jobs)?jobs:[]);
      setBitLockerRecovery(Array.isArray(recovery)?recovery:[]);
    }catch(error){
      onToast?.(`BitLocker activity load failed: ${errMsg(error)}`);
    }finally{
      setBitLockerLoadingDetail(false);
    }
  };

  const openBitLockerOptions=(client)=>{
    setSelectedAgent(client||null);
    setModal("bitlocker-options");
  };

  const statusBadge=(agent)=>{
    const health=String(healthByID[agent.id]?.health||"").toLowerCase();
    const baseStatus=String(agent.status||"").toLowerCase();
    const tdeState=String(agent.tde_state||"").toLowerCase();
    if(health==="down"||baseStatus==="disconnected"){
      return {label:"Down",color:"red"};
    }
    if(health==="degraded"||baseStatus==="degraded"){
      return {label:"Degraded",color:"amber"};
    }
    if(tdeState==="enabled"){
      return {label:"Active",color:"green"};
    }
    return {label:"Standby",color:"amber"};
  };

  const sortedAgents=[...agents].sort((a,b)=>String(a.name||"").localeCompare(String(b.name||"")));
  const normalizedDBSearch=String(dbSearch||"").trim().toLowerCase();
  const filteredAgents=sortedAgents.filter((agent)=>{
    if(!normalizedDBSearch){
      return true;
    }
    return [
      String(agent?.name||""),
      String(agent?.host||""),
      String(agent?.db_engine||""),
      String(agent?.version||""),
      String(agent?.assigned_key_id||"")
    ].join(" ").toLowerCase().includes(normalizedDBSearch);
  });
  const activeCount=sortedAgents.filter((agent)=>statusBadge(agent).label==="Active").length;
  const standbyCount=sortedAgents.filter((agent)=>statusBadge(agent).label==="Standby").length;
  const degradedCount=sortedAgents.filter((agent)=>statusBadge(agent).label==="Degraded").length;
  const downCount=sortedAgents.filter((agent)=>statusBadge(agent).label==="Down").length;
  const bitLockerBadge=(client)=>{
    const status=String(client?.status||"").toLowerCase();
    const health=String(client?.health||"").toLowerCase();
    const protection=String(client?.protection_status||"").toLowerCase();
    if(health==="down"||status==="disconnected"){
      return {label:"Down",color:"red"};
    }
    if(health==="degraded"||status==="degraded"){
      return {label:"Degraded",color:"amber"};
    }
    if(protection==="on"){
      return {label:"Protected",color:"green"};
    }
    if(protection==="suspended"){
      return {label:"Suspended",color:"amber"};
    }
    if(protection==="off"){
      return {label:"Off",color:"red"};
    }
    return {label:"Unknown",color:"blue"};
  };
  const sortedBitLockerClients=[...bitLockerClients].sort((a,b)=>String(a.name||"").localeCompare(String(b.name||"")));
  const dedupedBitLockerClients=useMemo(()=>{
    const seen=new Set<string>();
    const deduped:any[]=[];
    for(const client of sortedBitLockerClients){
      const key=`${String(client?.host||"").trim().toLowerCase()}|${String(client?.name||"").trim().toLowerCase()}`;
      if(seen.has(key)){
        continue;
      }
      seen.add(key);
      deduped.push(client);
    }
    return deduped;
  },[sortedBitLockerClients]);
  const normalizedBitLockerSearch=String(bitLockerSearch||"").trim().toLowerCase();
  const filteredBitLockerClients=dedupedBitLockerClients.filter((client)=>{
    if(!normalizedBitLockerSearch){
      return true;
    }
    return [
      String(client?.name||""),
      String(client?.host||""),
      String(client?.os_version||""),
      String(client?.mount_point||""),
      String(client?.protection_status||"")
    ].join(" ").toLowerCase().includes(normalizedBitLockerSearch);
  });
  const bitLockerProtectedCount=dedupedBitLockerClients.filter((client)=>bitLockerBadge(client).label==="Protected").length;
  const bitLockerSuspendedCount=dedupedBitLockerClients.filter((client)=>bitLockerBadge(client).label==="Suspended").length;
  const bitLockerDegradedCount=dedupedBitLockerClients.filter((client)=>bitLockerBadge(client).label==="Degraded").length;
  const bitLockerDownCount=dedupedBitLockerClients.filter((client)=>bitLockerBadge(client).label==="Down").length;
  const currentSubtab=String(subView||ekmSubtab||"db");
  const selectSubtab=(next:string)=>{
    if(onSubViewChange){
      onSubViewChange(next);
      return;
    }
    setEkmSubtab(next);
  };
  const showInlineSubTabs=!onSubViewChange;

  return <div>
    {showInlineSubTabs&&<div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap"}}>
      <Btn small primary={currentSubtab==="db"} onClick={()=>selectSubtab("db")}>EKM for DBs</Btn>
      <Btn small primary={currentSubtab==="bitlocker"} onClick={()=>selectSubtab("bitlocker")}>BitLocker Management</Btn>
      <Btn small primary={currentSubtab==="kmip"} onClick={()=>selectSubtab("kmip")}>KMIP</Btn>
    </div>}

    {currentSubtab==="db"&&<Section
      title="ENTERPRISE KEY MANAGEMENT  -  TDE AGENTS"
      actions={<div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
        <Inp
          style={{width:220}}
          value={dbSearch}
          onChange={(e)=>setDbSearch(e.target.value)}
          placeholder="Search hostname / agent..."
        />
        <Btn small primary={dbView==="cards"} onClick={()=>setDbView("cards")} title="Card view"><LayoutGrid size={12} strokeWidth={2}/></Btn>
        <Btn small primary={dbView==="list"} onClick={()=>setDbView("list")} title="List view"><List size={12} strokeWidth={2}/></Btn>
        <Btn small onClick={()=>void refresh(false)} disabled={loading}>
          <span style={{display:"inline-flex",alignItems:"center",gap:5}}>
            <RefreshCcw size={12} strokeWidth={2}/>
            {loading?"Refreshing...":"Refresh"}
          </span>
        </Btn>
        <Btn small primary onClick={openDeploy}>+ Deploy New Agent</Btn>
      </div>}
    >
      <div style={{display:"flex",gap:6,marginBottom:8,flexWrap:"wrap"}}>
        <B c="green">{`${activeCount} Active`}</B>
        <B c="amber">{`${standbyCount} Standby`}</B>
        <B c="amber">{`${degradedCount} Degraded`}</B>
        <B c="red">{`${downCount} Down`}</B>
      </div>
      {dbView==="cards"
        ? <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(300px,1fr))",gap:10}}>
          {filteredAgents.map((agent)=>{
            const badge=statusBadge(agent);
            const keyID=String(agent.assigned_key_id||"").trim();
            const keyMeta=keyMetaByID[keyID]||{};
            const health=healthByID[agent.id]||{};
            const metrics=health.metrics||{};
            const hbAgeSec=Number(health.last_heartbeat_age_sec||statusByID[agent.id]?.last_heartbeat_age_sec||0);
            const dbEngine=String(agent.db_engine||"mssql").toLowerCase()==="oracle"?"Oracle":"MSSQL";
            const dbVersion=String(agent.version||"").trim()||"-";
            const alg=String(keyMeta.algorithm||"").trim()||"Unassigned";
            return <Card key={agent.id}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:8}}>
                <div style={{minWidth:0}}>
                  <div style={{fontSize:18,color:C.white,fontWeight:700,marginBottom:4,lineHeight:1.1,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>
                    {agent.name}
                  </div>
                  <div style={{fontSize:12,color:C.dim}}>{`IP: ${agent.host||"-"}`}</div>
                </div>
                <B c={badge.color}>{badge.label}</B>
              </div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"4px 10px",marginTop:8}}>
                <div style={{fontSize:11,color:C.dim}}>{`Version: ${dbVersion}`}</div>
                <div style={{fontSize:11,color:C.dim}}>{`Engine: ${dbEngine}`}</div>
                <div style={{fontSize:11,color:C.dim,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{`TDE Key: ${alg}`}</div>
                <div style={{fontSize:11,color:C.dim}}>{`KMS Rotation: ${rotationDaysFor(agent)}d policy`}</div>
              </div>
              <div style={{fontSize:10,color:C.muted,marginTop:6}}>
                {`OS Health  CPU ${Number(metrics.cpu_usage_pct||0).toFixed(0)}%  MEM ${Number(metrics.memory_usage_pct||0).toFixed(0)}%  DISK ${Number(metrics.disk_usage_pct||0).toFixed(0)}%  HB ${hbAgeSec}s`}
              </div>
              <div style={{display:"flex",gap:8,marginTop:10}}>
                <Btn small onClick={()=>void runRotate(agent)} disabled={!keyID||rotatingAgentID===agent.id}>
                  {rotatingAgentID===agent.id?"Rotating...":"Rotate TDE Key"}
                </Btn>
                <Btn small onClick={()=>void openLogs(agent)}>Agent Logs</Btn>
                <Btn small danger onClick={()=>void runDelete(agent)} disabled={deletingAgentID===agent.id}>
                  {deletingAgentID===agent.id?"Deleting...":"Delete Agent"}
                </Btn>
              </div>
            </Card>;
          })}
        </div>
        : <Card style={{padding:0,overflow:"hidden"}}>
          <div style={{display:"grid",gridTemplateColumns:"1.1fr 1fr .7fr .8fr .8fr .8fr auto",padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>
            <div>Agent</div><div>Host / Engine</div><div>Version</div><div>TDE Key</div><div>KMS Rotation</div><div>Status</div><div>Options</div>
          </div>
          <div style={{maxHeight:320,overflowY:"auto"}}>
            {filteredAgents.map((agent)=>{
              const badge=statusBadge(agent);
              const keyID=String(agent.assigned_key_id||"").trim();
              const keyMeta=keyMetaByID[keyID]||{};
              const dbEngine=String(agent.db_engine||"mssql").toLowerCase()==="oracle"?"Oracle":"MSSQL";
              const dbVersion=String(agent.version||"").trim()||"-";
              const alg=String(keyMeta.algorithm||"").trim()||"Unassigned";
              const menuKey=String(agent.id||"");
              const menuOpen=dbMenu===menuKey;
              return <div key={agent.id} style={{display:"grid",gridTemplateColumns:"1.1fr 1fr .7fr .8fr .8fr .8fr auto",alignItems:"center",padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:10}}>
                <div style={{color:C.text,fontWeight:600,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{agent.name}</div>
                <div style={{color:C.dim,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{`${agent.host||"-"} � ${dbEngine}`}</div>
                <div style={{color:C.dim}}>{dbVersion}</div>
                <div style={{color:C.dim,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{alg}</div>
                <div style={{color:C.dim}}>{`${rotationDaysFor(agent)}d`}</div>
                <div><B c={badge.color}>{badge.label}</B></div>
                <div style={{position:"relative",justifySelf:"end"}}>
                  <button onClick={()=>setDbMenu(menuOpen?"":menuKey)} style={{border:`1px solid ${C.border}`,background:"transparent",color:C.accent,borderRadius:8,padding:"4px 6px",cursor:"pointer"}}>
                    <MoreVertical size={13} strokeWidth={2}/>
                  </button>
                  {menuOpen&&<div style={{position:"absolute",right:0,top:30,zIndex:20,minWidth:140,background:C.surface,border:`1px solid ${C.borderHi}`,borderRadius:8,padding:6,display:"grid",gap:4}}>
                    <button onClick={()=>{setDbMenu("");void runRotate(agent);}} style={{textAlign:"left",background:"transparent",border:"none",color:C.text,cursor:"pointer",padding:"6px 8px"}}>Rotate TDE Key</button>
                    <button onClick={()=>{setDbMenu("");void openLogs(agent);}} style={{textAlign:"left",background:"transparent",border:"none",color:C.text,cursor:"pointer",padding:"6px 8px"}}>Agent Logs</button>
                    <button onClick={()=>{setDbMenu("");void runDelete(agent);}} style={{textAlign:"left",background:"transparent",border:"none",color:C.red,cursor:"pointer",padding:"6px 8px"}}>Delete Agent</button>
                  </div>}
                </div>
              </div>;
            })}
          </div>
        </Card>}
      {!filteredAgents.length&&<Card>
        <div style={{fontSize:11,color:C.dim}}>
          {normalizedDBSearch?"No EKM agents match search.":"No EKM agents registered yet. Deploy an agent to start MSSQL/Oracle TDE integration over PKCS#11."}
        </div>
      </Card>}
    </Section>}

    {currentSubtab==="bitlocker"&&<Section
      title="ENTERPRISE KEY MANAGEMENT  -  BITLOCKER"
      actions={<div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
        <Inp
          style={{width:220}}
          value={bitLockerSearch}
          onChange={(e)=>setBitLockerSearch(e.target.value)}
          placeholder="Search BitLocker client / host..."
        />
        <Btn small primary={bitLockerView==="cards"} onClick={()=>setBitLockerView("cards")} title="Card view"><LayoutGrid size={12} strokeWidth={2}/></Btn>
        <Btn small primary={bitLockerView==="list"} onClick={()=>setBitLockerView("list")} title="List view"><List size={12} strokeWidth={2}/></Btn>
        <Btn small onClick={()=>void refresh(false)} disabled={loading}>
          <span style={{display:"inline-flex",alignItems:"center",gap:5}}>
            <RefreshCcw size={12} strokeWidth={2}/>
            {loading?"Refreshing...":"Refresh"}
          </span>
        </Btn>
        <Btn small onClick={openBitLockerScan}>Network Scan</Btn>
        <Btn small primary onClick={openBitLockerDeploy}>+ Register BitLocker Agent</Btn>
      </div>}
    >
      <div style={{display:"flex",gap:6,marginBottom:8,flexWrap:"wrap"}}>
        <B c="green">{`${bitLockerProtectedCount} Protected`}</B>
        <B c="amber">{`${bitLockerSuspendedCount} Suspended`}</B>
        <B c="amber">{`${bitLockerDegradedCount} Degraded`}</B>
        <B c="red">{`${bitLockerDownCount} Down`}</B>
      </div>
      {bitLockerView==="cards"
        ? <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(320px,360px))",justifyContent:"start",gap:10}}>
          {filteredBitLockerClients.map((client)=>{
            const badge=bitLockerBadge(client);
            const encryptionPct=Math.max(0,Math.min(100,Number(client.encryption_percentage||0)));
            const hbAge=formatAgo(client.last_heartbeat_at);
            const opBusy=(op)=>bitLockerOpClientID===`${String(client.id||"").trim()}:${op}`;
            const deleteBusy=bitLockerDeletingClientID===String(client.id||"").trim();
            return <Card key={client.id}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:8}}>
                <div style={{minWidth:0}}>
                  <div style={{fontSize:18,color:C.white,fontWeight:700,marginBottom:4,lineHeight:1.1,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>
                    {client.name}
                  </div>
                  <div style={{fontSize:12,color:C.dim}}>{`Host: ${client.host||"-"}`}</div>
                </div>
                <B c={badge.color}>{badge.label}</B>
              </div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"4px 10px",marginTop:8}}>
                <div style={{fontSize:11,color:C.dim}}>{`OS: ${client.os_version||"windows"}`}</div>
                <div style={{fontSize:11,color:C.dim}}>{`Mount: ${client.mount_point||"C:"}`}</div>
                <div style={{fontSize:11,color:C.dim}}>{`TPM: ${client.tpm_present?"present":"unknown"}`}</div>
                <div style={{fontSize:11,color:C.dim}}>{`Heartbeat: ${hbAge}`}</div>
              </div>
              <div style={{fontSize:10,color:C.muted,marginTop:6}}>{`Encryption ${encryptionPct.toFixed(1)}%  �  Protection ${String(client.protection_status||"unknown")}`}</div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8,marginTop:10}}>
                <Btn small onClick={()=>void runBitLockerOperation(client,"enable")} disabled={opBusy("enable")}>{opBusy("enable")?"...":"Enable"}</Btn>
                <Btn small onClick={()=>void runBitLockerOperation(client,"pause")} disabled={opBusy("pause")}>{opBusy("pause")?"...":"Pause"}</Btn>
                <Btn small onClick={()=>void runBitLockerOperation(client,"resume")} disabled={opBusy("resume")}>{opBusy("resume")?"...":"Resume"}</Btn>
                <Btn small onClick={()=>void runBitLockerOperation(client,"rotate")} disabled={opBusy("rotate")}>{opBusy("rotate")?"...":"Rotate Key"}</Btn>
                <Btn small onClick={()=>void runBitLockerOperation(client,"fetch_recovery")} disabled={opBusy("fetch_recovery")}>{opBusy("fetch_recovery")?"...":"Fetch Recovery"}</Btn>
                <Btn small onClick={()=>void openBitLockerActivity(client)}>Activity</Btn>
              </div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8,marginTop:8}}>
                <Btn small danger onClick={()=>void runBitLockerOperation(client,"disable")} disabled={opBusy("disable")}>{opBusy("disable")?"...":"Disable"}</Btn>
                <Btn small danger onClick={()=>void runBitLockerOperation(client,"remove")} disabled={opBusy("remove")}>{opBusy("remove")?"...":"Remove"}</Btn>
                <Btn small danger onClick={()=>void openBitLockerDelete(client)} disabled={deleteBusy}>{deleteBusy?"Deleting...":"Delete Client"}</Btn>
              </div>
            </Card>;
          })}
        </div>
        : <Card style={{padding:0,overflow:"hidden"}}>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr .9fr .8fr .8fr .8fr auto",padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>
            <div>Client</div><div>Host / OS</div><div>Mount</div><div>Protection</div><div>Encrypt %</div><div>Status</div><div>Options</div>
          </div>
          <div style={{maxHeight:320,overflowY:"auto"}}>
            {filteredBitLockerClients.map((client)=>{
              const badge=bitLockerBadge(client);
              const encryptionPct=Math.max(0,Math.min(100,Number(client.encryption_percentage||0)));
              const opBusy=(op)=>bitLockerOpClientID===`${String(client.id||"").trim()}:${op}`;
              const deleteBusy=bitLockerDeletingClientID===String(client.id||"").trim();
              return <div key={client.id} style={{display:"grid",gridTemplateColumns:"1fr 1fr .9fr .8fr .8fr .8fr auto",alignItems:"center",padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:10}}>
                <div style={{color:C.text,fontWeight:600,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{client.name}</div>
                <div style={{color:C.dim,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{`${client.host||"-"} � ${client.os_version||"windows"}`}</div>
                <div style={{color:C.dim}}>{client.mount_point||"C:"}</div>
                <div style={{color:C.dim}}>{String(client.protection_status||"unknown")}</div>
                <div style={{color:C.dim}}>{`${encryptionPct.toFixed(1)}%`}</div>
                <div><B c={badge.color}>{badge.label}</B></div>
                <div style={{position:"relative",justifySelf:"end"}}>
                  <button onClick={()=>openBitLockerOptions(client)} style={{border:`1px solid ${C.border}`,background:"transparent",color:C.accent,borderRadius:8,padding:"4px 6px",cursor:"pointer"}}>
                    <MoreVertical size={13} strokeWidth={2}/>
                  </button>
                </div>
              </div>;
            })}
          </div>
        </Card>}
      {!filteredBitLockerClients.length&&<Card>
        <div style={{fontSize:11,color:C.dim}}>
          {normalizedBitLockerSearch?"No BitLocker clients match search.":"No BitLocker clients registered. Use Register BitLocker Agent to onboard Windows endpoints with mTLS/JWT agent auth."}
        </div>
      </Card>}
    </Section>}

    {currentSubtab==="kmip"&&<KMIPTab session={session} onToast={onToast}/>}

    <Modal open={modal==="bitlocker-deploy"} onClose={()=>setModal(null)} title="Register BitLocker Agent" wide>
      <Row2>
        <FG label="Agent Name" required>
          <Inp value={bitLockerForm.name} onChange={(e)=>setBitLockerForm({...bitLockerForm,name:e.target.value})} placeholder="WIN-LAPTOP-001"/>
        </FG>
        <FG label="Host / IP" required>
          <Inp value={bitLockerForm.host} onChange={(e)=>setBitLockerForm({...bitLockerForm,host:e.target.value})} placeholder="10.0.20.15" mono/>
        </FG>
      </Row2>
      <Row2>
        <FG label="OS Version">
          <Inp value={bitLockerForm.os_version} onChange={(e)=>setBitLockerForm({...bitLockerForm,os_version:e.target.value})} placeholder="Windows 11 / Server 2022"/>
        </FG>
        <FG label="Mount Point">
          <Inp value={bitLockerForm.mount_point} onChange={(e)=>setBitLockerForm({...bitLockerForm,mount_point:e.target.value})} placeholder="C:" mono/>
        </FG>
      </Row2>
      <FG label="Heartbeat Interval (sec)">
        <Inp type="number" value={String(bitLockerForm.heartbeat_interval_sec)} onChange={(e)=>setBitLockerForm({...bitLockerForm,heartbeat_interval_sec:Number(e.target.value||30)})}/>
      </FG>
      <div style={{fontSize:10,color:C.muted,marginTop:8}}>
        Registration issues tenant-scoped BitLocker client identity. Download package and run on Windows host to start mTLS/JWT heartbeat and job execution.
      </div>
      {bitLockerDeployPackage&&<Card style={{marginTop:10}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
          <div style={{fontSize:12,color:C.text,fontWeight:700}}>{`Package ready: ${bitLockerDeployPackage.name} (${bitLockerDeployPackage.target_os})`}</div>
          <B c="green">Ready</B>
        </div>
        <div style={{display:"grid",gap:6}}>
          {(bitLockerDeployPackage.files||[]).map((file)=>(
            <div key={file.path} style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8,border:`1px solid ${C.border}`,borderRadius:8,padding:"8px 10px"}}>
              <div style={{minWidth:0}}>
                <div style={{fontSize:11,color:C.text,fontFamily:"'JetBrains Mono',monospace",whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{file.path}</div>
                <div style={{fontSize:9,color:C.muted}}>{`mode ${file.mode}`}</div>
              </div>
              <Btn small onClick={()=>downloadText(file.path,file.content)}>Download</Btn>
            </div>
          ))}
        </div>
      </Card>}
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)} disabled={bitLockerDeploying}>Close</Btn>
        <Btn primary onClick={()=>void submitBitLockerDeploy()} disabled={bitLockerDeploying}>{bitLockerDeploying?"Registering...":"Register BitLocker Agent"}</Btn>
      </div>
    </Modal>

    <Modal open={modal==="bitlocker-activity"} onClose={()=>setModal(null)} title={`BitLocker Activity: ${String(selectedAgent?.name||"")}`} wide>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
        <div style={{fontSize:10,color:C.dim}}>
          {`Client ${String(selectedAgent?.id||"-")}  �  ${String(selectedAgent?.host||"-")}`}
        </div>
        <div style={{display:"flex",gap:8}}>
          <Btn small onClick={()=>selectedAgent&&void openBitLockerActivity(selectedAgent)} disabled={bitLockerLoadingDetail}>{bitLockerLoadingDetail?"Refreshing...":"Refresh"}</Btn>
          <Btn small danger onClick={()=>selectedAgent&&void openBitLockerDelete(selectedAgent)} disabled={!selectedAgent||bitLockerDeletingClientID===String(selectedAgent?.id||"").trim()}>
            {bitLockerDeletingClientID===String(selectedAgent?.id||"").trim()?"Deleting...":"Delete Client"}
          </Btn>
        </div>
      </div>
      <Row2>
        <Card style={{maxHeight:330,overflowY:"auto"}}>
          <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:6}}>Queued / Completed Jobs</div>
          <div style={{display:"grid",gap:6}}>
            {bitLockerLoadingDetail&&<div style={{fontSize:10,color:C.dim}}>Loading jobs...</div>}
            {!bitLockerLoadingDetail&&bitLockerJobs.map((item)=>(
              <div key={item.id} style={{display:"grid",gridTemplateColumns:"110px 90px 1fr auto",gap:8,alignItems:"center",borderBottom:`1px solid ${C.border}`,paddingBottom:6}}>
                <div style={{fontSize:10,color:C.muted,fontFamily:"'JetBrains Mono',monospace"}}>{formatAgo(item.requested_at)}</div>
                <B c={String(item.status||"").toLowerCase()==="succeeded"?"green":String(item.status||"").toLowerCase()==="failed"?"red":"amber"}>{String(item.operation||"-")}</B>
                <div style={{fontSize:10,color:C.text,fontFamily:"'JetBrains Mono',monospace",whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{String(item.id||"-")}</div>
                <div style={{fontSize:9,color:C.dim}}>{String(item.status||"-")}</div>
              </div>
            ))}
            {!bitLockerLoadingDetail&&!bitLockerJobs.length&&<div style={{fontSize:10,color:C.dim}}>No BitLocker operations yet.</div>}
          </div>
        </Card>
        <Card style={{maxHeight:330,overflowY:"auto"}}>
          <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:6}}>Recovery Key Records</div>
          <div style={{display:"grid",gap:6}}>
            {bitLockerLoadingDetail&&<div style={{fontSize:10,color:C.dim}}>Loading recovery records...</div>}
            {!bitLockerLoadingDetail&&bitLockerRecovery.map((item)=>(
              <div key={item.id} style={{borderBottom:`1px solid ${C.border}`,paddingBottom:6}}>
                <div style={{display:"flex",justifyContent:"space-between",gap:8,alignItems:"center"}}>
                  <div style={{fontSize:10,color:C.text,fontFamily:"'JetBrains Mono',monospace"}}>{String(item.key_masked||"-")}</div>
                  <B c="blue">{String(item.volume_mount_point||"C:")}</B>
                </div>
                <div style={{fontSize:9,color:C.muted,fontFamily:"'JetBrains Mono',monospace",marginTop:4}}>{String(item.key_fingerprint||"-")}</div>
                <div style={{fontSize:9,color:C.dim,marginTop:4}}>{new Date(String(item.created_at||Date.now())).toLocaleString()}</div>
              </div>
            ))}
            {!bitLockerLoadingDetail&&!bitLockerRecovery.length&&<div style={{fontSize:10,color:C.dim}}>No recovery records saved yet.</div>}
          </div>
        </Card>
      </Row2>
      <div style={{display:"flex",justifyContent:"flex-end",marginTop:12}}>
        <Btn onClick={()=>setModal(null)}>Close</Btn>
      </div>
    </Modal>

    <Modal open={modal==="bitlocker-options"} onClose={()=>setModal(null)} title={`BitLocker Options: ${String(selectedAgent?.name||"")}`}>
      <div style={{display:"grid",gap:8}}>
        <Row2>
          <Btn small onClick={()=>{selectedAgent&&void runBitLockerOperation(selectedAgent,"enable");}} disabled={!selectedAgent||bitLockerOpClientID===`${String(selectedAgent?.id||"").trim()}:enable`}>{bitLockerOpClientID===`${String(selectedAgent?.id||"").trim()}:enable`?"Enabling...":"Enable"}</Btn>
          <Btn small onClick={()=>{selectedAgent&&void runBitLockerOperation(selectedAgent,"pause");}} disabled={!selectedAgent||bitLockerOpClientID===`${String(selectedAgent?.id||"").trim()}:pause`}>{bitLockerOpClientID===`${String(selectedAgent?.id||"").trim()}:pause`?"Pausing...":"Pause"}</Btn>
        </Row2>
        <Row2>
          <Btn small onClick={()=>{selectedAgent&&void runBitLockerOperation(selectedAgent,"resume");}} disabled={!selectedAgent||bitLockerOpClientID===`${String(selectedAgent?.id||"").trim()}:resume`}>{bitLockerOpClientID===`${String(selectedAgent?.id||"").trim()}:resume`?"Resuming...":"Resume"}</Btn>
          <Btn small onClick={()=>{selectedAgent&&void runBitLockerOperation(selectedAgent,"rotate");}} disabled={!selectedAgent||bitLockerOpClientID===`${String(selectedAgent?.id||"").trim()}:rotate`}>{bitLockerOpClientID===`${String(selectedAgent?.id||"").trim()}:rotate`?"Rotating...":"Rotate Key"}</Btn>
        </Row2>
        <Row2>
          <Btn small onClick={()=>{selectedAgent&&void runBitLockerOperation(selectedAgent,"fetch_recovery");}} disabled={!selectedAgent||bitLockerOpClientID===`${String(selectedAgent?.id||"").trim()}:fetch_recovery`}>{bitLockerOpClientID===`${String(selectedAgent?.id||"").trim()}:fetch_recovery`?"Fetching...":"Fetch Recovery"}</Btn>
          <Btn small onClick={()=>{if(selectedAgent){void openBitLockerActivity(selectedAgent);}}} disabled={!selectedAgent}>Activity</Btn>
        </Row2>
        <Row2>
          <Btn small danger onClick={()=>{selectedAgent&&void runBitLockerOperation(selectedAgent,"disable");}} disabled={!selectedAgent||bitLockerOpClientID===`${String(selectedAgent?.id||"").trim()}:disable`}>{bitLockerOpClientID===`${String(selectedAgent?.id||"").trim()}:disable`?"Disabling...":"Disable"}</Btn>
          <Btn small danger onClick={()=>{selectedAgent&&void runBitLockerOperation(selectedAgent,"remove");}} disabled={!selectedAgent||bitLockerOpClientID===`${String(selectedAgent?.id||"").trim()}:remove`}>{bitLockerOpClientID===`${String(selectedAgent?.id||"").trim()}:remove`?"Removing...":"Remove"}</Btn>
        </Row2>
        <Btn small danger onClick={()=>{if(selectedAgent){void openBitLockerDelete(selectedAgent);}}} disabled={!selectedAgent||bitLockerDeletingClientID===String(selectedAgent?.id||"").trim()}>
          {bitLockerDeletingClientID===String(selectedAgent?.id||"").trim()?"Deleting...":"Delete Client"}
        </Btn>
      </div>
      <div style={{display:"flex",justifyContent:"flex-end",marginTop:12}}>
        <Btn onClick={()=>setModal(null)}>Close</Btn>
      </div>
    </Modal>

    <Modal open={modal==="bitlocker-delete"} onClose={()=>!bitLockerDeleteSubmitting&&setModal(null)} title={`Delete BitLocker Client: ${String(bitLockerDeleteTarget?.name||"")}`} wide>
      <div style={{fontSize:11,color:C.red,lineHeight:1.5,marginBottom:10}}>
        WARNING: This permanently deletes the BitLocker client from KMS UI and backend DB (client record, queued jobs, and stored recovery records).
      </div>
      <div style={{fontSize:10,color:C.dim,marginBottom:10}}>
        Ensure recovery key is backed up before proceeding.
      </div>
      {bitLockerDeleteLoading&&<div style={{fontSize:10,color:C.dim,marginBottom:10}}>Loading delete preview...</div>}
      {!bitLockerDeleteLoading&&bitLockerDeletePreview&&<Card style={{marginBottom:10}}>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"6px 10px"}}>
          <div style={{fontSize:10,color:C.dim}}>{`Client ID: ${String(bitLockerDeletePreview.client_id||"-")}`}</div>
          <div style={{fontSize:10,color:C.dim}}>{`Host: ${String(bitLockerDeletePreview.host||"-")}`}</div>
          <div style={{fontSize:10,color:C.dim}}>{`Recovery records: ${Number(bitLockerDeletePreview.recovery_keys_available||0)}`}</div>
          <div style={{fontSize:10,color:C.dim}}>{`Latest key at: ${bitLockerDeletePreview.latest_recovery_at?new Date(String(bitLockerDeletePreview.latest_recovery_at)).toLocaleString():"-"}`}</div>
        </div>
      </Card>}
      <Chk
        label="I confirm the BitLocker recovery key is backed up and I want to view the stored key string before delete."
        checked={bitLockerDeleteConfirmBackup}
        onChange={()=>setBitLockerDeleteConfirmBackup(!bitLockerDeleteConfirmBackup)}
        disabled={bitLockerDeleteSubmitting}
      />
      {bitLockerDeleteConfirmBackup&&<FG label="BitLocker Key String Stored In DB">
        <Txt
          rows={3}
          readOnly
          value={String(bitLockerDeletePreview?.latest_recovery_key||bitLockerDeletePreview?.latest_recovery_key_masked||"No recovery key record found for this client.")}
        />
      </FG>}
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)} disabled={bitLockerDeleteSubmitting}>Cancel</Btn>
        <Btn danger onClick={()=>void submitBitLockerDelete()} disabled={bitLockerDeleteSubmitting||bitLockerDeleteLoading||!bitLockerDeleteConfirmBackup}>
          {bitLockerDeleteSubmitting?"Deleting...":"Delete Client"}
        </Btn>
      </div>
    </Modal>

    <Modal open={modal==="bitlocker-scan"} onClose={()=>!bitLockerScanRunning&&!bitLockerOnboarding&&setModal(null)} title="Network Scan (Windows BitLocker Endpoints)" wide>
      <Row2>
        <FG label="IP Range (CIDR or start-end)" required>
          <Inp
            value={bitLockerScanForm.ip_range}
            onChange={(e)=>setBitLockerScanForm({...bitLockerScanForm,ip_range:e.target.value})}
            placeholder="10.0.0.0/24 or 10.0.0.10-10.0.0.120"
            mono
          />
        </FG>
        <FG label="Max Hosts">
          <Inp
            type="number"
            value={String(bitLockerScanForm.max_hosts)}
            onChange={(e)=>setBitLockerScanForm({...bitLockerScanForm,max_hosts:Number(e.target.value||256)})}
          />
        </FG>
      </Row2>
      <Row2>
        <FG label="Concurrency">
          <Inp
            type="number"
            value={String(bitLockerScanForm.concurrency)}
            onChange={(e)=>setBitLockerScanForm({...bitLockerScanForm,concurrency:Number(e.target.value||32)})}
          />
        </FG>
        <FG label="Port Timeout (ms)">
          <Inp
            type="number"
            value={String(bitLockerScanForm.port_timeout_ms)}
            onChange={(e)=>setBitLockerScanForm({...bitLockerScanForm,port_timeout_ms:Number(e.target.value||350)})}
          />
        </FG>
      </Row2>
      <Chk
        label="Windows-only strict mode (require SMB + WinRM)"
        checked={Boolean(bitLockerScanForm.require_winrm)}
        onChange={()=>setBitLockerScanForm({...bitLockerScanForm,require_winrm:!bitLockerScanForm.require_winrm})}
        disabled={bitLockerScanRunning}
      />
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:10}}>
        <Btn onClick={()=>setModal(null)} disabled={bitLockerScanRunning||bitLockerOnboarding}>Close</Btn>
        <Btn primary onClick={()=>void runBitLockerScan()} disabled={bitLockerScanRunning}>{bitLockerScanRunning?"Scanning...":"Run Scan"}</Btn>
      </div>
      {bitLockerScanResult&&<Card style={{marginTop:12}}>
        <div style={{display:"flex",gap:10,flexWrap:"wrap",marginBottom:8}}>
          <B c="blue">{`Scanned ${Number(bitLockerScanResult?.scanned_hosts||0)}`}</B>
          <B c="green">{`Windows ${Number(bitLockerScanResult?.windows_hosts||0)}`}</B>
          <B c="amber">{`Duration ${Number(bitLockerScanResult?.duration_ms||0)} ms`}</B>
        </div>
        <div style={{maxHeight:260,overflowY:"auto",border:`1px solid ${C.border}`,borderRadius:8}}>
          <div style={{display:"grid",gridTemplateColumns:"36px 1fr 1fr .8fr .8fr 1fr",padding:"8px 10px",borderBottom:`1px solid ${C.border}`,fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>
            <div></div><div>IP</div><div>Host</div><div>OS</div><div>Confidence</div><div>Ports</div>
          </div>
          {(bitLockerScanCandidates||[]).map((row:any)=>{
            const ip=String(row?.ip||"").trim();
            const selected=Boolean(bitLockerScanSelected?.[ip]);
            return <div key={ip} style={{display:"grid",gridTemplateColumns:"36px 1fr 1fr .8fr .8fr 1fr",padding:"8px 10px",borderBottom:`1px solid ${C.border}`,fontSize:10,alignItems:"center"}}>
              <div>
                <Chk label="" checked={selected} onChange={()=>toggleBitLockerCandidate(ip)} disabled={!ip||bitLockerOnboarding}/>
              </div>
              <div style={{color:C.text,fontFamily:"'JetBrains Mono',monospace"}}>{ip||"-"}</div>
              <div style={{color:C.dim,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{String(row?.host||"-")}</div>
              <div style={{color:C.dim}}>{String(row?.os_guess||"Windows")}</div>
              <div><B c={String(row?.confidence||"").toLowerCase()==="high"?"green":"amber"}>{String(row?.confidence||"medium")}</B></div>
              <div style={{color:C.dim,fontFamily:"'JetBrains Mono',monospace"}}>{Array.isArray(row?.ports_open)?row.ports_open.join(", "):"-"}</div>
            </div>;
          })}
          {!bitLockerScanCandidates.length&&<div style={{padding:"10px 12px",fontSize:10,color:C.dim}}>No Windows endpoints found for this range.</div>}
        </div>
        <div style={{display:"flex",justifyContent:"flex-end",marginTop:10}}>
          <Btn primary onClick={()=>void onboardScannedBitLocker()} disabled={bitLockerOnboarding||!Object.values(bitLockerScanSelected||{}).some(Boolean)}>
            {bitLockerOnboarding?"Onboarding...":"Onboard Selected"}
          </Btn>
        </div>
      </Card>}
    </Modal>

    <Modal open={modal==="deploy"} onClose={()=>setModal(null)} title="Deploy EKM Agent" wide>
      <Row2>
        <FG label="Agent Name" required>
          <Inp value={deployForm.name} onChange={(e)=>setDeployForm({...deployForm,name:e.target.value})} placeholder="MSSQL-Prod-01"/>
        </FG>
        <FG label="Host / IP" required>
          <Inp value={deployForm.host} onChange={(e)=>setDeployForm({...deployForm,host:e.target.value})} placeholder="10.0.5.10" mono/>
        </FG>
      </Row2>
      <Row2>
        <FG label="Database Engine" required>
          <Sel value={deployForm.db_engine} onChange={(e)=>setDeployForm({...deployForm,db_engine:e.target.value})}>
            <option value="mssql">Microsoft SQL Server (TDE)</option>
            <option value="oracle">Oracle Database (TDE)</option>
          </Sel>
        </FG>
        <FG label="Target OS" required>
          <Sel value={deployForm.target_os} onChange={(e)=>{setDeployPackage(null);setDeployForm({...deployForm,target_os:e.target.value});}}>
            <option value="linux">Linux Agent</option>
            <option value="windows">Windows Agent</option>
          </Sel>
        </FG>
      </Row2>
      <Row2>
        <FG label="Database Version">
          <Inp value={deployForm.version} onChange={(e)=>setDeployForm({...deployForm,version:e.target.value})} placeholder="SQL Server 2022 / Oracle 19c"/>
        </FG>
        <FG label="Heartbeat Interval (sec)">
          <Inp type="number" value={deployForm.heartbeat_interval_sec} onChange={(e)=>setDeployForm({...deployForm,heartbeat_interval_sec:Number(e.target.value||30)})}/>
        </FG>
      </Row2>
      <FG
        label="KMS Rotation Cycle (days)"
        hint="This rotates KMS-side TDE key assignment/version policy. Database-side TDE switch/re-encryption still requires DB operations."
      >
        <Sel value={String(deployForm.rotation_cycle_days)} onChange={(e)=>setDeployForm({...deployForm,rotation_cycle_days:Number(e.target.value)})}>
          <option value="90">90 days</option>
          <option value="180">180 days</option>
          <option value="365">365 days</option>
        </Sel>
      </FG>
      <div style={{fontSize:10,color:C.muted,marginTop:8}}>
        Deploy package includes PKCS#11 templates for MSSQL/Oracle TDE with heartbeat, rotate, and register endpoints. Only selected OS scripts are listed below.
      </div>
      {deployPackage&&<Card style={{marginTop:10}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
          <div style={{fontSize:12,color:C.text,fontWeight:700}}>{`Package ready: ${deployPackage.name} (${deployPackage.target_os})`}</div>
          <B c="green">Ready</B>
        </div>
        <div style={{display:"grid",gap:6}}>
          {visibleDeployFiles.map((file)=>(
            <div key={file.path} style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8,border:`1px solid ${C.border}`,borderRadius:8,padding:"8px 10px"}}>
              <div style={{minWidth:0}}>
                <div style={{fontSize:11,color:C.text,fontFamily:"'JetBrains Mono',monospace",whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{file.path}</div>
                <div style={{fontSize:9,color:C.muted}}>{`mode ${file.mode}`}</div>
              </div>
              <Btn small onClick={()=>downloadText(file.path,file.content)}>Download</Btn>
            </div>
          ))}
        </div>
      </Card>}
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)} disabled={deploying}>Close</Btn>
        <Btn primary onClick={()=>void submitDeploy()} disabled={deploying}>{deploying?"Deploying...":"Deploy New Agent"}</Btn>
      </div>
    </Modal>

    <Modal open={modal==="logs"} onClose={()=>setModal(null)} title={`Agent Logs: ${String(selectedAgent?.name||"")}`} wide>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
        <div style={{fontSize:10,color:C.dim}}>
          {`Live key operations for ${String(selectedAgent?.db_engine||"").toUpperCase()} TDE agent ${String(selectedAgent?.host||"-")}`}
        </div>
        <Btn small onClick={()=>selectedAgent&&void openLogs(selectedAgent)} disabled={logsLoading}>{logsLoading?"Refreshing...":"Refresh"}</Btn>
      </div>
      <Card style={{maxHeight:340,overflowY:"auto"}}>
        <div style={{display:"grid",gap:6}}>
          {logsLoading&&<div style={{fontSize:10,color:C.dim}}>Loading logs...</div>}
          {!logsLoading&&logs.map((item)=>(
            <div key={item.id} style={{display:"grid",gridTemplateColumns:"120px 80px 1fr auto",gap:8,alignItems:"center",borderBottom:`1px solid ${C.border}`,paddingBottom:6}}>
              <div style={{fontSize:10,color:C.muted,fontFamily:"'JetBrains Mono',monospace"}}>{formatAgo(item.created_at)}</div>
              <B c={String(item.status||"").toLowerCase()==="success"?"green":"red"}>{item.operation||"-"}</B>
              <div style={{fontSize:10,color:C.text,fontFamily:"'JetBrains Mono',monospace",whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{item.key_id||"-"}</div>
              <div style={{fontSize:9,color:String(item.status||"").toLowerCase()==="success"?C.muted:C.red,maxWidth:260,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{item.error_message||item.status}</div>
            </div>
          ))}
          {!logsLoading&&!logs.length&&<div style={{fontSize:10,color:C.dim}}>No key access logs for this agent yet.</div>}
        </div>
      </Card>
      <div style={{display:"flex",justifyContent:"flex-end",marginTop:12}}>
        <Btn onClick={()=>setModal(null)}>Close</Btn>
      </div>
    </Modal>
    {promptDialog.ui}
  </div>;
};


