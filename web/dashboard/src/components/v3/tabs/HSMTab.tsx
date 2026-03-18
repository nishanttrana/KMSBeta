// @ts-nocheck
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  getAuthCLIHSMConfig,
  getAuthCLIStatus,
  listAuthCLIHSMPartitions,
  openAuthCLISession,
  upsertAuthCLIHSMConfig
} from "../../../lib/authAdmin";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { Btn, Card, Chk, FG, Inp, Modal, Row2, Section, Sel, Txt } from "../legacyPrimitives";
import { HSM_VENDOR_PROFILES, inferHSMVendor, normalizeHSMVendorView } from "../../../modules/hsm/vendorProfiles";
import { Terminal, Upload, Shield, Key, HardDrive, Copy, CheckCircle2, XCircle, RefreshCw, Server, Lock, Cpu } from "lucide-react";

/* ── tiny copy helper ── */
const copyText=(text:string,onToast?:any)=>{
  navigator.clipboard.writeText(text).then(()=>onToast?.("Copied to clipboard.")).catch(()=>{});
};

/* ── monospace code block ── */
const CodeBlock=({value,onToast,label}:{value:string,onToast?:any,label?:string})=>(
  <div style={{position:"relative",background:"rgba(0,0,0,.35)",borderRadius:6,padding:"8px 10px",fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:C.text,whiteSpace:"pre-wrap",wordBreak:"break-all",lineHeight:1.6}}>
    {label&&<div style={{fontSize:8,color:C.muted,marginBottom:4,textTransform:"uppercase",letterSpacing:1}}>{label}</div>}
    {value}
    <span onClick={()=>copyText(value,onToast)} style={{position:"absolute",top:6,right:6,cursor:"pointer",color:C.dim,fontSize:10}} title="Copy"><Copy size={12}/></span>
  </div>
);

/* ── status dot ── */
const Dot=({ok}:{ok:boolean})=>(
  <span style={{display:"inline-block",width:7,height:7,borderRadius:4,background:ok?C.green:C.red,flexShrink:0}}/>
);

/* ── KV row in info tables ── */
const KV=({k,v,mono}:{k:string,v:string,mono?:boolean})=>(
  <div style={{display:"flex",justifyContent:"space-between",padding:"3px 0",fontSize:10,gap:8}}>
    <span style={{color:C.muted}}>{k}</span>
    <span style={{color:C.text,textAlign:"right",...(mono?{fontFamily:"'JetBrains Mono',monospace"}:{})}}>{v}</span>
  </div>
);

/* ── Step indicator ── */
const Step=({n,title,done,active}:{n:number,title:string,done?:boolean,active?:boolean})=>(
  <div style={{display:"flex",alignItems:"center",gap:8,padding:"6px 0"}}>
    <span style={{
      width:22,height:22,borderRadius:11,display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,fontWeight:700,flexShrink:0,
      background:done?C.green:active?C.accent:"rgba(255,255,255,.08)",
      color:done||active?C.bg:C.muted
    }}>{done?"✓":n}</span>
    <span style={{fontSize:11,color:done?C.green:active?C.text:C.muted,fontWeight:active?600:400}}>{title}</span>
  </div>
);

export const HSMTab=({session,onToast,subView,onSubViewChange})=>{
  const initRef=useRef("");
  const [modal,setModal]=useState<null|"gen"|"ssh">(null);
  const [statusLoading,setStatusLoading]=useState(false);
  const [configLoading,setConfigLoading]=useState(false);
  const [configSaving,setConfigSaving]=useState(false);
  const [discovering,setDiscovering]=useState(false);
  const [cliStatus,setCLIStatus]=useState<any>(null);
  const [cliHints,setCLIHints]=useState<any>(null);
  const [providerName,setProviderName]=useState("customer-hsm");
  const [hsmVendorID,setHSMVendorID]=useState("generic");
  const [providerFileName,setProviderFileName]=useState("");
  const [pinEnvVar,setPinEnvVar]=useState("HSM_PIN");
  const [providerReadOnly,setProviderReadOnly]=useState(false);
  const [providerEnabled,setProviderEnabled]=useState(false);
  const [configUpdatedAt,setConfigUpdatedAt]=useState("");
  const [configUpdatedBy,setConfigUpdatedBy]=useState("");
  const [slots,setSlots]=useState<any[]>([]);
  const [rawOutput,setRawOutput]=useState("");
  const [lastDiscoveredAt,setLastDiscoveredAt]=useState("");
  const [selectedSlotID,setSelectedSlotID]=useState("");
  const [selectedPartition,setSelectedPartition]=useState("");
  const [keyAlgo,setKeyAlgo]=useState("AES-256");
  const [keyLabel,setKeyLabel]=useState("");
  /* SSH session state */
  const [sshUser,setSshUser]=useState("cli-user");
  const [sshPass,setSshPass]=useState("");
  const [sshOpening,setSshOpening]=useState(false);
  const [sshSession,setSshSession]=useState<any>(null);
  const [keyExtractable,setKeyExtractable]=useState(false);
  const [keySensitive,setKeySensitive]=useState(true);
  const [keyTokenObj,setKeyTokenObj]=useState(true);

  const tabVendorID=useMemo(()=>normalizeHSMVendorView(String(subView||"hsm-generic")),[subView]);
  const activeVendorID=onSubViewChange?tabVendorID:hsmVendorID;
  const activeVendor=HSM_VENDOR_PROFILES[activeVendorID]||HSM_VENDOR_PROFILES.generic;

  const providerDir=String(cliHints?.provider_library_dir||"").trim();
  const templateLibraryPath=String(cliHints?.pkcs11_config_template?.library_path||"").trim();
  const workspaceRoot=String(cliHints?.workspace_root||"").trim();
  const integrationService=String(cliHints?.integration_service||"").trim()||"hsm-integration";
  const cliEnabled=Boolean(cliStatus?.enabled);
  const cliHost=String(cliStatus?.host||"127.0.0.1");
  const cliPort=Number(cliStatus?.port||2222);
  const cliUsername=String(cliStatus?.cli_username||"cli-user");

  const resolvedLibraryPath=useMemo(()=>{
    const file=String(providerFileName||"").trim();
    if(providerDir&&file) return `${providerDir}/${file}`;
    if(file&&templateLibraryPath.includes("<pkcs11-library-file>")) return templateLibraryPath.replace("<pkcs11-library-file>",file);
    return templateLibraryPath;
  },[providerDir,providerFileName,templateLibraryPath]);

  const partitionOptions=useMemo(()=>{
    const seen=new Set<string>(); const out:string[]=[];
    for(const item of Array.isArray(slots)?slots:[]){
      const label=String(item?.partition||item?.token_label||"").trim();
      if(!label||seen.has(label)) continue;
      seen.add(label); out.push(label);
    }
    const selected=String(selectedPartition||"").trim();
    if(selected&&!seen.has(selected)) out.unshift(selected);
    return out;
  },[selectedPartition,slots]);

  const slotOptions=useMemo(()=>{
    const out=Array.isArray(slots)?[...slots]:[];
    const selected=String(selectedSlotID||"").trim();
    if(selected&&!out.some((s:any)=>String(s?.slot_id||"").trim()===selected)) out.unshift({slot_id:selected,slot_name:"saved-slot",token_present:true});
    return out;
  },[selectedSlotID,slots]);

  const inferLibraryFilename=(libraryPath:string)=>{
    const normalized=String(libraryPath||"").trim().replace(/\\/g,"/");
    if(!normalized||normalized.includes("<pkcs11-library-file>")) return "";
    const parts=normalized.split("/").filter(Boolean);
    return parts.length?String(parts[parts.length-1]||"").trim():"";
  };

  const applyVendorProfile=(vendorID:string,force=false)=>{
    const profile=HSM_VENDOR_PROFILES[vendorID]||HSM_VENDOR_PROFILES.generic;
    setHSMVendorID(profile.id);
    if(force||!String(providerName||"").trim()||String(providerName||"").trim()==="customer-hsm") setProviderName(String(profile.defaultProviderName||"customer-hsm"));
    if(force||!String(pinEnvVar||"").trim()||String(pinEnvVar||"").trim()==="HSM_PIN") setPinEnvVar(String(profile.defaultPINEnvVar||"HSM_PIN"));
  };

  useEffect(()=>{
    if(!onSubViewChange) return;
    setHSMVendorID(tabVendorID);
    applyVendorProfile(tabVendorID,false);
  },[onSubViewChange,tabVendorID]);

  const refreshCLIHints=useCallback(async(silent=false)=>{
    if(!session?.token) return;
    setStatusLoading(true);
    try{
      const out=await getAuthCLIStatus(session);
      setCLIStatus(out||null); setCLIHints(out?.hsm_pkcs11_onboarding||null);
      setSshUser(String(out?.cli_username||"cli-user"));
      if(!silent) onToast?.("HSM integration status refreshed.");
    }catch(error){ onToast?.(`HSM status load failed: ${errMsg(error)}`); }
    finally{ setStatusLoading(false); }
  },[session,onToast]);

  const loadProviderConfig=useCallback(async(silent=false)=>{
    if(!session?.token) return;
    setConfigLoading(true);
    try{
      const cfg=await getAuthCLIHSMConfig(session);
      setProviderName(String(cfg?.provider_name||"customer-hsm").trim()||"customer-hsm");
      setPinEnvVar(String(cfg?.pin_env_var||"HSM_PIN").trim()||"HSM_PIN");
      if(!onSubViewChange) setHSMVendorID(inferHSMVendor(cfg?.metadata,cfg?.provider_name,cfg?.library_path));
      setProviderReadOnly(Boolean(cfg?.read_only)); setProviderEnabled(Boolean(cfg?.enabled));
      setConfigUpdatedAt(String(cfg?.updated_at||"").trim()); setConfigUpdatedBy(String(cfg?.updated_by||"").trim());
      const nextSlotID=String(cfg?.slot_id||"").trim(); if(nextSlotID) setSelectedSlotID(nextSlotID);
      const nextPartition=String(cfg?.partition_label||cfg?.token_label||"").trim(); if(nextPartition) setSelectedPartition(nextPartition);
      const nextDiscoveredAt=String(cfg?.metadata?.last_discovery_at||"").trim(); if(nextDiscoveredAt) setLastDiscoveredAt(nextDiscoveredAt);
      const inferredFile=inferLibraryFilename(String(cfg?.library_path||"").trim()); if(inferredFile) setProviderFileName(inferredFile);
      if(!silent) onToast?.("HSM provider config loaded.");
    }catch(error){ onToast?.(`HSM config load failed: ${errMsg(error)}`); }
    finally{ setConfigLoading(false); }
  },[session,onToast,onSubViewChange]);

  const persistProviderConfig=async(overrides:any={},options:any={})=>{
    if(!session?.token){ onToast?.("Login required."); return null; }
    const effectiveLibraryPath=String((overrides?.library_path??resolvedLibraryPath)||"").trim();
    const effectivePartition=String((overrides?.partition_label??overrides?.token_label??selectedPartition)||"").trim();
    const metadataInput={ui_source:"dashboard-hsm",hsm_vendor_id:String(activeVendor?.id||"generic"),hsm_vendor_label:String(activeVendor?.label||"Generic PKCS#11 HSM"),hsm_vendor_abbreviations:Array.isArray(activeVendor?.abbreviations)?activeVendor.abbreviations:[],...(overrides?.metadata&&typeof overrides.metadata==="object"?overrides.metadata:{})};
    setConfigSaving(true);
    try{
      const updated=await upsertAuthCLIHSMConfig(session,{provider_name:String((overrides?.provider_name??providerName)||"customer-hsm").trim()||"customer-hsm",integration_service:String((overrides?.integration_service??integrationService)||"hsm-integration").trim()||"hsm-integration",library_path:effectiveLibraryPath,slot_id:String((overrides?.slot_id??selectedSlotID)||"").trim(),partition_label:effectivePartition,token_label:String((overrides?.token_label??effectivePartition)||"").trim(),pin_env_var:String((overrides?.pin_env_var??pinEnvVar)||"HSM_PIN").trim()||"HSM_PIN",read_only:Boolean(overrides?.read_only??providerReadOnly),enabled:Boolean(overrides?.enabled??providerEnabled),metadata:metadataInput});
      setProviderName(String(updated?.provider_name||"customer-hsm").trim()||"customer-hsm");
      setPinEnvVar(String(updated?.pin_env_var||"HSM_PIN").trim()||"HSM_PIN");
      if(!onSubViewChange) setHSMVendorID(inferHSMVendor(updated?.metadata,updated?.provider_name,updated?.library_path));
      setProviderReadOnly(Boolean(updated?.read_only)); setProviderEnabled(Boolean(updated?.enabled));
      setSelectedSlotID(String(updated?.slot_id||"").trim()); setSelectedPartition(String(updated?.partition_label||updated?.token_label||"").trim());
      setConfigUpdatedAt(String(updated?.updated_at||"").trim()); setConfigUpdatedBy(String(updated?.updated_by||"").trim());
      const inferredFile=inferLibraryFilename(String(updated?.library_path||"").trim()); if(inferredFile) setProviderFileName(inferredFile);
      if(!Boolean(options?.silent_success)) onToast?.(String(options?.success_message||"HSM provider config saved."));
      return updated;
    }catch(error){ onToast?.(`${String(options?.error_prefix||"HSM save failed")}: ${errMsg(error)}`); return null; }
    finally{ setConfigSaving(false); }
  };

  const autoFetchPartitions=async()=>{
    if(!session?.token){ onToast?.("Login required."); return; }
    const libPath=String(resolvedLibraryPath||"").trim();
    if(!libPath||libPath.includes("<pkcs11-library-file>")){ onToast?.("Enter the PKCS#11 library filename first."); return; }
    setDiscovering(true);
    try{
      const out=await listAuthCLIHSMPartitions(session,libPath);
      const rows=Array.isArray(out?.items)?out.items:[];
      setSlots(rows); setRawOutput(String(out?.raw_output||""));
      const discoveredAt=new Date().toISOString(); setLastDiscoveredAt(discoveredAt);
      const firstSlot=String(rows[0]?.slot_id||"").trim();
      const firstWithPartition=rows.find((r:any)=>String(r?.partition||r?.token_label||"").trim());
      const firstPartition=String(firstWithPartition?.partition||firstWithPartition?.token_label||"").trim();
      if(firstSlot) setSelectedSlotID(firstSlot);
      if(firstPartition) setSelectedPartition(firstPartition);
      const persisted=await persistProviderConfig({integration_service:String(out?.service_name||integrationService||"hsm-integration").trim()||"hsm-integration",library_path:libPath,slot_id:firstSlot,partition_label:firstPartition,token_label:firstPartition,metadata:{auto_bound:true,discovered_service:String(out?.service_name||integrationService||"hsm-integration").trim()||"hsm-integration",last_discovery_at:discoveredAt,discovered_slot_count:rows.length}},{silent_success:true,error_prefix:"Auto-bind failed"});
      onToast?.(persisted?`Discovered ${rows.length} slot(s) and auto-bound config.`:`Discovered ${rows.length} slot(s).`);
    }catch(error){ onToast?.(`Partition discovery failed: ${errMsg(error)}`); }
    finally{ setDiscovering(false); }
  };

  /* SSH session open */
  const openSSHSession=async()=>{
    if(!session?.token) return;
    if(!sshUser.trim()||!sshPass.trim()){ onToast?.("SSH username and password required."); return; }
    setSshOpening(true);
    try{
      const opened=await openAuthCLISession(session,{username:sshUser.trim(),password:sshPass});
      setSshSession(opened); setSshPass("");
      onToast?.("SSH session opened. Use the commands below to upload your PKCS#11 library.");
    }catch(error){ onToast?.(`SSH session failed: ${errMsg(error)}`); }
    finally{ setSshOpening(false); }
  };

  useEffect(()=>{
    if(!selectedSlotID) return;
    const slot=(Array.isArray(slots)?slots:[]).find((item:any)=>String(item?.slot_id||"")===String(selectedSlotID));
    const partition=String(slot?.partition||slot?.token_label||"").trim();
    if(partition&&!String(selectedPartition||"").trim()) setSelectedPartition(partition);
  },[selectedPartition,selectedSlotID,slots]);

  /* Auto-load on mount */
  useEffect(()=>{
    const token=String(session?.token||"");
    if(!token||initRef.current===token) return;
    initRef.current=token;
    void refreshCLIHints(true);
    void loadProviderConfig(true);
  },[session?.token,refreshCLIHints,loadProviderConfig]);

  /* ── derived ── */
  const hasLibrary=Boolean(providerFileName.trim());
  const hasSlots=slotOptions.length>0;
  const hasPartition=Boolean(selectedPartition.trim());
  const stepComplete={ssh:Boolean(sshSession),upload:hasLibrary,discover:hasSlots,bind:hasPartition&&providerEnabled};
  const scpUploadCmd=`scp -P ${cliPort} ./${Array.isArray(activeVendor?.libraryExamples)?activeVendor.libraryExamples[0]:"libVendorPKCS11.so"} ${cliUsername}@${cliHost}:incoming/`;
  const sftpCmd=`sftp -P ${cliPort} ${cliUsername}@${cliHost}`;
  const sshCmd=sshSession?.ssh_command||`ssh ${cliUsername}@${cliHost} -p ${cliPort}`;
  const installCmd=String(cliHints?.install_library_command||`/opt/vecta/hsm/scripts/install-provider.sh ${providerFileName||"<library-file>"}`);
  const verifyCmd=String(cliHints?.verify_provider_command||`/opt/vecta/hsm/scripts/verify-provider.sh`);

  return <div>
    {/* ── Vendor Header ── */}
    <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:12}}>
      <div style={{width:40,height:40,borderRadius:8,background:"rgba(6,214,224,.08)",display:"flex",alignItems:"center",justifyContent:"center"}}><Cpu size={20} style={{color:C.accent}}/></div>
      <div>
        <div style={{fontSize:14,fontWeight:700,color:C.text}}>{activeVendor?.label||"Generic PKCS#11 HSM"}</div>
        <div style={{fontSize:10,color:C.muted}}>Hardware Security Module integration via PKCS#11 — {activeVendor?.slotTerm} / {activeVendor?.partitionTerm} / {activeVendor?.tokenTerm}</div>
      </div>
      <div style={{marginLeft:"auto",display:"flex",gap:6}}>
        <Btn small onClick={()=>void refreshCLIHints()} disabled={statusLoading}><RefreshCw size={11} style={{marginRight:4}}/>{statusLoading?"Loading...":"Refresh"}</Btn>
      </div>
    </div>

    {activeVendorID==="securosys"&&<Card style={{padding:12,marginBottom:12,background:"rgba(6,214,224,.06)",border:`1px solid ${C.accent}33`}}>
      <div style={{fontSize:11,fontWeight:700,color:C.text,marginBottom:6}}>Securosys Primus Setup</div>
      <div style={{fontSize:10,color:C.muted,lineHeight:1.6}}>
        Upload the Primus PKCS#11 library, discover the published PKCS#11 slot IDs, then bind the selected slot to the target Primus partition user. The default provider profile is <code style={{color:C.accent}}>securosys-primus</code> and the default PIN environment variable is <code style={{color:C.accent}}>SECUROSYS_HSM_PIN</code>.
      </div>
    </Card>}

    {/* ── Onboarding Steps ── */}
    <Card style={{padding:14,marginBottom:12}}>
      <div style={{fontSize:11,fontWeight:600,color:C.muted,marginBottom:8}}>PKCS#11 LIBRARY ONBOARDING</div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:6}}>
        <Step n={1} title="Open SSH Session" done={stepComplete.ssh} active={!stepComplete.ssh}/>
        <Step n={2} title="Upload PKCS#11 Library" done={stepComplete.upload} active={stepComplete.ssh&&!stepComplete.upload}/>
        <Step n={3} title="Discover Slots" done={stepComplete.discover} active={stepComplete.upload&&!stepComplete.discover}/>
        <Step n={4} title="Bind & Enable" done={stepComplete.bind} active={stepComplete.discover&&!stepComplete.bind}/>
      </div>
    </Card>

    {/* ── Row: SSH + Connection Info ── */}
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:10}}>
      {/* SSH Session Panel */}
      <Card style={{padding:14}}>
        <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:10}}>
          <Terminal size={14} style={{color:C.accent}}/>
          <span style={{fontSize:11,fontWeight:600,color:C.text}}>SSH / SFTP Session</span>
          <Dot ok={cliEnabled}/>
          <span style={{fontSize:9,color:cliEnabled?C.green:C.red,marginLeft:2}}>{cliEnabled?"CLI Enabled":"CLI Disabled"}</span>
        </div>
        {!cliEnabled&&<div style={{fontSize:10,color:C.muted,padding:"8px 0"}}>
          The CLI user must be enabled in the Admin panel before SSH access is available. Navigate to Admin → CLI to enable the cli-user account.
        </div>}
        {cliEnabled&&<>
          <Row2>
            <FG label="SSH Username"><Inp value={sshUser} onChange={(e)=>setSshUser(e.target.value)} mono/></FG>
            <FG label="SSH Password"><Inp type="password" value={sshPass} onChange={(e)=>setSshPass(e.target.value)} mono placeholder="Enter CLI password"/></FG>
          </Row2>
          <div style={{display:"flex",gap:6,marginTop:6}}>
            <Btn small primary onClick={()=>void openSSHSession()} disabled={sshOpening||!sshUser.trim()||!sshPass.trim()}>{sshOpening?"Connecting...":"Open SSH Session"}</Btn>
            {sshSession&&<span style={{fontSize:9,color:C.green,display:"flex",alignItems:"center",gap:3}}><CheckCircle2 size={10}/>Session active — expires {new Date(sshSession.expires_at).toLocaleTimeString()}</span>}
          </div>
          {sshSession&&<div style={{marginTop:10,display:"grid",gap:6}}>
            <CodeBlock value={sshCmd} onToast={onToast} label="SSH Command"/>
            <CodeBlock value={scpUploadCmd} onToast={onToast} label={`SCP Upload (${activeVendor?.shortName} library)`}/>
            <CodeBlock value={sftpCmd} onToast={onToast} label="SFTP Interactive"/>
          </div>}
        </>}
      </Card>

      {/* Connection Info */}
      <Card style={{padding:14}}>
        <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:10}}>
          <Server size={14} style={{color:C.accent}}/>
          <span style={{fontSize:11,fontWeight:600,color:C.text}}>Connection & Status</span>
        </div>
        {[
          ["Vendor",activeVendor?.label||"Generic"],
          ["Integration Mode",cliEnabled?"Hardware PKCS#11 (SSH-integrated)":"Disabled"],
          ["Service",integrationService],
          ["SSH Endpoint",`${cliHost}:${cliPort}`],
          ["Workspace",workspaceRoot||"—"],
          ["Provider Dir",providerDir||"—"],
          ["Library Path",resolvedLibraryPath||"—"],
          ["Slots Discovered",String(Array.isArray(slots)?slots.length:0)],
          ["Partitions",String(partitionOptions.length)],
          ["Provider Enabled",providerEnabled?"Yes":"No"],
          ["Last Updated",configUpdatedAt?new Date(configUpdatedAt).toLocaleString():"Not saved"],
          ["Updated By",configUpdatedBy||"—"]
        ].map(([k,v])=><KV key={k} k={k} v={v} mono/>)}
      </Card>
    </div>

    {/* ── Library Installation Guide ── */}
    <Section title="PKCS#11 Library Installation" actions={<div style={{display:"flex",gap:6}}>
      <Btn small onClick={()=>void loadProviderConfig()} disabled={configLoading}>{configLoading?"Loading...":"Load Saved Config"}</Btn>
    </div>}>
      <Card style={{padding:14}}>
        <div style={{fontSize:10,color:C.muted,marginBottom:10}}>
          Upload the vendor PKCS#11 shared library ({activeVendor?.libraryExamples?.join(" or ")||"libVendorPKCS11.so"}) via SCP/SFTP to the <code style={{color:C.accent}}>incoming/</code> directory, then the install script moves it to the provider directory and verifies the checksum.
        </div>
        <Row2>
          <FG label={`${activeVendor?.shortName||"Generic"} Provider Name`} required>
            <Inp value={providerName} onChange={(e)=>setProviderName(e.target.value)} mono placeholder="customer-hsm"/>
          </FG>
          <FG label="Provider Library Filename" required hint={`Example: ${Array.isArray(activeVendor?.libraryExamples)?activeVendor.libraryExamples.join(" / "):"libVendorPKCS11.so"}`}>
            <Inp value={providerFileName} onChange={(e)=>setProviderFileName(e.target.value)} mono placeholder={String((Array.isArray(activeVendor?.libraryExamples)&&activeVendor.libraryExamples[0])||"libVendorPKCS11.so")}/>
          </FG>
        </Row2>
        <FG label="Resolved PKCS#11 Library Path">
          <Inp value={resolvedLibraryPath||""} readOnly mono/>
        </FG>
        {hasLibrary&&<div style={{marginTop:8,display:"grid",gap:6}}>
          <CodeBlock value={installCmd} onToast={onToast} label="Install Library (run inside SSH)"/>
          <CodeBlock value={verifyCmd} onToast={onToast} label="Verify Provider"/>
        </div>}
      </Card>
    </Section>

    {/* ── Slot Discovery & Binding ── */}
    <Section title={`${activeVendor?.slotTerm||"Slot"} Discovery & Binding`} actions={<div style={{display:"flex",gap:6}}>
      <Btn small primary onClick={()=>void autoFetchPartitions()} disabled={discovering||!hasLibrary}>{discovering?"Discovering...":"Discover Slots"}</Btn>
      <Btn small primary onClick={()=>void persistProviderConfig({},{success_message:"HSM provider config saved."})} disabled={configSaving||configLoading}>{configSaving?"Saving...":"Save Config"}</Btn>
      <Btn small onClick={()=>setModal("gen")} disabled={!hasPartition}>Generate Key in HSM</Btn>
    </div>}>
      <Card style={{padding:14}}>
        <Row2>
          <FG label={`Detected ${activeVendor?.slotTerm||"Slot"}`} required>
            <Sel value={selectedSlotID} onChange={(e)=>setSelectedSlotID(e.target.value)}>
              {slotOptions.map((slot:any)=><option key={`hsm-slot-${String(slot?.slot_id||"")}`} value={String(slot?.slot_id||"")}>
                {`${String(slot?.slot_id||"")} — ${String(slot?.slot_name||"slot")}${slot?.token_present?" (token present)":""}`}
              </option>)}
              {!slotOptions.length&&<option value="">No slots discovered</option>}
            </Sel>
          </FG>
          <FG label={`Detected ${activeVendor?.partitionTerm||"Partition"}`} required>
            <Sel value={selectedPartition} onChange={(e)=>setSelectedPartition(e.target.value)}>
              {partitionOptions.map((p)=><option key={`hsm-part-${p}`} value={p}>{p}</option>)}
              {!partitionOptions.length&&<option value="">No partitions detected</option>}
            </Sel>
          </FG>
        </Row2>
        <Row2>
          <FG label={`${activeVendor?.shortName||"HSM"} PIN Environment Variable`}>
            <Inp value={pinEnvVar} onChange={(e)=>setPinEnvVar(e.target.value)} mono placeholder="HSM_PIN"/>
          </FG>
          <FG label="Integration Service">
            <Inp value={integrationService||"hsm-integration"} readOnly mono/>
          </FG>
        </Row2>
        <div style={{display:"flex",gap:16,marginTop:8}}>
          <Chk label="Enabled for key operations" checked={providerEnabled} onChange={()=>setProviderEnabled((v)=>!v)}/>
          <Chk label="Read-only session mode" checked={providerReadOnly} onChange={()=>setProviderReadOnly((v)=>!v)}/>
        </div>
      </Card>

      {/* Discovered slots table */}
      {slots.length>0&&<Card style={{padding:14,marginTop:8}}>
        <div style={{fontSize:11,fontWeight:600,color:C.muted,marginBottom:8}}>DISCOVERED SLOTS ({slots.length})</div>
        <div style={{display:"grid",gap:4}}>
          {slots.map((slot:any,i:number)=>(
            <div key={i} style={{display:"grid",gridTemplateColumns:"60px 1fr 1fr 1fr 80px",gap:8,fontSize:10,padding:"4px 0",borderBottom:`1px solid ${C.border}`}}>
              <span style={{color:C.accent,fontFamily:"'JetBrains Mono',monospace"}}>{String(slot?.slot_id||"")}</span>
              <span style={{color:C.text}}>{String(slot?.slot_name||"—")}</span>
              <span style={{color:C.muted}}>{String(slot?.token_label||slot?.partition||"—")}</span>
              <span style={{color:C.dim}}>{String(slot?.token_manufacturer||"—")}</span>
              <span style={{color:slot?.token_present?C.green:C.red,textAlign:"right"}}>{slot?.token_present?"Present":"Absent"}</span>
            </div>
          ))}
        </div>
      </Card>}

      {/* Raw output */}
      {rawOutput.trim()&&<Card style={{padding:14,marginTop:8}}>
        <FG label="Raw pkcs11-tool Output" hint="Captured from list-partitions.sh inside hsm-integration service">
          <Txt rows={8} value={rawOutput} readOnly placeholder="// Slot discovery output"/>
        </FG>
        <div style={{fontSize:9,color:C.dim,marginTop:4}}>Last discovered: {lastDiscoveredAt?new Date(lastDiscoveredAt).toLocaleString():"—"}</div>
      </Card>}
    </Section>

    {/* ── Key Export Conditions ── */}
    <Section title="Key Export Policy & Conditions">
      <Card style={{padding:14}}>
        <div style={{fontSize:11,fontWeight:600,color:C.muted,marginBottom:10}}>WHEN CAN AN HSM KEY BE EXPORTED?</div>
        <div style={{fontSize:10,color:C.dim,marginBottom:12}}>
          Keys stored in an HSM follow a dual-check export model. Both the KMS policy <b>and</b> the HSM attributes must permit export for key material to leave the HSM boundary.
        </div>
        <div style={{display:"grid",gap:8}}>
          {[
            { condition: "KMS Export Policy", field: "export_allowed = true", desc: "Set via key policy in the Keys tab. If false, the key cannot be exported regardless of HSM attributes.", icon: Shield },
            { condition: "HSM Extractable Attribute", field: "CKA_EXTRACTABLE = true", desc: "Set during key generation in the HSM. If false, the HSM firmware prevents the key from being wrapped.", icon: Key },
            { condition: "HSM Sensitive Attribute", field: "CKA_SENSITIVE", desc: "When true, key material never appears in plaintext outside HSM. Export requires wrapping with a KEK.", icon: Lock },
            { condition: "Wrapping Key Available", field: "wrapping_key_id required", desc: "A wrapping key (KEK) must exist and be accessible to wrap the target key for secure export.", icon: HardDrive },
            { condition: "Approval Workflow (if configured)", field: "approval_required = true", desc: "If quorum policy is attached, M-of-N approvals must be granted before export proceeds.", icon: CheckCircle2 },
          ].map((item) => (
            <div key={item.condition} style={{display:"grid",gridTemplateColumns:"32px 1fr",gap:10,padding:"8px 10px",borderRadius:6,background:"rgba(255,255,255,.02)",border:`1px solid ${C.border}`}}>
              <div style={{display:"flex",alignItems:"center",justifyContent:"center"}}><item.icon size={16} style={{color:C.accent}}/></div>
              <div>
                <div style={{fontSize:11,fontWeight:700,color:C.text}}>{item.condition}</div>
                <div style={{fontSize:9,color:C.accent,fontFamily:"'JetBrains Mono',monospace",marginTop:2}}>{item.field}</div>
                <div style={{fontSize:10,color:C.dim,marginTop:3}}>{item.desc}</div>
              </div>
            </div>
          ))}
        </div>
        <div style={{marginTop:12,padding:"8px 12px",borderRadius:6,background:`${C.amber}12`,border:`1px solid ${C.amber}33`,fontSize:10,color:C.dim}}>
          <b style={{color:C.amber}}>Sync behavior:</b> Non-exportable keys sync as <code style={{color:C.accent}}>metadata_only</code> across cluster nodes. Exportable keys sync as <code style={{color:C.accent}}>wrapped_blob_allowed</code>, meaning a wrapped copy can be replicated.
        </div>
      </Card>
    </Section>

    {/* ── HSM Certificate Storage ── */}
    <Section title="Certificate Storage in HSM">
      <Card style={{padding:14}}>
        <div style={{fontSize:11,fontWeight:600,color:C.muted,marginBottom:10}}>STORE CERTIFICATES IN HSM</div>
        <div style={{fontSize:10,color:C.dim,marginBottom:12}}>
          Just like individual keys, X.509 certificates can be stored with their private keys inside the HSM. The KMS holds a reference (metadata) while the actual private key and optionally the certificate object remain on the HSM.
        </div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:12}}>
          <Card style={{padding:10,background:"rgba(255,255,255,.02)"}}>
            <div style={{fontSize:10,fontWeight:700,color:C.green,marginBottom:6}}>HSM-Backed CA</div>
            <div style={{display:"grid",gap:4,fontSize:10,color:C.dim}}>
              <div>1. Create CA with <code style={{color:C.accent}}>key_backend: "hsm"</code></div>
              <div>2. Specify <code style={{color:C.accent}}>key_ref</code> pointing to HSM key ID</div>
              <div>3. Signing operations use HSM via PKCS#11</div>
              <div>4. Private key never leaves HSM boundary</div>
            </div>
          </Card>
          <Card style={{padding:10,background:"rgba(255,255,255,.02)"}}>
            <div style={{fontSize:10,fontWeight:700,color:C.blue,marginBottom:6}}>HSM-Backed Certificates</div>
            <div style={{display:"grid",gap:4,fontSize:10,color:C.dim}}>
              <div>1. Generate key pair inside HSM</div>
              <div>2. Export CSR from HSM key</div>
              <div>3. Issue certificate via KMS CA</div>
              <div>4. Store cert object on HSM via PKCS#11 <code style={{color:C.accent}}>C_CreateObject</code></div>
            </div>
          </Card>
        </div>
        <div style={{display:"grid",gap:6}}>
          {[
            { label: "CA Key Backend", value: `key_backend = "hsm" | key_ref = "<key-id>"`, desc: "Set when creating a CA to use HSM for signing" },
            { label: "Certificate Key Ref", value: `key_ref = "<hsm-key-id>"`, desc: "Links issued certificate to its HSM private key" },
            { label: "HSM Partition", value: `hsm_partition_label = "${selectedPartition||"<partition>"}"`, desc: "PKCS#11 partition where cert objects are stored" },
            { label: "Object Class", value: "CKO_CERTIFICATE (X.509)", desc: "PKCS#11 object type for certificate storage" },
            { label: "Trust Attributes", value: "CKA_TRUSTED, CKA_CERTIFICATE_CATEGORY", desc: "PKCS#11 attributes for CA trust chain" },
          ].map((item) => (
            <div key={item.label} style={{display:"grid",gridTemplateColumns:"160px 1fr",gap:8,padding:"6px 0",borderBottom:`1px solid ${C.border}`}}>
              <div style={{fontSize:10,fontWeight:600,color:C.text}}>{item.label}</div>
              <div>
                <div style={{fontSize:10,color:C.accent,fontFamily:"'JetBrains Mono',monospace"}}>{item.value}</div>
                <div style={{fontSize:9,color:C.dim}}>{item.desc}</div>
              </div>
            </div>
          ))}
        </div>
        <div style={{marginTop:12,padding:"8px 12px",borderRadius:6,background:`${C.blue}12`,border:`1px solid ${C.blue}33`,fontSize:10,color:C.dim}}>
          <b style={{color:C.blue}}>Supported HSM vendors:</b> Any PKCS#11 v2.40+ compliant HSM — Securosys Primus, Thales Luna, Entrust nShield, AWS CloudHSM, Marvell LiquidSecurity, Utimaco, YubiHSM, SoftHSM (dev).
        </div>
      </Card>
    </Section>

    {/* ── Generate Key Modal ── */}
    <Modal open={modal==="gen"} onClose={()=>setModal(null)} title="Generate Key in HSM">
      <div style={{fontSize:10,color:C.muted,marginBottom:10}}>Generate a new cryptographic key object directly inside the HSM {activeVendor?.partitionTerm||"partition"}. The key never leaves the HSM boundary.</div>
      <FG label="Algorithm" required>
        <Sel value={keyAlgo} onChange={(e)=>setKeyAlgo(e.target.value)}>
          <option value="AES-256">AES-256 (Symmetric)</option>
          <option value="AES-128">AES-128 (Symmetric)</option>
          <option value="RSA-2048">RSA-2048</option>
          <option value="RSA-4096">RSA-4096</option>
          <option value="ECDSA-P256">ECDSA P-256</option>
          <option value="ECDSA-P384">ECDSA P-384</option>
          <option value="Ed25519">Ed25519</option>
        </Sel>
      </FG>
      <FG label="Key Label" required hint="Unique label for the key object on the HSM">
        <Inp placeholder="e.g. kms-master-key-001" mono value={keyLabel} onChange={(e)=>setKeyLabel(e.target.value)}/>
      </FG>
      <Row2>
        <FG label={activeVendor?.partitionTerm||"Partition"} required>
          <Sel value={selectedPartition} onChange={(e)=>setSelectedPartition(e.target.value)}>
            {partitionOptions.map((p)=><option key={`hsm-gen-part-${p}`} value={p}>{p}</option>)}
            {!partitionOptions.length&&<option value="">No partitions detected</option>}
          </Sel>
        </FG>
        <FG label={activeVendor?.slotTerm||"Slot"}>
          <Inp value={selectedSlotID||"auto"} readOnly mono/>
        </FG>
      </Row2>
      <FG label="Key Attributes">
        <Chk label="Extractable (can be wrapped and exported)" checked={keyExtractable} onChange={()=>setKeyExtractable(v=>!v)}/>
        <Chk label="Sensitive (never appears in plaintext outside HSM)" checked={keySensitive} onChange={()=>setKeySensitive(v=>!v)}/>
        <Chk label="Token object (persists on HSM across sessions)" checked={keyTokenObj} onChange={()=>setKeyTokenObj(v=>!v)}/>
      </FG>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
        <Btn primary onClick={()=>{
          onToast?.(`HSM key generation requested: ${keyAlgo} label="${keyLabel}" partition="${selectedPartition}" [extractable=${keyExtractable}, sensitive=${keySensitive}, token=${keyTokenObj}]`);
          setModal(null);
        }} disabled={!selectedPartition.trim()||!keyLabel.trim()}>Generate in HSM</Btn>
      </div>
    </Modal>
  </div>;
};
