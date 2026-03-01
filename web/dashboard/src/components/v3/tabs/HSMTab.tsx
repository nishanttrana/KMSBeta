// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import {
  getAuthCLIHSMConfig,
  getAuthCLIStatus,
  listAuthCLIHSMPartitions,
  upsertAuthCLIHSMConfig
} from "../../../lib/authAdmin";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { Btn, Card, Chk, FG, Inp, Modal, Row2, Section, Sel, Txt } from "../legacyPrimitives";
import { HSM_VENDOR_PROFILES, inferHSMVendor, normalizeHSMVendorView } from "../../../modules/hsm/vendorProfiles";
export const HSMTab=({session,onToast,subView,onSubViewChange})=>{
  const [modal,setModal]=useState<null|"gen">(null);
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
  const tabVendorID=useMemo(()=>normalizeHSMVendorView(String(subView||"hsm-generic")),[subView]);
  const activeVendorID=onSubViewChange?tabVendorID:hsmVendorID;
  const activeVendor=HSM_VENDOR_PROFILES[activeVendorID]||HSM_VENDOR_PROFILES.generic;

  const providerDir=String(cliHints?.provider_library_dir||"").trim();
  const templateLibraryPath=String(cliHints?.pkcs11_config_template?.library_path||"").trim();
  const workspaceRoot=String(cliHints?.workspace_root||"").trim();
  const integrationService=String(cliHints?.integration_service||"").trim()||"hsm-integration";
  const resolvedLibraryPath=useMemo(()=>{
    const file=String(providerFileName||"").trim();
    if(providerDir&&file){
      return `${providerDir}/${file}`;
    }
    if(file&&templateLibraryPath.includes("<pkcs11-library-file>")){
      return templateLibraryPath.replace("<pkcs11-library-file>",file);
    }
    return templateLibraryPath;
  },[providerDir,providerFileName,templateLibraryPath]);

  const partitionOptions=useMemo(()=>{
    const seen=new Set<string>();
    const out:string[]=[];
    for(const item of Array.isArray(slots)?slots:[]){
      const label=String(item?.partition||item?.token_label||"").trim();
      if(!label||seen.has(label)){
        continue;
      }
      seen.add(label);
      out.push(label);
    }
    const selected=String(selectedPartition||"").trim();
    if(selected&&!seen.has(selected)){
      out.unshift(selected);
    }
    return out;
  },[selectedPartition,slots]);

  const slotOptions=useMemo(()=>{
    const out=Array.isArray(slots)?[...slots]:[];
    const selected=String(selectedSlotID||"").trim();
    if(selected&&!out.some((slot:any)=>String(slot?.slot_id||"").trim()===selected)){
      out.unshift({slot_id:selected,slot_name:"saved-slot",token_present:true});
    }
    return out;
  },[selectedSlotID,slots]);

  const inferLibraryFilename=(libraryPath:string)=>{
    const normalized=String(libraryPath||"").trim().replace(/\\/g,"/");
    if(!normalized||normalized.includes("<pkcs11-library-file>")){
      return "";
    }
    const parts=normalized.split("/").filter(Boolean);
    return parts.length?String(parts[parts.length-1]||"").trim():"";
  };

  const applyVendorProfile=(vendorID:string,force=false)=>{
    const profile=HSM_VENDOR_PROFILES[vendorID]||HSM_VENDOR_PROFILES.generic;
    setHSMVendorID(profile.id);
    if(force||!String(providerName||"").trim()||String(providerName||"").trim()==="customer-hsm"){
      setProviderName(String(profile.defaultProviderName||"customer-hsm"));
    }
    if(force||!String(pinEnvVar||"").trim()||String(pinEnvVar||"").trim()==="HSM_PIN"){
      setPinEnvVar(String(profile.defaultPINEnvVar||"HSM_PIN"));
    }
  };

  useEffect(()=>{
    if(!onSubViewChange){
      return;
    }
    setHSMVendorID(tabVendorID);
    applyVendorProfile(tabVendorID,false);
  },[onSubViewChange,tabVendorID]);

  const refreshCLIHints=async(silent=false)=>{
    if(!session?.token){
      return;
    }
    setStatusLoading(true);
    try{
      const out=await getAuthCLIStatus(session);
      setCLIStatus(out||null);
      setCLIHints(out?.hsm_pkcs11_onboarding||null);
      if(!silent){
        onToast?.("HSM integration status refreshed.");
      }
    }catch(error){
      onToast?.(`HSM status load failed: ${errMsg(error)}`);
    }finally{
      setStatusLoading(false);
    }
  };

  const loadProviderConfig=async(silent=false)=>{
    if(!session?.token){
      return;
    }
    setConfigLoading(true);
    try{
      const cfg=await getAuthCLIHSMConfig(session);
      const nextProviderName=String(cfg?.provider_name||"customer-hsm").trim()||"customer-hsm";
      const nextPINEnvVar=String(cfg?.pin_env_var||"HSM_PIN").trim()||"HSM_PIN";
      const nextLibraryPath=String(cfg?.library_path||"").trim();
      const nextSlotID=String(cfg?.slot_id||"").trim();
      const nextPartition=String(cfg?.partition_label||cfg?.token_label||"").trim();
      const nextDiscoveredAt=String(cfg?.metadata?.last_discovery_at||"").trim();

      setProviderName(nextProviderName);
      setPinEnvVar(nextPINEnvVar);
      if(!onSubViewChange){
        setHSMVendorID(inferHSMVendor(cfg?.metadata,nextProviderName,nextLibraryPath));
      }
      setProviderReadOnly(Boolean(cfg?.read_only));
      setProviderEnabled(Boolean(cfg?.enabled));
      setConfigUpdatedAt(String(cfg?.updated_at||"").trim());
      setConfigUpdatedBy(String(cfg?.updated_by||"").trim());
      if(nextSlotID){
        setSelectedSlotID(nextSlotID);
      }
      if(nextPartition){
        setSelectedPartition(nextPartition);
      }
      if(nextDiscoveredAt){
        setLastDiscoveredAt(nextDiscoveredAt);
      }
      const inferredFile=inferLibraryFilename(nextLibraryPath);
      if(inferredFile){
        setProviderFileName(inferredFile);
      }
      if(!silent){
        onToast?.("Persisted HSM provider config loaded.");
      }
    }catch(error){
      onToast?.(`HSM provider config load failed: ${errMsg(error)}`);
    }finally{
      setConfigLoading(false);
    }
  };

  const persistProviderConfig=async(overrides:any={},options:any={})=>{
    if(!session?.token){
      onToast?.("Login is required to save HSM provider config.");
      return null;
    }
    const effectiveLibraryPath=String((overrides?.library_path??resolvedLibraryPath)||"").trim();
    const effectivePartition=String((overrides?.partition_label??overrides?.token_label??selectedPartition)||"").trim();
    const metadataInput={
      ui_source:"dashboard-hsm",
      hsm_vendor_id:String(activeVendor?.id||"generic"),
      hsm_vendor_label:String(activeVendor?.label||"Generic PKCS#11 HSM"),
      hsm_vendor_abbreviations:Array.isArray(activeVendor?.abbreviations)?activeVendor.abbreviations:[],
      ...(overrides?.metadata&&typeof overrides.metadata==="object"?overrides.metadata:{})
    };
    setConfigSaving(true);
    try{
        const updated=await upsertAuthCLIHSMConfig(session,{
        provider_name:String((overrides?.provider_name??providerName)||"customer-hsm").trim()||"customer-hsm",
        integration_service:String((overrides?.integration_service??integrationService)||"hsm-integration").trim()||"hsm-integration",
        library_path:effectiveLibraryPath,
        slot_id:String((overrides?.slot_id??selectedSlotID)||"").trim(),
        partition_label:effectivePartition,
        token_label:String((overrides?.token_label??effectivePartition)||"").trim(),
        pin_env_var:String((overrides?.pin_env_var??pinEnvVar)||"HSM_PIN").trim()||"HSM_PIN",
        read_only:Boolean(overrides?.read_only??providerReadOnly),
        enabled:Boolean(overrides?.enabled??providerEnabled),
        metadata:metadataInput
      });
      setProviderName(String(updated?.provider_name||"customer-hsm").trim()||"customer-hsm");
      setPinEnvVar(String(updated?.pin_env_var||"HSM_PIN").trim()||"HSM_PIN");
      if(!onSubViewChange){
        setHSMVendorID(inferHSMVendor(updated?.metadata,updated?.provider_name,updated?.library_path));
      }
      setProviderReadOnly(Boolean(updated?.read_only));
      setProviderEnabled(Boolean(updated?.enabled));
      setSelectedSlotID(String(updated?.slot_id||"").trim());
      setSelectedPartition(String(updated?.partition_label||updated?.token_label||"").trim());
      setConfigUpdatedAt(String(updated?.updated_at||"").trim());
      setConfigUpdatedBy(String(updated?.updated_by||"").trim());
      const inferredFile=inferLibraryFilename(String(updated?.library_path||"").trim());
      if(inferredFile){
        setProviderFileName(inferredFile);
      }
      if(!Boolean(options?.silent_success)){
        onToast?.(String(options?.success_message||"HSM provider config saved."));
      }
      return updated;
    }catch(error){
      onToast?.(`${String(options?.error_prefix||"HSM provider save failed")}: ${errMsg(error)}`);
      return null;
    }finally{
      setConfigSaving(false);
    }
  };

  const autoFetchPartitions=async()=>{
    if(!session?.token){
      onToast?.("Login is required to discover HSM partitions.");
      return;
    }
    const libPath=String(resolvedLibraryPath||"").trim();
    if(!libPath||libPath.includes("<pkcs11-library-file>")){
      onToast?.("Enter the uploaded PKCS#11 library filename first.");
      return;
    }
    setDiscovering(true);
    try{
      const out=await listAuthCLIHSMPartitions(session,libPath);
      const rows=Array.isArray(out?.items)?out.items:[];
      setSlots(rows);
      setRawOutput(String(out?.raw_output||""));
      const discoveredAt=new Date().toISOString();
      setLastDiscoveredAt(discoveredAt);
      const firstSlot=String(rows[0]?.slot_id||"").trim();
      const firstWithPartition=rows.find((row:any)=>String(row?.partition||row?.token_label||"").trim());
      const firstPartition=String(firstWithPartition?.partition||firstWithPartition?.token_label||"").trim();
      if(firstSlot){
        setSelectedSlotID(firstSlot);
      }
      if(firstPartition){
        setSelectedPartition(firstPartition);
      }
      const persisted=await persistProviderConfig({
        integration_service:String(out?.service_name||integrationService||"hsm-integration").trim()||"hsm-integration",
        library_path:libPath,
        slot_id:firstSlot,
        partition_label:firstPartition,
        token_label:firstPartition,
        metadata:{
          auto_bound:true,
          discovered_service:String(out?.service_name||integrationService||"hsm-integration").trim()||"hsm-integration",
          last_discovery_at:discoveredAt,
          discovered_slot_count:rows.length
        }
      },{silent_success:true,error_prefix:"Auto-bind failed"});
      if(persisted){
        onToast?.(`Discovered ${rows.length} slot(s) from ${String(out?.service_name||integrationService)} and auto-bound HSM config.`);
      }else{
        onToast?.(`Discovered ${rows.length} slot(s) from ${String(out?.service_name||integrationService)}.`);
      }
    }catch(error){
      onToast?.(`Partition discovery failed: ${errMsg(error)}`);
    }finally{
      setDiscovering(false);
    }
  };

  useEffect(()=>{
    if(!selectedSlotID){
      return;
    }
    const slot=(Array.isArray(slots)?slots:[]).find((item:any)=>String(item?.slot_id||"")===String(selectedSlotID));
    const partition=String(slot?.partition||slot?.token_label||"").trim();
    if(partition&&!String(selectedPartition||"").trim()){
      setSelectedPartition(partition);
    }
  },[selectedPartition,selectedSlotID,slots]);

  const connectionRows=[
    ["HSM Vendor",activeVendor?.label||"Generic PKCS#11 HSM"],
    ["Mode",Boolean(cliStatus?.enabled)?"Hardware PKCS#11 (CLI-integrated)":"CLI integration disabled"],
    ["Service",integrationService],
    ["Endpoint",`${String(cliStatus?.host||"127.0.0.1")}:${Number(cliStatus?.port||2222)}`],
    ["Workspace",workspaceRoot||"-"],
    ["Provider",providerName||"-"],
    ["Provider Dir",providerDir||"-"],
    ["Library Path",resolvedLibraryPath||"-"],
    ["Slots",String(Array.isArray(slots)?slots.length:0)],
    ["Partitions",String(partitionOptions.length)],
    ["Config Enabled",providerEnabled?"yes":"no"],
    ["Config Updated",configUpdatedAt?new Date(configUpdatedAt).toLocaleString():"not saved"]
  ];

  return <div>
    <Section title={`${String(activeVendor?.label||"Generic PKCS#11 HSM")} Profile`}>
      <Card>
        <FG label="Vendor">
          <Inp value={String(activeVendor?.label||"Generic PKCS#11 HSM")} readOnly/>
        </FG>
        <div style={{fontSize:10,color:C.muted}}>
          {`${String(activeVendor?.slotTerm||"Slot")} / ${String(activeVendor?.partitionTerm||"Partition")} / ${String(activeVendor?.tokenTerm||"Token")} terms are applied on this page.`}
        </div>
      </Card>
    </Section>

    <Row2>
      <Card>
        <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:6}}>CONNECTION</div>
        {connectionRows.map(([k,v])=>
          <div key={String(k)} style={{display:"flex",justifyContent:"space-between",padding:"3px 0",fontSize:10,gap:8}}>
            <span style={{color:C.muted}}>{String(k)}</span>
            <span style={{color:C.text,fontFamily:"'JetBrains Mono',monospace",textAlign:"right"}}>{String(v)}</span>
          </div>
        )}
      </Card>
      <Card>
        <div style={{fontSize:11,color:C.muted,fontWeight:600,marginBottom:6}}>DISCOVERY STATUS</div>
        {[["Partition source","PKCS#11 list via dedicated hsm-integration service"],["Last fetch",lastDiscoveredAt?new Date(lastDiscoveredAt).toLocaleString():"not fetched"],[`${String(activeVendor?.slotTerm||"Slot")} selected`,selectedSlotID||"-"],[`${String(activeVendor?.partitionTerm||"Partition")} selected`,selectedPartition||"-"],["Config updated by",configUpdatedBy||"-"],["Auto-bind","Enabled (discovery writes slot/partition to persisted config)"]].map(([k,v])=>
          <div key={String(k)} style={{display:"flex",justifyContent:"space-between",padding:"3px 0",fontSize:10,gap:8}}>
            <span style={{color:C.muted}}>{String(k)}</span>
            <span style={{color:C.accent,textAlign:"right"}}>{String(v)}</span>
          </div>
        )}
        <div style={{display:"flex",gap:8,marginTop:10}}>
          <Btn small onClick={()=>void refreshCLIHints()} disabled={statusLoading}>{statusLoading?"Refreshing...":"Refresh Hints"}</Btn>
          <Btn small onClick={()=>void loadProviderConfig()} disabled={configLoading||configSaving}>{configLoading?"Loading...":"Load Config"}</Btn>
          <Btn small primary onClick={()=>void autoFetchPartitions()} disabled={discovering}>{discovering?"Discovering...":"Auto-fetch Partitions"}</Btn>
        </div>
      </Card>
    </Row2>

    <Section title="HSM Configuration" actions={<div style={{display:"flex",gap:8}}>
      <Btn small onClick={()=>void refreshCLIHints()} disabled={statusLoading}>{statusLoading?"Refreshing...":"Refresh"}</Btn>
      <Btn small onClick={()=>void loadProviderConfig()} disabled={configLoading||configSaving}>{configLoading?"Loading...":"Load Saved"}</Btn>
      <Btn small primary onClick={()=>void autoFetchPartitions()} disabled={discovering}>{discovering?"Discovering...":"Auto-fetch Partitions"}</Btn>
      <Btn small primary onClick={()=>void persistProviderConfig({},{success_message:"HSM provider config saved."})} disabled={configSaving||configLoading}>{configSaving?"Saving...":"Save Provider Config"}</Btn>
      <Btn small onClick={()=>setModal("gen")} disabled={!selectedPartition}>Generate Key in HSM</Btn>
    </div>}>
      <Card>
        <Row2>
          <FG label={`${String(activeVendor?.shortName||"Generic")} Provider Name`} required>
            <Inp value={providerName} onChange={(e)=>setProviderName(e.target.value)} mono placeholder="customer-hsm"/>
          </FG>
          <FG label="Integration Service">
            <Inp value={integrationService||"hsm-integration"} readOnly mono/>
          </FG>
        </Row2>
        <Row2>
          <FG label="Provider Library Directory">
            <Inp value={providerDir||""} readOnly mono/>
          </FG>
          <FG label="Provider Library Filename" required hint={`Example: ${Array.isArray(activeVendor?.libraryExamples)?activeVendor.libraryExamples.join(" / "):"libVendorPKCS11.so"}`}>
            <Inp value={providerFileName} onChange={(e)=>setProviderFileName(e.target.value)} mono placeholder={String((Array.isArray(activeVendor?.libraryExamples)&&activeVendor.libraryExamples[0])||"libVendorPKCS11.so")}/>
          </FG>
        </Row2>
        <FG label="Resolved PKCS#11 Library Path" required>
          <Inp value={resolvedLibraryPath||""} readOnly mono/>
        </FG>
        <Row2>
          <FG label={`Detected ${String(activeVendor?.slotTerm||"Slot")}`} required>
            <Sel value={selectedSlotID} onChange={(e)=>setSelectedSlotID(e.target.value)}>
              {slotOptions.map((slot:any)=><option key={`hsm-slot-${String(slot?.slot_id||"")}`} value={String(slot?.slot_id||"")}>
                {`${String(slot?.slot_id||"")} - ${String(slot?.slot_name||"slot")}${String(slot?.token_present)?" (token present)":""}`}
              </option>)}
              {!slotOptions.length?<option value="">No slots discovered yet</option>:null}
            </Sel>
          </FG>
          <FG label={`Detected ${String(activeVendor?.partitionTerm||"Partition")}`} required>
            <Sel value={selectedPartition} onChange={(e)=>setSelectedPartition(e.target.value)}>
              {partitionOptions.map((partition)=>(
                <option key={`hsm-part-${partition}`} value={partition}>{partition}</option>
              ))}
              {!partitionOptions.length?<option value="">No partitions detected yet</option>:null}
            </Sel>
          </FG>
        </Row2>
        <Row2>
          <FG label={`${String(activeVendor?.shortName||"HSM")} PIN Environment Variable`}>
            <Inp value={pinEnvVar} onChange={(e)=>setPinEnvVar(e.target.value)} mono placeholder="HSM_PIN"/>
          </FG>
          <FG label="Provider Flags">
            <Chk label="Enabled for key operations" checked={providerEnabled} onChange={()=>setProviderEnabled((v)=>!v)}/>
            <Chk label="Read-only session mode" checked={providerReadOnly} onChange={()=>setProviderReadOnly((v)=>!v)}/>
          </FG>
        </Row2>
        <FG label="Raw PKCS#11 Discovery Output" hint="Captured from list-partitions utility inside hsm-integration service.">
          <Txt rows={7} value={rawOutput} readOnly placeholder="// Slot discovery output appears here after auto-fetch"/>
        </FG>
      </Card>
    </Section>

    <Modal open={modal==="gen"} onClose={()=>setModal(null)} title="Generate Key in HSM">
      <FG label="Algorithm" required>
        <Sel value={keyAlgo} onChange={(e)=>setKeyAlgo(e.target.value)}>
          <option value="AES-256">AES-256</option>
          <option value="RSA-2048">RSA-2048</option>
          <option value="RSA-4096">RSA-4096</option>
          <option value="ECDSA-P384">ECDSA-P384</option>
          <option value="Ed25519">Ed25519</option>
        </Sel>
      </FG>
      <FG label="Key Label" required>
        <Inp placeholder="Enter customer key label" mono value={keyLabel} onChange={(e)=>setKeyLabel(e.target.value)}/>
      </FG>
      <FG label={String(activeVendor?.partitionTerm||"Partition")} required>
        <Sel value={selectedPartition} onChange={(e)=>setSelectedPartition(e.target.value)}>
          {partitionOptions.map((partition)=>(
            <option key={`hsm-gen-part-${partition}`} value={partition}>{partition}</option>
          ))}
          {!partitionOptions.length?<option value="">No partitions detected yet</option>:null}
        </Sel>
      </FG>
      <FG label="Key Attributes">
        <Chk label="Extractable (can be wrapped and exported)" checked={false}/>
        <Chk label="Sensitive (never appears in plaintext)" checked={true}/>
        <Chk label="Token object (persists on HSM)" checked={true}/>
      </FG>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
        <Btn primary onClick={()=>{
          onToast?.(`HSM key generate request prepared for partition "${selectedPartition}" (${keyAlgo}).`);
          setModal(null);
        }} disabled={!String(selectedPartition||"").trim()||!String(keyLabel||"").trim()}>Generate in HSM</Btn>
      </div>
    </Modal>
  </div>;
};


