// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import {
  createKMIPClient,
  createKMIPInteropTarget,
  createKMIPProfile,
  deleteKMIPClient,
  deleteKMIPInteropTarget,
  deleteKMIPProfile,
  getKMIPCapabilities,
  listKMIPInteropTargets,
  listKMIPClients,
  listKMIPProfiles,
  validateKMIPInteropTarget
} from "../../../lib/kmip";
import { listCAs } from "../../../lib/certs";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, Chk, FG, Inp, Modal, Row2, Section, Sel, Stat, Txt, usePromptDialog } from "../legacyPrimitives";
export const KMIPTab=({session,onToast})=>{
  const promptDialog=usePromptDialog();
  const [loading,setLoading]=useState(false);
  const [profiles,setProfiles]=useState([]);
  const [clients,setClients]=useState([]);
  const [caItems,setCAItems]=useState([]);
  const [kmipCaps,setKMIPCaps]=useState<any>(null);
  const [modal,setModal]=useState(null);
  const [savingProfile,setSavingProfile]=useState(false);
  const [savingClient,setSavingClient]=useState(false);
  const [deletingProfileID,setDeletingProfileID]=useState("");
  const [deletingClientID,setDeletingClientID]=useState("");
  const [clientCertSource,setClientCertSource]=useState("paste");
  const [issuedBundle,setIssuedBundle]=useState(null);
  const [interopTargets,setInteropTargets]=useState([]);
  const [savingInteropTarget,setSavingInteropTarget]=useState(false);
  const [deletingInteropTargetID,setDeletingInteropTargetID]=useState("");
  const [validatingInteropTargetID,setValidatingInteropTargetID]=useState("");
  const [interopValidationResult,setInteropValidationResult]=useState(null);
  const [interopForm,setInteropForm]=useState({
    name:"",
    vendor:"generic",
    endpoint:"",
    server_name:"",
    expected_min_version:"3.0",
    test_key_operation:true,
    ca_pem:"",
    client_cert_pem:"",
    client_key_pem:""
  });
  const [profileForm,setProfileForm]=useState({
    name:"",
    ca_id:"",
    username_location:"cn",
    subject_field_to_modify:"uid",
    do_not_modify_subject_dn:false,
    certificate_duration_days:365,
    role:"kmip-client",
    organization:"",
    organizational_unit:"",
    email:"",
    uid:"",
    surname:"",
    city:"",
    state:"",
    country:""
  });
  const [clientForm,setClientForm]=useState({
    name:"",
    profile_id:"",
    registration_token:"",
    role:"kmip-client",
    enrollment_mode:"internal",
    common_name:"",
    csr_pem:"",
    certificate_pem:"",
    private_key_pem:"",
    ca_bundle_pem:"",
    serial_number:"",
    password:"",
    password_match:"",
    device_id:"",
    network_id:"",
    machine_id:"",
    media_id:""
  });

  const resetProfileForm=()=>setProfileForm({
    name:"",
    ca_id:"",
    username_location:"cn",
    subject_field_to_modify:"uid",
    do_not_modify_subject_dn:false,
    certificate_duration_days:365,
    role:"kmip-client",
    organization:"",
    organizational_unit:"",
    email:"",
    uid:"",
    surname:"",
    city:"",
    state:"",
    country:""
  });
  const resetClientForm=()=>setClientForm({
    name:"",
    profile_id:"",
    registration_token:"",
    role:"kmip-client",
    enrollment_mode:"internal",
    common_name:"",
    csr_pem:"",
    certificate_pem:"",
    private_key_pem:"",
    ca_bundle_pem:"",
    serial_number:"",
    password:"",
    password_match:"",
    device_id:"",
    network_id:"",
    machine_id:"",
    media_id:""
  });
  const resetInteropForm=()=>setInteropForm({
    name:"",
    vendor:"generic",
    endpoint:"",
    server_name:"",
    expected_min_version:"3.0",
    test_key_operation:true,
    ca_pem:"",
    client_cert_pem:"",
    client_key_pem:""
  });

  const refresh=async(silent=false)=>{
    if(!session?.token){
      setProfiles([]);
      setClients([]);
      setCAItems([]);
      setInteropTargets([]);
      return;
    }
    if(!silent){
      setLoading(true);
    }
    try{
      const [profileItems,clientItems,caList,caps,interopItems]=await Promise.all([
        listKMIPProfiles(session),
        listKMIPClients(session),
        listCAs(session),
        getKMIPCapabilities(session),
        listKMIPInteropTargets(session)
      ]);
      setProfiles(Array.isArray(profileItems)?profileItems:[]);
      setClients(Array.isArray(clientItems)?clientItems:[]);
      setCAItems(Array.isArray(caList)?caList:[]);
      setKMIPCaps(caps||null);
      setInteropTargets(Array.isArray(interopItems)?interopItems:[]);
    }catch(error){
      onToast?.(`KMIP load failed: ${errMsg(error)}`);
    }finally{
      if(!silent){
        setLoading(false);
      }
    }
  };

  useEffect(()=>{
    if(!session?.tenantId){
      setProfiles([]);
      setClients([]);
      setCAItems([]);
      setInteropTargets([]);
      return;
    }
    void refresh();
  },[session?.tenantId]);

  const selectedProfile=useMemo(()=>{
    return (Array.isArray(profiles)?profiles:[]).find((p)=>String(p.id)===String(clientForm.profile_id))||null;
  },[profiles,clientForm.profile_id]);

  const stats=useMemo(()=>{
    const list=Array.isArray(clients)?clients:[];
    const active=list.filter((it)=>String(it.status||"").toLowerCase()==="active").length;
    const external=list.filter((it)=>String(it.enrollment_mode||"").toLowerCase()==="external").length;
    const expiringSoon=list.filter((it)=>{
      const ts=new Date(String(it.cert_not_after||""));
      if(Number.isNaN(ts.getTime())){
        return false;
      }
      const days=(ts.getTime()-Date.now())/(24*60*60*1000);
      return days>=0&&days<=30;
    }).length;
    return {
      total:list.length,
      active,
      external,
      expiringSoon
    };
  },[clients]);
  const kmipVersionLabel=String(kmipCaps?.highest_supported_version||"").trim()?`KMIP ${String(kmipCaps?.highest_supported_version).trim()}`:"KMIP";
  const kmipProtocolLabel=String(kmipCaps?.protocol||"TTLV over TLS").trim();
  const kmipLibraryLabel=[
    String(kmipCaps?.library||"github.com/ovh/kmip-go").trim(),
    String(kmipCaps?.library_version||"").trim()
  ].filter(Boolean).join(" ");
  const supportedVersions=Array.isArray(kmipCaps?.supported_versions)?kmipCaps.supported_versions:[];
  const implementedOps=Array.isArray(kmipCaps?.implemented_operations)
    ?kmipCaps.implemented_operations
    :(Array.isArray(kmipCaps?.operations)?kmipCaps.operations:[]);
  const unimplementedOps=Array.isArray(kmipCaps?.unimplemented_operations)?kmipCaps.unimplemented_operations:[];
  const implementedObjects=Array.isArray(kmipCaps?.implemented_object_types)
    ?kmipCaps.implemented_object_types
    :(Array.isArray(kmipCaps?.object_types)?kmipCaps.object_types:[]);
  const unimplementedObjects=Array.isArray(kmipCaps?.unimplemented_object_types)?kmipCaps.unimplemented_object_types:[];
  const authModes=Array.isArray(kmipCaps?.auth_modes)?kmipCaps.auth_modes:[];
  const interoperabilityScope=Array.isArray(kmipCaps?.interoperability_scope)?kmipCaps.interoperability_scope:[];
  const integrationTargets=Array.isArray(kmipCaps?.integration_targets)?kmipCaps.integration_targets:[];
  const integrationNote=String(kmipCaps?.integration_note||"").trim();

  const saveProfile=async()=>{
    if(!session?.token){
      return;
    }
    const name=String(profileForm.name||"").trim();
    const caID=String(profileForm.ca_id||"").trim();
    if(!name||!caID){
      onToast?.("Profile name and CA are required.");
      return;
    }
    setSavingProfile(true);
    try{
      const metadata=JSON.stringify({
        organization:String(profileForm.organization||"").trim(),
        organizational_unit:String(profileForm.organizational_unit||"").trim(),
        email:String(profileForm.email||"").trim(),
        uid:String(profileForm.uid||"").trim(),
        surname:String(profileForm.surname||"").trim(),
        city:String(profileForm.city||"").trim(),
        state:String(profileForm.state||"").trim(),
        country:String(profileForm.country||"").trim()
      });
      await createKMIPProfile(session,{
        name,
        ca_id:caID,
        username_location:String(profileForm.username_location||"cn").trim(),
        subject_field_to_modify:String(profileForm.subject_field_to_modify||"uid").trim(),
        do_not_modify_subject_dn:Boolean(profileForm.do_not_modify_subject_dn),
        certificate_duration_days:Math.max(1,Math.min(3650,Number(profileForm.certificate_duration_days||365))),
        role:String(profileForm.role||"kmip-client").trim(),
        metadata_json:metadata
      });
      onToast?.("KMIP client profile created.");
      setModal(null);
      resetProfileForm();
      await refresh(true);
    }catch(error){
      onToast?.(`Create profile failed: ${errMsg(error)}`);
    }finally{
      setSavingProfile(false);
    }
  };

  const readPEMFile=async(file,targetField)=>{
    if(!file){
      return;
    }
    try{
      const text=await file.text();
      setClientForm((prev)=>({...prev,[targetField]:String(text||"")}));
    }catch{
      onToast?.("Unable to read selected file.");
    }
  };

  const downloadText=(filename,content)=>{
    const text=String(content||"");
    if(!text){
      return;
    }
    const blob=new Blob([text],{type:"text/plain;charset=utf-8"});
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url;
    a.download=filename;
    a.click();
    setTimeout(()=>URL.revokeObjectURL(url),500);
  };

  const saveClient=async()=>{
    if(!session?.token){
      return;
    }
    const name=String(clientForm.name||"").trim();
    const mode=String(clientForm.enrollment_mode||"internal").trim().toLowerCase();
    if(!name){
      onToast?.("Client name is required.");
      return;
    }
    if(mode==="internal"&&!String(clientForm.profile_id||"").trim()){
      onToast?.("Select a client profile for internal enrollment.");
      return;
    }
    if(mode==="external"&&!String(clientForm.certificate_pem||"").trim()){
      onToast?.("External enrollment requires a certificate PEM.");
      return;
    }
    if(String(clientForm.password||"")!==String(clientForm.password_match||"")){
      onToast?.("Device credential password mismatch.");
      return;
    }
    setSavingClient(true);
    try{
      const metadata=JSON.stringify({
        serial_number:String(clientForm.serial_number||"").trim(),
        password:String(clientForm.password||"").trim(),
        device_id:String(clientForm.device_id||"").trim(),
        network_id:String(clientForm.network_id||"").trim(),
        machine_id:String(clientForm.machine_id||"").trim(),
        media_id:String(clientForm.media_id||"").trim()
      });
      const out=await createKMIPClient(session,{
        name,
        profile_id:String(clientForm.profile_id||"").trim()||undefined,
        registration_token:String(clientForm.registration_token||"").trim()||undefined,
        role:String(clientForm.role||selectedProfile?.role||"kmip-client").trim(),
        enrollment_mode:mode==="external"?"external":"internal",
        common_name:String(clientForm.common_name||"").trim()||undefined,
        csr_pem:String(clientForm.csr_pem||"").trim()||undefined,
        certificate_pem:String(clientForm.certificate_pem||"").trim()||undefined,
        private_key_pem:String(clientForm.private_key_pem||"").trim()||undefined,
        ca_bundle_pem:String(clientForm.ca_bundle_pem||"").trim()||undefined,
        metadata_json:metadata
      });
      if(String(out?.issued_cert_pem||"").trim()||String(out?.issued_key_pem||"").trim()){
        setIssuedBundle({
          name,
          cert:String(out?.issued_cert_pem||""),
          key:String(out?.issued_key_pem||"")
        });
      }
      onToast?.("KMIP client added successfully.");
      setModal(null);
      resetClientForm();
      await refresh(true);
    }catch(error){
      onToast?.(`Add client failed: ${errMsg(error)}`);
    }finally{
      setSavingClient(false);
    }
  };

  const removeProfile=async(profile:any)=>{
    if(!session?.token){
      return;
    }
    const profileID=String(profile?.id||"").trim();
    if(!profileID){
      return;
    }
    const profileName=String(profile?.name||profileID).trim();
    const confirmed=await promptDialog.confirm({
      title:"Delete KMIP Client Profile",
      message:`Delete KMIP client profile "${profileName}"? Clients using this profile must be deleted first.`,
      confirmLabel:"Delete Profile",
      cancelLabel:"Cancel",
      danger:true
    });
    if(!confirmed){
      return;
    }
    setDeletingProfileID(profileID);
    try{
      await deleteKMIPProfile(session,profileID);
      if(String(clientForm.profile_id||"")===profileID){
        setClientForm((prev)=>({...prev,profile_id:""}));
      }
      onToast?.("KMIP client profile deleted.");
      await refresh(true);
    }catch(error){
      onToast?.(`Delete profile failed: ${errMsg(error)}`);
    }finally{
      setDeletingProfileID("");
    }
  };

  const removeClient=async(client:any)=>{
    if(!session?.token){
      return;
    }
    const clientID=String(client?.id||"").trim();
    if(!clientID){
      return;
    }
    const clientName=String(client?.name||clientID).trim();
    const confirmed=await promptDialog.confirm({
      title:"Delete KMIP Client",
      message:`Delete KMIP client "${clientName}"? This removes certificate-based KMIP access for this client.`,
      confirmLabel:"Delete Client",
      cancelLabel:"Cancel",
      danger:true
    });
    if(!confirmed){
      return;
    }
    setDeletingClientID(clientID);
    try{
      await deleteKMIPClient(session,clientID);
      onToast?.("KMIP client deleted.");
      await refresh(true);
    }catch(error){
      onToast?.(`Delete client failed: ${errMsg(error)}`);
    }finally{
      setDeletingClientID("");
    }
  };

  const saveInteropTarget=async()=>{
    if(!session?.token){
      return;
    }
    const name=String(interopForm.name||"").trim();
    const endpoint=String(interopForm.endpoint||"").trim();
    const caPEM=String(interopForm.ca_pem||"").trim();
    const certPEM=String(interopForm.client_cert_pem||"").trim();
    const keyPEM=String(interopForm.client_key_pem||"").trim();
    if(!name||!endpoint||!caPEM||!certPEM||!keyPEM){
      onToast?.("Name, endpoint, CA PEM, client cert PEM and client key PEM are required.");
      return;
    }
    setSavingInteropTarget(true);
    try{
      await createKMIPInteropTarget(session,{
        name,
        vendor:String(interopForm.vendor||"generic").trim(),
        endpoint,
        server_name:String(interopForm.server_name||"").trim()||undefined,
        expected_min_version:String(interopForm.expected_min_version||"3.0").trim()||undefined,
        test_key_operation:Boolean(interopForm.test_key_operation),
        ca_pem:caPEM,
        client_cert_pem:certPEM,
        client_key_pem:keyPEM
      });
      onToast?.("KMIP interop target created.");
      resetInteropForm();
      setModal(null);
      await refresh(true);
    }catch(error){
      onToast?.(`Create interop target failed: ${errMsg(error)}`);
    }finally{
      setSavingInteropTarget(false);
    }
  };

  const removeInteropTarget=async(target:any)=>{
    if(!session?.token){
      return;
    }
    const targetID=String(target?.id||"").trim();
    if(!targetID){
      return;
    }
    const targetName=String(target?.name||targetID).trim();
    const confirmed=await promptDialog.confirm({
      title:"Delete KMIP Interop Target",
      message:`Delete interop target "${targetName}"?`,
      confirmLabel:"Delete Target",
      cancelLabel:"Cancel",
      danger:true
    });
    if(!confirmed){
      return;
    }
    setDeletingInteropTargetID(targetID);
    try{
      await deleteKMIPInteropTarget(session,targetID);
      onToast?.("KMIP interop target deleted.");
      await refresh(true);
    }catch(error){
      onToast?.(`Delete interop target failed: ${errMsg(error)}`);
    }finally{
      setDeletingInteropTargetID("");
    }
  };

  const runInteropValidation=async(target:any)=>{
    if(!session?.token){
      return;
    }
    const targetID=String(target?.id||"").trim();
    if(!targetID){
      return;
    }
    setValidatingInteropTargetID(targetID);
    try{
      const out=await validateKMIPInteropTarget(session,targetID);
      setInteropValidationResult(out?.result||null);
      if(out?.result?.verified){
        onToast?.(`Interop validation verified for ${String(target?.name||targetID)}.`);
      }else{
        onToast?.(`Interop validation failed for ${String(target?.name||targetID)}: ${String(out?.result?.error||"Unknown error")}`);
      }
      await refresh(true);
    }catch(error){
      onToast?.(`Interop validation failed: ${errMsg(error)}`);
    }finally{
      setValidatingInteropTargetID("");
    }
  };

  return <div>
    <div style={{display:"flex",gap:12,marginBottom:14,flexWrap:"wrap"}}>
      <Stat l="Client Profiles" v={String((profiles||[]).length)} c="blue"/>
      <Stat l="Registered Clients" v={String(stats.total)} c="accent"/>
      <Stat l="Active Clients" v={String(stats.active)} c="green"/>
      <Stat l="Expiring <=30d" v={String(stats.expiringSoon)} c={stats.expiringSoon>0?"amber":"blue"}/>
      <Stat l="Protocol" v={kmipVersionLabel} s={`${kmipProtocolLabel}:${String(kmipCaps?.port||"5696")} | ${kmipLibraryLabel}`} c="purple"/>
    </div>


    <Card style={{marginBottom:10}}>
      <div style={{display:"grid",gap:8}}>
        <div style={{fontSize:11,color:C.text,fontWeight:700}}>KMIP Capabilities (real server coverage)</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:12}}>
          <div>
            <div style={{fontSize:10,color:C.muted,marginBottom:4}}>Supported Protocol Versions</div>
            <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
              {supportedVersions.map((v)=><B key={`ver-${String(v)}`} c="purple">{String(v)}</B>)}
              {!supportedVersions.length?<span style={{fontSize:10,color:C.dim}}>-</span>:null}
            </div>
          </div>
          <div>
            <div style={{fontSize:10,color:C.muted,marginBottom:4}}>Authentication</div>
            <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
              {authModes.map((v)=><B key={`auth-${String(v)}`} c="blue">{String(v)}</B>)}
              {!authModes.length?<span style={{fontSize:10,color:C.dim}}>mTLS client certificate</span>:null}
            </div>
          </div>
        </div>
        <Row2>
          <Card style={{borderColor:C.borderHi}}>
            <div style={{fontSize:10,color:C.muted,marginBottom:4}}>Implemented Operations ({implementedOps.length})</div>
            <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
              {implementedOps.map((op)=><B key={`op-impl-${String(op)}`} c="green">{String(op)}</B>)}
              {!implementedOps.length?<span style={{fontSize:10,color:C.dim}}>-</span>:null}
            </div>
          </Card>
          <Card style={{borderColor:C.borderHi}}>
            <div style={{fontSize:10,color:C.muted,marginBottom:4}}>Missing KMIP 3.2 Operations ({unimplementedOps.length})</div>
            <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
              {unimplementedOps.map((op)=><B key={`op-miss-${String(op)}`} c="amber">{String(op)}</B>)}
              {!unimplementedOps.length?<span style={{fontSize:10,color:C.green}}>None</span>:null}
            </div>
          </Card>
        </Row2>
        <Row2>
          <Card style={{borderColor:C.borderHi}}>
            <div style={{fontSize:10,color:C.muted,marginBottom:4}}>Implemented Object Types ({implementedObjects.length})</div>
            <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
              {implementedObjects.map((ot)=><B key={`ot-impl-${String(ot)}`} c="green">{String(ot)}</B>)}
              {!implementedObjects.length?<span style={{fontSize:10,color:C.dim}}>-</span>:null}
            </div>
          </Card>
          <Card style={{borderColor:C.borderHi}}>
            <div style={{fontSize:10,color:C.muted,marginBottom:4}}>Missing KMIP 3.2 Object Types ({unimplementedObjects.length})</div>
            <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
              {unimplementedObjects.map((ot)=><B key={`ot-miss-${String(ot)}`} c="amber">{String(ot)}</B>)}
              {!unimplementedObjects.length?<span style={{fontSize:10,color:C.green}}>None</span>:null}
            </div>
          </Card>
        </Row2>
        <div style={{fontSize:10,color:C.dim}}>
          {interoperabilityScope.length
            ?interoperabilityScope.map((line)=>String(line)).join(" | ")
            :"Generic KMIP interoperability is protocol-based. Product certification/qualification should be validated per target platform."}
        </div>
        <div>
          <div style={{fontSize:10,color:C.muted,marginBottom:4}}>KMIP-Capable Integration Targets</div>
          <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
            {integrationTargets.map((target)=><B key={`interop-${String(target)}`} c="blue">{String(target)}</B>)}
            {!integrationTargets.length?<span style={{fontSize:10,color:C.dim}}>-</span>:null}
          </div>
          {integrationNote?<div style={{fontSize:10,color:C.dim,marginTop:6}}>{integrationNote}</div>:null}
        </div>
      </div>
    </Card>    {issuedBundle?<Card style={{marginBottom:10,borderColor:C.green}}>
      <div style={{display:"flex",justifyContent:"space-between",gap:8,alignItems:"center",marginBottom:6,flexWrap:"wrap"}}>
        <div>
          <div style={{fontSize:12,color:C.text,fontWeight:700}}>Issued Client Bundle: {issuedBundle.name}</div>
          <div style={{fontSize:10,color:C.dim}}>Internal enrollment generated this client certificate and key. Download once and store securely.</div>
        </div>
        <div style={{display:"flex",gap:8}}>
          <Btn small onClick={()=>downloadText(`${issuedBundle.name}.crt.pem`,issuedBundle.cert)}>Download Cert</Btn>
          {issuedBundle.key?<Btn small onClick={()=>downloadText(`${issuedBundle.name}.key.pem`,issuedBundle.key)}>Download Key</Btn>:null}
          <Btn small onClick={()=>setIssuedBundle(null)}>Dismiss</Btn>
        </div>
      </div>
    </Card>:null}

    <Row2>
      <Section
        title="Client Profiles"
        actions={<div style={{display:"flex",gap:8}}>
          <Btn small onClick={()=>void refresh()}>{loading?"Refreshing...":"Refresh"}</Btn>
          <Btn small primary onClick={()=>setModal("profile")}>+ Add Profile</Btn>
        </div>}
      >
        <Card style={{padding:0,overflow:"hidden"}}>
          <div style={{display:"grid",gridTemplateColumns:"1fr .9fr .7fr .7fr .7fr",gap:0,padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>
            <div>Profile</div><div>CA</div><div>Duration</div><div>Role</div><div>Actions</div>
          </div>
          <div style={{maxHeight:260,overflowY:"auto"}}>
            {(profiles||[]).map((p)=><div key={p.id} style={{display:"grid",gridTemplateColumns:"1fr .9fr .7fr .7fr .7fr",padding:"8px 12px",fontSize:10,borderBottom:`1px solid ${C.border}`,gap:8}}>
              <div>
                <div style={{fontSize:11,color:C.text,fontWeight:600}}>{p.name}</div>
                <div style={{fontSize:9,color:C.muted,fontFamily:"'JetBrains Mono',monospace"}}>{p.id}</div>
              </div>
              <div style={{fontSize:9,color:C.dim}}>{(caItems.find((ca)=>String(ca.id)===String(p.ca_id))?.name)||p.ca_id||"-"}</div>
              <div style={{fontSize:9,color:C.dim}}>{`${Number(p.certificate_duration_days||0)||365}d`}</div>
              <div><B c="blue">{p.role||"kmip-client"}</B></div>
              <div style={{display:"flex",alignItems:"center",justifyContent:"flex-start"}}>
                <Btn small danger onClick={()=>void removeProfile(p)} disabled={deletingProfileID!==""||deletingClientID!==""}>
                  {deletingProfileID===String(p.id)?"Deleting...":"Delete"}
                </Btn>
              </div>
            </div>)}
            {!(profiles||[]).length?<div style={{padding:12,fontSize:10,color:C.muted}}>No KMIP client profiles yet.</div>:null}
          </div>
        </Card>
      </Section>

      <Section
        title="KMIP Clients"
        actions={<div style={{display:"flex",gap:8}}>
          <Btn small onClick={()=>void refresh(true)}>Refresh</Btn>
          <Btn small primary onClick={()=>setModal("client")}>+ Add Client</Btn>
        </div>}
      >
        <Card style={{padding:0,overflow:"hidden"}}>
          <div style={{display:"grid",gridTemplateColumns:"1fr .6fr .7fr .8fr .8fr .8fr",gap:0,padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>
            <div>Client</div><div>Status</div><div>Mode</div><div>Fingerprint</div><div>Expires</div><div>Actions</div>
          </div>
          <div style={{maxHeight:260,overflowY:"auto"}}>
            {(clients||[]).map((c)=><div key={c.id} style={{display:"grid",gridTemplateColumns:"1fr .6fr .7fr .8fr .8fr .8fr",padding:"8px 12px",fontSize:10,borderBottom:`1px solid ${C.border}`,gap:8}}>
              <div>
                <div style={{fontSize:11,color:C.text,fontWeight:600}}>{c.name}</div>
                <div style={{fontSize:9,color:C.muted}}>{c.role}</div>
              </div>
              <div><B c={String(c.status||"").toLowerCase()==="active"?"green":"red"}>{String(c.status||"-").toUpperCase()}</B></div>
              <div style={{fontSize:9,color:C.dim}}>{String(c.enrollment_mode||"-")}</div>
              <div style={{fontSize:9,color:C.dim,fontFamily:"'JetBrains Mono',monospace"}}>{String(c.cert_fingerprint_sha256||"-").slice(0,16)}...</div>
              <div style={{fontSize:9,color:C.dim}}>{c.cert_not_after?new Date(String(c.cert_not_after)).toLocaleString():"-"}</div>
              <div style={{display:"flex",alignItems:"center",justifyContent:"flex-start"}}>
                <Btn small danger onClick={()=>void removeClient(c)} disabled={deletingClientID!==""||deletingProfileID!==""}>
                  {deletingClientID===String(c.id)?"Deleting...":"Delete"}
                </Btn>
              </div>
            </div>)}
            {!(clients||[]).length?<div style={{padding:12,fontSize:10,color:C.muted}}>No KMIP clients registered. Add client certificate to allow mTLS access.</div>:null}
          </div>
        </Card>
      </Section>
    </Row2>

    <Section
      title="KMIP Interop Validation Targets"
      actions={<div style={{display:"flex",gap:8}}>
        <Btn small onClick={()=>void refresh(true)}>Refresh</Btn>
        <Btn small primary onClick={()=>setModal("interop-target")}>+ Add Target</Btn>
      </div>}
    >
      <Card style={{padding:0,overflow:"hidden"}}>
        <div style={{display:"grid",gridTemplateColumns:"1fr .7fr .8fr .6fr .7fr 1fr",gap:0,padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>
          <div>Target</div><div>Vendor</div><div>Endpoint</div><div>KMIP Min</div><div>Status</div><div>Actions</div>
        </div>
        <div style={{maxHeight:260,overflowY:"auto"}}>
          {(interopTargets||[]).map((target:any)=>{
            const status=String(target?.last_status||"unknown").toLowerCase();
            const tone=status==="verified"?"green":status==="failed"?"red":"blue";
            return <div key={String(target?.id||"")} style={{display:"grid",gridTemplateColumns:"1fr .7fr .8fr .6fr .7fr 1fr",padding:"8px 12px",fontSize:10,borderBottom:`1px solid ${C.border}`,gap:8}}>
              <div>
                <div style={{fontSize:11,color:C.text,fontWeight:600}}>{String(target?.name||"-")}</div>
                <div style={{fontSize:9,color:C.muted}}>Checked: {String(target?.last_checked_at?new Date(String(target.last_checked_at)).toLocaleString():"Never")}</div>
              </div>
              <div style={{fontSize:9,color:C.dim}}>{String(target?.vendor||"generic")}</div>
              <div style={{fontSize:9,color:C.dim,fontFamily:"'JetBrains Mono',monospace"}}>{String(target?.endpoint||"-")}</div>
              <div style={{fontSize:9,color:C.dim}}>{String(target?.expected_min_version||"-")}</div>
              <div>
                <B c={tone}>{String(target?.last_status||"unknown").toUpperCase()}</B>
                {String(target?.last_error||"").trim()?<div style={{fontSize:9,color:C.red,marginTop:4,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{String(target.last_error)}</div>:null}
              </div>
              <div style={{display:"flex",gap:6,alignItems:"center",flexWrap:"wrap"}}>
                <Btn small onClick={()=>void runInteropValidation(target)} disabled={validatingInteropTargetID!==""||deletingInteropTargetID!==""}>
                  {validatingInteropTargetID===String(target?.id||"")?"Validating...":"Validate"}
                </Btn>
                <Btn small danger onClick={()=>void removeInteropTarget(target)} disabled={validatingInteropTargetID!==""||deletingInteropTargetID!==""}>
                  {deletingInteropTargetID===String(target?.id||"")?"Deleting...":"Delete"}
                </Btn>
              </div>
            </div>;
          })}
          {!(interopTargets||[]).length?<div style={{padding:12,fontSize:10,color:C.muted}}>No interop validation targets configured.</div>:null}
        </div>
      </Card>
      {interopValidationResult?<Card style={{marginTop:10,borderColor:C.borderHi}}>
        <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:6}}>Last Validation Result</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(4,minmax(0,1fr))",gap:8}}>
          <div><B c={interopValidationResult?.verified?"green":"red"}>{interopValidationResult?.verified?"VERIFIED":"FAILED"}</B></div>
          <div><span style={{fontSize:10,color:C.muted}}>Handshake:</span> <span style={{fontSize:10,color:C.text}}>{interopValidationResult?.handshake_ok?"ok":"fail"}</span></div>
          <div><span style={{fontSize:10,color:C.muted}}>Discover:</span> <span style={{fontSize:10,color:C.text}}>{interopValidationResult?.discover_versions_ok?"ok":"fail"}</span></div>
          <div><span style={{fontSize:10,color:C.muted}}>Query:</span> <span style={{fontSize:10,color:C.text}}>{interopValidationResult?.query_ok?"ok":"fail"}</span></div>
        </div>
        <div style={{marginTop:6,fontSize:10,color:C.dim}}>
          Key Op: {interopValidationResult?.key_operation_ok?"ok":"fail"} | Negotiated: {String(interopValidationResult?.negotiated_version||"-")} | Latency: {String(interopValidationResult?.latency_ms||0)} ms
        </div>
        {String(interopValidationResult?.error||"").trim()?<div style={{marginTop:6,fontSize:10,color:C.red}}>{String(interopValidationResult.error)}</div>:null}
      </Card>:null}
    </Section>

    <Card style={{marginTop:10}}>
      <div style={{fontSize:10,color:C.dim}}>
        KMIP access control is certificate-linked. Registered client certificates are validated and used during KMIP mTLS connect. External client certificates must chain to a CA configured in Certificates tab.
      </div>
    </Card>

    <Modal open={modal==="profile"} onClose={()=>setModal(null)} title="Add KMIP Client Profile" wide>
      <Row2>
        <FG label="Profile Name" required><Inp value={profileForm.name} onChange={(e)=>setProfileForm((p)=>({...p,name:e.target.value}))} placeholder="prod-kmip-clients"/></FG>
        <FG label="Issuing CA" required>
          <Sel value={profileForm.ca_id} onChange={(e)=>setProfileForm((p)=>({...p,ca_id:e.target.value}))}>
            <option value="">Select CA</option>
            {(caItems||[]).map((ca)=><option key={ca.id} value={ca.id}>{ca.name} ({ca.algorithm})</option>)}
          </Sel>
        </FG>
      </Row2>
      <Row2>
        <FG label="Username Location in Certificate">
          <Sel value={profileForm.username_location} onChange={(e)=>setProfileForm((p)=>({...p,username_location:e.target.value}))}>
            <option value="cn">CN</option>
            <option value="email">Email</option>
            <option value="uid">UID</option>
          </Sel>
        </FG>
        <FG label="Subject DN Field to Modify">
          <Sel value={profileForm.subject_field_to_modify} onChange={(e)=>setProfileForm((p)=>({...p,subject_field_to_modify:e.target.value}))}>
            <option value="uid">UID</option>
            <option value="cn">CN</option>
            <option value="email">emailAddress</option>
          </Sel>
        </FG>
      </Row2>
      <Row2>
        <FG label="Certificate Duration (days)">
          <Inp type="number" value={String(profileForm.certificate_duration_days)} onChange={(e)=>setProfileForm((p)=>({...p,certificate_duration_days:Math.max(1,Number(e.target.value||365))}))}/>
        </FG>
        <FG label="Role">
          <Sel value={profileForm.role} onChange={(e)=>setProfileForm((p)=>({...p,role:e.target.value}))}>
            <option value="kmip-client">kmip-client</option>
            <option value="kmip-admin">kmip-admin</option>
            <option value="kmip-service">kmip-service</option>
          </Sel>
        </FG>
      </Row2>
      <FG label="Certificate Details (stored with profile metadata)">
        <Row2>
          <FG label="Organization"><Inp value={profileForm.organization} onChange={(e)=>setProfileForm((p)=>({...p,organization:e.target.value}))}/></FG>
          <FG label="Organizational Unit"><Inp value={profileForm.organizational_unit} onChange={(e)=>setProfileForm((p)=>({...p,organizational_unit:e.target.value}))}/></FG>
        </Row2>
        <Row2>
          <FG label="Email"><Inp value={profileForm.email} onChange={(e)=>setProfileForm((p)=>({...p,email:e.target.value}))}/></FG>
          <FG label="UID"><Inp value={profileForm.uid} onChange={(e)=>setProfileForm((p)=>({...p,uid:e.target.value}))}/></FG>
        </Row2>
        <Row2>
          <FG label="Surname"><Inp value={profileForm.surname} onChange={(e)=>setProfileForm((p)=>({...p,surname:e.target.value}))}/></FG>
          <FG label="City"><Inp value={profileForm.city} onChange={(e)=>setProfileForm((p)=>({...p,city:e.target.value}))}/></FG>
        </Row2>
        <Row2>
          <FG label="State"><Inp value={profileForm.state} onChange={(e)=>setProfileForm((p)=>({...p,state:e.target.value}))}/></FG>
          <FG label="Country"><Inp value={profileForm.country} onChange={(e)=>setProfileForm((p)=>({...p,country:e.target.value}))}/></FG>
        </Row2>
      </FG>
      <Chk label="Do not modify subject DN" checked={Boolean(profileForm.do_not_modify_subject_dn)} onChange={(e)=>setProfileForm((p)=>({...p,do_not_modify_subject_dn:e.target.checked}))}/>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
        <Btn primary onClick={()=>void saveProfile()} disabled={savingProfile}>{savingProfile?"Saving...":"Save Profile"}</Btn>
      </div>
    </Modal>

    <Modal open={modal==="client"} onClose={()=>setModal(null)} title="Add KMIP Client" wide>
      <Row2>
        <FG label="Name" required><Inp value={clientForm.name} onChange={(e)=>setClientForm((p)=>({...p,name:e.target.value}))} placeholder="core-banking-hsm-client"/></FG>
        <FG label="Registration Token"><Inp value={clientForm.registration_token} onChange={(e)=>setClientForm((p)=>({...p,registration_token:e.target.value}))} placeholder="optional auto-generated"/></FG>
      </Row2>
      <Row2>
        <FG label="Enrollment Mode">
          <Sel value={clientForm.enrollment_mode} onChange={(e)=>setClientForm((p)=>({...p,enrollment_mode:e.target.value}))}>
            <option value="internal">Internal cert issuance (from CA tab)</option>
            <option value="external">External certificate upload</option>
          </Sel>
        </FG>
        <FG label="Role">
          <Sel value={clientForm.role} onChange={(e)=>setClientForm((p)=>({...p,role:e.target.value}))}>
            <option value="kmip-client">kmip-client</option>
            <option value="kmip-admin">kmip-admin</option>
            <option value="kmip-service">kmip-service</option>
          </Sel>
        </FG>
      </Row2>

      {String(clientForm.enrollment_mode)==="internal"?<>
        <Row2>
          <FG label="Client Profile" required>
            <Sel value={clientForm.profile_id} onChange={(e)=>setClientForm((p)=>({...p,profile_id:e.target.value,role:(profiles.find((x)=>String(x.id)===String(e.target.value))?.role)||p.role}))}>
              <option value="">Select profile</option>
              {(profiles||[]).map((p)=><option key={p.id} value={p.id}>{p.name} ({p.role})</option>)}
            </Sel>
          </FG>
          <FG label="Common Name (optional)"><Inp value={clientForm.common_name} onChange={(e)=>setClientForm((p)=>({...p,common_name:e.target.value}))} placeholder="defaults to tenant:role"/></FG>
        </Row2>
        <FG label="CSR PEM (optional)">
          <Txt value={clientForm.csr_pem} onChange={(e)=>setClientForm((p)=>({...p,csr_pem:e.target.value}))} placeholder="Paste external CSR if you want CA-signed cert from existing key pair..."/>
        </FG>
      </>:<>
        <FG label="Client Certificate Source">
          <div style={{display:"flex",gap:10,alignItems:"center"}}>
            <label style={{display:"flex",gap:6,alignItems:"center",fontSize:10,color:C.dim}}>
              <input type="radio" checked={clientCertSource==="paste"} onChange={()=>setClientCertSource("paste")}/> Paste PEM
            </label>
            <label style={{display:"flex",gap:6,alignItems:"center",fontSize:10,color:C.dim}}>
              <input type="radio" checked={clientCertSource==="upload"} onChange={()=>setClientCertSource("upload")}/> Upload cert/key files
            </label>
          </div>
        </FG>
        {clientCertSource==="upload"?<Card>
          <div style={{display:"grid",gap:8}}>
            <div style={{fontSize:10,color:C.dim}}>Upload filters only allow key/certificate material.</div>
            <input type="file" accept=".pem,.crt,.cer,.der" onChange={(e)=>void readPEMFile(e.target.files?.[0],"certificate_pem")}/>
            <input type="file" accept=".pem,.key" onChange={(e)=>void readPEMFile(e.target.files?.[0],"private_key_pem")}/>
            <input type="file" accept=".pem,.crt,.cer,.p7b,.p7c" onChange={(e)=>void readPEMFile(e.target.files?.[0],"ca_bundle_pem")}/>
          </div>
        </Card>:null}
        <FG label="Client Certificate PEM" required>
          <Txt value={clientForm.certificate_pem} onChange={(e)=>setClientForm((p)=>({...p,certificate_pem:e.target.value}))} placeholder="-----BEGIN CERTIFICATE-----"/>
        </FG>
        <FG label="Client Private Key PEM (optional)">
          <Txt value={clientForm.private_key_pem} onChange={(e)=>setClientForm((p)=>({...p,private_key_pem:e.target.value}))} placeholder="-----BEGIN PRIVATE KEY-----"/>
        </FG>
        <FG label="CA Bundle PEM (optional chain)">
          <Txt value={clientForm.ca_bundle_pem} onChange={(e)=>setClientForm((p)=>({...p,ca_bundle_pem:e.target.value}))} placeholder="Intermediate CA certificates (if any)..."/>
        </FG>
      </>}

      <FG label="Device Credentials (metadata)">
        <Row2>
          <FG label="Serial Number"><Inp value={clientForm.serial_number} onChange={(e)=>setClientForm((p)=>({...p,serial_number:e.target.value}))}/></FG>
          <FG label="Device ID"><Inp value={clientForm.device_id} onChange={(e)=>setClientForm((p)=>({...p,device_id:e.target.value}))}/></FG>
        </Row2>
        <Row2>
          <FG label="Password"><Inp type="password" value={clientForm.password} onChange={(e)=>setClientForm((p)=>({...p,password:e.target.value}))}/></FG>
          <FG label="Password Match"><Inp type="password" value={clientForm.password_match} onChange={(e)=>setClientForm((p)=>({...p,password_match:e.target.value}))}/></FG>
        </Row2>
        <Row2>
          <FG label="Network ID"><Inp value={clientForm.network_id} onChange={(e)=>setClientForm((p)=>({...p,network_id:e.target.value}))}/></FG>
          <FG label="Machine ID"><Inp value={clientForm.machine_id} onChange={(e)=>setClientForm((p)=>({...p,machine_id:e.target.value}))}/></FG>
        </Row2>
        <FG label="Media ID"><Inp value={clientForm.media_id} onChange={(e)=>setClientForm((p)=>({...p,media_id:e.target.value}))}/></FG>
      </FG>

      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
        <Btn primary onClick={()=>void saveClient()} disabled={savingClient}>{savingClient?"Saving...":"Save Client"}</Btn>
      </div>
    </Modal>

    <Modal open={modal==="interop-target"} onClose={()=>setModal(null)} title="Add KMIP Interop Validation Target" wide>
      <Row2>
        <FG label="Target Name" required>
          <Inp value={interopForm.name} onChange={(e)=>setInteropForm((p)=>({...p,name:e.target.value}))} placeholder="mysql-prod-kmip"/>
        </FG>
        <FG label="Vendor" required>
          <Sel value={interopForm.vendor} onChange={(e)=>setInteropForm((p)=>({...p,vendor:e.target.value}))}>
            <option value="generic">Generic</option>
            <option value="mysql">MySQL</option>
            <option value="mongodb">MongoDB</option>
            <option value="vmware">VMware / ESXi</option>
            <option value="scality">Scality</option>
            <option value="netapp">NetApp</option>
            <option value="hpe">HPE</option>
            <option value="dell">Dell</option>
          </Sel>
        </FG>
      </Row2>
      <Row2>
        <FG label="KMIP Endpoint" required>
          <Inp value={interopForm.endpoint} onChange={(e)=>setInteropForm((p)=>({...p,endpoint:e.target.value}))} placeholder="10.0.5.10:5696"/>
        </FG>
        <FG label="TLS Server Name (optional)">
          <Inp value={interopForm.server_name} onChange={(e)=>setInteropForm((p)=>({...p,server_name:e.target.value}))} placeholder="kmip.example.com"/>
        </FG>
      </Row2>
      <Row2>
        <FG label="Expected Min KMIP Version">
          <Inp value={interopForm.expected_min_version} onChange={(e)=>setInteropForm((p)=>({...p,expected_min_version:e.target.value}))} placeholder="3.0"/>
        </FG>
        <FG label="Validation Options">
          <Chk label="Run test key operation (Create/Encrypt/Decrypt/Destroy)" checked={Boolean(interopForm.test_key_operation)} onChange={(e)=>setInteropForm((p)=>({...p,test_key_operation:e.target.checked}))}/>
        </FG>
      </Row2>
      <FG label="Target CA PEM" required>
        <Txt value={interopForm.ca_pem} onChange={(e)=>setInteropForm((p)=>({...p,ca_pem:e.target.value}))} placeholder="-----BEGIN CERTIFICATE-----"/>
      </FG>
      <FG label="Client Certificate PEM" required>
        <Txt value={interopForm.client_cert_pem} onChange={(e)=>setInteropForm((p)=>({...p,client_cert_pem:e.target.value}))} placeholder="-----BEGIN CERTIFICATE-----"/>
      </FG>
      <FG label="Client Private Key PEM" required>
        <Txt value={interopForm.client_key_pem} onChange={(e)=>setInteropForm((p)=>({...p,client_key_pem:e.target.value}))} placeholder="-----BEGIN PRIVATE KEY-----"/>
      </FG>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)}>Cancel</Btn>
        <Btn primary onClick={()=>void saveInteropTarget()} disabled={savingInteropTarget}>{savingInteropTarget?"Saving...":"Save Target"}</Btn>
      </div>
    </Modal>
  </div>;
};





