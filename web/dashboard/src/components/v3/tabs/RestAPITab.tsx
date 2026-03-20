import { useCallback, useEffect, useMemo, useState } from "react";
import type { AuthSession } from "../../../lib/auth";
import {
  getAuthRESTClientSecuritySummary,
  listAuthClients,
  updateAuthClient
} from "../../../lib/authAdmin";
import { listCertificates } from "../../../lib/certs";
import { listSecrets } from "../../../lib/secrets";
import { DISCOVERED_REST_API_CATALOG } from "../../../generated/restApiCatalog.generated";
import { executeRestPlaygroundRequest } from "../../../lib/restPlayground";
import { REST_API_CATALOG } from "../restApiCatalog";
import { B, Btn, Card, Chk, FG, Inp, Row2, Row3, Section, Sel, Stat, Txt } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";

const REST_API_METHODS_WITH_BODY = new Set(["POST", "PUT", "PATCH"]);
const REST_CLIENT_AUTH_MODES = [
  { id: "api_key", label: "API Key / Bearer" },
  { id: "oauth_mtls", label: "OAuth mTLS" },
  { id: "dpop", label: "DPoP" },
  { id: "http_message_signature", label: "HTTP Message Signatures" }
];

type RestAPITabProps = {
  session: AuthSession | null;
  keyCatalog: any[];
  onToast?: (message: string) => void;
};

function keyChoicesFromCatalog(keyCatalog: any[]): any[] {
  if (!Array.isArray(keyCatalog)) {
    return [];
  }
  return keyCatalog.filter((k: any) => String(k?.state || "").trim().toLowerCase() !== "deleted");
}
const normalizeRestPathTemplate=(raw:string)=>{
  const value=String(raw||"");
  return value.replace(/\{([a-zA-Z0-9_]+)\}/g,(match,param)=>{
    const key=String(param||"").trim();
    if(!key){
      return match;
    }
    return `{{${key}}}`;
  });
};

const restClientAuthModeLabel=(value:string)=>{
  const key=String(value||"api_key").trim().toLowerCase();
  return REST_CLIENT_AUTH_MODES.find((item)=>item.id===key)?.label||key.replaceAll("_"," ");
};

const restClientAuthModeColor=(value:string)=>{
  switch(String(value||"api_key").trim().toLowerCase()){
    case "oauth_mtls":
      return "green";
    case "dpop":
      return "blue";
    case "http_message_signature":
      return "accent";
    default:
      return "amber";
  }
};

const fmtClientTS=(value:any)=>{
  const raw=String(value||"").trim();
  if(!raw){
    return "Never";
  }
  const dt=new Date(raw);
  if(Number.isNaN(dt.getTime())){
    return raw;
  }
  return dt.toLocaleString();
};

const REST_API_CATALOG_FULL=(()=>{
  const rows:any[]=[];
  const seen=new Set<string>();
  const add=(item:any)=>{
    const service=String(item?.service||"").trim();
    const method=String(item?.method||"GET").trim().toUpperCase();
    const pathTemplate=normalizeRestPathTemplate(String(item?.pathTemplate||"/"));
    if(!service){
      return;
    }
    const key=`${service}|${method}|${pathTemplate}`;
    if(seen.has(key)){
      return;
    }
    seen.add(key);
    rows.push({...item,method,pathTemplate});
  };
  (Array.isArray(REST_API_CATALOG)?REST_API_CATALOG:[]).forEach(add);
  (Array.isArray(DISCOVERED_REST_API_CATALOG)?DISCOVERED_REST_API_CATALOG:[]).forEach(add);
  return rows;
})();

// 
// TAB: REST API (authenticated playground)
// 
export const RestAPITab=({session,keyCatalog,onToast}: RestAPITabProps)=>{
  const [selectedEndpointID,setSelectedEndpointID]=useState(String(REST_API_CATALOG_FULL[0]?.id||""));
  const [authMode,setAuthMode]=useState("session-jwt");
  const [customJWT,setCustomJWT]=useState("");
  const [tenantParam,setTenantParam]=useState(String(session?.tenantId||""));
  const [serviceName,setServiceName]=useState(String(REST_API_CATALOG_FULL[0]?.service||"keycore"));
  const [method,setMethod]=useState(String(REST_API_CATALOG_FULL[0]?.method||"GET"));
  const [pathValue,setPathValue]=useState(String(REST_API_CATALOG_FULL[0]?.pathTemplate||"/"));
  const [bodyValue,setBodyValue]=useState(String(REST_API_CATALOG_FULL[0]?.bodyTemplate||""));
  const [endpointSearch,setEndpointSearch]=useState("");
  const [keyID,setKeyID]=useState("");
  const [certID,setCertID]=useState("");
  const [secretID,setSecretID]=useState("");
  const [certOptions,setCertOptions]=useState<any[]>([]);
  const [secretOptions,setSecretOptions]=useState<any[]>([]);
  const [running,setRunning]=useState(false);
  const [statusText,setStatusText]=useState("No request executed yet.");
  const [responseText,setResponseText]=useState("// Response will appear here...");
  const [requestPreview,setRequestPreview]=useState("// cURL preview will appear here...");
  const [clientLoading,setClientLoading]=useState(false);
  const [clientSaving,setClientSaving]=useState(false);
  const [clientSummary,setClientSummary]=useState<any>(null);
  const [clientItems,setClientItems]=useState<any[]>([]);
  const [selectedClientID,setSelectedClientID]=useState("");
  const [clientDraft,setClientDraft]=useState<any>(null);

  const filteredEndpoints=useMemo(()=>{
    const query=String(endpointSearch||"").trim().toLowerCase();
    if(!query){
      return REST_API_CATALOG_FULL;
    }
    return REST_API_CATALOG_FULL.filter((item:any)=>{
      const haystack=[
        String(item?.group||""),
        String(item?.title||""),
        String(item?.service||""),
        String(item?.method||""),
        String(item?.pathTemplate||""),
        String(item?.description||"")
      ].join(" ").toLowerCase();
      return haystack.includes(query);
    });
  },[endpointSearch]);

  useEffect(()=>{
    if(!filteredEndpoints.some((item:any)=>String(item?.id||"")===String(selectedEndpointID||""))){
      setSelectedEndpointID(String(filteredEndpoints[0]?.id||REST_API_CATALOG_FULL[0]?.id||""));
    }
  },[filteredEndpoints,selectedEndpointID]);

  const endpoint=useMemo(
    ()=>filteredEndpoints.find((item:any)=>String(item?.id||"")===String(selectedEndpointID||""))||filteredEndpoints[0]||REST_API_CATALOG_FULL[0],
    [selectedEndpointID,filteredEndpoints]
  );

  const groupedEndpoints=useMemo(()=>{
    const groups:any={};
    filteredEndpoints.forEach((item:any)=>{
      const g=String(item.group||"Other");
      if(!groups[g]){
        groups[g]=[];
      }
      groups[g].push(item);
    });
    return Object.entries(groups);
  },[filteredEndpoints]);

  const keyChoices=useMemo(()=>keyChoicesFromCatalog(keyCatalog),[keyCatalog]);
  const selectedClient=useMemo(
    ()=>clientItems.find((item:any)=>String(item?.id||"")===String(selectedClientID||""))||null,
    [clientItems,selectedClientID]
  );

  useEffect(()=>{
    setServiceName(String(endpoint?.service||"keycore"));
    setMethod(String(endpoint?.method||"GET"));
    setPathValue(normalizeRestPathTemplate(String(endpoint?.pathTemplate||"/")));
    setBodyValue(String(endpoint?.bodyTemplate||""));
  },[endpoint]);

  useEffect(()=>{
    if(!keyID&&Array.isArray(keyChoices)&&keyChoices.length){
      setKeyID(String(keyChoices[0]?.id||""));
    }
  },[keyChoices,keyID]);

  useEffect(()=>{
    setTenantParam(String(session?.tenantId||""));
  },[session?.tenantId]);

  const loadClientSecurity=useCallback(async(silent=true)=>{
    if(!session?.token){
      setClientSummary(null);
      setClientItems([]);
      setSelectedClientID("");
      setClientDraft(null);
      return;
    }
    if(!silent){
      setClientLoading(true);
    }
    try{
      const [summaryOut,clientsOut]=await Promise.all([
        getAuthRESTClientSecuritySummary(session).catch(()=>null),
        listAuthClients(session).catch(()=>[])
      ]);
      const restClients=(Array.isArray(clientsOut)?clientsOut:[]).filter((item:any)=>{
        const iface=String(item?.interface_name||"rest").trim().toLowerCase();
        return !iface||iface==="rest";
      });
      setClientSummary(summaryOut||null);
      setClientItems(restClients);
      setSelectedClientID((prev)=>{
        if(restClients.some((item:any)=>String(item?.id||"")===String(prev||""))){
          return prev;
        }
        return String(restClients[0]?.id||"");
      });
    }catch(error){
      if(!silent){
        onToast?.(`REST client security load failed: ${errMsg(error)}`);
      }
    }finally{
      if(!silent){
        setClientLoading(false);
      }
    }
  },[onToast,session]);

  useEffect(()=>{
    void loadClientSecurity(true);
  },[loadClientSecurity]);

  useEffect(()=>{
    if(!selectedClient){
      setClientDraft(null);
      return;
    }
    setClientDraft({
      ...selectedClient,
      ip_whitelist_text:Array.isArray(selectedClient?.ip_whitelist)?selectedClient.ip_whitelist.join(", "):""
    });
  },[selectedClient]);

  useEffect(()=>{
    if(!session?.token){
      setCertOptions([]);
      setSecretOptions([]);
      return;
    }
    let cancelled=false;
    (async()=>{
      try{
        const [certs,secrets]=await Promise.all([
          listCertificates(session,{limit:200,offset:0}),
          listSecrets(session,{limit:200,offset:0})
        ]);
        if(cancelled){
          return;
        }
        setCertOptions(Array.isArray(certs)?certs:[]);
        setSecretOptions(Array.isArray(secrets)?secrets:[]);
        if(!certID&&Array.isArray(certs)&&certs.length){
          setCertID(String(certs[0]?.id||""));
        }
        if(!secretID&&Array.isArray(secrets)&&secrets.length){
          setSecretID(String(secrets[0]?.id||""));
        }
      }catch{
        if(!cancelled){
          setCertOptions([]);
          setSecretOptions([]);
        }
      }
    })();
    return ()=>{cancelled=true;};
  },[session,session?.token,session?.tenantId,certID,secretID]);

  const resolveTemplateValue=useCallback((name:string,encode:boolean)=>{
    const key=String(name||"").trim();
    let value="";
    if(key==="tenant_id"){
      value=String(tenantParam||"");
    }else if(key==="key_id"){
      value=String(keyID||"");
    }else if(key==="cert_id"){
      value=String(certID||"");
    }else if(key==="secret_id"){
      value=String(secretID||"");
    }else if(key==="id"){
      value=String(keyID||certID||secretID||"sample");
    }else if(key.endsWith("_id")){
      value="sample";
    }else if(key==="name"){
      value="default";
    }else if(key==="protocol"){
      value="generic";
    }else if(key==="slave"){
      value="node-b";
    }else if(key==="version"||key==="ver"){
      value="1";
    }else{
      value="sample";
    }
    return encode?encodeURIComponent(value):value;
  },[tenantParam,keyID,certID,secretID]);

  const resolvePathTemplate=useCallback((raw:string)=>{
    return normalizeRestPathTemplate(String(raw||""))
      .replace(/\{\{([a-zA-Z0-9_]+)\}\}/g,(_,param)=>resolveTemplateValue(String(param||""),true));
  },[resolveTemplateValue]);

  const resolveBodyTemplate=useCallback((raw:string)=>{
    return String(raw||"")
      .replace(/\{\{([a-zA-Z0-9_]+)\}\}/g,(_,param)=>resolveTemplateValue(String(param||""),false));
  },[resolveTemplateValue]);

  const pretty=(value:any)=>{
    if(value===null||value===undefined){
      return "";
    }
    if(typeof value==="string"){
      try{
        return JSON.stringify(JSON.parse(value),null,2);
      }catch{
        return value;
      }
    }
    try{
      return JSON.stringify(value,null,2);
    }catch{
      return String(value);
    }
  };

  const buildPreview=useCallback(()=>{
    const resolvedPath=resolvePathTemplate(pathValue);
    const resolvedBody=resolveBodyTemplate(bodyValue);
    const trimmedMethod=String(method||"GET").toUpperCase();
    const url=`{{base_url}}/svc/${String(serviceName||"").trim()}${resolvedPath}`;
    const tokenPlaceholder=authMode==="session-jwt"?"<session-jwt>":"<custom-jwt>";
    const lines=[
      `curl -X ${trimmedMethod} "${url}"`,
      `  -H "Authorization: Bearer ${tokenPlaceholder}"`,
      `  -H "X-Tenant-ID: ${String(tenantParam||"")}"`,
      `  -H "Content-Type: application/json"`
    ];
    if(REST_API_METHODS_WITH_BODY.has(trimmedMethod)&&String(resolvedBody||"").trim()){
      lines.push(`  -d '${resolvedBody.replaceAll("'","\\'")}'`);
    }
    setRequestPreview(lines.join(" \\\n"));
  },[authMode,bodyValue,method,pathValue,resolveBodyTemplate,resolvePathTemplate,serviceName,tenantParam]);

  useEffect(()=>{
    buildPreview();
  },[buildPreview]);

  const executeRequest=async()=>{
    if(!session?.token&&authMode==="session-jwt"){
      onToast?.("Login is required to execute API calls.");
      return;
    }
    const token=authMode==="session-jwt"?String(session?.token||"").trim():String(customJWT||"").trim();
    if(!token){
      onToast?.("JWT is required before calling this endpoint.");
      return;
    }
    const tenantID=String(tenantParam||"").trim();
    if(!tenantID){
      onToast?.("Tenant parameter is required.");
      return;
    }
    const unresolved=String(pathValue||"");
    if(unresolved.includes("{{key_id}}")&&!String(keyID||"").trim()){
      onToast?.("Select key_id before executing this endpoint.");
      return;
    }
    if(unresolved.includes("{{cert_id}}")&&!String(certID||"").trim()){
      onToast?.("Select cert_id before executing this endpoint.");
      return;
    }
    if(unresolved.includes("{{secret_id}}")&&!String(secretID||"").trim()){
      onToast?.("Select secret_id before executing this endpoint.");
      return;
    }

    const resolvedPath=resolvePathTemplate(pathValue);
    const resolvedBody=resolveBodyTemplate(bodyValue);
    const trimmedMethod=String(method||"GET").toUpperCase();
    let parsedBody:any=undefined;
    if(REST_API_METHODS_WITH_BODY.has(trimmedMethod)&&String(resolvedBody||"").trim()){
      try{
        parsedBody=JSON.parse(resolvedBody);
      }catch{
        onToast?.("Request body must be valid JSON.");
        return;
      }
    }

    setRunning(true);
    setStatusText("Executing...");
    const start=performance.now();
    try{
      const response=await executeRestPlaygroundRequest({
        baseSession: session,
        token,
        tenantId: tenantID,
        service: String(serviceName || "").trim(),
        path: resolvedPath,
        method: trimmedMethod,
        ...(parsedBody === undefined ? {} : { bodyJSON: JSON.stringify(parsedBody) })
      });
      const elapsed=Math.round(performance.now()-start);
      const contentType=String(response.headers.get("content-type")||"");
      let payload:any="";
      if(contentType.includes("application/json")){
        payload=await response.json();
      }else{
        payload=await response.text();
      }
      setResponseText(pretty(payload)||"");
      setStatusText(`${response.status} ${response.statusText} - ${elapsed} ms`);
      if(!response.ok){
        onToast?.(`API call failed (${response.status}): ${response.statusText}`);
      }
    }catch(error){
      const msg=errMsg(error);
      setStatusText(`Request error - ${msg}`);
      setResponseText(msg);
      onToast?.(`API call failed: ${msg}`);
    }finally{
      setRunning(false);
    }
  };

  const saveClientSecurity=async()=>{
    if(!session?.token){
      onToast?.("Login is required to update REST clients.");
      return;
    }
    if(!selectedClientID||!clientDraft){
      onToast?.("Select a REST client first.");
      return;
    }
    const ipWhitelist=String(clientDraft?.ip_whitelist_text||"")
      .split(",")
      .map((value:string)=>String(value||"").trim())
      .filter(Boolean);
    setClientSaving(true);
    try{
      await updateAuthClient(session,selectedClientID,{
        ip_whitelist:ipWhitelist,
        rate_limit:Math.max(1,Number(clientDraft?.rate_limit||1000)),
        auth_mode:String(clientDraft?.auth_mode||"api_key"),
        replay_protection_enabled:Boolean(clientDraft?.replay_protection_enabled),
        mtls_cert_fingerprint:String(clientDraft?.mtls_cert_fingerprint||"").trim(),
        mtls_subject_dn:String(clientDraft?.mtls_subject_dn||"").trim(),
        mtls_uri_san:String(clientDraft?.mtls_uri_san||"").trim(),
        http_signature_key_id:String(clientDraft?.http_signature_key_id||"").trim(),
        http_signature_public_key_pem:String(clientDraft?.http_signature_public_key_pem||"").trim(),
        http_signature_algorithm:String(clientDraft?.http_signature_algorithm||"").trim()
      });
      onToast?.("REST client security policy saved.");
      await loadClientSecurity(true);
    }catch(error){
      onToast?.(`REST client update failed: ${errMsg(error)}`);
    }finally{
      setClientSaving(false);
    }
  };

  return <div>
    <Section title="REST API" actions={<>
      <B c="blue">JWT Required</B>
      <Btn small onClick={executeRequest} disabled={running}>{running?"Executing...":"Execute Call"}</Btn>
    </>}>
      <Card style={{marginBottom:10}}>
        <div style={{fontSize:10,color:C.dim,lineHeight:1.5}}>
          Live API playground for management and cryptographic endpoints. Calls are executed against real backend services over
          <span style={{color:C.text}}> /svc/&lt;service&gt;...</span> and require authentication.
        </div>
        <div style={{fontSize:10,color:C.dim,marginTop:6}}>
          Tenant parameter is explicit and drives both <span style={{color:C.text}}>X-Tenant-ID</span> and template replacement for <span style={{color:C.text}}>{"{{tenant_id}}"}</span>.
        </div>
        <div style={{fontSize:10,color:C.dim,marginTop:6}}>
          {`Catalog endpoints available: ${REST_API_CATALOG_FULL.length}`}
        </div>
        <div style={{fontSize:10,color:C.muted,marginTop:6}}>
          Product label: <span style={{color:C.accent,fontWeight:700}}>REST API</span>.
        </div>
      </Card>
      <div style={{display:"grid",gridTemplateColumns:"repeat(5,minmax(0,1fr))",gap:10,marginBottom:10}}>
        <Stat l="REST Clients" v={String(Number(clientSummary?.total_clients||clientItems.length||0))} s={`${Number(clientSummary?.sender_constrained_clients||0)} sender-constrained`} c="accent"/>
        <Stat l="OAuth mTLS" v={String(Number(clientSummary?.oauth_mtls_clients||0))} s="cert-bound tokens" c="green"/>
        <Stat l="DPoP" v={String(Number(clientSummary?.dpop_clients||0))} s={`${Number(clientSummary?.replay_protected_clients||0)} replay-protected`} c="blue"/>
        <Stat l="Signature Failures" v={String(Number(clientSummary?.signature_failures||0))} s={`${Number(clientSummary?.unsigned_rejects||0)} unsigned blocked`} c={Number(clientSummary?.signature_failures||0)>0||Number(clientSummary?.unsigned_rejects||0)>0?"amber":"green"}/>
        <Stat l="Replay Violations" v={String(Number(clientSummary?.replay_violations||0))} s={String(clientSummary?.last_violation_at||"").trim()?`Last ${fmtClientTS(clientSummary?.last_violation_at)}`:"No recent violations"} c={Number(clientSummary?.replay_violations||0)>0?"red":"green"}/>
      </div>
      <Row2>
        <Card>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
            <div>
              <div style={{fontSize:12,fontWeight:700,color:C.text}}>REST Client Security</div>
              <div style={{fontSize:10,color:C.dim,marginTop:4}}>Manage sender-constrained auth per client: OAuth mTLS, DPoP, and HTTP Message Signatures.</div>
            </div>
            <Btn small onClick={()=>void loadClientSecurity(false)} disabled={clientLoading}>{clientLoading?"Refreshing...":"Refresh Security"}</Btn>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"1.1fr 1.3fr",gap:10}}>
            <div style={{display:"grid",gap:8,alignContent:"start"}}>
              {clientItems.length===0&&<div style={{fontSize:10,color:C.muted}}>No REST client registrations found yet.</div>}
              {clientItems.map((item:any)=>{
                const selected=String(item?.id||"")===String(selectedClientID||"");
                return <button
                  key={String(item?.id||"")}
                  type="button"
                  onClick={()=>setSelectedClientID(String(item?.id||""))}
                  style={{
                    textAlign:"left",
                    border:`1px solid ${selected?C.accent:C.border}`,
                    background:selected?C.accentDim:C.surface,
                    borderRadius:12,
                    padding:"10px 12px",
                    cursor:"pointer"
                  }}
                >
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8}}>
                    <div style={{fontSize:11,fontWeight:700,color:C.text}}>{String(item?.client_name||item?.id||"-")}</div>
                    <B c={String(item?.status||"").toLowerCase()==="approved"?"green":"amber"}>{String(item?.status||"pending")}</B>
                  </div>
                  <div style={{display:"flex",gap:6,flexWrap:"wrap",marginTop:6}}>
                    <B c={restClientAuthModeColor(String(item?.auth_mode||"api_key"))}>{restClientAuthModeLabel(String(item?.auth_mode||"api_key"))}</B>
                    <B c={Boolean(item?.replay_protection_enabled)?"blue":"amber"}>{Boolean(item?.replay_protection_enabled)?"Replay on":"Replay off"}</B>
                  </div>
                  <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:6,marginTop:8}}>
                    <div><div style={{fontSize:8,color:C.muted,textTransform:"uppercase"}}>Verified</div><div style={{fontSize:10,color:C.text}}>{Number(item?.verified_request_count||0)}</div></div>
                    <div><div style={{fontSize:8,color:C.muted,textTransform:"uppercase"}}>Replay</div><div style={{fontSize:10,color:Number(item?.replay_violation_count||0)>0?C.red:C.text}}>{Number(item?.replay_violation_count||0)}</div></div>
                    <div><div style={{fontSize:8,color:C.muted,textTransform:"uppercase"}}>Signature</div><div style={{fontSize:10,color:Number(item?.signature_failure_count||0)>0?C.amber:C.text}}>{Number(item?.signature_failure_count||0)}</div></div>
                  </div>
                </button>;
              })}
            </div>
            <div>
              {clientDraft?<div style={{display:"grid",gap:8}}>
                <Row2>
                  <FG label="Client"><Inp value={String(clientDraft?.client_name||"")} readOnly/></FG>
                  <FG label="Requested Role"><Inp value={String(clientDraft?.requested_role||"")} readOnly/></FG>
                </Row2>
                <Row3>
                  <FG label="Auth Mode">
                    <Sel value={String(clientDraft?.auth_mode||"api_key")} onChange={(e)=>setClientDraft((prev:any)=>({...prev,auth_mode:e.target.value}))}>
                      {REST_CLIENT_AUTH_MODES.map((item)=>(
                        <option key={item.id} value={item.id}>{item.label}</option>
                      ))}
                    </Sel>
                  </FG>
                  <FG label="Rate Limit">
                    <Inp type="number" min={1} value={String(clientDraft?.rate_limit||1000)} onChange={(e)=>setClientDraft((prev:any)=>({...prev,rate_limit:Number(e.target.value||1000)}))}/>
                  </FG>
                  <FG label="Last Used Mode">
                    <Inp value={String(clientDraft?.last_auth_mode_used||"never")} readOnly/>
                  </FG>
                </Row3>
                <Chk label="Replay protection enabled" checked={Boolean(clientDraft?.replay_protection_enabled)} onChange={()=>setClientDraft((prev:any)=>({...prev,replay_protection_enabled:!Boolean(prev?.replay_protection_enabled)}))}/>
                <FG label="IP Allowlist (comma-separated)">
                  <Inp value={String(clientDraft?.ip_whitelist_text||"")} onChange={(e)=>setClientDraft((prev:any)=>({...prev,ip_whitelist_text:e.target.value}))} placeholder="10.10.10.0/24, 203.0.113.44"/>
                </FG>
                {String(clientDraft?.auth_mode||"api_key")==="oauth_mtls"&&<>
                  <FG label="mTLS Certificate SHA-256 Fingerprint">
                    <Inp value={String(clientDraft?.mtls_cert_fingerprint||"")} onChange={(e)=>setClientDraft((prev:any)=>({...prev,mtls_cert_fingerprint:e.target.value}))} mono placeholder="AB:CD:..."/>
                  </FG>
                  <Row2>
                    <FG label="Subject DN">
                      <Inp value={String(clientDraft?.mtls_subject_dn||"")} onChange={(e)=>setClientDraft((prev:any)=>({...prev,mtls_subject_dn:e.target.value}))} placeholder="CN=sdk-client,OU=Payments,O=Example"/>
                    </FG>
                    <FG label="URI SAN">
                      <Inp value={String(clientDraft?.mtls_uri_san||"")} onChange={(e)=>setClientDraft((prev:any)=>({...prev,mtls_uri_san:e.target.value}))} placeholder="spiffe://root/workloads/sdk-client"/>
                    </FG>
                  </Row2>
                  <div style={{fontSize:10,color:C.dim}}>OAuth mTLS binds issued access tokens to the presented client certificate thumbprint. The same certificate must be presented again on REST calls.</div>
                </>}
                {String(clientDraft?.auth_mode||"api_key")==="dpop"&&<div style={{fontSize:10,color:C.dim}}>DPoP proof keys are supplied dynamically by the client during token issuance. The KMS binds the access token to the proof JWK thumbprint and checks anti-replay on each signed request.</div>}
                {String(clientDraft?.auth_mode||"api_key")==="http_message_signature"&&<>
                  <Row2>
                    <FG label="Signature Key ID">
                      <Inp value={String(clientDraft?.http_signature_key_id||"")} onChange={(e)=>setClientDraft((prev:any)=>({...prev,http_signature_key_id:e.target.value}))} placeholder="sdk-signing-key-01"/>
                    </FG>
                    <FG label="Signature Algorithm">
                      <Sel value={String(clientDraft?.http_signature_algorithm||"ed25519")} onChange={(e)=>setClientDraft((prev:any)=>({...prev,http_signature_algorithm:e.target.value}))}>
                        <option value="ed25519">Ed25519</option>
                        <option value="rsa-pss-sha512">RSA-PSS-SHA512</option>
                        <option value="ecdsa-p256-sha256">ECDSA-P256-SHA256</option>
                        <option value="ecdsa-p384-sha384">ECDSA-P384-SHA384</option>
                      </Sel>
                    </FG>
                  </Row2>
                  <FG label="HTTP Signature Public Key (PEM)">
                    <Txt rows={7} mono value={String(clientDraft?.http_signature_public_key_pem||"")} onChange={(e)=>setClientDraft((prev:any)=>({...prev,http_signature_public_key_pem:e.target.value}))} placeholder={"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}/>
                  </FG>
                  <div style={{fontSize:10,color:C.dim}}>HTTP Message Signatures verify request components plus content digest using the registered public key, and they share the same replay-defense path as DPoP.</div>
                </>}
                {String(clientDraft?.auth_mode||"api_key")==="api_key"&&<div style={{fontSize:10,color:C.dim}}>Legacy bearer and API-key callers remain available here, but they are counted as non-compliant in posture and compliance until moved to a sender-constrained mode.</div>}
                <div style={{display:"grid",gridTemplateColumns:"repeat(4,minmax(0,1fr))",gap:8}}>
                  <Stat l="Verified" v={String(Number(clientDraft?.verified_request_count||0))} s={fmtClientTS(clientDraft?.last_verified_request_at)} c="green"/>
                  <Stat l="Replay" v={String(Number(clientDraft?.replay_violation_count||0))} s={fmtClientTS(clientDraft?.last_replay_violation_at)} c={Number(clientDraft?.replay_violation_count||0)>0?"red":"blue"}/>
                  <Stat l="Signature" v={String(Number(clientDraft?.signature_failure_count||0))} s={fmtClientTS(clientDraft?.last_signature_failure_at)} c={Number(clientDraft?.signature_failure_count||0)>0?"amber":"green"}/>
                  <Stat l="Unsigned" v={String(Number(clientDraft?.unsigned_reject_count||0))} s={fmtClientTS(clientDraft?.last_unsigned_reject_at)} c={Number(clientDraft?.unsigned_reject_count||0)>0?"amber":"green"}/>
                </div>
                <div style={{display:"flex",justifyContent:"flex-end",gap:8}}>
                  <Btn onClick={()=>setClientDraft(selectedClient?{...selectedClient,ip_whitelist_text:Array.isArray(selectedClient?.ip_whitelist)?selectedClient.ip_whitelist.join(", "):""}:null)}>Reset</Btn>
                  <Btn primary onClick={saveClientSecurity} disabled={clientSaving}>{clientSaving?"Saving...":"Save Client Security"}</Btn>
                </div>
              </div>:<div style={{fontSize:10,color:C.muted}}>Select a REST client to review sender-constrained auth settings.</div>}
            </div>
          </div>
        </Card>
        <Card>
          <div style={{fontSize:12,fontWeight:700,color:C.text,marginBottom:8}}>What This Protects</div>
          <div style={{display:"grid",gap:8}}>
            <div style={{padding:"8px 10px",border:`1px solid ${C.border}`,borderRadius:10,background:C.surface}}>
              <div style={{fontSize:10,color:C.text,fontWeight:700}}>OAuth mTLS</div>
              <div style={{fontSize:9,color:C.dim,marginTop:4}}>Binds the access token to the client certificate thumbprint so a stolen bearer token cannot be replayed without the certificate.</div>
            </div>
            <div style={{padding:"8px 10px",border:`1px solid ${C.border}`,borderRadius:10,background:C.surface}}>
              <div style={{fontSize:10,color:C.text,fontWeight:700}}>DPoP</div>
              <div style={{fontSize:9,color:C.dim,marginTop:4}}>Adds a per-request proof JWT tied to the HTTP method, URL, access token hash, and a one-time nonce window.</div>
            </div>
            <div style={{padding:"8px 10px",border:`1px solid ${C.border}`,borderRadius:10,background:C.surface}}>
              <div style={{fontSize:10,color:C.text,fontWeight:700}}>HTTP Message Signatures</div>
              <div style={{fontSize:9,color:C.dim,marginTop:4}}>Signs request components and body digests using the client public key so automation and SDK calls become tamper-evident and replay-aware.</div>
            </div>
          </div>
        </Card>
      </Row2>
      <Row2>
        <Card style={{minHeight:620}}>
          <FG label="Search Endpoints">
            <Inp value={endpointSearch} onChange={(e)=>setEndpointSearch(e.target.value)} placeholder="Search service, method, path or capability..." mono/>
            <div style={{fontSize:10,color:C.muted,marginTop:6}}>
              {`${filteredEndpoints.length} matched`}
            </div>
          </FG>
          <FG label="Endpoint Catalog">
            <Sel value={selectedEndpointID} onChange={(e)=>setSelectedEndpointID(e.target.value)}>
              {groupedEndpoints.map(([group,items]:any)=><optgroup key={String(group)} label={String(group)}>
                {items.map((item:any)=><option key={item.id} value={item.id}>{item.title}</option>)}
              </optgroup>)}
            </Sel>
          </FG>
          <FG label="What this endpoint does">
            <div style={{fontSize:10,color:C.dim,lineHeight:1.5}}>{String(endpoint?.description||"")}</div>
          </FG>
          <Row2>
            <FG label="Service"><Inp value={String(endpoint?.service||"")} readOnly/></FG>
            <FG label="Method"><Inp value={String(endpoint?.method||"")} readOnly/></FG>
          </Row2>
          <FG label="Path">
            <Inp value={String(endpoint?.pathTemplate||"")} readOnly mono/>
          </FG>
          <FG label="Authentication">
            <div style={{fontSize:10,color:C.dim}}>
              Bearer JWT is mandatory. Endpoint execution is blocked until JWT is present.
            </div>
          </FG>
          <FG label="Request Example">
            <Txt rows={4} readOnly mono value={String(endpoint?.requestExample||"")}/>
          </FG>
          <FG label="Expected Success Response">
            <Txt rows={6} readOnly mono value={pretty(endpoint?.responseExample||{})}/>
          </FG>
          <FG label="Expected Error Codes">
            <div style={{display:"grid",gap:6}}>
              {(Array.isArray(endpoint?.errorCodes)?endpoint.errorCodes:[]).map((item:any)=>(
                <div key={`${item.code}-${item.meaning}`} style={{display:"flex",gap:8,fontSize:10}}>
                  <B c={Number(item.code)>=500?"red":Number(item.code)>=400?"amber":"blue"}>{String(item.code)}</B>
                  <span style={{color:C.dim}}>{String(item.meaning||"")}</span>
                </div>
              ))}
            </div>
          </FG>
        </Card>
        <Card style={{minHeight:620}}>
          <FG label="Authentication Mode" required>
            <Sel value={authMode} onChange={(e)=>setAuthMode(e.target.value)}>
              <option value="session-jwt">Use current session JWT</option>
              <option value="custom-jwt">Use custom Bearer JWT</option>
            </Sel>
          </FG>
          {authMode==="custom-jwt"&&<FG label="Custom Bearer JWT" required>
            <Txt rows={4} mono value={customJWT} onChange={(e)=>setCustomJWT(e.target.value)} placeholder="Paste JWT token"/>
          </FG>}
          <Row3>
            <FG label="Service"><Inp value={serviceName} onChange={(e)=>setServiceName(e.target.value)} mono/></FG>
            <FG label="Method">
              <Sel value={method} onChange={(e)=>setMethod(e.target.value.toUpperCase())}>
                <option>GET</option>
                <option>POST</option>
                <option>PUT</option>
                <option>PATCH</option>
                <option>DELETE</option>
              </Sel>
            </FG>
            <FG label="Tenant Parameter (X-Tenant-ID)" required><Inp value={tenantParam} onChange={(e)=>setTenantParam(e.target.value)} mono placeholder="tenant-id"/></FG>
          </Row3>
          <FG label="Path (supports {{tenant_id}} and dynamic {{param}} placeholders)">
            <Inp value={pathValue} onChange={(e)=>setPathValue(e.target.value)} mono/>
          </FG>
          <Row3>
            <FG label="key_id">
              <Sel value={keyID} onChange={(e)=>setKeyID(e.target.value)}>
                <option value="">- select key -</option>
                {(Array.isArray(keyChoices)?keyChoices:[]).map((k:any)=><option key={k.id} value={k.id}>{k.name} ({k.id})</option>)}
              </Sel>
            </FG>
            <FG label="cert_id">
              <Sel value={certID} onChange={(e)=>setCertID(e.target.value)}>
                <option value="">- select cert -</option>
                {(Array.isArray(certOptions)?certOptions:[]).map((c:any)=><option key={c.id} value={c.id}>{c.subject_cn||c.id} ({c.id})</option>)}
              </Sel>
            </FG>
            <FG label="secret_id">
              <Sel value={secretID} onChange={(e)=>setSecretID(e.target.value)}>
                <option value="">- select secret -</option>
                {(Array.isArray(secretOptions)?secretOptions:[]).map((s:any)=><option key={s.id} value={s.id}>{s.name||s.id} ({s.id})</option>)}
              </Sel>
            </FG>
          </Row3>
          <FG label="JSON Body">
            <Txt rows={10} mono value={bodyValue} onChange={(e)=>setBodyValue(e.target.value)} placeholder='{"tenant_id":"{{tenant_id}}"}'/>
          </FG>
          <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginBottom:8}}>
            <Btn onClick={buildPreview}>Refresh cURL</Btn>
            <Btn primary onClick={executeRequest} disabled={running}>{running?"Executing...":"Execute Call"}</Btn>
          </div>
          <FG label={`Response (${statusText})`}>
            <Txt rows={10} mono value={responseText} readOnly/>
          </FG>
          <FG label="How to call (cURL)">
            <Txt rows={6} mono value={requestPreview} readOnly/>
          </FG>
        </Card>
      </Row2>
    </Section>
  </div>;
};
