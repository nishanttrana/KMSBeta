import { useCallback, useEffect, useMemo, useState } from "react";
import type { AuthSession } from "../../../lib/auth";
import { listCertificates } from "../../../lib/certs";
import { listSecrets } from "../../../lib/secrets";
import { DISCOVERED_REST_API_CATALOG } from "../../../generated/restApiCatalog.generated";
import { executeRestPlaygroundRequest } from "../../../lib/restPlayground";
import { REST_API_CATALOG } from "../restApiCatalog";
import { B, Btn, Card, FG, Inp, Row2, Row3, Section, Sel, Txt } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";

const REST_API_METHODS_WITH_BODY = new Set(["POST", "PUT", "PATCH"]);

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
