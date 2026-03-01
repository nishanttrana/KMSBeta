// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import { RefreshCcw } from "lucide-react";
import {
  configureHYOKEndpoint,
  deleteHYOKEndpoint,
  getHYOKDKEPublicKey,
  getHYOKHealth,
  hyokCrypto,
  listHYOKEndpoints,
  listHYOKRequests
} from "../../../lib/hyok";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, Chk, FG, Inp, Modal, Row2, Section, Sel, Txt, usePromptDialog } from "../legacyPrimitives";
function formatAgo(value: unknown): string {
  const raw = String(value || "").trim();
  if (!raw) {
    return "-";
  }
  const ts = new Date(raw);
  if (Number.isNaN(ts.getTime())) {
    return "-";
  }
  const diffSec = Math.max(0, Math.floor((Date.now() - ts.getTime()) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}d ago`;
}


function normalizeKeyState(state: string): string {
  const raw = String(state || "").toLowerCase().trim();
  if (raw === "destroyed" || raw === "deleted") {
    return "deleted";
  }
  if (raw === "destroy-pending" || raw === "delete-pending" || raw === "deletion-pending") {
    return "destroy-pending";
  }
  if (raw === "preactive" || raw === "pre-active") {
    return "pre-active";
  }
  if (raw === "retired" || raw === "deactivated") {
    return "deactivated";
  }
  if (raw === "generation" || raw === "generated") {
    return "pre-active";
  }
  return raw || "unknown";
}

function keyChoicesFromCatalog(keyCatalog: any[]): any[] {
  if (!Array.isArray(keyCatalog)) {
    return [];
  }
  return keyCatalog.filter((k) => normalizeKeyState(String(k?.state || "")) !== "deleted");
}

function renderKeyOptions(keyChoices: any[]): any[] {
  if (!keyChoices.length) {
    return [<option key="no-customer-keys" value="">No customer keys available</option>];
  }
  return keyChoices.map((k) => (
    <option key={k.id} value={k.id}>
      {k.name} {k.algo ? `(${k.algo})` : ""}
    </option>
  ));
}

const HYOK_PROTOCOL_LABELS={
  dke:"Microsoft DKE",
  salesforce:"Salesforce Cache-Only",
  google:"Google Cloud EKM",
  generic:"Generic HYOK"
};

const HYOK_PROTOCOL_DETAILS={
  dke:"Double Key Encryption: decrypt + public key delivery",
  salesforce:"Shield Platform Encryption wrap/unwrap proxy",
  google:"External Key Manager wrap/unwrap proxy",
  generic:"Generic encrypt/decrypt/wrap/unwrap proxy"
};

const HYOK_OPS_BY_PROTOCOL={
  dke:["decrypt","publickey"],
  salesforce:["wrap","unwrap"],
  google:["wrap","unwrap"],
  generic:["encrypt","decrypt","wrap","unwrap"]
};

export const HYOKTab=({session,keyCatalog,onToast})=>{
  const [modal,setModal]=useState<null|"config">(null);
  const [loading,setLoading]=useState(false);
  const [refreshing,setRefreshing]=useState(false);
  const [saving,setSaving]=useState(false);
  const [executing,setExecuting]=useState(false);
  const [endpoints,setEndpoints]=useState<any[]>([]);
  const [requests,setRequests]=useState<any[]>([]);
  const [health,setHealth]=useState<any>(null);
  const [cfgProtocol,setCfgProtocol]=useState("generic");
  const [cfgEnabled,setCfgEnabled]=useState(true);
  const [cfgAuthMode,setCfgAuthMode]=useState("mtls_or_jwt");
  const [cfgPolicyID,setCfgPolicyID]=useState("");
  const [cfgGovernance,setCfgGovernance]=useState(false);
  const [cfgMetadata,setCfgMetadata]=useState("{\n  \"description\": \"\"\n}");
  const [testProtocol,setTestProtocol]=useState("generic");
  const [testOperation,setTestOperation]=useState("encrypt");
  const [testKeyID,setTestKeyID]=useState("");
  const [testPlaintext,setTestPlaintext]=useState("");
  const [testCiphertext,setTestCiphertext]=useState("");
  const [testIV,setTestIV]=useState("");
  const [testRefID,setTestRefID]=useState("");
  const [testRequester,setTestRequester]=useState("");
  const [testRequesterEmail,setTestRequesterEmail]=useState("");
  const [testOutput,setTestOutput]=useState("// HYOK result will appear here...");
  const keyChoices=useMemo(()=>keyChoicesFromCatalog(keyCatalog),[keyCatalog]);
  const promptDialog=usePromptDialog();

  const refresh=async(silent=false)=>{
    if(!session?.token){
      setEndpoints([]);
      setRequests([]);
      setHealth(null);
      return;
    }
    if(!silent){
      setLoading(true);
    }else{
      setRefreshing(true);
    }
    try{
      const [eps,reqs,h]=await Promise.all([
        listHYOKEndpoints(session),
        listHYOKRequests(session,{limit:60,offset:0}),
        getHYOKHealth(session)
      ]);
      setEndpoints(Array.isArray(eps)?eps:[]);
      setRequests(Array.isArray(reqs)?reqs:[]);
      setHealth(h||null);
    }catch(error){
      onToast?.(`HYOK load failed: ${errMsg(error)}`);
    }finally{
      if(!silent){
        setLoading(false);
      }else{
        setRefreshing(false);
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

  useEffect(()=>{
    if(testKeyID){
      return;
    }
    const first=Array.isArray(keyChoices)?keyChoices[0]:null;
    if(first?.id){
      setTestKeyID(String(first.id));
    }
  },[keyChoices,testKeyID]);

  useEffect(()=>{
    const allowed=HYOK_OPS_BY_PROTOCOL[testProtocol]||[];
    if(!allowed.includes(testOperation)){
      setTestOperation(String(allowed[0]||"encrypt"));
    }
  },[testProtocol,testOperation]);

  const openConfig=(protocol:string)=>{
    const existing=(Array.isArray(endpoints)?endpoints:[]).find((item)=>String(item?.protocol||"")===protocol);
    setCfgProtocol(protocol);
    setCfgEnabled(existing?Boolean(existing.enabled):true);
    setCfgAuthMode(String(existing?.auth_mode||"mtls_or_jwt"));
    setCfgPolicyID(String(existing?.policy_id||""));
    setCfgGovernance(Boolean(existing?.governance_required));
    setCfgMetadata(String(existing?.metadata_json||"{\n  \"description\": \"\"\n}"));
    setModal("config");
  };

  const submitConfig=async()=>{
    if(!session?.token){
      return;
    }
    const protocol=String(cfgProtocol||"").trim();
    if(!protocol){
      onToast?.("Select a protocol.");
      return;
    }
    const authMode=String(cfgAuthMode||"").trim();
    if(!authMode){
      onToast?.("Select an auth mode.");
      return;
    }
    const metadataJSON=String(cfgMetadata||"{}").trim()||"{}";
    if(metadataJSON){
      try{
        JSON.parse(metadataJSON);
      }catch{
        onToast?.("Metadata JSON is invalid.");
        return;
      }
    }
    setSaving(true);
    try{
      await configureHYOKEndpoint(session,protocol,{
        enabled:Boolean(cfgEnabled),
        auth_mode:authMode,
        policy_id:String(cfgPolicyID||"").trim(),
        governance_required:Boolean(cfgGovernance),
        metadata_json:metadataJSON
      });
      onToast?.(`HYOK endpoint updated: ${HYOK_PROTOCOL_LABELS[protocol]||protocol}.`);
      setModal(null);
      await refresh(true);
    }catch(error){
      onToast?.(`HYOK endpoint update failed: ${errMsg(error)}`);
    }finally{
      setSaving(false);
    }
  };

  const runDelete=async(protocol:string)=>{
    const confirmed=await promptDialog.confirm({
      title:"Delete HYOK Endpoint Config",
      message:`Delete endpoint config for ${HYOK_PROTOCOL_LABELS[protocol]||protocol}?\n\nThis resets it to default endpoint policy.`,
      confirmLabel:"Delete",
      danger:true
    });
    if(!confirmed){
      return;
    }
    try{
      await deleteHYOKEndpoint(session,protocol);
      onToast?.(`HYOK endpoint removed: ${HYOK_PROTOCOL_LABELS[protocol]||protocol}.`);
      await refresh(true);
    }catch(error){
      onToast?.(`Delete endpoint failed: ${errMsg(error)}`);
    }
  };

  const executeTest=async()=>{
    if(!session?.token){
      return;
    }
    const keyID=String(testKeyID||"").trim();
    if(!keyID){
      onToast?.("Select a key.");
      return;
    }
    const protocol=String(testProtocol||"generic");
    const operation=String(testOperation||"encrypt");
    setExecuting(true);
    try{
      if(protocol==="dke"&&operation==="publickey"){
        const out=await getHYOKDKEPublicKey(session,keyID);
        setTestOutput(JSON.stringify(out,null,2));
      }else{
        const out=await hyokCrypto(session,protocol,operation,keyID,{
          plaintext:testPlaintext,
          ciphertext:testCiphertext,
          iv:testIV,
          reference_id:testRefID,
          requester_id:testRequester,
          requester_email:testRequesterEmail
        });
        setTestOutput(JSON.stringify(out,null,2));
      }
      onToast?.(`HYOK ${operation} completed.`);
      await refresh(true);
    }catch(error){
      onToast?.(`HYOK ${operation} failed: ${errMsg(error)}`);
    }finally{
      setExecuting(false);
    }
  };

  const endpointRows=Array.isArray(endpoints)?endpoints:[];
  const requestRows=Array.isArray(requests)?requests:[];
  const allowedOps=HYOK_OPS_BY_PROTOCOL[testProtocol]||[];
  const enabledCount=endpointRows.filter((item)=>Boolean(item?.enabled)).length;
  const protocolStatuses=(health&&typeof health==="object"&&health.protocol_statuses&&typeof health.protocol_statuses==="object")
    ? health.protocol_statuses
    : {};
  const proxyHealthStatus=String(health?.status||"unknown").toLowerCase();
  const proxyHealthColor=proxyHealthStatus==="ok"?"green":proxyHealthStatus==="degraded"?"red":"amber";
  const endpointStatusMeta=(protocol:string,item:any)=>{
    const info=protocolStatuses?.[protocol]||{};
    const status=String(info?.status||"").toLowerCase();
    const reason=String(info?.reason||"").trim();
    if(status==="connected"){
      return {label:"Active",color:"green",reason};
    }
    if(status==="configured"){
      return {label:"Configured",color:"amber",reason};
    }
    if(status==="not_configured"){
      return {label:"Not Configured",color:"amber",reason:reason||"Endpoint is not configured yet."};
    }
    if(status==="disabled"){
      return {label:"Disabled",color:"red",reason};
    }
    if(status==="auth_failed"){
      return {label:"Auth Failed",color:"red",reason};
    }
    if(status==="degraded"||status==="unreachable"){
      return {label:"Degraded",color:"red",reason};
    }
    return Boolean(item?.enabled)
      ? {label:"Enabled",color:"blue",reason}
      : {label:"Disabled",color:"red",reason};
  };

  return <div>
    <Section
      title="HYOK Proxy Endpoints"
      actions={<>
        <Btn small onClick={()=>void refresh(false)} disabled={loading||refreshing}><RefreshCcw size={12} strokeWidth={2}/> Refresh</Btn>
      </>}
    >
      <Row2>
        <Card>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
            <div style={{fontSize:12,color:C.text,fontWeight:700}}>Proxy Health</div>
            <B c={proxyHealthColor}>{String(health?.status||"unknown").toUpperCase()}</B>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"4px 10px"}}>
            {[["Tenant",String(health?.tenant_id||session?.tenantId||"-")],["Connected Endpoints",`${Number(health?.connected_endpoints||0)} / ${Number(health?.endpoint_count||endpointRows.length||4)}`],["Enabled Endpoints",`${Number(health?.enabled_endpoints||enabledCount)} / ${Number(health?.endpoint_count||endpointRows.length||4)}`],["Policy Fail Closed",Boolean(health?.policy_fail_closed)?"Yes":"No"],["Checked",formatAgo(String(health?.checked_at||""))]].map(([k,v])=>
              <div key={k} style={{display:"flex",justifyContent:"space-between",fontSize:10,padding:"2px 0",gap:8}}>
                <span style={{color:C.muted}}>{k}</span>
                <span style={{color:C.text,fontFamily:"'JetBrains Mono',monospace",textAlign:"right"}}>{v}</span>
              </div>
            )}
          </div>
        </Card>
        <Card>
          <div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:6}}>SUPPORTED PROTOCOLS</div>
          <div style={{display:"grid",gap:6}}>
            {["dke","salesforce","google","generic"].map((protocol)=>{
              const item=endpointRows.find((e)=>String(e?.protocol||"")===protocol);
              const statusMeta=endpointStatusMeta(protocol,item);
              return <div key={protocol} style={{display:"flex",justifyContent:"space-between",alignItems:"center",border:`1px solid ${C.border}`,borderRadius:8,padding:"8px 10px"}}>
                <div style={{minWidth:0}}>
                  <div style={{fontSize:11,color:C.text,fontWeight:700}}>{HYOK_PROTOCOL_LABELS[protocol]}</div>
                  <div style={{fontSize:9,color:C.dim,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{HYOK_PROTOCOL_DETAILS[protocol]}</div>
                  {statusMeta.reason?<div style={{fontSize:9,color:C.muted,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{statusMeta.reason}</div>:null}
                </div>
                <div style={{display:"flex",alignItems:"center",gap:6,flexShrink:0}}>
                  <B c={statusMeta.color}>{statusMeta.label}</B>
                  <Btn small onClick={()=>openConfig(protocol)}>Configure</Btn>
                  <Btn small danger onClick={()=>void runDelete(protocol)}>Delete</Btn>
                </div>
              </div>;
            })}
          </div>
        </Card>
      </Row2>
    </Section>

    <Section title="HYOK Live Test Console">
      <Row2>
        <Card>
          <FG label="Protocol" required>
            <Sel value={testProtocol} onChange={(e)=>setTestProtocol(e.target.value)}>
              <option value="dke">Microsoft DKE</option>
              <option value="salesforce">Salesforce Cache-Only</option>
              <option value="google">Google Cloud EKM</option>
              <option value="generic">Generic HYOK</option>
            </Sel>
          </FG>
          <FG label="Operation" required>
            <Sel value={testOperation} onChange={(e)=>setTestOperation(e.target.value)}>
              {allowedOps.map((op)=><option key={op} value={op}>{op}</option>)}
            </Sel>
          </FG>
          <FG label="Vecta Key" required>
            <Sel value={testKeyID} onChange={(e)=>setTestKeyID(e.target.value)}>
              {renderKeyOptions(keyChoices)}
            </Sel>
          </FG>
          {testOperation==="encrypt"||testOperation==="wrap"?<FG label="Plaintext (base64)" required>
            <Txt rows={4} value={testPlaintext} onChange={(e)=>setTestPlaintext(e.target.value)} placeholder="SGVsbG8gd29ybGQ="/>
          </FG>:null}
          {testOperation==="decrypt"||testOperation==="unwrap"?<FG label="Ciphertext (base64)" required>
            <Txt rows={4} value={testCiphertext} onChange={(e)=>setTestCiphertext(e.target.value)} placeholder="Paste ciphertext base64"/>
          </FG>:null}
          {testOperation!=="publickey"?<Row2>
            <FG label="IV (base64)">
              <Inp value={testIV} onChange={(e)=>setTestIV(e.target.value)} placeholder="Optional for algorithm/mode" mono/>
            </FG>
            <FG label="Reference ID">
              <Inp value={testRefID} onChange={(e)=>setTestRefID(e.target.value)} placeholder="txn-..." mono/>
            </FG>
          </Row2>:null}
          <Row2>
            <FG label="Requester ID">
              <Inp value={testRequester} onChange={(e)=>setTestRequester(e.target.value)} placeholder="svc-app-01" mono/>
            </FG>
            <FG label="Requester Email">
              <Inp value={testRequesterEmail} onChange={(e)=>setTestRequesterEmail(e.target.value)} placeholder="security@bank.com" mono/>
            </FG>
          </Row2>
          <Btn primary onClick={()=>void executeTest()} disabled={executing}>{executing?"Executing...":"Execute HYOK Request"}</Btn>
        </Card>
        <Card>
          <div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:6}}>OUTPUT</div>
          <Txt rows={22} value={testOutput} readOnly/>
        </Card>
      </Row2>
    </Section>

    <Section title="HYOK Request Audit Trail">
      <Card style={{padding:0,overflow:"hidden"}}>
        <div style={{display:"grid",gridTemplateColumns:"120px 90px 80px 110px 1fr 90px",padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>
          <div>Time</div><div>Protocol</div><div>Operation</div><div>Status</div><div>Key / Requester</div><div>Auth</div>
        </div>
        <div style={{maxHeight:260,overflowY:"auto"}}>
          {requestRows.map((item)=>(
            <div key={item.id} style={{display:"grid",gridTemplateColumns:"120px 90px 80px 110px 1fr 90px",padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:10,alignItems:"center"}}>
              <div style={{color:C.dim,fontFamily:"'JetBrains Mono',monospace"}}>{formatAgo(item.created_at)}</div>
              <div style={{color:C.accent}}>{String(item.protocol||"-")}</div>
              <div style={{color:C.text}}>{String(item.operation||"-")}</div>
              <div><B c={String(item.status||"").toLowerCase()==="success"?"green":String(item.status||"").toLowerCase()==="pending_approval"?"amber":"red"}>{String(item.status||"unknown")}</B></div>
              <div style={{minWidth:0}}>
                <div style={{color:C.text,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{String(item.key_id||"-")}</div>
                <div style={{fontSize:9,color:C.muted,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{String(item.requester_id||item.auth_subject||"-")}</div>
              </div>
              <div style={{color:C.dim}}>{String(item.auth_mode||"-")}</div>
            </div>
          ))}
          {!requestRows.length&&<div style={{padding:"12px",fontSize:10,color:C.dim}}>{loading?"Loading HYOK requests...":"No HYOK requests yet."}</div>}
        </div>
      </Card>
    </Section>

    <Modal open={modal==="config"} onClose={()=>setModal(null)} title="Configure HYOK Endpoint" wide>
      <FG label="Protocol" required>
        <Sel value={cfgProtocol} onChange={(e)=>setCfgProtocol(e.target.value)}>
          <option value="dke">Microsoft DKE</option>
          <option value="salesforce">Salesforce Cache-Only</option>
          <option value="google">Google Cloud EKM</option>
          <option value="generic">Generic HYOK</option>
        </Sel>
      </FG>
      <Row2>
        <FG label="Enabled">
          <Chk label="Enable protocol endpoint" checked={cfgEnabled} onChange={()=>setCfgEnabled((v)=>!v)}/>
        </FG>
        <FG label="Governance">
          <Chk label="Require governance approval before crypto release" checked={cfgGovernance} onChange={()=>setCfgGovernance((v)=>!v)}/>
        </FG>
      </Row2>
      <FG label="Auth Mode" required>
        <Sel value={cfgAuthMode} onChange={(e)=>setCfgAuthMode(e.target.value)}>
          <option value="mtls_or_jwt">mTLS or JWT</option>
          <option value="mtls">mTLS only</option>
          <option value="jwt">JWT only</option>
        </Sel>
      </FG>
      <FG label="Policy ID">
        <Inp value={cfgPolicyID} onChange={(e)=>setCfgPolicyID(e.target.value)} placeholder="Optional policy ID for hyok.<protocol>.<op>" mono/>
      </FG>
      <FG label="Metadata JSON" hint="Stored with endpoint configuration; keep valid JSON.">
        <Txt rows={6} value={cfgMetadata} onChange={(e)=>setCfgMetadata(e.target.value)} placeholder='{"description":"Production DKE endpoint"}'/>
      </FG>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)} disabled={saving}>Cancel</Btn>
        <Btn primary onClick={()=>void submitConfig()} disabled={saving}>{saving?"Saving...":"Save Endpoint"}</Btn>
      </div>
    </Modal>
    {promptDialog.ui}
  </div>;
};

