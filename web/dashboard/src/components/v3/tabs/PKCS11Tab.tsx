// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import { downloadEKMSDK, getEKMSDKOverview } from "../../../lib/ekm";
import { refreshSession } from "../../../lib/auth";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, FG, Inp, Row2, Section, Sel } from "../legacyPrimitives";
export const PKCS11Tab=({session,onToast})=>{
  const [loading,setLoading]=useState(false);
  const [downloading,setDownloading]=useState("");
  const [jwtLoading,setJWTLoading]=useState(false);
  const [sdkTenant,setSDKTenant]=useState(String(session?.tenantId||""));
  const [sdkJWT,setSDKJWT]=useState("");
  const [sdkJWTExp,setSDKJWTExp]=useState("");
  const [sdkJWTGeneratedAt,setSDKJWTGeneratedAt]=useState("");
  const [showJWT,setShowJWT]=useState(false);
  const [overview,setOverview]=useState<any>({
    refreshed_at:"",
    providers:[],
    mechanisms:[],
    clients:[]
  });
  const [pkcsTarget,setPKCSTarget]=useState("linux");
  const [jcaTarget,setJCATarget]=useState("all");

  const saveBase64File=(filename:string,b64:string,mime:string)=>{
    const raw=atob(String(b64||""));
    const bytes=new Uint8Array(raw.length);
    for(let i=0;i<raw.length;i+=1){
      bytes[i]=raw.charCodeAt(i);
    }
    const blob=new Blob([bytes],{type:mime||"application/octet-stream"});
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url;
    a.download=String(filename||"sdk.zip");
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const loadOverview=async(silent=false)=>{
    if(!session?.token){
      setOverview({refreshed_at:"",providers:[],mechanisms:[],clients:[]});
      return;
    }
    const tenantID=String(sdkTenant||session?.tenantId||"").trim();
    if(!tenantID){
      onToast?.("Tenant parameter is required for SDK telemetry.");
      return;
    }
    if(!silent){
      setLoading(true);
    }
    try{
      const out=await getEKMSDKOverview(session,tenantID);
      setOverview(out||{refreshed_at:"",providers:[],mechanisms:[],clients:[]});
    }catch(error){
      onToast?.(`SDK dashboard load failed: ${errMsg(error)}`);
    }finally{
      if(!silent){
        setLoading(false);
      }
    }
  };

  const downloadArtifact=async(provider:"pkcs11"|"jca",targetOS:"linux"|"windows"|"macos"|"all")=>{
    if(!session?.token){
      onToast?.("Login is required to download SDK.");
      return;
    }
    const tenantID=String(sdkTenant||session?.tenantId||"").trim();
    if(!tenantID){
      onToast?.("Tenant parameter is required for SDK download.");
      return;
    }
    const key=`${provider}:${targetOS}`;
    setDownloading(key);
    try{
      const out=await downloadEKMSDK(session,provider,targetOS,tenantID);
      saveBase64File(String(out?.filename||`vecta-${provider}-${targetOS}.zip`),String(out?.content||""),String(out?.content_type||"application/zip"));
      onToast?.(`${provider.toUpperCase()} SDK downloaded (${targetOS}).`);
      await loadOverview(true);
    }catch(error){
      onToast?.(`SDK download failed: ${errMsg(error)}`);
    }finally{
      setDownloading("");
    }
  };

  const createSDKJWT=async()=>{
    if(!session?.token){
      onToast?.("Login is required to create JWT.");
      return;
    }
    if(String(session?.mode||"")!=="backend"){
      onToast?.("JWT creation is available only in backend-auth mode.");
      return;
    }
    setJWTLoading(true);
    try{
      const out=await refreshSession(session);
      const token=String(out?.token||"").trim();
      if(!token){
        throw new Error("Auth service did not return access_token.");
      }
      setSDKJWT(token);
      setSDKJWTExp(String(out?.expiresAt||"").trim());
      setSDKJWTGeneratedAt(new Date().toISOString());
      setShowJWT(false);
      onToast?.("New JWT created for SDK usage.");
    }catch(error){
      onToast?.(`JWT creation failed: ${errMsg(error)}`);
    }finally{
      setJWTLoading(false);
    }
  };

  const copySDKJWT=async()=>{
    const token=String(sdkJWT||"").trim();
    if(!token){
      onToast?.("No JWT available yet.");
      return;
    }
    try{
      await navigator.clipboard.writeText(token);
      onToast?.("JWT copied.");
    }catch{
      onToast?.("Copy failed. Please copy manually.");
    }
  };

  useEffect(()=>{
    setSDKTenant(String(session?.tenantId||""));
  },[session?.tenantId]);

  useEffect(()=>{
    void loadOverview();
  },[session?.token,sdkTenant]);

  const providerByID=useMemo(()=>{
    const out:any={};
    for(const item of Array.isArray(overview?.providers)?overview.providers:[]){
      out[String(item?.id||"").toLowerCase()]=item;
    }
    return out;
  },[overview?.providers]);
  const pkcs=providerByID.pkcs11||{};
  const jca=providerByID.jca||{};
  const mechanismRows=Array.isArray(overview?.mechanisms)?overview.mechanisms:[];
  const maxOps=Math.max(...mechanismRows.map((row:any)=>Number(row?.ops_24h||0)),1);
  const clientRows=Array.isArray(overview?.clients)?overview.clients:[];

  const statusBadge=(status:string)=>{
    const s=String(status||"").toLowerCase();
    const tone=s==="active"?"green":s==="degraded"?"amber":"red";
    const label=s==="active"?"Active":s==="degraded"?"Degraded":"Down";
    const color=tone==="green"?C.green:tone==="amber"?C.amber:C.red;
    const bg=tone==="green"?C.greenDim:tone==="amber"?C.amberDim:C.redDim;
    const dotClass=tone==="green"?"sync-dot sync-dot--online":tone==="amber"?"sync-dot sync-dot--degraded":"sync-dot sync-dot--down";
    return <span style={{
      display:"inline-flex",
      alignItems:"center",
      gap:6,
      padding:"4px 10px",
      borderRadius:999,
      fontSize:11,
      fontWeight:700,
      color,
      background:bg
    }}>
      <span className={dotClass} style={{width:6,height:6,borderRadius:999,background:color}}/>
      {label}
    </span>;
  };

  const fmtOps=(n:any)=>{
    const v=Number(n||0);
    if(v>=1_000_000){
      return `${(v/1_000_000).toFixed(v>=10_000_000?0:1)}M`;
    }
    if(v>=1_000){
      return `${(v/1_000).toFixed(v>=10_000?0:1)}K`;
    }
    return String(v);
  };

  return <div>
    <Section title="SDK Providers">
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10,gap:8,flexWrap:"wrap"}}>
        <div style={{fontSize:10,color:C.muted}}>
          {loading?"Loading SDK telemetry...":`Refreshed ${overview?.refreshed_at?new Date(overview.refreshed_at).toLocaleString():"-"}`}
        </div>
        <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap",minWidth:360}}>
          <span style={{fontSize:10,color:C.muted}}>Tenant</span>
          <Inp w={220} mono value={sdkTenant} onChange={(e)=>setSDKTenant(e.target.value)} placeholder="tenant-id"/>
          <Btn small onClick={()=>void createSDKJWT()} disabled={jwtLoading||!session?.token||session?.mode!=="backend"}>
            {jwtLoading?"Creating JWT...":"Create JWT"}
          </Btn>
          <Btn small onClick={()=>void loadOverview()} disabled={loading}>{loading?"Refreshing...":"Refresh"}</Btn>
        </div>
      </div>
      {sdkJWT?<Card style={{marginBottom:10,padding:10}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8,marginBottom:6,flexWrap:"wrap"}}>
          <div style={{fontSize:11,color:C.text,fontWeight:700}}>SDK JWT (Bearer)</div>
          <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
            <Btn small onClick={()=>setShowJWT((v)=>!v)}>{showJWT?"Hide":"Show"}</Btn>
            <Btn small primary onClick={()=>void copySDKJWT()}>Copy JWT</Btn>
          </div>
        </div>
        <div style={{fontSize:10,color:C.dim,marginBottom:6}}>
          Use this token in SDK config (`VECTA_TOKEN`) instead of challenge-response.
          {sdkJWTExp?` Expires: ${new Date(sdkJWTExp).toLocaleString()}.`:""}
        </div>
        <textarea
          value={showJWT?sdkJWT:`${String(sdkJWT).slice(0,18)}...${String(sdkJWT).slice(-18)}`}
          readOnly
          style={{
            width:"100%",
            minHeight:72,
            resize:"vertical",
            border:`1px solid ${C.border}`,
            background:C.surface,
            color:C.text,
            borderRadius:10,
            padding:"8px 10px",
            fontSize:11,
            fontFamily:"'JetBrains Mono',monospace"
          }}
        />
        <div style={{fontSize:10,color:C.muted,marginTop:6}}>
          {`Generated ${sdkJWTGeneratedAt?new Date(sdkJWTGeneratedAt).toLocaleString():"-"}`}
        </div>
      </Card>:null}
      <Row2>
        <Card style={{minHeight:238,display:"flex",flexDirection:"column"}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
            <div style={{fontSize:13,color:C.text,fontWeight:700}}>{String(pkcs?.name||"PKCS#11 C Provider")}</div>
            {statusBadge(String(pkcs?.status||"active"))}
          </div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8,flex:1}}>
            {[["Library",pkcs?.artifact_name||"libvecta-pkcs11.so"],["Version",pkcs?.version||"v2.40 / v3.0"],["Size",pkcs?.size_label||"-"],["Transport",pkcs?.transport||"HTTPS + mTLS"],["Sessions",`${Number(pkcs?.sessions_active||0)} active`],["Ops/day",fmtOps(pkcs?.ops_24h)] ,["Top Mech",pkcs?.top_mechanism||"-"],["Clients",`${Number(pkcs?.clients_connected||0)} connected`]].map(([k,v])=>
              <div key={String(k)} style={{display:"flex",flexDirection:"column",gap:2}}>
                <span style={{fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:.7}}>{String(k)}</span>
                <span style={{fontSize:12,color:C.text,fontWeight:600}}>{String(v)}</span>
              </div>
            )}
          </div>
          <div style={{display:"flex",gap:6,flexWrap:"wrap",marginTop:8}}>
            {(Array.isArray(pkcs?.platforms)?pkcs.platforms:[]).map((p:string)=><B key={p} c="blue">{String(p)}</B>)}
          </div>
          <div style={{display:"flex",alignItems:"center",gap:8,marginTop:10}}>
            <Sel w={120} value={pkcsTarget} onChange={(e)=>setPKCSTarget(String(e.target.value||"linux"))}>
              <option value="linux">Linux</option>
              <option value="macos">macOS</option>
              <option value="windows">Windows</option>
            </Sel>
            <Btn small primary onClick={()=>void downloadArtifact("pkcs11",pkcsTarget as any)} disabled={downloading===`pkcs11:${pkcsTarget}`}>{downloading===`pkcs11:${pkcsTarget}`?"Downloading...":"Download SDK"}</Btn>
          </div>
        </Card>

        <Card style={{minHeight:238,display:"flex",flexDirection:"column"}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
            <div style={{fontSize:13,color:C.text,fontWeight:700}}>{String(jca?.name||"Java JCA/JCE Provider")}</div>
            {statusBadge(String(jca?.status||"active"))}
          </div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8,flex:1}}>
            {[["JAR",jca?.artifact_name||"vecta-jca-provider.jar"],["Version",jca?.version||"VECTA v1.0"],["Size",jca?.size_label||"-"],["Transport",jca?.transport||"HTTPS + mTLS"],["Sessions",`${Number(jca?.sessions_active||0)} active`],["Ops/day",fmtOps(jca?.ops_24h)],["Top Mech",jca?.top_mechanism||"-"],["Clients",`${Number(jca?.clients_connected||0)} apps`]].map(([k,v])=>
              <div key={String(k)} style={{display:"flex",flexDirection:"column",gap:2}}>
                <span style={{fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:.7}}>{String(k)}</span>
                <span style={{fontSize:12,color:C.text,fontWeight:600}}>{String(v)}</span>
              </div>
            )}
          </div>
          <div style={{display:"flex",gap:6,flexWrap:"wrap",marginTop:8}}>
            {(Array.isArray(jca?.capabilities)?jca.capabilities:[]).map((p:string)=><B key={p} c="blue">{String(p)}</B>)}
          </div>
          <div style={{display:"flex",alignItems:"center",gap:8,marginTop:10}}>
            <Sel w={120} value={jcaTarget} onChange={(e)=>setJCATarget(String(e.target.value||"all"))}>
              <option value="all">All OS</option>
              <option value="linux">Linux</option>
              <option value="windows">Windows</option>
              <option value="macos">macOS</option>
            </Sel>
            <Btn small primary onClick={()=>void downloadArtifact("jca",jcaTarget as any)} disabled={downloading===`jca:${jcaTarget}`}>{downloading===`jca:${jcaTarget}`?"Downloading...":"Download JAR"}</Btn>
          </div>
        </Card>
      </Row2>
    </Section>

    <Section title="Mechanism Usage (24h)">
      <Card>
        {mechanismRows.map((row:any)=>{
          const ops=Number(row?.ops_24h||0);
          const pct=maxOps>0?Math.max(2,(ops/maxOps)*100):0;
          return <div key={String(row?.mechanism||Math.random())} style={{display:"grid",gridTemplateColumns:"220px 1fr 92px 54px",gap:10,alignItems:"center",padding:"6px 0",borderBottom:`1px solid ${C.border}`}}>
            <div style={{fontSize:11,color:C.text,fontFamily:"'JetBrains Mono',monospace"}}>{String(row?.mechanism||"-")}</div>
            <div style={{height:10,background:C.border,borderRadius:999,overflow:"hidden"}}>
              <div style={{height:"100%",width:`${pct}%`,background:C.accent,borderRadius:999}}/>
            </div>
            <div style={{fontSize:11,color:C.text,textAlign:"right",fontWeight:700}}>{fmtOps(ops)}</div>
            <div style={{fontSize:11,color:C.accent,textAlign:"right",fontWeight:700}}>{`${Math.round(Number(row?.percent||0))}%`}</div>
          </div>;
        })}
        {!mechanismRows.length?<div style={{fontSize:10,color:C.muted}}>No mechanism usage recorded in the last 24 hours.</div>:null}
      </Card>
    </Section>

    <Section title="Connected Clients">
      <Card style={{overflow:"hidden"}}>
        <div style={{display:"grid",gridTemplateColumns:"2fr 1.3fr 1.3fr 1fr 110px",gap:8,padding:"6px 0",borderBottom:`1px solid ${C.border}`}}>
          {["Client","SDK","Mechanism","Ops/day","Status"].map((h)=><div key={h} style={{fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>{h}</div>)}
        </div>
        <div style={{maxHeight:260,overflowY:"auto"}}>
          {clientRows.map((client:any)=><div key={String(client?.id||client?.name||Math.random())} style={{display:"grid",gridTemplateColumns:"2fr 1.3fr 1.3fr 1fr 110px",gap:8,padding:"10px 0",borderBottom:`1px solid ${C.border}`}}>
            <div style={{minWidth:0}}>
              <div style={{fontSize:13,color:C.text,fontWeight:700,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{String(client?.name||client?.id||"-")}</div>
              <div style={{fontSize:10,color:C.dim,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{String(client?.id||"-")}</div>
            </div>
            <div style={{fontSize:11,color:C.dim,display:"flex",alignItems:"center"}}>{String(client?.sdk||"-")}</div>
            <div style={{fontSize:11,color:C.accent,fontFamily:"'JetBrains Mono',monospace",display:"flex",alignItems:"center"}}>{String(client?.mechanism||"-")}</div>
            <div style={{fontSize:12,color:C.text,fontWeight:700,display:"flex",alignItems:"center"}}>{`${fmtOps(client?.ops_24h)} ops/day`}</div>
            <div style={{display:"flex",justifyContent:"flex-end",alignItems:"center"}}>{statusBadge(String(client?.status||"down"))}</div>
          </div>)}
          {!clientRows.length?<div style={{padding:"12px 0",fontSize:10,color:C.muted}}>No SDK clients connected yet. Register EKM agents and run crypto operations to populate this panel.</div>:null}
        </div>
      </Card>
    </Section>
  </div>;
};


// 
// MAIN APP WITH SIDEBAR
// 


