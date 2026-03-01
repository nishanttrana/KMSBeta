import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCcw } from "lucide-react";
import type { AuthSession } from "../../../lib/auth";
import {
  createSecret,
  deleteSecret as deleteVaultSecret,
  generateKeyPairSecret,
  getSecretValue,
  listSecrets
} from "../../../lib/secrets";
import { Btn, Chk, FG, Inp, Modal, Row2, Section, Sel, Txt, usePromptDialog } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";

function safeFileName(input: string, fallback = "secret"): string {
  const raw = String(input || "").trim();
  const normalized = raw.replace(/[^a-zA-Z0-9._-]/g, "_").replace(/^_+|_+$/g, "");
  return normalized || fallback;
}

type VaultTabProps = {
  session: AuthSession | null;
  onToast?: (message: string) => void;
};

export const VaultTab=({session,onToast}: VaultTabProps)=>{
  const [modal,setModal]=useState<string|null>(null);
  const [busy,setBusy]=useState(false);
  const [loading,setLoading]=useState(false);
  const [refreshing,setRefreshing]=useState(false);
  const [refreshTick,setRefreshTick]=useState(0);
  const [secrets,setSecrets]=useState<any[]>([]);
  const [search,setSearch]=useState("");
  const [category,setCategory]=useState("all");

  const [createName,setCreateName]=useState("");
  const [createType,setCreateType]=useState("api_key");
  const [createValue,setCreateValue]=useState("");
  const [createTTLMode,setCreateTTLMode]=useState("none");
  const [createTTLCustom,setCreateTTLCustom]=useState("");
  const [createLeaseBased,setCreateLeaseBased]=useState(false);
  const [createDeliveryFormat,setCreateDeliveryFormat]=useState("raw");

  const [generateType,setGenerateType]=useState("ed25519");
  const [generateName,setGenerateName]=useState("");
  const [generatedPublicKey,setGeneratedPublicKey]=useState("");

  const [selectedSecret,setSelectedSecret]=useState<any|null>(null);
  const [valueFormat,setValueFormat]=useState("raw");
  const [retrievedValue,setRetrievedValue]=useState("");
  const [retrievedType,setRetrievedType]=useState("");
  const promptDialog=usePromptDialog();

  const categories=[
    {id:"all",label:"All"},
    {id:"ssh",label:"SSH"},
    {id:"pgp",label:"PGP"},
    {id:"ppk",label:"PPK"},
    {id:"x509",label:"X.509"},
    {id:"pkcs12",label:"PKCS#12"},
    {id:"jwk",label:"JWK"},
    {id:"kerberos",label:"Kerberos"},
    {id:"oauth",label:"OAuth"},
    {id:"wireguard",label:"WireGuard"},
    {id:"aws",label:"AWS"}
  ];

  const generateTypeOptions=[
    {value:"ed25519",label:"Ed25519 (SSH - recommended)"},
    {value:"rsa-4096",label:"RSA-4096 (SSH)"},
    {value:"ecdsa-p384",label:"ECDSA-P384 (SSH)"},
    {value:"pgp-rsa-4096",label:"PGP / GPG (RSA-4096)"},
    {value:"age-x25519",label:"age (X25519)"},
    {value:"wireguard-curve25519",label:"WireGuard (Curve25519)"}
  ];

  const supportedTypes=[
    "api_key","password","database_credentials","token","oauth_client_secret",
    "ssh_private_key","ssh_public_key","pgp_private_key","pgp_public_key","ppk",
    "x509_certificate","pkcs12","jwk","kerberos_keytab","wireguard_private_key",
    "wireguard_public_key","age_key","tls_private_key","tls_certificate","binary_blob",
    "bitlocker_keys"
  ];

  const ttlToSeconds=(mode:string,custom:string)=>{
    if(mode==="none") return 0;
    if(mode==="1h") return 3600;
    if(mode==="24h") return 86400;
    if(mode==="7d") return 604800;
    if(mode==="30d") return 2592000;
    if(mode==="90d") return 7776000;
    if(mode==="365d") return 31536000;
    if(mode==="custom"){
      return Math.max(0,Math.trunc(Number(custom||0)));
    }
    return 0;
  };

  const normalizeType=(value:string)=>String(value||"").trim().toLowerCase().replace(/\s+/g,"_");

  const loadSecrets=useCallback(async(force=false)=>{
    if(!session){
      return;
    }
    setLoading(true);
    try{
      const items=await listSecrets(session,{limit:500,offset:0,noCache:Boolean(force)});
      setSecrets(Array.isArray(items)?items:[]);
    }catch(error){
      onToast?.(`Secrets load failed: ${errMsg(error)}`);
    }finally{
      setLoading(false);
    }
  },[onToast,session]);

  useEffect(()=>{
    void loadSecrets(false);
  },[loadSecrets,refreshTick]);

  const handleRefresh=async()=>{
    if(!session){
      return;
    }
    setRefreshing(true);
    try{
      await loadSecrets(true);
      onToast?.("Secrets refreshed.");
    }finally{
      setRefreshing(false);
    }
  };

  const matchesCategory=useCallback((secret:any)=>{
    if(category==="all") return true;
    const type=String(secret?.secret_type||"").toLowerCase();
    const name=String(secret?.name||"").toLowerCase();
    const labels=Object.entries(secret?.labels||{}).map(([k,v])=>`${k}=${v}`).join(" ").toLowerCase();
    if(category==="ssh") return type.includes("ssh_");
    if(category==="pgp") return type.includes("pgp_");
    if(category==="ppk") return type==="ppk";
    if(category==="x509") return type==="x509_certificate"||type==="tls_certificate"||type==="tls_private_key";
    if(category==="pkcs12") return type==="pkcs12";
    if(category==="jwk") return type==="jwk";
    if(category==="kerberos") return type==="kerberos_keytab";
    if(category==="oauth") return type==="oauth_client_secret"||type==="token";
    if(category==="wireguard") return type.includes("wireguard_");
    if(category==="aws") return name.includes("aws")||labels.includes("aws");
    return true;
  },[category]);

  const ttlCompact=(secret:any)=>{
    const ttlSec=Number(secret?.lease_ttl_seconds||0);
    if(ttlSec<=0) return "8";
    if(ttlSec>=86400) return `${Math.round(ttlSec/86400)}d`;
    if(ttlSec>=3600) return `${Math.round(ttlSec/3600)}h`;
    if(ttlSec>=60) return `${Math.round(ttlSec/60)}m`;
    return `${ttlSec}s`;
  };

  const secretBadge=(secret:any)=>{
    const type=String(secret?.secret_type||"").toLowerCase();
    const map:any={
      api_key:{t:"api key",bg:"#1f5a8a",fg:"#72d4ff"},
      database_credentials:{t:"database cred",bg:"#4f2030",fg:"#ff6980"},
      ssh_private_key:{t:"ssh key",bg:"#124c46",fg:"#46efc2"},
      pgp_private_key:{t:"pgp key",bg:"#3b2a61",fg:"#b497ff"},
      ppk:{t:"ppk key",bg:"#2c2f7c",fg:"#9db0ff"},
      x509_certificate:{t:"x509 cert",bg:"#1f3f79",fg:"#72adff"},
      tls_certificate:{t:"x509 cert",bg:"#1f3f79",fg:"#72adff"},
      pkcs12:{t:"pkcs#12",bg:"#423311",fg:"#ffd06d"},
      jwk:{t:"jwk",bg:"#2f3d14",fg:"#b3ff62"},
      kerberos_keytab:{t:"kerberos keytab",bg:"#113c4d",fg:"#5fdfff"},
      oauth_client_secret:{t:"oauth secret",bg:"#412916",fg:"#ffb575"},
      wireguard_private_key:{t:"wireguard key",bg:"#123862",fg:"#5bc3ff"},
      bitlocker_keys:{t:"bitlocker keys",bg:"#3f2a19",fg:"#ffc78a"}
    };
    return map[type]||{t:type||"secret",bg:"#223047",fg:"#93b1df"};
  };

  const defaultFormatForType=(secret:any)=>{
    const type=String(secret?.secret_type||"");
    if(type==="ssh_private_key") return "pem";
    if(type==="pgp_private_key"||type==="pgp_public_key") return "armored";
    if(type==="ppk") return "ppk";
    if(type==="jwk") return "jwk";
    if(type==="pkcs12") return "extract";
    return "raw";
  };

  const downloadNameFor=(secret:any,format:string)=>{
    const base=safeFileName(String(secret?.name||secret?.id||"secret"),"secret");
    const extMap:any={pem:"pem",openssh:"pub",ppk:"ppk",armored:"asc",jwk:"json",extract:"json",raw:"txt"};
    return `${base}.${extMap[String(format||"raw")]||"txt"}`;
  };

  const downloadTextFile=(filename:string,content:string,mime="text/plain;charset=utf-8")=>{
    const blob=new Blob([String(content||"")],{type:mime});
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url;
    a.download=filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const filteredSecrets=useMemo(()=>{
    const q=String(search||"").trim().toLowerCase();
    return secrets.filter((s:any)=>{
      if(!matchesCategory(s)) return false;
      if(!q) return true;
      return [s.name,s.id,s.secret_type,s.description].some((v)=>String(v||"").toLowerCase().includes(q));
    });
  },[secrets,search,matchesCategory]);

  const submitCreate=async()=>{
    if(!session){
      return;
    }
    if(!createName.trim()||!createType.trim()||!createValue){
      onToast?.("Secret name, type, and value are required.");
      return;
    }
    setBusy(true);
    try{
      await createSecret(session,{
        name:createName.trim(),
        secret_type:normalizeType(createType),
        value:createValue,
        labels:{delivery_format:createDeliveryFormat},
        lease_ttl_seconds:ttlToSeconds(createTTLMode,createTTLCustom),
        metadata:{source:"dashboard",lease_based:createLeaseBased}
      });
      onToast?.("Secret stored.");
      setModal(null);
      setCreateName("");
      setCreateValue("");
      setCreateType("api_key");
      setCreateTTLMode("none");
      setCreateTTLCustom("");
      setCreateLeaseBased(false);
      setCreateDeliveryFormat("raw");
      setRefreshTick((n)=>n+1);
    }catch(error){
      onToast?.(`Store secret failed: ${errMsg(error)}`);
    }finally{
      setBusy(false);
    }
  };

  const submitGenerate=async()=>{
    if(!session){
      return;
    }
    if(!generateName.trim()){
      onToast?.("Key name is required.");
      return;
    }
    setBusy(true);
    try{
      const out=await generateKeyPairSecret(session,{
        name:generateName.trim(),
        key_type:generateType,
        labels:{source:"dashboard",key_type:generateType},
        lease_ttl_seconds:0
      });
      setGeneratedPublicKey(String(out.public_key||""));
      onToast?.(`${String(out.key_type||generateType)} key pair generated and private key stored in vault.`);
      setRefreshTick((n)=>n+1);
    }catch(error){
      onToast?.(`Generate key pair failed: ${errMsg(error)}`);
    }finally{
      setBusy(false);
    }
  };

  const openRetrieve=async(secret:any)=>{
    if(!session){
      return;
    }
    setSelectedSecret(secret);
    const format=defaultFormatForType(secret);
    setValueFormat(format);
    setRetrievedValue("");
    setRetrievedType("");
    setModal("retrieve");
    setBusy(true);
    try{
      const out=await getSecretValue(session,secret.id,format);
      setRetrievedValue(String(out.value||""));
      setRetrievedType(String(out.content_type||""));
    }catch(error){
      onToast?.(`Read secret failed: ${errMsg(error)}`);
    }finally{
      setBusy(false);
    }
  };

  const fetchFormat=async()=>{
    if(!session||!selectedSecret){
      return;
    }
    setBusy(true);
    try{
      const out=await getSecretValue(session,selectedSecret.id,valueFormat);
      setRetrievedValue(String(out.value||""));
      setRetrievedType(String(out.content_type||""));
      onToast?.(`Secret fetched in ${valueFormat} format.`);
    }catch(error){
      onToast?.(`Format retrieval failed: ${errMsg(error)}`);
    }finally{
      setBusy(false);
    }
  };

  const downloadSecret=async(secret:any)=>{
    if(!session){
      return;
    }
    setBusy(true);
    try{
      const format=defaultFormatForType(secret);
      const out=await getSecretValue(session,secret.id,format);
      downloadTextFile(downloadNameFor(secret,format),String(out.value||""),String(out.content_type||"text/plain"));
      onToast?.(`Downloaded ${String(secret.name||"secret")}.`);
    }catch(error){
      onToast?.(`Download failed: ${errMsg(error)}`);
    }finally{
      setBusy(false);
    }
  };

  const removeSecret=async(secret:any)=>{
    if(!session){
      return;
    }
    const confirmed=await promptDialog.confirm({
      title:"Delete Secret",
      message:`Delete secret ${String(secret?.name||"")}?`,
      confirmLabel:"Delete",
      danger:true
    });
    if(!confirmed){
      return;
    }
    setBusy(true);
    try{
      await deleteVaultSecret(session,String(secret?.id||""));
      onToast?.("Secret deleted.");
      await loadSecrets(true);
    }catch(error){
      onToast?.(`Delete failed: ${errMsg(error)}`);
    }finally{
      setBusy(false);
    }
  };

  return <div>
    <Section title="Secret Vault" actions={<>
      <Btn small onClick={()=>void handleRefresh()} disabled={refreshing||busy}><span style={{display:"inline-flex",alignItems:"center",gap:6}}><RefreshCcw size={12}/>{refreshing?"Refreshing...":"Refresh"}</span></Btn>
    </>}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:12,marginBottom:14,flexWrap:"wrap"}}>
        <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
          {categories.map((cat)=><button key={cat.id} onClick={()=>setCategory(cat.id)} style={{
            height:40,padding:"0 12px",borderRadius:10,
            border:`1px solid ${category===cat.id?C.accent:C.border}`,
            background:category===cat.id?"linear-gradient(180deg,#1ed3ee,#11b8df)":"transparent",
            color:category===cat.id?"#032432":C.text,fontSize:11,cursor:"pointer",fontWeight:600
          }}>{cat.label}</button>)}
        </div>
        <div style={{display:"flex",gap:10}}>
          <Btn primary onClick={()=>setModal("create")} style={{height:40,padding:"0 20px",borderRadius:11,fontWeight:700}}>+ Store Secret</Btn>
          <Btn onClick={()=>setModal("generate")} style={{height:40,padding:"0 20px",borderRadius:11,fontWeight:600}}>Generate</Btn>
        </div>
      </div>
      <div style={{marginBottom:10}}>
        <Inp placeholder="Search secrets by name, id, type..." value={search} onChange={(e)=>setSearch(e.target.value)} style={{maxWidth:420,height:40}}/>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(300px,1fr))",gap:12}}>
        {filteredSecrets.map((s:any)=>{
          const badge=secretBadge(s);
          return <div key={s.id} style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:16,minHeight:122}}>
            <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",gap:10}}>
              <div style={{fontSize:13,fontWeight:800,color:C.text,lineHeight:1.25}}>{s.name}</div>
              <span style={{background:badge.bg,color:badge.fg,borderRadius:999,padding:"4px 10px",fontSize:11,fontWeight:700,whiteSpace:"nowrap"}}>{badge.t}</span>
            </div>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginTop:10,fontSize:11,color:C.muted}}>
              <span>TTL: {ttlCompact(s)}</span>
              <span style={{fontSize:11,color:"#89a5cf"}}>{`v${Number(s.current_version||1)}`}</span>
            </div>
            <div style={{display:"flex",gap:8,marginTop:12}}>
              <Btn small onClick={()=>void openRetrieve(s)} disabled={busy}>Retrieve</Btn>
              <Btn small onClick={()=>void downloadSecret(s)} disabled={busy}>Download</Btn>
              <Btn small danger onClick={()=>void removeSecret(s)} disabled={busy}>Delete</Btn>
            </div>
          </div>;
        })}
      </div>
      {!filteredSecrets.length?<div style={{marginTop:12,fontSize:11,color:C.muted}}>{loading?"Loading secrets...":"No secrets found for current filter."}</div>:null}
    </Section>

    <Modal open={modal==="create"} onClose={()=>setModal(null)} title="Store New Secret" wide>
      <Row2>
        <FG label="Name" required><Inp placeholder="prod-api-key-stripe" value={createName} onChange={(e)=>setCreateName(e.target.value)}/></FG>
        <FG label="Type" required>
          <Sel value={createType} onChange={(e)=>setCreateType(e.target.value)}>
            {supportedTypes.map((type)=><option key={type} value={type}>{type}</option>)}
          </Sel>
        </FG>
      </Row2>
      <FG label="Secret Value" required hint="Envelope-encrypted at rest. Never stored plaintext.">
        <Txt placeholder="Paste API key, PEM block, JSON..." rows={6} value={createValue} onChange={(e)=>setCreateValue(e.target.value)}/>
      </FG>
      <Row2>
        <FG label="TTL">
          <Sel value={createTTLMode} onChange={(e)=>setCreateTTLMode(e.target.value)}>
            <option value="none">No expiry</option>
            <option value="1h">1 hour</option>
            <option value="24h">24 hours</option>
            <option value="7d">7 days</option>
            <option value="30d">30 days</option>
            <option value="90d">90 days</option>
            <option value="365d">365 days</option>
            <option value="custom">Custom (seconds)</option>
          </Sel>
        </FG>
        <FG label="Delivery Format">
          <Sel value={createDeliveryFormat} onChange={(e)=>setCreateDeliveryFormat(e.target.value)}>
            <option value="raw">As stored (raw)</option>
            <option value="pem">PEM</option>
            <option value="jwk">JWK</option>
            <option value="armored">Armored</option>
            <option value="ppk">PPK</option>
          </Sel>
        </FG>
      </Row2>
      {createTTLMode==="custom"?<FG label="Custom TTL (seconds)">
        <Inp type="number" min="0" value={createTTLCustom} onChange={(e)=>setCreateTTLCustom(e.target.value)}/>
      </FG>:null}
      <Chk label="Lease-based access (must renew TTL)" checked={createLeaseBased} onChange={()=>setCreateLeaseBased((v)=>!v)}/>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}><Btn onClick={()=>setModal(null)} disabled={busy}>Cancel</Btn><Btn primary onClick={()=>void submitCreate()} disabled={busy}>{busy?"Storing...":"Store Secret"}</Btn></div>
    </Modal>

    <Modal open={modal==="generate"} onClose={()=>setModal(null)} title="Generate Key Pair">
      <FG label="Key Type" required>
        <Sel value={generateType} onChange={(e)=>setGenerateType(e.target.value)}>
          {generateTypeOptions.map((item)=><option key={item.value} value={item.value}>{item.label}</option>)}
        </Sel>
      </FG>
      <FG label="Name" required><Inp placeholder="deploy-key-gh" value={generateName} onChange={(e)=>setGenerateName(e.target.value)}/></FG>
      {generatedPublicKey&&<FG label="Generated Public Key"><Txt rows={3} value={generatedPublicKey} readOnly/></FG>}
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}><Btn onClick={()=>setModal(null)} disabled={busy}>Cancel</Btn><Btn primary onClick={()=>void submitGenerate()} disabled={busy}>{busy?"Generating...":"Generate"}</Btn></div>
    </Modal>

    <Modal open={modal==="retrieve"} onClose={()=>setModal(null)} title={`Retrieve Secret${selectedSecret?`: ${selectedSecret.name}`:""}`} wide>
      <Row2>
        <FG label="Output Format">
          <Sel value={valueFormat} onChange={(e)=>setValueFormat(e.target.value)}>
            <option value="raw">raw</option>
            <option value="pem">pem</option>
            <option value="openssh">openssh</option>
            <option value="ppk">ppk</option>
            <option value="extract">extract</option>
            <option value="jwk">jwk</option>
            <option value="armored">armored</option>
          </Sel>
        </FG>
        <FG label="Content Type"><Inp value={retrievedType} readOnly/></FG>
      </Row2>
      <FG label="Value"><Txt rows={10} value={retrievedValue} readOnly/></FG>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}><Btn onClick={()=>setModal(null)} disabled={busy}>Close</Btn><Btn primary onClick={()=>void fetchFormat()} disabled={busy}>{busy?"Fetching...":"Fetch Format"}</Btn></div>
    </Modal>

    {promptDialog.ui}
  </div>;
};
