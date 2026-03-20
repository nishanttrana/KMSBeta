// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import { RefreshCcw, Shield, Lock, VenetianMask, CreditCard, ScrollText, KeyRound, Gauge, Database, FileKey } from "lucide-react";
import {
  B,
  Bar,
  Btn,
  Card,
  Chk,
  FG,
  Inp,
  Row2,
  Row3,
  Section,
  Sel,
  Stat,
  Txt,
  usePromptDialog
} from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  appDecryptFields,
  appEncryptFields,
  appEnvelopeDecrypt,
  appEnvelopeEncrypt,
  appSearchableDecrypt,
  appSearchableEncrypt,
  applyMask,
  completeFieldEncryptionWrapperRegistration,
  createMaskingPolicy,
  createRedactionPolicy,
  createTokenVault,
  deleteTokenVault,
  detokenizeValues,
  downloadFieldEncryptionWrapperSDK,
  downloadTokenVaultExternalSchema,
  fpeDecrypt,
  fpeEncrypt,
  getDataProtectionPolicy,
  getDataProtectStats,
  getDataProtectAuditLog,
  initFieldEncryptionWrapperRegistration,
  issueFieldEncryptionLease,
  listFieldEncryptionLeases,
  listFieldEncryptionWrappers,
  listTokenVaults,
  redactContent,
  revokeFieldEncryptionLease,
  submitFieldEncryptionUsageReceipt,
  tokenizeValues,
  updateDataProtectionPolicy
} from "../../../lib/dataprotect";
import { PKCS11Tab } from "./PKCS11Tab";
import { PaymentPolicyTab } from "./PaymentPolicyTab";

function normalizeKeyState(state: string): string {
  const normalized = String(state || "").trim().toLowerCase();
  if (!normalized) {
    return "active";
  }
  if (["deleted", "destroyed", "purged"].includes(normalized)) {
    return "deleted";
  }
  if (["pending_delete", "pending-destroy", "scheduled_delete", "scheduled-destroy"].includes(normalized)) {
    return "pending_delete";
  }
  if (["disabled", "inactive", "suspended", "revoked"].includes(normalized)) {
    return "disabled";
  }
  if (["compromised"].includes(normalized)) {
    return "compromised";
  }
  return normalized;
}

function keyChoicesFromCatalog(keyCatalog: any[]): any[] {
  if (!Array.isArray(keyCatalog)) {
    return [];
  }
  return keyCatalog.filter((k) => normalizeKeyState(String(k?.state || "")) !== "deleted");
}

function isSupportedSymmetricCipherAlgorithm(algorithm: string): boolean {
  const v = String(algorithm || "").toUpperCase();
  if (!v.includes("AES") && !v.includes("3DES") && !v.includes("TDES") && !v.includes("DES") && !v.includes("CHACHA20") && !v.includes("CAMELLIA")) {
    return false;
  }
  if (v.includes("CHACHA20") || v.includes("CAMELLIA")) {
    return true;
  }
  if (v.includes("AES")) {
    if (v.includes("ECB") || v.includes("CCM") || v.includes("CFB") || v.includes("OFB") || v.includes("XTS")) {
      return false;
    }
    return true;
  }
  if (v.includes("3DES") || v.includes("TDES")) {
    return v.includes("CBC");
  }
  return false;
}

function isPublicComponentLike(key: any): boolean {
  const role = String(key?.componentRole || "").toLowerCase();
  if (role === "public") {
    return true;
  }
  const keyType = String(key?.keyType || "").toLowerCase();
  return keyType.includes("public");
}

function isVaultCapableKeyChoice(key: any): boolean {
  const algo = String(key?.algo || "").toUpperCase();
  const keyType = String(key?.keyType || "").toLowerCase();
  const state = String(key?.state || "").toLowerCase();
  if (state && state !== "active") {
    return false;
  }
  if (isPublicComponentLike(key)) {
    return false;
  }
  if (keyType && keyType !== "symmetric") {
    return false;
  }
  if (algo.includes("HMAC") || algo.includes("CMAC") || algo.includes("GMAC")) {
    return false;
  }
  return isSupportedSymmetricCipherAlgorithm(algo);
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
export const TokenizeTab=({session,keyCatalog,onToast})=>{
  const [op,setOp]=useState("Tokenize");
  const [loading,setLoading]=useState(false);
  const [submitting,setSubmitting]=useState(false);
  const [resultText,setResultText]=useState("// Output will appear here...");
  const keyChoices=useMemo(()=>keyChoicesFromCatalog(keyCatalog),[keyCatalog]);
  const defaultKeyId=String(keyChoices[0]?.id||"");
  const vaultCapableKeys=useMemo(()=>keyChoices.filter((k)=>isVaultCapableKeyChoice(k)),[keyChoices]);
  const defaultVaultKeyId=String(vaultCapableKeys[0]?.id||"");

  const [vaults,setVaults]=useState<any[]>([]);
  const [tokenMode,setTokenMode]=useState<"vault"|"vaultless">("vault");
  const [tokenVaultId,setTokenVaultId]=useState("");
  const [tokenVaultlessFormat,setTokenVaultlessFormat]=useState("deterministic");
  const [tokenVaultlessType,setTokenVaultlessType]=useState("credit_card");
  const [tokenVaultlessKeyId,setTokenVaultlessKeyId]=useState(defaultVaultKeyId);
  const [tokenVaultlessRegex,setTokenVaultlessRegex]=useState("");
  const [tokenVaultlessCustomFormat,setTokenVaultlessCustomFormat]=useState("");
  const [tokenInput,setTokenInput]=useState("4111 1111 1111 1111");
  const [tokenBatch,setTokenBatch]=useState(false);
  const [tokenTTL,setTokenTTL]=useState("0");
  const [detokenizeInput,setDetokenizeInput]=useState("");

  const [fpeKeyId,setFPEKeyId]=useState(defaultVaultKeyId||defaultKeyId);
  const [fpeAlgorithm,setFPEAlgorithm]=useState("FF1");
  const [fpeRadix,setFPERadix]=useState("10");
  const [fpeTweak,setFPETweak]=useState("");
  const [fpeInput,setFPEInput]=useState("");

  const [maskPattern,setMaskPattern]=useState("partial_last4");
  const [maskRole,setMaskRole]=useState("analyst");
  const [maskInput,setMaskInput]=useState("John Smith - SSN: 123-45-6789");
  const [maskConsistent,setMaskConsistent]=useState(true);

  const [redactInput,setRedactInput]=useState("Please contact john@bank.com at +1-555-0123.");
  const [redactAction,setRedactAction]=useState("replace_placeholder");
  const [redactPlaceholder,setRedactPlaceholder]=useState("[REDACTED]");
  const [redactDetectOnly,setRedactDetectOnly]=useState(false);

  const [fieldKeyId,setFieldKeyId]=useState(defaultVaultKeyId||defaultKeyId);
  const [fieldAlgorithm,setFieldAlgorithm]=useState("AES-GCM");
  const [fieldDoc,setFieldDoc]=useState('{"name":"John","ssn":"123-45-6789","card":"4111111111111111"}');
  const [fieldPaths,setFieldPaths]=useState("$.ssn,$.card");
  const [fieldAAD,setFieldAAD]=useState("");
  const [fieldDecrypt,setFieldDecrypt]=useState(false);

  const [envMode,setEnvMode]=useState("encrypt");
  const [envKeyId,setEnvKeyId]=useState(defaultVaultKeyId||defaultKeyId);
  const [envAlgo,setEnvAlgo]=useState("AES-GCM");
  const [envAAD,setEnvAAD]=useState("");
  const [envPlaintext,setEnvPlaintext]=useState("");
  const [envPackage,setEnvPackage]=useState('{"ciphertext":"","iv":"","wrapped_dek":"","wrapped_dek_iv":"","algorithm":"AES-GCM"}');

  const setOutput=(v:any)=>setResultText(JSON.stringify(v,null,2));

  const parseObject=(raw:string,label:string)=>{
    const text=String(raw||"").trim();
    if(!text){
      throw new Error(`${label} is required.`);
    }
    let parsed:any;
    try{
      parsed=JSON.parse(text);
    }catch{
      throw new Error(`${label} must be valid JSON.`);
    }
    if(!parsed||typeof parsed!=="object"||Array.isArray(parsed)){
      throw new Error(`${label} must be a JSON object.`);
    }
    return parsed;
  };

  const parseList=(raw:string)=>{
    return String(raw||"").split(/[,\n]/).map((v)=>String(v||"").trim()).filter(Boolean);
  };

  useEffect(()=>{
    if(!session?.token){
      setVaults([]);
      return;
    }
    let cancelled=false;
    const loadVaults=async()=>{
      setLoading(true);
      try{
        const items=await listTokenVaults(session,{limit:300,offset:0});
        if(!cancelled){
          setVaults(items||[]);
        }
      }catch(error){
        if(!cancelled){
          onToast?.(`Token vault load failed: ${errMsg(error)}`);
        }
      }finally{
        if(!cancelled){
          setLoading(false);
        }
      }
    };
    void loadVaults();
    return()=>{cancelled=true;};
  },[session?.token,session?.tenantId,onToast]);

  useEffect(()=>{
    const fallback=defaultVaultKeyId||defaultKeyId;
    if(!fpeKeyId&&fallback)setFPEKeyId(fallback);
    if(!fieldKeyId&&fallback)setFieldKeyId(fallback);
    if(!envKeyId&&fallback)setEnvKeyId(fallback);
    if(!tokenVaultlessKeyId&&fallback)setTokenVaultlessKeyId(fallback);
  },[defaultKeyId,defaultVaultKeyId,fpeKeyId,fieldKeyId,envKeyId,tokenVaultlessKeyId]);

  const vaultSelectOptions=useMemo(()=>{
    return Array.isArray(vaults)?vaults:[];
  },[vaults]);

  const selectedTokenVault=useMemo(()=>{
    return vaultSelectOptions.find((v:any)=>String(v?.id||"")===String(tokenVaultId||""))||null;
  },[vaultSelectOptions,tokenVaultId]);

  useEffect(()=>{
    if(!vaultSelectOptions.length){
      setTokenVaultId("");
      return;
    }
    if(!vaultSelectOptions.some((v:any)=>String(v?.id||"")===String(tokenVaultId))){
      setTokenVaultId(String(vaultSelectOptions[0]?.id||""));
    }
  },[vaultSelectOptions,tokenVaultId]);

  const run=async(fn:()=>Promise<void>)=>{
    if(submitting){
      return;
    }
    if(!session?.token){
      onToast?.("Login is required.");
      return;
    }
    setSubmitting(true);
    try{
      await fn();
    }catch(error){
      const message=errMsg(error);
      setOutput({error:message,operation:op});
      onToast?.(message);
    }finally{
      setSubmitting(false);
    }
  };

  const submitCurrent=async()=>{
    await run(async()=>{
      if(op==="Tokenize"){
        const values=tokenBatch?String(tokenInput||"").split("\n").map((v)=>String(v||"").trim()).filter(Boolean):[String(tokenInput||"").trim()];
        if(!values.length||!values[0]){
          throw new Error("Input value is required.");
        }
        if(tokenMode==="vault"){
          if(!String(tokenVaultId||"").trim()){
            throw new Error("Token vault is required.");
          }
        }else{
          if(!String(tokenVaultlessKeyId||"").trim()){
            throw new Error("A symmetric encryption key is required for vaultless tokenization.");
          }
          if(String(tokenVaultlessType||"").trim()==="custom"&&!String(tokenVaultlessRegex||"").trim()){
            throw new Error("Custom regex is required when token type is custom.");
          }
          if(String(tokenVaultlessFormat||"").trim()==="custom"&&!String(tokenVaultlessCustomFormat||"").trim()){
            throw new Error("Custom token format name is required when vaultless format is custom.");
          }
        }
        const items=await tokenizeValues(session,{
          mode:tokenMode,
          vault_id:tokenMode==="vault"?tokenVaultId:"",
          key_id:tokenMode==="vaultless"?tokenVaultlessKeyId:"",
          token_type:tokenMode==="vaultless"?tokenVaultlessType:undefined,
          format:tokenMode==="vaultless"?tokenVaultlessFormat:undefined,
          custom_token_format:tokenMode==="vaultless"?String(tokenVaultlessCustomFormat||"").trim()||undefined:undefined,
          custom_regex:tokenMode==="vaultless"?tokenVaultlessRegex:undefined,
          values,
          ttl_hours:Math.max(0,Math.trunc(Number(tokenTTL||0)))
        });
        setOutput({operation:"tokenize",items});
        return;
      }
      if(op==="Detokenize"){
        const tokens=String(detokenizeInput||"").split("\n").map((v)=>String(v||"").trim()).filter(Boolean);
        if(!tokens.length){
          throw new Error("Token input is required.");
        }
        const items=await detokenizeValues(session,{tokens});
        setOutput({operation:"detokenize",items});
        return;
      }
      if(op==="FPE Encrypt"||op==="FPE Decrypt"){
        if(!String(fpeKeyId||"").trim()){
          throw new Error("Key is required.");
        }
        if(!String(fpeInput||"").trim()){
          throw new Error(op==="FPE Encrypt"?"Plaintext is required.":"Ciphertext is required.");
        }
        const payload={key_id:fpeKeyId,algorithm:fpeAlgorithm,radix:Math.max(2,Math.min(36,Math.trunc(Number(fpeRadix||10)))),tweak:String(fpeTweak||"").trim()};
        const result=op==="FPE Encrypt"
          ? await fpeEncrypt(session,{...payload,plaintext:String(fpeInput||"").trim()})
          : await fpeDecrypt(session,{...payload,ciphertext:String(fpeInput||"").trim()});
        setOutput({operation:op,result});
        return;
      }
      if(op==="Mask"){
        if(!String(maskInput||"").trim()){
          throw new Error("Input is required.");
        }
        const policy=await createMaskingPolicy(session,{
          name:`ui-mask-${Date.now()}`,
          target_type:"json",
          field_path:"$.value",
          mask_pattern:maskPattern,
          roles_full:[],
          roles_partial:[],
          roles_redacted:[],
          consistent:maskConsistent
        });
        const masked=await applyMask(session,{policy_id:String(policy.id||""),role:maskRole,data:{value:String(maskInput||"")}},{preview:true});
        setOutput({operation:"mask",pattern:maskPattern,input:maskInput,output:masked?.value||"",policy_id:policy.id});
        return;
      }
      if(op==="Redact"){
        if(!String(redactInput||"").trim()){
          throw new Error("Input document is required.");
        }
        const policy=await createRedactionPolicy(session,{
          name:`ui-redact-${Date.now()}`,
          action:redactAction as any,
          placeholder:redactPlaceholder,
          scope:"all",
          applies_to:["*"],
          patterns:[
            {type:"regex",label:"EMAIL",pattern:"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"},
            {type:"regex",label:"PHONE",pattern:"(?:\\+?\\d{1,3}[\\s.-]?)?(?:\\(?\\d{3}\\)?[\\s.-]?\\d{3}[\\s.-]?\\d{4})"},
            {type:"regex",label:"SSN",pattern:"\\b\\d{3}-\\d{2}-\\d{4}\\b"},
            {type:"regex",label:"PAN",pattern:"\\b(?:\\d[ -]*?){13,19}\\b"}
          ]
        });
        const result=await redactContent(session,{policy_id:String(policy.id||""),content:redactInput,content_type:"text/plain"},{detectOnly:redactDetectOnly});
        setOutput({operation:redactDetectOnly?"redact_detect":"redact_apply",policy_id:policy.id,result});
        return;
      }
      if(op==="Field Encrypt"){
        if(!String(fieldKeyId||"").trim()&&!fieldDecrypt){
          throw new Error("KEK is required.");
        }
        const doc=parseObject(fieldDoc,"JSON document");
        const fields=parseList(fieldPaths);
        if(!fields.length){
          throw new Error("Field list is required.");
        }
        const payload={document:doc,fields,key_id:String(fieldKeyId||""),algorithm:fieldAlgorithm,aad:fieldAAD};
        const result=fieldDecrypt?await appDecryptFields(session,payload):await appEncryptFields(session,payload);
        setOutput({operation:fieldDecrypt?"field_decrypt":"field_encrypt",result});
        return;
      }
      if(op==="Envelope Encrypt"){
        if(!String(envKeyId||"").trim()){
          throw new Error("KEK is required.");
        }
        const result=envMode==="encrypt"
          ? await appEnvelopeEncrypt(session,{key_id:envKeyId,algorithm:envAlgo,plaintext:envPlaintext,aad:envAAD})
          : await appEnvelopeDecrypt(session,{key_id:envKeyId,algorithm:envAlgo,aad:envAAD,...parseObject(envPackage,"Envelope package")});
        setOutput({operation:envMode==="encrypt"?"envelope_encrypt":"envelope_decrypt",result});
      }
    });
  };

  const tabs=["Tokenize","Detokenize","FPE Encrypt","FPE Decrypt","Mask","Redact","Field Encrypt","Envelope Encrypt"];
  const panelTitle=
    op==="Mask"?"Data Masking":
    op==="Redact"?"PII Redaction":
    op==="Field Encrypt"?"Field Encryption":
    op==="Envelope Encrypt"?"Envelope Encryption":
    op==="FPE Encrypt"||op==="FPE Decrypt"?"Format Preserving Encryption":
    op==="Detokenize"?"Detokenization":"Tokenization";

  return <div style={{display:"grid",gap:12}}>
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:12,flexWrap:"wrap"}}>
      <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
        {tabs.map((name)=>(
          <button
            key={name}
            onClick={()=>setOp(name)}
            style={{
              background:op===name?C.accent:"transparent",
              color:op===name?C.bg:C.text,
              border:`1px solid ${op===name?C.accent:C.border}`,
              borderRadius:8,
              padding:"8px 14px",
              fontSize:12,
              fontWeight:600,
              cursor:"pointer"
            }}
          >
            {name}
          </button>
        ))}
      </div>
      <div style={{display:"flex",gap:8}}>
        <Btn small onClick={async()=>{if(!session?.token)return;setLoading(true);try{setVaults(await listTokenVaults(session,{limit:300,offset:0}));}catch(error){onToast?.(`Refresh failed: ${errMsg(error)}`);}finally{setLoading(false);}}} disabled={loading||submitting}><RefreshCcw size={12} strokeWidth={2}/> Refresh</Btn>
      </div>
    </div>
    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,alignItems:"start"}}>
      <Card style={{padding:18}}>
        <div style={{fontSize:30,fontWeight:700,color:C.text,marginBottom:8,fontFamily:"'Rajdhani','IBM Plex Sans',sans-serif",lineHeight:1}}>{panelTitle}</div>
        <div style={{fontSize:11,color:C.muted,marginBottom:12}}>All operations execute against the <span style={{color:C.accent}}>dataprotect</span> backend with real cryptography.</div>
        {op==="Tokenize"&&<>
          <FG label="Tokenization Mode" required>
            <Sel value={tokenMode} onChange={(e)=>setTokenMode((e.target.value==="vaultless"?"vaultless":"vault") as "vault"|"vaultless")}>
              <option value="vault">Vault (reversible)</option>
              <option value="vaultless">Vaultless (non-reversible)</option>
            </Sel>
          </FG>
          {tokenMode==="vault"?<>
            <FG label="Token Vault" required>
              <Sel value={tokenVaultId} onChange={(e)=>setTokenVaultId(e.target.value)}>
                <option value="">{vaultSelectOptions.length?"Select vault":"No token vault found. Create vault from Token / Mask / Redact Policy."}</option>
                {vaultSelectOptions.map((v:any)=>{
                  const storage=String(v?.storage_type||"internal").toLowerCase()==="external"
                    ? `external:${String(v?.external_provider||"db")}`
                    : "internal";
                  return <option key={String(v?.id||"")} value={String(v?.id||"")}>
                    {`${String(v?.name||"")} (${String(v?.token_type||"")}/${String(v?.format||"")}) [${storage}]`}
                  </option>;
                })}
              </Sel>
            </FG>
            <div style={{fontSize:10,color:C.dim,marginBottom:8}}>
              {selectedTokenVault
                ? `Selected vault storage: ${String(selectedTokenVault?.storage_type||"internal")}${String(selectedTokenVault?.external_provider||"").trim()?` (${String(selectedTokenVault?.external_provider||"")})`:""}.`
                : "Vault list includes internal and external vault connections created from policy."}
            </div>
          </>:<>
            <FG label="Vaultless Format" required>
              <Sel value={tokenVaultlessFormat} onChange={(e)=>setTokenVaultlessFormat(e.target.value)}>
                <option value="format_preserving">Format Preserving</option>
                <option value="deterministic">Deterministic</option>
                <option value="irreversible">Irreversible</option>
                <option value="custom">Custom</option>
              </Sel>
            </FG>
            {tokenVaultlessFormat==="custom"&&<FG label="Custom Format Name" required><Inp value={tokenVaultlessCustomFormat} onChange={(e)=>setTokenVaultlessCustomFormat(e.target.value)} placeholder="pan_enterprise"/></FG>}
            <FG label="Encryption Key" required hint="Only active symmetric cipher keys are allowed.">
              <Sel value={tokenVaultlessKeyId} onChange={(e)=>setTokenVaultlessKeyId(e.target.value)}>
                {renderKeyOptions(vaultCapableKeys)}
              </Sel>
            </FG>
            <FG label="Token Type" required>
              <Sel value={tokenVaultlessType} onChange={(e)=>setTokenVaultlessType(e.target.value)}>
                <option value="credit_card">credit_card (PAN with Luhn validation)</option>
                <option value="ssn">ssn</option>
                <option value="email">email</option>
                <option value="phone">phone</option>
                <option value="iban">iban</option>
                <option value="custom">custom</option>
              </Sel>
            </FG>
            {tokenVaultlessType==="custom"&&<FG label="Custom Regex" required><Inp value={tokenVaultlessRegex} onChange={(e)=>setTokenVaultlessRegex(e.target.value)} placeholder="^\\d{3}-\\d{2}-\\d{4}$" mono/></FG>}
            <div style={{fontSize:10,color:C.dim,marginBottom:8}}>Vaultless mode does not store original data, so detokenization is intentionally unavailable.</div>
          </>}
          <FG label="Input Value" required><Txt value={tokenInput} onChange={(e)=>setTokenInput(e.target.value)} rows={3}/></FG>
          <Chk label="Batch mode (multiple values, one per line)" checked={tokenBatch} onChange={()=>setTokenBatch((v)=>!v)}/>
          {tokenMode==="vault"
            ?<FG label="TTL"><Sel value={tokenTTL} onChange={(e)=>setTokenTTL(e.target.value)}><option value="0">No expiry</option><option value="24">24 hours</option><option value="720">30 days</option><option value="2160">90 days</option></Sel></FG>
            :<div style={{fontSize:10,color:C.dim,marginTop:6}}>TTL applies only to vault mode. Vaultless output is immediate and non-stored.</div>}
        </>}
        {op==="Detokenize"&&<><FG label="Tokens" required hint="One token per line"><Txt value={detokenizeInput} onChange={(e)=>setDetokenizeInput(e.target.value)} rows={8} placeholder="tok_..."/></FG></>}
        {(op==="FPE Encrypt"||op==="FPE Decrypt")&&<><FG label="FPE Algorithm"><Sel value={fpeAlgorithm} onChange={(e)=>setFPEAlgorithm(e.target.value)}><option value="FF1">FF1</option><option value="FF3-1">FF3-1</option></Sel></FG>
          <FG label="Key" required><Sel value={fpeKeyId} onChange={(e)=>setFPEKeyId(e.target.value)}>{renderKeyOptions(vaultCapableKeys)}</Sel></FG>
          <Row2><FG label="Radix"><Inp value={fpeRadix} onChange={(e)=>setFPERadix(e.target.value)} mono/></FG><FG label="Tweak"><Inp value={fpeTweak} onChange={(e)=>setFPETweak(e.target.value)} mono/></FG></Row2>
          <FG label={op==="FPE Encrypt"?"Plaintext":"Ciphertext"} required><Inp value={fpeInput} onChange={(e)=>setFPEInput(e.target.value)} mono/></FG></>}
        {op==="Mask"&&<><FG label="Masking Pattern" required><Sel value={maskPattern} onChange={(e)=>setMaskPattern(e.target.value)}><option value="partial_last4">Partial - show last 4</option><option value="full">Full mask</option><option value="hash">Hash</option><option value="substitute">Substitute</option><option value="nullify">Nullify</option><option value="date_shift">Date shift</option><option value="shuffle">Shuffle</option></Sel></FG>
          <FG label="Apply To Role"><Sel value={maskRole} onChange={(e)=>setMaskRole(e.target.value)}><option value="analyst">Analyst</option><option value="admin">Admin</option><option value="auditor">Auditor</option><option value="developer">Developer</option></Sel></FG>
          <FG label="Input"><Txt value={maskInput} onChange={(e)=>setMaskInput(e.target.value)} rows={4}/></FG>
          <Chk label="Consistent masking (same input -> same masked output)" checked={maskConsistent} onChange={()=>setMaskConsistent((v)=>!v)}/></>}
        {op==="Redact"&&<><FG label="Redaction Action"><Sel value={redactAction} onChange={(e)=>setRedactAction(e.target.value)}><option value="replace_placeholder">Replace with [REDACTED]</option><option value="remove">Remove entirely</option><option value="hash">Hash value</option></Sel></FG>
          <FG label="Placeholder"><Inp value={redactPlaceholder} onChange={(e)=>setRedactPlaceholder(e.target.value)}/></FG>
          <FG label="Input Document" required><Txt value={redactInput} onChange={(e)=>setRedactInput(e.target.value)} rows={6}/></FG>
          <Chk label="Detect only (no redaction apply)" checked={redactDetectOnly} onChange={()=>setRedactDetectOnly((v)=>!v)}/></>}
        {op==="Field Encrypt"&&<><FG label="Encryption Algorithm"><Sel value={fieldAlgorithm} onChange={(e)=>setFieldAlgorithm(e.target.value)}><option value="AES-GCM">AES-GCM</option><option value="AES-SIV">AES-SIV</option><option value="CHACHA20-POLY1305">ChaCha20-Poly1305</option></Sel></FG>
          <FG label="KEK (Key Encryption Key)" required><Sel value={fieldKeyId} onChange={(e)=>setFieldKeyId(e.target.value)}>{renderKeyOptions(vaultCapableKeys)}</Sel></FG>
          <FG label="JSON Document" required><Txt value={fieldDoc} onChange={(e)=>setFieldDoc(e.target.value)} rows={6}/></FG>
          <FG label="Fields to Encrypt" hint="JSONPath expressions"><Inp value={fieldPaths} onChange={(e)=>setFieldPaths(e.target.value)} mono/></FG>
          <FG label="AAD"><Inp value={fieldAAD} onChange={(e)=>setFieldAAD(e.target.value)} /></FG>
          <Chk label="Decrypt fields instead of encrypt" checked={fieldDecrypt} onChange={()=>setFieldDecrypt((v)=>!v)}/></>}
        {op==="Envelope Encrypt"&&<><FG label="KEK" required><Sel value={envKeyId} onChange={(e)=>setEnvKeyId(e.target.value)}>{renderKeyOptions(vaultCapableKeys)}</Sel></FG>
          <FG label="Mode"><Sel value={envMode} onChange={(e)=>setEnvMode(e.target.value)}><option value="encrypt">Encrypt</option><option value="decrypt">Decrypt</option></Sel></FG>
          <FG label="DEK Algorithm"><Sel value={envAlgo} onChange={(e)=>setEnvAlgo(e.target.value)}><option value="AES-GCM">AES-GCM</option><option value="AES-SIV">AES-SIV</option><option value="CHACHA20-POLY1305">ChaCha20-Poly1305</option></Sel></FG>
          {envMode==="encrypt"?<FG label="Plaintext" required><Txt value={envPlaintext} onChange={(e)=>setEnvPlaintext(e.target.value)} rows={5}/></FG>:<FG label="Envelope Package JSON" required><Txt value={envPackage} onChange={(e)=>setEnvPackage(e.target.value)} rows={5}/></FG>}
          <FG label="AAD"><Inp value={envAAD} onChange={(e)=>setEnvAAD(e.target.value)} /></FG></>}
        <Btn primary full style={{marginTop:12,padding:"10px 14px",fontSize:12}} onClick={()=>void submitCurrent()} disabled={submitting||loading}>{submitting?"Working...":op}</Btn>
      </Card>
      <Card style={{padding:18}}>
        <div style={{fontSize:30,fontWeight:700,color:C.text,marginBottom:8,fontFamily:"'Rajdhani','IBM Plex Sans',sans-serif",lineHeight:1}}>Result</div>
        <Txt value={resultText} rows={24} readOnly style={{minHeight:420}}/>
      </Card>
    </div>

    <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
      <Card style={{padding:16}}>
        <div style={{fontSize:22,fontWeight:700,color:C.text,marginBottom:6,fontFamily:"'Rajdhani','IBM Plex Sans',sans-serif"}}>Data Masking</div>
        <div style={{fontSize:11,color:C.dim,marginBottom:8}}>Pattern: <span style={{color:C.accent}}>{maskPattern}</span> - Role: <span style={{color:C.accent}}>{maskRole}</span></div>
        <div style={{fontSize:12,color:C.text,background:C.surface,border:`1px solid ${C.border}`,borderRadius:8,padding:10,marginBottom:10}}>
          <div style={{color:C.dim,marginBottom:4}}>Input:</div>
          <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:11,wordBreak:"break-word"}}>{maskInput||"-"}</div>
        </div>
        <Btn small onClick={()=>setOp("Mask")}>Open Mask Operation</Btn>
      </Card>
      <Card style={{padding:16}}>
        <div style={{fontSize:22,fontWeight:700,color:C.text,marginBottom:6,fontFamily:"'Rajdhani','IBM Plex Sans',sans-serif"}}>PII Redaction</div>
        <div style={{fontSize:11,color:C.dim,marginBottom:8}}>Action: <span style={{color:C.accent}}>{redactAction}</span> {redactDetectOnly?"(detect-only)":"(apply)"}</div>
        <div style={{fontSize:12,color:C.text,background:C.surface,border:`1px solid ${C.border}`,borderRadius:8,padding:10,marginBottom:10,maxHeight:90,overflow:"hidden"}}>
          <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:11,wordBreak:"break-word"}}>{redactInput||"-"}</div>
        </div>
        <Btn small onClick={()=>setOp("Redact")}>Open Redact Operation</Btn>
      </Card>
    </div>
  </div>;
};

export const DataEncryptionTab=({session,keyCatalog,onToast})=>{
  const [mode,setMode]=useState("Field-Level (FLE)");
  const [submitting,setSubmitting]=useState(false);
  const [resultText,setResultText]=useState(`{
  "name": "John",
  "ssn": "ENC[AES-SIV:...]",
  "card": "ENC[AES-GCM:...]"
}`);
  const keyChoices=useMemo(()=>keyChoicesFromCatalog(keyCatalog),[keyCatalog]);
  const dataProtectKeyChoices=useMemo(()=>keyChoices.filter((k)=>isVaultCapableKeyChoice(k)),[keyChoices]);
  const defaultKeyId=String(dataProtectKeyChoices[0]?.id||"");
  const [keyId,setKeyId]=useState(defaultKeyId);
  const [algorithm,setAlgorithm]=useState("AES-GCM");
  const [aad,setAAD]=useState("");
  const [encMode,setEncMode]=useState("encrypt");

  const [docText,setDocText]=useState('{"name":"John","ssn":"123-45-6789","card":"4111111111111111"}');
  const [fieldsText,setFieldsText]=useState("$.ssn,$.card");
  const [docID,setDocID]=useState("");

  const [plainText,setPlainText]=useState("");
  const [envelopeText,setEnvelopeText]=useState('{"ciphertext":"","iv":"","wrapped_dek":"","wrapped_dek_iv":"","algorithm":"AES-GCM"}');
  const [searchablePlaintext,setSearchablePlaintext]=useState("");
  const [searchableCiphertext,setSearchableCiphertext]=useState("");

  const [fpeAlgorithm,setFPEAlgorithm]=useState("FF1");
  const [fpeRadix,setFPERadix]=useState("10");
  const [fpeTweak,setFPETweak]=useState("");
  const [fpeInput,setFPEInput]=useState("");
  const [fpeMode,setFPEMode]=useState("encrypt");

  const parseObject=(raw:string,label:string)=>{
    const text=String(raw||"").trim();
    if(!text){
      throw new Error(`${label} is required.`);
    }
    let parsed:any;
    try{
      parsed=JSON.parse(text);
    }catch{
      throw new Error(`${label} must be valid JSON.`);
    }
    if(!parsed||typeof parsed!=="object"||Array.isArray(parsed)){
      throw new Error(`${label} must be a JSON object.`);
    }
    return parsed;
  };

  const parseList=(raw:string)=>{
    return String(raw||"").split(/[,\n]/).map((v)=>String(v||"").trim()).filter(Boolean);
  };

  useEffect(()=>{
    if(!keyId&&defaultKeyId){
      setKeyId(defaultKeyId);
    }
  },[keyId,defaultKeyId]);

  const run=async(fn:()=>Promise<any>)=>{
    if(submitting){
      return;
    }
    if(!session?.token){
      onToast?.("Login is required.");
      return;
    }
    setSubmitting(true);
    try{
      const result=await fn();
      setResultText(JSON.stringify(result,null,2));
    }catch(error){
      const message=errMsg(error);
      setResultText(JSON.stringify({error:message,mode},null,2));
      onToast?.(message);
    }finally{
      setSubmitting(false);
    }
  };

  const submit=async()=>{
    if(mode==="Field-Level (FLE)"){
      await run(async()=>{
        const document=parseObject(docText,"Document");
        const fields=parseList(fieldsText);
        if(!fields.length){
          throw new Error("Field list is required.");
        }
        if(encMode==="encrypt"){
          return appEncryptFields(session,{
            document_id:String(docID||"").trim()||undefined,
            document,
            fields,
            key_id:keyId,
            algorithm,
            aad
          });
        }
        return appDecryptFields(session,{
          document_id:String(docID||"").trim()||undefined,
          document,
          fields,
          key_id:keyId,
          algorithm,
          aad
        });
      });
      return;
    }
    if(mode==="Envelope"){
      await run(async()=>{
        if(encMode==="encrypt"){
          if(!String(plainText||"")){
            throw new Error("Plaintext is required.");
          }
          return appEnvelopeEncrypt(session,{
            key_id:keyId,
            algorithm,
            plaintext:plainText,
            aad
          });
        }
        const payload=parseObject(envelopeText,"Envelope payload");
        return appEnvelopeDecrypt(session,{
          key_id:keyId,
          algorithm:String(payload.algorithm||algorithm),
          ciphertext:String(payload.ciphertext||""),
          iv:String(payload.iv||""),
          wrapped_dek:String(payload.wrapped_dek||""),
          wrapped_dek_iv:String(payload.wrapped_dek_iv||""),
          aad
        });
      });
      return;
    }
    if(mode==="Searchable (AES-SIV)"){
      await run(async()=>{
        if(encMode==="encrypt"){
          if(!String(searchablePlaintext||"").trim()){
            throw new Error("Plaintext is required.");
          }
          return appSearchableEncrypt(session,{key_id:keyId,plaintext:searchablePlaintext,aad});
        }
        if(!String(searchableCiphertext||"").trim()){
          throw new Error("Ciphertext is required.");
        }
        return appSearchableDecrypt(session,{key_id:keyId,ciphertext:searchableCiphertext,aad});
      });
      return;
    }
    await run(async()=>{
      if(fpeMode==="encrypt"){
        if(!String(fpeInput||"").trim()){
          throw new Error("Plaintext is required.");
        }
        return fpeEncrypt(session,{key_id:keyId,algorithm:fpeAlgorithm,radix:Math.max(2,Math.min(36,Math.trunc(Number(fpeRadix||10)))),tweak:fpeTweak,plaintext:fpeInput});
      }
      if(!String(fpeInput||"").trim()){
        throw new Error("Ciphertext is required.");
      }
      return fpeDecrypt(session,{key_id:keyId,algorithm:fpeAlgorithm,radix:Math.max(2,Math.min(36,Math.trunc(Number(fpeRadix||10)))),tweak:fpeTweak,ciphertext:fpeInput});
    });
  };

  const tabs=["Field-Level (FLE)","Envelope","Searchable (AES-SIV)","FPE (FF1/FF3-1)"];
  return <div style={{display:"grid",gap:12}}>
    <Card style={{padding:16}}>
      <div style={{fontSize:28,fontWeight:700,color:C.text,marginBottom:10,fontFamily:"'Rajdhani','IBM Plex Sans',sans-serif",lineHeight:1}}>Data Encryption</div>
      <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:10}}>
        {tabs.map((name)=>(
          <button
            key={name}
            onClick={()=>setMode(name)}
            style={{
              background:mode===name?C.accentDim:"transparent",
              color:mode===name?C.accent:C.text,
              border:`1px solid ${mode===name?C.accent:C.border}`,
              borderRadius:8,
              padding:"8px 12px",
              fontSize:12,
              fontWeight:600,
              cursor:"pointer"
            }}
          >
            {name}
          </button>
        ))}
      </div>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
        <div>
          <FG label="Key" required hint="Only active symmetric cipher keys are allowed for data encryption"><Sel value={keyId} onChange={(e)=>setKeyId(e.target.value)}>{renderKeyOptions(dataProtectKeyChoices)}</Sel></FG>
          <Row2>
            <FG label="Mode"><Sel value={encMode} onChange={(e)=>setEncMode(e.target.value)}><option value="encrypt">Encrypt</option><option value="decrypt">Decrypt</option></Sel></FG>
            {(mode==="Field-Level (FLE)"||mode==="Envelope")
              ?<FG label="Algorithm"><Sel value={algorithm} onChange={(e)=>setAlgorithm(e.target.value)}><option value="AES-GCM">AES-GCM</option><option value="AES-SIV">AES-SIV</option><option value="CHACHA20-POLY1305">ChaCha20-Poly1305</option></Sel></FG>
              :<FG label="Algorithm"><Inp value={mode==="Searchable (AES-SIV)"?"AES-SIV (fixed for searchable deterministic encryption)":"Not applicable in FPE mode"} readOnly/></FG>}
          </Row2>
          {mode==="Field-Level (FLE)"&&<>
            <FG label="Document ID"><Inp value={docID} onChange={(e)=>setDocID(e.target.value)} placeholder="Optional"/></FG>
            <FG label="Fields"><Inp value={fieldsText} onChange={(e)=>setFieldsText(e.target.value)} mono/></FG>
            <FG label="Document JSON"><Txt value={docText} onChange={(e)=>setDocText(e.target.value)} rows={8}/></FG>
          </>}
          {mode==="Envelope"&&<>
            {encMode==="encrypt"?<FG label="Plaintext"><Txt value={plainText} onChange={(e)=>setPlainText(e.target.value)} rows={6}/></FG>:<FG label="Envelope payload JSON"><Txt value={envelopeText} onChange={(e)=>setEnvelopeText(e.target.value)} rows={6}/></FG>}
          </>}
          {mode==="Searchable (AES-SIV)"&&<>
            {encMode==="encrypt"?<FG label="Plaintext"><Txt value={searchablePlaintext} onChange={(e)=>setSearchablePlaintext(e.target.value)} rows={6}/></FG>:<FG label="Ciphertext (base64)"><Txt value={searchableCiphertext} onChange={(e)=>setSearchableCiphertext(e.target.value)} rows={6}/></FG>}
          </>}
          {mode==="FPE (FF1/FF3-1)"&&<>
            <Row2>
              <FG label="FPE algorithm"><Sel value={fpeAlgorithm} onChange={(e)=>setFPEAlgorithm(e.target.value)}><option value="FF1">FF1</option><option value="FF3-1">FF3-1</option></Sel></FG>
              <FG label="Direction"><Sel value={fpeMode} onChange={(e)=>setFPEMode(e.target.value)}><option value="encrypt">Encrypt</option><option value="decrypt">Decrypt</option></Sel></FG>
            </Row2>
            <Row2><FG label="Radix"><Inp value={fpeRadix} onChange={(e)=>setFPERadix(e.target.value)} mono/></FG><FG label="Tweak"><Inp value={fpeTweak} onChange={(e)=>setFPETweak(e.target.value)} mono/></FG></Row2>
            <FG label={fpeMode==="encrypt"?"Plaintext":"Ciphertext"}><Inp value={fpeInput} onChange={(e)=>setFPEInput(e.target.value)} mono/></FG>
          </>}
          {mode!=="FPE (FF1/FF3-1)"&&<FG label="AAD" hint={mode==="Searchable (AES-SIV)"?"Same plaintext+AAD+key returns same ciphertext by design.":"Optional authenticated context"}><Inp value={aad} onChange={(e)=>setAAD(e.target.value)} placeholder="Optional"/></FG>}
          <Btn primary onClick={()=>void submit()} disabled={submitting} style={{marginTop:6,padding:"8px 14px",fontSize:12}}>
            {submitting?"Working...":"Execute"}
          </Btn>
        </div>
        <div>
          <div style={{fontSize:12,fontWeight:700,color:C.dim,textTransform:"uppercase",letterSpacing:1,marginBottom:6}}>Output</div>
          <Txt value={resultText} rows={22} readOnly style={{minHeight:430}}/>
        </div>
      </div>
    </Card>
  </div>;
};

const FieldEncryptionRuntime=({session,keyCatalog,onToast})=>{
  const [loading,setLoading]=useState(false);
  const [busy,setBusy]=useState(false);
  const [wrappers,setWrappers]=useState<any[]>([]);
  const [leases,setLeases]=useState<any[]>([]);
  const [resultText,setResultText]=useState("// Field Encryption runtime output will appear here...");
  const promptDialog=usePromptDialog();
  const keyChoices=useMemo(()=>keyChoicesFromCatalog(keyCatalog),[keyCatalog]);
  const [sdkTargetOS,setSDKTargetOS]=useState("linux");

  const [initWrapperID,setInitWrapperID]=useState("");
  const [initAppID,setInitAppID]=useState("");
  const [initDisplayName,setInitDisplayName]=useState("");
  const [initSigningPub,setInitSigningPub]=useState("");
  const [initEncryptionPub,setInitEncryptionPub]=useState("");
  const [initTransport,setInitTransport]=useState("mtls+jwt");
  const [initMetadataJSON,setInitMetadataJSON]=useState("{}");

  const [completeChallengeID,setCompleteChallengeID]=useState("");
  const [completeWrapperID,setCompleteWrapperID]=useState("");
  const [completeSignature,setCompleteSignature]=useState("");
  const [completeCSR,setCompleteCSR]=useState("");
  const [completeFingerprint,setCompleteFingerprint]=useState("");
  const [completeApproved,setCompleteApproved]=useState(true);
  const [completeApprovedBy,setCompleteApprovedBy]=useState("");
  const [completeAttestationEvidenceB64,setCompleteAttestationEvidenceB64]=useState("");
  const [completeAttestationSignatureB64,setCompleteAttestationSignatureB64]=useState("");
  const [completeAttestationPublicKeyPEM,setCompleteAttestationPublicKeyPEM]=useState("");
  const [wrapperRuntimeToken,setWrapperRuntimeToken]=useState("");
  const [wrapperClientCertFP,setWrapperClientCertFP]=useState("");

  const [leaseWrapperID,setLeaseWrapperID]=useState("");
  const [leaseKeyID,setLeaseKeyID]=useState("");
  const [leaseOperation,setLeaseOperation]=useState("encrypt");
  const [leaseNonce,setLeaseNonce]=useState("");
  const [leaseTimestamp,setLeaseTimestamp]=useState("");
  const [leaseSignature,setLeaseSignature]=useState("");
  const [leaseTTL,setLeaseTTL]=useState("300");
  const [leaseMaxOps,setLeaseMaxOps]=useState("1000");

  const [receiptLeaseID,setReceiptLeaseID]=useState("");
  const [receiptWrapperID,setReceiptWrapperID]=useState("");
  const [receiptKeyID,setReceiptKeyID]=useState("");
  const [receiptOperation,setReceiptOperation]=useState("encrypt");
  const [receiptCount,setReceiptCount]=useState("1");
  const [receiptNonce,setReceiptNonce]=useState("");
  const [receiptTimestamp,setReceiptTimestamp]=useState("");
  const [receiptSignature,setReceiptSignature]=useState("");
  const [receiptClientStatus,setReceiptClientStatus]=useState("ok");

  const parseMapJSON=(raw:string,label:string)=>{
    const text=String(raw||"").trim();
    if(!text){
      return {};
    }
    let parsed:any={};
    try{
      parsed=JSON.parse(text);
    }catch{
      throw new Error(`${label} must be valid JSON object.`);
    }
    if(!parsed||typeof parsed!=="object"||Array.isArray(parsed)){
      throw new Error(`${label} must be valid JSON object.`);
    }
    return parsed;
  };

  const makeNonce=()=>{
    try{
      const bytes=new Uint8Array(24);
      if(typeof window!=="undefined"&&window.crypto&&window.crypto.getRandomValues){
        window.crypto.getRandomValues(bytes);
      }else{
        for(let i=0;i<bytes.length;i+=1){
          bytes[i]=Math.floor(Math.random()*256);
        }
      }
      return btoa(String.fromCharCode(...Array.from(bytes))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
    }catch{
      return `nonce-${Date.now()}`;
    }
  };

  const refresh=async(silent=false)=>{
    if(!session?.token){
      setWrappers([]);
      setLeases([]);
      return;
    }
    if(!silent){
      setLoading(true);
    }
    try{
      const [wrapperItems,leaseItems]=await Promise.all([
        listFieldEncryptionWrappers(session,{limit:500,offset:0}),
        listFieldEncryptionLeases(session,{limit:500,offset:0})
      ]);
      setWrappers(Array.isArray(wrapperItems)?wrapperItems:[]);
      setLeases(Array.isArray(leaseItems)?leaseItems:[]);
      if(!leaseWrapperID&&Array.isArray(wrapperItems)&&wrapperItems.length){
        setLeaseWrapperID(String(wrapperItems[0]?.wrapper_id||""));
      }
      const selectedWrapperID=String(leaseWrapperID||wrapperItems?.[0]?.wrapper_id||"");
      const selectedWrapper=Array.isArray(wrapperItems)
        ? wrapperItems.find((item:any)=>String(item?.wrapper_id||"")===selectedWrapperID)
        : null;
      if(!String(wrapperClientCertFP||"").trim()&&String(selectedWrapper?.cert_fingerprint||"").trim()){
        setWrapperClientCertFP(String(selectedWrapper?.cert_fingerprint||"").trim());
      }
      if(!leaseKeyID&&keyChoices.length){
        setLeaseKeyID(String(keyChoices[0]?.id||""));
      }
      if(!receiptLeaseID&&Array.isArray(leaseItems)&&leaseItems.length){
        setReceiptLeaseID(String(leaseItems[0]?.lease_id||""));
        setReceiptWrapperID(String(leaseItems[0]?.wrapper_id||""));
        setReceiptKeyID(String(leaseItems[0]?.key_id||""));
      }
    }catch(error){
      if(!silent){
        onToast?.(`Field Encryption refresh failed: ${errMsg(error)}`);
      }
    }finally{
      if(!silent){
        setLoading(false);
      }
    }
  };

  useEffect(()=>{
    if(!session?.token){
      return;
    }
    void refresh(true);
  },[session?.token,session?.tenantId,session?.username]);

  useEffect(()=>{
    if(!leaseKeyID&&keyChoices.length){
      setLeaseKeyID(String(keyChoices[0]?.id||""));
    }
  },[keyChoices,leaseKeyID]);

  const submitInit=async()=>{
    if(!session?.token){
      onToast?.("Login is required.");
      return;
    }
    if(!String(initWrapperID||"").trim()||!String(initAppID||"").trim()){
      onToast?.("wrapper_id and app_id are required.");
      return;
    }
    if(!String(initSigningPub||"").trim()||!String(initEncryptionPub||"").trim()){
      onToast?.("Signing and encryption public keys are required.");
      return;
    }
    setBusy(true);
    try{
      const out=await initFieldEncryptionWrapperRegistration(session,{
        wrapper_id:String(initWrapperID||"").trim(),
        app_id:String(initAppID||"").trim(),
        display_name:String(initDisplayName||"").trim()||String(initWrapperID||"").trim(),
        signing_public_key_b64:String(initSigningPub||"").trim(),
        encryption_public_key_b64:String(initEncryptionPub||"").trim(),
        transport:String(initTransport||"mtls+jwt").trim()||"mtls+jwt",
        metadata:parseMapJSON(initMetadataJSON,"Init metadata")
      });
      setCompleteChallengeID(String((out as any)?.challenge_id||""));
      setCompleteWrapperID(String((out as any)?.wrapper_id||String(initWrapperID||"").trim()));
      setResultText(JSON.stringify(out,null,2));
      onToast?.("Wrapper registration challenge issued.");
      await refresh(true);
    }catch(error){
      onToast?.(`Registration init failed: ${errMsg(error)}`);
    }finally{
      setBusy(false);
    }
  };

  const submitComplete=async()=>{
    if(!session?.token){
      onToast?.("Login is required.");
      return;
    }
    if(!String(completeChallengeID||"").trim()||!String(completeWrapperID||"").trim()||!String(completeSignature||"").trim()){
      onToast?.("challenge_id, wrapper_id and signature are required.");
      return;
    }
    setBusy(true);
    try{
      const out=await completeFieldEncryptionWrapperRegistration(session,{
        challenge_id:String(completeChallengeID||"").trim(),
        wrapper_id:String(completeWrapperID||"").trim(),
        signature_b64:String(completeSignature||"").trim(),
        csr_pem:String(completeCSR||"").trim()||undefined,
        cert_fingerprint:String(completeFingerprint||"").trim()||undefined,
        governance_approved:Boolean(completeApproved),
        approved_by:String(completeApprovedBy||"").trim()||session?.username||"dashboard",
        attestation_evidence_b64:String(completeAttestationEvidenceB64||"").trim()||undefined,
        attestation_signature_b64:String(completeAttestationSignatureB64||"").trim()||undefined,
        attestation_public_key_pem:String(completeAttestationPublicKeyPEM||"").trim()||undefined
      });
      setResultText(JSON.stringify(out,null,2));
      setLeaseWrapperID(String(out?.wrapper?.wrapper_id||leaseWrapperID||""));
      setWrapperRuntimeToken(String(out?.auth_profile?.token||wrapperRuntimeToken||""));
      setWrapperClientCertFP(String(out?.wrapper?.cert_fingerprint||completeFingerprint||wrapperClientCertFP||""));
      if(Array.isArray(out?.warnings)&&out.warnings.length){
        onToast?.(`Registration warning: ${String(out.warnings[0]||"")}`);
      }
      onToast?.("Wrapper registration completed.");
      await refresh(true);
    }catch(error){
      onToast?.(`Registration complete failed: ${errMsg(error)}`);
    }finally{
      setBusy(false);
    }
  };

  const downloadSDK=async()=>{
    if(!session?.token){
      onToast?.("Login is required.");
      return;
    }
    setBusy(true);
    try{
      const artifact=await downloadFieldEncryptionWrapperSDK(session,sdkTargetOS);
      const clean=String(artifact?.content||"").replace(/\s+/g,"");
      const raw=atob(clean);
      const bytes=new Uint8Array(raw.length);
      for(let i=0;i<raw.length;i+=1){
        bytes[i]=raw.charCodeAt(i);
      }
      const blob=new Blob([bytes],{type:String(artifact?.content_type||"application/zip")});
      const url=URL.createObjectURL(blob);
      const a=document.createElement("a");
      a.href=url;
      a.download=String(artifact?.filename||`vecta-field-encryption-wrapper-sdk-${sdkTargetOS}.zip`);
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setResultText(JSON.stringify({sdk_artifact:artifact},null,2));
      onToast?.(`Wrapper SDK downloaded (${String(artifact?.target_os||sdkTargetOS)}).`);
    }catch(error){
      onToast?.(`Wrapper SDK download failed: ${errMsg(error)}`);
    }finally{
      setBusy(false);
    }
  };

  const submitLease=async()=>{
    if(!session?.token){
      onToast?.("Login is required.");
      return;
    }
    if(!String(leaseWrapperID||"").trim()||!String(leaseKeyID||"").trim()){
      onToast?.("wrapper_id and key_id are required.");
      return;
    }
    if(!String(leaseSignature||"").trim()){
      onToast?.("Signed challenge/nonce is required.");
      return;
    }
    setBusy(true);
    try{
      const nonce=String(leaseNonce||"").trim()||makeNonce();
      const ts=String(leaseTimestamp||"").trim()||new Date().toISOString();
      const lease=await issueFieldEncryptionLease(session,{
        wrapper_id:String(leaseWrapperID||"").trim(),
        key_id:String(leaseKeyID||"").trim(),
        operation:String(leaseOperation||"encrypt").trim(),
        nonce,
        timestamp:ts,
        signature_b64:String(leaseSignature||"").trim(),
        requested_ttl_sec:Math.max(1,Math.min(86400,Number(leaseTTL||300))),
        requested_max_ops:Math.max(1,Math.min(1000000,Number(leaseMaxOps||1000))),
        wrapper_token:String(wrapperRuntimeToken||"").trim(),
        client_cert_fingerprint:String(wrapperClientCertFP||"").trim()
      });
      setReceiptLeaseID(String(lease?.lease_id||""));
      setReceiptWrapperID(String(lease?.wrapper_id||""));
      setReceiptKeyID(String(lease?.key_id||""));
      setLeaseNonce(nonce);
      setLeaseTimestamp(ts);
      setResultText(JSON.stringify({lease},null,2));
      onToast?.("Field-encryption lease issued.");
      await refresh(true);
    }catch(error){
      onToast?.(`Lease issue failed: ${errMsg(error)}`);
    }finally{
      setBusy(false);
    }
  };

  const submitReceipt=async()=>{
    if(!session?.token){
      onToast?.("Login is required.");
      return;
    }
    if(!String(receiptLeaseID||"").trim()||!String(receiptWrapperID||"").trim()||!String(receiptKeyID||"").trim()){
      onToast?.("lease_id, wrapper_id and key_id are required.");
      return;
    }
    if(!String(receiptSignature||"").trim()){
      onToast?.("Receipt signature is required.");
      return;
    }
    setBusy(true);
    try{
      const nonce=String(receiptNonce||"").trim()||makeNonce();
      const ts=String(receiptTimestamp||"").trim()||new Date().toISOString();
      const receipt=await submitFieldEncryptionUsageReceipt(session,{
        lease_id:String(receiptLeaseID||"").trim(),
        wrapper_id:String(receiptWrapperID||"").trim(),
        key_id:String(receiptKeyID||"").trim(),
        operation:String(receiptOperation||"encrypt").trim(),
        op_count:Math.max(1,Math.min(100000,Number(receiptCount||1))),
        nonce,
        timestamp:ts,
        signature_b64:String(receiptSignature||"").trim(),
        client_status:String(receiptClientStatus||"ok").trim(),
        wrapper_token:String(wrapperRuntimeToken||"").trim(),
        client_cert_fingerprint:String(wrapperClientCertFP||"").trim()
      });
      setReceiptNonce(nonce);
      setReceiptTimestamp(ts);
      setResultText(JSON.stringify({receipt},null,2));
      onToast?.("Usage receipt submitted.");
      await refresh(true);
    }catch(error){
      onToast?.(`Receipt submission failed: ${errMsg(error)}`);
    }finally{
      setBusy(false);
    }
  };

  const revokeLease=async(lease:any)=>{
    if(!session?.token){
      return;
    }
    const confirmed=await promptDialog.confirm({
      title:"Revoke Field Encryption Lease",
      message:`Revoke lease ${String(lease?.lease_id||"")} for wrapper ${String(lease?.wrapper_id||"")}?`,
      confirmLabel:"Revoke",
      danger:true
    });
    if(!confirmed){
      return;
    }
    setBusy(true);
    try{
      await revokeFieldEncryptionLease(session,String(lease?.lease_id||""),"revoked by admin");
      onToast?.("Lease revoked.");
      await refresh(true);
    }catch(error){
      onToast?.(`Lease revoke failed: ${errMsg(error)}`);
    }finally{
      setBusy(false);
    }
  };

  return <div style={{display:"grid",gap:12}}>
    <Section title="Field Encryption Runtime" actions={<>
      <Sel value={sdkTargetOS} onChange={(e)=>setSDKTargetOS(e.target.value)} style={{minWidth:120}}>
        <option value="linux">SDK: Linux</option>
        <option value="windows">SDK: Windows</option>
        <option value="macos">SDK: macOS</option>
      </Sel>
      <Btn small onClick={()=>void downloadSDK()} disabled={busy}>Download SDK</Btn>
      <Btn small onClick={()=>void refresh(false)} disabled={loading||busy}>{loading?"Refreshing...":"Refresh"}</Btn>
    </>}>
      <Card>
        <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:6}}>Execution Model</div>
        <div style={{fontSize:10,color:C.dim,lineHeight:1.5}}>
          Wrapper registration is mandatory when <code style={{color:C.accent}}>require_registered_wrapper</code> is enabled. Lease issuance enforces nonce/timestamp/signature checks and policy gates (cache/local crypto).
        </div>
      </Card>
    </Section>

    <Row3>
      <Stat l="Wrappers" v={String(wrappers.length)} s="Registered wrapper identities" c="accent"/>
      <Stat l="Leases" v={String(leases.length)} s="Issued local-crypto leases" c="blue"/>
      <Stat l="Active Leases" v={String((leases||[]).filter((item)=>!Boolean(item?.revoked)).length)} s="Not revoked" c="green"/>
    </Row3>

    <Section title="Wrapper Registration">
      <Card style={{display:"grid",gap:10}}>
        <div style={{fontSize:11,color:C.text,fontWeight:700}}>1) Registration Init (challenge issuance)</div>
        <Row3>
          <FG label="Wrapper ID" required><Inp value={initWrapperID} onChange={(e)=>setInitWrapperID(e.target.value)} placeholder="wrapper-prod-01"/></FG>
          <FG label="App ID" required><Inp value={initAppID} onChange={(e)=>setInitAppID(e.target.value)} placeholder="payments-api"/></FG>
          <FG label="Display Name"><Inp value={initDisplayName} onChange={(e)=>setInitDisplayName(e.target.value)} placeholder="Payments API Wrapper"/></FG>
          <FG label="Transport"><Sel value={initTransport} onChange={(e)=>setInitTransport(e.target.value)}><option value="mtls+jwt">mtls+jwt</option><option value="mtls">mtls</option><option value="jwt">jwt</option></Sel></FG>
        </Row3>
        <Row2>
          <FG label="Signing Public Key (base64)" required><Txt rows={3} value={initSigningPub} onChange={(e)=>setInitSigningPub(e.target.value)} mono/></FG>
          <FG label="Encryption Public Key (base64)" required><Txt rows={3} value={initEncryptionPub} onChange={(e)=>setInitEncryptionPub(e.target.value)} mono/></FG>
        </Row2>
        <FG label="Metadata (JSON object)"><Txt rows={2} value={initMetadataJSON} onChange={(e)=>setInitMetadataJSON(e.target.value)} mono/></FG>
        <div style={{display:"flex",justifyContent:"flex-end"}}><Btn small primary onClick={()=>void submitInit()} disabled={busy}>{busy?"Working...":"Init Registration"}</Btn></div>

        <div style={{height:1,background:C.line}}/>

        <div style={{fontSize:11,color:C.text,fontWeight:700}}>2) Registration Complete (challenge response)</div>
        <Row3>
          <FG label="Challenge ID" required><Inp value={completeChallengeID} onChange={(e)=>setCompleteChallengeID(e.target.value)} mono/></FG>
          <FG label="Wrapper ID" required><Inp value={completeWrapperID} onChange={(e)=>setCompleteWrapperID(e.target.value)}/></FG>
          <FG label="Approved By"><Inp value={completeApprovedBy} onChange={(e)=>setCompleteApprovedBy(e.target.value)} placeholder={session?.username||"admin"}/></FG>
        </Row3>
        <Row2>
          <FG label="Signature (base64)" required><Txt rows={3} value={completeSignature} onChange={(e)=>setCompleteSignature(e.target.value)} mono/></FG>
          <FG label="CSR PEM (optional)"><Txt rows={3} value={completeCSR} onChange={(e)=>setCompleteCSR(e.target.value)} mono/></FG>
        </Row2>
        <Row2>
          <FG label="TPM Attestation Evidence (base64 JSON, optional)"><Txt rows={3} value={completeAttestationEvidenceB64} onChange={(e)=>setCompleteAttestationEvidenceB64(e.target.value)} mono/></FG>
          <FG label="TPM Attestation Signature (base64, optional)"><Txt rows={3} value={completeAttestationSignatureB64} onChange={(e)=>setCompleteAttestationSignatureB64(e.target.value)} mono/></FG>
        </Row2>
        <FG label="TPM Attestation Public Key PEM (optional)"><Txt rows={3} value={completeAttestationPublicKeyPEM} onChange={(e)=>setCompleteAttestationPublicKeyPEM(e.target.value)} mono/></FG>
        <Row2>
          <FG label="Cert Fingerprint (optional)"><Inp value={completeFingerprint} onChange={(e)=>setCompleteFingerprint(e.target.value)} mono/></FG>
          <Chk label="Governance approved" checked={completeApproved} onChange={()=>setCompleteApproved((v)=>!v)}/>
        </Row2>
        <div style={{display:"flex",justifyContent:"flex-end"}}><Btn small primary onClick={()=>void submitComplete()} disabled={busy}>{busy?"Working...":"Complete Registration"}</Btn></div>
      </Card>
    </Section>

    <Section title="Lease and Receipt">
      <Card style={{display:"grid",gap:10}}>
        <div style={{fontSize:11,color:C.text,fontWeight:700}}>3) Key Lease for Local Crypto</div>
        <Row3>
          <FG label="Wrapper ID" required><Sel value={leaseWrapperID} onChange={(e)=>setLeaseWrapperID(e.target.value)}><option value="">Select wrapper</option>{(wrappers||[]).map((item)=><option key={String(item?.wrapper_id||"")} value={String(item?.wrapper_id||"")}>{`${String(item?.display_name||item?.wrapper_id||"")} (${String(item?.wrapper_id||"")})`}</option>)}</Sel></FG>
          <FG label="Key ID" required><Sel value={leaseKeyID} onChange={(e)=>setLeaseKeyID(e.target.value)}>{renderKeyOptions(keyChoices)}</Sel></FG>
          <FG label="Operation"><Sel value={leaseOperation} onChange={(e)=>setLeaseOperation(e.target.value)}><option value="encrypt">encrypt</option><option value="decrypt">decrypt</option><option value="tokenize">tokenize</option><option value="detokenize">detokenize</option><option value="mask">mask</option><option value="redact">redact</option></Sel></FG>
          <FG label="Requested TTL (sec)"><Inp type="number" min={1} max={86400} value={leaseTTL} onChange={(e)=>setLeaseTTL(e.target.value)}/></FG>
          <FG label="Requested Max Ops"><Inp type="number" min={1} max={1000000} value={leaseMaxOps} onChange={(e)=>setLeaseMaxOps(e.target.value)}/></FG>
        </Row3>
        <Row2>
          <FG label="Wrapper Runtime JWT"><Inp value={wrapperRuntimeToken} onChange={(e)=>setWrapperRuntimeToken(e.target.value)} placeholder="From registration auth_profile.token" mono/></FG>
          <FG label="Client Cert Fingerprint"><Inp value={wrapperClientCertFP} onChange={(e)=>setWrapperClientCertFP(e.target.value)} placeholder="sha256 fingerprint" mono/></FG>
        </Row2>
        <Row3>
          <FG label="Nonce"><Inp value={leaseNonce} onChange={(e)=>setLeaseNonce(e.target.value)} placeholder="Auto-generated if empty" mono/></FG>
          <FG label="Timestamp (RFC3339)"><Inp value={leaseTimestamp} onChange={(e)=>setLeaseTimestamp(e.target.value)} placeholder="Auto-generated if empty" mono/></FG>
          <FG label="Signature (base64)" required><Inp value={leaseSignature} onChange={(e)=>setLeaseSignature(e.target.value)} mono/></FG>
        </Row3>
        <div style={{display:"flex",justifyContent:"flex-end"}}><Btn small primary onClick={()=>void submitLease()} disabled={busy}>{busy?"Working...":"Issue Lease"}</Btn></div>

        <div style={{height:1,background:C.line}}/>

        <div style={{fontSize:11,color:C.text,fontWeight:700}}>4) Local Usage Receipt</div>
        <Row3>
          <FG label="Lease ID" required><Inp value={receiptLeaseID} onChange={(e)=>setReceiptLeaseID(e.target.value)} mono/></FG>
          <FG label="Wrapper ID" required><Inp value={receiptWrapperID} onChange={(e)=>setReceiptWrapperID(e.target.value)} mono/></FG>
          <FG label="Key ID" required><Inp value={receiptKeyID} onChange={(e)=>setReceiptKeyID(e.target.value)} mono/></FG>
          <FG label="Operation"><Sel value={receiptOperation} onChange={(e)=>setReceiptOperation(e.target.value)}><option value="encrypt">encrypt</option><option value="decrypt">decrypt</option><option value="tokenize">tokenize</option><option value="detokenize">detokenize</option><option value="mask">mask</option><option value="redact">redact</option></Sel></FG>
          <FG label="Operation Count"><Inp type="number" min={1} max={100000} value={receiptCount} onChange={(e)=>setReceiptCount(e.target.value)}/></FG>
          <FG label="Client Status"><Inp value={receiptClientStatus} onChange={(e)=>setReceiptClientStatus(e.target.value)} placeholder="ok"/></FG>
          <FG label="Nonce"><Inp value={receiptNonce} onChange={(e)=>setReceiptNonce(e.target.value)} placeholder="Auto-generated if empty" mono/></FG>
          <FG label="Timestamp (RFC3339)"><Inp value={receiptTimestamp} onChange={(e)=>setReceiptTimestamp(e.target.value)} placeholder="Auto-generated if empty" mono/></FG>
          <FG label="Signature (base64)" required><Inp value={receiptSignature} onChange={(e)=>setReceiptSignature(e.target.value)} mono/></FG>
        </Row3>
        <div style={{display:"flex",justifyContent:"flex-end"}}><Btn small primary onClick={()=>void submitReceipt()} disabled={busy}>{busy?"Working...":"Submit Receipt"}</Btn></div>
      </Card>
    </Section>

    <Row2>
      <Section title="Registered Wrappers">
        <Card style={{maxHeight:260,overflowY:"auto"}}>
          {(wrappers||[]).length?(
            <div style={{display:"grid",gap:8}}>
              {wrappers.map((item:any)=>{
                const status=String(item?.status||"pending").toLowerCase();
                const badgeColor=status==="active"?"green":status==="pending"?"yellow":"muted";
                return <Card key={String(item?.wrapper_id||"")} style={{padding:10}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8}}>
                    <div>
                      <div style={{fontSize:11,color:C.text,fontWeight:700}}>{String(item?.display_name||item?.wrapper_id||"")}</div>
                      <div style={{fontSize:9,color:C.muted}}>{String(item?.wrapper_id||"")} � {String(item?.app_id||"")}</div>
                    </div>
                    <B c={badgeColor as any}>{status||"pending"}</B>
                  </div>
                </Card>;
              })}
            </div>
          ):<div style={{fontSize:10,color:C.dim}}>No wrappers registered for this tenant.</div>}
        </Card>
      </Section>
      <Section title="Issued Leases">
        <Card style={{maxHeight:260,overflowY:"auto"}}>
          {(leases||[]).length?(
            <div style={{display:"grid",gap:8}}>
              {leases.map((item:any)=>{
                const revoked=Boolean(item?.revoked);
                return <Card key={String(item?.lease_id||"")} style={{padding:10}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8}}>
                    <div>
                      <div style={{fontSize:11,color:C.text,fontWeight:700}}>{String(item?.lease_id||"")}</div>
                      <div style={{fontSize:9,color:C.muted}}>{`${String(item?.wrapper_id||"")} � ${String(item?.operation||"")} � used ${Number(item?.used_ops||0)}/${Number(item?.max_ops||0)}`}</div>
                    </div>
                    <div style={{display:"flex",alignItems:"center",gap:8}}>
                      <B c={revoked?"red":"green"}>{revoked?"revoked":"active"}</B>
                      {!revoked?<Btn small danger onClick={()=>void revokeLease(item)} disabled={busy}>Revoke</Btn>:null}
                    </div>
                  </div>
                </Card>;
              })}
            </div>
          ):<div style={{fontSize:10,color:C.dim}}>No leases issued for this tenant.</div>}
        </Card>
      </Section>
    </Row2>

    <Section title="Runtime Output">
      <Card>
        <Txt rows={12} value={resultText} readOnly/>
      </Card>
    </Section>
    {promptDialog.ui}
  </div>;
};

const DataEncryptionPolicy=({session,onToast})=>{
  const [loading,setLoading]=useState(false);
  const [saving,setSaving]=useState(false);
  const [dataPolicy,setDataPolicy]=useState<any>(null);
  const [attestationAllowedPCRsJSON,setAttestationAllowedPCRsJSON]=useState("{}");
  const dataAlgoOptions=["AES-GCM","AES-SIV","CHACHA20-POLY1305"];
  const useCaseProfiles=[
    {id:"field_level",label:"Field-Level (FLE)"},
    {id:"envelope",label:"Envelope"},
    {id:"searchable",label:"Searchable"}
  ];
  const localKeyClassOptions=["symmetric","hmac","asymmetric","pqc"];
  const forceRemoteOpsOptions=["encrypt","decrypt","tokenize","detokenize","mask","redact","sign","verify","wrap","unwrap"];
  const localAlgoOptions=["AES-GCM","AES-SIV","CHACHA20-POLY1305"];
  const parseCsvList=(value:string)=>String(value||"").split(",").map((item)=>item.trim()).filter(Boolean);
  const toggleStringList=(list:string[]|undefined,value:string)=>{
    const normalized=String(value||"").trim();
    const current=Array.isArray(list)?list.map((item)=>String(item||"").trim()).filter(Boolean):[];
    if(!normalized){
      return current;
    }
    return current.includes(normalized)?current.filter((item)=>item!==normalized):[...current,normalized];
  };
  const fmtBytes=(value:number)=>{
    const n=Math.max(0,Number(value||0));
    if(n>=1024*1024){
      return `${(n/(1024*1024)).toFixed(1)} MB`;
    }
    if(n>=1024){
      return `${(n/1024).toFixed(1)} KB`;
    }
    return `${n} B`;
  };

  const loadPolicy=async(silent=false)=>{
    if(!session?.token){
      setDataPolicy(null);
      setAttestationAllowedPCRsJSON("{}");
      return;
    }
    if(!silent){
      setLoading(true);
    }
    try{
      const dp=await getDataProtectionPolicy(session);
      const attestationAllowedPCRs=(dp?.attestation_allowed_pcrs&&typeof dp.attestation_allowed_pcrs==="object"&&!Array.isArray(dp.attestation_allowed_pcrs))?dp.attestation_allowed_pcrs:{};
      setAttestationAllowedPCRsJSON(JSON.stringify(attestationAllowedPCRs,null,2));
      setDataPolicy({
        tenant_id:String(dp?.tenant_id||session?.tenantId||""),
        allowed_data_algorithms:Array.isArray(dp?.allowed_data_algorithms)&&dp.allowed_data_algorithms.length?dp.allowed_data_algorithms:dataAlgoOptions,
        algorithm_profile_policy:dp?.algorithm_profile_policy&&typeof dp.algorithm_profile_policy==="object"?dp.algorithm_profile_policy:{
          field_level:["AES-GCM","AES-SIV","CHACHA20-POLY1305"],
          envelope:["AES-GCM","AES-SIV","CHACHA20-POLY1305"],
          searchable:["AES-SIV"]
        },
        require_aad_for_aead:Boolean(dp?.require_aad_for_aead),
        required_aad_claims:Array.isArray(dp?.required_aad_claims)?dp.required_aad_claims:[],
        enforce_aad_tenant_binding:Boolean(dp?.enforce_aad_tenant_binding),
        allowed_aad_environments:Array.isArray(dp?.allowed_aad_environments)?dp.allowed_aad_environments:[],
        max_fields_per_operation:Math.max(1,Number(dp?.max_fields_per_operation||64)),
        max_document_bytes:Math.max(1024,Number(dp?.max_document_bytes||262144)),
        max_app_crypto_request_bytes:Math.max(1024,Number(dp?.max_app_crypto_request_bytes||1048576)),
        max_app_crypto_batch_size:Math.max(1,Number(dp?.max_app_crypto_batch_size||256)),
        require_symmetric_keys:Boolean(dp?.require_symmetric_keys??true),
        require_fips_keys:Boolean(dp?.require_fips_keys),
        min_key_size_bits:Math.max(0,Number(dp?.min_key_size_bits||0)),
        allowed_encrypt_field_paths:Array.isArray(dp?.allowed_encrypt_field_paths)?dp.allowed_encrypt_field_paths:[],
        allowed_decrypt_field_paths:Array.isArray(dp?.allowed_decrypt_field_paths)?dp.allowed_decrypt_field_paths:[],
        denied_decrypt_field_paths:Array.isArray(dp?.denied_decrypt_field_paths)?dp.denied_decrypt_field_paths:[],
        block_wildcard_field_paths:Boolean(dp?.block_wildcard_field_paths??true),
        allow_deterministic_encryption:Boolean(dp?.allow_deterministic_encryption??true),
        allow_searchable_encryption:Boolean(dp?.allow_searchable_encryption??true),
        allow_range_search:Boolean(dp?.allow_range_search),
        envelope_kek_allowlist:Array.isArray(dp?.envelope_kek_allowlist)?dp.envelope_kek_allowlist:[],
        max_wrapped_dek_age_minutes:Math.max(0,Number(dp?.max_wrapped_dek_age_minutes||0)),
        require_rewrap_on_dek_age_exceeded:Boolean(dp?.require_rewrap_on_dek_age_exceeded??true),
        allow_vaultless_tokenization:Boolean(dp?.allow_vaultless_tokenization),
        tokenization_mode_policy:dp?.tokenization_mode_policy&&typeof dp.tokenization_mode_policy==="object"?dp.tokenization_mode_policy:{
          credit_card:["vault","vaultless"],
          ssn:["vault","vaultless"],
          iban:["vault","vaultless"],
          email:["vault","vaultless"],
          phone:["vault","vaultless"],
          custom:["vault","vaultless"]
        },
        token_format_policy:dp?.token_format_policy&&typeof dp.token_format_policy==="object"?dp.token_format_policy:{
          credit_card:["format_preserving","deterministic","irreversible","random","custom"],
          ssn:["format_preserving","deterministic","irreversible","random","custom"],
          iban:["format_preserving","deterministic","irreversible","random","custom"],
          email:["format_preserving","deterministic","irreversible","random","custom"],
          phone:["format_preserving","deterministic","irreversible","random","custom"],
          custom:["format_preserving","deterministic","irreversible","random","custom"]
        },
        custom_token_formats:dp?.custom_token_formats&&typeof dp.custom_token_formats==="object"?dp.custom_token_formats:{},
        reuse_existing_token_for_same_input:Boolean(dp?.reuse_existing_token_for_same_input??true),
        enforce_unique_token_per_vault:Boolean(dp?.enforce_unique_token_per_vault??true),
        require_token_ttl:Boolean(dp?.require_token_ttl),
        max_token_ttl_hours:Math.max(0,Number(dp?.max_token_ttl_hours||0)),
        allow_token_renewal:Boolean(dp?.allow_token_renewal??true),
        max_token_renewals:Math.max(0,Number(dp?.max_token_renewals??3)),
        allow_one_time_tokens:Boolean(dp?.allow_one_time_tokens??true),
        detokenize_allowed_purposes:Array.isArray(dp?.detokenize_allowed_purposes)?dp.detokenize_allowed_purposes:[],
        detokenize_allowed_workflows:Array.isArray(dp?.detokenize_allowed_workflows)?dp.detokenize_allowed_workflows:[],
        require_detokenize_justification:Boolean(dp?.require_detokenize_justification),
        allow_bulk_tokenize:Boolean(dp?.allow_bulk_tokenize??true),
        allow_bulk_detokenize:Boolean(dp?.allow_bulk_detokenize??true),
        allow_redaction_detect_only:Boolean(dp?.allow_redaction_detect_only),
        allowed_redaction_detectors:Array.isArray(dp?.allowed_redaction_detectors)&&dp.allowed_redaction_detectors.length?dp.allowed_redaction_detectors:["EMAIL","PHONE","SSN","PAN","IBAN","NAME","CUSTOM"],
        allowed_redaction_actions:Array.isArray(dp?.allowed_redaction_actions)&&dp.allowed_redaction_actions.length?dp.allowed_redaction_actions:["replace_placeholder","remove","hash"],
        allow_custom_regex_tokens:Boolean(dp?.allow_custom_regex_tokens),
        max_custom_regex_length:Math.max(1,Number(dp?.max_custom_regex_length||512)),
        max_custom_regex_groups:Math.max(0,Number(dp?.max_custom_regex_groups||16)),
        max_token_batch:Math.max(1,Number(dp?.max_token_batch||10000)),
        max_detokenize_batch:Math.max(1,Number(dp?.max_detokenize_batch||10000)),
        require_token_context_tags:Boolean(dp?.require_token_context_tags),
        required_token_context_keys:Array.isArray(dp?.required_token_context_keys)?dp.required_token_context_keys:[],
        masking_role_policy:dp?.masking_role_policy&&typeof dp.masking_role_policy==="object"?dp.masking_role_policy:{admin:"none",auditor:"hash",analyst:"partial_last4",support:"partial_last4"},
        token_metadata_retention_days:Math.max(1,Number(dp?.token_metadata_retention_days||365)),
        redaction_event_retention_days:Math.max(1,Number(dp?.redaction_event_retention_days||365)),
        require_registered_wrapper:Boolean(dp?.require_registered_wrapper ?? true),
        local_crypto_allowed:Boolean(dp?.local_crypto_allowed),
        cache_enabled:Boolean(dp?.cache_enabled),
        cache_ttl_sec:Math.max(1,Number(dp?.cache_ttl_sec||300)),
        lease_max_ops:Math.max(1,Number(dp?.lease_max_ops||1000)),
        max_cached_keys:Math.max(1,Number(dp?.max_cached_keys||16)),
        allowed_local_algorithms:Array.isArray(dp?.allowed_local_algorithms)&&dp.allowed_local_algorithms.length?dp.allowed_local_algorithms:["AES-GCM","AES-SIV","CHACHA20-POLY1305"],
        allowed_key_classes_for_local_export:Array.isArray(dp?.allowed_key_classes_for_local_export)&&dp.allowed_key_classes_for_local_export.length?dp.allowed_key_classes_for_local_export:["symmetric"],
        force_remote_ops:Array.isArray(dp?.force_remote_ops)?dp.force_remote_ops:[],
        require_mtls:Boolean(dp?.require_mtls),
        require_signed_nonce:Boolean(dp?.require_signed_nonce ?? true),
        anti_replay_window_sec:Math.max(1,Number(dp?.anti_replay_window_sec||300)),
        attested_wrapper_only:Boolean(dp?.attested_wrapper_only),
        revoke_on_policy_change:Boolean(dp?.revoke_on_policy_change ?? true),
        rekey_on_policy_change:Boolean(dp?.rekey_on_policy_change),
        receipt_reconciliation_enabled:Boolean(dp?.receipt_reconciliation_enabled),
        receipt_heartbeat_sec:Math.max(1,Number(dp?.receipt_heartbeat_sec||120)),
        receipt_missing_grace_sec:Math.max(1,Number(dp?.receipt_missing_grace_sec||60)),
        require_tpm_attestation:Boolean(dp?.require_tpm_attestation),
        require_non_exportable_wrapper_keys:Boolean(dp?.require_non_exportable_wrapper_keys),
        attestation_ak_allowlist:Array.isArray(dp?.attestation_ak_allowlist)?dp.attestation_ak_allowlist:[],
        attestation_allowed_pcrs:attestationAllowedPCRs
      });
    }catch(error){
      if(!silent){
        onToast?.(`Data encryption policy load failed: ${errMsg(error)}`);
      }
    }finally{
      if(!silent){
        setLoading(false);
      }
    }
  };

  useEffect(()=>{
    void loadPolicy();
  },[session?.token,session?.tenantId]);

  const savePolicy=async()=>{
    if(!session?.token){
      onToast?.("Login is required to update data encryption policy.");
      return;
    }
    if(!dataPolicy){
      onToast?.("Policy settings are not loaded.");
      return;
    }
    let attestationAllowedPCRs:any={};
    try{
      const parsed=JSON.parse(String(attestationAllowedPCRsJSON||"{}"));
      if(!parsed||typeof parsed!=="object"||Array.isArray(parsed)){
        throw new Error("Attestation PCR policy must be a JSON object.");
      }
      attestationAllowedPCRs=parsed;
    }catch(error){
      onToast?.(`Attestation PCR policy JSON is invalid: ${errMsg(error)}`);
      return;
    }
    setSaving(true);
    try{
      const updated=await updateDataProtectionPolicy(session,{
        tenant_id:session.tenantId,
        allowed_data_algorithms:Array.isArray(dataPolicy?.allowed_data_algorithms)?dataPolicy.allowed_data_algorithms:dataAlgoOptions,
        algorithm_profile_policy:dataPolicy?.algorithm_profile_policy&&typeof dataPolicy.algorithm_profile_policy==="object"?dataPolicy.algorithm_profile_policy:{},
        require_aad_for_aead:Boolean(dataPolicy?.require_aad_for_aead),
        required_aad_claims:Array.isArray(dataPolicy?.required_aad_claims)?dataPolicy.required_aad_claims:[],
        enforce_aad_tenant_binding:Boolean(dataPolicy?.enforce_aad_tenant_binding),
        allowed_aad_environments:Array.isArray(dataPolicy?.allowed_aad_environments)?dataPolicy.allowed_aad_environments:[],
        max_fields_per_operation:Math.max(1,Math.min(2048,Number(dataPolicy?.max_fields_per_operation||64))),
        max_document_bytes:Math.max(1024,Math.min(16777216,Number(dataPolicy?.max_document_bytes||262144))),
        max_app_crypto_request_bytes:Math.max(1024,Math.min(67108864,Number(dataPolicy?.max_app_crypto_request_bytes||1048576))),
        max_app_crypto_batch_size:Math.max(1,Math.min(4096,Number(dataPolicy?.max_app_crypto_batch_size||256))),
        require_symmetric_keys:Boolean(dataPolicy?.require_symmetric_keys??true),
        require_fips_keys:Boolean(dataPolicy?.require_fips_keys),
        min_key_size_bits:Math.max(0,Math.min(16384,Number(dataPolicy?.min_key_size_bits||0))),
        allowed_encrypt_field_paths:Array.isArray(dataPolicy?.allowed_encrypt_field_paths)?dataPolicy.allowed_encrypt_field_paths:[],
        allowed_decrypt_field_paths:Array.isArray(dataPolicy?.allowed_decrypt_field_paths)?dataPolicy.allowed_decrypt_field_paths:[],
        denied_decrypt_field_paths:Array.isArray(dataPolicy?.denied_decrypt_field_paths)?dataPolicy.denied_decrypt_field_paths:[],
        block_wildcard_field_paths:Boolean(dataPolicy?.block_wildcard_field_paths),
        allow_deterministic_encryption:Boolean(dataPolicy?.allow_deterministic_encryption),
        allow_searchable_encryption:Boolean(dataPolicy?.allow_searchable_encryption),
        allow_range_search:Boolean(dataPolicy?.allow_range_search),
        envelope_kek_allowlist:Array.isArray(dataPolicy?.envelope_kek_allowlist)?dataPolicy.envelope_kek_allowlist:[],
        max_wrapped_dek_age_minutes:Math.max(0,Math.min(525600,Number(dataPolicy?.max_wrapped_dek_age_minutes||0))),
        require_rewrap_on_dek_age_exceeded:Boolean(dataPolicy?.require_rewrap_on_dek_age_exceeded),
        allow_vaultless_tokenization:Boolean(dataPolicy?.allow_vaultless_tokenization),
        tokenization_mode_policy:dataPolicy?.tokenization_mode_policy&&typeof dataPolicy.tokenization_mode_policy==="object"?dataPolicy.tokenization_mode_policy:{},
        token_format_policy:dataPolicy?.token_format_policy&&typeof dataPolicy.token_format_policy==="object"?dataPolicy.token_format_policy:{},
        custom_token_formats:dataPolicy?.custom_token_formats&&typeof dataPolicy.custom_token_formats==="object"?dataPolicy.custom_token_formats:{},
        reuse_existing_token_for_same_input:Boolean(dataPolicy?.reuse_existing_token_for_same_input??true),
        enforce_unique_token_per_vault:Boolean(dataPolicy?.enforce_unique_token_per_vault??true),
        require_token_ttl:Boolean(dataPolicy?.require_token_ttl),
        max_token_ttl_hours:Math.max(0,Math.min(87600,Number(dataPolicy?.max_token_ttl_hours||0))),
        allow_token_renewal:Boolean(dataPolicy?.allow_token_renewal),
        max_token_renewals:Math.max(0,Math.min(100,Number(dataPolicy?.max_token_renewals||3))),
        allow_one_time_tokens:Boolean(dataPolicy?.allow_one_time_tokens),
        detokenize_allowed_purposes:Array.isArray(dataPolicy?.detokenize_allowed_purposes)?dataPolicy.detokenize_allowed_purposes:[],
        detokenize_allowed_workflows:Array.isArray(dataPolicy?.detokenize_allowed_workflows)?dataPolicy.detokenize_allowed_workflows:[],
        require_detokenize_justification:Boolean(dataPolicy?.require_detokenize_justification),
        allow_bulk_tokenize:Boolean(dataPolicy?.allow_bulk_tokenize),
        allow_bulk_detokenize:Boolean(dataPolicy?.allow_bulk_detokenize),
        allow_redaction_detect_only:Boolean(dataPolicy?.allow_redaction_detect_only),
        allowed_redaction_detectors:Array.isArray(dataPolicy?.allowed_redaction_detectors)?dataPolicy.allowed_redaction_detectors:[],
        allowed_redaction_actions:Array.isArray(dataPolicy?.allowed_redaction_actions)?dataPolicy.allowed_redaction_actions:[],
        allow_custom_regex_tokens:Boolean(dataPolicy?.allow_custom_regex_tokens),
        max_custom_regex_length:Math.max(1,Math.min(4096,Number(dataPolicy?.max_custom_regex_length||512))),
        max_custom_regex_groups:Math.max(1,Math.min(128,Number(dataPolicy?.max_custom_regex_groups||16))),
        max_token_batch:Math.max(1,Math.min(100000,Number(dataPolicy?.max_token_batch||10000))),
        max_detokenize_batch:Math.max(1,Math.min(100000,Number(dataPolicy?.max_detokenize_batch||10000))),
        require_token_context_tags:Boolean(dataPolicy?.require_token_context_tags),
        required_token_context_keys:Array.isArray(dataPolicy?.required_token_context_keys)?dataPolicy.required_token_context_keys:[],
        masking_role_policy:dataPolicy?.masking_role_policy&&typeof dataPolicy.masking_role_policy==="object"?dataPolicy.masking_role_policy:{},
        token_metadata_retention_days:Math.max(1,Math.min(36500,Number(dataPolicy?.token_metadata_retention_days||365))),
        redaction_event_retention_days:Math.max(1,Math.min(36500,Number(dataPolicy?.redaction_event_retention_days||365))),
        require_registered_wrapper:Boolean(dataPolicy?.require_registered_wrapper),
        local_crypto_allowed:Boolean(dataPolicy?.local_crypto_allowed),
        cache_enabled:Boolean(dataPolicy?.cache_enabled),
        cache_ttl_sec:Math.max(1,Math.min(86400,Number(dataPolicy?.cache_ttl_sec||300))),
        lease_max_ops:Math.max(1,Math.min(1000000,Number(dataPolicy?.lease_max_ops||1000))),
        max_cached_keys:Math.max(1,Math.min(10000,Number(dataPolicy?.max_cached_keys||16))),
        allowed_local_algorithms:Array.isArray(dataPolicy?.allowed_local_algorithms)?dataPolicy.allowed_local_algorithms:[],
        allowed_key_classes_for_local_export:Array.isArray(dataPolicy?.allowed_key_classes_for_local_export)?dataPolicy.allowed_key_classes_for_local_export:[],
        force_remote_ops:Array.isArray(dataPolicy?.force_remote_ops)?dataPolicy.force_remote_ops:[],
        require_mtls:Boolean(dataPolicy?.require_mtls),
        require_signed_nonce:Boolean(dataPolicy?.require_signed_nonce),
        anti_replay_window_sec:Math.max(1,Math.min(86400,Number(dataPolicy?.anti_replay_window_sec||300))),
        attested_wrapper_only:Boolean(dataPolicy?.attested_wrapper_only),
        revoke_on_policy_change:Boolean(dataPolicy?.revoke_on_policy_change),
        rekey_on_policy_change:Boolean(dataPolicy?.rekey_on_policy_change),
        receipt_reconciliation_enabled:Boolean(dataPolicy?.receipt_reconciliation_enabled),
        receipt_heartbeat_sec:Math.max(1,Math.min(86400,Number(dataPolicy?.receipt_heartbeat_sec||120))),
        receipt_missing_grace_sec:Math.max(1,Math.min(86400,Number(dataPolicy?.receipt_missing_grace_sec||60))),
        require_tpm_attestation:Boolean(dataPolicy?.require_tpm_attestation),
        require_non_exportable_wrapper_keys:Boolean(dataPolicy?.require_non_exportable_wrapper_keys),
        attestation_ak_allowlist:Array.isArray(dataPolicy?.attestation_ak_allowlist)?dataPolicy.attestation_ak_allowlist:[],
        attestation_allowed_pcrs:attestationAllowedPCRs,
        updated_by:session?.username||"dashboard"
      });
      setDataPolicy((prev)=>({...prev,...updated}));
      setAttestationAllowedPCRsJSON(JSON.stringify((updated?.attestation_allowed_pcrs&&typeof updated.attestation_allowed_pcrs==="object")?updated.attestation_allowed_pcrs:{},null,2));
      onToast?.("Data encryption policy updated.");
    }catch(error){
      onToast?.(`Data encryption policy update failed: ${errMsg(error)}`);
    }finally{
      setSaving(false);
    }
  };

  return <div style={{display:"grid",gap:12}}>
    <Section title="Data Encryption Policy" actions={<>
      <Btn small onClick={()=>void loadPolicy(false)} disabled={loading}>{loading?"Refreshing...":"Refresh"}</Btn>
      <Btn small primary onClick={savePolicy} disabled={saving||loading}>{saving?"Saving...":"Save Policy"}</Btn>
    </>}>
      <Card>
        <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:6}}>Policy Scope</div>
        <div style={{fontSize:10,color:C.dim,lineHeight:1.4}}>
          This tab controls data-encryption behavior for Field-Level, Envelope and Searchable application encryption flows. Changes apply immediately to all SDKs, wrappers, and REST API consumers.
        </div>
      </Card>
    </Section>

    <Section title="Data Encryption Controls">
      <Card style={{display:"grid",gap:8}}>
        <div style={{fontSize:11,color:C.text,fontWeight:700}}>1. Algorithm Profile Policy</div>
        <div style={{fontSize:10,color:C.dim}}>Controls which algorithms are globally allowed and which are valid per use-case (FLE, Envelope, Searchable).</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8}}>
          {dataAlgoOptions.map((algo)=>{
            const selected=(Array.isArray(dataPolicy?.allowed_data_algorithms)?dataPolicy.allowed_data_algorithms:[]).includes(algo);
            return <Chk key={`dp-allowed-algo-${algo}`} label={`Allow ${algo}`} checked={selected} onChange={()=>setDataPolicy((prev)=>{
              const current=Array.isArray(prev?.allowed_data_algorithms)?[...prev.allowed_data_algorithms]:[];
              const next=current.includes(algo)?current.filter((item)=>item!==algo):[...current,algo];
              return {...prev,allowed_data_algorithms:next};
            })}/>;
          })}
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8}}>
          {useCaseProfiles.map((profile)=>(
            <div key={`alg-profile-${profile.id}`} style={{border:`1px solid ${C.line}`,borderRadius:10,padding:"8px 10px"}}>
              <div style={{fontSize:12,color:C.text,fontWeight:700,marginBottom:6}}>{profile.label}</div>
              <div style={{display:"grid",gap:6}}>
                {dataAlgoOptions.map((algo)=>{
                  const current=Array.isArray(dataPolicy?.algorithm_profile_policy?.[profile.id])?dataPolicy.algorithm_profile_policy[profile.id]:[];
                  const selected=current.includes(algo);
                  return <Chk
                    key={`alg-profile-${profile.id}-${algo}`}
                    label={algo}
                    checked={selected}
                    onChange={()=>setDataPolicy((prev)=>{
                      const profileCurrent=Array.isArray(prev?.algorithm_profile_policy?.[profile.id])?[...prev.algorithm_profile_policy[profile.id]]:[];
                      const profileNext=profileCurrent.includes(algo)?profileCurrent.filter((item)=>item!==algo):[...profileCurrent,algo];
                      return {...prev,algorithm_profile_policy:{...(prev?.algorithm_profile_policy||{}),[profile.id]:profileNext}};
                    })}
                  />;
                })}
              </div>
            </div>
          ))}
        </div>

        <div style={{height:1,background:C.line,margin:"4px 0"}}/>

        <div style={{fontSize:11,color:C.text,fontWeight:700}}>2. Key-Class Binding Policy</div>
        <div style={{fontSize:10,color:C.dim}}>Defines eligible key classes for data encryption operations.</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8}}>
          <Chk label="Require symmetric keys only" checked={Boolean(dataPolicy?.require_symmetric_keys)} onChange={()=>setDataPolicy((prev)=>({...prev,require_symmetric_keys:!Boolean(prev?.require_symmetric_keys)}))}/>
          <Chk label="Require FIPS compliant keys" checked={Boolean(dataPolicy?.require_fips_keys)} onChange={()=>setDataPolicy((prev)=>({...prev,require_fips_keys:!Boolean(prev?.require_fips_keys)}))}/>
          <FG label="Minimum key size (bits, 0=disabled)">
            <Inp type="number" min={0} max={16384} value={String(dataPolicy?.min_key_size_bits??0)} onChange={(e)=>setDataPolicy((prev)=>({...prev,min_key_size_bits:Number(e.target.value||0)}))}/>
          </FG>
        </div>

        <div style={{height:1,background:C.line,margin:"4px 0"}}/>

        <div style={{fontSize:11,color:C.text,fontWeight:700}}>3. AAD Contract Policy</div>
        <div style={{fontSize:10,color:C.dim}}>Requires and validates structured AAD claims for AEAD and searchable operations.</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8}}>
          <Chk label="Require AAD for AEAD operations" checked={Boolean(dataPolicy?.require_aad_for_aead)} onChange={()=>setDataPolicy((prev)=>({...prev,require_aad_for_aead:!Boolean(prev?.require_aad_for_aead)}))}/>
          <Chk label="Enforce tenant_id claim binding" checked={Boolean(dataPolicy?.enforce_aad_tenant_binding)} onChange={()=>setDataPolicy((prev)=>({...prev,enforce_aad_tenant_binding:!Boolean(prev?.enforce_aad_tenant_binding)}))}/>
          <FG label="Required AAD claims (comma separated)">
            <Inp value={Array.isArray(dataPolicy?.required_aad_claims)?dataPolicy.required_aad_claims.join(", "):""} onChange={(e)=>setDataPolicy((prev)=>({...prev,required_aad_claims:parseCsvList(e.target.value)}))} placeholder="tenant_id, app_id, purpose"/>
          </FG>
          <FG label="Allowed AAD environments (comma separated)">
            <Inp value={Array.isArray(dataPolicy?.allowed_aad_environments)?dataPolicy.allowed_aad_environments.join(", "):""} onChange={(e)=>setDataPolicy((prev)=>({...prev,allowed_aad_environments:parseCsvList(e.target.value)}))} placeholder="prod, stage"/>
          </FG>
        </div>

        <div style={{height:1,background:C.line,margin:"4px 0"}}/>

        <div style={{fontSize:11,color:C.text,fontWeight:700}}>4. Field Scope Policy</div>
        <div style={{fontSize:10,color:C.dim}}>Restricts which JSONPaths can be encrypted/decrypted and blocks wildcard access when required.</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8}}>
          <Chk label="Block wildcard field paths" checked={Boolean(dataPolicy?.block_wildcard_field_paths)} onChange={()=>setDataPolicy((prev)=>({...prev,block_wildcard_field_paths:!Boolean(prev?.block_wildcard_field_paths)}))}/>
          <div/>
          <FG label="Allowed encrypt field paths (comma separated)">
            <Inp value={Array.isArray(dataPolicy?.allowed_encrypt_field_paths)?dataPolicy.allowed_encrypt_field_paths.join(", "):""} onChange={(e)=>setDataPolicy((prev)=>({...prev,allowed_encrypt_field_paths:parseCsvList(e.target.value)}))} placeholder="$.ssn, $.card.number"/>
          </FG>
          <FG label="Allowed decrypt field paths (comma separated)">
            <Inp value={Array.isArray(dataPolicy?.allowed_decrypt_field_paths)?dataPolicy.allowed_decrypt_field_paths.join(", "):""} onChange={(e)=>setDataPolicy((prev)=>({...prev,allowed_decrypt_field_paths:parseCsvList(e.target.value)}))} placeholder="$.ssn"/>
          </FG>
          <FG label="Denied decrypt field paths (comma separated)">
            <Inp value={Array.isArray(dataPolicy?.denied_decrypt_field_paths)?dataPolicy.denied_decrypt_field_paths.join(", "):""} onChange={(e)=>setDataPolicy((prev)=>({...prev,denied_decrypt_field_paths:parseCsvList(e.target.value)}))} placeholder="$.pan.full"/>
          </FG>
        </div>

        <div style={{height:1,background:C.line,margin:"4px 0"}}/>

        <div style={{fontSize:11,color:C.text,fontWeight:700}}>5. Deterministic/Searchable Policy</div>
        <div style={{fontSize:10,color:C.dim}}>Controls deterministic and searchable encryption behavior, including range search.</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8}}>
          <Chk label="Allow deterministic encryption" checked={Boolean(dataPolicy?.allow_deterministic_encryption)} onChange={()=>setDataPolicy((prev)=>({...prev,allow_deterministic_encryption:!Boolean(prev?.allow_deterministic_encryption)}))}/>
          <Chk label="Allow searchable encryption" checked={Boolean(dataPolicy?.allow_searchable_encryption)} onChange={()=>setDataPolicy((prev)=>({...prev,allow_searchable_encryption:!Boolean(prev?.allow_searchable_encryption)}))}/>
          <Chk label="Allow range search" checked={Boolean(dataPolicy?.allow_range_search)} onChange={()=>setDataPolicy((prev)=>({...prev,allow_range_search:!Boolean(prev?.allow_range_search)}))}/>
        </div>

        <div style={{height:1,background:C.line,margin:"4px 0"}}/>

        <div style={{fontSize:11,color:C.text,fontWeight:700}}>6. Envelope Policy</div>
        <div style={{fontSize:10,color:C.dim}}>Constrains KEK allowlist and wrapped DEK age enforcement during envelope operations.</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8}}>
          <FG label="Envelope KEK allowlist (key IDs, comma separated)">
            <Inp value={Array.isArray(dataPolicy?.envelope_kek_allowlist)?dataPolicy.envelope_kek_allowlist.join(", "):""} onChange={(e)=>setDataPolicy((prev)=>({...prev,envelope_kek_allowlist:parseCsvList(e.target.value)}))} placeholder="key_abc123, key_xyz789"/>
          </FG>
          <FG label="Max wrapped DEK age (minutes, 0=disabled)">
            <Inp type="number" min={0} max={525600} value={String(dataPolicy?.max_wrapped_dek_age_minutes??0)} onChange={(e)=>setDataPolicy((prev)=>({...prev,max_wrapped_dek_age_minutes:Number(e.target.value||0)}))}/>
          </FG>
          <Chk label="Require re-wrap when DEK age exceeds limit" checked={Boolean(dataPolicy?.require_rewrap_on_dek_age_exceeded)} onChange={()=>setDataPolicy((prev)=>({...prev,require_rewrap_on_dek_age_exceeded:!Boolean(prev?.require_rewrap_on_dek_age_exceeded)}))}/>
        </div>

        <div style={{height:1,background:C.line,margin:"4px 0"}}/>

        <div style={{fontSize:11,color:C.text,fontWeight:700}}>7. Payload Policy</div>
        <div style={{fontSize:10,color:C.dim}}>Applies request/field/batch size limits across Data Encryption REST operations.</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:10}}>
          <FG label="Max fields per operation">
            <Inp type="number" min={1} max={2048} value={String(dataPolicy?.max_fields_per_operation??64)} onChange={(e)=>setDataPolicy((prev)=>({...prev,max_fields_per_operation:Number(e.target.value||64)}))}/>
          </FG>
          <FG label="Max document size (bytes)">
            <Inp type="number" min={1024} max={16777216} value={String(dataPolicy?.max_document_bytes??262144)} onChange={(e)=>setDataPolicy((prev)=>({...prev,max_document_bytes:Number(e.target.value||262144)}))}/>
          </FG>
          <FG label={`Max app crypto request size (${fmtBytes(Number(dataPolicy?.max_app_crypto_request_bytes||1048576))})`}>
            <Inp type="number" min={1024} max={67108864} value={String(dataPolicy?.max_app_crypto_request_bytes??1048576)} onChange={(e)=>setDataPolicy((prev)=>({...prev,max_app_crypto_request_bytes:Number(e.target.value||1048576)}))}/>
          </FG>
          <FG label="Max app crypto batch size">
            <Inp type="number" min={1} max={4096} value={String(dataPolicy?.max_app_crypto_batch_size??256)} onChange={(e)=>setDataPolicy((prev)=>({...prev,max_app_crypto_batch_size:Number(e.target.value||256)}))}/>
          </FG>
        </div>

        <div style={{height:1,background:C.line,margin:"4px 0"}}/>

        <div style={{fontSize:11,color:C.text,fontWeight:700}}>8. Field Encryption Runtime Policy</div>
        <div style={{fontSize:10,color:C.dim}}>Enforces wrapper registration, local crypto leasing, cache controls, anti-replay checks, and mTLS requirements.</div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8}}>
          <Chk label="Require registered wrapper (mandatory registration flow)" checked={Boolean(dataPolicy?.require_registered_wrapper)} onChange={()=>setDataPolicy((prev)=>({...prev,require_registered_wrapper:!Boolean(prev?.require_registered_wrapper)}))}/>
          <Chk label="Allow local crypto path (wrapper local execution)" checked={Boolean(dataPolicy?.local_crypto_allowed)} onChange={()=>setDataPolicy((prev)=>({...prev,local_crypto_allowed:!Boolean(prev?.local_crypto_allowed)}))}/>
          <Chk label="Enable key cache/lease mode" checked={Boolean(dataPolicy?.cache_enabled)} onChange={()=>setDataPolicy((prev)=>({...prev,cache_enabled:!Boolean(prev?.cache_enabled)}))}/>
          <Chk label="Require mTLS for wrapper runtime APIs" checked={Boolean(dataPolicy?.require_mtls)} onChange={()=>setDataPolicy((prev)=>({...prev,require_mtls:!Boolean(prev?.require_mtls)}))}/>
          <Chk label="Require signed nonce + timestamp (anti-replay)" checked={Boolean(dataPolicy?.require_signed_nonce)} onChange={()=>setDataPolicy((prev)=>({...prev,require_signed_nonce:!Boolean(prev?.require_signed_nonce)}))}/>
          <Chk label="Attested wrappers only (strict mode)" checked={Boolean(dataPolicy?.attested_wrapper_only)} onChange={()=>setDataPolicy((prev)=>({...prev,attested_wrapper_only:!Boolean(prev?.attested_wrapper_only)}))}/>
          <Chk label="Require TPM attestation verification" checked={Boolean(dataPolicy?.require_tpm_attestation)} onChange={()=>setDataPolicy((prev)=>({...prev,require_tpm_attestation:!Boolean(prev?.require_tpm_attestation)}))}/>
          <Chk label="Require non-exportable wrapper key assertion" checked={Boolean(dataPolicy?.require_non_exportable_wrapper_keys)} onChange={()=>setDataPolicy((prev)=>({...prev,require_non_exportable_wrapper_keys:!Boolean(prev?.require_non_exportable_wrapper_keys)}))}/>
          <Chk label="Enable missing-receipt reconciliation" checked={Boolean(dataPolicy?.receipt_reconciliation_enabled)} onChange={()=>setDataPolicy((prev)=>({...prev,receipt_reconciliation_enabled:!Boolean(prev?.receipt_reconciliation_enabled)}))}/>
          <Chk label="Revoke active leases when policy changes" checked={Boolean(dataPolicy?.revoke_on_policy_change)} onChange={()=>setDataPolicy((prev)=>({...prev,revoke_on_policy_change:!Boolean(prev?.revoke_on_policy_change)}))}/>
          <Chk label="Require key re-lease/rekey on policy change" checked={Boolean(dataPolicy?.rekey_on_policy_change)} onChange={()=>setDataPolicy((prev)=>({...prev,rekey_on_policy_change:!Boolean(prev?.rekey_on_policy_change)}))}/>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:10}}>
          <FG label="Cache TTL (seconds)">
            <Inp type="number" min={1} max={86400} value={String(dataPolicy?.cache_ttl_sec??300)} onChange={(e)=>setDataPolicy((prev)=>({...prev,cache_ttl_sec:Number(e.target.value||300)}))}/>
          </FG>
          <FG label="Lease max operations">
            <Inp type="number" min={1} max={1000000} value={String(dataPolicy?.lease_max_ops??1000)} onChange={(e)=>setDataPolicy((prev)=>({...prev,lease_max_ops:Number(e.target.value||1000)}))}/>
          </FG>
          <FG label="Max cached keys per wrapper">
            <Inp type="number" min={1} max={10000} value={String(dataPolicy?.max_cached_keys??16)} onChange={(e)=>setDataPolicy((prev)=>({...prev,max_cached_keys:Number(e.target.value||16)}))}/>
          </FG>
          <FG label="Anti-replay window (seconds)">
            <Inp type="number" min={1} max={86400} value={String(dataPolicy?.anti_replay_window_sec??300)} onChange={(e)=>setDataPolicy((prev)=>({...prev,anti_replay_window_sec:Number(e.target.value||300)}))}/>
          </FG>
          <FG label="Receipt heartbeat (seconds)">
            <Inp type="number" min={1} max={86400} value={String(dataPolicy?.receipt_heartbeat_sec??120)} onChange={(e)=>setDataPolicy((prev)=>({...prev,receipt_heartbeat_sec:Number(e.target.value||120)}))}/>
          </FG>
          <FG label="Missing receipt grace (seconds)">
            <Inp type="number" min={1} max={86400} value={String(dataPolicy?.receipt_missing_grace_sec??60)} onChange={(e)=>setDataPolicy((prev)=>({...prev,receipt_missing_grace_sec:Number(e.target.value||60)}))}/>
          </FG>
        </div>
        <FG label="Attestation AK allowlist (SHA-256 fingerprints, comma separated)">
          <Inp value={Array.isArray(dataPolicy?.attestation_ak_allowlist)?dataPolicy.attestation_ak_allowlist.join(", "):""} onChange={(e)=>setDataPolicy((prev)=>({...prev,attestation_ak_allowlist:parseCsvList(e.target.value)}))} placeholder="ak_fp_1, ak_fp_2"/>
        </FG>
        <FG label="Allowed PCR policy JSON (map pcr index -> allowed values array)">
          <Txt rows={4} value={attestationAllowedPCRsJSON} onChange={(e)=>setAttestationAllowedPCRsJSON(e.target.value)} mono/>
        </FG>
        <div>
          <div style={{fontSize:10,color:C.text,fontWeight:700,marginBottom:8}}>Allowed local algorithms</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8}}>
            {localAlgoOptions.map((algo)=>{
              const selected=(Array.isArray(dataPolicy?.allowed_local_algorithms)?dataPolicy.allowed_local_algorithms:[]).includes(algo);
              return <Chk key={`dpol-local-algo-${algo}`} label={algo} checked={selected} onChange={()=>setDataPolicy((prev)=>({...prev,allowed_local_algorithms:toggleStringList(prev?.allowed_local_algorithms,algo)}))}/>;
            })}
          </div>
        </div>
        <div>
          <div style={{fontSize:10,color:C.text,fontWeight:700,marginBottom:8}}>Allowed key classes for local export/lease</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(4,minmax(0,1fr))",gap:8}}>
            {localKeyClassOptions.map((item)=>{
              const selected=(Array.isArray(dataPolicy?.allowed_key_classes_for_local_export)?dataPolicy.allowed_key_classes_for_local_export:[]).includes(item);
              return <Chk key={`dpol-local-class-${item}`} label={item} checked={selected} onChange={()=>setDataPolicy((prev)=>({...prev,allowed_key_classes_for_local_export:toggleStringList(prev?.allowed_key_classes_for_local_export,item)}))}/>;
            })}
          </div>
        </div>
        <div>
          <div style={{fontSize:10,color:C.text,fontWeight:700,marginBottom:8}}>Force remote execution for selected operations</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8}}>
            {forceRemoteOpsOptions.map((item)=>{
              const selected=(Array.isArray(dataPolicy?.force_remote_ops)?dataPolicy.force_remote_ops:[]).includes(item);
              return <Chk key={`dpol-force-remote-${item}`} label={item} checked={selected} onChange={()=>setDataPolicy((prev)=>({...prev,force_remote_ops:toggleStringList(prev?.force_remote_ops,item)}))}/>;
            })}
          </div>
        </div>
      </Card>
    </Section>
  </div>;
};

const TokenizeMaskRedactPolicy=({session,onToast})=>{
  const [loading,setLoading]=useState(false);
  const [saving,setSaving]=useState(false);
  const [creatingVault,setCreatingVault]=useState(false);
  const [refreshingVaults,setRefreshingVaults]=useState(false);
  const [deletingVaultId,setDeletingVaultId]=useState("");
  const [vaultRows,setVaultRows]=useState<any[]>([]);
  const [dataPolicy,setDataPolicy]=useState<any>(null);
  const [customTokenFormatsText,setCustomTokenFormatsText]=useState("{}");
  const [newVaultName,setNewVaultName]=useState("");
  const [newVaultTokenType,setNewVaultTokenType]=useState("credit_card");
  const [newVaultFormat,setNewVaultFormat]=useState("format_preserving");
  const [newVaultCustomFormat,setNewVaultCustomFormat]=useState("");
  const [newVaultKeyId,setNewVaultKeyId]=useState("");
  const [newVaultRegex,setNewVaultRegex]=useState("");
  const [newVaultStorageType,setNewVaultStorageType]=useState("internal");
  const [newVaultProvider,setNewVaultProvider]=useState("postgres");
  const [newVaultHost,setNewVaultHost]=useState("");
  const [newVaultPort,setNewVaultPort]=useState("");
  const [newVaultDatabase,setNewVaultDatabase]=useState("");
  const [newVaultSchema,setNewVaultSchema]=useState("public");
  const [newVaultTable,setNewVaultTable]=useState("token_vault_records");
  const [newVaultUser,setNewVaultUser]=useState("");
  const [newVaultPasswordRef,setNewVaultPasswordRef]=useState("");
  const [newVaultTLSMode,setNewVaultTLSMode]=useState("require");
  const dataAlgoOptions=["AES-GCM","AES-SIV","CHACHA20-POLY1305"];
  const tokenTypes=["credit_card","ssn","iban","email","phone","custom"];
  const tokenFormats=["random","format_preserving","deterministic","irreversible","custom"];
  const redactionDetectors=["EMAIL","PHONE","SSN","PAN","IBAN","NAME","CUSTOM"];
  const redactionActions=["replace_placeholder","remove","hash"];
  const maskingRoles=["admin","auditor","analyst","support"];
  const maskingPatterns=["none","full","partial_last4","partial_first2","hash","substitute","nullify"];

  const parseCustomTokenFormats=(raw:string)=>{
    let parsed:any;
    try{
      parsed=JSON.parse(String(raw||"{}"));
    }catch{
      throw new Error("Custom token formats must be valid JSON.");
    }
    if(!parsed||Array.isArray(parsed)||typeof parsed!=="object"){
      throw new Error("Custom token formats must be a JSON object.");
    }
    const out:Record<string,string>={};
    Object.entries(parsed).forEach(([key,val])=>{
      const name=String(key||"").trim().toLowerCase().replace(/\s+/g,"_").replace(/[^a-z0-9_-]/g,"");
      if(!name){
        return;
      }
      const tpl=String(val||"").trim();
      if(!tpl){
        return;
      }
      out[name]=tpl.slice(0,512);
    });
    return out;
  };

  const refreshVaultRows=async(silent=false)=>{
    if(!session?.token){
      setVaultRows([]);
      return;
    }
    if(!silent){
      setRefreshingVaults(true);
    }
    try{
      const rows=await listTokenVaults(session,{limit:300,offset:0});
      setVaultRows(Array.isArray(rows)?rows:[]);
    }catch(error){
      if(!silent){
        onToast?.(`Token vault refresh failed: ${errMsg(error)}`);
      }
    }finally{
      if(!silent){
        setRefreshingVaults(false);
      }
    }
  };

  useEffect(()=>{
    void refreshVaultRows(true);
  },[session?.token,session?.tenantId]);

  const downloadVaultSetup=async()=>{
    if(!session?.token){
      onToast?.("Login is required.");
      return;
    }
    try{
      const item=await downloadTokenVaultExternalSchema(session,newVaultProvider as any);
      const content=String(item?.content||"");
      if(!content){
        throw new Error("External setup script is empty.");
      }
      const blob=new Blob([content],{type:String(item?.content_type||"text/plain")});
      const url=URL.createObjectURL(blob);
      const anchor=document.createElement("a");
      anchor.href=url;
      anchor.download=String(item?.filename||`token_vault_${newVaultProvider}.sql`);
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      onToast?.("External vault setup script downloaded.");
    }catch(error){
      onToast?.(`Setup script download failed: ${errMsg(error)}`);
    }
  };

  const createVaultFromPolicy=async()=>{
    if(!session?.token){
      onToast?.("Login is required.");
      return;
    }
    if(!String(newVaultName||"").trim()){
      onToast?.("Vault name is required.");
      return;
    }
    if(!String(newVaultKeyId||"").trim()){
      onToast?.("Key ID is required.");
      return;
    }
    if(String(newVaultFormat||"").trim()==="custom"&&!String(newVaultCustomFormat||"").trim()){
      onToast?.("Custom token format name is required when format is custom.");
      return;
    }
    if(String(newVaultTokenType||"").trim()==="custom"&&!String(newVaultRegex||"").trim()){
      onToast?.("Custom regex is required for custom token type.");
      return;
    }
    if(String(newVaultStorageType||"")==="external"){
      if(newVaultProvider==="mongodb"){
        if(!String(newVaultHost||"").trim()||!String(newVaultDatabase||"").trim()){
          onToast?.("MongoDB vault requires URI and database.");
          return;
        }
      }else if(!String(newVaultHost||"").trim()||!String(newVaultDatabase||"").trim()){
        onToast?.("External vault requires host and database.");
        return;
      }
    }
    setCreatingVault(true);
    try{
      const externalConfig=String(newVaultStorageType||"")==="external"
        ? (newVaultProvider==="mongodb"
            ? {
                uri:(()=>{
                  const raw=String(newVaultHost||"").trim();
                  if(/^mongodb(\+srv)?:\/\//i.test(raw)){
                    return raw;
                  }
                  return `mongodb://${raw}`;
                })(),
                database:String(newVaultDatabase||"").trim()||"vecta_token_vault",
                auth_database:String(newVaultSchema||"").trim()||"admin",
                table:String(newVaultTable||"").trim()||"token_vault_records",
                password_ref:String(newVaultPasswordRef||"").trim()
              }
            : {
                host:String(newVaultHost||"").trim(),
                port:String(newVaultPort||"").trim(),
                database:String(newVaultDatabase||"").trim(),
                schema:String(newVaultSchema||"").trim(),
                table:String(newVaultTable||"").trim(),
                username:String(newVaultUser||"").trim(),
                password_ref:String(newVaultPasswordRef||"").trim(),
                tls_mode:String(newVaultTLSMode||"").trim()
              })
        : undefined;
      const created=await createTokenVault(session,{
        name:String(newVaultName||"").trim(),
        token_type:String(newVaultTokenType||"").trim(),
        format:newVaultFormat as any,
        custom_token_format:String(newVaultCustomFormat||"").trim()||undefined,
        key_id:String(newVaultKeyId||"").trim(),
        custom_regex:String(newVaultRegex||"").trim()||undefined,
        storage_type:(newVaultStorageType==="external"?"external":"internal") as any,
        external_provider:newVaultStorageType==="external"?String(newVaultProvider||"").trim():undefined,
        external_config:externalConfig,
        external_schema_version:newVaultStorageType==="external"?"v1":undefined
      });
      onToast?.(`Token vault created: ${String(created?.id||"")}`);
      await refreshVaultRows(true);
      setNewVaultName("");
      setNewVaultRegex("");
      setNewVaultCustomFormat("");
    }catch(error){
      onToast?.(`Token vault creation failed: ${errMsg(error)}`);
    }finally{
      setCreatingVault(false);
    }
  };

  const deleteVaultFromPolicy=async(row:any)=>{
    const vaultID=String(row?.id||"").trim();
    if(!session?.token){
      onToast?.("Login is required.");
      return;
    }
    if(!vaultID){
      onToast?.("Vault ID is required.");
      return;
    }
    const storageType=String(row?.storage_type||"internal").toLowerCase();
    const targetLabel=storageType==="external"?"external vault connection":"internal token vault";
    if(typeof window!=="undefined"){
      const ok=window.confirm(`Delete ${targetLabel} ${String(row?.name||vaultID)}? This will remove local metadata and token mappings for this vault.`);
      if(!ok){
        return;
      }
    }
    setDeletingVaultId(vaultID);
    try{
      await deleteTokenVault(session,vaultID,{governanceApproved:true});
      onToast?.(storageType==="external"?"External vault connection deleted.":"Token vault deleted.");
      await refreshVaultRows(true);
    }catch(error){
      onToast?.(`Delete vault failed: ${errMsg(error)}`);
    }finally{
      setDeletingVaultId("");
    }
  };

  const loadPolicy=async(silent=false)=>{
    if(!session?.token){
      setDataPolicy(null);
      setCustomTokenFormatsText("{}");
      setVaultRows([]);
      return;
    }
    if(!silent){
      setLoading(true);
    }
    try{
      const dp=await getDataProtectionPolicy(session);
      setDataPolicy({
        tenant_id:String(dp?.tenant_id||session?.tenantId||""),
        allowed_data_algorithms:Array.isArray(dp?.allowed_data_algorithms)&&dp.allowed_data_algorithms.length?dp.allowed_data_algorithms:dataAlgoOptions,
        require_aad_for_aead:Boolean(dp?.require_aad_for_aead),
        max_fields_per_operation:Math.max(1,Number(dp?.max_fields_per_operation||64)),
        max_document_bytes:Math.max(1024,Number(dp?.max_document_bytes||262144)),
        allow_vaultless_tokenization:Boolean(dp?.allow_vaultless_tokenization),
        tokenization_mode_policy:dp?.tokenization_mode_policy&&typeof dp.tokenization_mode_policy==="object"?dp.tokenization_mode_policy:{
          credit_card:["vault","vaultless"],
          ssn:["vault","vaultless"],
          iban:["vault","vaultless"],
          email:["vault","vaultless"],
          phone:["vault","vaultless"],
          custom:["vault","vaultless"]
        },
        token_format_policy:dp?.token_format_policy&&typeof dp.token_format_policy==="object"?dp.token_format_policy:{
          credit_card:["format_preserving","deterministic","irreversible","random","custom"],
          ssn:["format_preserving","deterministic","irreversible","random","custom"],
          iban:["format_preserving","deterministic","irreversible","random","custom"],
          email:["format_preserving","deterministic","irreversible","random","custom"],
          phone:["format_preserving","deterministic","irreversible","random","custom"],
          custom:["format_preserving","deterministic","irreversible","random","custom"]
        },
        custom_token_formats:dp?.custom_token_formats&&typeof dp.custom_token_formats==="object"?dp.custom_token_formats:{},
        reuse_existing_token_for_same_input:Boolean(dp?.reuse_existing_token_for_same_input??true),
        enforce_unique_token_per_vault:Boolean(dp?.enforce_unique_token_per_vault??true),
        require_token_ttl:Boolean(dp?.require_token_ttl),
        max_token_ttl_hours:Math.max(0,Number(dp?.max_token_ttl_hours||0)),
        allow_token_renewal:Boolean(dp?.allow_token_renewal??true),
        max_token_renewals:Math.max(0,Number(dp?.max_token_renewals??3)),
        allow_one_time_tokens:Boolean(dp?.allow_one_time_tokens??true),
        detokenize_allowed_purposes:Array.isArray(dp?.detokenize_allowed_purposes)?dp.detokenize_allowed_purposes:[],
        detokenize_allowed_workflows:Array.isArray(dp?.detokenize_allowed_workflows)?dp.detokenize_allowed_workflows:[],
        require_detokenize_justification:Boolean(dp?.require_detokenize_justification),
        allow_bulk_tokenize:Boolean(dp?.allow_bulk_tokenize??true),
        allow_bulk_detokenize:Boolean(dp?.allow_bulk_detokenize??true),
        allow_redaction_detect_only:Boolean(dp?.allow_redaction_detect_only),
        allowed_redaction_detectors:Array.isArray(dp?.allowed_redaction_detectors)&&dp.allowed_redaction_detectors.length?dp.allowed_redaction_detectors:["EMAIL","PHONE","SSN","PAN","IBAN","NAME","CUSTOM"],
        allowed_redaction_actions:Array.isArray(dp?.allowed_redaction_actions)&&dp.allowed_redaction_actions.length?dp.allowed_redaction_actions:["replace_placeholder","remove","hash"],
        allow_custom_regex_tokens:Boolean(dp?.allow_custom_regex_tokens),
        max_custom_regex_length:Math.max(1,Number(dp?.max_custom_regex_length||512)),
        max_custom_regex_groups:Math.max(1,Number(dp?.max_custom_regex_groups||16)),
        max_token_batch:Math.max(1,Number(dp?.max_token_batch||10000)),
        max_detokenize_batch:Math.max(1,Number(dp?.max_detokenize_batch||10000)),
        require_token_context_tags:Boolean(dp?.require_token_context_tags),
        required_token_context_keys:Array.isArray(dp?.required_token_context_keys)?dp.required_token_context_keys:[],
        masking_role_policy:dp?.masking_role_policy&&typeof dp.masking_role_policy==="object"?dp.masking_role_policy:{admin:"none",auditor:"hash",analyst:"partial_last4",support:"partial_last4"},
        token_metadata_retention_days:Math.max(1,Number(dp?.token_metadata_retention_days||365)),
        redaction_event_retention_days:Math.max(1,Number(dp?.redaction_event_retention_days||365))
      });
      const customFormats=dp?.custom_token_formats&&typeof dp.custom_token_formats==="object"?dp.custom_token_formats:{};
      setCustomTokenFormatsText(JSON.stringify(customFormats,null,2));
    }catch(error){
      if(!silent){
        onToast?.(`Tokenize/mask/redact policy load failed: ${errMsg(error)}`);
      }
    }finally{
      if(!silent){
        setLoading(false);
      }
    }
  };

  useEffect(()=>{
    void loadPolicy();
  },[session?.token,session?.tenantId]);

  const savePolicy=async()=>{
    if(!session?.token){
      onToast?.("Login is required to update tokenize/mask/redact policy.");
      return;
    }
    if(!dataPolicy){
      onToast?.("Policy settings are not loaded.");
      return;
    }
    setSaving(true);
    try{
      const parsedCustomTokenFormats=parseCustomTokenFormats(customTokenFormatsText);
      const updated=await updateDataProtectionPolicy(session,{
        tenant_id:session.tenantId,
        allowed_data_algorithms:Array.isArray(dataPolicy?.allowed_data_algorithms)?dataPolicy.allowed_data_algorithms:dataAlgoOptions,
        require_aad_for_aead:Boolean(dataPolicy?.require_aad_for_aead),
        max_fields_per_operation:Math.max(1,Math.min(2048,Number(dataPolicy?.max_fields_per_operation||64))),
        max_document_bytes:Math.max(1024,Math.min(16777216,Number(dataPolicy?.max_document_bytes||262144))),
        allow_vaultless_tokenization:Boolean(dataPolicy?.allow_vaultless_tokenization),
        tokenization_mode_policy:dataPolicy?.tokenization_mode_policy&&typeof dataPolicy.tokenization_mode_policy==="object"?dataPolicy.tokenization_mode_policy:{},
        token_format_policy:dataPolicy?.token_format_policy&&typeof dataPolicy.token_format_policy==="object"?dataPolicy.token_format_policy:{},
        custom_token_formats:parsedCustomTokenFormats,
        reuse_existing_token_for_same_input:Boolean(dataPolicy?.reuse_existing_token_for_same_input??true),
        enforce_unique_token_per_vault:Boolean(dataPolicy?.enforce_unique_token_per_vault??true),
        require_token_ttl:Boolean(dataPolicy?.require_token_ttl),
        max_token_ttl_hours:Math.max(0,Math.min(87600,Number(dataPolicy?.max_token_ttl_hours||0))),
        allow_token_renewal:Boolean(dataPolicy?.allow_token_renewal),
        max_token_renewals:Math.max(0,Math.min(100,Number(dataPolicy?.max_token_renewals||3))),
        allow_one_time_tokens:Boolean(dataPolicy?.allow_one_time_tokens),
        detokenize_allowed_purposes:Array.isArray(dataPolicy?.detokenize_allowed_purposes)?dataPolicy.detokenize_allowed_purposes:[],
        detokenize_allowed_workflows:Array.isArray(dataPolicy?.detokenize_allowed_workflows)?dataPolicy.detokenize_allowed_workflows:[],
        require_detokenize_justification:Boolean(dataPolicy?.require_detokenize_justification),
        allow_bulk_tokenize:Boolean(dataPolicy?.allow_bulk_tokenize),
        allow_bulk_detokenize:Boolean(dataPolicy?.allow_bulk_detokenize),
        allow_redaction_detect_only:Boolean(dataPolicy?.allow_redaction_detect_only),
        allowed_redaction_detectors:Array.isArray(dataPolicy?.allowed_redaction_detectors)?dataPolicy.allowed_redaction_detectors:[],
        allowed_redaction_actions:Array.isArray(dataPolicy?.allowed_redaction_actions)?dataPolicy.allowed_redaction_actions:[],
        allow_custom_regex_tokens:Boolean(dataPolicy?.allow_custom_regex_tokens),
        max_custom_regex_length:Math.max(1,Math.min(4096,Number(dataPolicy?.max_custom_regex_length||512))),
        max_custom_regex_groups:Math.max(1,Math.min(128,Number(dataPolicy?.max_custom_regex_groups||16))),
        max_token_batch:Math.max(1,Math.min(100000,Number(dataPolicy?.max_token_batch||10000))),
        max_detokenize_batch:Math.max(1,Math.min(100000,Number(dataPolicy?.max_detokenize_batch||10000))),
        require_token_context_tags:Boolean(dataPolicy?.require_token_context_tags),
        required_token_context_keys:Array.isArray(dataPolicy?.required_token_context_keys)?dataPolicy.required_token_context_keys:[],
        masking_role_policy:dataPolicy?.masking_role_policy&&typeof dataPolicy.masking_role_policy==="object"?dataPolicy.masking_role_policy:{},
        token_metadata_retention_days:Math.max(1,Math.min(36500,Number(dataPolicy?.token_metadata_retention_days||365))),
        redaction_event_retention_days:Math.max(1,Math.min(36500,Number(dataPolicy?.redaction_event_retention_days||365))),
        updated_by:session?.username||"dashboard"
      });
      setDataPolicy((prev)=>({...prev,...updated}));
      setCustomTokenFormatsText(JSON.stringify(updated?.custom_token_formats||parsedCustomTokenFormats,null,2));
      onToast?.("Tokenize/mask/redact policy updated.");
    }catch(error){
      onToast?.(`Tokenize/mask/redact policy update failed: ${errMsg(error)}`);
    }finally{
      setSaving(false);
    }
  };

  return <div style={{display:"grid",gap:12}}>
    <Section title="Tokenize / Mask / Redact Policy" actions={<>
      <Btn small onClick={()=>void loadPolicy(false)} disabled={loading}>{loading?"Refreshing...":"Refresh"}</Btn>
      <Btn small primary onClick={savePolicy} disabled={saving||loading}>{saving?"Saving...":"Save Policy"}</Btn>
    </>}>
      <Card>
        <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:6}}>Policy Scope</div>
        <div style={{fontSize:10,color:C.dim,lineHeight:1.4}}>
          Controls tokenization behavior, masking/redaction modes, regex policy, and token lifetime constraints. Changes propagate to all wrappers, SDKs, and REST API consumers.
        </div>
      </Card>
    </Section>

    <Section title="Tokenize / Mask / Redact Controls">
      <Card style={{display:"grid",gap:12}}>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
          <Chk label="Allow vaultless tokenization globally" checked={Boolean(dataPolicy?.allow_vaultless_tokenization)} onChange={()=>setDataPolicy((prev)=>({...prev,allow_vaultless_tokenization:!Boolean(prev?.allow_vaultless_tokenization)}))}/>
          <Chk label="Reuse existing token for same plaintext input" checked={Boolean(dataPolicy?.reuse_existing_token_for_same_input??true)} onChange={()=>setDataPolicy((prev)=>({...prev,reuse_existing_token_for_same_input:!Boolean(prev?.reuse_existing_token_for_same_input??true)}))}/>
          <Chk label="Enforce unique token values per vault" checked={Boolean(dataPolicy?.enforce_unique_token_per_vault??true)} onChange={()=>setDataPolicy((prev)=>({...prev,enforce_unique_token_per_vault:!Boolean(prev?.enforce_unique_token_per_vault??true)}))}/>
          <Chk label="Require token TTL" checked={Boolean(dataPolicy?.require_token_ttl)} onChange={()=>setDataPolicy((prev)=>({...prev,require_token_ttl:!Boolean(prev?.require_token_ttl)}))}/>
          <Chk label="Allow token lease renewal" checked={Boolean(dataPolicy?.allow_token_renewal)} onChange={()=>setDataPolicy((prev)=>({...prev,allow_token_renewal:!Boolean(prev?.allow_token_renewal)}))}/>
          <Chk label="Allow one-time tokens" checked={Boolean(dataPolicy?.allow_one_time_tokens)} onChange={()=>setDataPolicy((prev)=>({...prev,allow_one_time_tokens:!Boolean(prev?.allow_one_time_tokens)}))}/>
          <Chk label="Allow custom regex tokens" checked={Boolean(dataPolicy?.allow_custom_regex_tokens)} onChange={()=>setDataPolicy((prev)=>({...prev,allow_custom_regex_tokens:!Boolean(prev?.allow_custom_regex_tokens)}))}/>
          <Chk label="Allow redaction detect-only mode" checked={Boolean(dataPolicy?.allow_redaction_detect_only)} onChange={()=>setDataPolicy((prev)=>({...prev,allow_redaction_detect_only:!Boolean(prev?.allow_redaction_detect_only)}))}/>
          <Chk label="Allow bulk tokenize" checked={Boolean(dataPolicy?.allow_bulk_tokenize)} onChange={()=>setDataPolicy((prev)=>({...prev,allow_bulk_tokenize:!Boolean(prev?.allow_bulk_tokenize)}))}/>
          <Chk label="Allow bulk detokenize" checked={Boolean(dataPolicy?.allow_bulk_detokenize)} onChange={()=>setDataPolicy((prev)=>({...prev,allow_bulk_detokenize:!Boolean(prev?.allow_bulk_detokenize)}))}/>
          <Chk label="Require context tags for token operations" checked={Boolean(dataPolicy?.require_token_context_tags)} onChange={()=>setDataPolicy((prev)=>({...prev,require_token_context_tags:!Boolean(prev?.require_token_context_tags)}))}/>
          <Chk label="Require detokenize justification" checked={Boolean(dataPolicy?.require_detokenize_justification)} onChange={()=>setDataPolicy((prev)=>({...prev,require_detokenize_justification:!Boolean(prev?.require_detokenize_justification)}))}/>
        </div>

        <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:10}}>
          <FG label="Max token TTL (hours, 0=unlimited)">
            <Inp type="number" min={0} max={87600} value={String(dataPolicy?.max_token_ttl_hours??0)} onChange={(e)=>setDataPolicy((prev)=>({...prev,max_token_ttl_hours:Number(e.target.value||0)}))}/>
          </FG>
          <FG label="Max token renewals">
            <Inp type="number" min={0} max={100} value={String(dataPolicy?.max_token_renewals??3)} onChange={(e)=>setDataPolicy((prev)=>({...prev,max_token_renewals:Number(e.target.value||3)}))}/>
          </FG>
          <FG label="Max tokenize batch size">
            <Inp type="number" min={1} max={100000} value={String(dataPolicy?.max_token_batch??10000)} onChange={(e)=>setDataPolicy((prev)=>({...prev,max_token_batch:Number(e.target.value||10000)}))}/>
          </FG>
          <FG label="Max detokenize batch size">
            <Inp type="number" min={1} max={100000} value={String(dataPolicy?.max_detokenize_batch??10000)} onChange={(e)=>setDataPolicy((prev)=>({...prev,max_detokenize_batch:Number(e.target.value||10000)}))}/>
          </FG>
          <FG label="Max custom regex length">
            <Inp type="number" min={1} max={4096} value={String(dataPolicy?.max_custom_regex_length??512)} onChange={(e)=>setDataPolicy((prev)=>({...prev,max_custom_regex_length:Number(e.target.value||512)}))}/>
          </FG>
          <FG label="Max custom regex capture groups">
            <Inp type="number" min={1} max={128} value={String(dataPolicy?.max_custom_regex_groups??16)} onChange={(e)=>setDataPolicy((prev)=>({...prev,max_custom_regex_groups:Number(e.target.value||16)}))}/>
          </FG>
          <FG label="Token metadata retention (days)">
            <Inp type="number" min={1} max={36500} value={String(dataPolicy?.token_metadata_retention_days??365)} onChange={(e)=>setDataPolicy((prev)=>({...prev,token_metadata_retention_days:Number(e.target.value||365)}))}/>
          </FG>
          <FG label="Redaction event retention (days)">
            <Inp type="number" min={1} max={36500} value={String(dataPolicy?.redaction_event_retention_days??365)} onChange={(e)=>setDataPolicy((prev)=>({...prev,redaction_event_retention_days:Number(e.target.value||365)}))}/>
          </FG>
        </div>

        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
          <FG label="Detokenize allowed purposes (comma separated)">
            <Inp
              value={Array.isArray(dataPolicy?.detokenize_allowed_purposes)?dataPolicy.detokenize_allowed_purposes.join(", "):""}
              onChange={(e)=>setDataPolicy((prev)=>({...prev,detokenize_allowed_purposes:String(e.target.value||"").split(",").map((v)=>v.trim()).filter(Boolean)}))}
              placeholder="support-case, forensic, payment-dispute"
            />
          </FG>
          <FG label="Detokenize allowed workflows (comma separated)">
            <Inp
              value={Array.isArray(dataPolicy?.detokenize_allowed_workflows)?dataPolicy.detokenize_allowed_workflows.join(", "):""}
              onChange={(e)=>setDataPolicy((prev)=>({...prev,detokenize_allowed_workflows:String(e.target.value||"").split(",").map((v)=>v.trim()).filter(Boolean)}))}
              placeholder="incident-response, customer-support"
            />
          </FG>
          <FG label="Required context tag keys (comma separated)">
            <Inp
              value={Array.isArray(dataPolicy?.required_token_context_keys)?dataPolicy.required_token_context_keys.join(", "):""}
              onChange={(e)=>setDataPolicy((prev)=>({...prev,required_token_context_keys:String(e.target.value||"").split(",").map((v)=>v.trim()).filter(Boolean)}))}
              placeholder="dataset, region, consent"
            />
          </FG>
        </div>

        <div style={{display:"grid",gap:6}}>
          <div style={{fontSize:11,color:C.text,fontWeight:700}}>Tokenization Mode Policy (by data type)</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8}}>
            {tokenTypes.map((tokenType)=>(
              <div key={`mode-policy-${tokenType}`} style={{display:"grid",gridTemplateColumns:"1fr auto auto",alignItems:"center",gap:8,border:`1px solid ${C.line}`,borderRadius:10,padding:"8px 10px"}}>
                <div style={{fontSize:12,color:C.text}}>{tokenType}</div>
                <Chk
                  label="Vault"
                  checked={Array.isArray(dataPolicy?.tokenization_mode_policy?.[tokenType])&&dataPolicy.tokenization_mode_policy[tokenType].includes("vault")}
                  onChange={()=>setDataPolicy((prev)=>{
                    const current=Array.isArray(prev?.tokenization_mode_policy?.[tokenType])?[...prev.tokenization_mode_policy[tokenType]]:[];
                    const next=current.includes("vault")?current.filter((m)=>m!=="vault"):[...current,"vault"];
                    return {...prev,tokenization_mode_policy:{...(prev?.tokenization_mode_policy||{}),[tokenType]:next}};
                  })}
                />
                <Chk
                  label="Vaultless"
                  checked={Array.isArray(dataPolicy?.tokenization_mode_policy?.[tokenType])&&dataPolicy.tokenization_mode_policy[tokenType].includes("vaultless")}
                  onChange={()=>setDataPolicy((prev)=>{
                    const current=Array.isArray(prev?.tokenization_mode_policy?.[tokenType])?[...prev.tokenization_mode_policy[tokenType]]:[];
                    const next=current.includes("vaultless")?current.filter((m)=>m!=="vaultless"):[...current,"vaultless"];
                    return {...prev,tokenization_mode_policy:{...(prev?.tokenization_mode_policy||{}),[tokenType]:next}};
                  })}
                />
              </div>
            ))}
          </div>
        </div>

        <div style={{display:"grid",gap:6}}>
          <div style={{fontSize:11,color:C.text,fontWeight:700}}>Token Format Policy (by data type)</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8}}>
            {tokenTypes.map((tokenType)=>(
              <div key={`fmt-policy-${tokenType}`} style={{border:`1px solid ${C.line}`,borderRadius:10,padding:"8px 10px"}}>
                <div style={{fontSize:12,color:C.text,marginBottom:6}}>{tokenType}</div>
                <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:6}}>
                  {tokenFormats.map((format)=>(
                    <Chk
                      key={`fmt-policy-${tokenType}-${format}`}
                      label={format}
                      checked={Array.isArray(dataPolicy?.token_format_policy?.[tokenType])&&dataPolicy.token_format_policy[tokenType].includes(format)}
                      onChange={()=>setDataPolicy((prev)=>{
                        const current=Array.isArray(prev?.token_format_policy?.[tokenType])?[...prev.token_format_policy[tokenType]]:[];
                        const next=current.includes(format)?current.filter((f)=>f!==format):[...current,format];
                        return {...prev,token_format_policy:{...(prev?.token_format_policy||{}),[tokenType]:next}};
                      })}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div style={{display:"grid",gap:6}}>
          <div style={{fontSize:11,color:C.text,fontWeight:700}}>Custom Token Format Definitions</div>
          <div style={{fontSize:10,color:C.dim}}>Define named token templates (JSON map). Supported placeholders: <code>{"{{HASH8}}"}</code>, <code>{"{{HASH12}}"}</code>, <code>{"{{HASH16}}"}</code>, <code>{"{{LAST4}}"}</code>, <code>{"{{LEN}}"}</code>, <code>{"{{RAND8}}"}</code>, <code>{"{{RAND12}}"}</code>, <code>{"{{VALUE}}"}</code>.</div>
          <Txt rows={6} value={customTokenFormatsText} onChange={(e)=>setCustomTokenFormatsText(e.target.value)} placeholder={`{\n  "pan_enterprise": "PAN-{{HASH12}}-{{LAST4}}"\n}`} mono/>
        </div>

        <div style={{display:"grid",gap:6}}>
          <div style={{fontSize:11,color:C.text,fontWeight:700}}>Masking Role Policy</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8}}>
            {maskingRoles.map((role)=>(
              <FG key={`mask-role-${role}`} label={role}>
                <Sel
                  value={String(dataPolicy?.masking_role_policy?.[role]||"partial_last4")}
                  onChange={(e)=>setDataPolicy((prev)=>({...prev,masking_role_policy:{...(prev?.masking_role_policy||{}),[role]:String(e.target.value||"partial_last4")}}))}
                >
                  {maskingPatterns.map((pattern)=><option key={`mask-pattern-${role}-${pattern}`} value={pattern}>{pattern}</option>)}
                </Sel>
              </FG>
            ))}
          </div>
        </div>

        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
          <div>
            <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:6}}>Allowed Redaction Detectors</div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:6}}>
              {redactionDetectors.map((detector)=>(
                <Chk
                  key={`detector-${detector}`}
                  label={detector}
                  checked={Array.isArray(dataPolicy?.allowed_redaction_detectors)&&dataPolicy.allowed_redaction_detectors.includes(detector)}
                  onChange={()=>setDataPolicy((prev)=>{
                    const current=Array.isArray(prev?.allowed_redaction_detectors)?[...prev.allowed_redaction_detectors]:[];
                    const next=current.includes(detector)?current.filter((d)=>d!==detector):[...current,detector];
                    return {...prev,allowed_redaction_detectors:next};
                  })}
                />
              ))}
            </div>
          </div>
          <div>
            <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:6}}>Allowed Redaction Actions</div>
            <div style={{display:"grid",gap:6}}>
              {redactionActions.map((action)=>(
                <Chk
                  key={`redact-action-${action}`}
                  label={action}
                  checked={Array.isArray(dataPolicy?.allowed_redaction_actions)&&dataPolicy.allowed_redaction_actions.includes(action)}
                  onChange={()=>setDataPolicy((prev)=>{
                    const current=Array.isArray(prev?.allowed_redaction_actions)?[...prev.allowed_redaction_actions]:[];
                    const next=current.includes(action)?current.filter((a)=>a!==action):[...current,action];
                    return {...prev,allowed_redaction_actions:next};
                  })}
                />
              ))}
            </div>
          </div>
        </div>

        <div style={{display:"grid",gap:8,border:`1px solid ${C.border}`,borderRadius:10,padding:10}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8,flexWrap:"wrap"}}>
            <div style={{fontSize:11,color:C.text,fontWeight:700}}>Create Token Vault (from Policy)</div>
            <div style={{display:"flex",gap:8}}>
              <Btn small onClick={()=>void refreshVaultRows(false)} disabled={refreshingVaults||creatingVault}>{refreshingVaults?"Refreshing...":"Refresh Vaults"}</Btn>
              {newVaultStorageType==="external"&&<Btn small onClick={()=>void downloadVaultSetup()} disabled={creatingVault}>Download Setup Query</Btn>}
              <Btn small primary onClick={()=>void createVaultFromPolicy()} disabled={creatingVault||refreshingVaults}>{creatingVault?"Creating...":"Create Vault"}</Btn>
            </div>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8}}>
            <FG label="Vault Name" required><Inp value={newVaultName} onChange={(e)=>setNewVaultName(e.target.value)} placeholder="customer-data-vault"/></FG>
            <FG label="Token Type" required>
              <Sel value={newVaultTokenType} onChange={(e)=>setNewVaultTokenType(e.target.value)}>
                {tokenTypes.map((tokenType)=><option key={`policy-vault-token-type-${tokenType}`} value={tokenType}>{tokenType}</option>)}
              </Sel>
            </FG>
            <FG label="Token Format" required>
              <Sel value={newVaultFormat} onChange={(e)=>setNewVaultFormat(e.target.value)}>
                {tokenFormats.map((format)=><option key={`policy-vault-format-${format}`} value={format}>{format}</option>)}
              </Sel>
            </FG>
            {newVaultFormat==="custom"&&<FG label="Custom Format Name" required><Inp value={newVaultCustomFormat} onChange={(e)=>setNewVaultCustomFormat(e.target.value)} placeholder="pan_enterprise"/></FG>}
            {newVaultTokenType==="custom"&&<FG label="Custom Regex" required><Inp value={newVaultRegex} onChange={(e)=>setNewVaultRegex(e.target.value)} placeholder="^\\d{3}-\\d{2}-\\d{4}$" mono/></FG>}
            <FG label="Key ID" required><Inp value={newVaultKeyId} onChange={(e)=>setNewVaultKeyId(e.target.value)} placeholder="key-1" mono/></FG>
            <FG label="Storage Type">
              <Sel value={newVaultStorageType} onChange={(e)=>setNewVaultStorageType(e.target.value==="external"?"external":"internal")}>
                <option value="internal">Internal KMS vault DB</option>
                <option value="external">External DB vault</option>
              </Sel>
            </FG>
            {newVaultStorageType==="external"&&<FG label="External Provider" required>
              <Sel value={newVaultProvider} onChange={(e)=>setNewVaultProvider(e.target.value)}>
                <option value="postgres">PostgreSQL</option>
                <option value="mysql">MySQL</option>
                <option value="mssql">MSSQL</option>
                <option value="oracle">Oracle</option>
                <option value="mongodb">MongoDB</option>
              </Sel>
            </FG>}
            {newVaultStorageType==="external"&&newVaultProvider!=="mongodb"&&<FG label="Host" required><Inp value={newVaultHost} onChange={(e)=>setNewVaultHost(e.target.value)} placeholder="db.example.com"/></FG>}
            {newVaultStorageType==="external"&&newVaultProvider!=="mongodb"&&<FG label="Port"><Inp value={newVaultPort} onChange={(e)=>setNewVaultPort(e.target.value)} placeholder="5432"/></FG>}
            {newVaultStorageType==="external"&&newVaultProvider!=="mongodb"&&<FG label="Database" required><Inp value={newVaultDatabase} onChange={(e)=>setNewVaultDatabase(e.target.value)} placeholder="vecta_token_vault"/></FG>}
            {newVaultStorageType==="external"&&newVaultProvider!=="mongodb"&&<FG label="Schema"><Inp value={newVaultSchema} onChange={(e)=>setNewVaultSchema(e.target.value)} placeholder="public"/></FG>}
            {newVaultStorageType==="external"&&newVaultProvider!=="mongodb"&&<FG label="Table"><Inp value={newVaultTable} onChange={(e)=>setNewVaultTable(e.target.value)} placeholder="token_vault_records"/></FG>}
            {newVaultStorageType==="external"&&newVaultProvider!=="mongodb"&&<FG label="Username"><Inp value={newVaultUser} onChange={(e)=>setNewVaultUser(e.target.value)} placeholder="vault_user"/></FG>}
            {newVaultStorageType==="external"&&newVaultProvider==="mongodb"&&<FG label="MongoDB URI" required><Inp value={newVaultHost} onChange={(e)=>setNewVaultHost(e.target.value)} placeholder="mongodb://mongo.example.com:27017"/></FG>}
            {newVaultStorageType==="external"&&newVaultProvider==="mongodb"&&<FG label="Database" required><Inp value={newVaultDatabase} onChange={(e)=>setNewVaultDatabase(e.target.value)} placeholder="vecta_token_vault"/></FG>}
            {newVaultStorageType==="external"&&newVaultProvider==="mongodb"&&<FG label="Auth Database"><Inp value={newVaultSchema} onChange={(e)=>setNewVaultSchema(e.target.value)} placeholder="admin"/></FG>}
            {newVaultStorageType==="external"&&newVaultProvider==="mongodb"&&<FG label="Collection"><Inp value={newVaultTable} onChange={(e)=>setNewVaultTable(e.target.value)} placeholder="token_vault_records"/></FG>}
            {newVaultStorageType==="external"&&<FG label="Password Secret Ref" hint="Store DB password in KMS secret vault and reference it here."><Inp value={newVaultPasswordRef} onChange={(e)=>setNewVaultPasswordRef(e.target.value)} placeholder="secret://db/token-vault-password"/></FG>}
            {newVaultStorageType==="external"&&newVaultProvider!=="mongodb"&&<FG label="TLS Mode"><Inp value={newVaultTLSMode} onChange={(e)=>setNewVaultTLSMode(e.target.value)} placeholder="require"/></FG>}
          </div>
          <div style={{fontSize:10,color:C.dim}}>Vault tokens store token, token hash, ciphertext, original hash, metadata and lifecycle counters for deterministic lookup and detokenize controls.</div>
          <div style={{fontSize:10,color:C.text,fontWeight:700}}>Existing token vaults: {Array.isArray(vaultRows)?vaultRows.length:0}</div>
          <div style={{maxHeight:180,overflowY:"auto",border:`1px solid ${C.border}`,borderRadius:8,padding:8,display:"grid",gap:6}}>
            {(Array.isArray(vaultRows)?vaultRows:[]).map((row:any)=>{
              const id=String(row?.id||"");
              const storageType=String(row?.storage_type||"internal").toLowerCase();
              const isExternal=storageType==="external";
              return <div key={`policy-vault-row-${id}`} style={{display:"flex",justifyContent:"space-between",gap:8,alignItems:"center",border:`1px solid ${C.line}`,borderRadius:8,padding:"6px 8px"}}>
                <div style={{fontSize:10,color:C.text}}>
                  {`${String(row?.name||"")} (${id}) - ${String(row?.token_type||"")}/${String(row?.format||"")} - ${storageType}${String(row?.external_provider||"").trim()?`:${String(row?.external_provider||"")}`:""}`}
                </div>
                <Btn
                  small
                  onClick={()=>void deleteVaultFromPolicy(row)}
                  disabled={Boolean(deletingVaultId)||creatingVault||refreshingVaults}
                >
                  {deletingVaultId===id
                    ? "Deleting..."
                    : (isExternal?"Delete Connection":"Delete Vault")}
                </Btn>
              </div>;
            })}
            {!Array.isArray(vaultRows)||!vaultRows.length?<div style={{fontSize:10,color:C.dim}}>No token vaults found for this tenant.</div>:null}
          </div>
        </div>
      </Card>
    </Section>
  </div>;
};

const PaymentCryptoPolicy=({session,onToast})=>{
  const [loading,setLoading]=useState(false);
  const [saving,setSaving]=useState(false);
  const [payPolicy,setPayPolicy]=useState<any>(null);
  const [tr31ExportabilityMatrixText,setTR31ExportabilityMatrixText]=useState("{}");
  const [paymentKeyPurposeMatrixText,setPaymentKeyPurposeMatrixText]=useState("{}");
  const [rotationDaysByClassText,setRotationDaysByClassText]=useState("{}");
  const [pinTranslationPairsText,setPINTranslationPairsText]=useState("");
  const [cvvServiceCodesText,setCVVServiceCodesText]=useState("");
  const [issuerProfilesText,setIssuerProfilesText]=useState("");
  const tr31VersionOptions=["B","C","D"];
  const paymentKeyClassOptions=["ZMK","TMK","TPK","BMK","BDK","IPEK","ZPK","ZAK","ZEK","TAK","CVK","PVK","KBPK"];
  const tr31ExportabilityOptions=["E","N","S"];
  const isoCanonicalizationOptions=["exc-c14n","c14n11"];
  const isoSignatureSuiteOptions=["rsa-pss-sha256","rsa-pkcs1-sha256","ecdsa-sha256","ecdsa-sha384"];
  const macDomainOptions=["retail","iso9797","cmac"];
  const macPaddingOptions=["ansi-x9.19-m1","iso9797-m2","cmac"];
  const tcpOperationOptions=[
    "tr31.create","tr31.parse","tr31.translate","tr31.validate","tr31.key-usages",
    "pin.translate","pin.pvv.generate","pin.pvv.verify","pin.offset.generate","pin.offset.verify","pin.cvv.compute","pin.cvv.verify",
    "mac.retail","mac.iso9797","mac.cmac","mac.verify",
    "iso20022.sign","iso20022.verify","iso20022.encrypt","iso20022.decrypt","iso20022.lau.generate","iso20022.lau.verify"
  ];
  const sensitiveOperationOptions=[...tcpOperationOptions,"key.rotate"];
  const pinFormatOptions=["ISO-0","ISO-1","ISO-3"];

  const toggleStringList=(list:string[]|undefined,value:string)=>{
    const current=Array.isArray(list)?[...list]:[];
    return current.includes(value)?current.filter((item)=>item!==value):[...current,value];
  };

  const parseCSVList=(raw:string)=>{
    return Array.from(new Set(
      String(raw||"")
        .split(/[\n,]/g)
        .map((v)=>String(v||"").trim())
        .filter(Boolean)
    ));
  };

  const toPrettyJSON=(input:any)=>{
    const value=input&&typeof input==="object"&&!Array.isArray(input)?input:{};
    try{
      return JSON.stringify(value,null,2);
    }catch{
      return "{}";
    }
  };

  const parseStringArrayMap=(raw:string,label:string):Record<string,string[]>=>{
    let parsed:any;
    try{
      parsed=JSON.parse(String(raw||"{}"));
    }catch{
      throw new Error(`${label} must be valid JSON object.`);
    }
    if(!parsed||Array.isArray(parsed)||typeof parsed!=="object"){
      throw new Error(`${label} must be a JSON object.`);
    }
    const out:Record<string,string[]>={};
    Object.entries(parsed).forEach(([key,val])=>{
      const mapKey=String(key||"").trim();
      if(!mapKey){
        return;
      }
      if(!Array.isArray(val)){
        throw new Error(`${label}.${mapKey} must be an array of strings.`);
      }
      const normalized=Array.from(new Set(val.map((item)=>String(item||"").trim()).filter(Boolean)));
      if(normalized.length){
        out[mapKey]=normalized;
      }
    });
    return out;
  };

  const parseStringIntMap=(raw:string,label:string):Record<string,number>=>{
    let parsed:any;
    try{
      parsed=JSON.parse(String(raw||"{}"));
    }catch{
      throw new Error(`${label} must be valid JSON object.`);
    }
    if(!parsed||Array.isArray(parsed)||typeof parsed!=="object"){
      throw new Error(`${label} must be a JSON object.`);
    }
    const out:Record<string,number>={};
    Object.entries(parsed).forEach(([key,val])=>{
      const mapKey=String(key||"").trim();
      if(!mapKey){
        return;
      }
      const parsedNum=Math.floor(Number(val));
      if(!Number.isFinite(parsedNum)||parsedNum<=0){
        throw new Error(`${label}.${mapKey} must be a positive integer.`);
      }
      out[mapKey]=parsedNum;
    });
    return out;
  };

  const loadPolicy=async(silent=false)=>{
    if(!session?.token){
      setPayPolicy(null);
      setTR31ExportabilityMatrixText("{}");
      setPaymentKeyPurposeMatrixText("{}");
      setRotationDaysByClassText("{}");
      setPINTranslationPairsText("");
      setCVVServiceCodesText("");
      setIssuerProfilesText("");
      return;
    }
    if(!silent){
      setLoading(true);
    }
    try{
      const pp=await getPaymentPolicy(session);
      setPayPolicy({
        tenant_id:String(pp?.tenant_id||session?.tenantId||""),
        allowed_tr31_versions:Array.isArray(pp?.allowed_tr31_versions)&&pp.allowed_tr31_versions.length?pp.allowed_tr31_versions:tr31VersionOptions,
        require_kbpk_for_tr31:Boolean(pp?.require_kbpk_for_tr31),
        allowed_kbpk_classes:Array.isArray(pp?.allowed_kbpk_classes)?pp.allowed_kbpk_classes:[],
        allowed_tr31_exportability:Array.isArray(pp?.allowed_tr31_exportability)&&pp.allowed_tr31_exportability.length?pp.allowed_tr31_exportability:tr31ExportabilityOptions,
        allow_inline_key_material:Boolean(pp?.allow_inline_key_material),
        max_iso20022_payload_bytes:Math.max(1024,Number(pp?.max_iso20022_payload_bytes||262144)),
        require_iso20022_lau_context:Boolean(pp?.require_iso20022_lau_context),
        allowed_iso20022_canonicalization:Array.isArray(pp?.allowed_iso20022_canonicalization)?pp.allowed_iso20022_canonicalization:[],
        allowed_iso20022_signature_suites:Array.isArray(pp?.allowed_iso20022_signature_suites)?pp.allowed_iso20022_signature_suites:[],
        strict_pci_dss_4_0:Boolean(pp?.strict_pci_dss_4_0),
        require_key_id_for_operations:Boolean(pp?.require_key_id_for_operations),
        allow_tcp_interface:Boolean(pp?.allow_tcp_interface??true),
        require_jwt_on_tcp:Boolean(pp?.require_jwt_on_tcp??true),
        max_tcp_payload_bytes:Math.max(4096,Number(pp?.max_tcp_payload_bytes||262144)),
        allowed_tcp_operations:Array.isArray(pp?.allowed_tcp_operations)&&pp.allowed_tcp_operations.length?pp.allowed_tcp_operations:tcpOperationOptions,
        allowed_pin_block_formats:Array.isArray(pp?.allowed_pin_block_formats)&&pp.allowed_pin_block_formats.length?pp.allowed_pin_block_formats:pinFormatOptions,
        allowed_pin_translation_pairs:Array.isArray(pp?.allowed_pin_translation_pairs)?pp.allowed_pin_translation_pairs:[],
        disable_iso0_pin_block:Boolean(pp?.disable_iso0_pin_block),
        allowed_cvv_service_codes:Array.isArray(pp?.allowed_cvv_service_codes)?pp.allowed_cvv_service_codes:[],
        pvki_min:Number.isFinite(Number(pp?.pvki_min))?Math.max(0,Math.min(9,Number(pp?.pvki_min))):0,
        pvki_max:Number.isFinite(Number(pp?.pvki_max))?Math.max(0,Math.min(9,Number(pp?.pvki_max))):9,
        allowed_issuer_profiles:Array.isArray(pp?.allowed_issuer_profiles)?pp.allowed_issuer_profiles:[],
        allowed_mac_domains:Array.isArray(pp?.allowed_mac_domains)?pp.allowed_mac_domains:[],
        allowed_mac_padding_profiles:Array.isArray(pp?.allowed_mac_padding_profiles)?pp.allowed_mac_padding_profiles:[],
        dual_control_required_operations:Array.isArray(pp?.dual_control_required_operations)?pp.dual_control_required_operations:[],
        hsm_required_operations:Array.isArray(pp?.hsm_required_operations)?pp.hsm_required_operations:[],
        runtime_environment:String(pp?.runtime_environment||"prod").toLowerCase()==="test"?"test":"prod",
        disallow_test_keys_in_prod:Boolean(pp?.disallow_test_keys_in_prod),
        disallow_prod_keys_in_test:Boolean(pp?.disallow_prod_keys_in_test),
        decimalization_table:String(pp?.decimalization_table||"0123456789012345"),
        block_wildcard_pan:Boolean(pp?.block_wildcard_pan??true)
      });
      setTR31ExportabilityMatrixText(toPrettyJSON(pp?.tr31_exportability_matrix));
      setPaymentKeyPurposeMatrixText(toPrettyJSON(pp?.payment_key_purpose_matrix));
      setRotationDaysByClassText(toPrettyJSON(pp?.rotation_interval_days_by_class));
      setPINTranslationPairsText(Array.isArray(pp?.allowed_pin_translation_pairs)?pp.allowed_pin_translation_pairs.join(", "):"");
      setCVVServiceCodesText(Array.isArray(pp?.allowed_cvv_service_codes)?pp.allowed_cvv_service_codes.join(", "):"");
      setIssuerProfilesText(Array.isArray(pp?.allowed_issuer_profiles)?pp.allowed_issuer_profiles.join(", "):"");
    }catch(error){
      if(!silent){
        onToast?.(`Payment policy load failed: ${errMsg(error)}`);
      }
    }finally{
      if(!silent){
        setLoading(false);
      }
    }
  };

  useEffect(()=>{
    void loadPolicy();
  },[session?.token,session?.tenantId]);

  const savePolicy=async()=>{
    if(!session?.token){
      onToast?.("Login is required to update payment policy.");
      return;
    }
    if(!payPolicy){
      onToast?.("Policy settings are not loaded.");
      return;
    }
    let parsedTR31Matrix:Record<string,string[]>={};
    let parsedPurposeMatrix:Record<string,string[]>={};
    let parsedRotationByClass:Record<string,number>={};
    try{
      parsedTR31Matrix=parseStringArrayMap(tr31ExportabilityMatrixText,"TR-31 exportability matrix");
      parsedPurposeMatrix=parseStringArrayMap(paymentKeyPurposeMatrixText,"Payment key purpose matrix");
      parsedRotationByClass=parseStringIntMap(rotationDaysByClassText,"Rotation interval by class");
    }catch(parseError){
      onToast?.(errMsg(parseError));
      return;
    }
    const pvkiMin=Math.max(0,Math.min(9,Math.floor(Number(payPolicy?.pvki_min||0))));
    const pvkiMax=Math.max(0,Math.min(9,Math.floor(Number(payPolicy?.pvki_max||9))));
    if(pvkiMin>pvkiMax){
      onToast?.("PVKI min cannot be greater than PVKI max.");
      return;
    }
    setSaving(true);
    try{
      const updated=await updatePaymentPolicy(session,{
        tenant_id:session.tenantId,
        allowed_tr31_versions:Array.isArray(payPolicy?.allowed_tr31_versions)?payPolicy.allowed_tr31_versions:tr31VersionOptions,
        require_kbpk_for_tr31:Boolean(payPolicy?.require_kbpk_for_tr31),
        allowed_kbpk_classes:Array.isArray(payPolicy?.allowed_kbpk_classes)?payPolicy.allowed_kbpk_classes:[],
        allowed_tr31_exportability:Array.isArray(payPolicy?.allowed_tr31_exportability)?payPolicy.allowed_tr31_exportability:tr31ExportabilityOptions,
        tr31_exportability_matrix:parsedTR31Matrix,
        payment_key_purpose_matrix:parsedPurposeMatrix,
        allow_inline_key_material:Boolean(payPolicy?.allow_inline_key_material),
        max_iso20022_payload_bytes:Math.max(1024,Math.min(4194304,Number(payPolicy?.max_iso20022_payload_bytes||262144))),
        require_iso20022_lau_context:Boolean(payPolicy?.require_iso20022_lau_context),
        allowed_iso20022_canonicalization:Array.isArray(payPolicy?.allowed_iso20022_canonicalization)?payPolicy.allowed_iso20022_canonicalization:[],
        allowed_iso20022_signature_suites:Array.isArray(payPolicy?.allowed_iso20022_signature_suites)?payPolicy.allowed_iso20022_signature_suites:[],
        strict_pci_dss_4_0:Boolean(payPolicy?.strict_pci_dss_4_0),
        require_key_id_for_operations:Boolean(payPolicy?.require_key_id_for_operations),
        allow_tcp_interface:Boolean(payPolicy?.allow_tcp_interface),
        require_jwt_on_tcp:Boolean(payPolicy?.require_jwt_on_tcp),
        max_tcp_payload_bytes:Math.max(4096,Math.min(1048576,Number(payPolicy?.max_tcp_payload_bytes||262144))),
        allowed_tcp_operations:Array.isArray(payPolicy?.allowed_tcp_operations)?payPolicy.allowed_tcp_operations:tcpOperationOptions,
        allowed_pin_block_formats:Array.isArray(payPolicy?.allowed_pin_block_formats)?payPolicy.allowed_pin_block_formats:pinFormatOptions,
        allowed_pin_translation_pairs:parseCSVList(pinTranslationPairsText),
        disable_iso0_pin_block:Boolean(payPolicy?.disable_iso0_pin_block),
        allowed_cvv_service_codes:parseCSVList(cvvServiceCodesText),
        pvki_min:pvkiMin,
        pvki_max:pvkiMax,
        allowed_issuer_profiles:parseCSVList(issuerProfilesText),
        allowed_mac_domains:Array.isArray(payPolicy?.allowed_mac_domains)?payPolicy.allowed_mac_domains:[],
        allowed_mac_padding_profiles:Array.isArray(payPolicy?.allowed_mac_padding_profiles)?payPolicy.allowed_mac_padding_profiles:[],
        dual_control_required_operations:Array.isArray(payPolicy?.dual_control_required_operations)?payPolicy.dual_control_required_operations:[],
        hsm_required_operations:Array.isArray(payPolicy?.hsm_required_operations)?payPolicy.hsm_required_operations:[],
        rotation_interval_days_by_class:parsedRotationByClass,
        runtime_environment:String(payPolicy?.runtime_environment||"prod").toLowerCase()==="test"?"test":"prod",
        disallow_test_keys_in_prod:Boolean(payPolicy?.disallow_test_keys_in_prod),
        disallow_prod_keys_in_test:Boolean(payPolicy?.disallow_prod_keys_in_test),
        decimalization_table:String(payPolicy?.decimalization_table||"0123456789012345").trim(),
        block_wildcard_pan:Boolean(payPolicy?.block_wildcard_pan),
        updated_by:session?.username||"dashboard"
      });
      setPayPolicy((prev)=>({...prev,...updated}));
      setTR31ExportabilityMatrixText(toPrettyJSON(updated?.tr31_exportability_matrix));
      setPaymentKeyPurposeMatrixText(toPrettyJSON(updated?.payment_key_purpose_matrix));
      setRotationDaysByClassText(toPrettyJSON(updated?.rotation_interval_days_by_class));
      setPINTranslationPairsText(Array.isArray(updated?.allowed_pin_translation_pairs)?updated.allowed_pin_translation_pairs.join(", "):"");
      setCVVServiceCodesText(Array.isArray(updated?.allowed_cvv_service_codes)?updated.allowed_cvv_service_codes.join(", "):"");
      setIssuerProfilesText(Array.isArray(updated?.allowed_issuer_profiles)?updated.allowed_issuer_profiles.join(", "):"");
      onToast?.("Payment policy updated.");
    }catch(error){
      onToast?.(`Payment policy update failed: ${errMsg(error)}`);
    }finally{
      setSaving(false);
    }
  };

  return <div style={{display:"grid",gap:12}}>
    <Section title="Payment Policy" actions={<>
      <Btn small onClick={()=>void loadPolicy(false)} disabled={loading}>{loading?"Refreshing...":"Refresh"}</Btn>
      <Btn small primary onClick={savePolicy} disabled={saving||loading}>{saving?"Saving...":"Save Policy"}</Btn>
    </>}>
      <Card>
        <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:6}}>Policy Scope</div>
        <div style={{fontSize:10,color:C.dim,lineHeight:1.4}}>
          Enforces configurable payment cryptography policy across REST and Payment TCP interfaces (TR-31, PIN, MAC, ISO20022). Changes apply immediately to all payment crypto operations.
        </div>
      </Card>
    </Section>

    <Section title="Payment Crypto Controls">
      <Card style={{display:"grid",gap:8}}>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
          <Chk label="Disable ISO-0 PIN block format" checked={Boolean(payPolicy?.disable_iso0_pin_block)} onChange={()=>setPayPolicy((prev)=>{
            const disable=!Boolean(prev?.disable_iso0_pin_block);
            const current=Array.isArray(prev?.allowed_pin_block_formats)?[...prev.allowed_pin_block_formats]:pinFormatOptions;
            const nextFormats=disable?current.filter((fmt)=>fmt!=="ISO-0"):current;
            return {...prev,disable_iso0_pin_block:disable,allowed_pin_block_formats:nextFormats};
          })}/>
          <Chk label="Require KBPK/KEK for TR-31 operations" checked={Boolean(payPolicy?.require_kbpk_for_tr31)} onChange={()=>setPayPolicy((prev)=>({...prev,require_kbpk_for_tr31:!Boolean(prev?.require_kbpk_for_tr31)}))}/>
          <Chk label="Allow inline key material in payment API" checked={Boolean(payPolicy?.allow_inline_key_material)} onChange={()=>setPayPolicy((prev)=>({...prev,allow_inline_key_material:!Boolean(prev?.allow_inline_key_material)}))}/>
          <Chk label="Require ISO20022 LAU context" checked={Boolean(payPolicy?.require_iso20022_lau_context)} onChange={()=>setPayPolicy((prev)=>({...prev,require_iso20022_lau_context:!Boolean(prev?.require_iso20022_lau_context)}))}/>
          <Chk label="Require key_id for payment crypto operations" checked={Boolean(payPolicy?.require_key_id_for_operations)} onChange={()=>setPayPolicy((prev)=>({...prev,require_key_id_for_operations:!Boolean(prev?.require_key_id_for_operations)}))}/>
          <Chk label="Allow Payment TCP interface" checked={Boolean(payPolicy?.allow_tcp_interface)} onChange={()=>setPayPolicy((prev)=>({...prev,allow_tcp_interface:!Boolean(prev?.allow_tcp_interface)}))}/>
          <Chk label="Require JWT on Payment TCP interface" checked={Boolean(payPolicy?.require_jwt_on_tcp)} onChange={()=>setPayPolicy((prev)=>({...prev,require_jwt_on_tcp:!Boolean(prev?.require_jwt_on_tcp)}))}/>
          <Chk label="Block wildcard/non-digit PAN values" checked={Boolean(payPolicy?.block_wildcard_pan)} onChange={()=>setPayPolicy((prev)=>({...prev,block_wildcard_pan:!Boolean(prev?.block_wildcard_pan)}))}/>
          <Chk label="Block test payment keys in prod runtime" checked={Boolean(payPolicy?.disallow_test_keys_in_prod)} onChange={()=>setPayPolicy((prev)=>({...prev,disallow_test_keys_in_prod:!Boolean(prev?.disallow_test_keys_in_prod)}))}/>
          <Chk label="Block prod payment keys in test runtime" checked={Boolean(payPolicy?.disallow_prod_keys_in_test)} onChange={()=>setPayPolicy((prev)=>({...prev,disallow_prod_keys_in_test:!Boolean(prev?.disallow_prod_keys_in_test)}))}/>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8}}>
          {tr31VersionOptions.map((ver)=>{
            const selected=(Array.isArray(payPolicy?.allowed_tr31_versions)?payPolicy.allowed_tr31_versions:[]).includes(ver);
            return <Chk key={`pay-pol-ver-${ver}`} label={`TR-31 ${ver}`} checked={selected} onChange={()=>setPayPolicy((prev)=>{
              return {...prev,allowed_tr31_versions:toggleStringList(prev?.allowed_tr31_versions,ver)};
            })}/>;
          })}
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:10}}>
          <FG label="Runtime Environment">
            <Sel value={String(payPolicy?.runtime_environment||"prod")} onChange={(e)=>setPayPolicy((prev)=>({...prev,runtime_environment:e.target.value==="test"?"test":"prod"}))}>
              <option value="prod">Production</option>
              <option value="test">Test / Sandbox</option>
            </Sel>
          </FG>
          <FG label="Max ISO20022 payload bytes">
            <Inp type="number" min={1024} max={4194304} value={String(payPolicy?.max_iso20022_payload_bytes??262144)} onChange={(e)=>setPayPolicy((prev)=>({...prev,max_iso20022_payload_bytes:Number(e.target.value||262144)}))}/>
          </FG>
          <FG label="Max Payment TCP payload bytes">
            <Inp type="number" min={4096} max={1048576} value={String(payPolicy?.max_tcp_payload_bytes??262144)} onChange={(e)=>setPayPolicy((prev)=>({...prev,max_tcp_payload_bytes:Number(e.target.value||262144)}))}/>
          </FG>
          <FG label="Decimalization Table (16 digits)">
            <Inp
              value={String(payPolicy?.decimalization_table||"0123456789012345")}
              onChange={(e)=>setPayPolicy((prev)=>({...prev,decimalization_table:String(e.target.value||"").replace(/\s+/g,"")}))}
              placeholder="0123456789012345"
              mono
            />
          </FG>
          <FG label="PVKI Min">
            <Inp type="number" min={0} max={9} value={String(payPolicy?.pvki_min??0)} onChange={(e)=>setPayPolicy((prev)=>({...prev,pvki_min:Number(e.target.value||0)}))}/>
          </FG>
          <FG label="PVKI Max">
            <Inp type="number" min={0} max={9} value={String(payPolicy?.pvki_max??9)} onChange={(e)=>setPayPolicy((prev)=>({...prev,pvki_max:Number(e.target.value||9)}))}/>
          </FG>
        </div>
        <div>
          <div style={{fontSize:10,color:C.text,fontWeight:700,marginBottom:8}}>Allowed PIN block formats</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8}}>
            {pinFormatOptions.map((fmt)=>{
              const selected=(Array.isArray(payPolicy?.allowed_pin_block_formats)?payPolicy.allowed_pin_block_formats:[]).includes(fmt);
              const locked=Boolean(payPolicy?.disable_iso0_pin_block)&&fmt==="ISO-0";
              return <Chk key={`pay-pol-pin-${fmt}`} label={locked?`${fmt} (disabled by policy)`:fmt} checked={locked?false:selected} disabled={locked} onChange={()=>setPayPolicy((prev)=>{
                return {...prev,allowed_pin_block_formats:toggleStringList(prev?.allowed_pin_block_formats,fmt)};
              })}/>;
            })}
          </div>
        </div>
        <div>
          <div style={{fontSize:10,color:C.text,fontWeight:700,marginBottom:8}}>Allowed KBPK Classes</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(4,minmax(0,1fr))",gap:8}}>
            {paymentKeyClassOptions.map((klass)=>{
              const selected=(Array.isArray(payPolicy?.allowed_kbpk_classes)?payPolicy.allowed_kbpk_classes:[]).includes(klass);
              return <Chk key={`pay-pol-kbpk-${klass}`} label={klass} checked={selected} onChange={()=>setPayPolicy((prev)=>({...prev,allowed_kbpk_classes:toggleStringList(prev?.allowed_kbpk_classes,klass)}))}/>;
            })}
          </div>
        </div>
        <div>
          <div style={{fontSize:10,color:C.text,fontWeight:700,marginBottom:8}}>Allowed TR-31 Exportability Flags</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8}}>
            {tr31ExportabilityOptions.map((flag)=>{
              const selected=(Array.isArray(payPolicy?.allowed_tr31_exportability)?payPolicy.allowed_tr31_exportability:[]).includes(flag);
              return <Chk key={`pay-pol-exp-${flag}`} label={flag} checked={selected} onChange={()=>setPayPolicy((prev)=>({...prev,allowed_tr31_exportability:toggleStringList(prev?.allowed_tr31_exportability,flag)}))}/>;
            })}
          </div>
        </div>
        <div>
          <div style={{fontSize:10,color:C.text,fontWeight:700,marginBottom:8}}>Allowed ISO20022 Canonicalization</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8}}>
            {isoCanonicalizationOptions.map((item)=>{
              const selected=(Array.isArray(payPolicy?.allowed_iso20022_canonicalization)?payPolicy.allowed_iso20022_canonicalization:[]).includes(item);
              return <Chk key={`pay-pol-canon-${item}`} label={item} checked={selected} onChange={()=>setPayPolicy((prev)=>({...prev,allowed_iso20022_canonicalization:toggleStringList(prev?.allowed_iso20022_canonicalization,item)}))}/>;
            })}
          </div>
        </div>
        <div>
          <div style={{fontSize:10,color:C.text,fontWeight:700,marginBottom:8}}>Allowed ISO20022 Signature Suites</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:8}}>
            {isoSignatureSuiteOptions.map((item)=>{
              const selected=(Array.isArray(payPolicy?.allowed_iso20022_signature_suites)?payPolicy.allowed_iso20022_signature_suites:[]).includes(item);
              return <Chk key={`pay-pol-suite-${item}`} label={item} checked={selected} onChange={()=>setPayPolicy((prev)=>({...prev,allowed_iso20022_signature_suites:toggleStringList(prev?.allowed_iso20022_signature_suites,item)}))}/>;
            })}
          </div>
        </div>
        <div>
          <div style={{fontSize:10,color:C.text,fontWeight:700,marginBottom:8}}>Allowed MAC Domains</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8}}>
            {macDomainOptions.map((item)=>{
              const selected=(Array.isArray(payPolicy?.allowed_mac_domains)?payPolicy.allowed_mac_domains:[]).includes(item);
              return <Chk key={`pay-pol-mac-dom-${item}`} label={item} checked={selected} onChange={()=>setPayPolicy((prev)=>({...prev,allowed_mac_domains:toggleStringList(prev?.allowed_mac_domains,item)}))}/>;
            })}
          </div>
        </div>
        <div>
          <div style={{fontSize:10,color:C.text,fontWeight:700,marginBottom:8}}>Allowed MAC Padding Profiles</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8}}>
            {macPaddingOptions.map((item)=>{
              const selected=(Array.isArray(payPolicy?.allowed_mac_padding_profiles)?payPolicy.allowed_mac_padding_profiles:[]).includes(item);
              return <Chk key={`pay-pol-mac-pad-${item}`} label={item} checked={selected} onChange={()=>setPayPolicy((prev)=>({...prev,allowed_mac_padding_profiles:toggleStringList(prev?.allowed_mac_padding_profiles,item)}))}/>;
            })}
          </div>
        </div>
        <div>
          <div style={{fontSize:10,color:C.text,fontWeight:700,marginBottom:8}}>Allowed operations over Payment TCP</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8}}>
            {tcpOperationOptions.map((op)=>{
              const selected=(Array.isArray(payPolicy?.allowed_tcp_operations)?payPolicy.allowed_tcp_operations:[]).includes(op);
              return <Chk key={`pay-pol-op-${op}`} label={op} checked={selected} onChange={()=>setPayPolicy((prev)=>({...prev,allowed_tcp_operations:toggleStringList(prev?.allowed_tcp_operations,op)}))}/>;
            })}
          </div>
        </div>
        <div>
          <div style={{fontSize:10,color:C.text,fontWeight:700,marginBottom:8}}>Dual-control Required Operations</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8}}>
            {sensitiveOperationOptions.map((op)=>{
              const selected=(Array.isArray(payPolicy?.dual_control_required_operations)?payPolicy.dual_control_required_operations:[]).includes(op);
              return <Chk key={`pay-pol-dual-${op}`} label={op} checked={selected} onChange={()=>setPayPolicy((prev)=>({...prev,dual_control_required_operations:toggleStringList(prev?.dual_control_required_operations,op)}))}/>;
            })}
          </div>
        </div>
        <div>
          <div style={{fontSize:10,color:C.text,fontWeight:700,marginBottom:8}}>HSM-required Operations</div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:8}}>
            {sensitiveOperationOptions.map((op)=>{
              const selected=(Array.isArray(payPolicy?.hsm_required_operations)?payPolicy.hsm_required_operations:[]).includes(op);
              return <Chk key={`pay-pol-hsm-${op}`} label={op} checked={selected} onChange={()=>setPayPolicy((prev)=>({...prev,hsm_required_operations:toggleStringList(prev?.hsm_required_operations,op)}))}/>;
            })}
          </div>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:10}}>
          <FG label="Allowed PIN Translation Pairs (CSV or newline; e.g. ISO-0>ISO-1)">
            <Txt rows={3} value={pinTranslationPairsText} onChange={(e)=>setPINTranslationPairsText(e.target.value)} placeholder="ISO-0>ISO-1, ISO-1>ISO-3"/>
          </FG>
          <FG label="Allowed CVV Service Codes (CSV or newline)">
            <Txt rows={3} value={cvvServiceCodesText} onChange={(e)=>setCVVServiceCodesText(e.target.value)} placeholder="101, 201"/>
          </FG>
          <FG label="Allowed Issuer Profiles (CSV or newline)">
            <Txt rows={3} value={issuerProfilesText} onChange={(e)=>setIssuerProfilesText(e.target.value)} placeholder="issuer-alpha, issuer-beta"/>
          </FG>
        </div>
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:10}}>
          <FG label="TR-31 Exportability Matrix (JSON)">
            <Txt rows={8} value={tr31ExportabilityMatrixText} onChange={(e)=>setTR31ExportabilityMatrixText(e.target.value)} placeholder='{"D0":["E","N"],"K0":["N"]}'/>
          </FG>
          <FG label="Payment Key Purpose Matrix (JSON)">
            <Txt rows={8} value={paymentKeyPurposeMatrixText} onChange={(e)=>setPaymentKeyPurposeMatrixText(e.target.value)} placeholder='{"ZPK":["pin.translate"],"*":["iso20022.sign"]}'/>
          </FG>
          <FG label="Rotation Interval Days by Key Class (JSON)">
            <Txt rows={8} value={rotationDaysByClassText} onChange={(e)=>setRotationDaysByClassText(e.target.value)} placeholder='{"ZPK":90,"PVK":60}'/>
          </FG>
        </div>
      </Card>
    </Section>
  </div>;
};

const AuditLogViewer=({session,onToast})=>{
  const [entries,setEntries]=useState<any[]>([]);
  const [loading,setLoading]=useState(false);
  const [category,setCategory]=useState("");
  const refresh=async()=>{
    if(!session?.token)return;
    setLoading(true);
    try{
      const items=await getDataProtectAuditLog(session,{category:category||undefined,limit:50});
      setEntries(items||[]);
    }catch(error){
      onToast?.(`Audit log load failed: ${errMsg(error)}`);
    }finally{
      setLoading(false);
    }
  };
  useEffect(()=>{if(session?.token)void refresh();},[session?.token,session?.tenantId]);
  const catColors={tokenization:C.accent,encryption:C.blue,masking:C.purple,redaction:C.pink,policy:C.yellow,general:C.muted};
  return <Section title="Audit Log" actions={<>
    <Sel value={category} onChange={(e)=>setCategory(e.target.value)} style={{minWidth:130,fontSize:11}}>
      <option value="">All Categories</option>
      <option value="tokenization">Tokenization</option>
      <option value="encryption">Encryption</option>
      <option value="masking">Masking</option>
      <option value="redaction">Redaction</option>
      <option value="policy">Policy</option>
    </Sel>
    <Btn small onClick={()=>void refresh()} disabled={loading}>{loading?"Loading...":"Refresh"}</Btn>
  </>}>
    <Card style={{maxHeight:320,overflowY:"auto"}}>
      {entries.length?<div style={{display:"grid",gap:4}}>
        {entries.map((e,i)=>{
          const catColor=catColors[e?.category]||C.muted;
          const ts=e?.created_at?new Date(e.created_at).toLocaleString():"";
          return <div key={e?.id||i} style={{display:"grid",gridTemplateColumns:"3px 1fr",gap:0,borderRadius:6,overflow:"hidden",border:`1px solid ${C.line}`}}>
            <div style={{background:catColor}}/>
            <div style={{padding:"6px 10px",display:"flex",justifyContent:"space-between",alignItems:"center",gap:8}}>
              <div>
                <div style={{display:"flex",gap:6,alignItems:"center"}}>
                  <span style={{fontSize:11,fontWeight:700,color:C.text}}>{e?.operation||""}</span>
                  <B c={e?.category==="policy"?"yellow":e?.category==="encryption"?"blue":"accent"} style={{fontSize:9}}>{e?.category||""}</B>
                </div>
                <div style={{fontSize:10,color:C.dim}}>{e?.detail||""}</div>
              </div>
              <div style={{textAlign:"right",flexShrink:0}}>
                <div style={{fontSize:9,color:C.muted}}>{e?.actor||""}</div>
                <div style={{fontSize:9,color:C.dim}}>{ts}</div>
              </div>
            </div>
          </div>;
        })}
      </div>:<div style={{fontSize:11,color:C.dim,padding:12,textAlign:"center"}}>No audit entries found. Perform data protection operations to generate audit trail.</div>}
    </Card>
  </Section>;
};

export const DataProtectionTab=({session,keyCatalog,onToast,subView,onSubViewChange})=>{
  const [dataSubtab,setDataSubtab]=useState("fieldenc");
  const [stats,setStats]=useState<any>(null);
  const currentSubtab=String(subView||dataSubtab||"fieldenc");
  const selectSubtab=(next:string)=>{
    if(onSubViewChange){
      onSubViewChange(next);
      return;
    }
    setDataSubtab(next);
  };
  const showInlineSubTabs=!onSubViewChange;

  useEffect(()=>{
    if(!session?.token)return;
    getDataProtectStats(session).then(setStats).catch(()=>{});
  },[session?.token,session?.tenantId]);

  const statItems=[
    {l:"Token Vaults",v:stats?.token_vaults,icon:Database,color:C.accent},
    {l:"Tokens",v:stats?.total_tokens,icon:Shield,color:C.blue},
    {l:"Mask Policies",v:stats?.masking_policies,icon:VenetianMask,color:C.purple},
    {l:"Redact Policies",v:stats?.redaction_policies,icon:ScrollText,color:C.pink},
    {l:"Wrappers",v:stats?.registered_wrappers,icon:KeyRound,color:C.green},
    {l:"Active Leases",v:stats?.active_leases,icon:FileKey,color:C.yellow},
  ];
  const activeStatItems=statItems;
  const showStats=currentSubtab==="payment-policy"?false:Boolean(stats);

  return <div style={{display:"grid",gap:12}}>
    {showStats&&<div style={{display:"grid",gridTemplateColumns:"repeat(6,1fr)",gap:10}}>
      {activeStatItems.map((s,i)=>{
        const Icon=s.icon;
        return <Card key={i} style={{padding:"12px 14px",display:"flex",alignItems:"center",gap:10}}>
          <Icon size={18} style={{color:s.color,flexShrink:0}}/>
          <div>
            <div style={{fontSize:20,fontWeight:800,color:C.text,fontFamily:"'Rajdhani','IBM Plex Sans',sans-serif",lineHeight:1}}>{s.v??"-"}</div>
            <div style={{fontSize:9,color:C.muted,letterSpacing:0.5,textTransform:"uppercase"}}>{s.l}</div>
          </div>
        </Card>;
      })}
    </div>}
    {showInlineSubTabs&&<div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
      <Btn small primary={currentSubtab==="fieldenc"} onClick={()=>selectSubtab("fieldenc")}>Field Encryption</Btn>
      <Btn small primary={currentSubtab==="dataenc-policy"} onClick={()=>selectSubtab("dataenc-policy")}>Data Encryption Policy</Btn>
      <Btn small primary={currentSubtab==="token-policy"} onClick={()=>selectSubtab("token-policy")}>Token / Mask / Redact Policy</Btn>
      <Btn small primary={currentSubtab==="payment-policy"} onClick={()=>selectSubtab("payment-policy")}>Payment Policy</Btn>
      <Btn small primary={currentSubtab==="pkcs11"} onClick={()=>selectSubtab("pkcs11")}>PKCS#11 / JCA</Btn>
    </div>}
    {currentSubtab==="pkcs11"
      ? <PKCS11Tab session={session} onToast={onToast}/>
      : currentSubtab==="token-policy"
        ? <TokenizeMaskRedactPolicy session={session} onToast={onToast}/>
        : currentSubtab==="payment-policy"
          ? <PaymentPolicyTab session={session} onToast={onToast}/>
        : currentSubtab==="dataenc-policy"
          ? <DataEncryptionPolicy session={session} onToast={onToast}/>
          : <FieldEncryptionRuntime session={session} keyCatalog={keyCatalog} onToast={onToast}/>}
    <AuditLogViewer session={session} onToast={onToast}/>
  </div>;
};
