// @ts-nocheck
import { useEffect, useState } from "react";
import {
  computeCVV,
  computeMAC,
  createInjectionJob,
  createTR31,
  decryptISO20022,
  encryptISO20022,
  generateLAU,
  generatePVV,
  listInjectionJobs,
  listInjectionTerminals,
  listPaymentKeys,
  issueInjectionChallenge,
  registerInjectionTerminal,
  signISO20022,
  translatePIN,
  translateTR31,
  validateTR31,
  verifyCVV,
  verifyInjectionChallenge,
  verifyISO20022,
  verifyLAU,
  verifyMAC,
  verifyPVV
} from "../../../lib/payment";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, FG, Inp, Row2, Sel, Tabs, Txt } from "../legacyPrimitives";

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

export const PaymentTab=({session,keyCatalog,onToast})=>{
  const [op,setOp]=useState("TR-31 Create");
  const keyChoices=keyChoicesFromCatalog(keyCatalog);
  const [running,setRunning]=useState(false);
  const [resultText,setResultText]=useState("// Output will appear here...");
  const [paymentKeyItems,setPaymentKeyItems]=useState<any[]>([]);
  const [injectionTerminals,setInjectionTerminals]=useState<any[]>([]);
  const [injectionJobs,setInjectionJobs]=useState<any[]>([]);
  const [injectionLoading,setInjectionLoading]=useState(false);

  const [injTerminalName,setInjTerminalName]=useState("");
  const [injTerminalExternalID,setInjTerminalExternalID]=useState("");
  const [injTerminalPubPEM,setInjTerminalPubPEM]=useState("");
  const [injTerminalTransport,setInjTerminalTransport]=useState("jwt");
  const [injTerminalMeta,setInjTerminalMeta]=useState("{}");
  const [injSelectedTerminalRowID,setInjSelectedTerminalRowID]=useState("");
  const [injChallengeNonce,setInjChallengeNonce]=useState("");
  const [injChallengeExpiry,setInjChallengeExpiry]=useState("");
  const [injSignatureB64,setInjSignatureB64]=useState("");
  const [injVerifiedToken,setInjVerifiedToken]=useState("");
  const [injSelectedPaymentKeyID,setInjSelectedPaymentKeyID]=useState("");
  const [injTR31Version,setInjTR31Version]=useState("D");
  const [injKBPKKeyID,setInjKBPKKeyID]=useState("");
  const [injKBPKB64,setInjKBPKB64]=useState("");

  const [selectedKeyId,setSelectedKeyId]=useState("");
  const [tr31Version,setTR31Version]=useState("D");
  const [tr31Usage,setTR31Usage]=useState("D0");
  const [tr31Algorithm,setTR31Algorithm]=useState("AES");
  const [tr31SourceFormat,setTR31SourceFormat]=useState("variant");
  const [tr31TargetFormat,setTR31TargetFormat]=useState("tr31-d");
  const [tr31SourceBlock,setTR31SourceBlock]=useState("");
  const [tr31MaterialB64,setTR31MaterialB64]=useState("");
  const [tr31KBPKKeyID,setTR31KBPKKeyID]=useState("");
  const [tr31KBPKKeyB64,setTR31KBPKKeyB64]=useState("");
  const [tr31SourceKBPKKeyID,setTR31SourceKBPKKeyID]=useState("");
  const [tr31SourceKBPKKeyB64,setTR31SourceKBPKKeyB64]=useState("");
  const [tr31TargetKBPKKeyID,setTR31TargetKBPKKeyID]=useState("");
  const [tr31TargetKBPKKeyB64,setTR31TargetKBPKKeyB64]=useState("");

  const [pinSourceFormat,setPINSourceFormat]=useState("ISO-0");
  const [pinTargetFormat,setPINTargetFormat]=useState("ISO-1");
  const [pinSourceKeyID,setPINSourceKeyID]=useState("");
  const [pinTargetKeyID,setPINTargetKeyID]=useState("");
  const [pinSourceKeyB64,setPINSourceKeyB64]=useState("");
  const [pinTargetKeyB64,setPINTargetKeyB64]=useState("");
  const [pinBlockHex,setPINBlockHex]=useState("");
  const [pinPAN,setPINPAN]=useState("");

  const [pvvKeyID,setPVVKeyID]=useState("");
  const [pvvKeyB64,setPVVKeyB64]=useState("");
  const [pinValue,setPINValue]=useState("1234");
  const [pvvPAN,setPVVPAN]=useState("4111111111111111");
  const [pvki,setPVKI]=useState("1");
  const [pvvValue,setPVVValue]=useState("");

  const [cvvKeyID,setCVVKeyID]=useState("");
  const [cvvKeyB64,setCVVKeyB64]=useState("");
  const [cvvPAN,setCVVPAN]=useState("4111111111111111");
  const [cvvExpiry,setCVVExpiry]=useState("2612");
  const [cvvServiceCode,setCVVServiceCode]=useState("101");
  const [cvvValue,setCVVValue]=useState("");

  const [macType,setMACType]=useState<"retail"|"iso9797"|"cmac">("retail");
  const [macAlgorithm,setMACAlgorithm]=useState(3);
  const [macKeyID,setMACKeyID]=useState("");
  const [macKeyB64,setMACKeyB64]=useState("");
  const [macData,setMACData]=useState("PAYMENT-TEST-DATA");
  const [macValue,setMACValue]=useState("");

  const [isoKeyID,setISOKeyID]=useState("");
  const [isoXML,setISOXML]=useState('<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008"><Msg>test</Msg></Document>');
  const [isoSignature,setISOSignature]=useState("");
  const [isoCiphertext,setISOCiphertext]=useState("");
  const [isoIV,setISOIV]=useState("");

  const [lauKeyID,setLAUKeyID]=useState("");
  const [lauKeyB64,setLAUKeyB64]=useState("");
  const [lauContext,setLAUContext]=useState("swift");
  const [lauMessage,setLAUMessage]=useState("<AppHdr><MsgDefIdr>pacs.008</MsgDefIdr></AppHdr>");
  const [lauValue,setLAUValue]=useState("");

  useEffect(()=>{
    if(!keyChoices.length){
      return;
    }
    const fallback=String(keyChoices[0]?.id||"");
    if(!selectedKeyId){
      setSelectedKeyId(fallback);
    }
    if(!tr31KBPKKeyID){
      setTR31KBPKKeyID(fallback);
    }
    if(!tr31SourceKBPKKeyID){
      setTR31SourceKBPKKeyID(fallback);
    }
    if(!tr31TargetKBPKKeyID){
      setTR31TargetKBPKKeyID(fallback);
    }
    if(!pinSourceKeyID){
      setPINSourceKeyID(fallback);
    }
    if(!pinTargetKeyID){
      setPINTargetKeyID(fallback);
    }
    if(!pvvKeyID){
      setPVVKeyID(fallback);
    }
    if(!cvvKeyID){
      setCVVKeyID(fallback);
    }
    if(!macKeyID){
      setMACKeyID(fallback);
    }
    if(!isoKeyID){
      setISOKeyID(fallback);
    }
    if(!lauKeyID){
      setLAUKeyID(fallback);
    }
  },[keyChoices]);

  const refreshInjectionData=async(silent=false)=>{
    if(!session?.token){
      return;
    }
    if(!silent){
      setInjectionLoading(true);
    }
    try{
      const [payKeys,terminals,jobs]=await Promise.all([
        listPaymentKeys(session),
        listInjectionTerminals(session),
        listInjectionJobs(session)
      ]);
      const keyItems=Array.isArray(payKeys)?payKeys:[];
      const terminalItems=Array.isArray(terminals)?terminals:[];
      const jobItems=Array.isArray(jobs)?jobs:[];
      setPaymentKeyItems(keyItems);
      setInjectionTerminals(terminalItems);
      setInjectionJobs(jobItems);
      if(!injSelectedTerminalRowID&&terminalItems.length){
        setInjSelectedTerminalRowID(String(terminalItems[0]?.id||""));
      }
      if(!injSelectedPaymentKeyID&&keyItems.length){
        setInjSelectedPaymentKeyID(String(keyItems[0]?.id||""));
      }
      if(!injKBPKKeyID&&keyChoices.length){
        setInjKBPKKeyID(String(keyChoices[0]?.id||""));
      }
    }catch(error){
      onToast?.(`Payment injection refresh failed: ${errMsg(error)}`);
    }finally{
      if(!silent){
        setInjectionLoading(false);
      }
    }
  };

  useEffect(()=>{
    if(!session?.token){
      return;
    }
    void refreshInjectionData(true);
  },[session?.token,session?.tenantId]);

  const registerTerminal=async()=>{
    if(!session?.token){
      onToast?.("Login is required.");
      return;
    }
    setInjectionLoading(true);
    try{
      const created=await registerInjectionTerminal(session,{
        terminal_id:String(injTerminalExternalID||"").trim(),
        name:String(injTerminalName||"").trim(),
        public_key_pem:String(injTerminalPubPEM||"").trim(),
        transport:String(injTerminalTransport||"jwt"),
        metadata_json:String(injTerminalMeta||"{}").trim()||"{}"
      });
      onToast?.("PoS terminal registered.");
      setResultText(JSON.stringify({terminal:created},null,2));
      setInjTerminalName("");
      setInjTerminalExternalID("");
      setInjTerminalPubPEM("");
      await refreshInjectionData(true);
      if(created?.id){
        setInjSelectedTerminalRowID(String(created.id));
      }
    }catch(error){
      onToast?.(`Terminal register failed: ${errMsg(error)}`);
    }finally{
      setInjectionLoading(false);
    }
  };

  const issueChallenge=async()=>{
    if(!session?.token||!injSelectedTerminalRowID){
      onToast?.("Select a terminal first.");
      return;
    }
    setInjectionLoading(true);
    try{
      const challenge=await issueInjectionChallenge(session,injSelectedTerminalRowID);
      setInjChallengeNonce(String(challenge?.nonce||""));
      setInjChallengeExpiry(String(challenge?.expires_at||""));
      setResultText(JSON.stringify({challenge},null,2));
      onToast?.("Challenge issued.");
    }catch(error){
      onToast?.(`Challenge issue failed: ${errMsg(error)}`);
    }finally{
      setInjectionLoading(false);
    }
  };

  const verifyChallenge=async()=>{
    if(!session?.token||!injSelectedTerminalRowID){
      onToast?.("Select a terminal first.");
      return;
    }
    if(!String(injSignatureB64||"").trim()){
      onToast?.("Enter signature from terminal.");
      return;
    }
    setInjectionLoading(true);
    try{
      const out=await verifyInjectionChallenge(session,injSelectedTerminalRowID,String(injSignatureB64||"").trim());
      setInjVerifiedToken(String(out?.auth_token||""));
      setResultText(JSON.stringify(out,null,2));
      onToast?.("Terminal verified and token issued.");
      await refreshInjectionData(true);
    }catch(error){
      onToast?.(`Challenge verify failed: ${errMsg(error)}`);
    }finally{
      setInjectionLoading(false);
    }
  };

  const createInjection=async()=>{
    if(!session?.token){
      onToast?.("Login is required.");
      return;
    }
    if(!injSelectedTerminalRowID||!injSelectedPaymentKeyID){
      onToast?.("Select terminal and payment key.");
      return;
    }
    setInjectionLoading(true);
    try{
      const job=await createInjectionJob(session,{
        terminal_id:String(injSelectedTerminalRowID||"").trim(),
        payment_key_id:String(injSelectedPaymentKeyID||"").trim(),
        tr31_version:String(injTR31Version||"D").trim(),
        kbpk_key_id:String(injKBPKKeyID||"").trim()||undefined,
        kbpk_key_b64:String(injKBPKB64||"").trim()||undefined
      });
      setResultText(JSON.stringify({injection_job:job},null,2));
      onToast?.("Injection job queued.");
      await refreshInjectionData(true);
    }catch(error){
      onToast?.(`Injection job failed: ${errMsg(error)}`);
    }finally{
      setInjectionLoading(false);
    }
  };

  const runPaymentOp=async()=>{
    if(!session?.token){
      onToast?.("Login is required for payment operations.");
      return;
    }
    setRunning(true);
    try{
      let out:any={};
      if(op==="TR-31 Create"){
        const created=await createTR31(session,{
          key_id:selectedKeyId,
          tr31_version:tr31Version,
          algorithm:tr31Algorithm,
          usage_code:tr31Usage,
          mode_of_use:"B",
          exportability:"E",
          kbpk_key_id:String(tr31KBPKKeyID||"").trim()||undefined,
          kbpk_key_b64:String(tr31KBPKKeyB64||"").trim()||undefined,
          source_format:tr31SourceFormat,
          material_b64:String(tr31MaterialB64||"").trim()||undefined
        });
        const validated=created?.key_block?await validateTR31(session,String(created.key_block),{
          kbpk_key_id:String(tr31KBPKKeyID||"").trim()||undefined,
          kbpk_key_b64:String(tr31KBPKKeyB64||"").trim()||undefined
        }):null;
        out={created,validated};
      }else if(op==="TR-31 Translate"){
        out=await translateTR31(session,{
          source_key_id:selectedKeyId,
          source_block:String(tr31SourceBlock||"").trim()||undefined,
          source_format:tr31SourceFormat,
          target_format:tr31TargetFormat,
          source_kbpk_key_id:String(tr31SourceKBPKKeyID||"").trim()||undefined,
          source_kbpk_key_b64:String(tr31SourceKBPKKeyB64||"").trim()||undefined,
          target_kbpk_key_id:String(tr31TargetKBPKKeyID||"").trim()||undefined,
          target_kbpk_key_b64:String(tr31TargetKBPKKeyB64||"").trim()||undefined,
          tr31_version:tr31Version,
          algorithm:tr31Algorithm,
          usage_code:tr31Usage,
          mode_of_use:"B",
          exportability:"E"
        });
      }else if(op==="PIN Translate"){
        const translated=await translatePIN(session,{
          source_format:pinSourceFormat,
          target_format:pinTargetFormat,
          pin_block:String(pinBlockHex||"").trim().toUpperCase(),
          pan:String(pinPAN||"").trim(),
          source_zpk_key_id:String(pinSourceKeyID||"").trim()||undefined,
          source_zpk_key_b64:String(pinSourceKeyB64||"").trim()||undefined,
          target_zpk_key_id:String(pinTargetKeyID||"").trim()||undefined,
          target_zpk_key_b64:String(pinTargetKeyB64||"").trim()||undefined
        });
        out={pin_block:translated};
      }else if(op==="PIN Verify"){
        const verified=await verifyPVV(session,{
          pin:String(pinValue||"").trim(),
          pan:String(pvvPAN||"").trim(),
          pvki:String(pvki||"").trim(),
          pvv:String(pvvValue||"").trim(),
          pvk_key_id:String(pvvKeyID||"").trim()||undefined,
          pvk_key_b64:String(pvvKeyB64||"").trim()||undefined
        });
        out={verified};
      }else if(op==="PVV Generate"){
        const pvv=await generatePVV(session,{
          pin:String(pinValue||"").trim(),
          pan:String(pvvPAN||"").trim(),
          pvki:String(pvki||"").trim(),
          pvk_key_id:String(pvvKeyID||"").trim()||undefined,
          pvk_key_b64:String(pvvKeyB64||"").trim()||undefined
        });
        setPVVValue(pvv);
        out={pvv};
      }else if(op==="CVV Compute"){
        const cvv=await computeCVV(session,{
          pan:String(cvvPAN||"").trim(),
          expiry_yymm:String(cvvExpiry||"").trim(),
          service_code:String(cvvServiceCode||"").trim(),
          cvk_key_id:String(cvvKeyID||"").trim()||undefined,
          cvk_key_b64:String(cvvKeyB64||"").trim()||undefined
        });
        const verified=await verifyCVV(session,{
          pan:String(cvvPAN||"").trim(),
          expiry_yymm:String(cvvExpiry||"").trim(),
          service_code:String(cvvServiceCode||"").trim(),
          cvv,
          cvk_key_id:String(cvvKeyID||"").trim()||undefined,
          cvk_key_b64:String(cvvKeyB64||"").trim()||undefined
        });
        setCVVValue(cvv);
        out={cvv,verified};
      }else if(op==="MAC Generate"){
        const dataB64=btoa(String(macData||""));
        const mac=await computeMAC(session,{
          type:macType,
          key_id:String(macKeyID||"").trim()||undefined,
          key_b64:String(macKeyB64||"").trim()||undefined,
          data_b64:dataB64,
          algorithm:Number(macAlgorithm||3)
        });
        const verified=await verifyMAC(session,{
          type:macType,
          key_id:String(macKeyID||"").trim()||undefined,
          key_b64:String(macKeyB64||"").trim()||undefined,
          data_b64:dataB64,
          mac_b64:mac,
          algorithm:Number(macAlgorithm||3)
        });
        setMACValue(mac);
        out={mac_b64:mac,verified};
      }else if(op==="ISO 20022 Sign"){
        const signed=await signISO20022(session,{
          key_id:String(isoKeyID||"").trim(),
          xml:String(isoXML||"")
        });
        const sig=String(signed?.signature_b64||"").trim();
        setISOSignature(sig);
        const verified=sig?await verifyISO20022(session,{
          key_id:String(isoKeyID||"").trim(),
          xml:String(isoXML||""),
          signature_b64:sig
        }):false;
        out={...signed,verified};
      }else if(op==="ISO 20022 Encrypt"){
        const encrypted=await encryptISO20022(session,{
          key_id:String(isoKeyID||"").trim(),
          xml:String(isoXML||""),
          iv:String(isoIV||"").trim()||undefined
        });
        const cipher=String(encrypted?.ciphertext||"");
        const iv=String(encrypted?.iv||"");
        setISOCiphertext(cipher);
        setISOIV(iv);
        const decrypted=cipher?await decryptISO20022(session,{
          key_id:String(isoKeyID||"").trim(),
          ciphertext:cipher,
          iv:iv
        }):"";
        out={...encrypted,decrypted_xml:decrypted};
      }else if(op==="LAU Generate"){
        const lau=await generateLAU(session,{
          key_id:String(lauKeyID||"").trim()||undefined,
          lau_key_b64:String(lauKeyB64||"").trim()||undefined,
          message:String(lauMessage||""),
          context:String(lauContext||"")
        });
        const verified=await verifyLAU(session,{
          key_id:String(lauKeyID||"").trim()||undefined,
          lau_key_b64:String(lauKeyB64||"").trim()||undefined,
          message:String(lauMessage||""),
          context:String(lauContext||""),
          lau_b64:lau
        });
        setLAUValue(lau);
        out={lau_b64:lau,verified};
      }
      setResultText(JSON.stringify(out,null,2));
    }catch(error){
      const msg=errMsg(error);
      onToast?.(`Payment operation failed: ${msg}`);
      setResultText(JSON.stringify({error:msg},null,2));
    }finally{
      setRunning(false);
    }
  };

  return <div>
    <Tabs tabs={["TR-31 Create","TR-31 Translate","PIN Translate","PIN Verify","PVV Generate","CVV Compute","MAC Generate","ISO 20022 Sign","ISO 20022 Encrypt","LAU Generate","Payment Key Injection"]} active={op} onChange={setOp}/>
    <Row2>
      <Card>
        {op==="TR-31 Create"&&<>
          <Row2>
            <FG label="Key to Wrap" required><Sel value={selectedKeyId} onChange={(e)=>setSelectedKeyId(e.target.value)}>{renderKeyOptions(keyChoices)}</Sel></FG>
            <FG label="KBPK / KEK" required><Sel value={tr31KBPKKeyID} onChange={(e)=>setTR31KBPKKeyID(e.target.value)}>{renderKeyOptions(keyChoices)}</Sel></FG>
          </Row2>
          <Row2>
            <FG label="TR-31 Version"><Sel value={tr31Version} onChange={(e)=>setTR31Version(e.target.value)}><option value="D">D - AES CMAC</option><option value="B">B - TDES variant</option><option value="C">C - TDES derivation</option></Sel></FG>
            <FG label="Source Format"><Sel value={tr31SourceFormat} onChange={(e)=>setTR31SourceFormat(e.target.value)}><option value="variant">Variant</option><option value="tr31-b">TR-31 B</option><option value="tr31-c">TR-31 C</option><option value="tr31-d">TR-31 D</option><option value="aes-kwp">AES-KWP</option></Sel></FG>
          </Row2>
          <Row2>
            <FG label="Algorithm"><Sel value={tr31Algorithm} onChange={(e)=>setTR31Algorithm(e.target.value)}><option value="AES">AES</option><option value="TDES">TDES</option></Sel></FG>
            <FG label="Key Usage"><Sel value={tr31Usage} onChange={(e)=>setTR31Usage(e.target.value)}><option value="P0">P0</option><option value="B0">B0</option><option value="D0">D0</option><option value="M0">M0</option><option value="M3">M3</option><option value="K0">K0</option><option value="V0">V0</option></Sel></FG>
          </Row2>
          <FG label="KBPK / KEK (base64 override)" hint="Optional override. If set, backend uses this instead of KBPK key ID.">
            <Inp value={tr31KBPKKeyB64} onChange={(e)=>setTR31KBPKKeyB64(e.target.value)} mono/>
          </FG>
          <FG label="Override Material (base64)" hint="Optional. If empty, backend resolves key material from selected key ID.">
            <Txt value={tr31MaterialB64} onChange={(e)=>setTR31MaterialB64(e.target.value)} rows={4}/>
          </FG>
        </>}

        {op==="TR-31 Translate"&&<>
          <FG label="Source Key ID"><Sel value={selectedKeyId} onChange={(e)=>setSelectedKeyId(e.target.value)}>{renderKeyOptions(keyChoices)}</Sel></FG>
          <Row2>
            <FG label="Source Format"><Sel value={tr31SourceFormat} onChange={(e)=>setTR31SourceFormat(e.target.value)}><option value="variant">Variant</option><option value="tr31-b">TR-31 B</option><option value="tr31-c">TR-31 C</option><option value="tr31-d">TR-31 D</option><option value="aes-kwp">AES-KWP</option></Sel></FG>
            <FG label="Target Format"><Sel value={tr31TargetFormat} onChange={(e)=>setTR31TargetFormat(e.target.value)}><option value="variant">Variant</option><option value="tr31-b">TR-31 B</option><option value="tr31-c">TR-31 C</option><option value="tr31-d">TR-31 D</option><option value="aes-kwp">AES-KWP</option></Sel></FG>
          </Row2>
          <Row2>
            <FG label="Source KBPK / KEK"><Sel value={tr31SourceKBPKKeyID} onChange={(e)=>setTR31SourceKBPKKeyID(e.target.value)}>{renderKeyOptions(keyChoices)}</Sel></FG>
            <FG label="Target KBPK / KEK"><Sel value={tr31TargetKBPKKeyID} onChange={(e)=>setTR31TargetKBPKKeyID(e.target.value)}>{renderKeyOptions(keyChoices)}</Sel></FG>
          </Row2>
          <Row2>
            <FG label="Source KBPK (base64 override)"><Inp value={tr31SourceKBPKKeyB64} onChange={(e)=>setTR31SourceKBPKKeyB64(e.target.value)} mono/></FG>
            <FG label="Target KBPK (base64 override)"><Inp value={tr31TargetKBPKKeyB64} onChange={(e)=>setTR31TargetKBPKKeyB64(e.target.value)} mono/></FG>
          </Row2>
          <FG label="Source Block (optional)" hint="If provided, backend translates this block; otherwise it uses source key ID."><Txt value={tr31SourceBlock} onChange={(e)=>setTR31SourceBlock(e.target.value)} rows={5}/></FG>
        </>}

        {op==="PIN Translate"&&<>
          <Row2>
            <FG label="Source PIN Block Format"><Sel value={pinSourceFormat} onChange={(e)=>setPINSourceFormat(e.target.value)}><option>ISO-0</option><option>ISO-1</option><option>ISO-3</option><option>ISO-4</option></Sel></FG>
            <FG label="Target PIN Block Format"><Sel value={pinTargetFormat} onChange={(e)=>setPINTargetFormat(e.target.value)}><option>ISO-0</option><option>ISO-1</option><option>ISO-3</option><option>ISO-4</option></Sel></FG>
          </Row2>
          <FG label="Source ZPK"><Sel value={pinSourceKeyID} onChange={(e)=>setPINSourceKeyID(e.target.value)}>{renderKeyOptions(keyChoices)}</Sel></FG>
          <FG label="Target ZPK"><Sel value={pinTargetKeyID} onChange={(e)=>setPINTargetKeyID(e.target.value)}>{renderKeyOptions(keyChoices)}</Sel></FG>
          <FG label="Source ZPK (base64 override)" hint="Optional. Use this if key IDs are not registered in KeyCore."><Inp value={pinSourceKeyB64} onChange={(e)=>setPINSourceKeyB64(e.target.value)} mono/></FG>
          <FG label="Target ZPK (base64 override)" hint="Optional. Use this if key IDs are not registered in KeyCore."><Inp value={pinTargetKeyB64} onChange={(e)=>setPINTargetKeyB64(e.target.value)} mono/></FG>
          <FG label="PIN Block (hex)" required><Inp value={pinBlockHex} onChange={(e)=>setPINBlockHex(e.target.value)} placeholder="0412AC8967BFCD01" mono/></FG>
          <FG label="PAN (required for ISO-0/ISO-3)" hint="Right-most 12 digits (excluding check digit) are used internally."><Inp value={pinPAN} onChange={(e)=>setPINPAN(e.target.value)} placeholder="4111111111111111" mono/></FG>
        </>}

        {op==="PIN Verify"&&<>
          <FG label="PVK Key"><Sel value={pvvKeyID} onChange={(e)=>setPVVKeyID(e.target.value)}>{renderKeyOptions(keyChoices)}</Sel></FG>
          <FG label="PVK Key (base64 override)" hint="Optional override if external key material is used."><Inp value={pvvKeyB64} onChange={(e)=>setPVVKeyB64(e.target.value)} mono/></FG>
          <Row2>
            <FG label="PIN"><Inp value={pinValue} onChange={(e)=>setPINValue(e.target.value)} mono/></FG>
            <FG label="PVKI"><Inp value={pvki} onChange={(e)=>setPVKI(e.target.value)} mono/></FG>
          </Row2>
          <FG label="PAN"><Inp value={pvvPAN} onChange={(e)=>setPVVPAN(e.target.value)} mono/></FG>
          <FG label="PVV"><Inp value={pvvValue} onChange={(e)=>setPVVValue(e.target.value)} mono/></FG>
        </>}

        {op==="PVV Generate"&&<>
          <FG label="PVK Key"><Sel value={pvvKeyID} onChange={(e)=>setPVVKeyID(e.target.value)}>{renderKeyOptions(keyChoices)}</Sel></FG>
          <FG label="PVK Key (base64 override)" hint="Optional override if external key material is used."><Inp value={pvvKeyB64} onChange={(e)=>setPVVKeyB64(e.target.value)} mono/></FG>
          <Row2>
            <FG label="PIN"><Inp value={pinValue} onChange={(e)=>setPINValue(e.target.value)} mono/></FG>
            <FG label="PVKI"><Inp value={pvki} onChange={(e)=>setPVKI(e.target.value)} mono/></FG>
          </Row2>
          <FG label="PAN"><Inp value={pvvPAN} onChange={(e)=>setPVVPAN(e.target.value)} mono/></FG>
        </>}

        {op==="CVV Compute"&&<>
          <FG label="CVK Key"><Sel value={cvvKeyID} onChange={(e)=>setCVVKeyID(e.target.value)}>{renderKeyOptions(keyChoices)}</Sel></FG>
          <FG label="CVK Key (base64 override)" hint="Optional override if external key material is used."><Inp value={cvvKeyB64} onChange={(e)=>setCVVKeyB64(e.target.value)} mono/></FG>
          <FG label="PAN" required><Inp value={cvvPAN} onChange={(e)=>setCVVPAN(e.target.value)} placeholder="4111111111111111" mono/></FG>
          <Row2>
            <FG label="Expiry (YYMM)" required><Inp value={cvvExpiry} onChange={(e)=>setCVVExpiry(e.target.value)} placeholder="2612" mono/></FG>
            <FG label="Service Code" required><Inp value={cvvServiceCode} onChange={(e)=>setCVVServiceCode(e.target.value)} placeholder="101" mono/></FG>
          </Row2>
          <FG label="CVV (for verify)"><Inp value={cvvValue} onChange={(e)=>setCVVValue(e.target.value)} mono/></FG>
        </>}

        {op==="MAC Generate"&&<>
          <Row2>
            <FG label="MAC Type"><Sel value={macType} onChange={(e)=>setMACType(e.target.value as any)}><option value="retail">Retail MAC (ANSI X9.19)</option><option value="iso9797">ISO 9797</option><option value="cmac">AES CMAC</option></Sel></FG>
            <FG label="ISO9797 Algorithm"><Sel value={String(macAlgorithm)} onChange={(e)=>setMACAlgorithm(Number(e.target.value||3))}><option value="1">1</option><option value="3">3</option></Sel></FG>
          </Row2>
          <FG label="MAC Key"><Sel value={macKeyID} onChange={(e)=>setMACKeyID(e.target.value)}>{renderKeyOptions(keyChoices)}</Sel></FG>
          <FG label="MAC Key (base64 override)" hint="Optional override if external key material is used."><Inp value={macKeyB64} onChange={(e)=>setMACKeyB64(e.target.value)} mono/></FG>
          <FG label="Data"><Txt value={macData} onChange={(e)=>setMACData(e.target.value)} rows={4}/></FG>
          <FG label="MAC (for verify)"><Inp value={macValue} onChange={(e)=>setMACValue(e.target.value)} mono/></FG>
        </>}

        {op==="ISO 20022 Sign"&&<>
          <FG label="Signing Key" required><Sel value={isoKeyID} onChange={(e)=>setISOKeyID(e.target.value)}>{renderKeyOptions(keyChoices)}</Sel></FG>
          <FG label="XML Document" required><Txt value={isoXML} onChange={(e)=>setISOXML(e.target.value)} rows={6}/></FG>
          <FG label="Signature (for verify)"><Txt value={isoSignature} onChange={(e)=>setISOSignature(e.target.value)} rows={3} mono/></FG>
        </>}

        {op==="ISO 20022 Encrypt"&&<>
          <FG label="Encryption Key" required><Sel value={isoKeyID} onChange={(e)=>setISOKeyID(e.target.value)}>{renderKeyOptions(keyChoices)}</Sel></FG>
          <FG label="XML Document" required><Txt value={isoXML} onChange={(e)=>setISOXML(e.target.value)} rows={6}/></FG>
          <Row2>
            <FG label="IV (base64 optional)"><Inp value={isoIV} onChange={(e)=>setISOIV(e.target.value)} mono/></FG>
            <FG label="Ciphertext (base64)"><Inp value={isoCiphertext} onChange={(e)=>setISOCiphertext(e.target.value)} mono/></FG>
          </Row2>
        </>}

        {op==="LAU Generate"&&<>
          <FG label="LAU Key"><Sel value={lauKeyID} onChange={(e)=>setLAUKeyID(e.target.value)}>{renderKeyOptions(keyChoices)}</Sel></FG>
          <FG label="LAU Key (base64 override)" hint="Optional override if external key material is used."><Inp value={lauKeyB64} onChange={(e)=>setLAUKeyB64(e.target.value)} mono/></FG>
          <FG label="Context"><Inp value={lauContext} onChange={(e)=>setLAUContext(e.target.value)} mono/></FG>
          <FG label="Message"><Txt value={lauMessage} onChange={(e)=>setLAUMessage(e.target.value)} rows={5}/></FG>
          <FG label="LAU (for verify)"><Txt value={lauValue} onChange={(e)=>setLAUValue(e.target.value)} rows={3} mono/></FG>
        </>}

        {op==="Payment Key Injection"&&<>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
            <div style={{fontSize:11,color:C.muted,fontWeight:700}}>PoS Terminal Onboarding and Remote Injection</div>
            <Btn small onClick={()=>void refreshInjectionData()} disabled={injectionLoading}>{injectionLoading?"Refreshing...":"Refresh"}</Btn>
          </div>
          <Row2>
            <FG label="Terminal Name" required><Inp value={injTerminalName} onChange={(e)=>setInjTerminalName(e.target.value)} placeholder="Store-01 POS"/></FG>
            <FG label="Terminal ID" required><Inp value={injTerminalExternalID} onChange={(e)=>setInjTerminalExternalID(e.target.value)} placeholder="pos-store-01"/></FG>
          </Row2>
          <Row2>
            <FG label="Transport"><Sel value={injTerminalTransport} onChange={(e)=>setInjTerminalTransport(e.target.value)}><option value="jwt">JWT</option><option value="mtls">mTLS</option></Sel></FG>
            <FG label="Metadata (JSON)"><Inp value={injTerminalMeta} onChange={(e)=>setInjTerminalMeta(e.target.value)} mono/></FG>
          </Row2>
          <FG label="Terminal RSA Public Key (PEM)" required>
            <Txt value={injTerminalPubPEM} onChange={(e)=>setInjTerminalPubPEM(e.target.value)} rows={5} placeholder={"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}/>
          </FG>
          <div style={{display:"flex",gap:8,marginBottom:10}}>
            <Btn small primary onClick={()=>void registerTerminal()} disabled={injectionLoading}>Register Terminal</Btn>
          </div>

          <Row2>
            <FG label="Registered Terminal"><Sel value={injSelectedTerminalRowID} onChange={(e)=>setInjSelectedTerminalRowID(e.target.value)}>{(Array.isArray(injectionTerminals)?injectionTerminals:[]).map((t)=>{return <option key={String(t?.id||"")} value={String(t?.id||"")}>{`${String(t?.name||"terminal")} [${String(t?.status||"pending")}]`}</option>;})}</Sel></FG>
            <FG label="Challenge Expires"><Inp value={injChallengeExpiry} readOnly mono/></FG>
          </Row2>
          <FG label="Challenge Nonce"><Inp value={injChallengeNonce} readOnly mono/></FG>
          <Row2>
            <FG label="Signature (base64)"><Inp value={injSignatureB64} onChange={(e)=>setInjSignatureB64(e.target.value)} mono/></FG>
            <FG label="Terminal Token (issued once)"><Inp value={injVerifiedToken} readOnly mono/></FG>
          </Row2>
          <div style={{display:"flex",gap:8,marginBottom:10}}>
            <Btn small onClick={()=>void issueChallenge()} disabled={injectionLoading||!injSelectedTerminalRowID}>Issue Challenge</Btn>
            <Btn small onClick={()=>void verifyChallenge()} disabled={injectionLoading||!injSelectedTerminalRowID}>Verify Challenge</Btn>
          </div>

          <div style={{height:1,background:C.border,margin:"10px 0"}}/>
          <Row2>
            <FG label="Payment Key"><Sel value={injSelectedPaymentKeyID} onChange={(e)=>setInjSelectedPaymentKeyID(e.target.value)}>{(Array.isArray(paymentKeyItems)?paymentKeyItems:[]).map((k)=>{return <option key={String(k?.id||"")} value={String(k?.id||"")}>{`${String(k?.id||"")} - ${String(k?.key_id||"")} (${String(k?.usage_code||"")})`}</option>;})}</Sel></FG>
            <FG label="TR-31 Version"><Sel value={injTR31Version} onChange={(e)=>setInjTR31Version(e.target.value)}><option value="D">D - AES CMAC</option><option value="B">B - TDES variant</option><option value="C">C - TDES derivation</option></Sel></FG>
          </Row2>
          <FG label="KBPK / KEK Key"><Sel value={injKBPKKeyID} onChange={(e)=>setInjKBPKKeyID(e.target.value)}>{renderKeyOptions(keyChoices)}</Sel></FG>
          <FG label="KBPK / KEK (base64 override)"><Inp value={injKBPKB64} onChange={(e)=>setInjKBPKB64(e.target.value)} mono/></FG>

          <FG label="Recent Injection Jobs">
            <div style={{maxHeight:180,overflow:"auto",border:`1px solid ${C.border}`,borderRadius:8,padding:8}}>
              {(Array.isArray(injectionJobs)?injectionJobs:[]).slice(0,12).map((j)=>{return <div key={String(j?.id||"")} style={{display:"flex",justifyContent:"space-between",gap:8,padding:"5px 0",borderBottom:`1px solid ${C.border}`}}>
                <div style={{fontSize:10,color:C.text,maxWidth:350,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{`${String(j?.id||"")} | ${String(j?.payment_key_id||"")} | ${String(j?.terminal_id||"")}`}</div>
                <B c={String(j?.status||"").toLowerCase()==="applied"?"green":String(j?.status||"").toLowerCase()==="failed"?"red":"blue"}>{String(j?.status||"queued")}</B>
              </div>;})}
              {!Array.isArray(injectionJobs)||!injectionJobs.length?<div style={{fontSize:10,color:C.dim}}>No injection jobs yet.</div>:null}
            </div>
          </FG>
        </>}

        <Btn
          primary
          full
          style={{marginTop:10}}
          onClick={()=>{if(op==="Payment Key Injection"){void createInjection();return;}void runPaymentOp();}}
          disabled={op==="Payment Key Injection"?injectionLoading:running}
        >
          {op==="Payment Key Injection"
            ? (injectionLoading?"Submitting...":"Create Injection Job")
            : (running?"Executing...":"Execute")}
        </Btn>
      </Card>
      <Card><FG label="Result"><Txt value={resultText} rows={18} readOnly/></FG></Card>
    </Row2>
  </div>;
};

