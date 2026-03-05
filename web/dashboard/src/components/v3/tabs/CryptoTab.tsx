// @ts-nocheck
import { useEffect, useMemo, useRef, useState } from "react";
import { Check, RefreshCcw, X } from "lucide-react";
import {
  decodeOutputFromBase64,
  decryptData,
  deriveKey,
  encryptData,
  hashData,
  kemDecapsulate,
  kemEncapsulate,
  randomBytes,
  signData,
  verifyData
} from "../../../lib/keycore";
import { isFipsModeEnabled } from "../runtimeUtils";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, Inp, Sel, Txt } from "../legacyPrimitives";

function normalizeKeyState(state: string): string {
  const raw = String(state || "").toLowerCase().trim();
  if (raw === "destroyed" || raw === "deleted") return "deleted";
  if (raw === "destroy-pending" || raw === "delete-pending" || raw === "deletion-pending") return "destroy-pending";
  if (raw === "preactive" || raw === "pre-active") return "pre-active";
  if (raw === "retired" || raw === "deactivated") return "deactivated";
  if (raw === "generation" || raw === "generated") return "pre-active";
  return raw || "unknown";
}

function keyStateLabel(state: string): string {
  const norm = normalizeKeyState(state);
  switch (norm) {
    case "pre-active":
      return "Pre-active";
    case "active":
      return "Active";
    case "disabled":
      return "Disabled";
    case "deactivated":
      return "Deactivated (Retired)";
    case "destroy-pending":
      return "Delete Pending";
    case "deleted":
      return "Deleted";
    default:
      return norm
        .split("-")
        .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
        .join(" ");
  }
}

function keyChoicesFromCatalog(keyCatalog: any[]): any[] {
  if (!Array.isArray(keyCatalog)) return [];
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

function isFipsAlgorithm(algorithm: string): boolean {
  const v = String(algorithm || "").toUpperCase();
  if (!v) return false;
  if (
    v.includes("CHACHA20") || v.includes("CAMELLIA") || v.includes("ECIES") || v.includes("BRAINPOOL") ||
    v.includes("KECCAK") || v.includes("RIPEMD") || v.includes("BLAKE") || v.includes("POLY1305") ||
    (v.includes("AES") && v.includes("ECB"))
  ) {
    return false;
  }
  return (
    v.includes("AES") || v.includes("RSA") || v.includes("ECDSA") || v.includes("ECDH") || v.includes("HMAC") ||
    v.includes("CMAC") || v.includes("GMAC") || v.includes("ML-KEM") || v.includes("ML-DSA") || v.includes("SLH-DSA")
  );
}

function isFipsHashAlgorithm(algorithm: string): boolean {
  const v = String(algorithm || "").toLowerCase().trim();
  return v === "sha-256" || v === "sha-384" || v === "sha-512" || v === "sha3-256" || v === "sha3-384" || v === "sha3-512";
}

function isFipsRandomSource(source: string): boolean {
  const v = String(source || "").toLowerCase().trim();
  return v === "kms-csprng" || v === "hsm-trng";
}

function isFipsMechanism(name: string): boolean {
  const v = String(name || "").toUpperCase();
  if (!v) return false;
  if (
    v.includes("CHACHA20") || v.includes("CAMELLIA") || v.includes("ECIES") || v.includes("BRAINPOOL") ||
    v.includes("KECCAK") || v.includes("RIPEMD") || v.includes("BLAKE") || v.includes("POLY1305") ||
    (v.includes("AES") && v.includes("ECB"))
  ) {
    return false;
  }
  return (
    v.includes("AES") || v.includes("RSA") || v.includes("ECDSA") || v.includes("ECDH") || v.includes("HMAC") ||
    v.includes("CMAC") || v.includes("GMAC") || v.includes("ML-KEM") || v.includes("ML-DSA") || v.includes("SLH-DSA") ||
    v.includes("SHA-256") || v.includes("SHA-384") || v.includes("SHA-512") || v.includes("SHA3")
  );
}

function isAEADAlgorithm(algorithm: string): boolean {
  const v = String(algorithm || "").toUpperCase();
  return v.includes("GCM") || v.includes("CCM") || v.includes("POLY1305");
}

function usesIVAlgorithm(algorithm: string): boolean {
  const v = String(algorithm || "").toUpperCase();
  if (!v || v.includes("ECB")) return false;
  return isAEADAlgorithm(v) || v.includes("CBC") || v.includes("CTR") || v.includes("CFB") || v.includes("OFB") || v.includes("XTS") || v.includes("CHACHA20");
}

function isHMACAlgorithm(algorithm: string): boolean {
  return String(algorithm || "").toUpperCase().includes("HMAC");
}

function isMLKEMAlgorithm(algorithm: string): boolean {
  return String(algorithm || "").toUpperCase().includes("ML-KEM");
}

function isRSAAlgorithm(algorithm: string): boolean {
  return String(algorithm || "").toUpperCase().includes("RSA");
}

function isECDSAAlgorithm(algorithm: string): boolean {
  const v = String(algorithm || "").toUpperCase();
  return v.includes("ECDSA") || v.includes("BRAINPOOL");
}

function isEd25519Algorithm(algorithm: string): boolean {
  return String(algorithm || "").toUpperCase().includes("ED25519");
}

function isSupportedSymmetricCipherAlgorithm(algorithm: string): boolean {
  const v = String(algorithm || "").toUpperCase();
  if (!v.includes("AES") && !v.includes("3DES") && !v.includes("TDES") && !v.includes("DES") && !v.includes("CHACHA20") && !v.includes("CAMELLIA")) {
    return false;
  }
  if (v.includes("CHACHA20") || v.includes("CAMELLIA")) return true;
  if (v.includes("AES")) {
    if (v.includes("ECB") || v.includes("CCM") || v.includes("CFB") || v.includes("OFB") || v.includes("XTS")) return false;
    return true;
  }
  if (v.includes("3DES") || v.includes("TDES")) return v.includes("CBC");
  return false;
}

function supportedOpsForKey(key: any): string[] {
  const algo = String(key?.algo || "");
  const keyType = String(key?.keyType || "").toLowerCase();
  const ops = new Set<string>(["Hash", "Random"]);
  if (isSupportedSymmetricCipherAlgorithm(algo)) {
    ops.add("Encrypt"); ops.add("Decrypt"); ops.add("Wrap"); ops.add("Unwrap"); ops.add("Key Derive");
  }
  if (isHMACAlgorithm(algo)) {
    ops.add("Sign"); ops.add("Verify"); ops.add("MAC"); ops.add("Key Derive");
  }
  if (isRSAAlgorithm(algo)) {
    ops.add("Encrypt"); ops.add("Wrap"); ops.add("Verify");
    if (!keyType.includes("public")) {
      ops.add("Decrypt"); ops.add("Unwrap"); ops.add("Sign");
    }
  }
  if (isECDSAAlgorithm(algo) || isEd25519Algorithm(algo)) {
    ops.add("Verify");
    if (!keyType.includes("public")) ops.add("Sign");
  }
  if (isMLKEMAlgorithm(algo)) {
    ops.add("KEM Encapsulate");
    if (!keyType.includes("public")) ops.add("KEM Decapsulate");
  }
  return Array.from(ops);
}

function supportsOperationForKey(key: any, op: string): boolean {
  const keyRequired = op !== "Hash" && op !== "Random";
  if (!keyRequired) return true;
  return supportedOpsForKey(key).includes(op);
}

function preferredKEMAlgorithmForKey(key: any): "ml-kem-768" | "ml-kem-1024" {
  const algo = String(key?.algo || "").toUpperCase();
  return algo.includes("1024") ? "ml-kem-1024" : "ml-kem-768";
}
export const CryptoTab=({session,keyCatalog,onToast,fipsMode})=>{
  const [op,setOp]=useState("Encrypt");
  const [selectedKeyId,setSelectedKeyId]=useState("");
  const [payloadInput,setPayloadInput]=useState("");
  const [signatureInput,setSignatureInput]=useState("");
  const [ivInput,setIVInput]=useState("");
  const [aadInput,setAadInput]=useState("");
  const [referenceId,setReferenceId]=useState("");
  const [inputEncoding,setInputEncoding]=useState("utf-8");
  const [aadEncoding,setAadEncoding]=useState("utf-8");
  const [binaryInputEncoding,setBinaryInputEncoding]=useState("base64");
  const [outputEncoding,setOutputEncoding]=useState("utf-8");
  const [binaryOutputEncoding,setBinaryOutputEncoding]=useState("base64");
  const [ivMode,setIVMode]=useState("internal");
  const [hmacAlgorithm,setHmacAlgorithm]=useState("hmac-sha256");
  const [hashAlgorithm,setHashAlgorithm]=useState("sha-256");
  const [kdfAlgorithm,setKdfAlgorithm]=useState("hkdf-sha256");
  const [kdfLengthBits,setKdfLengthBits]=useState("256");
  const [kdfInfo,setKdfInfo]=useState("");
  const [kdfSalt,setKdfSalt]=useState("");
  const [randomLength,setRandomLength]=useState("32");
  const [randomSource,setRandomSource]=useState("kms-csprng");
  const [kemAlgorithm,setKemAlgorithm]=useState("ml-kem-768");
  const [resultText,setResultText]=useState("// Result will appear here...");
  const [auditEvent,setAuditEvent]=useState("-");
  const [durationMs,setDurationMs]=useState("-");
  const [busy,setBusy]=useState(false);
  const [errorText,setErrorText]=useState("");
  const [pickedAlgorithm,setPickedAlgorithm]=useState("");

  const keyChoices=useMemo(()=>keyChoicesFromCatalog(keyCatalog),[keyCatalog]);
  const keyRequired = op!=="Hash" && op!=="Random";
  const activeKey = useMemo(()=>keyChoices.find((k)=>k.id===selectedKeyId)||null,[keyChoices,selectedKeyId]);
  const allowedOps = useMemo(()=>supportedOpsForKey(activeKey),[activeKey]);

  useEffect(()=>{
    if(!selectedKeyId || !keyChoices.some((k)=>k.id===selectedKeyId)){
      setSelectedKeyId(keyChoices[0]?.id||"");
    }
  },[selectedKeyId,keyChoices]);

  useEffect(()=>{
    setErrorText("");
  },[op]);

  useEffect(()=>{
    if(op==="KEM Encapsulate"||op==="KEM Decapsulate"){
      setKemAlgorithm(preferredKEMAlgorithmForKey(activeKey));
    }
  },[op,activeKey]);

  useEffect(()=>{
    if(op==="Hash"||op==="Random"){
      return;
    }
    if(!supportsOperationForKey(activeKey,op)){
      const next=allowedOps.find((item)=>item!=="Hash"&&item!=="Random")||"Hash";
      setOp(next);
    }
  },[op,activeKey,allowedOps]);

  const payloadLabel = useMemo(()=>{
    if(op==="Encrypt"){
      return "Plaintext";
    }
    if(op==="Decrypt"){
      return "Ciphertext";
    }
    if(op==="Sign"){
      return "Message";
    }
    if(op==="Verify"){
      return "Message";
    }
    if(op==="Wrap"){
      return "Material to Wrap";
    }
    if(op==="Unwrap"){
      return "Wrapped Material";
    }
    if(op==="MAC"){
      return "Message";
    }
    if(op==="Hash"){
      return "Input";
    }
    if(op==="KEM Decapsulate"){
      return "Encapsulated Key";
    }
    return "Input";
  },[op]);

  const payloadPlaceholder = useMemo(()=>{
    if(op==="Decrypt"||op==="Unwrap"||op==="KEM Decapsulate"){
      return "Paste ciphertext / encapsulated key";
    }
    if(op==="Hash"){
      return "Data to hash";
    }
    return "Enter input data";
  },[op]);

  const activeAlgo = String(activeKey?.algo || "");
  const activeIsAEAD = isAEADAlgorithm(activeAlgo);
  const activeUsesIV = usesIVAlgorithm(activeAlgo);
  const signatureModeOptions = useMemo(()=>{
    if(op==="MAC" || isHMACAlgorithm(activeAlgo)){
      return [
        {value:"hmac-sha256",label:"HMAC-SHA256"},
        {value:"hmac-sha384",label:"HMAC-SHA384"},
        {value:"hmac-sha512",label:"HMAC-SHA512"}
      ];
    }
    if(isRSAAlgorithm(activeAlgo)){
      return [
        {value:"rsa-pss-sha256",label:"RSA-PSS-SHA256"},
        {value:"rsa-pss-sha384",label:"RSA-PSS-SHA384"},
        {value:"rsa-pss-sha512",label:"RSA-PSS-SHA512"}
      ];
    }
    if(isECDSAAlgorithm(activeAlgo)){
      return [
        {value:"ecdsa-sha256",label:"ECDSA-SHA256"},
        {value:"ecdsa-sha384",label:"ECDSA-SHA384"},
        {value:"ecdsa-sha512",label:"ECDSA-SHA512"}
      ];
    }
    if(isEd25519Algorithm(activeAlgo)){
      return [{value:"ed25519",label:"Ed25519"}];
    }
    return [
      {value:"hmac-sha256",label:"HMAC-SHA256"},
      {value:"hmac-sha384",label:"HMAC-SHA384"},
      {value:"hmac-sha512",label:"HMAC-SHA512"}
    ];
  },[op,activeAlgo]);
  const opAllowedForKey = supportsOperationForKey(activeKey, op);
  const showIVMode = (op==="Encrypt" || op==="Wrap") && activeUsesIV;
  const needsPayload = op!=="Random" && op!=="Key Derive" && op!=="KEM Encapsulate";
  const needsSignature = op==="Verify";
  const needsIV = ((op==="Decrypt" || op==="Unwrap") && activeUsesIV) || (showIVMode && ivMode==="external");
  const supportsAAD = ((op==="Encrypt" || op==="Decrypt" || op==="Wrap" || op==="Unwrap") && activeIsAEAD);
  const supportsReference = op==="Encrypt" || op==="Wrap" || op==="Hash" || op==="Random" || op==="Key Derive" || op==="KEM Encapsulate" || op==="KEM Decapsulate";
  const supportsInputEncoding = op==="Encrypt"||op==="Sign"||op==="Verify"||op==="Wrap"||op==="MAC"||op==="Hash"||op==="Key Derive";
  const supportsBinaryInputEncoding = needsIV || op==="Decrypt" || op==="Unwrap" || op==="KEM Decapsulate";
  const supportsPlainOutputEncoding = op==="Decrypt" || op==="Unwrap";
  const supportsBinaryOutputEncoding = op==="Hash"||op==="Random"||op==="Key Derive"||op==="KEM Encapsulate"||op==="KEM Decapsulate";
  const runtimeFipsEnabled = isFipsModeEnabled(fipsMode);
  const selectedKeyFips = activeKey ? isFipsAlgorithm(activeAlgo) : false;
  const currentMechanismFips = keyRequired
    ? (!activeKey || selectedKeyFips)
    : op==="Hash"
      ? isFipsHashAlgorithm(hashAlgorithm)
      : op==="Random"
        ? isFipsRandomSource(randomSource)
        : true;
  const fipsExecutionBlocked = runtimeFipsEnabled && !currentMechanismFips;
  const algorithmContextHint = !keyRequired
    ? "Operation does not require a key selection."
    : !activeKey
    ? "Select a key to validate mechanism-specific fields."
    : activeIsAEAD
    ? "AEAD mode selected: AAD is available."
    : activeUsesIV
    ? "This mode uses IV/nonce but not AAD."
    : "This mode does not use IV/AAD.";

  useEffect(()=>{
    if(op!=="Sign" && op!=="Verify" && op!=="MAC"){
      return;
    }
    if(signatureModeOptions.some((item)=>item.value===hmacAlgorithm)){
      return;
    }
    setHmacAlgorithm(signatureModeOptions[0]?.value||"hmac-sha256");
  },[op,signatureModeOptions,hmacAlgorithm]);

  const applyResult = (value: any)=>{
    setResultText(JSON.stringify(value,null,2));
  };

  const runOperation = async()=>{
    if(!session){
      const message = "Session is required.";
      setErrorText(message);
      onToast?.(message);
      return;
    }
    if(keyRequired && !selectedKeyId){
      const message = "Select a key first.";
      setErrorText(message);
      onToast?.(message);
      return;
    }
    if(keyRequired && !opAllowedForKey){
      const message = `${op} is not supported for key algorithm ${activeAlgo || "selected key"}.`;
      setErrorText(message);
      onToast?.(message);
      return;
    }
    if(fipsExecutionBlocked){
      const message = "Blocked by FIPS mode. Select a FIPS-approved key/algorithm.";
      setErrorText(message);
      onToast?.(message);
      return;
    }
    if(needsPayload && !String(payloadInput||"").trim()){
      const message = `${payloadLabel} is required.`;
      setErrorText(message);
      onToast?.(message);
      return;
    }
    if(needsIV && !String(ivInput||"").trim()){
      const message = "IV is required.";
      setErrorText(message);
      onToast?.(message);
      return;
    }
    if(needsSignature && !String(signatureInput||"").trim()){
      const message = "Signature is required.";
      setErrorText(message);
      onToast?.(message);
      return;
    }

    setBusy(true);
    setErrorText("");
    const started = Date.now();
    const aadValue = supportsAAD ? aadInput : "";
    const aadValueEncoding = aadEncoding;
    const ivValue = showIVMode && ivMode==="external" ? ivInput : "";
    try{
      let audit = "";
      if(op==="Encrypt"){
        const out=await encryptData(session,selectedKeyId,payloadInput,{
          inputEncoding,
          ivMode:ivMode as any,
          iv:ivValue,
          ivEncoding:binaryInputEncoding==="hex"?"hex":"base64",
          aad:aadValue,
          aadEncoding:aadValueEncoding,
          referenceId
        });
        applyResult({ciphertext:out.ciphertext,iv:out.iv,version:out.version,key_id:out.keyId,kcv:out.kcv||"",reference_id:referenceId||""});
        audit="audit.key.encrypt";
      }else if(op==="Decrypt"){
        const out=await decryptData(session,selectedKeyId,payloadInput,ivInput,{
          inputEncoding:binaryInputEncoding as any,
          outputEncoding:outputEncoding as any,
          aad:aadValue,
          aadEncoding:aadValueEncoding
        });
        applyResult({plaintext:out.plaintext,plaintext_base64:out.plaintextBase64,version:out.version,key_id:out.keyId});
        audit="audit.key.decrypt";
      }else if(op==="Sign"){
        const out=await signData(session,selectedKeyId,payloadInput,{inputEncoding:inputEncoding as any,algorithm:hmacAlgorithm as any});
        applyResult({signature:out.signature,version:out.version,key_id:out.key_id,algorithm:hmacAlgorithm});
        audit="audit.key.sign";
      }else if(op==="Verify"){
        const out=await verifyData(session,selectedKeyId,payloadInput,signatureInput,{inputEncoding:inputEncoding as any,algorithm:hmacAlgorithm as any});
        applyResult({verified:out.verified,version:out.version,key_id:out.key_id,algorithm:hmacAlgorithm});
        audit="audit.key.verify";
      }else if(op==="Wrap"){
        const out=await encryptData(session,selectedKeyId,payloadInput,{
          inputEncoding,
          ivMode:ivMode as any,
          iv:ivValue,
          ivEncoding:binaryInputEncoding==="hex"?"hex":"base64",
          aad:aadValue,
          aadEncoding:aadValueEncoding,
          referenceId
        });
        applyResult({wrapped_material:out.ciphertext,material_iv:out.iv,version:out.version,key_id:out.keyId,kcv:out.kcv||"",reference_id:referenceId||""});
        audit="audit.key.wrap";
      }else if(op==="Unwrap"){
        const out=await decryptData(session,selectedKeyId,payloadInput,ivInput,{
          inputEncoding:binaryInputEncoding as any,
          outputEncoding:outputEncoding as any,
          aad:aadValue,
          aadEncoding:aadValueEncoding
        });
        applyResult({material:out.plaintext,material_base64:out.plaintextBase64,version:out.version,key_id:out.keyId});
        audit="audit.key.unwrap";
      }else if(op==="MAC"){
        const out=await signData(session,selectedKeyId,payloadInput,{inputEncoding:inputEncoding as any,algorithm:hmacAlgorithm as any});
        applyResult({mac:out.signature,version:out.version,key_id:out.key_id,algorithm:hmacAlgorithm});
        audit="audit.key.mac";
      }else if(op==="Hash"){
        const out=await hashData(session,payloadInput,hashAlgorithm as any,inputEncoding as any,referenceId);
        const digestRendered=binaryOutputEncoding==="hex"?decodeOutputFromBase64(out.digestBase64,"hex"):out.digestBase64;
        applyResult({algorithm:out.algorithm,digest:digestRendered,digest_base64:out.digestBase64,reference_id:referenceId||""});
        audit="audit.crypto.hash";
      }else if(op==="KEM Encapsulate"){
        const out=await kemEncapsulate(session,selectedKeyId,{
          algorithm:kemAlgorithm as any,
          referenceId
        });
        const sharedRendered=binaryOutputEncoding==="hex"?decodeOutputFromBase64(out.sharedSecretBase64,"hex"):out.sharedSecretBase64;
        applyResult({algorithm:out.algorithm,shared_secret:sharedRendered,shared_secret_base64:out.sharedSecretBase64,encapsulated_key:out.encapsulatedKeyBase64,key_id:out.keyId,version:out.version,reference_id:referenceId||""});
        audit="audit.key.kem_encapsulate";
      }else if(op==="KEM Decapsulate"){
        const out=await kemDecapsulate(session,selectedKeyId,{
          algorithm:kemAlgorithm as any,
          encapsulatedKeyBase64:payloadInput,
          inputEncoding:binaryInputEncoding as any,
          referenceId
        });
        const sharedRendered=binaryOutputEncoding==="hex"?decodeOutputFromBase64(out.sharedSecretBase64,"hex"):out.sharedSecretBase64;
        applyResult({algorithm:out.algorithm,shared_secret:sharedRendered,shared_secret_base64:out.sharedSecretBase64,key_id:out.keyId,version:out.version,reference_id:referenceId||""});
        audit="audit.key.kem_decapsulate";
      }else if(op==="Key Derive"){
        const out=await deriveKey(session,selectedKeyId,{
          algorithm:kdfAlgorithm as any,
          lengthBits:Number(kdfLengthBits||0),
          info:kdfInfo,
          salt:kdfSalt,
          infoEncoding:inputEncoding as any,
          saltEncoding:inputEncoding as any,
          referenceId
        });
        const derivedRendered=binaryOutputEncoding==="hex"?decodeOutputFromBase64(out.derivedKeyBase64,"hex"):out.derivedKeyBase64;
        applyResult({algorithm:out.algorithm,length_bits:out.lengthBits,derived_key:derivedRendered,derived_key_base64:out.derivedKeyBase64,key_id:out.keyId,version:out.version,reference_id:referenceId||""});
        audit="audit.key.derive";
      }else if(op==="Random"){
        const out=await randomBytes(session,Number(randomLength||0),randomSource as any,referenceId);
        const bytesRendered=binaryOutputEncoding==="hex"?decodeOutputFromBase64(out.bytesBase64,"hex"):out.bytesBase64;
        applyResult({bytes:bytesRendered,bytes_base64:out.bytesBase64,length:out.length,source:out.source,reference_id:referenceId||""});
        audit="audit.crypto.random";
      }
      setAuditEvent(audit);
      const elapsed=Math.max(0,Date.now()-started);
      setDurationMs(`${elapsed} ms`);
      onToast?.(`${op} completed`);
    }catch(error){
      const message=errMsg(error);
      setErrorText(message);
      setAuditEvent("failed");
      const elapsed=Math.max(0,Date.now()-started);
      setDurationMs(`${elapsed} ms`);
      applyResult({error:message});
      onToast?.(`${op} failed: ${message}`);
    }finally{
      setBusy(false);
    }
  };

  const opTabs=[
    {id:"Encrypt",label:"Encrypt"},
    {id:"Decrypt",label:"Decrypt"},
    {id:"Sign",label:"Sign"},
    {id:"Verify",label:"Verify"},
    {id:"Wrap",label:"Wrap"},
    {id:"Unwrap",label:"Unwrap"},
    {id:"MAC",label:"MAC"},
    {id:"Key Derive",label:"Derive"},
    {id:"KEM Encapsulate",label:"KEM Encap"},
    {id:"KEM Decapsulate",label:"KEM Decap"},
    {id:"Hash",label:"Hash"},
    {id:"Random",label:"Random"}
  ];

  const cryptoAlgorithms=[
    {group:"Symmetric",items:[["AES-128-GCM",true],["AES-192-GCM",true],["AES-256-GCM",true],["AES-256-CTR",true],["AES-256-CBC",true],["AES-256-ECB",false],["AES-256-CCM",true],["Camellia-256",false],["ChaCha20-Poly1305",false],["3DES",true]]},
    {group:"MAC",items:[["AES-CMAC",true],["AES-GMAC",true],["HMAC-SHA256",true],["HMAC-SHA3-256",true],["HMAC-SHA512",true],["Poly1305",true]]},
    {group:"Asymmetric",items:[["RSA-2048-OAEP",true],["RSA-4096-OAEP",true],["RSA-8192",true],["ECIES-P256",false]]},
    {group:"Signatures",items:[["RSA-PSS-4096",true],["ECDSA-P256",true],["ECDSA-P384",true],["ECDSA-P521",true],["ECDSA-Brainpool256",false],["Ed25519",true],["Ed448",true],["DSA-3072",true]]},
    {group:"Key Exchange",items:[["DH-2048",true],["DH-4096",true],["ECDH-P384",true],["X25519",true]]},
    {group:"Hash",items:[["SHA-256",true],["SHA-512",true],["SHA3-256",true],["SHA3-512",true],["SHAKE256",true],["Keccak-256",false],["RIPEMD-160",false],["BLAKE2b",false]]},
    {group:"PQC",items:[["ML-KEM-768",true],["ML-KEM-1024",true],["ML-DSA-65",true],["ML-DSA-87",true],["SLH-DSA-256f",true],["HSS/LMS",true],["XMSS",true]]},
    {group:"Hybrid",items:[["ECDH + ML-KEM-768",true],["ECDSA + ML-DSA-65",true]]}
  ];

  const inferOperationFromAlgorithm=(algorithmName:string):string=>{
    const value=String(algorithmName||"").toUpperCase();
    if(!value){
      return "Encrypt";
    }
    if(
      value.includes("HMAC")||
      value.includes("CMAC")||
      value.includes("GMAC")||
      value==="POLY1305"
    ){
      return "MAC";
    }
    if(
      value.includes("SHA")||
      value.includes("SHAKE")||
      value.includes("KECCAK")||
      value.includes("RIPEMD")||
      value.includes("BLAKE")
    ){
      return "Hash";
    }
    if(value.includes("ML-KEM")){
      return "KEM Encapsulate";
    }
    if(
      value.includes("ML-DSA")||
      value.includes("SLH-DSA")||
      value.includes("RSA-PSS")||
      value.includes("ECDSA")||
      value.includes("ED25519")||
      value.includes("ED448")
    ){
      return "Sign";
    }
    if(
      value.startsWith("DH-")||
      value.includes("ECDH")||
      value.includes("X25519")||
      value.includes("X448")
    ){
      return "Key Derive";
    }
    return "Encrypt";
  };

  const selectAlgorithmFromRail=(algorithmName:string,fipsApproved:boolean)=>{
    if(runtimeFipsEnabled && !fipsApproved){
      onToast?.(`${algorithmName} is blocked while FIPS mode is enabled.`);
      return;
    }
    setPickedAlgorithm(algorithmName);
    const nextOp=inferOperationFromAlgorithm(algorithmName);
    setOp(nextOp);
    const normalized=String(algorithmName||"").toUpperCase();
    const matchingKey=keyChoices.find((k)=>{
      const keyAlgo=String(k?.algo||"").toUpperCase();
      return keyAlgo===normalized||keyAlgo.includes(normalized)||normalized.includes(keyAlgo);
    });
    if(matchingKey){
      setSelectedKeyId(matchingKey.id);
    }else if(nextOp!=="Hash"&&nextOp!=="Random"){
      onToast?.(`No backend key found for ${algorithmName}. Create/import a matching key first.`);
    }
  };

  const selectedAlgorithmInRail=String(pickedAlgorithm||activeAlgo||"").toUpperCase();

  const renderResultAsHex=()=>{
    try{
      const bytes=new TextEncoder().encode(resultText);
      const hex=Array.from(bytes).map((b)=>b.toString(16).padStart(2,"0")).join("");
      setResultText(hex);
    }catch(error){
      onToast?.(`Hex render failed: ${errMsg(error)}`);
    }
  };

  const renderResultAsBase64=()=>{
    try{
      const bytes=new TextEncoder().encode(resultText);
      let raw="";
      bytes.forEach((b)=>{raw+=String.fromCharCode(b);});
      setResultText(btoa(raw));
    }catch(error){
      onToast?.(`Base64 render failed: ${errMsg(error)}`);
    }
  };

  const downloadResult=()=>{
    try{
      const blob=new Blob([resultText],{type:"text/plain;charset=utf-8"});
      const url=URL.createObjectURL(blob);
      const anchor=document.createElement("a");
      anchor.href=url;
      anchor.download=`crypto-${String(op||"result").toLowerCase().replace(/\s+/g,"-")}.txt`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    }catch(error){
      onToast?.(`Download failed: ${errMsg(error)}`);
    }
  };

  const opButtonLabel=opTabs.find((item)=>item.id===op)?.label||op;
  const showModeSelector=op==="Sign"||op==="Verify"||op==="MAC"||op==="Hash"||op==="KEM Encapsulate"||op==="KEM Decapsulate"||op==="Key Derive";
  const topControlColumns=keyRequired&&showModeSelector?"1fr 1fr":"1fr";

  return <div style={{display:"grid",gridTemplateColumns:"270px 1fr",gap:12,alignItems:"start"}}>
    <div style={{background:C.card,border:`1px solid ${C.borderHi}`,borderRadius:12,padding:12,maxHeight:680,overflowY:"auto"}}>
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:8,marginBottom:8}}>
        <div style={{fontSize:11,fontWeight:700,color:C.dim,textTransform:"uppercase",letterSpacing:1}}>Algorithms</div>
        <div
          title={runtimeFipsEnabled?"FIPS mode is enforced globally from Administration":"Standard mode allows all algorithms"}
          style={{
            display:"inline-flex",
            alignItems:"center",
            gap:5,
            padding:"4px 8px",
            borderRadius:999,
            border:`1px solid ${runtimeFipsEnabled?(currentMechanismFips?C.green:C.red):C.blue}`,
            background:runtimeFipsEnabled?(currentMechanismFips?C.greenDim:C.redDim):C.blueDim,
            color:runtimeFipsEnabled?(currentMechanismFips?C.green:C.red):C.blue,
            fontSize:10,
            fontWeight:700
          }}
        >
          {runtimeFipsEnabled
            ?(currentMechanismFips?<Check size={11} strokeWidth={2.5}/>:<X size={11} strokeWidth={2.5}/>)
            :<Check size={11} strokeWidth={2.5}/>}
          FIPS
        </div>
      </div>
      <div style={{display:"grid",gap:10}}>
        {cryptoAlgorithms.map((section)=>(
          <div key={section.group}>
            <div style={{fontSize:10,fontWeight:700,color:C.accent,textTransform:"uppercase",letterSpacing:.9,marginBottom:4}}>{section.group}</div>
            <div style={{display:"grid",gap:2}}>
              {section.items.map(([name,ok])=>{
                const fipsApproved=Boolean(ok);
                const allowedByMode=!runtimeFipsEnabled || fipsApproved;
                return (
                <button
                  key={`${section.group}-${name}`}
                  onClick={()=>selectAlgorithmFromRail(String(name),fipsApproved)}
                  disabled={!allowedByMode}
                  style={{
                    display:"grid",
                    gridTemplateColumns:"1fr auto",
                    alignItems:"center",
                    gap:8,
                    padding:"4px 6px",
                    borderRadius:6,
                    border:`1px solid ${selectedAlgorithmInRail===String(name).toUpperCase()?C.accent:C.border}`,
                    background:selectedAlgorithmInRail===String(name).toUpperCase()?C.accentDim:"transparent",
                    cursor:allowedByMode?"pointer":"not-allowed",
                    opacity:allowedByMode?1:.75
                  }}
                >
                  <span style={{fontSize:10,color:C.text}}>{name}</span>
                  <span style={{display:"inline-flex",alignItems:"center",justifyContent:"center",width:16,height:16,borderRadius:4,border:`1px solid ${allowedByMode?C.green:C.red}`,background:allowedByMode?C.greenDim:C.redDim,color:allowedByMode?C.green:C.red}}>
                    {allowedByMode?<Check size={10} strokeWidth={2.5}/>:<X size={10} strokeWidth={2.5}/>}
                  </span>
                </button>
              )})}
            </div>
          </div>
        ))}
      </div>
    </div>

    <div>
      <div style={{display:"flex",justifyContent:"space-between",gap:10,flexWrap:"wrap",marginBottom:10}}>
        <div style={{display:"flex",gap:6,flexWrap:"wrap",alignItems:"center"}}>
          {opTabs.map((item)=>(
            (()=>{ const tabAllowed = supportsOperationForKey(activeKey,item.id); return (
            <button
              key={item.id}
              onClick={()=>{ if(tabAllowed){ setOp(item.id); } }}
              disabled={!tabAllowed}
              style={{
                background:op===item.id?C.accent:"transparent",
                color:op===item.id?C.bg:(!tabAllowed?C.muted:C.dim),
                border:`1px solid ${op===item.id?C.accent:C.border}`,
                borderRadius:8,
                padding:"7px 14px",
                fontSize:11,
                fontWeight:700,
                cursor:tabAllowed?"pointer":"not-allowed",
                opacity:tabAllowed?1:.55
              }}
            >
              {item.label}
            </button>
          )})()
          ))}
          <div style={{width:1,height:18,background:C.border,marginLeft:2,marginRight:2}}/>
        </div>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
        <div style={{background:C.card,border:`1px solid ${C.borderHi}`,borderRadius:12,padding:12}}>
          <div style={{fontSize:10,fontWeight:700,color:C.dim,textTransform:"uppercase",letterSpacing:.9,marginBottom:8}}>Input</div>
          <div style={{display:"grid",gap:9}}>
            <div style={{display:"grid",gridTemplateColumns:topControlColumns,gap:8}}>
              {keyRequired&&<Sel value={selectedKeyId} onChange={(e)=>setSelectedKeyId(e.target.value)} style={{height:40,borderRadius:9,fontSize:12}}>
                {renderKeyOptions(keyChoices)}
              </Sel>}
              {showModeSelector&&(
                op==="Sign"||op==="Verify"||op==="MAC"
                  ?<Sel value={hmacAlgorithm} onChange={(e)=>setHmacAlgorithm(e.target.value)} style={{height:40,borderRadius:9,fontSize:12}}>
                    {signatureModeOptions.map((item)=><option key={item.value} value={item.value}>{item.label}</option>)}
                  </Sel>
                  :op==="Hash"
                  ?<Sel value={hashAlgorithm} onChange={(e)=>setHashAlgorithm(e.target.value)} style={{height:40,borderRadius:9,fontSize:12}}>
                    <option value="sha-256">SHA-256</option>
                    <option value="sha-384">SHA-384</option>
                    <option value="sha-512">SHA-512</option>
                    <option value="sha3-256">SHA3-256</option>
                    <option value="sha3-384">SHA3-384</option>
                    <option value="sha3-512">SHA3-512</option>
                    <option value="blake2b-256">BLAKE2b-256</option>
                  </Sel>
                  :op==="Key Derive"
                  ?<Sel value={kdfAlgorithm} onChange={(e)=>setKdfAlgorithm(e.target.value)} style={{height:40,borderRadius:9,fontSize:12}}>
                    <option value="hkdf-sha256">HKDF-SHA256</option>
                    <option value="hkdf-sha384">HKDF-SHA384</option>
                    <option value="hkdf-sha512">HKDF-SHA512</option>
                  </Sel>
                  :<Sel value={kemAlgorithm} onChange={(e)=>setKemAlgorithm(e.target.value)} style={{height:40,borderRadius:9,fontSize:12}}>
                    <option value="ml-kem-768">ML-KEM-768</option>
                    <option value="ml-kem-1024">ML-KEM-1024</option>
                  </Sel>
              )}
            </div>

            <div style={{fontSize:10,color:C.muted}}>
              {activeKey?`Key: ${activeKey.name} (${activeKey.algo}) - ${keyStateLabel(activeKey.state)} - ${activeKey.ver}`:algorithmContextHint}
            </div>

            {needsPayload&&<Txt rows={7} placeholder={payloadPlaceholder} value={payloadInput} onChange={(e)=>setPayloadInput(e.target.value)} style={{minHeight:156}}/>}

            {needsSignature&&<Inp placeholder="Signature (base64)" value={signatureInput} onChange={(e)=>setSignatureInput(e.target.value)} mono/>}

            {showIVMode&&<Sel value={ivMode} onChange={(e)=>setIVMode(e.target.value)}>
              <option value="internal">IV Mode: internal</option>
              <option value="external">IV Mode: external</option>
              <option value="deterministic">IV Mode: deterministic</option>
            </Sel>}

            {needsIV&&<Inp placeholder="IV / nonce" value={ivInput} onChange={(e)=>setIVInput(e.target.value)} mono/>}

            {supportsAAD&&<div style={{display:"grid",gridTemplateColumns:"1fr 140px",gap:8}}>
              <Inp placeholder="AAD (Additional authenticated data)" value={aadInput} onChange={(e)=>setAadInput(e.target.value)} mono/>
              <Sel value={aadEncoding} onChange={(e)=>setAadEncoding(e.target.value)}>
                <option value="utf-8">AAD: UTF-8</option>
                <option value="base64">AAD: Base64</option>
                <option value="hex">AAD: Hex</option>
              </Sel>
            </div>}

            {op==="Key Derive"&&<div style={{display:"grid",gridTemplateColumns:"140px 1fr 1fr",gap:8}}>
              <Inp type="number" min="8" step="8" value={kdfLengthBits} onChange={(e)=>setKdfLengthBits(e.target.value)} placeholder="Length (bits)"/>
              <Inp value={kdfInfo} onChange={(e)=>setKdfInfo(e.target.value)} placeholder="KDF info/context"/>
              <Inp value={kdfSalt} onChange={(e)=>setKdfSalt(e.target.value)} placeholder="KDF salt"/>
            </div>}

            {op==="Random"&&<div style={{display:"grid",gridTemplateColumns:"160px 1fr",gap:8}}>
              <Inp type="number" min="1" max="4096" value={randomLength} onChange={(e)=>setRandomLength(e.target.value)} placeholder="Length (bytes)"/>
              <Sel value={randomSource} onChange={(e)=>setRandomSource(e.target.value)}>
                <option value="kms-csprng">KMS CSPRNG</option>
                <option value="hsm-trng">HSM TRNG</option>
                <option value="qkd-seeded-csprng">QKD-seeded CSPRNG</option>
              </Sel>
            </div>}

            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
              {supportsInputEncoding&&<Sel value={inputEncoding} onChange={(e)=>setInputEncoding(e.target.value)}>
                <option value="utf-8">Encoding: UTF-8</option>
                <option value="base64">Encoding: Base64</option>
                <option value="hex">Encoding: Hex</option>
              </Sel>}
              {supportsBinaryInputEncoding&&<Sel value={binaryInputEncoding} onChange={(e)=>setBinaryInputEncoding(e.target.value)}>
                <option value="base64">Binary input: Base64</option>
                <option value="hex">Binary input: Hex</option>
              </Sel>}
              {supportsPlainOutputEncoding&&<Sel value={outputEncoding} onChange={(e)=>setOutputEncoding(e.target.value)}>
                <option value="utf-8">Plain output: UTF-8</option>
                <option value="base64">Plain output: Base64</option>
                <option value="hex">Plain output: Hex</option>
              </Sel>}
              {supportsBinaryOutputEncoding&&<Sel value={binaryOutputEncoding} onChange={(e)=>setBinaryOutputEncoding(e.target.value)}>
                <option value="base64">Binary output: Base64</option>
                <option value="hex">Binary output: Hex</option>
              </Sel>}
            </div>

            {supportsReference&&<Inp placeholder="Reference ID (txn-...)" value={referenceId} onChange={(e)=>setReferenceId(e.target.value)} mono/>}

            <button
              onClick={runOperation}
              disabled={busy || (keyRequired && !selectedKeyId) || fipsExecutionBlocked || (keyRequired && !opAllowedForKey)}
              style={{
                background:`linear-gradient(180deg, ${C.glowStrong}, ${C.glow})`,
                color:C.accent,
                border:`1px solid ${C.accent}`,
                borderRadius:10,
                height:38,
                fontSize:13,
                fontWeight:700,
                cursor:busy || (keyRequired && !selectedKeyId) || fipsExecutionBlocked || (keyRequired && !opAllowedForKey)?"not-allowed":"pointer",
                opacity:busy || (keyRequired && !selectedKeyId) || fipsExecutionBlocked || (keyRequired && !opAllowedForKey)?0.7:1
              }}
            >
              {busy?`Execute ${opButtonLabel}...`:`Execute ${opButtonLabel}`}
            </button>
            {fipsExecutionBlocked&&<div style={{fontSize:10,color:C.red}}>This action is blocked by global FIPS mode.</div>}
            {keyRequired&&!opAllowedForKey&&<div style={{fontSize:10,color:C.red}}>{`${op} is not valid for key algorithm ${activeAlgo || "-"}.`}</div>}
          </div>
        </div>

        <div style={{background:C.card,border:`1px solid ${C.borderHi}`,borderRadius:12,padding:12,display:"grid",gap:8}}>
          <div style={{fontSize:10,fontWeight:700,color:C.dim,textTransform:"uppercase",letterSpacing:.9}}>Output</div>
          <Txt rows={16} value={resultText} readOnly style={{minHeight:300}}/>
          <div style={{display:"flex",justifyContent:"space-between",gap:8,flexWrap:"wrap",alignItems:"center"}}>
            <div style={{fontSize:10,color:errorText?C.red:C.green,fontFamily:"'JetBrains Mono',monospace"}}>{auditEvent} - {durationMs}</div>
            <div style={{display:"flex",gap:6}}>
              <Btn small onClick={renderResultAsHex}>Hex</Btn>
              <Btn small onClick={renderResultAsBase64}>Base64</Btn>
              <Btn small onClick={downloadResult}>Download</Btn>
            </div>
          </div>
          {errorText&&<div style={{fontSize:10,color:C.red}}>{errorText}</div>}
        </div>
      </div>
    </div>
  </div>;
};
