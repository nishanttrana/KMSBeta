// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import { MoreVertical, RefreshCcw } from "lucide-react";
import {
  acmeChallengeComplete,
  acmeFinalize,
  acmeNewAccount,
  acmeNewOrder,
  cmpv2Request,
  createCA,
  deleteCA,
  deleteCertificate,
  downloadCertificateAsset,
  estServerKeygen,
  getCRL,
  getOCSP,
  issueCertificate,
  listCAs,
  listCertificates,
  listInventory,
  listProfiles,
  listProtocolConfigs,
  listProtocolSchemas,
  renewCertificate,
  revokeCertificate,
  scepEnroll,
  signCertificateCSR,
  updateProtocolConfig,
  uploadThirdPartyCertificate,
  getCertExpiryAlertPolicy,
  updateCertExpiryAlertPolicy
} from "../../../lib/certs";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Bar, Btn, Card, Chk, FG, Inp, Modal, Radio, Row2, Section, Sel, Stat, Txt, usePromptDialog } from "../legacyPrimitives";

function sanitizeDisplayText(value: unknown): string {
  return String(value || "")
    .replace(/\uFFFD/g, " ")
    .replace(/[\u2013\u2014]/g, "-")
    .replace(/\u2192/g, "->")
    .replace(/[\u2022\u00B7]/g, " | ")
    .replace(/[^\x20-\x7E]/g, "")
    .replace(/\s{2,}/g, " ")
    .trim();
}

function formatDestroyAt(value: string): string {
  const raw = String(value || "").trim();
  if (!raw) {
    return "-";
  }
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) {
    return raw;
  }
  return dt.toLocaleString();
}
export const CertsTab=({session,onToast,subView,onSubViewChange})=>{
  const [modal,setModal]=useState(null);
  const [loading,setLoading]=useState(false);
  const [submitting,setSubmitting]=useState(false);
  const [testingProtocol,setTestingProtocol]=useState("");
  const [cas,setCAs]=useState([]);
  const [certs,setCerts]=useState([]);
  const [profiles,setProfiles]=useState([]);
  const [inventory,setInventory]=useState([]);
  const [protocols,setProtocols]=useState([]);
  const [protocolSchemas,setProtocolSchemas]=useState([]);

  const [caType,setCAType]=useState("root");
  const [caParent,setCAParent]=useState("");
  const [caAlgorithm,setCAAlgorithm]=useState("RSA-4096-SHA384");
  const [caSubject,setCASubject]=useState("CN=Vecta Root CA, O=Bank Corp, C=CH");
  const [caValidity,setCAValidity]=useState("3650");
  const [caBackend,setCABackend]=useState("keycore");
  const [caPathLength,setCAPathLength]=useState("1");
  const [caKeyUsageSign,setCAKeyUsageSign]=useState(true);
  const [caKeyUsageCRL,setCAKeyUsageCRL]=useState(true);
  const [caKeyUsageDigital,setCAKeyUsageDigital]=useState(false);

  const [issueCAID,setIssueCAID]=useState("");
  const [issueProfileID,setIssueProfileID]=useState("");
  const [issueCertType,setIssueCertType]=useState("tls-server");
  const [issueAlgorithm,setIssueAlgorithm]=useState("ECDSA-P384");
  const [issueCN,setIssueCN]=useState("");
  const [issueSANs,setIssueSANs]=useState("");
  const [issueOrg,setIssueOrg]=useState("Bank Corp");
  const [issueValidityMode,setIssueValidityMode]=useState("preset");
  const [issueValidityDays,setIssueValidityDays]=useState("365");
  const [issueValidityCustomDays,setIssueValidityCustomDays]=useState("365");
  const [issueNotAfter,setIssueNotAfter]=useState("");
  const [issueDigitalSig,setIssueDigitalSig]=useState(true);
  const [issueKeyEnc,setIssueKeyEnc]=useState(true);
  const [issueTLSAuth,setIssueTLSAuth]=useState(true);
  const [issueTLSClient,setIssueTLSClient]=useState(false);
  const [issueCodeSign,setIssueCodeSign]=useState(false);
  const [issueAutoRenew,setIssueAutoRenew]=useState(false);
  const [issueEnableOCSP,setIssueEnableOCSP]=useState(true);

  const [uploadPurpose,setUploadPurpose]=useState("KMS Web Interface (HTTPS:443)");
  const [uploadCertPEM,setUploadCertPEM]=useState("");
  const [uploadKeyPEM,setUploadKeyPEM]=useState("");
  const [uploadBundlePEM,setUploadBundlePEM]=useState("");
  const [uploadSetActive,setUploadSetActive]=useState(true);
  const [uploadEnableOCSP,setUploadEnableOCSP]=useState(true);
  const [uploadAutoRenew,setUploadAutoRenew]=useState(false);

  const [csrCAID,setCSRCAID]=useState("");
  const [csrProfileID,setCSRProfileID]=useState("");
  const [csrCertType,setCSRCertType]=useState("tls-server");
  const [csrAlgorithm,setCSRAlgorithm]=useState("ECDSA-P384");
  const [csrPEM,setCSRPEM]=useState("");
  const [csrValidityMode,setCSRValidityMode]=useState("preset");
  const [csrValidityDays,setCSRValidityDays]=useState("365");
  const [csrValidityCustomDays,setCSRValidityCustomDays]=useState("365");
  const [csrNotAfter,setCSRNotAfter]=useState("");

  const [protocolName,setProtocolName]=useState("acme");
  const [protocolEnabled,setProtocolEnabled]=useState(true);
  const [protocolConfigText,setProtocolConfigText]=useState("{}");
  const [caExpanded,setCAExpanded]=useState({});
  const [issuedExpanded,setIssuedExpanded]=useState({});
  const [rowActionBusy,setRowActionBusy]=useState("");
  const [caStatusView,setCAStatusView]=useState("all");
  const [certStatusView,setCertStatusView]=useState("all");
  const [certSearch,setCertSearch]=useState("");
  const [certPageSize,setCertPageSize]=useState(10);
  const [certPageIndex,setCertPageIndex]=useState(0);
  const [openCertActionMenuId,setOpenCertActionMenuId]=useState("");
  const [certActionMenuPos,setCertActionMenuPos]=useState({top:0,left:0});
  const [downloadTargetCert,setDownloadTargetCert]=useState(null);
  const [downloadAsset,setDownloadAsset]=useState("certificate");
  const [downloadFormat,setDownloadFormat]=useState("pem");
  const [downloadIncludeChain,setDownloadIncludeChain]=useState(true);
  const [downloadPassword,setDownloadPassword]=useState("");
  const [alertPolicyDaysBefore,setAlertPolicyDaysBefore]=useState(30);
  const [alertPolicyIncludeExternal,setAlertPolicyIncludeExternal]=useState(true);
  const [alertPolicySaving,setAlertPolicySaving]=useState(false);
  const promptDialog=usePromptDialog();
  const requestedCertPane=String(subView||"cert-overview").trim().toLowerCase();
  const activeCertPane=requestedCertPane==="cert-enrollment"?"cert-enrollment":"cert-overview";
  const showEnrollmentPane=activeCertPane==="cert-enrollment";
  const showOverviewPane=!showEnrollmentPane;

  const refresh=async()=>{
    if(!session){
      return;
    }
    setLoading(true);
    try{
      const loadAllCertificates=async()=>{
        const out=[];
        let offset=0;
        while(offset<=10000){
          const batch=await listCertificates(session,{limit:500,offset});
          out.push(...(Array.isArray(batch)?batch:[]));
          if(!Array.isArray(batch)||batch.length<500){
            break;
          }
          offset+=500;
        }
        return out;
      };
      const [caItems,certItems,profileItems,inventoryItems,protocolItems,protocolSchemaItems,alertPolicy]=await Promise.all([
        listCAs(session),
        loadAllCertificates(),
        listProfiles(session),
        listInventory(session),
        listProtocolConfigs(session),
        listProtocolSchemas(session),
        getCertExpiryAlertPolicy(session)
      ]);
      setCAs(Array.isArray(caItems)?caItems:[]);
      setCerts(Array.isArray(certItems)?certItems:[]);
      setProfiles(Array.isArray(profileItems)?profileItems:[]);
      setInventory(Array.isArray(inventoryItems)?inventoryItems:[]);
      setProtocols(Array.isArray(protocolItems)?protocolItems:[]);
      setProtocolSchemas(Array.isArray(protocolSchemaItems)?protocolSchemaItems:[]);
      setAlertPolicyDaysBefore(Math.max(1,Math.min(3650,Number(alertPolicy?.days_before||30))));
      setAlertPolicyIncludeExternal(Boolean(alertPolicy?.include_external ?? true));
      if(!issueCAID&&Array.isArray(caItems)&&caItems.length){
        setIssueCAID(caItems[0].id);
      }
      if(!csrCAID&&Array.isArray(caItems)&&caItems.length){
        setCSRCAID(caItems[0].id);
      }
    }catch(e){
      onToast?.(`PKI refresh failed: ${errMsg(e)}`);
    }finally{
      setLoading(false);
    }
  };

  useEffect(()=>{
    if(!session?.tenantId){
      return;
    }
    void refresh();
  },[session?.tenantId]);

  useEffect(()=>{
    if(!onSubViewChange){
      return;
    }
    if(String(subView||"").trim()){
      return;
    }
    onSubViewChange("cert-overview");
  },[subView,onSubViewChange]);

  const protocolOrder=useMemo(()=>["acme","est","scep","cmpv2","runtime-mtls"],[]);

  const protocolSchemaByName=useMemo(()=>{
    const out={};
    (Array.isArray(protocolSchemas)?protocolSchemas:[]).forEach((schema)=>{
      const key=String(schema?.protocol||"").toLowerCase();
      if(key){
        out[key]=schema;
      }
    });
    return out;
  },[protocolSchemas]);

  const protocolMeta=useMemo(()=>{
    return protocolOrder.map((name)=>{
      const schema=protocolSchemaByName[name]||{};
      const fallback=(name==="acme"?{title:"ACME",rfc:"RFC 8555",desc:"HTTP-01, DNS-01"}:
        name==="est"?{title:"EST",rfc:"RFC 7030",desc:"IoT enrollment"}:
        name==="scep"?{title:"SCEP",rfc:"RFC 8894",desc:"MDM / Legacy"}:
        name==="cmpv2"?{title:"CMPv2",rfc:"RFC 4210",desc:"Enterprise PKI"}:
        {title:"Runtime mTLS",rfc:"Internal",desc:"Tenant runtime root CA selection"});
      const rfcRaw=String(schema?.rfc||fallback.rfc||"").trim();
      const rfcLabel=/^rfc\s*/i.test(rfcRaw)?`RFC ${rfcRaw.replace(/^rfc\s*/i,"")}`:rfcRaw;
      return {
        name,
        title:String(schema?.title||fallback.title),
        rfc:rfcLabel,
        desc:String(schema?.description||fallback.desc)
      };
    });
  },[protocolOrder,protocolSchemaByName]);

  const protocolDefaultConfigs=useMemo(()=>{
    const fallback={
      acme:{rfc:"8555",challenge_types:["http-01","dns-01"],auto_renew:true,require_eab:false,allow_wildcard:true,allow_ip_identifiers:false,max_sans:100,default_validity_days:397,rate_limit_per_hour:1000},
      est:{rfc:"7030",device_enrollment:true,server_keygen:true,auth_mode:"mtls",require_csr_pop:true,allow_reenroll:true,default_validity_days:397,max_csr_bytes:32768},
      scep:{rfc:"8894",legacy_mdm:true,challenge_password_required:false,challenge_password:"",allow_renewal:true,default_validity_days:397,max_csr_bytes:32768,digest_algorithms:["sha256","sha384"],encryption_algorithms:["aes256","aes128","des3"]},
      cmpv2:{rfc:"4210",enterprise_pki:true,message_types:["ir","cr","kur","rr"],require_message_protection:true,require_transaction_id:true,allow_implicit_confirm:true,default_validity_days:397},
      "runtime-mtls":{mode:"default",runtime_root_ca_name:""}
    };
    const out={...fallback};
    protocolOrder.forEach((name)=>{
      const schema=protocolSchemaByName[name];
      if(schema&&schema.defaults&&typeof schema.defaults==="object"){
        out[name]=schema.defaults;
      }
    });
    return out;
  },[protocolOrder,protocolSchemaByName]);

  const protocolOptionDocs=useMemo(()=>{
    const fallback={
      acme:["challenge_types: http-01 | dns-01 | tls-alpn-01","require_eab: enforce external account binding","allow_wildcard / allow_ip_identifiers","max_sans / default_validity_days / rate_limit_per_hour"],
      est:["auth_mode: mtls | basic | bearer | none","require_csr_pop: CSR proof-of-possession required","server_keygen and allow_reenroll toggles","default_validity_days and max_csr_bytes guardrails"],
      scep:["challenge_password_required + challenge_password","allow_renewal toggle","digest_algorithms and encryption_algorithms policies","default_validity_days and max_csr_bytes guardrails"],
      cmpv2:["message_types: ir | cr | kur | rr","require_message_protection and require_transaction_id","allow_implicit_confirm toggle","default_validity_days policy"],
      "runtime-mtls":["mode: default | custom","runtime_root_ca_name is required only when mode=custom","Controls per-tenant runtime root CA selection for internal mTLS issuance"]
    };
    const out={...fallback};
    protocolOrder.forEach((name)=>{
      const schema=protocolSchemaByName[name];
      if(schema&&Array.isArray(schema.options)&&schema.options.length){
        out[name]=schema.options.map((opt)=>{
          const allowed=Array.isArray(opt?.allowed)&&opt.allowed.length?` allowed=${opt.allowed.join("|")}`:"";
          return `${String(opt?.key||"")} (${String(opt?.type||"value")})${allowed} - ${String(opt?.description||"")}`;
        });
      }
    });
    return out;
  },[protocolOrder,protocolSchemaByName]);

  const activeProtocolDocs=protocolOptionDocs[String(protocolName||"").toLowerCase()]||[];
  const activeProtocolImplementation=(protocolSchemaByName[String(protocolName||"").toLowerCase()]||{}).implementation||null;

  const protocolByName=useMemo(()=>{
    const out={};
    (Array.isArray(protocols)?protocols:[]).forEach((cfg)=>{
      out[String(cfg.protocol||"").toLowerCase()]=cfg;
    });
    return out;
  },[protocols]);

  const certByID=useMemo(()=>{
    const out=new Map();
    (Array.isArray(certs)?certs:[]).forEach((c)=>out.set(String(c.id),c));
    return out;
  },[certs]);

  const certsByCA=useMemo(()=>{
    const out={};
    (Array.isArray(certs)?certs:[]).forEach((c)=>{
      const key=String(c.ca_id||"");
      if(!out[key]){
        out[key]=[];
      }
      out[key].push(c);
    });
    return out;
  },[certs]);

  const roots=useMemo(()=>{
    const all=Array.isArray(cas)?cas:[];
    const ids=new Set(all.map((c)=>String(c.id)));
    return all.filter((c)=>!String(c.parent_ca_id||"").trim()||!ids.has(String(c.parent_ca_id)));
  },[cas]);

  const childrenOf=(caID)=>{
    return (Array.isArray(cas)?cas:[]).filter((c)=>String(c.parent_ca_id||"")===String(caID||""));
  };
  useEffect(()=>{
    const all=Array.isArray(cas)?cas:[];
    if(!all.length){
      return;
    }
    setCAExpanded((prev)=>{
      const next={...(prev||{})};
      all.forEach((ca)=>{
        const id=String(ca?.id||"");
        if(id&&!Object.prototype.hasOwnProperty.call(next,id)){
          next[id]=true;
        }
      });
      return next;
    });
    setIssuedExpanded((prev)=>{
      const next={...(prev||{})};
      all.forEach((ca)=>{
        const id=String(ca?.id||"");
        if(id&&!Object.prototype.hasOwnProperty.call(next,id)){
          next[id]=true;
        }
      });
      return next;
    });
  },[cas]);

  useEffect(()=>{
    if(!openCertActionMenuId){
      return;
    }
    const close=()=>setOpenCertActionMenuId("");
    window.addEventListener("click",close);
    return()=>window.removeEventListener("click",close);
  },[openCertActionMenuId]);

  useEffect(()=>{
    setCertPageIndex(0);
  },[certStatusView,certPageSize,certSearch]);

  useEffect(()=>{
    if(downloadAsset==="public-key"){
      if(!["pem","der","pkcs8"].includes(String(downloadFormat||""))){
        setDownloadFormat("pem");
      }
      return;
    }
    if(downloadAsset==="pkcs11"){
      if(downloadFormat!=="pem"){
        setDownloadFormat("pem");
      }
      return;
    }
    if(!["pem","der","pkcs12","pfx"].includes(String(downloadFormat||""))){
      setDownloadFormat("pem");
    }
  },[downloadAsset,downloadFormat]);

  const stats=useMemo(()=>{
    const all=Array.isArray(certs)?certs:[];
    const active=all.filter((c)=>String(c.status||"").toLowerCase()==="active").length;
    const revoked=all.filter((c)=>String(c.status||"").toLowerCase()==="revoked").length;
    const deleted=all.filter((c)=>String(c.status||"").toLowerCase()==="deleted").length;
    const pqc=all.filter((c)=>{
      const cls=String(c.cert_class||"").toLowerCase();
      return cls==="pqc"||cls==="hybrid";
    }).length;
    const expiring=(Array.isArray(inventory)?inventory:[]).filter((it)=>{
      const cert=certByID.get(String(it.cert_id||""));
      if(!alertPolicyIncludeExternal&&String(cert?.ca_id||"").toLowerCase()==="external-ca"){
        return false;
      }
      const ts=new Date(String(it.not_after||"")).getTime();
      if(Number.isNaN(ts)){
        return false;
      }
      const left=ts-Date.now();
      return left>=0&&left<=alertPolicyDaysBefore*24*3600*1000;
    }).length;
    return {active,revoked,deleted,pqc,expiring,total:all.length,cas:(Array.isArray(cas)?cas:[]).length};
  },[cas,certs,inventory,certByID,alertPolicyDaysBefore,alertPolicyIncludeExternal]);

  const expiryItems=useMemo(()=>{
    const items=(Array.isArray(inventory)?inventory:[]).map((it)=>{
      const cert=certByID.get(String(it.cert_id||""));
      if(!alertPolicyIncludeExternal&&String(cert?.ca_id||"").toLowerCase()==="external-ca"){
        return null;
      }
      const notAfterRaw=String(it.not_after||cert?.not_after||"");
      const ts=new Date(notAfterRaw).getTime();
      const daysLeft=Number.isNaN(ts)?9999:Math.ceil((ts-Date.now())/(24*3600*1000));
      return {
        certId:String(it.cert_id||""),
        subject:String(cert?.subject_cn||it.cert_id||"certificate"),
        notAfter:notAfterRaw,
        daysLeft
      };
    }).filter(Boolean);
    items.sort((a,b)=>a.daysLeft-b.daysLeft);
    return items.slice(0,5);
  },[inventory,certByID,alertPolicyIncludeExternal]);

  const filteredCerts=useMemo(()=>{
    const q=String(certSearch||"").trim().toLowerCase();
    const out=[...(Array.isArray(certs)?certs:[])].filter((c)=>{
      if(certStatusView!=="all"&&String(c.status||"").toLowerCase()!==certStatusView){
        return false;
      }
      if(!q){
        return true;
      }
      return [
        c?.subject_cn,
        c?.id,
        c?.algorithm,
        c?.cert_class,
        c?.status
      ].some((value)=>String(value||"").toLowerCase().includes(q));
    });
    out.sort((a,b)=>new Date(String(b.created_at||0)).getTime()-new Date(String(a.created_at||0)).getTime());
    return out;
  },[certs,certStatusView,certSearch]);

  const certTotalPages=useMemo(()=>{
    return Math.max(1,Math.ceil(filteredCerts.length/Math.max(1,certPageSize)));
  },[filteredCerts.length,certPageSize]);

  const certCurrentPage=useMemo(()=>{
    return Math.min(Math.max(0,certPageIndex),certTotalPages-1);
  },[certPageIndex,certTotalPages]);

  const pagedCerts=useMemo(()=>{
    const start=certCurrentPage*certPageSize;
    const end=start+certPageSize;
    return filteredCerts.slice(start,end);
  },[filteredCerts,certCurrentPage,certPageSize]);

  const certStatusCounts=useMemo(()=>{
    const all=Array.isArray(certs)?certs:[];
    return {
      all: all.length,
      active: all.filter((c)=>String(c.status||"").toLowerCase()==="active").length,
      revoked: all.filter((c)=>String(c.status||"").toLowerCase()==="revoked").length,
      deleted: all.filter((c)=>String(c.status||"").toLowerCase()==="deleted").length
    };
  },[certs]);
  const caStatusCounts=useMemo(()=>{
    const all=Array.isArray(cas)?cas:[];
    return {
      all: all.length,
      active: all.filter((c)=>String(c.status||"").toLowerCase()==="active").length,
      revoked: all.filter((c)=>String(c.status||"").toLowerCase()==="revoked").length
    };
  },[cas]);

  useEffect(()=>{
    if(certPageIndex>certTotalPages-1){
      setCertPageIndex(Math.max(0,certTotalPages-1));
    }
  },[certPageIndex,certTotalPages]);

  const currentPQCProfiles=useMemo(()=>{
    return (Array.isArray(profiles)?profiles:[]).filter((p)=>{
      const cls=String(p.cert_class||"").toLowerCase();
      return cls==="pqc"||cls==="hybrid";
    });
  },[profiles]);

  const inferCAName=(subject:string, fallback:string)=>{
    const m=String(subject||"").match(/CN\s*=\s*([^,]+)/i);
    const cn=m&&m[1]?String(m[1]).trim():"";
    if(cn){
      return cn;
    }
    return fallback;
  };

  const openProtocolModal=(name:string)=>{
    const key=String(name||"acme").toLowerCase();
    const cfg=protocolByName[key];
    const fallback=protocolDefaultConfigs[key]||{};
    setProtocolName(String(name||"acme"));
    setProtocolEnabled(cfg?Boolean(cfg.enabled):true);
    let formatted="{}";
    try{
      const parsed=cfg?.config_json?JSON.parse(String(cfg.config_json)):fallback;
      formatted=JSON.stringify(parsed||{},null,2);
    }catch{
      formatted=JSON.stringify(fallback||{},null,2);
    }
    setProtocolConfigText(formatted);
    setModal("protocol-config");
  };

  const saveProtocol=async()=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    let parsed={};
    try{
      parsed=JSON.parse(String(protocolConfigText||"{}"));
    }catch{
      onToast?.("Protocol configuration must be valid JSON.");
      return;
    }
    setSubmitting(true);
    try{
      await updateProtocolConfig(session,protocolName as any,{
        enabled:protocolEnabled,
        config_json:JSON.stringify(parsed),
        updated_by:session.username||"dashboard"
      });
      onToast?.(`${String(protocolName).toUpperCase()} configuration saved.`);
      setModal(null);
      await refresh();
    }catch(e){
      onToast?.(`Failed to save protocol config: ${errMsg(e)}`);
    }finally{
      setSubmitting(false);
    }
  };

  const runProtocolTest=async(name:string)=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    const activeCA=(Array.isArray(cas)?cas:[]).find((c)=>String(c.status||"").toLowerCase()==="active")||cas[0];
    if(!activeCA?.id){
      onToast?.("Create an issuing CA first.");
      return;
    }
    const stamp=Date.now();
    setTestingProtocol(name);
    try{
      if(name==="acme"){
        const account=await acmeNewAccount(session,`pki+${stamp}@example.com`);
        const cn=`acme-${stamp}.local`;
        const order=await acmeNewOrder(session,{
          ca_id:activeCA.id,
          account_id:account.account_id,
          subject_cn:cn,
          sans:[cn]
        });
        await acmeChallengeComplete(session,order.challenge_id,order.order_id);
        await acmeFinalize(session,order.order_id,"");
      }else if(name==="est"){
        await estServerKeygen(session,{
          ca_id:activeCA.id,
          subject_cn:`est-device-${stamp}.local`,
          sans:[`est-device-${stamp}.local`]
        });
      }else if(name==="scep"){
        await scepEnroll(session,{
          ca_id:activeCA.id,
          transaction_id:`txn-${stamp}`
        });
      }else if(name==="cmpv2"){
        await cmpv2Request(session,{
          ca_id:activeCA.id,
          message_type:"ir",
          transaction_id:`cmp-${stamp}`,
          protected:true,
          protection_alg:"pbm-sha256",
          payload_json:JSON.stringify({
            subject_cn:`cmp-client-${stamp}.local`,
            sans:[`cmp-client-${stamp}.local`],
            cert_type:"tls-client"
          })
        });
      }
      onToast?.(`${String(name).toUpperCase()} enrollment test succeeded.`);
      await refresh();
    }catch(e){
      onToast?.(`${String(name).toUpperCase()} test failed: ${errMsg(e)}`);
    }finally{
      setTestingProtocol("");
    }
  };

  const submitCreateCA=async()=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    const validity=Math.max(30,Number(caValidity||"3650"));
    const subject=String(caSubject||"").trim();
    if(!subject){
      onToast?.("Subject DN is required.");
      return;
    }
    setSubmitting(true);
    try{
      const name=inferCAName(subject,caType==="root"?"Root CA":"Intermediate CA");
      await createCA(session,{
        name,
        parent_ca_id:caType==="intermediate"?caParent:"",
        ca_level:caType as any,
        algorithm:caAlgorithm,
        key_backend:caBackend==="keycore"?"keycore":"software",
        subject,
        validity_days:validity,
        ots_max:Number(caPathLength||"0")>0&&String(caAlgorithm).toUpperCase().includes("XMSS")?10000:0,
        ots_alert_threshold:Number(caPathLength||"0")>0&&String(caAlgorithm).toUpperCase().includes("XMSS")?100:0
      });
      onToast?.("Certificate Authority created.");
      setModal(null);
      await refresh();
    }catch(e){
      onToast?.(`Create CA failed: ${errMsg(e)}`);
    }finally{
      setSubmitting(false);
    }
  };

  const resolveValidityInput=(mode,presetDays,customDays,notAfterValue)=>{
    if(mode==="custom-date-time"){
      const raw=String(notAfterValue||"").trim();
      if(!raw){
        return {error:"Custom expiry date/time is required."};
      }
      const ts=new Date(raw);
      if(Number.isNaN(ts.getTime())){
        return {error:"Custom expiry date/time is invalid."};
      }
      return {validity_days:0,not_after:ts.toISOString()};
    }
    const daySource=mode==="custom-days"?customDays:presetDays;
    const days=Math.max(1,Number(daySource||"365"));
    if(!Number.isFinite(days)){
      return {error:"Validity days must be a valid number."};
    }
    return {validity_days:days,not_after:undefined};
  };

  const submitIssueCert=async(isPQC:boolean)=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    if(!issueCAID||!issueCN.trim()){
      onToast?.("Issuing CA and Common Name are required.");
      return;
    }
    const sans=String(issueSANs||"").split(",").map((v)=>v.trim()).filter(Boolean);
    const metadata={
      organization:issueOrg,
      key_usage:{
        digital_signature:issueDigitalSig,
        key_encipherment:issueKeyEnc,
        key_cert_sign:caKeyUsageSign,
        crl_sign:caKeyUsageCRL,
        digital_signature_ca:caKeyUsageDigital
      },
      extended_key_usage:{
        tls_server:issueTLSAuth,
        tls_client:issueTLSClient,
        code_signing:issueCodeSign
      },
      auto_renew_acme:issueAutoRenew,
      enable_ocsp_stapling:issueEnableOCSP
    };
    const validity=resolveValidityInput(issueValidityMode,issueValidityDays,issueValidityCustomDays,issueNotAfter);
    if(validity.error){
      onToast?.(validity.error);
      return;
    }
    setSubmitting(true);
    try{
      const selectedProfile=(Array.isArray(profiles)?profiles:[]).find((p)=>String(p.id)===String(issueProfileID));
      const selectedAlgorithm=isPQC
        ? (selectedProfile?.algorithm||issueAlgorithm||"ML-DSA-65")
        : (selectedProfile?.algorithm||issueAlgorithm||"ECDSA-P384");
      const out=await issueCertificate(session,{
        ca_id:issueCAID,
        profile_id:issueProfileID||undefined,
        cert_type:issueCertType,
        algorithm:selectedAlgorithm,
        cert_class:isPQC?"pqc":undefined,
        subject_cn:issueCN.trim(),
        sans,
        server_keygen:true,
        validity_days:validity.validity_days,
        not_after:validity.not_after,
        protocol:isPQC?"ui-pqc-issue":"ui-issue",
        metadata_json:JSON.stringify(metadata)
      });
      onToast?.(
        out.privateKeyPEM
          ?"Certificate issued. Private key generated server-side."
          :"Certificate issued."
      );
      setModal(null);
      await refresh();
    }catch(e){
      onToast?.(`Issue certificate failed: ${errMsg(e)}`);
    }finally{
      setSubmitting(false);
    }
  };

  const submitSignCSR=async()=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    if(!csrCAID){
      onToast?.("Issuing CA is required.");
      return;
    }
    if(!String(csrPEM||"").trim()){
      onToast?.("CSR PEM is required.");
      return;
    }
    const validity=resolveValidityInput(csrValidityMode,csrValidityDays,csrValidityCustomDays,csrNotAfter);
    if(validity.error){
      onToast?.(validity.error);
      return;
    }
    setSubmitting(true);
    try{
      await signCertificateCSR(session,{
        ca_id:csrCAID,
        profile_id:csrProfileID||undefined,
        cert_type:csrCertType,
        algorithm:csrAlgorithm,
        csr_pem:String(csrPEM||"").trim(),
        validity_days:validity.validity_days,
        not_after:validity.not_after,
        protocol:"ui-csr-sign"
      });
      onToast?.("CSR signed successfully.");
      setModal(null);
      await refresh();
    }catch(error){
      onToast?.(`CSR signing failed: ${errMsg(error)}`);
    }finally{
      setSubmitting(false);
    }
  };


  const submitUpload=async()=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    if(!uploadPurpose.trim()||!uploadCertPEM.trim()){
      onToast?.("Purpose and certificate PEM are required.");
      return;
    }
    setSubmitting(true);
    try{
      await uploadThirdPartyCertificate(session,{
        purpose:uploadPurpose,
        certificate_pem:uploadCertPEM,
        private_key_pem:uploadKeyPEM,
        ca_bundle_pem:uploadBundlePEM,
        set_active:uploadSetActive,
        enable_ocsp_stapling:uploadEnableOCSP,
        auto_renew_acme:uploadAutoRenew,
        updated_by:session.username||"dashboard"
      });
      onToast?.("3rd-party certificate uploaded.");
      setModal(null);
      await refresh();
    }catch(e){
      onToast?.(`Upload failed: ${errMsg(e)}`);
    }finally{
      setSubmitting(false);
    }
  };

  const downloadTextFile=(filename,content,mime="text/plain")=>{
    const blob=new Blob([String(content||"")],{type:mime});
    const url=URL.createObjectURL(blob);
    const link=document.createElement("a");
    link.href=url;
    link.download=String(filename||"download.txt");
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const downloadBase64File=(filename,b64,mime="application/octet-stream")=>{
    const clean=String(b64||"").replace(/\s+/g,"");
    const binary=window.atob(clean);
    const bytes=new Uint8Array(binary.length);
    for(let i=0;i<binary.length;i+=1){
      bytes[i]=binary.charCodeAt(i);
    }
    const blob=new Blob([bytes],{type:mime});
    const url=URL.createObjectURL(blob);
    const link=document.createElement("a");
    link.href=url;
    link.download=String(filename||"download.bin");
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const safeFileName=(input,fallback="certificate")=>{
    const out=String(input||fallback).replace(/[^a-z0-9._-]+/gi,"-").replace(/^-+|-+$/g,"");
    return out||fallback;
  };

  const openDownloadModal=(cert)=>{
    setDownloadTargetCert(cert||null);
    setDownloadAsset("certificate");
    setDownloadFormat("pem");
    setDownloadIncludeChain(true);
    setDownloadPassword("");
    setModal("cert-download");
  };

  const submitDownloadCert=async()=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    if(!downloadTargetCert?.id){
      onToast?.("Select a certificate first.");
      return;
    }
    if((downloadFormat==="pkcs12"||downloadFormat==="pfx")&&!String(downloadPassword||"").trim()){
      onToast?.("Password is required for PKCS#12 export.");
      return;
    }
    setSubmitting(true);
    try{
      const out=await downloadCertificateAsset(session,String(downloadTargetCert.id||""),{
        asset:downloadAsset as any,
        format:downloadFormat as any,
        include_chain:Boolean(downloadIncludeChain),
        password:downloadPassword
      });
      const baseName=safeFileName(String(downloadTargetCert.subject_cn||downloadTargetCert.id||"certificate"),"certificate");
      const extension=downloadFormat==="pkcs12"||downloadFormat==="pfx"
        ?"p12"
        :downloadFormat==="der"
          ?"der"
          :downloadAsset==="pkcs11"
            ?"json"
            :downloadAsset==="public-key"&&downloadFormat==="pkcs8"
              ?"pem"
              :"pem";
      const fileName=`${baseName}-${String(downloadAsset||"certificate")}.${extension}`;
      const content=String(out?.content||"");
      const isBinaryBase64=(downloadFormat==="pkcs12"||downloadFormat==="pfx")||
        (downloadFormat==="der"&&!String(content).trim().startsWith("{"));
      if(isBinaryBase64){
        downloadBase64File(fileName,content,String(out?.contentType||"application/octet-stream"));
      }else{
        downloadTextFile(fileName,content,String(out?.contentType||"text/plain"));
      }
      onToast?.(`Downloaded ${String(downloadAsset||"certificate")} (${String(downloadFormat||"pem")}).`);
      setModal(null);
    }catch(error){
      onToast?.(`Download failed: ${errMsg(error)}`);
    }finally{
      setSubmitting(false);
    }
  };

  const runCertAction=async(actionKey,fn)=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    setRowActionBusy(String(actionKey||""));
    try{
      await fn();
    }catch(e){
      onToast?.(`Certificate action failed: ${errMsg(e)}`);
    }finally{
      setRowActionBusy("");
    }
  };

  const toggleCA=(caID)=>{
    const id=String(caID||"");
    if(!id){
      return;
    }
    setCAExpanded((prev)=>{
      const src=prev||{};
      const cur=Object.prototype.hasOwnProperty.call(src,id)?Boolean(src[id]):true;
      return {...src,[id]:!cur};
    });
  };

  const toggleIssued=(caID)=>{
    const id=String(caID||"");
    if(!id){
      return;
    }
    setIssuedExpanded((prev)=>{
      const src=prev||{};
      const cur=Object.prototype.hasOwnProperty.call(src,id)?Boolean(src[id]):true;
      return {...src,[id]:!cur};
    });
  };

  const actRenewCert=async(cert)=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    const raw=await promptDialog.prompt({
      title:"Renew Certificate",
      message:"Renew certificate validity in days.",
      defaultValue:"365",
      placeholder:"365",
      confirmLabel:"Renew",
      validate:(value:string)=>{
        const n=Number(value);
        if(!Number.isFinite(n)||n<=0){
          return "Validity days must be a positive number.";
        }
        return "";
      }
    });
    if(raw===null){
      return;
    }
    const days=Math.max(1,Math.trunc(Number(raw||"365")));
    await runCertAction(`renew-${cert.id}`,async()=>{
      await renewCertificate(session,String(cert.id||""),days);
      onToast?.(`Certificate renewed: ${String(cert.subject_cn||cert.id)}`);
      await refresh();
    });
  };

  const actRevokeCert=async(cert)=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    if(String(cert.status||"").toLowerCase()==="revoked"){
      onToast?.("Certificate is already revoked.");
      return;
    }
    const reason=await promptDialog.prompt({
      title:"Revoke Certificate",
      message:"Enter revocation reason.",
      defaultValue:"key_compromise",
      placeholder:"key_compromise",
      confirmLabel:"Revoke",
      danger:true,
      validate:(value:string)=>String(value||"").trim()? "" : "Revocation reason is required."
    });
    if(reason===null){
      return;
    }
    await runCertAction(`revoke-${cert.id}`,async()=>{
      await revokeCertificate(session,String(cert.id||""),String(reason||"unspecified"));
      onToast?.(`Certificate revoked: ${String(cert.subject_cn||cert.id)}`);
      await refresh();
    });
  };

  const actDeleteCert=async(cert)=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    const label=String(cert.subject_cn||cert.id||"certificate");
    const ok=await promptDialog.confirm({
      title:"Delete Certificate",
      message:`Delete certificate '${label}'?\n\nThis permanently flushes certificate material/metadata from DB and cannot be recovered. Deleted tab keeps only a minimal reference.`,
      confirmLabel:"Delete",
      danger:true
    });
    if(!ok){
      return;
    }
    await runCertAction(`delete-${cert.id}`,async()=>{
      await deleteCertificate(session,String(cert.id||""));
      onToast?.(`Certificate moved to Deleted: ${label}`);
      await refresh();
    });
  };

  const actOCSP=async(cert)=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    await runCertAction(`ocsp-${cert.id}`,async()=>{
      const out=await getOCSP(session,{cert_id:String(cert.id||"")});
      const reason=String(out?.reason||"").trim();
      const status=String(out?.status||"unknown").toLowerCase();
      const statusLabel=status==="good"
        ?"Good (valid and not revoked)"
        :status==="revoked"
          ?"Revoked"
          :status==="expired"
            ?"Expired"
            :"Unknown";
      onToast?.(`OCSP status for ${String(cert.subject_cn||cert.id)}: ${statusLabel}${reason?` - ${reason}`:""}`);
    });
  };

  const actDownloadCert=(cert)=>{
    openDownloadModal(cert);
  };

  const actCRL=async(ca)=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    await runCertAction(`crl-${ca.id}`,async()=>{
      const out=await getCRL(session,String(ca.id||""));
      const safe=String(ca.name||ca.id||"ca").replace(/[^a-z0-9-_]+/gi,"-").replace(/^-+|-+$/g,"").toLowerCase();
      const fileName=`${safe||"ca"}-crl.pem`;
      downloadTextFile(fileName,String(out?.crl_pem||""),"application/x-pem-file");
      onToast?.(`CRL generated for ${String(ca.name||ca.id)} at ${String(out?.generated_at||"")}`);
    });
  };

  const actDeleteCA=async(ca:any)=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    const label=String(ca?.name||ca?.id||"CA");
    const ok=await promptDialog.confirm({
      title:"Delete Certificate Authority",
      message:`Delete CA '${label}'?\n\nThis permanently removes CA metadata and cannot be undone.\n\nDelete will be blocked if this CA has child CAs or issued certificates.`,
      confirmLabel:"Delete CA",
      danger:true
    });
    if(!ok){
      return;
    }
    await runCertAction(`delete-ca-${String(ca?.id||"")}`,async()=>{
      await deleteCA(session,String(ca?.id||""));
      onToast?.(`CA deleted: ${label}`);
      await refresh();
    });
  };

  const saveAlertPolicy=async()=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    const days=Math.max(1,Math.min(3650,Number(alertPolicyDaysBefore||30)));
    setAlertPolicySaving(true);
    try{
      const out=await updateCertExpiryAlertPolicy(session,{
        days_before:days,
        include_external:Boolean(alertPolicyIncludeExternal),
        updated_by:session.username||"dashboard"
      });
      setAlertPolicyDaysBefore(Math.max(1,Math.min(3650,Number(out?.days_before||days))));
      setAlertPolicyIncludeExternal(Boolean(out?.include_external));
      onToast?.("Certificate alert policy updated.");
      setModal(null);
      await refresh();
    }catch(error){
      onToast?.(`Alert policy update failed: ${errMsg(error)}`);
    }finally{
      setAlertPolicySaving(false);
    }
  };

  const placeCertMenuFromButton=(button,menuWidth,menuHeight)=>{
    const rect=button.getBoundingClientRect();
    const left=Math.max(8,Math.min(window.innerWidth-menuWidth-8,rect.right-menuWidth));
    let top=rect.bottom+6;
    if(top+menuHeight>window.innerHeight-8){
      top=Math.max(8,rect.top-menuHeight-6);
    }
    return {top,left};
  };

  const openCertActionMenu=(event,certID)=>{
    event.stopPropagation();
    if(openCertActionMenuId===certID){
      setOpenCertActionMenuId("");
      return;
    }
    const pos=placeCertMenuFromButton(event.currentTarget,210,320);
    setCertActionMenuPos(pos);
    setOpenCertActionMenuId(certID);
  };

  const renderIssuedCertRow=(crt)=>{
    const certID=String(crt.id||"");
    const statusRaw=String(crt.status||"unknown");
    const status=statusRaw.toLowerCase();
    return <div key={certID} style={{padding:"6px 8px",border:`1px solid ${C.border}`,borderRadius:8,background:"rgba(7,13,25,.65)"}}>
      <div style={{minWidth:0}}>
        <div style={{fontSize:11,color:C.text,fontWeight:600,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{String(crt.subject_cn||crt.id||"certificate")}</div>
        <div style={{fontSize:9,color:C.muted,fontFamily:"'JetBrains Mono',monospace",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{certID}</div>
        <div style={{display:"flex",gap:6,marginTop:4,alignItems:"center",flexWrap:"wrap"}}>
          <B c={status==="active"?"green":status==="revoked"||status==="deleted"?"red":"amber"}>{statusRaw||"unknown"}</B>
          <span style={{fontSize:9,color:C.dim}}>{String(crt.algorithm||"-")}</span>
          <span style={{fontSize:9,color:C.dim}}>exp: {formatDestroyAt(String(crt.not_after||"-"))}</span>
        </div>
      </div>
    </div>;
  };

  const renderCANode=(ca,depth=0)=>{
    const caID=String(ca.id||"");
    const children=childrenOf(caID).filter((child)=>{
      if(caStatusView==="all"){
        return true;
      }
      return String(child?.status||"").toLowerCase()===caStatusView;
    });
    const certList=[...((certsByCA[caID]||[]) as any[])].filter((crt)=>{
      if(certStatusView==="all"){
        return true;
      }
      return String(crt?.status||"").toLowerCase()===certStatusView;
    });
    certList.sort((a,b)=>new Date(String(b.created_at||0)).getTime()-new Date(String(a.created_at||0)).getTime());
    const open=Object.prototype.hasOwnProperty.call(caExpanded||{},caID)?Boolean(caExpanded[caID]):true;
    const issuedOpen=Object.prototype.hasOwnProperty.call(issuedExpanded||{},caID)?Boolean(issuedExpanded[caID]):true;
    const status=String(ca.status||"unknown").toLowerCase();
    const crlBusy=String(rowActionBusy||"")===`crl-${caID}`;
    const deleteCABusy=String(rowActionBusy||"")===`delete-ca-${caID}`;
    return <Card key={caID} style={{padding:8,marginLeft:depth*16,background:depth===0?"rgba(6,214,224,.08)":"rgba(148,163,184,.10)",borderColor:depth===0?C.accentDim:C.border}}>
      <div style={{display:"flex",justifyContent:"space-between",gap:8,alignItems:"flex-start"}}>
        <div style={{minWidth:0}}>
          <button onClick={()=>toggleCA(caID)} style={{background:"transparent",border:"none",padding:0,margin:0,color:C.accent,cursor:"pointer",fontSize:11,fontWeight:700}}>{open?"v":">"} {depth===0?"Root":"Intermediate"}: {String(ca.name||caID)}</button>
          <div style={{fontSize:9,color:C.muted,marginTop:3}}>{`${String(ca.algorithm||"-")} | ${String(ca.ca_level||"root")} | ${String(ca.key_backend||"software")}`}</div>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:6,flexWrap:"wrap",justifyContent:"flex-end"}}>
          <B c={status==="active"?"green":status==="revoked"?"red":"amber"}>{String(ca.status||"unknown")}</B>
          <Btn small onClick={()=>void actCRL(ca)} disabled={crlBusy}>{crlBusy?"Generating...":"CRL"}</Btn>
          <Btn small danger onClick={()=>void actDeleteCA(ca)} disabled={deleteCABusy}>{deleteCABusy?"Deleting...":"Delete"}</Btn>
        </div>
      </div>
      {open?<>
        {children.length?<div style={{display:"grid",gap:8,marginTop:8}}>{children.map((child)=>renderCANode(child,depth+1))}</div>:null}
        <div style={{marginTop:8,paddingTop:8,borderTop:`1px solid ${C.border}`}}>
          <button onClick={()=>toggleIssued(caID)} style={{background:"transparent",border:"none",padding:0,color:C.blue,cursor:"pointer",fontSize:10,fontWeight:700}}>{issuedOpen?"v":">"} Issued Certificates ({certList.length})</button>
          {issuedOpen?<div style={{display:"grid",gap:6,marginTop:6,maxHeight:200,overflowY:"auto",paddingRight:4}}>
            {certList.length?certList.map((crt)=>renderIssuedCertRow(crt)):<div style={{fontSize:10,color:C.muted}}>No issued certificates under this CA.</div>}
          </div>:null}
        </div>
      </>:null}
    </Card>;
  };

  return <div>
    {showOverviewPane&&<>
      <div style={{display:"flex",gap:12,marginBottom:14}}>
        <Stat l="Active Certs" v={String(stats.active)} c="green"/>
        <Stat l="Revoked" v={String(stats.revoked)} c="red"/>
        <Stat l="Deleted" v={String(stats.deleted)} c="blue"/>
        <Stat l="CAs" v={String(stats.cas)} s={`${roots.length} root`} c="accent"/>
        <Stat l="PQC Certs" v={String(stats.pqc)} s={`${stats.total?Math.round((stats.pqc*100)/stats.total):0}% of total`} c="purple"/>
        <Stat l={`Expiring (${alertPolicyDaysBefore}d)`} v={String(stats.expiring)} c="amber"/>
      </div>
      <div style={{fontSize:9,color:C.muted,marginBottom:10}}>
        OCSP status meanings: <span style={{color:C.green}}>good</span> = valid and not revoked, <span style={{color:C.red}}>revoked</span> = explicitly revoked, <span style={{color:C.amber}}>expired</span> = validity ended.
      </div>
    </>}

    {showEnrollmentPane&&<Section title="Enrollment Protocols">
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
        {protocolMeta.map((meta)=>{
          const cfg=protocolByName[meta.name];
          const enabled=cfg?Boolean(cfg.enabled):true;
          const canTest=meta.name!=="runtime-mtls";
          return <Card key={meta.name} style={{padding:12}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
              <div style={{fontSize:16,fontWeight:700,color:C.text}}>{meta.title}</div>
              <B c={enabled?"green":"red"}>{enabled?"Active":"Disabled"}</B>
            </div>
            <div style={{fontSize:10,color:C.accent,marginBottom:4}}>{meta.rfc}</div>
            <div style={{fontSize:11,color:C.dim,marginBottom:8}}>{meta.desc}</div>
            <div style={{display:"flex",gap:6}}>
              <Btn small onClick={()=>openProtocolModal(meta.name)}>Configure</Btn>
              <Btn
                small
                primary
                disabled={!enabled||testingProtocol===meta.name||!canTest}
                onClick={()=>void runProtocolTest(meta.name)}
              >
                {!canTest?"N/A":testingProtocol===meta.name?"Testing...":"Test Enroll"}
              </Btn>
            </div>
          </Card>;
        })}
      </div>
    </Section>}

    {showOverviewPane&&<div style={{display:"grid",gridTemplateColumns:"2fr 1fr",gap:10,marginBottom:12}}>
      <Card style={{padding:10}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
          <div style={{fontSize:12,fontWeight:700,color:C.text}}>CA Hierarchy</div>
          <div style={{display:"flex",alignItems:"center",gap:6}}>
            <Btn small onClick={()=>setCAStatusView("all")} style={{background:caStatusView==="all"?C.accentDim:"transparent",color:caStatusView==="all"?C.accent:C.text}}>{`All ${caStatusCounts.all}`}</Btn>
            <Btn small onClick={()=>setCAStatusView("active")} style={{background:caStatusView==="active"?C.greenDim:"transparent",color:caStatusView==="active"?C.green:C.text}}>{`Active ${caStatusCounts.active}`}</Btn>
            <Btn small onClick={()=>setCAStatusView("revoked")} style={{background:caStatusView==="revoked"?C.redDim:"transparent",color:caStatusView==="revoked"?C.red:C.text}}>{`Revoked ${caStatusCounts.revoked}`}</Btn>
            <Btn small onClick={()=>void refresh()} disabled={loading}><span style={{display:"inline-flex",alignItems:"center",gap:6}}><RefreshCcw size={12}/>{loading?"Refreshing...":"Refresh"}</span></Btn>
            <Btn small primary onClick={()=>setModal("create-ca")}>+ Create CA</Btn>
          </div>
        </div>
        {!roots.length&&!loading?<div style={{fontSize:10,color:C.muted}}>No CA found. Create a root CA to start issuance.</div>:null}
        <div style={{display:"grid",gap:8,maxHeight:360,overflowY:"auto",paddingRight:4}}>
          {roots.filter((root)=>{
            if(caStatusView==="all"){
              return true;
            }
            return String(root?.status||"").toLowerCase()===caStatusView;
          }).map((root)=>renderCANode(root,0))}
        </div>
      </Card>

      <div style={{display:"grid",gap:10}}>
        <Card style={{padding:10}}>
          <div style={{fontSize:12,fontWeight:700,color:C.text,marginBottom:4}}>Expiry Calendar</div>
          <div style={{fontSize:9,color:C.muted,marginBottom:8}}>{`Alert window: ${alertPolicyDaysBefore} day(s)${alertPolicyIncludeExternal?" including":" excluding"} external certs`}</div>
          <div style={{display:"grid",gap:8}}>
            {expiryItems.map((it)=>{
              const c=it.daysLeft<=15?"red":it.daysLeft<=60?"amber":"green";
              const pct=Math.max(4,Math.min(100,it.daysLeft<=0?100:(365-Math.min(365,it.daysLeft))/3.65));
              return <div key={it.certId} style={{borderBottom:`1px solid ${C.border}`,paddingBottom:6}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                  <div style={{fontSize:11,color:C.text,maxWidth:190,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{it.subject}</div>
                  <B c={c}>{it.daysLeft<0?"expired":`${it.daysLeft}d`}</B>
                </div>
                <Bar pct={pct} color={c==="red"?C.red:c==="amber"?C.amber:C.green}/>
              </div>;
            })}
            {!expiryItems.length?<div style={{fontSize:10,color:C.muted}}>No certificates available.</div>:null}
          </div>
        </Card>
      </div>
    </div>}

    {showOverviewPane&&<div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:12}}>
      <Btn small primary onClick={()=>setModal("issue")} style={{height:34,padding:"0 14px"}}>+ Issue</Btn>
      <Btn small onClick={()=>setModal("sign-csr")} style={{height:34,padding:"0 14px"}}>Sign CSR</Btn>
      <Btn small onClick={()=>setModal("issue-pqc")} style={{height:34,padding:"0 14px"}}>PQC</Btn>
      <Btn small onClick={()=>setModal("upload-3p")} style={{height:34,padding:"0 14px"}}>Upload 3rd-Party</Btn>
      <Btn small onClick={()=>setModal("cert-alert-policy")} style={{height:34,padding:"0 14px"}}>Alert Policy</Btn>
    </div>}

    {showOverviewPane&&<Section title="Certificates">
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8,marginBottom:8,flexWrap:"wrap"}}>
        <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
          <Inp
            placeholder="Search certificate by name, ID, algorithm..."
            w={320}
            value={certSearch}
            onChange={(e)=>setCertSearch(e.target.value)}
            style={{height:34,borderRadius:9,fontSize:11}}
          />
        <Btn small onClick={()=>setCertStatusView("all")} style={{background:certStatusView==="all"?C.accentDim:"transparent",color:certStatusView==="all"?C.accent:C.text}}>
          {`All (${certStatusCounts.all})`}
        </Btn>
        <Btn small onClick={()=>setCertStatusView("active")} style={{background:certStatusView==="active"?C.greenDim:"transparent",color:certStatusView==="active"?C.green:C.text}}>
          {`Active (${certStatusCounts.active})`}
        </Btn>
        <Btn small onClick={()=>setCertStatusView("revoked")} style={{background:certStatusView==="revoked"?C.redDim:"transparent",color:certStatusView==="revoked"?C.red:C.text}}>
          {`Revoked (${certStatusCounts.revoked})`}
        </Btn>
        <Btn small onClick={()=>setCertStatusView("deleted")} style={{background:certStatusView==="deleted"?C.blueDim:"transparent",color:certStatusView==="deleted"?C.blue:C.text}}>
          {`Deleted (${certStatusCounts.deleted})`}
        </Btn>
        </div>
        <Btn small onClick={()=>void refresh()} disabled={loading}><span style={{display:"inline-flex",alignItems:"center",gap:6}}><RefreshCcw size={12}/>{loading?"Refreshing...":"Refresh"}</span></Btn>
      </div>
      <Card style={{padding:0,overflow:"hidden"}}>
        <div style={{display:"grid",gridTemplateColumns:"1.3fr 1fr .8fr .8fr .9fr .55fr",gap:0,padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>
          <div>Common Name</div><div>Algorithm</div><div>Class</div><div>Status</div><div>Expires</div><div style={{textAlign:"right"}}>Actions</div>
        </div>
        <div style={{maxHeight:220,overflowY:"auto"}}>
          {pagedCerts.map((c)=>(
            <div key={c.id} style={{display:"grid",gridTemplateColumns:"1.3fr 1fr .8fr .8fr .9fr .55fr",padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:11,alignItems:"center"}}>
              <div>
                <div style={{color:C.text,fontWeight:600}}>{c.subject_cn||c.id}</div>
                <div style={{fontSize:9,color:C.muted,fontFamily:"'JetBrains Mono',monospace"}}>{c.id}</div>
              </div>
              <div style={{color:C.accent}}>{c.algorithm}</div>
              <div style={{color:C.dim,textTransform:"uppercase"}}>{c.cert_class}</div>
              <div><B c={String(c.status).toLowerCase()==="active"?"green":String(c.status).toLowerCase()==="revoked"||String(c.status).toLowerCase()==="deleted"?"red":"amber"}>{c.status}</B></div>
              <div style={{color:C.dim}}>{formatDestroyAt(String(c.not_after||"-"))}</div>
              <div style={{display:"flex",justifyContent:"flex-end",position:"relative"}} onClick={(e)=>e.stopPropagation()}>
                {(() => {
                  const certID=String(c.id||"");
                  const statusRaw=String(c.status||"unknown");
                  const status=statusRaw.toLowerCase();
                  const certClass=String(c.cert_class||"").toLowerCase();
                  const certProtocol=String(c.protocol||"").toLowerCase();
                  const busy=String(rowActionBusy||"");
                  const showMenu=openCertActionMenuId===certID;
                  const canRenew=status==="active"||status==="expired";
                  const canRevoke=status==="active"||status==="expired";
                  const isInternalMTLS=certClass==="internal-mtls"||certProtocol.includes("internal-mtls");
                  const canDelete=status!=="deleted"&&!isInternalMTLS;
                  return <>
                <button
                  onClick={(e)=>openCertActionMenu(e,certID)}
                  aria-label="Certificate actions"
                  style={{
                    background:"transparent",
                    border:`1px solid ${C.border}`,
                    borderRadius:7,
                    color:C.accent,
                    width:28,
                    height:24,
                    display:"inline-flex",
                    alignItems:"center",
                    justifyContent:"center",
                    cursor:"pointer"
                  }}
                >
                  <MoreVertical size={14} strokeWidth={2}/>
                </button>
                {showMenu&&<div style={{
                  position:"fixed",
                  top:certActionMenuPos.top,
                  left:certActionMenuPos.left,
                  zIndex:3000,
                  minWidth:190,
                  background:C.surface,
                  border:`1px solid ${C.borderHi}`,
                  borderRadius:8,
                  boxShadow:"0 12px 24px rgba(0,0,0,.35)",
                  padding:4,
                  display:"grid",
                  gap:2
                }}>
                  <button
                    onClick={(e)=>{
                      e.stopPropagation();
                      setOpenCertActionMenuId("");
                      actDownloadCert(c);
                    }}
                    style={{background:"transparent",border:"none",color:C.text,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:"pointer",borderRadius:6}}
                  >
                    Download
                  </button>
                  {canRenew?<button
                    onClick={(e)=>{
                      e.stopPropagation();
                      setOpenCertActionMenuId("");
                      void actRenewCert(c);
                    }}
                    disabled={busy===`renew-${certID}`}
                    style={{background:"transparent",border:"none",color:C.text,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:busy===`renew-${certID}`?"not-allowed":"pointer",borderRadius:6}}
                  >
                    {busy===`renew-${certID}`?"Renewing...":"Renew"}
                  </button>:null}
                  {canRevoke?<button
                    onClick={(e)=>{
                      e.stopPropagation();
                      setOpenCertActionMenuId("");
                      void actRevokeCert(c);
                    }}
                    disabled={busy===`revoke-${certID}`}
                    style={{background:"transparent",border:"none",color:C.text,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:busy===`revoke-${certID}`?"not-allowed":"pointer",borderRadius:6}}
                  >
                    {busy===`revoke-${certID}`?"Revoking...":"Revoke"}
                  </button>:null}
                  <button
                    onClick={(e)=>{
                      e.stopPropagation();
                      setOpenCertActionMenuId("");
                      void actOCSP(c);
                    }}
                    disabled={busy===`ocsp-${certID}`}
                    style={{background:"transparent",border:"none",color:C.text,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:busy===`ocsp-${certID}`?"not-allowed":"pointer",borderRadius:6}}
                  >
                    {busy===`ocsp-${certID}`?"Checking...":"OCSP"}
                  </button>
                  {canDelete?<button
                    onClick={(e)=>{
                      e.stopPropagation();
                      setOpenCertActionMenuId("");
                      void actDeleteCert(c);
                    }}
                    disabled={busy===`delete-${certID}`}
                    style={{background:"transparent",border:"none",color:C.red,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:busy===`delete-${certID}`?"not-allowed":"pointer",borderRadius:6}}
                  >
                    {busy===`delete-${certID}`?"Deleting...":"Delete"}
                  </button>:<div style={{padding:"6px 8px",fontSize:10,color:C.muted}}>
                    {status==="deleted"?"Already deleted":"Managed runtime mTLS cert (renew/rotate only)"}
                  </div>}
                </div>}
                </>;
                })()}
              </div>
            </div>
          ))}
          {!pagedCerts.length&&!loading?<div style={{padding:12,fontSize:10,color:C.muted}}>No certificates for current filter.</div>:null}
        </div>
      </Card>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:10,marginTop:8,flexWrap:"wrap"}}>
        <div style={{display:"flex",alignItems:"center",gap:8,fontSize:10,color:C.dim}}>
          <span>Rows per page</span>
          <Sel w={92} value={String(certPageSize)} onChange={(e)=>setCertPageSize(Number(e.target.value||10))}>
            <option value="10">10</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </Sel>
          <span>{filteredCerts.length?`${certCurrentPage*certPageSize+1}-${Math.min((certCurrentPage+1)*certPageSize,filteredCerts.length)} of ${filteredCerts.length}`:`0 of 0`}</span>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:8}}>
          <Btn small onClick={()=>setCertPageIndex((prev)=>Math.max(0,prev-1))} disabled={certCurrentPage<=0}>Prev</Btn>
          <div style={{fontSize:10,color:C.text,minWidth:74,textAlign:"center"}}>{`Page ${certCurrentPage+1} / ${certTotalPages}`}</div>
          <Btn small onClick={()=>setCertPageIndex((prev)=>Math.min(certTotalPages-1,prev+1))} disabled={certCurrentPage>=certTotalPages-1}>Next</Btn>
        </div>
      </div>
    </Section>}

    <Modal open={modal==="create-ca"} onClose={()=>setModal(null)} title="Create Certificate Authority" wide>
      <Row2>
        <FG label="CA Type" required>
          <Sel value={caType} onChange={(e)=>setCAType(e.target.value)}>
            <option value="root">Root CA (self-signed)</option>
            <option value="intermediate">Intermediate CA (signed by parent)</option>
          </Sel>
        </FG>
        <FG label="Parent CA" hint="Required for intermediate CAs">
          <Sel value={caParent} onChange={(e)=>setCAParent(e.target.value)} disabled={caType!=="intermediate"}>
            <option value="">- None (Root CA) -</option>
            {cas.map((c)=><option key={c.id} value={c.id}>{c.name} ({c.algorithm})</option>)}
          </Sel>
        </FG>
      </Row2>
      <FG label="CA Signing Algorithm" required>
        <Sel value={caAlgorithm} onChange={(e)=>setCAAlgorithm(e.target.value)}>
          <optgroup label="Classical">
            <option value="RSA-4096-SHA384">RSA-4096-SHA384</option>
            <option value="RSA-3072-SHA256">RSA-3072-SHA256</option>
            <option value="ECDSA-P384-SHA384">ECDSA-P384-SHA384</option>
            <option value="ECDSA-P256-SHA256">ECDSA-P256-SHA256</option>
          </optgroup>
          <optgroup label="Post-Quantum">
            <option value="ML-DSA-87">ML-DSA-87</option>
            <option value="ML-DSA-65">ML-DSA-65</option>
            <option value="SLH-DSA-256f">SLH-DSA-256f</option>
            <option value="SLH-DSA-128f">SLH-DSA-128f</option>
            <option value="HSS-LMS-SHA256">HSS/LMS-SHA256</option>
            <option value="XMSS-SHA256">XMSS-SHA256</option>
          </optgroup>
          <optgroup label="Hybrid">
            <option value="ECDSA-P384+ML-DSA-65">ECDSA-P384 + ML-DSA-65</option>
            <option value="RSA-3072+ML-DSA-65">RSA-3072 + ML-DSA-65</option>
          </optgroup>
        </Sel>
      </FG>
      <Row2>
        <FG label="Subject DN" required><Inp value={caSubject} onChange={(e)=>setCASubject(e.target.value)} placeholder="CN=Vecta Root CA, O=Bank Corp, C=CH"/></FG>
        <FG label="Validity"><Sel value={caValidity} onChange={(e)=>setCAValidity(e.target.value)}><option value="3650">10 years (Root CA)</option><option value="1825">5 years (Intermediate)</option><option value="1095">3 years</option><option value="365">1 year</option></Sel></FG>
      </Row2>
      <FG label="Key Storage">
        <Radio label="HSM-backed (external HSM - FIPS boundary)" selected={caBackend==="keycore"} onSelect={()=>setCABackend("keycore")}/>
        <Radio label="Software vault (envelope-encrypted)" selected={caBackend==="software"} onSelect={()=>setCABackend("software")}/>
      </FG>
      <FG label="Path Length Constraint" hint="Max depth of CA chain below this CA"><Inp value={caPathLength} onChange={(e)=>setCAPathLength(e.target.value)} placeholder="1" type="number"/></FG>
      <FG label="Key Usage">
        <Chk label="Key Cert Sign" checked={caKeyUsageSign} onChange={()=>setCAKeyUsageSign((v)=>!v)}/>
        <Chk label="CRL Sign" checked={caKeyUsageCRL} onChange={()=>setCAKeyUsageCRL((v)=>!v)}/>
        <Chk label="Digital Signature" checked={caKeyUsageDigital} onChange={()=>setCAKeyUsageDigital((v)=>!v)}/>
      </FG>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)} disabled={submitting}>Cancel</Btn>
        <Btn primary onClick={()=>void submitCreateCA()} disabled={submitting||loading}>{submitting?"Creating...":"Create CA"}</Btn>
      </div>
    </Modal>

    <Modal open={modal==="issue"||modal==="issue-pqc"} onClose={()=>setModal(null)} title={modal==="issue-pqc"?"Issue PQC Certificate":"Issue Certificate"} wide>
      <Row2>
        <FG label="Issuing CA" required>
          <Sel value={issueCAID} onChange={(e)=>setIssueCAID(e.target.value)}>
            <option value="">Select CA</option>
            {cas.map((c)=><option key={c.id} value={c.id}>{c.name} ({c.algorithm})</option>)}
          </Sel>
        </FG>
        <FG label="Profile">
          <Sel value={issueProfileID} onChange={(e)=>setIssueProfileID(e.target.value)}>
            <option value="">Default profile</option>
            {(modal==="issue-pqc"?currentPQCProfiles:profiles).map((p)=><option key={p.id} value={p.id}>{p.name} ({p.algorithm})</option>)}
          </Sel>
        </FG>
      </Row2>
      <Row2>
        <FG label={modal==="issue-pqc"?"PQC Algorithm":"Signing Algorithm"} required>
          <Sel value={issueAlgorithm} onChange={(e)=>setIssueAlgorithm(e.target.value)}>
            {modal==="issue-pqc"?<>
              <option value="ML-DSA-65">ML-DSA-65</option>
              <option value="ML-DSA-87">ML-DSA-87</option>
              <option value="SLH-DSA-256f">SLH-DSA-256f</option>
              <option value="ECDSA-P384+ML-DSA-65">ECDSA-P384 + ML-DSA-65</option>
            </>:<>
              <option value="ECDSA-P384">ECDSA-P384</option>
              <option value="ECDSA-P256">ECDSA-P256</option>
              <option value="RSA-3072">RSA-3072</option>
              <option value="RSA-4096">RSA-4096</option>
            </>}
          </Sel>
        </FG>
        <FG label="Profile Type">
          <Sel value={issueCertType} onChange={(e)=>setIssueCertType(e.target.value)}>
            <option value="tls-server">TLS Server</option>
            <option value="tls-client">TLS Client (mTLS)</option>
            <option value="code-signing">Code Signing</option>
            <option value="email">Email / S-MIME</option>
            <option value="device">Device Identity</option>
          </Sel>
        </FG>
      </Row2>
      <Row2>
        <FG label="Common Name (CN)" required><Inp value={issueCN} onChange={(e)=>setIssueCN(e.target.value)} placeholder="api.bank.com"/></FG>
        <FG label="SANs"><Inp value={issueSANs} onChange={(e)=>setIssueSANs(e.target.value)} placeholder="api.bank.com, *.api.bank.com, 10.0.1.100" mono/></FG>
      </Row2>
      <Row2>
        <FG label="Organization"><Inp value={issueOrg} onChange={(e)=>setIssueOrg(e.target.value)} placeholder="Bank Corp"/></FG>
        <FG label="Validity">
          <div style={{display:"grid",gap:6}}>
            <Sel value={issueValidityMode} onChange={(e)=>setIssueValidityMode(e.target.value)}>
              <option value="preset">Preset days</option>
              <option value="custom-days">Custom days</option>
              <option value="custom-date-time">Custom expiry date & time</option>
            </Sel>
            {issueValidityMode==="preset"?<Sel value={issueValidityDays} onChange={(e)=>setIssueValidityDays(e.target.value)}>
              <option value="365">365 days</option>
              <option value="180">180 days</option>
              <option value="90">90 days</option>
              <option value="30">30 days</option>
              <option value="730">730 days</option>
            </Sel>:null}
            {issueValidityMode==="custom-days"?<Inp type="number" min={1} value={issueValidityCustomDays} onChange={(e)=>setIssueValidityCustomDays(e.target.value)} placeholder="Enter validity days"/>:null}
            {issueValidityMode==="custom-date-time"?<Inp type="datetime-local" value={issueNotAfter} onChange={(e)=>setIssueNotAfter(e.target.value)}/>:null}
          </div>
        </FG>
      </Row2>
      <FG label="Key Usage">
        <Chk label="Digital Signature" checked={issueDigitalSig} onChange={()=>setIssueDigitalSig((v)=>!v)}/>
        <Chk label="Key Encipherment" checked={issueKeyEnc} onChange={()=>setIssueKeyEnc((v)=>!v)}/>
      </FG>
      <FG label="Extended Key Usage">
        <Chk label="TLS Server Auth" checked={issueTLSAuth} onChange={()=>setIssueTLSAuth((v)=>!v)}/>
        <Chk label="TLS Client Auth" checked={issueTLSClient} onChange={()=>setIssueTLSClient((v)=>!v)}/>
        <Chk label="Code Signing" checked={issueCodeSign} onChange={()=>setIssueCodeSign((v)=>!v)}/>
      </FG>
      <Chk label="Auto-renew via ACME (RFC 8555)" checked={issueAutoRenew} onChange={()=>setIssueAutoRenew((v)=>!v)}/>
      <Chk label="Enable OCSP stapling" checked={issueEnableOCSP} onChange={()=>setIssueEnableOCSP((v)=>!v)}/>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)} disabled={submitting}>Cancel</Btn>
        <Btn primary onClick={()=>void submitIssueCert(modal==="issue-pqc")} disabled={submitting||loading}>{submitting?"Issuing...":"Issue Certificate"}</Btn>
      </div>
    </Modal>

    <Modal open={modal==="sign-csr"} onClose={()=>setModal(null)} title="Sign External CSR" wide>
      <Row2>
        <FG label="Issuing CA" required>
          <Sel value={csrCAID} onChange={(e)=>setCSRCAID(e.target.value)}>
            <option value="">Select CA</option>
            {cas.map((c)=><option key={c.id} value={c.id}>{c.name} ({c.algorithm})</option>)}
          </Sel>
        </FG>
        <FG label="Profile">
          <Sel value={csrProfileID} onChange={(e)=>setCSRProfileID(e.target.value)}>
            <option value="">Default profile</option>
            {profiles.map((p)=><option key={p.id} value={p.id}>{p.name} ({p.algorithm})</option>)}
          </Sel>
        </FG>
      </Row2>
      <Row2>
        <FG label="Certificate Type">
          <Sel value={csrCertType} onChange={(e)=>setCSRCertType(e.target.value)}>
            <option value="tls-server">TLS Server</option>
            <option value="tls-client">TLS Client (mTLS)</option>
            <option value="code-signing">Code Signing</option>
            <option value="email">Email / S-MIME</option>
            <option value="device">Device Identity</option>
          </Sel>
        </FG>
        <FG label="Signing Algorithm">
          <Sel value={csrAlgorithm} onChange={(e)=>setCSRAlgorithm(e.target.value)}>
            <option value="ECDSA-P384">ECDSA-P384</option>
            <option value="ECDSA-P256">ECDSA-P256</option>
            <option value="RSA-3072">RSA-3072</option>
            <option value="RSA-4096">RSA-4096</option>
            <option value="ML-DSA-65">ML-DSA-65</option>
            <option value="ML-DSA-87">ML-DSA-87</option>
          </Sel>
        </FG>
      </Row2>
      <FG label="CSR (PEM)" required>
        <Txt value={csrPEM} onChange={(e)=>setCSRPEM(e.target.value)} placeholder="-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----" rows={8}/>
      </FG>
      <FG label="Validity">
        <div style={{display:"grid",gap:6}}>
          <Sel value={csrValidityMode} onChange={(e)=>setCSRValidityMode(e.target.value)}>
            <option value="preset">Preset days</option>
            <option value="custom-days">Custom days</option>
            <option value="custom-date-time">Custom expiry date & time</option>
          </Sel>
          {csrValidityMode==="preset"?<Sel value={csrValidityDays} onChange={(e)=>setCSRValidityDays(e.target.value)}>
            <option value="365">365 days</option>
            <option value="180">180 days</option>
            <option value="90">90 days</option>
            <option value="30">30 days</option>
            <option value="730">730 days</option>
          </Sel>:null}
          {csrValidityMode==="custom-days"?<Inp type="number" min={1} value={csrValidityCustomDays} onChange={(e)=>setCSRValidityCustomDays(e.target.value)} placeholder="Enter validity days"/>:null}
          {csrValidityMode==="custom-date-time"?<Inp type="datetime-local" value={csrNotAfter} onChange={(e)=>setCSRNotAfter(e.target.value)}/>:null}
        </div>
      </FG>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)} disabled={submitting}>Cancel</Btn>
        <Btn primary onClick={()=>void submitSignCSR()} disabled={submitting||loading}>{submitting?"Signing...":"Sign CSR"}</Btn>
      </div>
    </Modal>

    <Modal open={modal==="cert-download"} onClose={()=>setModal(null)} title={`Download Certificate Asset${downloadTargetCert?`: ${String(downloadTargetCert.subject_cn||downloadTargetCert.id)}`:""}`}>
      <FG label="Asset">
        <Sel value={downloadAsset} onChange={(e)=>setDownloadAsset(e.target.value)}>
          <option value="certificate">Certificate</option>
          <option value="chain">Certificate + chain</option>
          <option value="ca">CA cert / chain</option>
          <option value="public-key">Public key</option>
          <option value="pkcs11">PKCS#11 reference</option>
        </Sel>
      </FG>
      <FG label="Format">
        <Sel value={downloadFormat} onChange={(e)=>setDownloadFormat(e.target.value)}>
          {(downloadAsset==="public-key")?<><option value="pem">PEM</option><option value="der">DER (base64)</option><option value="pkcs8">PKCS#8 (PEM)</option></>:null}
          {(downloadAsset!=="public-key"&&downloadAsset!=="pkcs11")?<><option value="pem">PEM</option><option value="der">DER (base64)</option><option value="pkcs12">PKCS#12 (.p12, password protected)</option></>:null}
          {downloadAsset==="pkcs11"?<option value="pem">JSON (PKCS#11 URI)</option>:null}
        </Sel>
      </FG>
      {(downloadAsset==="certificate"||downloadAsset==="ca")?<Chk label="Include full issuer chain" checked={downloadIncludeChain} onChange={()=>setDownloadIncludeChain((v)=>!v)}/>:null}
      {(downloadFormat==="pkcs12"||downloadFormat==="pfx")?<FG label="Export Password" required>
        <Inp type="password" value={downloadPassword} onChange={(e)=>setDownloadPassword(e.target.value)} placeholder="Required for PKCS#12"/>
      </FG>:null}
      <div style={{fontSize:10,color:C.muted,marginTop:8}}>
        Supports PEM/DER/PKCS#12 plus PKCS#8 public key and PKCS#11 reference downloads.
      </div>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)} disabled={submitting}>Cancel</Btn>
        <Btn primary onClick={()=>void submitDownloadCert()} disabled={submitting}>{submitting?"Preparing...":"Download"}</Btn>
      </div>
    </Modal>

    <Modal open={modal==="upload-3p"} onClose={()=>setModal(null)} title="Upload 3rd-Party Web Certificate" wide>
      <div style={{background:C.blueDim,border:`1px solid ${C.blue}`,borderRadius:8,padding:10,marginBottom:12,fontSize:10,color:C.blue}}>
        Upload certificates from external CAs (DigiCert, Let's Encrypt, etc.) for KMS interface or service endpoints.
      </div>
      <FG label="Purpose" required>
        <Sel value={uploadPurpose} onChange={(e)=>setUploadPurpose(e.target.value)}>
          <option>KMS Web Interface (HTTPS:443)</option>
          <option>API Gateway TLS termination</option>
          <option>KMIP Server (TLS)</option>
          <option>Syslog TLS</option>
          <option>Custom service endpoint</option>
        </Sel>
      </FG>
      <FG label="Certificate (PEM)" required><Txt value={uploadCertPEM} onChange={(e)=>setUploadCertPEM(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----" rows={6}/></FG>
      <FG label="Private Key (PEM)"><Txt value={uploadKeyPEM} onChange={(e)=>setUploadKeyPEM(e.target.value)} placeholder="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----" rows={4}/></FG>
      <FG label="CA Bundle (PEM)"><Txt value={uploadBundlePEM} onChange={(e)=>setUploadBundlePEM(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----" rows={3}/></FG>
      <Chk label="Set as active web interface certificate" checked={uploadSetActive} onChange={()=>setUploadSetActive((v)=>!v)}/>
      <Chk label="Enable OCSP stapling" checked={uploadEnableOCSP} onChange={()=>setUploadEnableOCSP((v)=>!v)}/>
      <Chk label="Auto-renew via ACME when expiring" checked={uploadAutoRenew} onChange={()=>setUploadAutoRenew((v)=>!v)}/>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)} disabled={submitting}>Cancel</Btn>
        <Btn primary onClick={()=>void submitUpload()} disabled={submitting||loading}>{submitting?"Uploading...":"Upload & Apply"}</Btn>
      </div>
    </Modal>

    <Modal open={modal==="cert-alert-policy"} onClose={()=>setModal(null)} title="Certificate Expiry Alert Policy">
      <FG label="Create Alert Before Expiry (days)" required>
        <Inp
          type="number"
          min={1}
          max={3650}
          value={String(alertPolicyDaysBefore)}
          onChange={(e)=>setAlertPolicyDaysBefore(Math.max(1,Math.min(3650,Number(e.target.value||30))))}
        />
      </FG>
      <Chk label="Include external / 3rd-party certificates in monitoring" checked={alertPolicyIncludeExternal} onChange={()=>setAlertPolicyIncludeExternal((v)=>!v)}/>
      <div style={{fontSize:10,color:C.muted,marginTop:8}}>
        Alerts are emitted from backend policy sweep and appear in Alert Center + bell count until acknowledged.
      </div>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)} disabled={alertPolicySaving}>Cancel</Btn>
        <Btn primary onClick={()=>void saveAlertPolicy()} disabled={alertPolicySaving}>{alertPolicySaving?"Saving...":"Save Policy"}</Btn>
      </div>
    </Modal>

    <Modal open={modal==="protocol-config"} onClose={()=>setModal(null)} title={`Configure ${String(protocolName||"").toUpperCase()} Protocol`} wide>
      <FG label="Protocol Enabled">
        <Radio label="Enabled" selected={protocolEnabled} onSelect={()=>setProtocolEnabled(true)}/>
        <Radio label="Disabled" selected={!protocolEnabled} onSelect={()=>setProtocolEnabled(false)}/>
      </FG>
      <FG label="Supported Options" hint="Use these keys in configuration JSON.">
        <div style={{display:"grid",gap:4}}>
          {activeProtocolDocs.map((line,idx)=><div key={`${String(protocolName||"cfg")}-${idx}`} style={{fontSize:10,color:C.dim,fontFamily:"'JetBrains Mono',monospace"}}>- {sanitizeDisplayText(line)}</div>)}
        </div>
      </FG>
      {activeProtocolImplementation?<FG label="Implementation" hint="Open-source runtime details for this protocol engine.">
        <div style={{display:"grid",gap:4}}>
          <div style={{fontSize:10,color:C.dim,fontFamily:"'JetBrains Mono',monospace"}}>engine={sanitizeDisplayText(activeProtocolImplementation.engine||"native-go")} language={sanitizeDisplayText(activeProtocolImplementation.language||"go")} oss_only={String(Boolean(activeProtocolImplementation.oss_only))}</div>
          {Array.isArray(activeProtocolImplementation.sdks)&&activeProtocolImplementation.sdks.length?<div style={{fontSize:10,color:C.dim,fontFamily:"'JetBrains Mono',monospace"}}>sdk: {sanitizeDisplayText(activeProtocolImplementation.sdks.join(" | "))}</div>:null}
          {Array.isArray(activeProtocolImplementation.hardening)&&activeProtocolImplementation.hardening.length?<div style={{fontSize:10,color:C.dim,fontFamily:"'JetBrains Mono',monospace"}}>hardening: {sanitizeDisplayText(activeProtocolImplementation.hardening.join(" | "))}</div>:null}
          {String(activeProtocolImplementation.notes||"").trim()?<div style={{fontSize:10,color:C.dim}}>{sanitizeDisplayText(activeProtocolImplementation.notes||"")}</div>:null}
        </div>
      </FG>:null}
      <FG label="Configuration JSON" required hint="Stored as protocol policy. Unknown keys are rejected.">
        <Txt rows={10} value={protocolConfigText} onChange={(e)=>setProtocolConfigText(e.target.value)} />
      </FG>
      <div style={{display:"flex",justifyContent:"space-between",gap:8,marginTop:12}}>
        <Btn onClick={()=>setProtocolConfigText(JSON.stringify(protocolDefaultConfigs[String(protocolName||"").toLowerCase()]||{},null,2))} disabled={submitting||loading}>Reset Recommended</Btn>
        <div style={{display:"flex",gap:8}}>
          <Btn onClick={()=>setModal(null)} disabled={submitting}>Cancel</Btn>
          <Btn primary onClick={()=>void saveProtocol()} disabled={submitting||loading}>{submitting?"Saving...":"Save Configuration"}</Btn>
        </div>
      </div>
    </Modal>
  </div>;
};

