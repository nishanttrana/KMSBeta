// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { useEffect, useMemo, useState } from "react";
import { MoreVertical, RefreshCcw, Shield, ShieldCheck, ShieldX, ShieldAlert, KeyRound, FileText, Clock, AlertTriangle, Lock, Unlock, Download, Trash2, RotateCcw, Eye, Settings, Zap, Server, Globe, Fingerprint, CheckCircle2, XCircle, ChevronDown, ChevronRight } from "lucide-react";
import {
  acmeChallengeComplete,
  acmeChallengeInfo,
  acmeFinalize,
  acmeNewAccount,
  acmeNewOrder,
  cmpv2Confirm,
  cmpv2Request,
  createCA,
  deleteCA,
  deleteCertificate,
  downloadCertificateAsset,
  estCSRAttributes,
  estServerKeygen,
  estSimpleEnroll,
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
  scepGetCert,
  signCertificateCSR,
  updateProtocolConfig,
  uploadThirdPartyCertificate,
  getCertExpiryAlertPolicy,
  updateCertExpiryAlertPolicy,
  getCertRenewalSummary,
  getCertSTARSummary,
  createCertSTARSubscription,
  refreshCertSTARSubscription,
  deleteCertSTARSubscription,
  refreshCertRenewalSummary,
  listCertMerkleEpochs,
  buildCertMerkleEpoch,
  getCertMerkleProof,
  verifyCertMerkleProof
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
  const [renewalSummary,setRenewalSummary]=useState(null);
  const [renewalRefreshing,setRenewalRefreshing]=useState(false);
  const [starSummary,setStarSummary]=useState(null);
  const [starRefreshing,setStarRefreshing]=useState(false);
  const [ctEpochs,setCTEpochs]=useState([]);
  const [ctBuilding,setCTBuilding]=useState(false);
  const [ctProofCertId,setCTProofCertId]=useState("");
  const [ctProofResult,setCTProofResult]=useState(null);
  const [starName,setStarName]=useState("");
  const [starAccountID,setStarAccountID]=useState("");
  const [starCAID,setStarCAID]=useState("");
  const [starProfileID,setStarProfileID]=useState("");
  const [starSubjectCN,setStarSubjectCN]=useState("");
  const [starSANs,setStarSANs]=useState("");
  const [starCertType,setStarCertType]=useState("tls-server");
  const [starAlgorithm,setStarAlgorithm]=useState("ECDSA-P384");
  const [starValidityHours,setStarValidityHours]=useState("24");
  const [starRenewBeforeMinutes,setStarRenewBeforeMinutes]=useState("120");
  const [starAutoRenew,setStarAutoRenew]=useState(true);
  const [starAllowDelegation,setStarAllowDelegation]=useState(false);
  const [starDelegatedSubscriber,setStarDelegatedSubscriber]=useState("");
  const [starRolloutGroup,setStarRolloutGroup]=useState("");
  const [starMetadataText,setStarMetadataText]=useState("{\n  \"workload\": \"edge-gateway\"\n}");
  const promptDialog=usePromptDialog();
  const requestedCertPane=String(subView||"cert-overview").trim().toLowerCase();
  const activeCertPane=requestedCertPane==="cert-enrollment"?"cert-enrollment":"cert-overview";
  const showEnrollmentPane=activeCertPane==="cert-enrollment";
  const showOverviewPane=!showEnrollmentPane;

  const [caLoading,setCALoading]=useState(false);
  const [certLoading,setCertLoading]=useState(false);

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

  const refreshCAs=async()=>{
    if(!session) return;
    setCALoading(true);
    try{
      const caItems=await listCAs(session);
      setCAs(Array.isArray(caItems)?caItems:[]);
      if(!issueCAID&&Array.isArray(caItems)&&caItems.length){
        setIssueCAID(caItems[0].id);
      }
      if(!csrCAID&&Array.isArray(caItems)&&caItems.length){
        setCSRCAID(caItems[0].id);
      }
      if(!starCAID&&Array.isArray(caItems)&&caItems.length){
        setStarCAID(caItems[0].id);
      }
    }catch(e){
      onToast?.(`CA refresh failed: ${errMsg(e)}`);
    }finally{
      setCALoading(false);
    }
  };

  const refreshCerts=async()=>{
    if(!session) return;
    setCertLoading(true);
    try{
      const [certItems,inventoryItems,alertPolicy]=await Promise.all([
        loadAllCertificates(),
        listInventory(session),
        getCertExpiryAlertPolicy(session)
      ]);
      setCerts(Array.isArray(certItems)?certItems:[]);
      setInventory(Array.isArray(inventoryItems)?inventoryItems:[]);
      setAlertPolicyDaysBefore(Math.max(1,Math.min(3650,Number(alertPolicy?.days_before||30))));
      setAlertPolicyIncludeExternal(Boolean(alertPolicy?.include_external ?? true));
      setRenewalSummary(await getCertRenewalSummary(session).catch(()=>null));
      setStarSummary(await getCertSTARSummary(session).catch(()=>null));
    }catch(e){
      onToast?.(`Certificates refresh failed: ${errMsg(e)}`);
    }finally{
      setCertLoading(false);
    }
  };

  const refresh=async()=>{
    if(!session){
      return;
    }
    setLoading(true);
    try{
      const [caItems,certItems,profileItems,inventoryItems,protocolItems,protocolSchemaItems,alertPolicy,renewalSummaryOut,starSummaryOut,ctEpochItems]=await Promise.all([
        listCAs(session),
        loadAllCertificates(),
        listProfiles(session),
        listInventory(session),
        listProtocolConfigs(session),
        listProtocolSchemas(session),
        getCertExpiryAlertPolicy(session),
        getCertRenewalSummary(session).catch(()=>null),
        getCertSTARSummary(session).catch(()=>null),
        listCertMerkleEpochs(session,50).catch(()=>[])
      ]);
      setCAs(Array.isArray(caItems)?caItems:[]);
      setCerts(Array.isArray(certItems)?certItems:[]);
      setProfiles(Array.isArray(profileItems)?profileItems:[]);
      setInventory(Array.isArray(inventoryItems)?inventoryItems:[]);
      setProtocols(Array.isArray(protocolItems)?protocolItems:[]);
      setProtocolSchemas(Array.isArray(protocolSchemaItems)?protocolSchemaItems:[]);
      setAlertPolicyDaysBefore(Math.max(1,Math.min(3650,Number(alertPolicy?.days_before||30))));
      setAlertPolicyIncludeExternal(Boolean(alertPolicy?.include_external ?? true));
      setRenewalSummary(renewalSummaryOut||null);
      setStarSummary(starSummaryOut||null);
      setCTEpochs(Array.isArray(ctEpochItems)?ctEpochItems:[]);
      if(!issueCAID&&Array.isArray(caItems)&&caItems.length){
        setIssueCAID(caItems[0].id);
      }
      if(!csrCAID&&Array.isArray(caItems)&&caItems.length){
        setCSRCAID(caItems[0].id);
      }
      if(!starCAID&&Array.isArray(caItems)&&caItems.length){
        setStarCAID(caItems[0].id);
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
      acme:{rfc:"8555",challenge_types:["http-01","dns-01"],auto_renew:true,enable_ari:true,ari_poll_hours:24,ari_window_bias_percent:35,emergency_rotation_threshold_hours:48,mass_renewal_risk_threshold:8,enable_star:true,default_star_validity_hours:24,max_star_validity_hours:168,allow_star_delegation:true,max_star_subscriptions:500,star_mass_rollout_threshold:12,require_eab:false,allow_wildcard:true,allow_ip_identifiers:false,max_sans:100,default_validity_days:397,rate_limit_per_hour:1000},
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
      acme:["challenge_types: http-01 | dns-01 | tls-alpn-01","enable_ari + ari_poll_hours","ari_window_bias_percent + emergency_rotation_threshold_hours","mass_renewal_risk_threshold","enable_star + default_star_validity_hours + max_star_validity_hours","allow_star_delegation + max_star_subscriptions + star_mass_rollout_threshold","require_eab: enforce external account binding","allow_wildcard / allow_ip_identifiers","max_sans / default_validity_days / rate_limit_per_hour"],
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
    const missedWindows=Number(renewalSummary?.missed_window_count||0);
    const emergencyRotations=Number(renewalSummary?.emergency_rotation_count||0);
    return {active,revoked,pqc,expiring,missedWindows,emergencyRotations,total:all.length,cas:(Array.isArray(cas)?cas:[]).length};
  },[cas,certs,inventory,certByID,alertPolicyDaysBefore,alertPolicyIncludeExternal,renewalSummary]);

  const expiryItems=useMemo(()=>{
    const items=(Array.isArray(inventory)?inventory:[]).map((it)=>{
      const cert=certByID.get(String(it.cert_id||""));
      if(!cert) return null;
      const certStatus=String(cert.status||"").toLowerCase();
      if(certStatus==="revoked"||certStatus==="deleted") return null;
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

  const renewalWindows=useMemo(()=>{
    return (Array.isArray(renewalSummary?.renewal_windows)?renewalSummary.renewal_windows:[]).slice(0,5);
  },[renewalSummary]);

  const renewalSchedule=useMemo(()=>{
    return (Array.isArray(renewalSummary?.ca_directed_schedule)?renewalSummary.ca_directed_schedule:[]).slice(0,5);
  },[renewalSummary]);

  const massRenewalRisks=useMemo(()=>{
    return (Array.isArray(renewalSummary?.mass_renewal_risks)?renewalSummary.mass_renewal_risks:[]).slice(0,5);
  },[renewalSummary]);

  const starSubscriptions=useMemo(()=>{
    return (Array.isArray(starSummary?.subscriptions)?starSummary.subscriptions:[]).slice(0,5);
  },[starSummary]);

  const starMassRolloutRisks=useMemo(()=>{
    return (Array.isArray(starSummary?.mass_rollout_risks)?starSummary.mass_rollout_risks:[]).slice(0,5);
  },[starSummary]);

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
      revoked: all.filter((c)=>String(c.status||"").toLowerCase()==="revoked").length
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
      onToast?.(`Certificate permanently deleted: ${label}`);
      await refreshCerts();
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
    const caID=String(ca?.id||"");
    const issuedCount=(certsByCA[caID]||[]).length;
    // First try normal delete
    const ok=await promptDialog.confirm({
      title:"Delete Certificate Authority",
      message:issuedCount>0
        ?`Delete CA '${label}'?\n\n${issuedCount} issued certificate(s) exist. This will fail unless you choose Force Delete.\n\nForce Delete: revokes all certificates under this CA, permanently removes certificate material, and deletes the CA.\n\nThis action CANNOT be undone.`
        :`Delete CA '${label}'?\n\nThis permanently removes the CA and cannot be undone.\n\nDelete will be blocked if this CA has child CAs.`,
      confirmLabel:issuedCount>0?"Force Delete CA":"Delete CA",
      danger:true
    });
    if(!ok){
      return;
    }
    await runCertAction(`delete-ca-${caID}`,async()=>{
      try{
        await deleteCA(session,caID,issuedCount>0);
        onToast?.(`CA deleted: ${label}${issuedCount>0?` (${issuedCount} certificate(s) removed)`:""}`);
        await Promise.all([refreshCAs(),refreshCerts()]);
      }catch(firstErr){
        const errStr=String((firstErr as any)?.message||firstErr||"");
        if(errStr.includes("issued certificate")&&!issuedCount){
          // Backend reported certs we didn't see — offer force
          const forceOk=await promptDialog.confirm({
            title:"Force Delete CA",
            message:`CA '${label}' has issued certificates in the backend.\n\nForce Delete will revoke and permanently remove ALL certificates under this CA, then delete the CA.\n\nThis action CANNOT be undone.`,
            confirmLabel:"Force Delete",
            danger:true
          });
          if(!forceOk){
            return;
          }
          await deleteCA(session,caID,true);
          onToast?.(`CA force-deleted: ${label}`);
          await Promise.all([refreshCAs(),refreshCerts()]);
        }else{
          throw firstErr;
        }
      }
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

  const refreshRenewalIntel=async()=>{
    if(!session){
      return;
    }
    setRenewalRefreshing(true);
    try{
      const out=await refreshCertRenewalSummary(session);
      setRenewalSummary(out||null);
      onToast?.("Renewal intelligence refreshed.");
    }catch(error){
      onToast?.(`Renewal intelligence refresh failed: ${errMsg(error)}`);
    }finally{
      setRenewalRefreshing(false);
    }
  };

  const refreshSTARIntel=async()=>{
    if(!session){
      return;
    }
    setStarRefreshing(true);
    try{
      const out=await getCertSTARSummary(session);
      setStarSummary(out||null);
      onToast?.("ACME STAR subscriptions refreshed.");
    }catch(error){
      onToast?.(`ACME STAR refresh failed: ${errMsg(error)}`);
    }finally{
      setStarRefreshing(false);
    }
  };

  const submitCreateSTARSubscription=async()=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    if(!String(starCAID||"").trim()){
      onToast?.("Select a CA for the STAR subscription.");
      return;
    }
    if(!String(starSubjectCN||"").trim()){
      onToast?.("Subject CN is required for the STAR subscription.");
      return;
    }
    setSubmitting(true);
    try{
      let metadata;
      const rawMetadata=String(starMetadataText||"").trim();
      if(rawMetadata){
        metadata=JSON.parse(rawMetadata);
      }
      const created=await createCertSTARSubscription(session,{
        name:String(starName||"").trim(),
        account_id:String(starAccountID||"").trim(),
        ca_id:String(starCAID||"").trim(),
        profile_id:String(starProfileID||"").trim(),
        subject_cn:String(starSubjectCN||"").trim(),
        sans:String(starSANs||"").split(",").map((v)=>String(v||"").trim()).filter(Boolean),
        cert_type:String(starCertType||"tls-server").trim(),
        cert_class:"star",
        algorithm:String(starAlgorithm||"ECDSA-P384").trim(),
        validity_hours:Math.max(1,Math.min(336,Math.trunc(Number(starValidityHours||24)))),
        renew_before_minutes:Math.max(5,Math.min(24*60,Math.trunc(Number(starRenewBeforeMinutes||120)))),
        auto_renew:Boolean(starAutoRenew),
        allow_delegation:Boolean(starAllowDelegation),
        delegated_subscriber:Boolean(starAllowDelegation)?String(starDelegatedSubscriber||"").trim():"",
        rollout_group:String(starRolloutGroup||"").trim(),
        metadata
      });
      onToast?.(`ACME STAR subscription created: ${String(created.name||created.subject_cn||created.id)}`);
      setModal(null);
      setStarName("");
      setStarAccountID("");
      setStarSubjectCN("");
      setStarSANs("");
      setStarProfileID("");
      setStarRolloutGroup("");
      setStarDelegatedSubscriber("");
      setStarMetadataText("{\n  \"workload\": \"edge-gateway\"\n}");
      await Promise.all([refreshRenewalIntel(),refreshSTARIntel(),refreshCerts()]);
    }catch(error){
      onToast?.(`ACME STAR create failed: ${errMsg(error)}`);
    }finally{
      setSubmitting(false);
    }
  };

  const actRefreshSTARSubscription=async(item,force=false)=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    await runCertAction(`star-refresh-${item.id}`,async()=>{
      const out=await refreshCertSTARSubscription(session,String(item.id||""),{
        force:Boolean(force),
        requested_by:session.username||"dashboard"
      });
      onToast?.(`ACME STAR renewed: ${String(out.subject_cn||out.name||out.id)}`);
      await Promise.all([refreshRenewalIntel(),refreshSTARIntel()]);
    });
  };

  const actDeleteSTARSubscription=async(item)=>{
    if(!session){
      onToast?.("Missing active session.");
      return;
    }
    const label=String(item?.name||item?.subject_cn||item?.id||"STAR subscription");
    const ok=await promptDialog.confirm({
      title:"Delete ACME STAR Subscription",
      message:`Delete ACME STAR subscription '${label}'?\n\nThis stops future automated STAR renewals for the delegated or short-lived workload.`,
      confirmLabel:"Delete",
      danger:true
    });
    if(!ok){
      return;
    }
    await runCertAction(`star-delete-${item.id}`,async()=>{
      await deleteCertSTARSubscription(session,String(item.id||""));
      onToast?.(`ACME STAR subscription deleted: ${label}`);
      await Promise.all([refreshRenewalIntel(),refreshSTARIntel()]);
    });
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
    const statusIcon=status==="active"?<CheckCircle2 size={10} color={C.green}/>:status==="revoked"?<XCircle size={10} color={C.red}/>:status==="deleted"?<Trash2 size={10} color={C.blue}/>:<ShieldAlert size={10} color={C.amber}/>;
    return <div key={certID} style={{padding:"7px 10px",border:`1px solid ${C.border}`,borderRadius:8,background:C.bg}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8}}>
        <div style={{minWidth:0,flex:1}}>
          <div style={{fontSize:11,color:C.text,fontWeight:600,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{String(crt.subject_cn||crt.id||"certificate")}</div>
          <div style={{display:"flex",gap:8,marginTop:3,alignItems:"center",flexWrap:"wrap"}}>
            <div style={{display:"inline-flex",alignItems:"center",gap:3}}>{statusIcon}<B c={status==="active"?"green":status==="revoked"||status==="deleted"?"red":"amber"}>{statusRaw||"unknown"}</B></div>
            <span style={{fontSize:9,color:C.accent,fontFamily:"'JetBrains Mono',monospace",background:C.accentDim,padding:"1px 5px",borderRadius:3}}>{String(crt.algorithm||"-")}</span>
            <span style={{fontSize:9,color:C.dim}}>{formatDestroyAt(String(crt.not_after||"-"))}</span>
          </div>
        </div>
        <div style={{fontSize:8,color:C.muted,fontFamily:"'JetBrains Mono',monospace",maxWidth:80,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{certID.slice(0,12)}...</div>
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
    return <Card key={caID} style={{padding:10,marginLeft:depth*20,background:depth===0?`linear-gradient(135deg,${C.accentDim} 0%,${C.card} 100%)`:`linear-gradient(135deg,${C.dimTint} 0%,${C.card} 100%)`,borderColor:depth===0?C.accentDim:C.border}}>
      <div style={{display:"flex",justifyContent:"space-between",gap:8,alignItems:"flex-start"}}>
        <div style={{minWidth:0,flex:1}}>
          <button onClick={()=>toggleCA(caID)} style={{background:"transparent",border:"none",padding:0,margin:0,color:depth===0?C.accent:C.text,cursor:"pointer",fontSize:12,fontWeight:700,display:"flex",alignItems:"center",gap:6}}>
            {open?<ChevronDown size={14}/>:<ChevronRight size={14}/>}
            <Shield size={14} color={depth===0?C.accent:C.dim}/>
            <span>{depth===0?"Root CA":"Intermediate CA"}: {String(ca.name||caID)}</span>
          </button>
          <div style={{display:"flex",gap:10,marginTop:5,marginLeft:34,flexWrap:"wrap",alignItems:"center"}}>
            <span style={{fontSize:9,color:C.accent,fontFamily:"'JetBrains Mono',monospace",background:C.accentDim,padding:"2px 6px",borderRadius:4}}>{String(ca.algorithm||"-")}</span>
            <span style={{fontSize:9,color:C.dim}}>{String(ca.key_backend||"software")==="keycore"?"HSM-backed":"Software vault"}</span>
            <span style={{fontSize:9,color:C.muted}}>Created: {formatDestroyAt(String(ca.created_at||""))}</span>
          </div>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:6,flexWrap:"wrap",justifyContent:"flex-end",flexShrink:0}}>
          <B c={status==="active"?"green":status==="revoked"?"red":"amber"}>{String(ca.status||"unknown")}</B>
          <B c="blue">{certList.length} cert{certList.length!==1?"s":""}</B>
          <Btn small onClick={()=>void actCRL(ca)} disabled={crlBusy}><span style={{display:"inline-flex",alignItems:"center",gap:4}}><Download size={10}/>{crlBusy?"...":"CRL"}</span></Btn>
          <Btn small danger onClick={()=>void actDeleteCA(ca)} disabled={deleteCABusy}><span style={{display:"inline-flex",alignItems:"center",gap:4}}><Trash2 size={10}/>{deleteCABusy?"...":"Delete"}</span></Btn>
        </div>
      </div>
      {open?<>
        {children.length?<div style={{display:"grid",gap:8,marginTop:10}}>{children.map((child)=>renderCANode(child,depth+1))}</div>:null}
        <div style={{marginTop:10,paddingTop:8,borderTop:`1px solid ${C.border}`}}>
          <button onClick={()=>toggleIssued(caID)} style={{background:"transparent",border:"none",padding:0,color:C.blue,cursor:"pointer",fontSize:10,fontWeight:700,display:"flex",alignItems:"center",gap:5}}>
            {issuedOpen?<ChevronDown size={12}/>:<ChevronRight size={12}/>}
            <FileText size={12}/>
            Issued Certificates ({certList.length})
          </button>
          {issuedOpen?<div style={{display:"grid",gap:6,marginTop:6,maxHeight:200,overflowY:"auto",paddingRight:4}}>
            {certList.length?certList.map((crt)=>renderIssuedCertRow(crt)):<div style={{fontSize:10,color:C.muted,padding:"6px 0"}}>No issued certificates under this CA.</div>}
          </div>:null}
        </div>
      </>:null}
    </Card>;
  };

  return <div>
    {showOverviewPane&&<>
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(140px,1fr))",gap:10,marginBottom:14}}>
        <Card style={{padding:"12px 14px",background:`linear-gradient(135deg,${C.card} 0%,${C.greenTint} 100%)`}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
            <ShieldCheck size={14} color={C.green}/>
            <span style={{fontSize:9,color:C.dim,textTransform:"uppercase",letterSpacing:.5}}>Active</span>
          </div>
          <div style={{fontSize:22,fontWeight:800,color:C.green,lineHeight:1}}>{String(stats.active)}</div>
          <div style={{fontSize:9,color:C.muted,marginTop:4}}>{stats.total?`${Math.round((stats.active*100)/stats.total)}% of total`:"—"}</div>
        </Card>
        <Card style={{padding:"12px 14px",background:`linear-gradient(135deg,${C.card} 0%,${C.redTint} 100%)`}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
            <ShieldX size={14} color={C.red}/>
            <span style={{fontSize:9,color:C.dim,textTransform:"uppercase",letterSpacing:.5}}>Revoked</span>
          </div>
          <div style={{fontSize:22,fontWeight:800,color:C.red,lineHeight:1}}>{String(stats.revoked)}</div>
        </Card>
        <Card style={{padding:"12px 14px",background:`linear-gradient(135deg,${C.card} 0%,${C.accentTint} 100%)`}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
            <Shield size={14} color={C.accent}/>
            <span style={{fontSize:9,color:C.dim,textTransform:"uppercase",letterSpacing:.5}}>CAs</span>
          </div>
          <div style={{fontSize:22,fontWeight:800,color:C.accent,lineHeight:1}}>{String(stats.cas)}</div>
          <div style={{fontSize:9,color:C.muted,marginTop:4}}>{roots.length} root</div>
        </Card>
        <Card style={{padding:"12px 14px",background:`linear-gradient(135deg,${C.card} 0%,${C.purpleTint} 100%)`}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
            <Fingerprint size={14} color={C.purple}/>
            <span style={{fontSize:9,color:C.dim,textTransform:"uppercase",letterSpacing:.5}}>PQC</span>
          </div>
          <div style={{fontSize:22,fontWeight:800,color:C.purple,lineHeight:1}}>{String(stats.pqc)}</div>
          <div style={{fontSize:9,color:C.muted,marginTop:4}}>{stats.total?Math.round((stats.pqc*100)/stats.total):0}% of total</div>
        </Card>
        <Card style={{padding:"12px 14px",background:`linear-gradient(135deg,${C.card} 0%,${stats.expiring>0?"${C.amberTint}":"${C.greenTint}"} 100%)`}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
            <Clock size={14} color={stats.expiring>0?C.amber:C.green}/>
            <span style={{fontSize:9,color:C.dim,textTransform:"uppercase",letterSpacing:.5}}>Expiring</span>
          </div>
          <div style={{fontSize:22,fontWeight:800,color:stats.expiring>0?C.amber:C.green,lineHeight:1}}>{String(stats.expiring)}</div>
          <div style={{fontSize:9,color:C.muted,marginTop:4}}>within {alertPolicyDaysBefore}d</div>
        </Card>
        <Card style={{padding:"12px 14px",background:`linear-gradient(135deg,${C.card} 0%,${stats.missedWindows>0?C.redTint:C.blueTint} 100%)`}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
            <AlertTriangle size={14} color={stats.missedWindows>0?C.red:C.blue}/>
            <span style={{fontSize:9,color:C.dim,textTransform:"uppercase",letterSpacing:.5}}>Missed Windows</span>
          </div>
          <div style={{fontSize:22,fontWeight:800,color:stats.missedWindows>0?C.red:C.blue,lineHeight:1}}>{String(stats.missedWindows)}</div>
          <div style={{fontSize:9,color:C.muted,marginTop:4}}>RFC 9773 renewal windows</div>
        </Card>
        <Card style={{padding:"12px 14px",background:`linear-gradient(135deg,${C.card} 0%,${stats.emergencyRotations>0?C.redTint:C.accentTint} 100%)`}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
            <ShieldAlert size={14} color={stats.emergencyRotations>0?C.red:C.accent}/>
            <span style={{fontSize:9,color:C.dim,textTransform:"uppercase",letterSpacing:.5}}>Emergency Rotation</span>
          </div>
          <div style={{fontSize:22,fontWeight:800,color:stats.emergencyRotations>0?C.red:C.accent,lineHeight:1}}>{String(stats.emergencyRotations)}</div>
          <div style={{fontSize:9,color:C.muted,marginTop:4}}>{renewalSummary?.ari_enabled===false?"Local coordinated policy":"CA-directed schedule active"}</div>
        </Card>
      </div>
    </>}

    {showEnrollmentPane&&<>
      <div style={{display:"grid",gridTemplateColumns:"repeat(6,1fr)",gap:10,marginBottom:14}}>
        <Card style={{padding:"12px 14px"}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
            <Server size={14} color={C.accent}/>
            <span style={{fontSize:9,color:C.dim,textTransform:"uppercase",letterSpacing:.5}}>Protocols</span>
          </div>
          <div style={{fontSize:22,fontWeight:800,color:C.accent,lineHeight:1}}>{protocolMeta.length}</div>
          <div style={{fontSize:9,color:C.muted,marginTop:4}}>configured</div>
        </Card>
        <Card style={{padding:"12px 14px"}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
            <CheckCircle2 size={14} color={C.green}/>
            <span style={{fontSize:9,color:C.dim,textTransform:"uppercase",letterSpacing:.5}}>Enabled</span>
          </div>
          <div style={{fontSize:22,fontWeight:800,color:C.green,lineHeight:1}}>{protocolMeta.filter((m)=>{const cfg=protocolByName[m.name];return cfg?Boolean(cfg.enabled):true;}).length}</div>
        </Card>
        <Card style={{padding:"12px 14px"}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
            <XCircle size={14} color={C.red}/>
            <span style={{fontSize:9,color:C.dim,textTransform:"uppercase",letterSpacing:.5}}>Disabled</span>
          </div>
          <div style={{fontSize:22,fontWeight:800,color:C.red,lineHeight:1}}>{protocolMeta.filter((m)=>{const cfg=protocolByName[m.name];return cfg?!Boolean(cfg.enabled):false;}).length}</div>
        </Card>
        <Card style={{padding:"12px 14px"}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
            <Globe size={14} color={C.blue}/>
            <span style={{fontSize:9,color:C.dim,textTransform:"uppercase",letterSpacing:.5}}>ACME</span>
          </div>
          <div style={{fontSize:11,fontWeight:700,color:protocolByName["acme"]?Boolean(protocolByName["acme"].enabled)?C.green:C.red:C.green,lineHeight:1.4}}>{protocolByName["acme"]?Boolean(protocolByName["acme"].enabled)?"Active":"Off":"Active"}</div>
          <div style={{fontSize:9,color:C.muted}}>RFC 8555</div>
        </Card>
        <Card style={{padding:"12px 14px"}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
            <Lock size={14} color={C.purple}/>
            <span style={{fontSize:9,color:C.dim,textTransform:"uppercase",letterSpacing:.5}}>EST</span>
          </div>
          <div style={{fontSize:11,fontWeight:700,color:protocolByName["est"]?Boolean(protocolByName["est"].enabled)?C.green:C.red:C.green,lineHeight:1.4}}>{protocolByName["est"]?Boolean(protocolByName["est"].enabled)?"Active":"Off":"Active"}</div>
          <div style={{fontSize:9,color:C.muted}}>RFC 7030</div>
        </Card>
        <Card style={{padding:"12px 14px"}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
            <KeyRound size={14} color={C.amber}/>
            <span style={{fontSize:9,color:C.dim,textTransform:"uppercase",letterSpacing:.5}}>SCEP</span>
          </div>
          <div style={{fontSize:11,fontWeight:700,color:protocolByName["scep"]?Boolean(protocolByName["scep"].enabled)?C.green:C.red:C.green,lineHeight:1.4}}>{protocolByName["scep"]?Boolean(protocolByName["scep"].enabled)?"Active":"Off":"Active"}</div>
          <div style={{fontSize:9,color:C.muted}}>RFC 8894</div>
        </Card>
      </div>
      <Section title="Enrollment Protocols">
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
        {protocolMeta.map((meta)=>{
          const cfg=protocolByName[meta.name];
          const enabled=cfg?Boolean(cfg.enabled):true;
          const canTest=meta.name!=="runtime-mtls";
          const protocolIcon=meta.name==="acme"?<Globe size={18} color={C.blue}/>:meta.name==="est"?<Lock size={18} color={C.purple}/>:meta.name==="scep"?<KeyRound size={18} color={C.amber}/>:meta.name==="cmpv2"?<Server size={18} color={C.green}/>:<Shield size={18} color={C.accent}/>;
          const configObj=(() => { try { return JSON.parse(String(cfg?.config_json||"{}")); } catch { return {}; } })();
          const endpoints:Array<{label:string;path:string}>=
            meta.name==="acme"?[
              {label:"Directory",path:"/acme/directory"},
              {label:"New Nonce",path:"/acme/new-nonce"},
              {label:"New Account",path:"/acme/new-account"},
              {label:"New Order",path:"/acme/new-order"},
              {label:"Renewal Info",path:"/acme/renewal-info/{id}"},
              {label:"STAR Summary",path:"/certs/star/summary"},
              {label:"STAR Subscriptions",path:"/certs/star/subscriptions"},
              {label:"Challenge",path:"/acme/challenge/{id}"},
              {label:"Finalize",path:"/acme/finalize/{id}"},
              {label:"Cert Download",path:"/acme/cert/{id}"}
            ]:meta.name==="est"?[
              {label:"CA Certs",path:"/est/.well-known/est/cacerts"},
              {label:"CSR Attributes",path:"/est/.well-known/est/csrattrs"},
              {label:"Simple Enroll",path:"/est/.well-known/est/simpleenroll"},
              {label:"Simple Re-enroll",path:"/est/.well-known/est/simplereenroll"},
              {label:"Server Keygen",path:"/est/.well-known/est/serverkeygen"}
            ]:meta.name==="scep"?[
              {label:"GetCACaps",path:"/scep/pkiclient.exe?operation=getcacaps"},
              {label:"GetCACert",path:"/scep/pkiclient.exe?operation=getcacert"},
              {label:"GetCert",path:"/scep/pkiclient.exe?operation=getcert"},
              {label:"PKIOperation",path:"/scep/pkiclient.exe?operation=pkioperation"}
            ]:meta.name==="cmpv2"?[
              {label:"PKI Request (IR/CR/KUR/RR)",path:"/cmpv2"},
              {label:"PKI Confirm",path:"/cmpv2/confirm"}
            ]:[];
          const features:string[]=
            meta.name==="acme"?[
              `Challenges: ${(configObj.challenge_types||["http-01","dns-01"]).join(", ")}`,
              `ARI: ${configObj.enable_ari!==false?"Enabled":"Disabled"}`,
              `Renewal Poll: ${configObj.ari_poll_hours||24}h`,
              `Window Bias: ${configObj.ari_window_bias_percent||35}%`,
              `Mass Risk Threshold: ${configObj.mass_renewal_risk_threshold||8}`,
              `STAR: ${configObj.enable_star!==false?"Enabled":"Disabled"}`,
              `STAR Default Lifetime: ${configObj.default_star_validity_hours||24}h`,
              `STAR Delegation: ${configObj.allow_star_delegation!==false?"Allowed":"Disabled"}`,
              `Wildcard: ${configObj.allow_wildcard!==false?"Yes":"No"}`,
              `EAB Required: ${configObj.require_eab?"Yes":"No"}`,
              `Rate Limit: ${configObj.rate_limit_per_hour||1000}/hr`,
              `Nonce replay protection`,
              `Challenge token generation`
            ]:meta.name==="est"?[
              `Auth: ${String(configObj.auth_mode||"mtls").toUpperCase()}`,
              `Server Keygen: ${configObj.server_keygen!==false?"Yes":"No"}`,
              `Re-enroll: ${configObj.allow_reenroll!==false?"Yes":"No"}`,
              `CSR PoP: ${configObj.require_csr_pop!==false?"Required":"Optional"}`,
              `CSR Attributes endpoint (RFC 7030 section 4.5)`,
              `Wire format: application/pkcs10 + DER response`
            ]:meta.name==="scep"?[
              `Challenge Password: ${configObj.challenge_password_required?"Required":"Optional"}`,
              `Renewal: ${configObj.allow_renewal!==false?"Allowed":"Disabled"}`,
              `Digest: ${(configObj.digest_algorithms||["sha256","sha384"]).join(", ")}`,
              `Encryption: ${(configObj.encryption_algorithms||["aes256","aes128"]).join(", ")}`,
              `PKIMessage parsing via smallstep/scep`,
              `GetCert retrieval by serial number`
            ]:meta.name==="cmpv2"?[
              `Messages: ${(configObj.message_types||["ir","cr","kur","rr"]).join(", ").toUpperCase()}`,
              `Protection: ${configObj.require_message_protection!==false?"Required":"Optional"}`,
              `Transaction ID: ${configObj.require_transaction_id!==false?"Required":"Optional"}`,
              `Implicit Confirm: ${configObj.allow_implicit_confirm!==false?"Yes":"No"}`,
              `PKI Confirmation (pkiconf) endpoint`,
              `Structured error responses`
            ]:[];
          const impl=meta.schema?.implementation;
          return <Card key={meta.name} style={{padding:14,background:`linear-gradient(135deg,${C.card} 0%,${enabled?"${C.greenTint3}":"${C.redTint3}"} 100%)`}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:8}}>
              <div style={{display:"flex",alignItems:"center",gap:10}}>
                <div style={{width:36,height:36,borderRadius:8,background:enabled?C.greenDim:C.redDim,display:"flex",alignItems:"center",justifyContent:"center"}}>{protocolIcon}</div>
                <div>
                  <div style={{fontSize:15,fontWeight:700,color:C.text}}>{meta.title}</div>
                  <div style={{fontSize:9,color:C.accent,fontFamily:"'JetBrains Mono',monospace"}}>{meta.rfc}</div>
                </div>
              </div>
              <B c={enabled?"green":"red"}>{enabled?"Active":"Disabled"}</B>
            </div>
            <div style={{fontSize:11,color:C.dim,marginBottom:6,lineHeight:1.5}}>{meta.desc}</div>
            {impl?<div style={{fontSize:9,color:C.muted,marginBottom:6}}>Engine: {impl.engine} | {(impl.sdks||[]).join(", ")}</div>:null}
            {features.length>0?<div style={{marginBottom:8}}>
              <div style={{fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:.5,marginBottom:4}}>Capabilities</div>
              <div style={{display:"flex",flexWrap:"wrap",gap:4}}>
                {features.map((f,i)=><span key={i} style={{fontSize:9,padding:"2px 6px",borderRadius:4,background:C.surfaceHi||C.accentDim,color:C.text,border:`1px solid ${C.border}`}}>{f}</span>)}
              </div>
            </div>:null}
            {endpoints.length>0?<div style={{marginBottom:8}}>
              <div style={{fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:.5,marginBottom:4}}>Endpoints</div>
              <div style={{display:"grid",gap:2}}>
                {endpoints.map((ep,i)=><div key={i} style={{display:"flex",gap:6,fontSize:9,alignItems:"center"}}>
                  <span style={{color:C.green,fontWeight:600,minWidth:90}}>{ep.label}</span>
                  <code style={{color:C.accent,fontFamily:"'JetBrains Mono',monospace",fontSize:8}}>{ep.path}</code>
                </div>)}
              </div>
            </div>:null}
            {cfg?.updated_at?<div style={{fontSize:9,color:C.muted,marginBottom:8}}>Last updated: {formatDestroyAt(String(cfg.updated_at||""))} by {String(cfg.updated_by||"system")}</div>:null}
            <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
              <Btn small onClick={()=>openProtocolModal(meta.name)}><span style={{display:"inline-flex",alignItems:"center",gap:4}}><Settings size={10}/>Configure</span></Btn>
              <Btn
                small
                primary
                disabled={!enabled||testingProtocol===meta.name||!canTest}
                onClick={()=>void runProtocolTest(meta.name)}
              >
                <span style={{display:"inline-flex",alignItems:"center",gap:4}}><Zap size={10}/>{!canTest?"N/A":testingProtocol===meta.name?"Testing...":"Test Enroll"}</span>
              </Btn>
              {meta.name==="acme"&&enabled?<Btn small onClick={()=>setModal("acme-wizard")}><span style={{display:"inline-flex",alignItems:"center",gap:4}}><Globe size={10}/>ACME Wizard</span></Btn>:null}
              {meta.name==="acme"&&enabled?<Btn small onClick={()=>setModal("acme-star")}><span style={{display:"inline-flex",alignItems:"center",gap:4}}><Clock size={10}/>STAR</span></Btn>:null}
              {meta.name==="est"&&enabled?<Btn small onClick={()=>setModal("est-wizard")}><span style={{display:"inline-flex",alignItems:"center",gap:4}}><Lock size={10}/>EST Enroll</span></Btn>:null}
              {meta.name==="scep"&&enabled?<Btn small onClick={()=>setModal("scep-wizard")}><span style={{display:"inline-flex",alignItems:"center",gap:4}}><KeyRound size={10}/>SCEP Enroll</span></Btn>:null}
              {meta.name==="cmpv2"&&enabled?<Btn small onClick={()=>setModal("cmpv2-wizard")}><span style={{display:"inline-flex",alignItems:"center",gap:4}}><Server size={10}/>CMPv2 Request</span></Btn>:null}
            </div>
          </Card>;
        })}
      </div>
    </Section>
    </>}

    {showOverviewPane&&<div style={{display:"grid",gridTemplateColumns:"2fr 1fr",gap:10,marginBottom:12}}>
      <Card style={{padding:12}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
          <div style={{display:"flex",alignItems:"center",gap:8}}>
            <Shield size={16} color={C.accent}/>
            <div style={{fontSize:13,fontWeight:700,color:C.text}}>CA Hierarchy</div>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:6}}>
            <Btn small onClick={()=>setCAStatusView("all")} style={{background:caStatusView==="all"?C.accentDim:"transparent",color:caStatusView==="all"?C.accent:C.text}}>{`All ${caStatusCounts.all}`}</Btn>
            <Btn small onClick={()=>setCAStatusView("active")} style={{background:caStatusView==="active"?C.greenDim:"transparent",color:caStatusView==="active"?C.green:C.text}}>{`Active ${caStatusCounts.active}`}</Btn>
            <Btn small onClick={()=>setCAStatusView("revoked")} style={{background:caStatusView==="revoked"?C.redDim:"transparent",color:caStatusView==="revoked"?C.red:C.text}}>{`Revoked ${caStatusCounts.revoked}`}</Btn>
            <Btn small onClick={()=>void refreshCAs()} disabled={caLoading}><span style={{display:"inline-flex",alignItems:"center",gap:6}}><RefreshCcw size={12}/>{caLoading?"...":"Refresh"}</span></Btn>
            <Btn small primary onClick={()=>setModal("create-ca")}><span style={{display:"inline-flex",alignItems:"center",gap:5}}><Shield size={11}/>Create CA</span></Btn>
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
        <Card style={{padding:12}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
            <Clock size={14} color={C.amber}/>
            <div style={{fontSize:13,fontWeight:700,color:C.text}}>Expiry Calendar</div>
          </div>
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
        <Card style={{padding:12}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8,marginBottom:6}}>
            <div style={{display:"flex",alignItems:"center",gap:8}}>
              <RefreshCcw size={14} color={C.accent}/>
              <div style={{fontSize:13,fontWeight:700,color:C.text}}>Renewal Windows</div>
            </div>
            <B c={renewalSummary?.ari_enabled===false?"amber":"green"}>{renewalSummary?.ari_enabled===false?"Local":"ARI"}</B>
          </div>
          <div style={{fontSize:9,color:C.muted,marginBottom:8}}>
            {`Poll every ${Number(renewalSummary?.recommended_poll_hours||24)}h • Missed ${Number(renewalSummary?.missed_window_count||0)} • Emergency ${Number(renewalSummary?.emergency_rotation_count||0)}`}
          </div>
          <div style={{display:"grid",gap:8}}>
            {renewalWindows.map((item)=>{
              const risk=String(item.risk_level||"low").toLowerCase();
              const tone=risk==="critical"?"red":risk==="high"||risk==="medium"?"amber":"green";
              return <div key={item.cert_id} style={{borderBottom:`1px solid ${C.border}`,paddingBottom:6}}>
                <div style={{display:"flex",justifyContent:"space-between",gap:8,alignItems:"center"}}>
                  <div style={{fontSize:11,color:C.text,maxWidth:180,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{String(item.subject_cn||item.cert_id)}</div>
                  <B c={tone}>{String(item.renewal_state||"scheduled").replaceAll("_"," ")}</B>
                </div>
                <div style={{fontSize:9,color:C.dim,marginTop:3}}>
                  {`${String(item.ca_name||item.ca_id||"CA")} • ${formatDestroyAt(String(item.window_start||""))} -> ${formatDestroyAt(String(item.window_end||""))}`}
                </div>
              </div>;
            })}
            {!renewalWindows.length?<div style={{fontSize:10,color:C.muted}}>No coordinated renewal windows available yet.</div>:null}
          </div>
        </Card>
        <Card style={{padding:12}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:6}}>
            <Server size={14} color={C.blue}/>
            <div style={{fontSize:13,fontWeight:700,color:C.text}}>CA-Directed Schedule</div>
          </div>
          <div style={{display:"grid",gap:8}}>
            {renewalSchedule.map((item)=>{
              const risk=String(item.risk_level||"low").toLowerCase();
              const tone=risk==="critical"?"red":risk==="high"||risk==="medium"?"amber":"green";
              return <div key={`${item.ca_id}-${item.bucket}`} style={{borderBottom:`1px solid ${C.border}`,paddingBottom:6}}>
                <div style={{display:"flex",justifyContent:"space-between",gap:8,alignItems:"center"}}>
                  <div style={{fontSize:11,color:C.text}}>{String(item.ca_name||item.ca_id||"CA")}</div>
                  <B c={tone}>{`${item.count} certs`}</B>
                </div>
                <div style={{fontSize:9,color:C.dim,marginTop:3}}>
                  {`${String(item.bucket||"-")} • ${formatDestroyAt(String(item.scheduled_start||""))} -> ${formatDestroyAt(String(item.scheduled_end||""))}`}
                </div>
              </div>;
            })}
            {!renewalSchedule.length?<div style={{fontSize:10,color:C.muted}}>No CA-directed schedule groups yet.</div>:null}
          </div>
        </Card>
        <Card style={{padding:12}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8,marginBottom:6}}>
            <div style={{display:"flex",alignItems:"center",gap:8}}>
              <ShieldAlert size={14} color={massRenewalRisks.length?C.amber:C.green}/>
              <div style={{fontSize:13,fontWeight:700,color:C.text}}>Mass-Renewal Risk</div>
            </div>
            <Btn small onClick={()=>void refreshRenewalIntel()} disabled={renewalRefreshing}>
              {renewalRefreshing?"Refreshing...":"Refresh"}
            </Btn>
          </div>
          <div style={{display:"grid",gap:8}}>
            {massRenewalRisks.map((item)=>(
              <div key={`${item.ca_id}-${item.bucket}-risk`} style={{borderBottom:`1px solid ${C.border}`,paddingBottom:6}}>
                <div style={{display:"flex",justifyContent:"space-between",gap:8,alignItems:"center"}}>
                  <div style={{fontSize:11,color:C.text}}>{String(item.ca_name||item.ca_id||"CA")}</div>
                  <B c="amber">{`${item.count} in bucket`}</B>
                </div>
                <div style={{fontSize:9,color:C.dim,marginTop:3}}>
                  {`${String(item.bucket||"-")} • stagger certificates or widen renewal bias if this becomes an operational hotspot.`}
                </div>
              </div>
            ))}
            {!massRenewalRisks.length?<div style={{fontSize:10,color:C.muted}}>No mass-renewal hotspots detected.</div>:null}
          </div>
        </Card>
        <Card style={{padding:12}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8,marginBottom:6}}>
            <div style={{display:"flex",alignItems:"center",gap:8}}>
              <Clock size={14} color={starSummary?.enabled===false?C.red:C.accent}/>
              <div style={{fontSize:13,fontWeight:700,color:C.text}}>ACME STAR</div>
            </div>
            <div style={{display:"flex",gap:6}}>
              <Btn small onClick={()=>void refreshSTARIntel()} disabled={starRefreshing}>{starRefreshing?"Refreshing...":"Refresh"}</Btn>
              <Btn small primary onClick={()=>setModal("acme-star")}>New</Btn>
            </div>
          </div>
          <div style={{fontSize:9,color:C.muted,marginBottom:8}}>
            {starSummary?.enabled===false
              ?"ACME STAR is disabled in the ACME protocol policy for this tenant."
              :`Subscriptions ${Number(starSummary?.subscription_count||renewalSummary?.star_subscription_count||0)} • Delegated ${Number(starSummary?.delegated_count||renewalSummary?.star_delegated_count||0)} • Due soon ${Number(starSummary?.due_soon_count||renewalSummary?.star_due_soon_count||0)}`}
          </div>
          {String(starSummary?.recommended_window_hint||"").trim()?<div style={{fontSize:10,color:C.dim,marginBottom:8}}>{String(starSummary?.recommended_window_hint||"")}</div>:null}
          <div style={{display:"grid",gap:8}}>
            {starSubscriptions.map((item)=>{
              const status=String(item.status||"active").toLowerCase();
              const tone=status==="active"?C.green:status==="error"?C.red:C.amber;
              return <div key={item.id} style={{borderBottom:`1px solid ${C.border}`,paddingBottom:6}}>
                <div style={{display:"flex",justifyContent:"space-between",gap:8,alignItems:"center"}}>
                  <div style={{minWidth:0}}>
                    <div style={{fontSize:11,color:C.text,fontWeight:700,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{String(item.name||item.subject_cn||item.id)}</div>
                    <div style={{fontSize:9,color:C.dim,marginTop:3}}>
                      {`${String(item.subject_cn||"-")} • ${item.validity_hours||24}h • renew ${item.renew_before_minutes||120}m early`}
                    </div>
                  </div>
                  <B c={status==="active"?"green":status==="error"?"red":"amber"}>{status}</B>
                </div>
                <div style={{display:"flex",justifyContent:"space-between",gap:8,alignItems:"center",marginTop:6}}>
                  <div style={{fontSize:9,color:C.dim}}>
                    {`${item.delegated_subscriber?`Delegated to ${item.delegated_subscriber}`:"Tenant-managed"} • next ${formatDestroyAt(String(item.next_renewal_at||""))}`}
                  </div>
                  <div style={{display:"flex",gap:6}}>
                    <Btn small onClick={()=>void actRefreshSTARSubscription(item,true)} disabled={rowActionBusy===`star-refresh-${item.id}`}>Renew</Btn>
                    <Btn small danger onClick={()=>void actDeleteSTARSubscription(item)} disabled={rowActionBusy===`star-delete-${item.id}`}>Delete</Btn>
                  </div>
                </div>
                {item.last_error?<div style={{fontSize:9,color:C.red,marginTop:4}}>{String(item.last_error||"")}</div>:null}
              </div>;
            })}
            {!starSubscriptions.length?<div style={{fontSize:10,color:C.muted}}>No ACME STAR subscriptions yet. Create one for short-lived edge, mesh, or delegated subscriber certificates.</div>:null}
            {starMassRolloutRisks.map((risk)=>(
              <div key={`star-risk-${risk.rollout_group}`} style={{borderTop:`1px dashed ${C.border}`,paddingTop:6}}>
                <div style={{display:"flex",justifyContent:"space-between",gap:8,alignItems:"center"}}>
                  <div style={{fontSize:10,color:C.text,fontWeight:700}}>{`STAR rollout ${String(risk.rollout_group||"-")}`}</div>
                  <B c={String(risk.risk_level||"medium").toLowerCase()==="high"?"red":"amber"}>{`${risk.count} subs`}</B>
                </div>
                <div style={{fontSize:9,color:C.dim,marginTop:3}}>
                  {`${formatDestroyAt(String(risk.scheduled_start||""))} -> ${formatDestroyAt(String(risk.scheduled_end||""))}${Array.isArray(risk.delegated_targets)&&risk.delegated_targets.length?` • delegated: ${risk.delegated_targets.join(", ")}`:""}`}
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>}

    {showOverviewPane&&<Card style={{padding:"10px 14px",marginBottom:12,background:`linear-gradient(135deg,${C.card} 0%,${C.accentTint3} 100%)`,borderColor:C.accentDim}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
        <div style={{fontSize:11,fontWeight:700,color:C.text}}>Certificate Operations</div>
        <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
          <Btn small primary onClick={()=>setModal("issue")} style={{height:32,padding:"0 14px"}}><span style={{display:"inline-flex",alignItems:"center",gap:5}}><FileText size={11}/>Issue Certificate</span></Btn>
          <Btn small onClick={()=>setModal("sign-csr")} style={{height:32,padding:"0 14px"}}><span style={{display:"inline-flex",alignItems:"center",gap:5}}><Fingerprint size={11}/>Sign CSR</span></Btn>
          <Btn small onClick={()=>setModal("issue-pqc")} style={{height:32,padding:"0 14px"}}><span style={{display:"inline-flex",alignItems:"center",gap:5}}><Shield size={11}/>PQC Issue</span></Btn>
          <Btn small onClick={()=>setModal("upload-3p")} style={{height:32,padding:"0 14px"}}><span style={{display:"inline-flex",alignItems:"center",gap:5}}><Globe size={11}/>Upload 3rd-Party</span></Btn>
          <Btn small onClick={()=>setModal("cert-alert-policy")} style={{height:32,padding:"0 14px"}}><span style={{display:"inline-flex",alignItems:"center",gap:5}}><AlertTriangle size={11}/>Alert Policy</span></Btn>
        </div>
      </div>
    </Card>}

    {/* ═══ Certificate Transparency (Merkle) ═══ */}
    {showOverviewPane&&<Section title="Certificate Transparency" actions={
      <div style={{display:"flex",gap:6}}>
        <Btn small onClick={async()=>{
          setCTBuilding(true);
          try{
            const res=await buildCertMerkleEpoch(session,500);
            if(res?.epoch){
              const updated=await listCertMerkleEpochs(session,50).catch(()=>[]);
              setCTEpochs(Array.isArray(updated)?updated:[]);
              onToast?.(`CT epoch #${res.epoch.epoch_number} built (${res.leaves} certs)`);
            }else{
              onToast?.("No new certificates to log.");
            }
          }catch(e){onToast?.(`CT build failed: ${errMsg(e)}`);}
          finally{setCTBuilding(false);}
        }} disabled={ctBuilding}>{ctBuilding?"Building...":"Build Epoch"}</Btn>
        <Btn small onClick={async()=>{
          const items=await listCertMerkleEpochs(session,50).catch(()=>[]);
          setCTEpochs(Array.isArray(items)?items:[]);
        }}>Refresh</Btn>
      </div>
    }>
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:12}}>
        <Stat l="CT Epochs" v={ctEpochs.length} c="green" i={Shield}/>
        <Stat l="Logged Certs" v={ctEpochs.reduce((s,e)=>s+(e.leaf_count||0),0)} c="accent" i={FileText}/>
      </div>

      <Card style={{padding:0,overflow:"hidden",marginBottom:12}}>
        <div style={{display:"grid",gridTemplateColumns:".5fr .6fr 1fr 1fr",padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>
          <div>Epoch</div><div>Certs</div><div>Root Hash</div><div style={{textAlign:"right"}}>Built</div>
        </div>
        <div style={{maxHeight:180,overflowY:"auto"}}>
          {ctEpochs.map((ep)=>(
            <div key={ep.id} style={{display:"grid",gridTemplateColumns:".5fr .6fr 1fr 1fr",padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:11,alignItems:"center"}}>
              <div style={{color:C.accent,fontWeight:600}}>#{ep.epoch_number}</div>
              <div style={{color:C.text}}>{ep.leaf_count}</div>
              <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:C.green}}>{ep.tree_root?`${ep.tree_root.slice(0,16)}...${ep.tree_root.slice(-8)}`:"—"}</div>
              <div style={{fontSize:10,color:C.dim,textAlign:"right"}}>{ep.created_at?new Date(ep.created_at).toLocaleString():"—"}</div>
            </div>
          ))}
          {!ctEpochs.length&&<div style={{padding:14,fontSize:10,color:C.dim,textAlign:"center"}}>No CT epochs built yet. Click "Build Epoch" to log certificates into a Merkle tree.</div>}
        </div>
      </Card>

      <Card>
        <div style={{fontSize:11,fontWeight:600,color:C.text,marginBottom:8}}>Certificate Inclusion Proof</div>
        <div style={{display:"flex",gap:8,alignItems:"flex-end",marginBottom:10}}>
          <div style={{flex:1}}>
            <Inp placeholder="Certificate ID (e.g. crt_...)" value={ctProofCertId} onChange={(e)=>setCTProofCertId(e.target.value)} style={{fontSize:11}}/>
          </div>
          <Btn small primary onClick={async()=>{
            const id=ctProofCertId.trim();
            if(!id){onToast?.("Enter a certificate ID.");return;}
            try{
              const proof=await getCertMerkleProof(session,id);
              const vr=await verifyCertMerkleProof(session,{leaf_hash:proof.leaf_hash,leaf_index:proof.leaf_index,siblings:proof.siblings,root:proof.root});
              setCTProofResult({certId:id,proof,verified:vr.valid});
            }catch(e){
              setCTProofResult({certId:id,error:errMsg(e)});
            }
          }}>Verify</Btn>
        </div>

        {ctProofResult&&(
          <div style={{padding:12,borderRadius:8,background:C.card,border:`1px solid ${C.border}`,fontSize:11}}>
            {ctProofResult.error?(
              <div style={{color:C.red}}>{ctProofResult.error}</div>
            ):ctProofResult.proof?(
              <div>
                <div style={{marginBottom:8}}>
                  <B c={ctProofResult.verified?"green":"red"}>{ctProofResult.verified?"VERIFIED":"FAILED"}</B>
                  {" "}<span style={{color:C.dim}}>Certificate</span>{" "}
                  <span style={{fontFamily:"'JetBrains Mono',monospace",color:C.accent,fontSize:10}}>{ctProofResult.certId}</span>
                </div>
                {ctProofResult.proof.subject_cn&&<div style={{fontSize:10,color:C.dim,marginBottom:6}}>Subject: <span style={{color:C.text}}>{ctProofResult.proof.subject_cn}</span> | Serial: <span style={{color:C.text}}>{ctProofResult.proof.serial_number}</span></div>}
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6,color:C.dim,fontSize:10,marginBottom:8}}>
                  <div>Epoch: <span style={{color:C.text}}>{ctProofResult.proof.epoch_id?.slice(0,12)}</span></div>
                  <div>Leaf Index: <span style={{color:C.text}}>{ctProofResult.proof.leaf_index}</span></div>
                  <div>Proof Steps: <span style={{color:C.text}}>{ctProofResult.proof.siblings?.length||0}</span></div>
                </div>
                <div style={{marginBottom:6}}>
                  <div style={{fontSize:10,color:C.muted,marginBottom:3}}>Root Hash</div>
                  <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:C.green,wordBreak:"break-all"}}>{ctProofResult.proof.root}</div>
                </div>
                <div>
                  <div style={{fontSize:10,color:C.muted,marginBottom:3}}>Inclusion Path</div>
                  {(ctProofResult.proof.siblings||[]).map((s,i)=>(
                    <div key={i} style={{fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:C.dim,marginBottom:2}}>
                      [{i}] {s.position.toUpperCase()}: {s.hash.slice(0,24)}...
                    </div>
                  ))}
                </div>
              </div>
            ):null}
          </div>
        )}
      </Card>
    </Section>}

    {showOverviewPane&&<Section title="Certificates">
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8,marginBottom:10,flexWrap:"wrap"}}>
        <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
          <Inp
            placeholder="Search by name, ID, algorithm, class..."
            w={320}
            value={certSearch}
            onChange={(e)=>setCertSearch(e.target.value)}
            style={{height:34,borderRadius:9,fontSize:11}}
          />
        <Btn small onClick={()=>setCertStatusView("all")} style={{background:certStatusView==="all"?C.accentDim:"transparent",color:certStatusView==="all"?C.accent:C.text,borderColor:certStatusView==="all"?C.accent:"transparent"}}>
          <span style={{display:"inline-flex",alignItems:"center",gap:4}}><FileText size={10}/>{`All (${certStatusCounts.all})`}</span>
        </Btn>
        <Btn small onClick={()=>setCertStatusView("active")} style={{background:certStatusView==="active"?C.greenDim:"transparent",color:certStatusView==="active"?C.green:C.text,borderColor:certStatusView==="active"?C.green:"transparent"}}>
          <span style={{display:"inline-flex",alignItems:"center",gap:4}}><CheckCircle2 size={10}/>{`Active (${certStatusCounts.active})`}</span>
        </Btn>
        <Btn small onClick={()=>setCertStatusView("revoked")} style={{background:certStatusView==="revoked"?C.redDim:"transparent",color:certStatusView==="revoked"?C.red:C.text,borderColor:certStatusView==="revoked"?C.red:"transparent"}}>
          <span style={{display:"inline-flex",alignItems:"center",gap:4}}><XCircle size={10}/>{`Revoked (${certStatusCounts.revoked})`}</span>
        </Btn>
        </div>
        <Btn small onClick={()=>void refreshCerts()} disabled={certLoading}><span style={{display:"inline-flex",alignItems:"center",gap:6}}><RefreshCcw size={12}/>{certLoading?"Refreshing...":"Refresh"}</span></Btn>
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
              <div style={{display:"flex",alignItems:"center",gap:4}}>{String(c.status).toLowerCase()==="active"?<CheckCircle2 size={11} color={C.green}/>:String(c.status).toLowerCase()==="revoked"?<XCircle size={11} color={C.red}/>:String(c.status).toLowerCase()==="deleted"?<Trash2 size={11} color={C.blue}/>:<ShieldAlert size={11} color={C.amber}/>}<B c={String(c.status).toLowerCase()==="active"?"green":String(c.status).toLowerCase()==="revoked"||String(c.status).toLowerCase()==="deleted"?"red":"amber"}>{c.status}</B></div>
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
                  {status!=="deleted"?<button
                    onClick={(e)=>{
                      e.stopPropagation();
                      setOpenCertActionMenuId("");
                      actDownloadCert(c);
                    }}
                    onMouseEnter={(e)=>{(e.currentTarget as any).style.background=C.accentDim;}}
                    onMouseLeave={(e)=>{(e.currentTarget as any).style.background="transparent";}}
                    style={{background:"transparent",border:"none",color:C.text,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:"pointer",borderRadius:6,display:"flex",alignItems:"center",gap:6}}
                  >
                    <Download size={12} color={C.accent}/> Download
                  </button>:<div style={{padding:"6px 8px",fontSize:10,color:C.muted,display:"flex",alignItems:"center",gap:6}}>
                    <XCircle size={12} color={C.muted}/> Download unavailable (deleted)
                  </div>}
                  {canRenew?<button
                    onClick={(e)=>{
                      e.stopPropagation();
                      setOpenCertActionMenuId("");
                      void actRenewCert(c);
                    }}
                    disabled={busy===`renew-${certID}`}
                    onMouseEnter={(e)=>{(e.currentTarget as any).style.background=C.greenDim;}}
                    onMouseLeave={(e)=>{(e.currentTarget as any).style.background="transparent";}}
                    style={{background:"transparent",border:"none",color:C.text,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:busy===`renew-${certID}`?"not-allowed":"pointer",borderRadius:6,display:"flex",alignItems:"center",gap:6}}
                  >
                    <RotateCcw size={12} color={C.green}/> {busy===`renew-${certID}`?"Renewing...":"Renew"}
                  </button>:null}
                  {canRevoke?<button
                    onClick={(e)=>{
                      e.stopPropagation();
                      setOpenCertActionMenuId("");
                      void actRevokeCert(c);
                    }}
                    disabled={busy===`revoke-${certID}`}
                    onMouseEnter={(e)=>{(e.currentTarget as any).style.background=C.amberDim;}}
                    onMouseLeave={(e)=>{(e.currentTarget as any).style.background="transparent";}}
                    style={{background:"transparent",border:"none",color:C.text,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:busy===`revoke-${certID}`?"not-allowed":"pointer",borderRadius:6,display:"flex",alignItems:"center",gap:6}}
                  >
                    <ShieldX size={12} color={C.amber}/> {busy===`revoke-${certID}`?"Revoking...":"Revoke"}
                  </button>:null}
                  <button
                    onClick={(e)=>{
                      e.stopPropagation();
                      setOpenCertActionMenuId("");
                      void actOCSP(c);
                    }}
                    disabled={busy===`ocsp-${certID}`}
                    onMouseEnter={(e)=>{(e.currentTarget as any).style.background=C.blueDim;}}
                    onMouseLeave={(e)=>{(e.currentTarget as any).style.background="transparent";}}
                    style={{background:"transparent",border:"none",color:C.text,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:busy===`ocsp-${certID}`?"not-allowed":"pointer",borderRadius:6,display:"flex",alignItems:"center",gap:6}}
                  >
                    <Eye size={12} color={C.blue}/> {busy===`ocsp-${certID}`?"Checking...":"OCSP Status"}
                  </button>
                  {canDelete?<>
                  <div style={{height:1,background:C.border,margin:"2px 0"}}/>
                  <button
                    onClick={(e)=>{
                      e.stopPropagation();
                      setOpenCertActionMenuId("");
                      void actDeleteCert(c);
                    }}
                    disabled={busy===`delete-${certID}`}
                    onMouseEnter={(e)=>{(e.currentTarget as any).style.background=C.redDim;}}
                    onMouseLeave={(e)=>{(e.currentTarget as any).style.background="transparent";}}
                    style={{background:"transparent",border:"none",color:C.red,fontSize:10,textAlign:"left",padding:"6px 8px",cursor:busy===`delete-${certID}`?"not-allowed":"pointer",borderRadius:6,display:"flex",alignItems:"center",gap:6}}
                  >
                    <Trash2 size={12} color={C.red}/> {busy===`delete-${certID}`?"Deleting...":"Delete Permanently"}
                  </button>
                  </>:<div style={{padding:"6px 8px",fontSize:10,color:C.muted,display:"flex",alignItems:"center",gap:6}}>
                    {status==="deleted"?<><Trash2 size={12} color={C.muted}/> Already deleted</>:<><Lock size={12} color={C.muted}/> Managed mTLS (renew/rotate only)</>}
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

    <Modal open={modal==="acme-star"} onClose={()=>setModal(null)} title="ACME STAR Short-Lived Certificates" wide>
      <div style={{display:"grid",gap:10}}>
        <div style={{fontSize:11,color:C.dim,lineHeight:1.6}}>
          Create short-lived automatically renewed certificates for gateways, service mesh edges, and delegated subscribers. STAR subscriptions keep issuance cadence, rollout grouping, and delegated subscriber metadata under the tenant ACME policy.
        </div>
        <Row2>
          <FG label="Display Name"><Inp value={starName} onChange={(e)=>setStarName(e.target.value)} placeholder="mesh-gateway-star"/></FG>
          <FG label="ACME Account ID"><Inp value={starAccountID} onChange={(e)=>setStarAccountID(e.target.value)} placeholder="acct_ops_prod"/></FG>
        </Row2>
        <Row2>
          <FG label="Issuing CA" required>
            <Sel value={starCAID} onChange={(e)=>setStarCAID(e.target.value)}>
              <option value="">Select CA</option>
              {cas.map((c)=><option key={c.id} value={c.id}>{c.name} ({c.algorithm})</option>)}
            </Sel>
          </FG>
          <FG label="Profile">
            <Sel value={starProfileID} onChange={(e)=>setStarProfileID(e.target.value)}>
              <option value="">Default profile</option>
              {profiles.map((p)=><option key={p.id} value={p.id}>{p.name}</option>)}
            </Sel>
          </FG>
        </Row2>
        <Row2>
          <FG label="Subject CN" required><Inp value={starSubjectCN} onChange={(e)=>setStarSubjectCN(e.target.value)} placeholder="gateway.tenant.example"/></FG>
          <FG label="SANs (comma separated)"><Inp value={starSANs} onChange={(e)=>setStarSANs(e.target.value)} placeholder="gateway.tenant.example, api.tenant.example"/></FG>
        </Row2>
        <Row2>
          <FG label="Certificate Type">
            <Sel value={starCertType} onChange={(e)=>setStarCertType(e.target.value)}>
              <option value="tls-server">TLS Server</option>
              <option value="tls-client">TLS Client</option>
              <option value="tls-server-client">TLS Server + Client</option>
            </Sel>
          </FG>
          <FG label="Algorithm">
            <Sel value={starAlgorithm} onChange={(e)=>setStarAlgorithm(e.target.value)}>
              <option value="ECDSA-P256">ECDSA-P256</option>
              <option value="ECDSA-P384">ECDSA-P384</option>
              <option value="RSA-3072-SHA256">RSA-3072</option>
              <option value="RSA-4096-SHA384">RSA-4096</option>
            </Sel>
          </FG>
        </Row2>
        <Row2>
          <FG label="Validity (hours)"><Inp type="number" min={1} max={336} value={starValidityHours} onChange={(e)=>setStarValidityHours(e.target.value)}/></FG>
          <FG label="Renew Before (minutes)"><Inp type="number" min={5} max={1440} value={starRenewBeforeMinutes} onChange={(e)=>setStarRenewBeforeMinutes(e.target.value)}/></FG>
        </Row2>
        <Row2>
          <FG label="Rollout Group"><Inp value={starRolloutGroup} onChange={(e)=>setStarRolloutGroup(e.target.value)} placeholder="mesh-us-east-1"/></FG>
          <FG label="Delegated Subscriber"><Inp value={starDelegatedSubscriber} onChange={(e)=>setStarDelegatedSubscriber(e.target.value)} placeholder="spiffe://prod/ns/gateway/sa/edge" disabled={!starAllowDelegation}/></FG>
        </Row2>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
          <Chk label="Auto-renew subscription" checked={starAutoRenew} onChange={()=>setStarAutoRenew((v)=>!v)}/>
          <Chk label="Allow delegated subscriber" checked={starAllowDelegation} onChange={()=>setStarAllowDelegation((v)=>!v)}/>
        </div>
        <FG label="Metadata (JSON)">
          <Txt rows={6} value={starMetadataText} onChange={(e)=>setStarMetadataText(e.target.value)} />
        </FG>
        <div style={{fontSize:10,color:C.muted}}>
          REST: <span style={{fontFamily:"'JetBrains Mono', monospace"}}>/certs/star/summary</span>, <span style={{fontFamily:"'JetBrains Mono', monospace"}}>/certs/star/subscriptions</span>. ACME directory metadata also advertises STAR capability and default short-lived validity.
        </div>
        <div style={{display:"flex",justifyContent:"space-between",gap:8,alignItems:"flex-start"}}>
          <div style={{fontSize:10,color:C.dim,maxWidth:520}}>
            {starSummary?.enabled===false
              ?"Enable ACME STAR in the ACME protocol configuration before creating subscriptions."
              :"Use delegated subscribers when the certificate consumer should identify itself separately while KMS still controls renewal cadence and rollout safety."}
          </div>
          <div style={{display:"flex",gap:8}}>
            <Btn onClick={()=>setModal(null)} disabled={submitting}>Cancel</Btn>
            <Btn primary onClick={()=>void submitCreateSTARSubscription()} disabled={submitting||starSummary?.enabled===false}>{submitting?"Creating...":"Create STAR Subscription"}</Btn>
          </div>
        </div>
      </div>
    </Modal>

    {/* ── ACME Enrollment Wizard ── */}
    <Modal open={modal==="acme-wizard"} onClose={()=>setModal(null)} title="ACME Certificate Enrollment (RFC 8555)" wide>
      {(()=>{
        const activeCA=(Array.isArray(cas)?cas:[]).find((c)=>String(c.status||"").toLowerCase()==="active");
        return <>
          <div style={{fontSize:11,color:C.dim,marginBottom:12,lineHeight:1.6}}>
            Full ACME protocol flow: create account, create order with domain validation challenge,
            respond to challenge, and finalize to obtain a certificate. Nonce replay protection and
            rate limiting are enforced server-side.
          </div>
          <div style={{display:"grid",gap:8,marginBottom:12}}>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",gap:8}}>
              {["1. Account","2. Order","3. Challenge","4. Finalize"].map((step,i)=>
                <div key={i} style={{textAlign:"center",padding:"8px 4px",borderRadius:8,background:C.accentDim,border:`1px solid ${C.border}`}}>
                  <div style={{fontSize:10,fontWeight:700,color:C.accent}}>{step}</div>
                </div>
              )}
            </div>
          </div>
          {!activeCA?<div style={{fontSize:11,color:C.red,marginBottom:8}}>No active CA found. Create a CA first.</div>:null}
          <FG label="Account Email">
            <Inp placeholder="admin@example.com" w="100%" id="acme-wiz-email"/>
          </FG>
          <FG label="Domain (Subject CN)">
            <Inp placeholder="app.example.com" w="100%" id="acme-wiz-cn"/>
          </FG>
          <FG label="SANs (comma-separated)">
            <Inp placeholder="app.example.com, www.example.com" w="100%" id="acme-wiz-sans"/>
          </FG>
          <FG label="Challenge Type">
            <Sel id="acme-wiz-challenge" value="http-01" style={{width:"100%"}}>
              <option value="http-01">HTTP-01 (file-based)</option>
              <option value="dns-01">DNS-01 (TXT record)</option>
              <option value="tls-alpn-01">TLS-ALPN-01</option>
            </Sel>
          </FG>
          <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
            <Btn onClick={()=>setModal(null)}>Cancel</Btn>
            <Btn primary disabled={!activeCA||submitting} onClick={async()=>{
              if(!session||!activeCA)return;
              setSubmitting(true);
              try{
                const email=String((document.getElementById("acme-wiz-email") as any)?.value||"").trim()||`acme-${Date.now()}@example.com`;
                const cn=String((document.getElementById("acme-wiz-cn") as any)?.value||"").trim()||`acme-${Date.now()}.local`;
                const sansRaw=String((document.getElementById("acme-wiz-sans") as any)?.value||"").trim();
                const sans=sansRaw?sansRaw.split(",").map(s=>s.trim()).filter(Boolean):[cn];
                const account=await acmeNewAccount(session,email);
                onToast?.(`ACME account created: ${account.account_id}`);
                const order=await acmeNewOrder(session,{ca_id:activeCA.id,account_id:account.account_id,subject_cn:cn,sans});
                onToast?.(`ACME order created: ${order.order_id} (challenge: ${order.challenge_id})`);
                const info=await acmeChallengeInfo(session,order.challenge_id,order.order_id).catch(()=>null);
                if(info){
                  onToast?.(`Challenge token: ${info.token.substring(0,20)}... Instructions: ${info.instructions.substring(0,80)}...`);
                }
                await acmeChallengeComplete(session,order.challenge_id,order.order_id);
                onToast?.("Challenge validated successfully.");
                const cert=await acmeFinalize(session,order.order_id,"");
                onToast?.(`Certificate issued: ${cert.id} (${cert.subject_cn})`);
                await refresh();
                setModal(null);
              }catch(e){onToast?.(`ACME wizard failed: ${errMsg(e)}`);}
              finally{setSubmitting(false);}
            }}>{submitting?"Processing...":"Run Full ACME Flow"}</Btn>
          </div>
        </>;
      })()}
    </Modal>

    {/* ── EST Enrollment Wizard ── */}
    <Modal open={modal==="est-wizard"} onClose={()=>setModal(null)} title="EST Certificate Enrollment (RFC 7030)" wide>
      {(()=>{
        const activeCA=(Array.isArray(cas)?cas:[]).find((c)=>String(c.status||"").toLowerCase()==="active");
        return <>
          <div style={{fontSize:11,color:C.dim,marginBottom:12,lineHeight:1.6}}>
            EST (Enrollment over Secure Transport) is used for IoT device enrollment, re-enrollment,
            and server-side key generation. Supports mTLS, bearer, and basic auth modes.
            CSR attributes endpoint provides algorithm and profile guidance.
          </div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:12}}>
            <Card style={{padding:10}}>
              <div style={{fontSize:10,fontWeight:700,color:C.text,marginBottom:4}}>Simple Enroll</div>
              <div style={{fontSize:9,color:C.dim}}>Submit a CSR for certificate issuance</div>
            </Card>
            <Card style={{padding:10}}>
              <div style={{fontSize:10,fontWeight:700,color:C.text,marginBottom:4}}>Server Keygen</div>
              <div style={{fontSize:9,color:C.dim}}>Server generates key pair + certificate</div>
            </Card>
          </div>
          {!activeCA?<div style={{fontSize:11,color:C.red,marginBottom:8}}>No active CA found.</div>:null}
          <FG label="Subject CN">
            <Inp placeholder="device-001.iot.local" w="100%" id="est-wiz-cn"/>
          </FG>
          <FG label="SANs (comma-separated)">
            <Inp placeholder="device-001.iot.local" w="100%" id="est-wiz-sans"/>
          </FG>
          <FG label="Auth Method">
            <Sel id="est-wiz-auth" style={{width:"100%"}}>
              <option value="mtls">mTLS (default)</option>
              <option value="bearer">Bearer Token</option>
              <option value="basic">HTTP Basic</option>
            </Sel>
          </FG>
          <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
            <Btn onClick={()=>setModal(null)}>Cancel</Btn>
            <Btn small onClick={async()=>{
              if(!session)return;
              try{
                const attrs=await estCSRAttributes(session);
                onToast?.(`EST CSR Attributes - Algorithms: ${attrs.algorithms.join(", ")} | Profiles: ${attrs.profile_ids.length}`);
              }catch(e){onToast?.(`CSR attrs failed: ${errMsg(e)}`);}
            }}>Query CSR Attrs</Btn>
            <Btn primary disabled={!activeCA||submitting} onClick={async()=>{
              if(!session||!activeCA)return;
              setSubmitting(true);
              try{
                const cn=String((document.getElementById("est-wiz-cn") as any)?.value||"").trim()||`est-device-${Date.now()}.local`;
                const sansRaw=String((document.getElementById("est-wiz-sans") as any)?.value||"").trim();
                const sans=sansRaw?sansRaw.split(",").map(s=>s.trim()).filter(Boolean):[cn];
                const cert=await estServerKeygen(session,{ca_id:activeCA.id,subject_cn:cn,sans});
                onToast?.(`EST certificate issued: ${cert.id} (${cert.subject_cn})`);
                await refresh();
                setModal(null);
              }catch(e){onToast?.(`EST enrollment failed: ${errMsg(e)}`);}
              finally{setSubmitting(false);}
            }}>{submitting?"Enrolling...":"Server Keygen Enroll"}</Btn>
          </div>
        </>;
      })()}
    </Modal>

    {/* ── SCEP Enrollment Wizard ── */}
    <Modal open={modal==="scep-wizard"} onClose={()=>setModal(null)} title="SCEP Certificate Enrollment (RFC 8894)" wide>
      {(()=>{
        const activeCA=(Array.isArray(cas)?cas:[]).find((c)=>String(c.status||"").toLowerCase()==="active");
        return <>
          <div style={{fontSize:11,color:C.dim,marginBottom:12,lineHeight:1.6}}>
            SCEP (Simple Certificate Enrollment Protocol) is widely used for MDM and legacy device enrollment.
            Supports PKCSReq, RenewalReq, and UpdateReq message types. Full PKIMessage wire format
            is supported via the smallstep/scep library including PKCS#7 envelope encryption/decryption.
          </div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8,marginBottom:12}}>
            {[{t:"PKCSReq",d:"Initial enrollment"},{t:"RenewalReq",d:"Certificate renewal"},{t:"GetCert",d:"Retrieve by serial"}].map((op)=>
              <Card key={op.t} style={{padding:10}}>
                <div style={{fontSize:10,fontWeight:700,color:C.text}}>{op.t}</div>
                <div style={{fontSize:9,color:C.dim}}>{op.d}</div>
              </Card>
            )}
          </div>
          {!activeCA?<div style={{fontSize:11,color:C.red,marginBottom:8}}>No active CA found.</div>:null}
          <FG label="Message Type">
            <Sel id="scep-wiz-msgtype" style={{width:"100%"}}>
              <option value="pkcsreq">PKCSReq (Initial Enrollment)</option>
              <option value="renewalreq">RenewalReq (Renewal)</option>
              <option value="updatereq">UpdateReq (Key Update)</option>
            </Sel>
          </FG>
          <FG label="Challenge Password (if required)">
            <Inp placeholder="challenge-secret" w="100%" id="scep-wiz-pass" type="password"/>
          </FG>
          <FG label="Transaction ID">
            <Inp placeholder="auto-generated" w="100%" id="scep-wiz-txn"/>
          </FG>
          <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
            <Btn onClick={()=>setModal(null)}>Cancel</Btn>
            <Btn primary disabled={!activeCA||submitting} onClick={async()=>{
              if(!session||!activeCA)return;
              setSubmitting(true);
              try{
                const msgType=String((document.getElementById("scep-wiz-msgtype") as any)?.value||"pkcsreq");
                const challenge=String((document.getElementById("scep-wiz-pass") as any)?.value||"").trim();
                const txnId=String((document.getElementById("scep-wiz-txn") as any)?.value||"").trim()||`txn-${Date.now()}`;
                const cert=await scepEnroll(session,{
                  ca_id:activeCA.id,
                  message_type:msgType,
                  challenge_password:challenge,
                  transaction_id:txnId
                });
                onToast?.(`SCEP certificate issued: ${cert.id} (txn: ${txnId})`);
                await refresh();
                setModal(null);
              }catch(e){onToast?.(`SCEP enrollment failed: ${errMsg(e)}`);}
              finally{setSubmitting(false);}
            }}>{submitting?"Enrolling...":"Submit SCEP Request"}</Btn>
          </div>
        </>;
      })()}
    </Modal>

    {/* ── CMPv2 Request Wizard ── */}
    <Modal open={modal==="cmpv2-wizard"} onClose={()=>setModal(null)} title="CMPv2 PKI Request (RFC 4210)" wide>
      {(()=>{
        const activeCA=(Array.isArray(cas)?cas:[]).find((c)=>String(c.status||"").toLowerCase()==="active");
        return <>
          <div style={{fontSize:11,color:C.dim,marginBottom:12,lineHeight:1.6}}>
            CMPv2 (Certificate Management Protocol v2) supports enterprise PKI operations including
            initial registration (IR), certification request (CR), key update (KUR), and revocation (RR).
            Message protection and transaction tracking are enforced per policy. PKI confirmation endpoint
            provides formal acceptance acknowledgment.
          </div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",gap:8,marginBottom:12}}>
            {[{t:"IR",d:"Initial Registration"},{t:"CR",d:"Certification Request"},{t:"KUR",d:"Key Update"},{t:"RR",d:"Revocation"}].map((op)=>
              <Card key={op.t} style={{padding:10,textAlign:"center"}}>
                <div style={{fontSize:12,fontWeight:700,color:C.accent}}>{op.t}</div>
                <div style={{fontSize:9,color:C.dim}}>{op.d}</div>
              </Card>
            )}
          </div>
          {!activeCA?<div style={{fontSize:11,color:C.red,marginBottom:8}}>No active CA found.</div>:null}
          <FG label="Message Type">
            <Sel id="cmpv2-wiz-type" style={{width:"100%"}}>
              <option value="ir">IR -- Initial Registration (new cert)</option>
              <option value="cr">CR -- Certification Request (new cert)</option>
              <option value="kur">KUR -- Key Update Request (renewal)</option>
              <option value="rr">RR -- Revocation Request</option>
            </Sel>
          </FG>
          <FG label="Subject CN (for IR/CR)">
            <Inp placeholder="cmp-client.enterprise.local" w="100%" id="cmpv2-wiz-cn"/>
          </FG>
          <FG label="Cert ID (for KUR/RR)">
            <Inp placeholder="crt_..." w="100%" id="cmpv2-wiz-certid"/>
          </FG>
          <FG label="Transaction ID">
            <Inp placeholder="auto-generated" w="100%" id="cmpv2-wiz-txn"/>
          </FG>
          <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
            <Btn onClick={()=>setModal(null)}>Cancel</Btn>
            <Btn primary disabled={!activeCA||submitting} onClick={async()=>{
              if(!session||!activeCA)return;
              setSubmitting(true);
              try{
                const msgType=String((document.getElementById("cmpv2-wiz-type") as any)?.value||"ir") as "ir"|"cr"|"kur"|"rr";
                const cn=String((document.getElementById("cmpv2-wiz-cn") as any)?.value||"").trim()||`cmp-${Date.now()}.local`;
                const certId=String((document.getElementById("cmpv2-wiz-certid") as any)?.value||"").trim();
                const txnId=String((document.getElementById("cmpv2-wiz-txn") as any)?.value||"").trim()||`cmp-${Date.now()}`;
                const cert=await cmpv2Request(session,{
                  ca_id:activeCA.id,
                  message_type:msgType,
                  cert_id:certId,
                  transaction_id:txnId,
                  protected:true,
                  protection_alg:"pbm-sha256",
                  payload_json:(msgType==="ir"||msgType==="cr")?JSON.stringify({subject_cn:cn,sans:[cn],cert_type:"tls-client"}):""
                });
                onToast?.(`CMPv2 ${msgType.toUpperCase()} succeeded: ${cert.id}`);
                // Send PKI confirmation
                if(msgType==="ir"||msgType==="cr"){
                  try{
                    const confirm=await cmpv2Confirm(session,txnId,cert.id);
                    onToast?.(`PKI Confirm: ${confirm.status} - ${confirm.message}`);
                  }catch(e2){onToast?.(`PKI Confirm: ${errMsg(e2)}`);}
                }
                await refresh();
                setModal(null);
              }catch(e){onToast?.(`CMPv2 request failed: ${errMsg(e)}`);}
              finally{setSubmitting(false);}
            }}>{submitting?"Processing...":"Submit CMPv2 Request"}</Btn>
          </div>
        </>;
      })()}
    </Modal>
    {promptDialog.ui}
  </div>;
};
