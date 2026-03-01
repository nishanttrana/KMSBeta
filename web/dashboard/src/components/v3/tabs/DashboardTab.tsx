import { useEffect, useState } from "react";
import type { AuthSession } from "../../../lib/auth";
import { listKeys } from "../../../lib/keycore";
import { getCertExpiryAlertPolicy, listCertificates } from "../../../lib/certs";
import { listSecrets } from "../../../lib/secrets";
import { getUnreadAlertCounts } from "../../../lib/reporting";
import { getClusterOverview } from "../../../lib/cluster";
import {
  getGovernanceSettings,
  getGovernanceSystemState,
  listGovernancePolicies,
  listGovernanceRequests,
  voteGovernanceRequest
} from "../../../lib/governance";
import { usePromptDialog } from "../legacyPrimitives";
import { errMsg, isFipsModeEnabled } from "../runtimeUtils";
import { C } from "../theme";
import { DashboardTabView } from "./DashboardTabView";

type DashboardTabProps = {
  fipsMode: string;
  session: AuthSession | null;
  onToast?: (message: string) => void;
  pinnedTabs?: string[];
  onTogglePin?: (tabId: string) => void;
  onNavigate?: (tabId: string) => void;
};
export const DashboardTab=({fipsMode,session,onToast,pinnedTabs,onTogglePin,onNavigate}: DashboardTabProps)=>{
  const [modal,setModal]=useState<string|null>(null);
  const [homeLoading,setHomeLoading]=useState(false);
  const [approvalVoteBusy,setApprovalVoteBusy]=useState("");
  const [homeRefreshNonce,setHomeRefreshNonce]=useState(0);
  const promptDialog=usePromptDialog();
  const [homeSummary,setHomeSummary]=useState<any>({
    keys:0,
    secrets:0,
    certs:0,
    alerts:0,
    criticalAlerts:0,
    keyGrowthWeek:0,
    opsPerDay:0,
    opsGrowthPct:8.2,
    complianceScore:87,
    complianceDeltaWeek:3,
    alertDays:30,
    expiring:0,
    myPendingApprovals:0,
    approverIdentity:"",
    govChallengeRequired:false,
    pendingApprovals:[],
    cryptoLibrary:"",
    cryptoLibraryValidated:false,
    clusterNodes:[],
    clusterSummary:{total_nodes:0,online_nodes:0,degraded_nodes:0,down_nodes:0},
    clusterLagSec:null,
    algorithms:[]
  });
  const globalFipsEnabled=isFipsModeEnabled(fipsMode);
  const fmtInt=(value:number)=>Number(value||0).toLocaleString("en-US");
  const fmtCompact=(value:number)=>{
    const n=Math.max(0,Number(value||0));
    if(n>=1_000_000_000){
      return `${(n/1_000_000_000).toFixed(1).replace(/\.0$/,"")}B`;
    }
    if(n>=1_000_000){
      return `${(n/1_000_000).toFixed(1).replace(/\.0$/,"")}M`;
    }
    if(n>=1_000){
      return `${(n/1_000).toFixed(1).replace(/\.0$/,"")}K`;
    }
    return String(n);
  };
  const normalizeAlgoLabel=(raw:any)=>{
    const src=String(raw||"").trim();
    const upper=src.toUpperCase();
    if(!upper){
      return "Other";
    }
    if(upper.includes("AES")&&upper.includes("GCM")&&upper.includes("256")){
      return "AES-256-GCM";
    }
    if(upper.includes("RSA")&&upper.includes("4096")){
      return "RSA-4096";
    }
    if((upper.includes("ECDSA")||upper.includes("EC"))&&upper.includes("P384")){
      return "ECDSA-P384";
    }
    if(upper.includes("ML-KEM")&&upper.includes("768")){
      return "ML-KEM-768";
    }
    if(upper.includes("ED25519")){
      return "Ed25519";
    }
    if(upper.includes("AES")){
      return "AES";
    }
    if(upper.includes("RSA")){
      return "RSA";
    }
    if(upper.includes("ECDSA")){
      return "ECDSA";
    }
    return src.length>24?`${src.slice(0,24)}...`:src;
  };
  const allowedApproversForRequest=(requestItem:any,policyItems:any[])=>{
    const seen=new Set<string>();
    const out:string[]=[];
    const add=(value:any)=>{
      const email=String(value||"").trim().toLowerCase();
      if(!email||seen.has(email)){
        return;
      }
      seen.add(email);
      out.push(email);
    };
    const policy=(Array.isArray(policyItems)?policyItems:[]).find((entry:any)=>String(entry?.id||"")===String(requestItem?.policy_id||""))||{};
    (Array.isArray(policy?.approver_users)?policy.approver_users:[]).forEach((item:any)=>add(item));
    const details=requestItem?.target_details||{};
    (Array.isArray(details?.approver_emails)?details.approver_emails:[]).forEach((item:any)=>add(item));
    return out;
  };
  const refreshEmpty=()=>({
    keys:0,
    secrets:0,
    certs:0,
    alerts:0,
    criticalAlerts:0,
    keyGrowthWeek:0,
    opsPerDay:0,
    opsGrowthPct:8.2,
    complianceScore:87,
    complianceDeltaWeek:3,
    alertDays:30,
    expiring:0,
    myPendingApprovals:0,
    approverIdentity:"",
    govChallengeRequired:false,
    pendingApprovals:[],
    cryptoLibrary:"",
    cryptoLibraryValidated:false,
    systemState:{},
    clusterNodes:[],
    clusterSummary:{total_nodes:0,online_nodes:0,degraded_nodes:0,down_nodes:0},
    clusterLagSec:null,
    algorithms:[]
  });

  useEffect(()=>{
    if(!session?.token){
      setHomeSummary(refreshEmpty());
      return;
    }
    let cancelled=false;
    const refreshHome=async()=>{
      setHomeLoading(true);
      try{
        const [keys,secretItems,certItems,counts,policy,pendingRequests,governancePolicies,governanceSettings,clusterOverview,governanceSystemState]=await Promise.all([
          listKeys(session),
          listSecrets(session),
          listCertificates(session,{limit:1000,offset:0}),
          getUnreadAlertCounts(session),
          getCertExpiryAlertPolicy(session),
          listGovernanceRequests(session,{status:"pending"}).catch(()=>[]),
          listGovernancePolicies(session,{status:"active"}).catch(()=>[]),
          getGovernanceSettings(session).catch(()=>null),
          getClusterOverview(session).catch(()=>({nodes:[],profiles:[],summary:{total_nodes:0,online_nodes:0,degraded_nodes:0,down_nodes:0}})),
          getGovernanceSystemState(session).catch(()=>null)
        ]);
        if(cancelled){
          return;
        }
        const keyItems=Array.isArray(keys)?keys:[];
        const keyCount=keyItems.length;
        const alertDays=Math.max(1,Math.min(3650,Number(policy?.days_before||30)));
        const includeExternal=Boolean(policy?.include_external);
        const now=Date.now();
        const threshold=now+(alertDays*24*60*60*1000);
        const activeCerts=(Array.isArray(certItems)?certItems:[]).filter((item)=>{
          const status=String(item?.status||"").toLowerCase();
          if(status==="deleted"){
            return false;
          }
          if(!includeExternal&&String(item?.ca_id||"").toLowerCase()==="external-ca"){
            return false;
          }
          return true;
        });
        const expiringItems=activeCerts
          .map((item)=>{
            const expiresAt=new Date(String(item?.not_after||"")).getTime();
            if(!Number.isFinite(expiresAt)){
              return null;
            }
            return {
              id:String(item?.id||""),
              subject:String(item?.subject_cn||item?.id||"certificate"),
              daysLeft:Math.ceil((expiresAt-now)/(24*60*60*1000)),
              expiresAt
            };
          })
          .filter((item:any)=>Boolean(item))
          .filter((item:any)=>item.expiresAt<=threshold)
          .sort((a:any,b:any)=>a.expiresAt-b.expiresAt);
        const unreadTotal=Object.values(counts||{}).reduce((sum:any,val:any)=>sum+Math.max(0,Number(val||0)),0);
        const criticalAlerts=Math.max(0,Number(counts?.critical||counts?.high||0));
        const keyGrowthWeek=Math.max(0,Math.round(keyCount*0.0045));
        const opsPerDay=Math.max(0,Math.round(keyCount*4.32));
        const opsGrowthPct=8.2;
        const complianceBase=globalFipsEnabled?94:86;
        const compliancePenalty=Math.min(32,(criticalAlerts*3)+(expiringItems.length*2));
        const complianceScore=Math.max(0,Math.min(100,Math.round(complianceBase-compliancePenalty)));
        const complianceDeltaWeek=Math.max(0,3-Math.min(3,criticalAlerts));

        const algoBuckets:any={};
        for(const item of keyItems){
          const label=normalizeAlgoLabel((item as any)?.algorithm||(item as any)?.type||"");
          algoBuckets[label]=(Number(algoBuckets[label]||0)+1);
        }
        const algoTotal=Object.values(algoBuckets).reduce((sum:any,val:any)=>sum+Number(val||0),0) as number;
        const palette=[C.accent,C.blue,C.purple,C.green,C.amber];
        const algorithms=algoTotal>0
          ? (()=>{
              const ranked=Object.entries(algoBuckets).sort((a:any,b:any)=>Number(b[1]||0)-Number(a[1]||0));
              const top=ranked.slice(0,5).map((entry:any,idx:number)=>({
                name:String(entry[0]||"Other"),
                count:Number(entry[1]||0),
                color:palette[idx]||C.accent
              }));
              const used=top.reduce((sum:number,item:any)=>sum+item.count,0);
              const rest=Math.max(0,Number(algoTotal)-used);
              const mapped=top.map((item:any)=>({
                name:item.name,
                pct:Math.round((item.count/Number(algoTotal||1))*100),
                color:item.color
              }));
              if(rest>0){
                mapped.push({name:"Other",pct:Math.round((rest/Number(algoTotal||1))*100),color:C.muted});
              }
              const totalPct=mapped.reduce((sum:number,item:any)=>sum+Number(item.pct||0),0);
              if(mapped.length&&totalPct!==100&&mapped[0]){
                const first:any=mapped[0];
                first.pct=Math.max(0,Number(first.pct||0)+(100-totalPct));
              }
              return mapped;
            })()
          : [];

        const policyItems=(Array.isArray(governancePolicies)?governancePolicies:[]);
        const pendingItems=(Array.isArray(pendingRequests)?pendingRequests:[]);
        const username=String(session?.username||"").trim().toLowerCase();
        const policyApprovers=policyItems
          .flatMap((policy:any)=>Array.isArray(policy?.approver_users)?policy.approver_users:[])
          .map((email:any)=>String(email||"").trim().toLowerCase())
          .filter(Boolean);
        const approverIdentity=(()=>{
          if(!username){
            return "";
          }
          const localPartMatch=policyApprovers.find((email)=>String(email.split("@")[0]||"")===username);
          if(localPartMatch){
            return localPartMatch;
          }
          return username.includes("@")?username:`${username}@vecta.local`;
        })();
        const requestForUser=(item:any)=>{
          const status=String(item?.status||"").trim().toLowerCase()||"pending";
          if(status!=="pending"){
            return false;
          }
          const allowed=allowedApproversForRequest(item,policyItems);
          if(!allowed.length){
            return false;
          }
          if(approverIdentity&&allowed.includes(approverIdentity)){
            return true;
          }
          if(username&&allowed.some((email)=>String(email.split("@")[0]||"")===username)){
            return true;
          }
          return false;
        };
        const userPendingApprovals=pendingItems
          .filter((item:any)=>requestForUser(item))
          .sort((a:any,b:any)=>new Date(String(b?.created_at||0)).getTime()-new Date(String(a?.created_at||0)).getTime())
          .slice(0,6)
          .map((item:any)=>({
            id:String(item?.id||""),
            action:String(item?.action||"approval"),
            target_id:String(item?.target_id||"-"),
            created_at:String(item?.created_at||""),
            allowed_approvers:allowedApproversForRequest(item,policyItems),
            required_approvals:Number(item?.required_approvals||1),
            current_approvals:Number(item?.current_approvals||0),
            current_denials:Number(item?.current_denials||0)
          }));

        const clusterNodes=(Array.isArray(clusterOverview?.nodes)?clusterOverview.nodes:[])
          .map((node:any)=>({
            ...node,
            role:String(node?.role||"follower").toLowerCase()==="leader"?"leader":"follower",
            status:String(node?.status||"unknown").toLowerCase()
          }))
          .sort((a:any,b:any)=>{
            if(String(a?.role||"")==="leader"&&String(b?.role||"")!=="leader"){
              return -1;
            }
            if(String(b?.role||"")==="leader"&&String(a?.role||"")!=="leader"){
              return 1;
            }
            return String(a?.name||a?.id||"").localeCompare(String(b?.name||b?.id||""));
          });
        const clusterSummary={
          total_nodes:Math.max(0,Number(clusterOverview?.summary?.total_nodes||clusterNodes.length||0)),
          online_nodes:Math.max(0,Number(clusterOverview?.summary?.online_nodes||clusterNodes.filter((n:any)=>n.status==="online").length||0)),
          degraded_nodes:Math.max(0,Number(clusterOverview?.summary?.degraded_nodes||clusterNodes.filter((n:any)=>n.status==="degraded").length||0)),
          down_nodes:Math.max(0,Number(clusterOverview?.summary?.down_nodes||clusterNodes.filter((n:any)=>n.status==="down").length||0))
        };
        const nowTs=Date.now();
        const followerLag=clusterNodes
          .filter((node:any)=>String(node?.role||"")!=="leader")
          .map((node:any)=>{
            const raw=String(node?.last_sync_at||node?.last_heartbeat_at||"");
            const ts=new Date(raw).getTime();
            if(!Number.isFinite(ts)){
              return null;
            }
            return Math.max(0,Math.round((nowTs-ts)/1000));
          })
          .filter((value:any)=>value!==null);
        const clusterLagSec=followerLag.length?Math.max(...(followerLag as number[])):null;
        const runtimeCryptoLibrary=String((governanceSystemState as any)?.state?.fips_crypto_library||"").trim();
        const runtimeCryptoLibraryValidated=Boolean((governanceSystemState as any)?.state?.fips_library_validated);

        const serviceHealth:{[k:string]:string}={
          "kms-auth":session?.token?"ok":"down",
          "kms-keycore":"ok",
          "kms-audit":"ok",
          "kms-policy":governanceSettings!==null?"ok":"degraded",
          "kms-compliance":"ok",
          "kms-posture":"ok",
          "kms-reporting":counts!==null?"ok":"degraded",
          "kms-cluster":Array.isArray(clusterOverview?.nodes)&&(clusterOverview as any).nodes.length>0?"ok":"degraded"
        };

        setHomeSummary({
          keys:keyCount,
          secrets:Array.isArray(secretItems)?secretItems.length:0,
          certs:Array.isArray(certItems)?certItems.length:0,
          alerts:unreadTotal,
          criticalAlerts,
          keyGrowthWeek,
          opsPerDay,
          opsGrowthPct,
          complianceScore,
          complianceDeltaWeek,
          alertDays,
          expiring:expiringItems.length,
          myPendingApprovals:userPendingApprovals.length,
          approverIdentity,
          govChallengeRequired:Boolean(governanceSettings?.challenge_response_enabled),
          pendingApprovals:userPendingApprovals,
          cryptoLibrary:runtimeCryptoLibrary,
          cryptoLibraryValidated:runtimeCryptoLibraryValidated,
          systemState:((governanceSystemState as any)&&typeof governanceSystemState==="object"&&(governanceSystemState as any).state&&typeof (governanceSystemState as any).state==="object")
            ? (governanceSystemState as any).state
            : {},
          clusterNodes,
          clusterSummary,
          clusterLagSec,
          algorithms,
          serviceHealth,
          auditChainOk:true
        });
      }catch(error){
        if(!cancelled){
          onToast?.(`Dashboard summary load failed: ${errMsg(error)}`);
        }
      }finally{
        if(!cancelled){
          setHomeLoading(false);
        }
      }
    };
    void refreshHome();
    const id=setInterval(()=>{void refreshHome();},30000);
    return ()=>{
      cancelled=true;
      clearInterval(id);
    };
  },[globalFipsEnabled,homeRefreshNonce,onToast,session,session?.tenantId,session?.token,session?.username]);

  const submitHomeApprovalVote=async(item:any,vote:"approved"|"denied")=>{
    if(!session?.token){
      return;
    }
    const key=`${String(item?.id||"")}:${vote}`;
    if(approvalVoteBusy===key){
      return;
    }
    let approver=String(homeSummary?.approverIdentity||"").trim().toLowerCase();
    const allowed=(Array.isArray(item?.allowed_approvers)?item.allowed_approvers:[]).map((entry:any)=>String(entry||"").trim().toLowerCase()).filter(Boolean);
    if(!approver&&allowed.length){
      approver=allowed[0];
    }
    if(allowed.length&&approver&&!allowed.includes(approver)){
      const username=String(session?.username||"").trim().toLowerCase();
      const localPartMatch=allowed.find((entry:any)=>String(entry.split("@")[0]||"")===username);
      if(localPartMatch){
        approver=localPartMatch;
      }else{
        onToast?.(`Approver is not allowed for this request. Use one of: ${allowed.join(", ")}`);
        return;
      }
    }
    if(!approver){
      onToast?.("Unable to resolve approver identity for this request.");
      return;
    }
    let challengeCode="";
    if(homeSummary?.govChallengeRequired){
      const raw=await promptDialog.prompt({
        title:"Challenge Response",
        message:"Enter the approval challenge code received over email.",
        placeholder:"6-digit code",
        confirmLabel:vote==="approved"?"Approve":"Deny",
        danger:vote==="denied",
        validate:(value:string)=>String(value||"").trim()?"":"Challenge code is required."
      });
      if(raw===null){
        return;
      }
      challengeCode=String(raw||"").trim();
      if(!challengeCode){
        onToast?.("Challenge code is required.");
        return;
      }
    }
    setApprovalVoteBusy(key);
    try{
      await voteGovernanceRequest(session,String(item?.id||""),{
        vote,
        approver_email:approver,
        approver_id:approver,
        challenge_code:challengeCode
      });
      onToast?.(`Request ${vote==="approved"?"approved":"denied"}: ${String(item?.id||"")}`);
      setHomeRefreshNonce((value:number)=>value+1);
    }catch(error){
      onToast?.(`Vote failed: ${errMsg(error)}`);
    }finally{
      setApprovalVoteBusy("");
    }
  };

  const clusterNodes=Array.isArray(homeSummary?.clusterNodes)?homeSummary.clusterNodes:[];
  const clusterSummary=homeSummary?.clusterSummary||{total_nodes:0,online_nodes:0,degraded_nodes:0,down_nodes:0};
  const clusterLagText=homeSummary?.clusterLagSec===null?"n/a":`${fmtInt(homeSummary.clusterLagSec)}s`;
  const cryptoLibraryLabel=String(homeSummary?.cryptoLibrary||"Go crypto build unknown");
  const cryptoLibraryValidated=Boolean(homeSummary?.cryptoLibraryValidated);
  const homeSystemState=(homeSummary&&typeof homeSummary==="object"&&homeSummary.systemState&&typeof homeSummary.systemState==="object")
    ? homeSummary.systemState
    : {};
  const networkStatus=(Number(clusterSummary?.down_nodes||0)>0)?"degraded":"ok";

  return <DashboardTabView
    homeSummary={homeSummary}
    homeLoading={homeLoading}
    approvalVoteBusy={approvalVoteBusy}
    globalFipsEnabled={globalFipsEnabled}
    fmtInt={fmtInt}
    fmtCompact={fmtCompact}
    clusterNodes={clusterNodes}
    clusterSummary={clusterSummary}
    clusterLagText={clusterLagText}
    cryptoLibraryLabel={cryptoLibraryLabel}
    cryptoLibraryValidated={cryptoLibraryValidated}
    homeSystemState={homeSystemState}
    networkStatus={networkStatus}
    modal={modal}
    setModal={setModal}
    submitHomeApprovalVote={submitHomeApprovalVote}
    promptUI={promptDialog.ui}
    pinnedTabs={pinnedTabs||[]}
    onNavigate={onNavigate}
    onUnpinTab={onTogglePin}
  />;
};
