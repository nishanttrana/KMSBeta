import { useEffect, useState } from "react";
import type { AuthSession } from "../../../lib/auth";
import { getOverview } from "../../../lib/opsMetrics";
import { getKeyStats } from "../../../lib/keycore";
import { getCertExpiryAlertPolicy, getCertSummary } from "../../../lib/certs";
import { listSecrets } from "../../../lib/secrets";
import { getUnreadAlertCounts } from "../../../lib/reporting";
import { getClusterOverview } from "../../../lib/cluster";
import { getComplianceAssessment, listComplianceAssessmentHistory } from "../../../lib/compliance";
import {
  getGovernanceSettings,
  getGovernanceSystemState,
  listGovernancePolicies,
  listGovernanceRequests,
  voteGovernanceRequest
} from "../../../lib/governance";
import { windowFrom } from "../chartDrill";
import { usePromptDialog } from "../legacyPrimitives";
import { errMsg, isFipsModeEnabled } from "../runtimeUtils";
import { DashboardTabView } from "./DashboardTabView";
import { KeyInventoryPanel } from "./KeyInventoryPanel";
import { OpsMetricsPanel } from "./OpsMetricsPanel";

type DashboardTabProps = {
  fipsMode: string;
  session: AuthSession | null;
  onToast?: (message: string) => void;
  pinnedTabs?: string[];
  onTogglePin?: (tabId: string) => void;
  onNavigate?: (tabId: string) => void;
  // Opens a module with its page search set (Key Management on one key).
  onSearchIn?: (target: string, text: string) => void;
  // The sidebar sub-option: status, metrics or inventory (13.65.0-beta;
  // they were a tab strip in the page).
  subView?: string;
};

// Operations: Status, Operation metrics and Key inventory.
export const DashboardTab=(props: DashboardTabProps)=>{
  const {session,subView,onSearchIn}=props;
  if(!session) return null;
  if(subView==="metrics") return <OpsMetricsPanel session={session}/>;
  if(subView==="inventory") return <KeyInventoryPanel session={session} onOpenKey={(id)=>onSearchIn?.("keys",id)}/>;
  return <OpsStatus {...props}/>;
};

const OpsStatus=({fipsMode,session,onToast,pinnedTabs,onTogglePin,onNavigate}: DashboardTabProps)=>{
  const [homeLoading,setHomeLoading]=useState(false);
  const [approvalVoteBusy,setApprovalVoteBusy]=useState("");
  const [homeRefreshNonce,setHomeRefreshNonce]=useState(0);
  const promptDialog=usePromptDialog();
  const [homeSummary,setHomeSummary]=useState<any>({
    keys:null,
    secrets:null,
    certs:null,
    alerts:null,
    criticalAlerts:null,
    keyGrowthWeek:null,
    opsPerDay:null,
    opsWeekTotal:null,
    complianceScore:0,
    complianceDeltaWeek:0,
    complianceHasAssessment:false,
    alertDays:30,
    expiring:null,
    myPendingApprovals:0,
    approverIdentity:"",
    govChallengeRequired:false,
    pendingApprovals:[],
    cryptoLibrary:"",
    cryptoLibraryValidated:false,
    clusterNodes:[],
    clusterSummary:{total_nodes:0,online_nodes:0,degraded_nodes:0,down_nodes:0},
    clusterLagSec:null
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
  const isRealComplianceAssessment=(item:any)=>Boolean(item&&typeof item==="object"&&String(item?.id||"").trim()&&!/^auto$/i.test(String(item?.trigger||"").trim()));
  const refreshEmpty=()=>({
    keys:null,
    secrets:null,
    certs:null,
    alerts:null,
    criticalAlerts:null,
    keyGrowthWeek:null,
    opsPerDay:null,
    opsWeekTotal:null,
    complianceScore:0,
    complianceDeltaWeek:0,
    complianceHasAssessment:false,
    alertDays:30,
    expiring:null,
    myPendingApprovals:0,
    approverIdentity:"",
    govChallengeRequired:false,
    pendingApprovals:[],
    cryptoLibrary:"",
    cryptoLibraryValidated:false,
    systemState:{},
    clusterNodes:[],
    clusterSummary:{total_nodes:0,online_nodes:0,degraded_nodes:0,down_nodes:0},
    clusterLagSec:null
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
        const [keys,secretItems,certSummary,counts,policy,pendingRequests,governancePolicies,governanceSettings,clusterOverview,governanceSystemState,complianceAssessment,complianceHistory,opsDay,opsWeek]=await Promise.all([
          // A failed source is null and shows "unavailable", never 0. Keys
          // are counted by keycore, never over a list fetched here.
          getKeyStats(session,{from:windowFrom("7d")}).catch(()=>null),
          listSecrets(session).catch(()=>null),
          getCertSummary(session).catch(()=>null),
          getUnreadAlertCounts(session).catch(()=>null),
          getCertExpiryAlertPolicy(session).catch(()=>null),
          listGovernanceRequests(session,{status:"pending"}).catch(()=>[]),
          listGovernancePolicies(session,{status:"active"}).catch(()=>[]),
          getGovernanceSettings(session).catch(()=>null),
          getClusterOverview(session).catch(()=>null), // unavailable, not "0 nodes"
          getGovernanceSystemState(session).catch(()=>null),
          getComplianceAssessment(session,"default").catch(()=>null),
          listComplianceAssessmentHistory(session,2,"default").catch(()=>[]),
          getOverview(session,"24h").catch(()=>null), // unavailable, not 0
          getOverview(session,"7d").catch(()=>null)
        ]);
        if(cancelled){
          return;
        }
        // Certificate counts come from the certs service over every
        // certificate; counting a capped list here showed 500 (13.21.0-beta).
        const alertDays=certSummary?Math.max(1,Number(certSummary.alert_days||30)):Math.max(1,Math.min(3650,Number(policy?.days_before||30)));
        const unreadTotal=counts?Object.values(counts).reduce((sum:any,val:any)=>sum+Math.max(0,Number(val||0)),0):null;
        const criticalAlerts=counts?Math.max(0,Number(counts.critical||0)):null;
        const keyGrowthWeek=keys?keys.created:null;
        // Metered cryptographic operations (the Operation metrics tab's source).
        const opsPerDay=opsDay?Math.max(0,Number(opsDay.total_ops||0)):null;
        const opsWeekTotal=opsWeek?Math.max(0,Number(opsWeek.total_ops||0)):null;
        const complianceHistoryItems=(Array.isArray(complianceHistory)?complianceHistory:[]).filter((entry:any)=>isRealComplianceAssessment(entry));
        const latestComplianceAssessment=isRealComplianceAssessment(complianceAssessment)
          ? complianceAssessment
          : (complianceHistoryItems[0]||null);
        const complianceHasAssessment=Boolean(latestComplianceAssessment)||complianceHistoryItems.length>0;
        const complianceServiceScoreRaw=Number((latestComplianceAssessment as any)?.overall_score ?? (latestComplianceAssessment as any)?.posture?.overall_score);
        const complianceScore=complianceHasAssessment&&Number.isFinite(complianceServiceScoreRaw)
          ? Math.max(0,Math.min(100,Math.round(complianceServiceScoreRaw)))
          : 0;
        const complianceDeltaWeek=(()=>{
          if(!complianceHasAssessment){
            return 0;
          }
          const hist=complianceHistoryItems
            .filter((entry:any)=>entry&&typeof entry==="object")
            .slice()
            .sort((a:any,b:any)=>new Date(String(b?.created_at||b?.updated_at||0)).getTime()-new Date(String(a?.created_at||a?.updated_at||0)).getTime());
          if(hist.length<2){
            return 0;
          }
          const latest=Number(hist[0]?.overall_score);
          const previous=Number(hist[1]?.overall_score);
          if(!Number.isFinite(latest)||!Number.isFinite(previous)){
            return 0;
          }
          return Math.round(latest-previous);
        })();

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
          unavailable:!clusterOverview,
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


        setHomeSummary({
          keys:keys?keys.total:null,
          secrets:Array.isArray(secretItems)?secretItems.length:null,
          certs:certSummary?certSummary.total:null,
          alerts:unreadTotal,
          criticalAlerts,
          keyGrowthWeek,
          opsPerDay,
          opsWeekTotal,
          complianceScore,
          complianceDeltaWeek,
          complianceHasAssessment,
          alertDays,
          expiring:certSummary?certSummary.expiring:null,
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
          clusterLagSec
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
    submitHomeApprovalVote={submitHomeApprovalVote}
    promptUI={promptDialog.ui}
    pinnedTabs={pinnedTabs||[]}
    onNavigate={onNavigate}
    onUnpinTab={onTogglePin}
    />;
};
