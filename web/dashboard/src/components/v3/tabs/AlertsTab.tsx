import { useCallback, useEffect, useMemo, useState } from "react";
import { Bell, Gauge, Radio as RadioIcon, RefreshCcw } from "lucide-react";
import type { AuthSession } from "../../../lib/auth";
import {
  acknowledgeAlertsBulk,
  acknowledgeAlert,
  escalateAlert,
  getReportingMTTR,
  listReportingAlerts,
  listReportingChannels
} from "../../../lib/reporting";
import { B, Btn, Card, Section, Sel, Tabs } from "../legacyPrimitives";
import { AlertAnalyticsPanel } from "./AlertAnalyticsPanel";
import { actionLabelForAlert, alertContext, alertHeadline, alertReason, formatAgo, isNoisyInfoAlert, summarizeAlertStats } from "./alertText";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";

type AlertsTabProps = {
  session: AuthSession | null;
  onToast?: (message: string) => void;
  onUnreadSync?: (count: number) => void;
};

export const AlertsTab=({session,onToast,onUnreadSync}: AlertsTabProps)=>{
  const [items,setItems]=useState<any[]>([]);
  const [stats,setStats]=useState<any>({total:0,by_severity:{},by_status:{}});
  const [mttr,setMTTR]=useState<Record<string,number>>({});
  const [channels,setChannels]=useState<any[]>([]);
  const [loading,setLoading]=useState(false);
  const [activeFilter,setActiveFilter]=useState("open");
  const [pageSize,setPageSize]=useState(10);
  const [pageIndex,setPageIndex]=useState(0);
  const [ackBusy,setAckBusy]=useState("");
  const [ackAllBusy,setAckAllBusy]=useState(false);
  const [escBusy,setEscBusy]=useState("");
  const [view,setView]=useState("Alerts");
  // Bumped after a triage action so Analytics reloads its counts.
  const [triaged,setTriaged]=useState(0);

  const refresh=useCallback(async(silent=false)=>{
    if(!session?.token){
      setItems([]);
      setStats({total:0,by_severity:{},by_status:{}});
      setMTTR({});
      setChannels([]);
      onUnreadSync?.(0);
      return;
    }
    if(!silent){
      setLoading(true);
    }
    try{
      const [alertsOut,mttrOut,channelsOut]=await Promise.all([
        listReportingAlerts(session,{limit:500,offset:0}),
        getReportingMTTR(session),
        listReportingChannels(session)
      ]);
      const visibleItems=(Array.isArray(alertsOut)?alertsOut:[]).filter((item:any)=>!isNoisyInfoAlert(item));
      setItems(visibleItems);
      setStats(summarizeAlertStats(visibleItems));
      setMTTR(mttrOut&&typeof mttrOut==="object"?mttrOut:{});
      setChannels(Array.isArray(channelsOut)?channelsOut:[]);
      const unread=Math.max(0,visibleItems.filter((item:any)=>String(item?.status||"").toLowerCase()==="new").length);
      onUnreadSync?.(unread);
    }catch(error){
      onToast?.(`Alerts load failed: ${errMsg(error)}`);
    }finally{
      if(!silent){
        setLoading(false);
      }
    }
  },[session,onToast,onUnreadSync]);

  useEffect(()=>{
    if(!session?.tenantId){
      setItems([]);
      return;
    }
    void refresh(false);
  },[session?.tenantId,session?.token,refresh]);

  useEffect(()=>{
    setPageIndex(0);
  },[activeFilter,pageSize]);

  const sortedItems=useMemo(()=>{
    const out=[...(Array.isArray(items)?items:[])];
    out.sort((a,b)=>new Date(String(b.created_at||b.updated_at||0)).getTime()-new Date(String(a.created_at||a.updated_at||0)).getTime());
    return out;
  },[items]);

  const openItems=useMemo(()=>sortedItems.filter((it)=>String(it.status||"").toLowerCase()==="new"),[sortedItems]);
  const criticalItems=useMemo(()=>openItems.filter((it)=>String(it.severity||"").toLowerCase()==="critical"),[openItems]);
  const highItems=useMemo(()=>openItems.filter((it)=>String(it.severity||"").toLowerCase()==="high"),[openItems]);
  const mediumItems=useMemo(()=>openItems.filter((it)=>{
    const sev=String(it.severity||"").toLowerCase();
    return sev==="warning"||sev==="medium";
  }),[openItems]);
  const resolvedItems=useMemo(()=>sortedItems.filter((it)=>{
    const st=String(it.status||"").toLowerCase();
    return st==="resolved"||st==="acknowledged";
  }),[sortedItems]);
  const suppressedItems=useMemo(()=>sortedItems.filter((it)=>String(it.status||"").toLowerCase()==="false_positive"),[sortedItems]);

  const filteredItems=useMemo(()=>{
    switch(activeFilter){
      case "critical": return criticalItems;
      case "high": return highItems;
      case "medium": return mediumItems;
      case "resolved": return resolvedItems;
      case "suppressed": return suppressedItems;
      case "open":
      default:
        return openItems;
    }
  },[activeFilter,criticalItems,highItems,mediumItems,openItems,resolvedItems,suppressedItems]);

  const totalPages=useMemo(()=>Math.max(1,Math.ceil(filteredItems.length/Math.max(1,pageSize))),[filteredItems.length,pageSize]);
  const currentPage=useMemo(()=>Math.min(Math.max(0,pageIndex),totalPages-1),[pageIndex,totalPages]);
  const pagedItems=useMemo(()=>{
    const start=currentPage*pageSize;
    return filteredItems.slice(start,start+pageSize);
  },[filteredItems,currentPage,pageSize]);

  useEffect(()=>{
    if(pageIndex>totalPages-1){
      setPageIndex(Math.max(0,totalPages-1));
    }
  },[pageIndex,totalPages]);

  const todayTotal=useMemo(()=>{
    const now=new Date();
    const y=now.getUTCFullYear();
    const m=now.getUTCMonth();
    const d=now.getUTCDate();
    return sortedItems.filter((it)=>{
      const ts=new Date(String(it.created_at||it.updated_at||0));
      return ts.getUTCFullYear()===y&&ts.getUTCMonth()===m&&ts.getUTCDate()===d;
    }).length;
  },[sortedItems]);

  const mttrAvg=useMemo(()=>{
    const vals=Object.values(mttr||{}).map((v)=>Number(v||0)).filter((v)=>Number.isFinite(v)&&v>0);
    if(!vals.length){
      return 0;
    }
    return vals.reduce((sum,val)=>sum+val,0)/vals.length;
  },[mttr]);

  const enabledChannels=useMemo(()=>{
    return (Array.isArray(channels)?channels:[]).filter((ch)=>Boolean(ch?.enabled));
  },[channels]);

  const alertCards=[
    {label:"Open",value:String(openItems.length),sub:`${criticalItems.length} crit / ${highItems.length} high`,tone:"red",icon:Bell},
    {label:"Critical",value:String(criticalItems.length),sub:criticalItems.length?"needs attention":"clear",tone:criticalItems.length?"red":"green",icon:Bell},
    {label:"Today",value:String(todayTotal),sub:stats?.total?`${Math.max(0,Math.round((resolvedItems.length/Math.max(1,stats.total))*100))}% triaged`:"audit events",tone:"accent",icon:Bell},
    {label:"MTTR",value:mttrAvg>0?`${(mttrAvg/60).toFixed(1)}h`:"—",sub:mttrAvg>0?`${Math.round(mttrAvg)}m avg`:"no data",tone:"green",icon:Gauge},
    {label:"Resolved",value:String(resolvedItems.length),sub:`${suppressedItems.length} suppressed`,tone:"green",icon:Bell},
    {label:"Channels",value:String(enabledChannels.length),sub:enabledChannels.length?enabledChannels.map((ch:any)=>String(ch.name||"")).slice(0,3).join(", "):"none",tone:"blue",icon:RadioIcon},
    {label:"Total",value:String(stats?.total||sortedItems.length),sub:`${Object.keys(stats?.by_severity||{}).length} severities`,tone:"accent",icon:Gauge},
  ];

  const filterTabs=[
    {id:"open",label:"All Open",count:openItems.length,tone:"accent"},
    {id:"critical",label:"Critical",count:criticalItems.length,tone:"red"},
    {id:"high",label:"High",count:highItems.length,tone:"amber"},
    {id:"medium",label:"Medium",count:mediumItems.length,tone:"blue"},
    {id:"resolved",label:"Resolved",count:resolvedItems.length,tone:"green"},
    {id:"suppressed",label:"Suppressed",count:suppressedItems.length,tone:"purple"}
  ];

  const severityTone=(severity:string)=>{
    const sev=String(severity||"").toLowerCase();
    if(sev==="critical") return "red";
    if(sev==="high") return "amber";
    if(sev==="warning"||sev==="medium") return "blue";
    return "green";
  };

  const ackAlert=async(item:any)=>{
    if(!session?.token){
      return;
    }
    const alertID=String(item?.id||"");
    if(!alertID){
      return;
    }
    setAckBusy(alertID);
    try{
      await acknowledgeAlert(session,alertID);
      onToast?.("Alert acknowledged.");
      setTriaged((n)=>n+1);
      await refresh(true);
    }catch(error){
      onToast?.(`Acknowledge failed: ${errMsg(error)}`);
    }finally{
      setAckBusy("");
    }
  };

  const ackAllAlerts=async()=>{
    if(!session?.token){
      return;
    }
    const ids=(Array.isArray(openItems)?openItems:[])
      .map((item:any)=>String(item?.id||"").trim())
      .filter(Boolean);
    if(!ids.length){
      onToast?.("No open alerts to acknowledge.");
      return;
    }
    setAckAllBusy(true);
    try{
      const updated=await acknowledgeAlertsBulk(session,{ids});
      onToast?.(`Acknowledged ${updated} alert${updated===1?"":"s"}.`);
      setTriaged((n)=>n+1);
      await refresh(true);
    }catch(error){
      onToast?.(`Acknowledge all failed: ${errMsg(error)}`);
    }finally{
      setAckAllBusy(false);
    }
  };

  const escalateOne=async(item:any)=>{
    if(!session?.token){
      return;
    }
    const alertID=String(item?.id||"");
    if(!alertID){
      return;
    }
    setEscBusy(alertID);
    try{
      await escalateAlert(session,alertID,"critical");
      onToast?.("Alert escalated to critical.");
      setTriaged((n)=>n+1);
      await refresh(true);
    }catch(error){
      onToast?.(`Escalation failed: ${errMsg(error)}`);
    }finally{
      setEscBusy("");
    }
  };

  const palette=C as Record<string,string>;

  const renderAlertCard=(item:any)=>{
    const sev=String(item?.severity||"info").toLowerCase();
    const status=String(item?.status||"new").toLowerCase();
    const tone=severityTone(sev);
    const canAck=status==="new";
    const canEscalate=status==="new"&&sev!=="critical";
    const actionLabel=actionLabelForAlert(item);
    return <Card key={String(item?.id||"")} style={{padding:"12px 14px"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:10}}>
        <div style={{minWidth:0,flex:1}}>
          <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4,flexWrap:"wrap"}}>
            <B c={tone}>{sev.toUpperCase()}</B>
            <div style={{fontSize:13,color:C.text,fontWeight:700,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{alertHeadline(item)}</div>
          </div>
          <div style={{fontSize:10,color:C.muted,marginBottom:4}}>{`Alert For: ${actionLabel}`}</div>
          <div style={{fontSize:11,color:C.dim,marginBottom:5}}>{alertReason(item)}</div>
          <div style={{fontSize:9,color:C.muted}}>
            {alertContext(item)}
          </div>
        </div>
        <div style={{display:"flex",flexDirection:"column",alignItems:"flex-end",gap:6,minWidth:170}}>
          <div style={{fontSize:10,color:C.muted}}>{formatAgo(String(item?.created_at||item?.updated_at||""))}</div>
          <div style={{display:"flex",gap:6,flexWrap:"wrap",justifyContent:"flex-end"}}>
            {canAck?<Btn small onClick={()=>void ackAlert(item)} disabled={ackBusy===String(item?.id||"")||escBusy===String(item?.id||"")} style={{height:30}}>{ackBusy===String(item?.id||"")?"Ack...":"Acknowledge"}</Btn>:null}
            {canEscalate?<Btn small danger onClick={()=>void escalateOne(item)} disabled={escBusy===String(item?.id||"")||ackBusy===String(item?.id||"")} style={{height:30}}>{escBusy===String(item?.id||"")?"Esc...":"Escalate"}</Btn>:null}
            {!canAck&&!canEscalate?<B c={status==="resolved"||status==="acknowledged"?"green":status==="false_positive"?"purple":"blue"}>{status}</B>:null}
          </div>
        </div>
      </div>
    </Card>;
  };

  return <div>
    <Tabs tabs={["Alerts","Analytics"]} active={view} onChange={setView}/>
    {view==="Analytics"&&session?<AlertAnalyticsPanel session={session} refreshKey={triaged} renderAlert={renderAlertCard}/>:null}
    {view==="Alerts"&&<>
    <div style={{display:"grid",gridTemplateColumns:"repeat(7,1fr)",gap:6,marginBottom:10}}>
      {alertCards.map((card)=><Card key={card.label} style={{padding:"8px 10px"}}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <div style={{fontSize:8,color:C.muted,textTransform:"uppercase",letterSpacing:.8,fontWeight:600}}>{card.label}</div>
          <card.icon size={11} strokeWidth={2} color={palette[card.tone]||C.dim}/>
        </div>
        <div style={{fontSize:18,fontWeight:700,letterSpacing:-.3,color:palette[card.tone]||C.accent,marginTop:2,lineHeight:1.1}}>{card.value}</div>
        <div style={{fontSize:9,color:C.dim,marginTop:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{card.sub}</div>
      </Card>)}
    </div>

    <Section
      title="Alert Center"
      actions={<div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
        <Btn small onClick={()=>void refresh(false)}><RefreshCcw size={12}/>{loading?"Refreshing...":"Refresh"}</Btn>
        <Btn
          small
          onClick={()=>void ackAllAlerts()}
          disabled={ackAllBusy||!openItems.length||loading}
        >
          {ackAllBusy?"Ack All...":"Acknowledge All"}
        </Btn>
      </div>}
    >
      <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:10}}>
        {filterTabs.map((tab)=><Btn
          key={tab.id}
          small
          onClick={()=>setActiveFilter(tab.id)}
          style={{
            background:activeFilter===tab.id?(palette[`${tab.tone}Dim`]||C.accentDim):"transparent",
            color:activeFilter===tab.id?(palette[tab.tone]||C.accent):C.text,
            borderColor:activeFilter===tab.id?(palette[tab.tone]||C.accent):C.border,
            height:28
          }}
        >{`${tab.label} (${tab.count})`}</Btn>)}
      </div>

      <div style={{display:"grid",gap:8}}>
        {pagedItems.map(renderAlertCard)}
        {!pagedItems.length&&!loading?<Card><div style={{fontSize:10,color:C.muted}}>No alerts found for current filter.</div></Card>:null}
      </div>

      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:10,marginTop:10,flexWrap:"wrap"}}>
        <div style={{display:"flex",alignItems:"center",gap:8,fontSize:10,color:C.dim}}>
          <span>Rows per page</span>
          <Sel w={92} value={String(pageSize)} onChange={(e)=>setPageSize(Number(e.target.value||10))}>
            <option value="10">10</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </Sel>
          <span>{filteredItems.length?`${currentPage*pageSize+1}-${Math.min((currentPage+1)*pageSize,filteredItems.length)} of ${filteredItems.length}`:`0 of 0`}</span>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:8}}>
          <Btn small onClick={()=>setPageIndex((prev)=>Math.max(0,prev-1))} disabled={currentPage<=0}>Prev</Btn>
          <div style={{fontSize:10,color:C.text,minWidth:74,textAlign:"center"}}>{`Page ${currentPage+1} / ${totalPages}`}</div>
          <Btn small onClick={()=>setPageIndex((prev)=>Math.min(totalPages-1,prev+1))} disabled={currentPage>=totalPages-1}>Next</Btn>
        </div>
      </div>
    </Section>
    </>}
  </div>;
};

