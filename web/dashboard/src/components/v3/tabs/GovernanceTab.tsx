// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import { Btn, Card, Inp, Sel, usePromptDialog } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import { getGovernanceSettings, listGovernancePolicies, listGovernanceRequests, voteGovernanceRequest } from "../../../lib/governance";

function tone(status:string){
  const s=String(status||"").toLowerCase();
  if(s==="approved"||s==="active") return C.green;
  if(s==="denied"||s==="rejected"||s==="failed") return C.red;
  if(s==="pending") return C.amber;
  return C.dim;
}

export const GovernanceTab=({session,onToast}:any)=>{
  const [loading,setLoading]=useState(false);
  const [status,setStatus]=useState("pending");
  const [policies,setPolicies]=useState<any[]>([]);
  const [requests,setRequests]=useState<any[]>([]);
  const [settings,setSettings]=useState<any>(null);
  const [voteBusy,setVoteBusy]=useState("");
  const [filter,setFilter]=useState("");
  const [approver,setApprover]=useState("");
  const prompt=usePromptDialog();

  const refresh=async()=>{
    if(!session?.token) return;
    setLoading(true);
    try{
      const [p,r,s]=await Promise.all([
        listGovernancePolicies(session,{status:"active"}).catch(()=>[]),
        listGovernanceRequests(session,{status}).catch(()=>[]),
        getGovernanceSettings(session).catch(()=>null)
      ]);
      setPolicies(Array.isArray(p)?p:[]);
      setRequests(Array.isArray(r)?r:[]);
      setSettings(s||null);
      if(!approver){
        const u=String(session?.username||"").trim().toLowerCase();
        setApprover(u.includes("@")?u:(u?`${u}@vecta.local`:""));
      }
    }catch(error:any){
      onToast?.(`Governance load failed: ${errMsg(error)}`);
    }finally{
      setLoading(false);
    }
  };

  useEffect(()=>{ void refresh(); },[session?.token,status]);

  const items=useMemo(()=>{
    const q=String(filter||"").trim().toLowerCase();
    const src=Array.isArray(requests)?requests:[];
    if(!q) return src;
    return src.filter((r:any)=>{
      const hay=[r?.id,r?.action,r?.target_type,r?.target_id,r?.status,r?.requester_email].map((v)=>String(v||"").toLowerCase()).join(" ");
      return hay.includes(q);
    });
  },[requests,filter]);

  const doVote=async(row:any,vote:"approved"|"denied")=>{
    if(!session?.token) return;
    const id=String(row?.id||"");
    if(!id) return;
    let challenge="";
    if(Boolean(settings?.challenge_response_enabled)){
      const entered=await prompt.prompt({title:"Challenge Response",message:"Enter governance challenge code",placeholder:"6-digit code",confirmLabel:vote==="approved"?"Approve":"Deny",danger:vote==="denied",validate:(v:string)=>String(v||"").trim()?"":"Challenge code is required."});
      if(entered===null) return;
      challenge=String(entered||"").trim();
      if(!challenge) return;
    }
    setVoteBusy(`${id}:${vote}`);
    try{
      await voteGovernanceRequest(session,id,{vote,approver_email:String(approver||"").trim(),approver_id:String(approver||"").trim(),challenge_code:challenge});
      onToast?.(`Request ${id} ${vote}.`);
      await refresh();
    }catch(error:any){
      onToast?.(`Vote failed: ${errMsg(error)}`);
    }finally{
      setVoteBusy("");
    }
  };

  return <div style={{display:"grid",gap:12}}>
    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8,flexWrap:"wrap"}}>
      <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
        <BCard label="Policies" value={String((policies||[]).length)} />
        <BCard label="Requests" value={String((requests||[]).length)} />
        <BCard label="Mode" value={String(settings?.approval_delivery_mode||"notify")} />
      </div>
      <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
        <Sel value={status} onChange={(e)=>setStatus(String(e.target.value||"pending"))} style={{width:140}}>
          <option value="pending">Pending</option>
          <option value="approved">Approved</option>
          <option value="denied">Denied</option>
          <option value="expired">Expired</option>
          <option value="all">All</option>
        </Sel>
        <Inp value={filter} onChange={(e)=>setFilter(e.target.value)} placeholder="Search requests" style={{width:220}}/>
        <Inp value={approver} onChange={(e)=>setApprover(e.target.value)} placeholder="Approver email" style={{width:220}}/>
        <Btn small onClick={()=>void refresh()} disabled={loading}>{loading?"Refreshing...":"Refresh"}</Btn>
      </div>
    </div>

    <Card>
      <div style={{display:"grid",gridTemplateColumns:"1fr",gap:8}}>
        {(items||[]).map((r:any)=>{
          const id=String(r?.id||"");
          const st=String(r?.status||"pending");
          const pending=st.toLowerCase()==="pending";
          return <div key={id} style={{display:"grid",gridTemplateColumns:"1.2fr 0.8fr 0.8fr 0.8fr auto",gap:8,alignItems:"center",borderBottom:`1px solid ${C.border}`,padding:"8px 0"}}>
            <div style={{minWidth:0}}>
              <div style={{fontSize:12,color:C.text,fontWeight:700,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{String(r?.action||"action")} | {String(r?.target_type||"target")} | {String(r?.target_id||"-")}</div>
              <div style={{fontSize:10,color:C.dim,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{id} | requester: {String(r?.requester_email||r?.requester_id||"-")} | {String(r?.created_at||"")}</div>
            </div>
            <div style={{fontSize:11,color:C.text}}>{Number(r?.required_approvals||0)} req</div>
            <div style={{fontSize:11,color:C.text}}>{Number(r?.current_approvals||0)} appr</div>
            <div style={{fontSize:11,color:tone(st),fontWeight:700}}>{st}</div>
            <div style={{display:"flex",gap:6,justifyContent:"flex-end"}}>
              <Btn small primary disabled={!pending||voteBusy===`${id}:approved`} onClick={()=>void doVote(r,"approved")}>Approve</Btn>
              <Btn small danger disabled={!pending||voteBusy===`${id}:denied`} onClick={()=>void doVote(r,"denied")}>Deny</Btn>
            </div>
          </div>;
        })}
        {!items.length?<div style={{fontSize:11,color:C.dim}}>No governance requests for selected filter.</div>:null}
      </div>
    </Card>
    {prompt.ui}
  </div>;
};

const BCard=({label,value}:{label:string;value:string})=><div style={{border:`1px solid ${C.border}`,borderRadius:8,padding:"8px 10px",background:C.surface}}><div style={{fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>{label}</div><div style={{fontSize:14,color:C.text,fontWeight:800,marginTop:2}}>{value}</div></div>;
