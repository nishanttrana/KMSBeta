import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../../lib/auth";
import { deleteClusterProfile, getClusterOverview, removeClusterNode, updateClusterNodeRole, upsertClusterNode, upsertClusterProfile } from "../../../lib/cluster";
import { usePromptDialog } from "../legacyPrimitives";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { ClusterTabView } from "./ClusterTabView";

type ClusterTabProps = {
  session: AuthSession | null;
  onToast?: (message: string) => void;
  subView?: string;
};
const CLUSTER_COMPONENT_CHOICES=[
  {id:"auth",label:"Auth"},
  {id:"keycore",label:"KeyCore"},
  {id:"audit",label:"Audit"},
  {id:"policy",label:"Policy"},
  {id:"governance",label:"Gov"},
  {id:"payment",label:"Payment"},
  {id:"dataprotect",label:"DataProtect"},
  {id:"byok",label:"BYOK"},
  {id:"hyok",label:"HYOK"},
  {id:"ekm",label:"EKM"},
  {id:"kmip",label:"KMIP"},
  {id:"certs",label:"Certs"},
  {id:"secrets",label:"Secrets"},
  {id:"qkd",label:"QKD"},
  {id:"mpc",label:"MPC"}
];

const clusterComponentLabel=(value:string)=>{
  const key=String(value||"").trim().toLowerCase();
  const hit=CLUSTER_COMPONENT_CHOICES.find((item)=>item.id===key);
  if(hit){
    return hit.label;
  }
  const extraLabels:Record<string,string>={
    cluster:"Cluster",
    compliance:"Compliance",
    reporting:"Reporting",
    sbom:"SBOM",
    pqc:"PQC",
    discovery:"Discovery",
    ai:"AI",
    "software-vault":"Software Vault"
  };
  if(extraLabels[key]){
    return extraLabels[key];
  }
  if(key.startsWith("kms-")){
    return key
      .replace(/^kms-/,"")
      .split(/[-_]/g)
      .filter(Boolean)
      .map((part)=>part.charAt(0).toUpperCase()+part.slice(1))
      .join(" ");
  }
  return key
    .split(/[-_]/g)
    .filter(Boolean)
    .map((part)=>part.charAt(0).toUpperCase()+part.slice(1))
    .join(" ")||String(value||"");
};

export const ClusterTab=({session,onToast,subView}: ClusterTabProps)=>{
  const promptDialog=usePromptDialog();
  const [loading,setLoading]=useState(false);
  const [overview,setOverview]=useState<any>(null);
  const [profileName,setProfileName]=useState("");
  const [profileDescription,setProfileDescription]=useState("");
  const [profileComponents,setProfileComponents]=useState<string[]>(["auth","keycore","audit","policy","governance"]);
  const [profileDefault,setProfileDefault]=useState(false);
  const [savingProfile,setSavingProfile]=useState(false);
  const [directNodeForm,setDirectNodeForm]=useState<any>({
    node_id:"",
    node_name:"",
    endpoint:"",
    profile_id:"",
    role:"follower",
    components:["auth","keycore","policy","governance"],
    seed_sync:true
  });
  const [directNodeBusy,setDirectNodeBusy]=useState(false);
  const [roleDrafts,setRoleDrafts]=useState<Record<string,string>>({});
  const [roleUpdatingNode,setRoleUpdatingNode]=useState("");
  const [removeBusyNode,setRemoveBusyNode]=useState("");
  const clusterView=String(subView||"settings").trim().toLowerCase();

  const refresh=useCallback(async(silent=false)=>{
    if(!session?.token){
      setOverview(null);
      return;
    }
    if(!silent){
      setLoading(true);
    }
    try{
      const out=await getClusterOverview(session);
      setOverview(out||{nodes:[],profiles:[]});
      const profiles=Array.isArray(out?.profiles)?out.profiles:[];
      setDirectNodeForm((prev:any)=>{
        const profileCurrent=String(prev?.profile_id||"").trim();
        const defaultProfile=profiles.find((item:any)=>Boolean(item?.is_default))||profiles[0]||null;
        const nextProfile=profiles.find((item:any)=>String(item?.id||"").trim()===profileCurrent)||defaultProfile;
        const allowedComponents=(Array.isArray(nextProfile?.components)?nextProfile.components:[])
          .map((value:any)=>String(value||"").trim().toLowerCase())
          .filter(Boolean)
          .filter((value:string)=>value!=="audit");
        const requestedComponents=(Array.isArray(prev?.components)?prev.components:[])
          .map((value:any)=>String(value||"").trim().toLowerCase())
          .filter(Boolean);
        const mergedComponents=requestedComponents.length
          ? requestedComponents.filter((component:string)=>allowedComponents.includes(component))
          : allowedComponents;
        return {
          ...prev,
          profile_id:String(nextProfile?.id||""),
          components:mergedComponents.length?mergedComponents:allowedComponents
        };
      });
    }catch(error){
      onToast?.(`Cluster load failed: ${errMsg(error)}`);
    }finally{
      if(!silent){
        setLoading(false);
      }
    }
  },[onToast,session]);

  useEffect(()=>{
    if(!session?.token){
      setOverview(null);
      return;
    }
    void refresh(false);
  },[refresh,session?.tenantId,session?.token]);

  useEffect(()=>{
    if(!session?.token){
      return;
    }
    const timer=window.setInterval(()=>{
      void refresh(true);
    },10000);
    return ()=>window.clearInterval(timer);
  },[refresh,session?.tenantId,session?.token]);

  const nodes=Array.isArray(overview?.nodes)?overview.nodes:[];
  const profiles=Array.isArray(overview?.profiles)?overview.profiles:[];
  const summary=overview?.summary||{};
  const selectiveNote=String(overview?.selective_component_sync?.note||"Nodes sync only the state for their enabled components.");
  const profileComponentScope=(profileID:string)=>{
    const profile=profiles.find((item:any)=>String(item?.id||"").trim()===String(profileID||"").trim());
    return (Array.isArray(profile?.components)?profile.components:[])
      .map((value:any)=>String(value||"").trim().toLowerCase())
      .filter(Boolean)
      .filter((value:string)=>value!=="audit");
  };
  const toggleDirectComponent=(componentID:string)=>{
    const allowed=profileComponentScope(String(directNodeForm?.profile_id||""));
    if(!allowed.includes(componentID)){
      return;
    }
    setDirectNodeForm((prev:any)=>{
      const existing=(Array.isArray(prev?.components)?prev.components:[])
        .map((value:any)=>String(value||"").trim().toLowerCase())
        .filter(Boolean);
      if(existing.includes(componentID)){
        return {...prev,components:existing.filter((item:string)=>item!==componentID)};
      }
      return {...prev,components:[...existing,componentID]};
    });
  };
  const updateNodeRoleAction=async(node:any)=>{
    const nodeID=String(node?.id||"").trim();
    if(!session?.token||!nodeID){
      return;
    }
    const requestedRole=String(roleDrafts[nodeID]||node?.role||"follower").trim().toLowerCase()==="leader"?"leader":"follower";
    const currentRole=String(node?.role||"follower").trim().toLowerCase()==="leader"?"leader":"follower";
    if(requestedRole===currentRole){
      return;
    }
    setRoleUpdatingNode(nodeID);
    try{
      await updateClusterNodeRole(session,nodeID,requestedRole);
      await refresh(true);
      onToast?.(`Node role updated: ${nodeID} -> ${requestedRole}.`);
    }catch(error){
      onToast?.(`Role update failed: ${errMsg(error)}`);
    }finally{
      setRoleUpdatingNode("");
    }
  };
  const removeNodeAction=async(node:any)=>{
    const nodeID=String(node?.id||"").trim();
    const nodeName=String(node?.name||nodeID).trim();
    const isFollower=String(node?.role||"follower").trim().toLowerCase()!=="leader";
    if(!session?.token||!nodeID){
      return;
    }
    const warningMessage=isFollower
      ? `Warning: deleting follower "${nodeName}" will erase synced cluster data on that follower and convert it to standalone mode.`
      : `Warning: deleting node "${nodeName}" will erase synced cluster data on that node and convert it to standalone mode.`;
    onToast?.(warningMessage);
    const confirmed=await promptDialog.confirm({
      title:"Delete Cluster Node",
      message:`${warningMessage}\n\nContinue?`,
      confirmLabel:"Delete Node",
      cancelLabel:"Cancel",
      danger:true
    });
    if(!confirmed){
      return;
    }
    setRemoveBusyNode(nodeID);
    try{
      const result=await removeClusterNode(session,nodeID,{reason:"removed_from_cluster",purge_synced_data:true});
      await refresh(true);
      const promoted=String(result?.promoted_leader_node||"").trim();
      onToast?.(promoted
        ? `Node removed and standalone. New leader: ${promoted}.`
        : "Node removed from cluster and switched to standalone.");
    }catch(error){
      onToast?.(`Remove node failed: ${errMsg(error)}`);
    }finally{
      setRemoveBusyNode("");
    }
  };
  const addExistingNode=async()=>{
    if(!session?.token){
      onToast?.("Login is required to add a cluster node.");
      return;
    }
    const nodeID=String(directNodeForm?.node_id||"").trim();
    const profileID=String(directNodeForm?.profile_id||"").trim();
    if(!nodeID||!profileID){
      onToast?.("Node ID and replication profile are required.");
      return;
    }
    const allowed=profileComponentScope(profileID);
    const selected=(Array.isArray(directNodeForm?.components)?directNodeForm.components:[])
      .map((value:any)=>String(value||"").trim().toLowerCase())
      .filter((value:string)=>allowed.includes(value));
    setDirectNodeBusy(true);
    try{
      await upsertClusterNode(session,{
        node_id:nodeID,
        node_name:String(directNodeForm?.node_name||nodeID).trim(),
        endpoint:String(directNodeForm?.endpoint||"").trim(),
        role:String(directNodeForm?.role||"follower").trim().toLowerCase()==="leader"?"leader":"follower",
        profile_id:profileID,
        components:selected.length?selected:allowed,
        status:"unknown",
        join_state:"active",
        seed_sync:Boolean(directNodeForm?.seed_sync)
      });
      setDirectNodeForm((prev:any)=>({
        ...prev,
        node_id:"",
        node_name:"",
        endpoint:"",
        role:"follower",
        components:selected.length?selected:allowed
      }));
      await refresh(true);
      onToast?.("Existing KMS instance added to cluster.");
    }catch(error){
      onToast?.(`Add node failed: ${errMsg(error)}`);
    }finally{
      setDirectNodeBusy(false);
    }
  };

  const toggleProfileComponent=(componentID:string)=>{
    setProfileComponents((prev)=>{
      const exists=prev.includes(componentID);
      if(exists){
        return prev.filter((item)=>item!==componentID);
      }
      return [...prev,componentID];
    });
  };

  const saveProfile=async()=>{
    if(!session?.token){
      onToast?.("Login is required to update cluster profiles.");
      return;
    }
    if(!String(profileName||"").trim()){
      onToast?.("Profile name is required.");
      return;
    }
    if(!profileComponents.length){
      onToast?.("Select at least one component for replication profile.");
      return;
    }
    setSavingProfile(true);
    try{
      await upsertClusterProfile(session,{
        name:String(profileName).trim(),
        description:String(profileDescription||"").trim(),
        components:profileComponents,
        is_default:Boolean(profileDefault)
      });
      setProfileName("");
      setProfileDescription("");
      setProfileDefault(false);
      setProfileComponents(["auth","keycore","audit","policy","governance"]);
      await refresh(true);
      onToast?.("Cluster replication profile saved.");
    }catch(error){
      onToast?.(`Profile save failed: ${errMsg(error)}`);
    }finally{
      setSavingProfile(false);
    }
  };

  const removeProfile=async(profile:any)=>{
    const profileID=String(profile?.id||"").trim();
    if(!session?.token){
      return;
    }
    if(!profileID){
      return;
    }
    if(profile?.is_default){
      onToast?.("Default profile cannot be deleted.");
      return;
    }
    const confirmed=await promptDialog.confirm({
      title:"Delete Replication Profile",
      message:`Delete replication profile "${String(profile?.name||profileID)}"?`,
      confirmLabel:"Delete",
      cancelLabel:"Cancel",
      danger:true
    });
    if(!confirmed){
      return;
    }
    try{
      await deleteClusterProfile(session,profileID);
      await refresh(true);
      onToast?.("Cluster replication profile deleted.");
    }catch(error){
      onToast?.(`Delete profile failed: ${errMsg(error)}`);
    }
  };

  const statusMeta=(status:string)=>{
    const normalized=String(status||"").trim().toLowerCase();
    if(normalized==="online"){
      return {tone:"green",label:"Online",color:C.green,bg:C.greenDim,dotClass:"sync-dot sync-dot--online"};
    }
    if(normalized==="degraded"){
      return {tone:"amber",label:"Degraded",color:C.amber,bg:C.amberDim,dotClass:"sync-dot sync-dot--degraded"};
    }
    if(normalized==="down"){
      return {tone:"red",label:"Down",color:C.red,bg:C.redDim,dotClass:"sync-dot sync-dot--down"};
    }
    return {tone:"blue",label:"Unknown",color:C.blue,bg:C.blueDim,dotClass:"sync-dot sync-dot--unknown"};
  };
  const roleBadge=(role:string,status:string)=>{
    const leader=String(role||"").trim().toLowerCase()==="leader";
    const health=statusMeta(status);
    return <span style={{
      display:"inline-flex",
      alignItems:"center",
      gap:6,
      padding:"5px 10px",
      borderRadius:999,
      background:health.bg,
      color:health.color,
      border:leader?`1px solid ${C.accent}`:`1px solid transparent`,
      fontSize:10,
      fontWeight:700
    }}>
      <span className={health.dotClass} style={{width:6,height:6,borderRadius:999,background:health.color}}/>
      {leader?"Leader":"Follower"}
    </span>;
  };
  const strictRoleBadge=(role:string,status:string)=>{
    const leader=String(role||"").trim().toLowerCase()==="leader";
    const health=statusMeta(status);
    return <span style={{
      display:"inline-flex",
      alignItems:"center",
      gap:6,
      padding:"8px 12px",
      borderRadius:999,
      background:health.bg,
      color:health.color,
      border:leader?`1px solid ${C.accent}`:`1px solid transparent`,
      fontSize:11,
      fontWeight:700
    }}>
      <span className={health.dotClass} style={{width:6,height:6,borderRadius:999,background:health.color}}/>
      {leader?"Leader":"Follower"}
    </span>;
  };
  const nodeStatusColor=(status:string)=>{
    const normalized=String(status||"").trim().toLowerCase();
    if(normalized==="online"){
      return "green";
    }
    if(normalized==="degraded"){
      return "amber";
    }
    if(normalized==="down"){
      return "red";
    }
    return "blue";
  };

  return <>
    <ClusterTabView
      clusterView={clusterView}
      loading={loading}
      refresh={refresh}
      nodes={nodes}
      selectiveNote={selectiveNote}
      strictRoleBadge={strictRoleBadge}
      statusMeta={statusMeta}
      clusterComponentLabel={clusterComponentLabel}
      roleBadge={roleBadge}
      nodeStatusColor={nodeStatusColor}
      roleDrafts={roleDrafts}
      setRoleDrafts={setRoleDrafts}
      roleUpdatingNode={roleUpdatingNode}
      updateNodeRoleAction={updateNodeRoleAction}
      removeBusyNode={removeBusyNode}
      removeNodeAction={removeNodeAction}
      summary={summary}
      profileName={profileName}
      setProfileName={setProfileName}
      profileDescription={profileDescription}
      setProfileDescription={setProfileDescription}
      profileComponents={profileComponents}
      toggleProfileComponent={toggleProfileComponent}
      profileDefault={profileDefault}
      setProfileDefault={setProfileDefault}
      savingProfile={savingProfile}
      saveProfile={saveProfile}
      profiles={profiles}
      removeProfile={removeProfile}
      directNodeForm={directNodeForm}
      setDirectNodeForm={setDirectNodeForm}
      profileComponentScope={profileComponentScope}
      toggleDirectComponent={toggleDirectComponent}
      directNodeBusy={directNodeBusy}
      addExistingNode={addExistingNode}
      componentChoices={CLUSTER_COMPONENT_CHOICES}
    />
    {promptDialog.ui}
  </>;
};

