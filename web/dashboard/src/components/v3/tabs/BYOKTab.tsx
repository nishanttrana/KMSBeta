// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import { LayoutGrid, List, MoreVertical, RefreshCcw } from "lucide-react";
import {
  deleteCloudAccount,
  discoverCloudInventory,
  importKeyToCloud,
  listCloudAccounts,
  listCloudBindings,
  normalizeCloudProvider,
  registerCloudAccount,
  rotateCloudBinding,
  syncCloudKeys,
  type CloudAccount,
  type DeleteCloudAccountResult,
  type CloudKeyBinding,
  type CloudProvider,
  type CloudSyncJob
} from "../../../lib/cloud";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Btn, Card, FG, Inp, Modal, Row2, Section, Sel, Txt, usePromptDialog } from "../legacyPrimitives";

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

function formatAgo(value: string): string {
  const raw = String(value || "").trim();
  if (!raw) {
    return "-";
  }
  const ts = new Date(raw).getTime();
  if (!Number.isFinite(ts)) {
    return raw;
  }
  const diffMs = Date.now() - ts;
  if (diffMs < 30_000) {
    return "now";
  }
  const sec = Math.floor(diffMs / 1000);
  if (sec < 60) {
    return `${sec}s ago`;
  }
  const min = Math.floor(sec / 60);
  if (min < 60) {
    return `${min}m ago`;
  }
  const hr = Math.floor(min / 60);
  if (hr < 24) {
    return `${hr}h ago`;
  }
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}
const CLOUD_PROVIDER_LABELS={aws:"AWS KMS",azure:"Azure Key Vault",gcp:"Google Cloud KMS",oci:"Oracle Cloud Vault",salesforce:"Salesforce BYOK"};
const CLOUD_PROVIDER_ORDER=["aws","azure","gcp","oci","salesforce"];

export const BYOKTab=({session,keyCatalog,onToast})=>{
  const [modal,setModal]=useState<null|"add"|"import">(null);
  const [accounts,setAccounts]=useState<CloudAccount[]>([]);
  const [bindings,setBindings]=useState<CloudKeyBinding[]>([]);
  const [inventoryCounts,setInventoryCounts]=useState<Record<string,number>>({});
  const [accountProbeByID,setAccountProbeByID]=useState<Record<string,boolean>>({});
  const [accountProbeErrorByID,setAccountProbeErrorByID]=useState<Record<string,string>>({});
  const [recentOps,setRecentOps]=useState<Array<{id:string;label:string;status:string;detail:string;ts:string}>>([]);
  const [loading,setLoading]=useState(false);
  const [refreshing,setRefreshing]=useState(false);
  const [syncingAccount,setSyncingAccount]=useState("");
  const [deletingAccount,setDeletingAccount]=useState("");
  const [rotatingBinding,setRotatingBinding]=useState("");
  const [submittingAdd,setSubmittingAdd]=useState(false);
  const [submittingImport,setSubmittingImport]=useState(false);
  const [connectorView,setConnectorView]=useState<"cards"|"list">("cards");
  const [connectorSearch,setConnectorSearch]=useState("");
  const [connectorMenu,setConnectorMenu]=useState("");

  const [addProvider,setAddProvider]=useState<CloudProvider>("aws");
  const [addName,setAddName]=useState("");
  const [addDefaultRegion,setAddDefaultRegion]=useState("");
  const [addCredsJSON,setAddCredsJSON]=useState("{\n  \"access_key_id\": \"\",\n  \"secret_access_key\": \"\",\n  \"region\": \"us-east-1\"\n}");

  const [importProvider,setImportProvider]=useState<CloudProvider>("aws");
  const [importAccountID,setImportAccountID]=useState("");
  const [importKeyID,setImportKeyID]=useState("");
  const [importCloudRegion,setImportCloudRegion]=useState("");
  const [importAlias,setImportAlias]=useState("");
  const promptDialog=usePromptDialog();

  const keyChoices=useMemo(()=>keyChoicesFromCatalog(keyCatalog),[keyCatalog]);

  const addRecentOp=(label:string,status:string,detail:string)=>{
    const item={
      id:`op_${Date.now()}_${Math.random().toString(16).slice(2,8)}`,
      label:String(label||""),
      status:String(status||"info"),
      detail:String(detail||""),
      ts:new Date().toISOString()
    };
    setRecentOps((prev)=>[item,...prev].slice(0,24));
  };

  const refresh=async(silent=false)=>{
    if(!session?.token){
      setAccounts([]);
      setBindings([]);
      setInventoryCounts({});
      setAccountProbeByID({});
      setAccountProbeErrorByID({});
      return;
    }
    if(!silent){
      setRefreshing(true);
    }
    try{
      const [acctItems,bindingItems]=await Promise.all([
        listCloudAccounts(session),
        listCloudBindings(session,{limit:500,offset:0})
      ]);
      setAccounts(Array.isArray(acctItems)?acctItems:[]);
      setBindings(Array.isArray(bindingItems)?bindingItems:[]);
      const counts:Record<string,number>={};
      const probe:Record<string,boolean>={};
      const probeErr:Record<string,string>={};
      await Promise.all((Array.isArray(acctItems)?acctItems:[]).map(async(acct)=>{
        try{
          const items=await discoverCloudInventory(session,{
            provider:(acct.provider as CloudProvider),
            accountId:acct.id
          });
          counts[acct.id]=Array.isArray(items)?items.length:0;
          probe[acct.id]=true;
          probeErr[acct.id]="";
        }catch(error){
          counts[acct.id]=0;
          probe[acct.id]=false;
          probeErr[acct.id]=errMsg(error);
        }
      }));
      setInventoryCounts(counts);
      setAccountProbeByID(probe);
      setAccountProbeErrorByID(probeErr);
    }catch(error){
      onToast?.(`BYOK refresh failed: ${errMsg(error)}`);
    }finally{
      if(!silent){
        setRefreshing(false);
      }
    }
  };

  useEffect(()=>{
    if(!session?.token){
      return;
    }
    setLoading(true);
    void refresh(true).finally(()=>setLoading(false));
  },[session?.token,session?.tenantId]);

  useEffect(()=>{
    if(!modal){
      return;
    }
    if(modal==="import"){
      const firstAccount=(Array.isArray(accounts)?accounts:[])[0];
      if(firstAccount){
        setImportProvider((firstAccount.provider as CloudProvider)||"aws");
        setImportAccountID(firstAccount.id||"");
        setImportCloudRegion(String(firstAccount.default_region||""));
      }else{
        setImportProvider("aws");
        setImportAccountID("");
      }
      const firstKey=(Array.isArray(keyChoices)?keyChoices:[])[0];
      setImportKeyID(firstKey?.id||"");
    }
  },[modal,accounts,keyChoices]);

  const providerCards=useMemo(()=>{
    const availableProviders=Array.from(new Set((Array.isArray(accounts)?accounts:[]).map((acct)=>String(acct.provider||"").toLowerCase()).filter(Boolean)));
    const orderedProviders=CLOUD_PROVIDER_ORDER.filter((provider)=>availableProviders.includes(provider));
    return orderedProviders.map((provider)=>{
      const acctList=(Array.isArray(accounts)?accounts:[]).filter((acct)=>String(acct.provider||"").toLowerCase()===provider);
      const bindingList=(Array.isArray(bindings)?bindings:[]).filter((binding)=>String(binding.provider||"").toLowerCase()===provider);
      const regions=Array.from(new Set([
        ...acctList.map((acct)=>String(acct.default_region||"").trim()).filter(Boolean),
        ...bindingList.map((binding)=>String(binding.region||"").trim()).filter(Boolean)
      ]));
      const inventoryTotal=acctList.reduce((sum,acct)=>sum+Number(inventoryCounts[acct.id]||0),0);
      const connectedCount=acctList.filter((acct)=>accountProbeByID[acct.id]===true).length;
      const failedCount=acctList.filter((acct)=>accountProbeByID[acct.id]===false).length;
      const hasProbePending=acctList.some((acct)=>typeof accountProbeByID[acct.id]==="undefined");
      const firstProbeError=(acctList.map((acct)=>String(accountProbeErrorByID[acct.id]||"").trim()).find(Boolean)||"");
      const hasFailure=bindingList.some((binding)=>String(binding.sync_status||"").toLowerCase()==="failed");
      const hasAnyBindings=bindingList.length>0;
      const allSynced=hasAnyBindings&&bindingList.every((binding)=>String(binding.sync_status||"").toLowerCase()==="synced");
      let stateLabel="Configured";
      let stateColor:"blue"|"green"|"amber"|"red"="blue";
      if(connectedCount>0&&failedCount===0){
        stateLabel="Connected";
        stateColor="green";
      }else if(connectedCount>0&&failedCount>0){
        stateLabel="Partial";
        stateColor="amber";
      }else if(failedCount>0&&!hasProbePending){
        stateLabel="Auth Failed";
        stateColor="red";
      }
      if(stateColor!=="red"&&allSynced){
        stateLabel="Synced";
        stateColor="green";
      }else if(stateColor!=="red"&&hasFailure){
        stateLabel="Partial";
        stateColor="amber";
      }else if(stateColor!=="red"&&hasAnyBindings&&connectedCount>0){
        stateLabel="Syncing";
        stateColor="blue";
      }
      return {
        provider,
        accounts:acctList,
        bindings:bindingList,
        regions,
        stateLabel,
        stateColor,
        inventoryTotal,
        probeError:firstProbeError
      };
    });
  },[accounts,bindings,inventoryCounts,accountProbeByID,accountProbeErrorByID]);
  const normalizedConnectorSearch=String(connectorSearch||"").trim().toLowerCase();
  const filteredProviderCards=useMemo(()=>{
    if(!normalizedConnectorSearch){
      return providerCards;
    }
    return providerCards.filter((card)=>{
      const providerLabel=String(CLOUD_PROVIDER_LABELS[card.provider]||card.provider).toLowerCase();
      const regions=String((card.regions||[]).join(" ")).toLowerCase();
      const accountNames=String((card.accounts||[]).map((acct:any)=>String(acct?.name||"")).join(" ")).toLowerCase();
      return providerLabel.includes(normalizedConnectorSearch)
        || regions.includes(normalizedConnectorSearch)
        || accountNames.includes(normalizedConnectorSearch);
    });
  },[providerCards,normalizedConnectorSearch]);

  const runSync=async(provider:string,accountId:string)=>{
    if(!session?.token){
      return;
    }
    setSyncingAccount(accountId||provider);
    try{
      const job:CloudSyncJob=await syncCloudKeys(session,{
        provider:provider as CloudProvider,
        accountId,
        mode:"full"
      });
      addRecentOp(`${CLOUD_PROVIDER_LABELS[provider]||provider} sync`,job?.status==="completed"?"ok":"warn",String(job?.status||"completed"));
      onToast?.(`${CLOUD_PROVIDER_LABELS[provider]||provider} sync ${String(job?.status||"completed")}.`);
      await refresh(true);
    }catch(error){
      addRecentOp(`${CLOUD_PROVIDER_LABELS[provider]||provider} sync`,"error",errMsg(error));
      onToast?.(`Cloud sync failed: ${errMsg(error)}`);
    }finally{
      setSyncingAccount("");
    }
  };

  const deleteConnector=async(provider:string,account:CloudAccount|undefined)=>{
    if(!session?.token){
      return;
    }
    const accountId=String(account?.id||"").trim();
    if(!accountId){
      onToast?.("No connector selected to delete.");
      return;
    }
    const providerLabel=CLOUD_PROVIDER_LABELS[provider]||provider;
    const accountName=String(account?.name||accountId);
    const ok=await promptDialog.confirm({
      title:"Delete Cloud Connector",
      message:`Delete connector "${accountName}" for ${providerLabel}? This removes connector credentials, bindings, and sync jobs from KMS DB.`,
      confirmLabel:"Delete Connector",
      cancelLabel:"Cancel",
      danger:true
    });
    if(!ok){
      return;
    }

    setConnectorMenu("");
    setDeletingAccount(accountId);
    try{
      const out:DeleteCloudAccountResult=await deleteCloudAccount(session,accountId);
      addRecentOp(
        `${providerLabel} connector`,
        "ok",
        `Deleted connector ${accountName} (bindings ${Number(out?.deleted_bindings||0)}, jobs ${Number(out?.deleted_sync_jobs||0)}).`
      );
      onToast?.(
        `Connector deleted: ${accountName} (bindings ${Number(out?.deleted_bindings||0)}, jobs ${Number(out?.deleted_sync_jobs||0)}).`
      );
      await refresh(true);
    }catch(error){
      addRecentOp(`${providerLabel} connector`,"error",errMsg(error));
      onToast?.(`Delete connector failed: ${errMsg(error)}`);
    }finally{
      setDeletingAccount("");
    }
  };

  const submitAddConnector=async()=>{
    if(!session?.token){
      return;
    }
    const name=String(addName||"").trim();
    if(!name){
      onToast?.("Connector name is required.");
      return;
    }
    const rawCreds=String(addCredsJSON||"{}").trim()||"{}";
    try{
      JSON.parse(rawCreds);
    }catch{
      onToast?.("Credentials JSON is invalid.");
      return;
    }
    setSubmittingAdd(true);
    try{
      const account=await registerCloudAccount(session,{
        provider:addProvider,
        name,
        defaultRegion:String(addDefaultRegion||"").trim(),
        credentialsJson:rawCreds
      });
      addRecentOp(`${CLOUD_PROVIDER_LABELS[account.provider]||account.provider} connector`,"ok",`Connector ${account.name} added`);
      onToast?.(`Cloud connector added: ${account.name}`);
      setModal(null);
      setAddName("");
      await refresh(true);
    }catch(error){
      addRecentOp(`${CLOUD_PROVIDER_LABELS[addProvider]||addProvider} connector`,"error",errMsg(error));
      onToast?.(`Add connector failed: ${errMsg(error)}`);
    }finally{
      setSubmittingAdd(false);
    }
  };

  const submitImport=async()=>{
    if(!session?.token){
      return;
    }
    if(!String(importKeyID||"").trim()){
      onToast?.("Select a Vecta key to import.");
      return;
    }
    if(!String(importAccountID||"").trim()){
      onToast?.("Select target cloud account.");
      return;
    }
    setSubmittingImport(true);
    try{
      const binding=await importKeyToCloud(session,{
        keyId:String(importKeyID||"").trim(),
        provider:importProvider,
        accountId:String(importAccountID||"").trim(),
        cloudRegion:String(importCloudRegion||"").trim(),
        metadata:{
          alias:String(importAlias||"").trim()
        }
      });
      addRecentOp(`${CLOUD_PROVIDER_LABELS[binding.provider]||binding.provider} import`,"ok",`${binding.key_id} -> ${binding.cloud_key_id}`);
      onToast?.(`Imported key to ${CLOUD_PROVIDER_LABELS[binding.provider]||binding.provider}.`);
      setModal(null);
      setImportAlias("");
      await refresh(true);
    }catch(error){
      addRecentOp(`${CLOUD_PROVIDER_LABELS[importProvider]||importProvider} import`,"error",errMsg(error));
      onToast?.(`Cloud import failed: ${errMsg(error)}`);
    }finally{
      setSubmittingImport(false);
    }
  };

  const rotateBindingAction=async(binding:CloudKeyBinding)=>{
    if(!session?.token){
      return;
    }
    const bid=String(binding?.id||"").trim();
    if(!bid){
      return;
    }
    setRotatingBinding(bid);
    try{
      const out=await rotateCloudBinding(session,bid,"manual-byok-rotate");
      addRecentOp(`${CLOUD_PROVIDER_LABELS[binding.provider]||binding.provider} rotate`,"ok",`${binding.key_id} -> ${out.versionId||"new version"}`);
      onToast?.(`Cloud key rotated for ${binding.key_id}.`);
      await refresh(true);
    }catch(error){
      addRecentOp(`${CLOUD_PROVIDER_LABELS[binding.provider]||binding.provider} rotate`,"error",errMsg(error));
      onToast?.(`Rotate cloud key failed: ${errMsg(error)}`);
    }finally{
      setRotatingBinding("");
    }
  };

  const bindingsView=(Array.isArray(bindings)?bindings:[]).slice(0,12);
  const hasAnyConnector=(Array.isArray(accounts)?accounts:[]).length>0;
  const importAccounts=(accounts||[]).filter((acct)=>String(acct.provider||"").toLowerCase()===String(importProvider||"").toLowerCase());
  const latestOps=recentOps.length?recentOps:bindingsView.map((binding)=>({
    id:`bind-${binding.id}`,
    label:`${CLOUD_PROVIDER_LABELS[binding.provider]||binding.provider} binding`,
    status:String(binding.sync_status||"").toLowerCase()==="failed"?"error":"ok",
    detail:`${binding.key_id} -> ${binding.cloud_key_id}`,
    ts:String(binding.updated_at||binding.created_at||"")
  }));

  return <div>
    <Section
      title="Bring Your Own Key - Cloud Connectors"
      actions={<div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
        <Inp
          style={{width:220}}
          value={connectorSearch}
          onChange={(e)=>setConnectorSearch(e.target.value)}
          placeholder="Search cloud/provider/region..."
        />
        <Btn small primary={connectorView==="cards"} onClick={()=>setConnectorView("cards")} title="Card view">
          <LayoutGrid size={12} strokeWidth={2}/>
        </Btn>
        <Btn small primary={connectorView==="list"} onClick={()=>setConnectorView("list")} title="List view">
          <List size={12} strokeWidth={2}/>
        </Btn>
        <Btn small onClick={()=>void refresh()} disabled={refreshing||loading}><RefreshCcw size={12} strokeWidth={2}/> Refresh</Btn>
        <Btn small primary onClick={()=>setModal("add")}>+ Add Connector</Btn>
      </div>}
    >
      {connectorView==="cards"
        ? <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(230px,1fr))",gap:10}}>
          {filteredProviderCards.map((card)=>{
            const activeAccount=card.accounts[0];
            const accountId=activeAccount?.id||"";
            return <Card key={card.provider}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
                <div style={{fontSize:12,color:C.text,fontWeight:700}}>{CLOUD_PROVIDER_LABELS[card.provider]||card.provider}</div>
                <B c={card.stateColor}>{card.stateLabel}</B>
              </div>
              <div style={{fontSize:11,color:C.text,marginBottom:4}}>{`${card.bindings.length} keys synced`}</div>
              <div style={{fontSize:10,color:C.dim,marginBottom:8}}>
                {card.regions.length?`Regions: ${card.regions.join(", ")}`:"No regions configured"}
              </div>
              <div style={{fontSize:10,color:C.muted,marginBottom:10}}>{`Cloud inventory: ${card.inventoryTotal} keys`}</div>
              {card.probeError&&<div style={{fontSize:9,color:C.red,marginBottom:8,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{card.probeError}</div>}
              <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                <Btn
                  small
                  onClick={()=>void runSync(card.provider,accountId)}
                  disabled={!accountId||syncingAccount===accountId||syncingAccount===card.provider||deletingAccount===accountId}
                >
                  {syncingAccount===accountId||syncingAccount===card.provider?"Syncing...":"Sync Now"}
                </Btn>
                <Btn
                  small
                  onClick={()=>{
                    setImportProvider(card.provider as CloudProvider);
                    setImportAccountID(accountId);
                    setImportCloudRegion(String(activeAccount?.default_region||""));
                    setModal("import");
                  }}
                  disabled={!accountId||deletingAccount===accountId}
                >
                  Import Keys
                </Btn>
                <Btn
                  small
                  danger
                  onClick={()=>void deleteConnector(card.provider,activeAccount)}
                  disabled={!accountId||deletingAccount===accountId}
                >
                  {deletingAccount===accountId?"Deleting...":"Delete Connector"}
                </Btn>
              </div>
            </Card>;
          })}
        </div>
        : <Card style={{padding:0,overflow:"visible"}}>
          <div style={{display:"grid",gridTemplateColumns:"1.1fr .8fr .8fr .9fr .8fr auto",padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>
            <div>Provider</div><div>Status</div><div>Keys Synced</div><div>Regions</div><div>Inventory</div><div>Options</div>
          </div>
          <div style={{overflow:"visible"}}>
            {filteredProviderCards.map((card)=>{
              const activeAccount=card.accounts[0];
              const accountId=activeAccount?.id||"";
              const menuOpen=connectorMenu===String(card.provider);
              return <div key={card.provider} style={{display:"grid",gridTemplateColumns:"1.1fr .8fr .8fr .9fr .8fr auto",alignItems:"center",padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:10}}>
                <div style={{color:C.text,fontWeight:600}}>{CLOUD_PROVIDER_LABELS[card.provider]||card.provider}</div>
                <div><B c={card.stateColor}>{card.stateLabel}</B></div>
                <div style={{color:C.dim}}>{String(card.bindings.length)}</div>
                <div style={{color:C.dim,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{card.regions.length?card.regions.join(", "):"-"}</div>
              <div style={{color:C.dim}}>{String(card.inventoryTotal)}</div>
              <div style={{position:"relative",justifySelf:"end"}}>
                  <button
                    onClick={()=>setConnectorMenu(menuOpen?"":String(card.provider))}
                    style={{border:`1px solid ${C.border}`,background:"transparent",color:C.accent,borderRadius:8,padding:"4px 6px",cursor:"pointer"}}
                  >
                    <MoreVertical size={13} strokeWidth={2}/>
                  </button>
                  {menuOpen&&<div style={{position:"absolute",right:0,top:30,zIndex:20,minWidth:132,background:C.surface,border:`1px solid ${C.borderHi}`,borderRadius:8,padding:6,display:"grid",gap:4}}>
                    <button
                      onClick={()=>{setConnectorMenu("");void runSync(card.provider,accountId);}}
                      disabled={!accountId||syncingAccount===accountId||syncingAccount===card.provider||deletingAccount===accountId}
                      style={{textAlign:"left",background:"transparent",border:"none",color:C.text,cursor:"pointer",padding:"6px 8px",borderRadius:6}}
                    >
                      {syncingAccount===accountId||syncingAccount===card.provider?"Syncing...":"Sync Now"}
                    </button>
                    <button
                      onClick={()=>{
                        setConnectorMenu("");
                        setImportProvider(card.provider as CloudProvider);
                        setImportAccountID(accountId);
                        setImportCloudRegion(String(activeAccount?.default_region||""));
                        setModal("import");
                      }}
                      disabled={!accountId||deletingAccount===accountId}
                      style={{textAlign:"left",background:"transparent",border:"none",color:C.text,cursor:"pointer",padding:"6px 8px",borderRadius:6}}
                    >
                      Import Keys
                    </button>
                    <button
                      onClick={()=>{void deleteConnector(card.provider,activeAccount);}}
                      disabled={!accountId||deletingAccount===accountId}
                      style={{textAlign:"left",background:"transparent",border:"none",color:C.red,cursor:"pointer",padding:"6px 8px",borderRadius:6}}
                    >
                      {deletingAccount===accountId?"Deleting...":"Delete Connector"}
                    </button>
                  </div>}
                </div>
              </div>;
            })}
            {!filteredProviderCards.length&&<div style={{padding:12,fontSize:10,color:C.dim}}>
              {hasAnyConnector
                ? "No cloud connectors match search."
                : "No cloud connectors configured yet. Click + Add Connector to create your first CSP connector."}
            </div>}
          </div>
        </Card>}
      {!filteredProviderCards.length&&connectorView==="cards"&&<Card><div style={{fontSize:10,color:C.dim}}>
        {hasAnyConnector
          ? "No cloud connectors match search."
          : "No cloud connectors configured yet. Click + Add Connector to create your first CSP connector."}
      </div></Card>}
    </Section>

    <Section title="Recent BYOK Operations">
      <Card>
        <div style={{display:"grid",gap:8}}>
          {latestOps.slice(0,8).map((item)=>(
            <div key={item.id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",borderBottom:`1px solid ${C.border}`,paddingBottom:6}}>
              <div style={{maxWidth:"75%"}}>
                <div style={{fontSize:11,color:C.text,whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>{item.detail}</div>
                <div style={{fontSize:10,color:C.muted}}>{item.label}</div>
              </div>
              <div style={{display:"flex",alignItems:"center",gap:8}}>
                <div style={{fontSize:10,color:C.dim}}>{formatAgo(item.ts)}</div>
                <B c={item.status==="error"?"red":item.status==="warn"?"amber":"green"}>{item.status==="error"?"Error":item.status==="warn"?"Partial":"OK"}</B>
              </div>
            </div>
          ))}
          {!latestOps.length&&<div style={{fontSize:10,color:C.dim}}>No BYOK operations yet.</div>}
        </div>
      </Card>
    </Section>

    <Section title="Managed Cloud Key Bindings">
      <Card>
        <div style={{display:"grid",gap:8}}>
          {bindingsView.map((binding)=>{
            const rowStatus=String(binding.sync_status||"").toLowerCase();
            return <div key={binding.id} style={{display:"grid",gridTemplateColumns:"1.2fr 1fr 1fr auto",gap:8,alignItems:"center",borderBottom:`1px solid ${C.border}`,paddingBottom:6}}>
              <div>
                <div style={{fontSize:11,color:C.text,fontWeight:600}}>{binding.key_id}</div>
                <div style={{fontSize:9,color:C.muted,fontFamily:"'JetBrains Mono',monospace",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{binding.cloud_key_ref||binding.cloud_key_id}</div>
              </div>
              <div style={{fontSize:10,color:C.dim}}>{CLOUD_PROVIDER_LABELS[binding.provider]||binding.provider}</div>
              <div style={{fontSize:10,color:C.dim}}>{binding.region||"-"}</div>
              <div style={{display:"flex",alignItems:"center",gap:6,justifyContent:"flex-end"}}>
                <B c={rowStatus==="failed"?"red":"green"}>{rowStatus==="failed"?"Failed":"Synced"}</B>
                <Btn
                  small
                  onClick={()=>void rotateBindingAction(binding)}
                  disabled={rotatingBinding===binding.id}
                >
                  {rotatingBinding===binding.id?"Rotating...":"Rotate"}
                </Btn>
              </div>
            </div>;
          })}
          {!bindingsView.length&&<div style={{fontSize:10,color:C.dim}}>No cloud key bindings yet. Add connector and import keys.</div>}
        </div>
      </Card>
    </Section>

    <Modal open={modal==="add"} onClose={()=>setModal(null)} title="Add Cloud Connector" wide>
      <FG label="Cloud Provider" required>
        <Sel value={addProvider} onChange={(e)=>setAddProvider(normalizeCloudProvider(e.target.value))}>
          <option value="aws">AWS KMS</option>
          <option value="azure">Azure Key Vault</option>
          <option value="gcp">Google Cloud KMS</option>
          <option value="oci">Oracle Cloud Vault</option>
          <option value="salesforce">Salesforce BYOK</option>
        </Sel>
      </FG>
      <FG label="Connector Name" required>
        <Inp value={addName} onChange={(e)=>setAddName(e.target.value)} placeholder="prod-main" mono/>
      </FG>
      <FG label="Default Region">
        <Inp value={addDefaultRegion} onChange={(e)=>setAddDefaultRegion(e.target.value)} placeholder="us-east-1 / eastus / europe-west1" mono/>
      </FG>
      <FG label="Credentials JSON" required hint="Stored encrypted. Use provider SDK credential schema for this connector.">
        <Txt rows={8} value={addCredsJSON} onChange={(e)=>setAddCredsJSON(e.target.value)} placeholder='{"access_key_id":"...","secret_access_key":"..."}'/>
      </FG>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)} disabled={submittingAdd}>Cancel</Btn>
        <Btn primary onClick={()=>void submitAddConnector()} disabled={submittingAdd}>{submittingAdd?"Adding...":"Add Connector"}</Btn>
      </div>
    </Modal>

    <Modal open={modal==="import"} onClose={()=>setModal(null)} title="Import Key to Cloud">
      <FG label="Vecta Key to Import" required>
        <Sel value={importKeyID} onChange={(e)=>setImportKeyID(e.target.value)}>
          {renderKeyOptions(keyChoices)}
        </Sel>
      </FG>
      <FG label="Cloud Provider" required>
        <Sel value={importProvider} onChange={(e)=>setImportProvider(normalizeCloudProvider(e.target.value))}>
          <option value="aws">AWS KMS</option>
          <option value="azure">Azure Key Vault</option>
          <option value="gcp">Google Cloud KMS</option>
          <option value="oci">Oracle Cloud Vault</option>
          <option value="salesforce">Salesforce BYOK</option>
        </Sel>
      </FG>
      <FG label="Target Account" required>
        <Sel value={importAccountID} onChange={(e)=>setImportAccountID(e.target.value)}>
          {importAccounts.map((acct)=>
            <option key={acct.id} value={acct.id}>{`${acct.name} (${acct.default_region||"default"})`}</option>
          )}
          {!importAccounts.length&&<option value="">No connector found for selected provider</option>}
        </Sel>
      </FG>
      <FG label="Cloud Region Override">
        <Inp value={importCloudRegion} onChange={(e)=>setImportCloudRegion(e.target.value)} placeholder="Leave empty to use account default" mono/>
      </FG>
      <FG label="Cloud Key Alias">
        <Inp value={importAlias} onChange={(e)=>setImportAlias(e.target.value)} placeholder="alias/vecta-prod-db" mono/>
      </FG>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)} disabled={submittingImport}>Cancel</Btn>
        <Btn primary onClick={()=>void submitImport()} disabled={submittingImport}>{submittingImport?"Importing...":"Import to Cloud"}</Btn>
      </div>
    </Modal>
    {promptDialog.ui}
  </div>;
};


