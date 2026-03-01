// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import { RefreshCcw } from "lucide-react";
import { B, Btn, Card, Inp, Modal, Row3, Section } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  diffCBOM,
  exportCBOM,
  exportSBOM,
  generateCBOM,
  generateSBOM,
  getCBOMSummary,
  getLatestCBOM,
  getLatestSBOM,
  listCBOMHistory,
  listSBOMHistory,
  listSBOMVulnerabilities
} from "../../../lib/sbom";
export const SBOMTab=({session,onToast}:any)=>{
  const [loading,setLoading]=useState(false);
  const [refreshing,setRefreshing]=useState(false);
  const [exportingSBOM,setExportingSBOM]=useState("");
  const [exportingCBOM,setExportingCBOM]=useState(false);
  const [sbomLatest,setSBOMLatest]=useState<any>(null);
  const [sbomHistory,setSBOMHistory]=useState<any[]>([]);
  const [sbomVulns,setSBOMVulns]=useState<any[]>([]);
  const [cbomLatest,setCBOMLatest]=useState<any>(null);
  const [cbomSummary,setCBOMSummary]=useState<any>({});
  const [cbomHistory,setCBOMHistory]=useState<any[]>([]);
  const [activeSBOMFormat,setActiveSBOMFormat]=useState("cyclonedx");
  const [exportMenuOpen,setExportMenuOpen]=useState(false);
  const [selectedDepCategory,setSelectedDepCategory]=useState("");
  const [depListOpen,setDepListOpen]=useState(false);
  const [depListTitle,setDepListTitle]=useState("");
  const [depListItems,setDepListItems]=useState<any[]>([]);
  const [depListFilter,setDepListFilter]=useState("");
  const [selectedCBOMCategory,setSelectedCBOMCategory]=useState("");
  const [cbomAssetListOpen,setCBOMAssetListOpen]=useState(false);
  const [cbomAssetListTitle,setCBOMAssetListTitle]=useState("");
  const [cbomAssetListItems,setCBOMAssetListItems]=useState<any[]>([]);
  const [cbomAssetListFilter,setCBOMAssetListFilter]=useState("");
  const [diffOpen,setDiffOpen]=useState(false);
  const [diffData,setDiffData]=useState<any>(null);

  const downloadTextFile=(filename,content,mime="application/json")=>{
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
    try{
      const bin=atob(String(b64||""));
      const bytes=new Uint8Array(bin.length);
      for(let i=0;i<bin.length;i+=1){
        bytes[i]=bin.charCodeAt(i);
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
    }catch{
      onToast?.("Export download failed: invalid base64 payload.");
    }
  };

  const loadData=async(opts:any={})=>{
    if(!session?.token){
      setSBOMLatest(null);
      setSBOMHistory([]);
      setSBOMVulns([]);
      setCBOMLatest(null);
      setCBOMSummary({});
      setCBOMHistory([]);
      return;
    }
    const doRefresh=Boolean(opts?.refresh);
    if(doRefresh){
      setRefreshing(true);
    }else if(!opts?.silent){
      setLoading(true);
    }
    try{
      if(doRefresh){
        await Promise.all([
          generateSBOM(session,"manual"),
          generateCBOM(session,"manual")
        ]);
      }
      const [sbomOut,sbomHistoryOut,vulnOut,cbomOut,summaryOut,historyOut]=await Promise.all([
        getLatestSBOM(session),
        listSBOMHistory(session,12),
        listSBOMVulnerabilities(session),
        getLatestCBOM(session),
        getCBOMSummary(session),
        listCBOMHistory(session,8)
      ]);
      setSBOMLatest(sbomOut||null);
      setSBOMHistory(Array.isArray(sbomHistoryOut)?sbomHistoryOut:[]);
      setSBOMVulns(Array.isArray(vulnOut)?vulnOut:[]);
      setCBOMLatest(cbomOut||null);
      setCBOMSummary(summaryOut||{});
      setCBOMHistory(Array.isArray(historyOut)?historyOut:[]);
      if(doRefresh){
        onToast?.("SBOM and CBOM refreshed from current components and cryptographic assets.");
      }
    }catch(error){
      onToast?.(`SBOM/CBOM load failed: ${errMsg(error)}`);
    }finally{
      if(doRefresh){
        setRefreshing(false);
      }else if(!opts?.silent){
        setLoading(false);
      }
    }
  };

  useEffect(()=>{
    void loadData({refresh:true});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  },[session?.token,session?.tenantId]);

  const exportSBOMFile=async(format:string)=>{
    if(!session?.token){
      onToast?.("Login is required.");
      return;
    }
    const snapshotID=String(sbomLatest?.id||"").trim();
    if(!snapshotID){
      onToast?.("SBOM snapshot is not ready. Refresh BOM first.");
      return;
    }
    setActiveSBOMFormat(format);
    setExportingSBOM(format);
    try{
      const encoding=format==="cyclonedx"?"json":"json";
      const artifact=await exportSBOM(session,snapshotID,format as any,encoding);
      const stamp=new Date().toISOString().replace(/[:.]/g,"-");
      if(String(artifact?.encoding||"").toLowerCase()==="base64"){
        const ext=format==="pdf"?"pdf":"bin";
        downloadBase64File(`vecta-sbom-${format}-${stamp}.${ext}`,artifact?.content||"",String(artifact?.content_type||"application/octet-stream"));
      }else{
        const ext=format==="spdx"?"spdx.json":format==="cyclonedx"?"cyclonedx.json":"txt";
        const mime=String(artifact?.content_type||"application/json");
        downloadTextFile(`vecta-sbom-${format}-${stamp}.${ext}`,artifact?.content||"",mime);
      }
      onToast?.(`SBOM exported as ${format.toUpperCase()}.`);
    }catch(error){
      onToast?.(`SBOM export failed: ${errMsg(error)}`);
    }finally{
      setExportingSBOM("");
    }
  };

  const exportSBOMCSV=()=>{
    const list=Array.isArray(sbomLatest?.document?.components)?sbomLatest.document.components:[];
    if(!list.length){
      onToast?.("SBOM snapshot is not ready. Refresh BOM first.");
      return;
    }
    try{
      setExportingSBOM("csv");
      const esc=(v:any)=>`"${String(v??"").replace(/"/g,'""')}"`;
      const rows=[
        ["name","version","type","ecosystem","supplier"],
        ...list.map((item:any)=>[
          String(item?.name||""),
          String(item?.version||""),
          String(item?.type||""),
          String(item?.ecosystem||""),
          String(item?.supplier||"")
        ])
      ];
      const csv=rows.map((row:any[])=>row.map((v:any)=>esc(v)).join(",")).join("\n");
      const stamp=new Date().toISOString().replace(/[:.]/g,"-");
      downloadTextFile(`vecta-sbom-csv-${stamp}.csv`,csv,"text/csv;charset=utf-8");
      onToast?.("SBOM exported as CSV.");
    }catch(error){
      onToast?.(`SBOM CSV export failed: ${errMsg(error)}`);
    }finally{
      setExportingSBOM("");
    }
  };

  const exportCBOMFile=async()=>{
    if(!session?.token){
      onToast?.("Login is required.");
      return;
    }
    const snapshotID=String(cbomLatest?.id||"").trim();
    if(!snapshotID){
      onToast?.("CBOM snapshot is not ready. Refresh BOM first.");
      return;
    }
    setExportingCBOM(true);
    try{
      const artifact=await exportCBOM(session,snapshotID,"cyclonedx");
      const stamp=new Date().toISOString().replace(/[:.]/g,"-");
      if(String(artifact?.encoding||"").toLowerCase()==="base64"){
        downloadBase64File(`vecta-cbom-${stamp}.pdf`,artifact?.content||"",String(artifact?.content_type||"application/pdf"));
      }else{
        downloadTextFile(`vecta-cbom-${stamp}.json`,artifact?.content||"",String(artifact?.content_type||"application/json"));
      }
      onToast?.("CBOM exported.");
    }catch(error){
      onToast?.(`CBOM export failed: ${errMsg(error)}`);
    }finally{
      setExportingCBOM(false);
    }
  };

  const openDiff=async()=>{
    if(!session?.token){
      onToast?.("Login is required.");
      return;
    }
    const history=Array.isArray(cbomHistory)?[...cbomHistory]:[];
    history.sort((a:any,b:any)=>new Date(String(b?.created_at||0)).getTime()-new Date(String(a?.created_at||0)).getTime());
    if(history.length<2){
      onToast?.("Need at least two CBOM snapshots for diff. Click Refresh BOM again.");
      return;
    }
    try{
      const latest=history[0];
      const prev=history[1];
      const out=await diffCBOM(session,String(prev?.id||""),String(latest?.id||""));
      setDiffData(out||null);
      setDiffOpen(true);
    }catch(error){
      onToast?.(`CBOM diff failed: ${errMsg(error)}`);
    }
  };

  const components=Array.isArray(sbomLatest?.document?.components)?sbomLatest.document.components:[];
  const vulnerabilities=Array.isArray(sbomVulns)?sbomVulns:[];

  const severityRank=(sev:string)=>{
    const normalized=String(sev||"").toLowerCase();
    if(normalized==="critical") return 5;
    if(normalized==="high") return 4;
    if(normalized==="medium") return 3;
    if(normalized==="low") return 2;
    return 1;
  };

  const componentVulnStats=useMemo(()=>{
    const out:any={};
    vulnerabilities.forEach((item:any)=>{
      const key=String(item?.component||"").trim().toLowerCase();
      if(!key){
        return;
      }
      if(!out[key]){
        out[key]={count:0,top:"none",rank:0};
      }
      out[key].count+=1;
      const rank=severityRank(String(item?.severity||""));
      if(rank>Number(out[key].rank||0)){
        out[key].rank=rank;
        out[key].top=String(item?.severity||"none").toLowerCase();
      }
    });
    return out;
  },[vulnerabilities]);

  const goComponents=components.filter((c:any)=>String(c?.type||"").toLowerCase()==="library"&&String(c?.ecosystem||"").toLowerCase()==="go");
  const containerComponents=components.filter((c:any)=>String(c?.type||"").toLowerCase()==="container");
  const systemComponents=components.filter((c:any)=>["runtime","infrastructure","os-pkg"].includes(String(c?.type||"").toLowerCase()));

  const categorySeverity=(names:string[])=>{
    const set=new Set(names.map((n)=>String(n||"").trim().toLowerCase()).filter(Boolean));
    const items=vulnerabilities.filter((v:any)=>set.has(String(v?.component||"").trim().toLowerCase()));
    if(!items.length){
      return {label:"0 CVEs",tone:"green"};
    }
    const stats={critical:0,high:0,medium:0,low:0,other:0};
    items.forEach((v:any)=>{
      const sev=String(v?.severity||"").toLowerCase();
      if(sev==="critical") stats.critical+=1;
      else if(sev==="high") stats.high+=1;
      else if(sev==="medium") stats.medium+=1;
      else if(sev==="low") stats.low+=1;
      else stats.other+=1;
    });
    if(stats.critical>0) return {label:`${stats.critical} critical`,tone:"red"};
    if(stats.high>0) return {label:`${stats.high} high`,tone:"red"};
    if(stats.medium>0) return {label:`${stats.medium} medium`,tone:"amber"};
    if(stats.low>0) return {label:`${stats.low} low`,tone:"amber"};
    return {label:`${items.length} CVEs`,tone:"blue"};
  };

  const sbomRows=[
    {label:"Go modules",count:goComponents.length,names:goComponents.map((c:any)=>String(c?.name||"")),components:goComponents},
    {label:"Containers",count:containerComponents.length,names:containerComponents.map((c:any)=>String(c?.name||"")),components:containerComponents},
    {label:"System pkgs",count:systemComponents.length,names:systemComponents.map((c:any)=>String(c?.name||"")),components:systemComponents}
  ].map((row)=>({...row,sev:categorySeverity(row.names)}));

  const openDependencyList=(row:any)=>{
    setSelectedDepCategory(String(row?.label||""));
    setDepListTitle(String(row?.label||"Dependencies"));
    setDepListFilter("");
    setDepListItems(Array.isArray(row?.components)?[...row.components]:[]);
    setDepListOpen(true);
  };

  const sbomTrend=useMemo(()=>{
    const items=Array.isArray(sbomHistory)?[...sbomHistory]:[];
    items.sort((a:any,b:any)=>{
      const ta=new Date(String(a?.created_at||a?.document?.generated_at||0)).getTime();
      const tb=new Date(String(b?.created_at||b?.document?.generated_at||0)).getTime();
      return ta-tb;
    });
    return items.slice(-10).map((item:any)=>{
      const docs=Array.isArray(item?.document?.components)?item.document.components:[];
      const go=docs.filter((c:any)=>String(c?.type||"").toLowerCase()==="library"&&String(c?.ecosystem||"").toLowerCase()==="go").length;
      const containers=docs.filter((c:any)=>String(c?.type||"").toLowerCase()==="container").length;
      const sys=docs.filter((c:any)=>["runtime","infrastructure","os-pkg"].includes(String(c?.type||"").toLowerCase())).length;
      return {
        id:String(item?.id||""),
        at:String(item?.created_at||item?.document?.generated_at||""),
        total:docs.length,
        go,
        containers,
        system:sys
      };
    });
  },[sbomHistory]);

  const trendMax=Math.max(1,...sbomTrend.map((point:any)=>Math.max(0,Number(point?.total||0))));
  const trendChartPoints=sbomTrend.map((point:any,index:number)=>{
    const x=sbomTrend.length===1?50:(index/(sbomTrend.length-1))*100;
    const y=100-((Number(point?.total||0)/trendMax)*100);
    return {
      x,
      y:Math.max(4,Math.min(96,y)),
      total:Number(point?.total||0),
      at:String(point?.at||""),
      label:new Date(String(point?.at||Date.now())).toLocaleDateString(undefined,{month:"short",day:"numeric"})
    };
  });
  const trendPoints=trendChartPoints.map((p:any)=>`${p.x},${p.y}`).join(" ");
  const trendTicksRaw=[trendMax,Math.round(trendMax*0.75),Math.round(trendMax*0.5),Math.round(trendMax*0.25),0];
  const trendTicks=Array.from(new Set(trendTicksRaw.filter((v)=>Number.isFinite(v)&&v>=0))).sort((a,b)=>b-a);
  const trendTickY=(v:number)=>Math.max(4,Math.min(96,100-((Math.max(0,Number(v||0))/trendMax)*100)));
  const latestTrend=sbomTrend.length?sbomTrend[sbomTrend.length-1]:null;
  const prevTrend=sbomTrend.length>1?sbomTrend[sbomTrend.length-2]:null;
  const trendDelta=(latestTrend&&prevTrend)?(Number(latestTrend.total||0)-Number(prevTrend.total||0)):0;
  const filteredDepList=depListItems.filter((item:any)=>{
    const q=String(depListFilter||"").trim().toLowerCase();
    if(!q){
      return true;
    }
    const name=String(item?.name||"").toLowerCase();
    const version=String(item?.version||"").toLowerCase();
    const typ=String(item?.type||"").toLowerCase();
    const eco=String(item?.ecosystem||"").toLowerCase();
    return name.includes(q)||version.includes(q)||typ.includes(q)||eco.includes(q);
  });

  const rawDist=cbomSummary?.algorithm_distribution||cbomLatest?.document?.algorithm_distribution||{};
  const grouped={AES:0,RSA:0,ECDSA:0,PQC:0,Other:0};
  Object.entries(rawDist||{}).forEach(([alg,val])=>{
    const count=Math.max(0,Number(val||0));
    const upper=String(alg||"").toUpperCase();
    if(upper.includes("AES")){
      grouped.AES+=count;
      return;
    }
    if(upper.includes("RSA")){
      grouped.RSA+=count;
      return;
    }
    if(upper.includes("ECDSA")||upper.includes("EDDSA")||upper.includes("ECDH")){
      grouped.ECDSA+=count;
      return;
    }
    if(upper.includes("ML-")||upper.includes("SLH")||upper.includes("XMSS")||upper.includes("KYBER")||upper.includes("DILITHIUM")||upper.includes("FALCON")){
      grouped.PQC+=count;
      return;
    }
    grouped.Other+=count;
  });
  const distItems=[
    {label:"AES",value:grouped.AES,color:"#22d3ee"},
    {label:"RSA",value:grouped.RSA,color:"#60a5fa"},
    {label:"ECDSA",value:grouped.ECDSA,color:"#8b5cf6"},
    {label:"PQC",value:grouped.PQC,color:"#34d399"},
    {label:"Other",value:grouped.Other,color:"#facc15"}
  ];
  const distTotal=distItems.reduce((sum,item)=>sum+Math.max(0,Number(item.value||0)),0);
  let acc=0;
  const slices=distItems
    .filter((item)=>Number(item.value||0)>0)
    .map((item)=>{
      const start=(acc/distTotal)*360;
      acc+=Number(item.value||0);
      const end=(acc/distTotal)*360;
      return `${item.color} ${start}deg ${end}deg`;
    });
  const donutBackground=distTotal>0?`conic-gradient(${slices.join(", ")})`:`conic-gradient(${C.border} 0deg 360deg)`;
  const totalAssets=Math.max(0,Number(cbomSummary?.total_assets??cbomLatest?.document?.total_asset_count??0));
  const cbomAssets=Array.isArray(cbomLatest?.document?.assets)?cbomLatest.document.assets:[];

  const isHSMBackedAsset=(asset:any)=>{
    const metadata=(asset&&typeof asset.metadata==="object"&&asset.metadata)?asset.metadata:{};
    const sourceBlob=[
      asset?.source,
      asset?.status,
      asset?.asset_type,
      asset?.name,
      asset?.algorithm,
      metadata?.storage,
      metadata?.provider,
      metadata?.backend,
      metadata?.key_store,
      metadata?.kek_mode,
      metadata?.origin,
      metadata?.hsm,
      metadata?.hsm_backed,
      metadata?.location
    ].map((v)=>String(v??"")).join(" ").toLowerCase();
    if(metadata?.hsm_backed===true){
      return true;
    }
    if(String(metadata?.storage||"").toLowerCase()==="hsm"){
      return true;
    }
    return /\bhsm\b|pkcs11|cloudhsm|luna|thales|utimaco|hsm-backed/.test(sourceBlob);
  };

  const isWeakLegacyAsset=(asset:any)=>{
    const alg=String(asset?.algorithm||"").toUpperCase();
    const status=String(asset?.status||"").toLowerCase();
    const bits=Number(asset?.strength_bits||0);
    if(bits>0&&bits<128){
      return true;
    }
    if(/\bDES\b|\b3DES\b|RC2|RC4|MD5|SHA1|RSA-1024|DSA-1024/.test(alg)){
      return true;
    }
    if(status.includes("weak")||status.includes("legacy")||status.includes("deprecated")){
      return true;
    }
    return Boolean(asset?.deprecated);
  };

  const cbomCategoryRows=useMemo(()=>{
    const list=Array.isArray(cbomAssets)?cbomAssets:[];
    const hsmBacked=list.filter((asset:any)=>isHSMBackedAsset(asset));
    const softwareBacked=list.filter((asset:any)=>!isHSMBackedAsset(asset));
    return [
      {label:"PQC-ready",items:list.filter((asset:any)=>Boolean(asset?.pqc_ready)),tone:"green"},
      {label:"Deprecated",items:list.filter((asset:any)=>Boolean(asset?.deprecated)),tone:"amber"},
      {label:"Weak / Legacy",items:list.filter((asset:any)=>isWeakLegacyAsset(asset)),tone:"red"},
      {label:"HSM-backed",items:hsmBacked,tone:"blue"},
      {label:"Software-backed",items:softwareBacked,tone:"blue"}
    ].map((row:any)=>({
      ...row,
      count:Array.isArray(row.items)?row.items.length:0
    }));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  },[cbomAssets]);

  const openCBOMAssetList=(row:any)=>{
    setSelectedCBOMCategory(String(row?.label||""));
    setCBOMAssetListTitle(`${String(row?.label||"")} Assets`);
    setCBOMAssetListFilter("");
    setCBOMAssetListItems(Array.isArray(row?.items)?[...row.items]:[]);
    setCBOMAssetListOpen(true);
  };

  const filteredCBOMAssetList=cbomAssetListItems.filter((asset:any)=>{
    const q=String(cbomAssetListFilter||"").trim().toLowerCase();
    if(!q){
      return true;
    }
    const text=[
      asset?.id,
      asset?.name,
      asset?.asset_type,
      asset?.source,
      asset?.algorithm,
      asset?.status,
      asset?.strength_bits
    ].map((v)=>String(v??"").toLowerCase()).join(" ");
    return text.includes(q);
  });

  const sbomGenerated=String(sbomLatest?.document?.generated_at||sbomLatest?.created_at||"");
  const cbomGenerated=String(cbomLatest?.document?.generated_at||cbomLatest?.created_at||"");

  return <div>
    <Section
      title="Software & Cryptographic BOM"
      actions={<div style={{display:"flex",alignItems:"center",gap:8}}>
        <Btn small onClick={()=>void loadData({refresh:true})} disabled={refreshing||loading}>
          <RefreshCcw size={12}/>{refreshing?"Refreshing...":"Refresh BOM"}
        </Btn>
      </div>}
    >
      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
        <Card style={{padding:"12px 14px"}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
            <div style={{fontSize:12,fontWeight:700,color:C.text,letterSpacing:-.2}}>Software BOM</div>
            <div style={{display:"flex",gap:6,position:"relative"}}>
              <Btn
                small
                onClick={()=>void exportSBOMFile("cyclonedx")}
                disabled={Boolean(exportingSBOM)}
                style={{
                  height:30,
                  fontSize:11,
                  background:activeSBOMFormat==="cyclonedx"?C.accentDim:"transparent",
                  borderColor:activeSBOMFormat==="cyclonedx"?C.accent:C.border,
                  color:activeSBOMFormat==="cyclonedx"?C.accent:C.dim
                }}
              >
                {exportingSBOM==="cyclonedx"?"...":"CycloneDX"}
              </Btn>
              <Btn
                small
                onClick={()=>void exportSBOMFile("spdx")}
                disabled={Boolean(exportingSBOM)}
                style={{
                  height:30,
                  fontSize:11,
                  background:activeSBOMFormat==="spdx"?C.accentDim:"transparent",
                  borderColor:activeSBOMFormat==="spdx"?C.accent:C.border,
                  color:activeSBOMFormat==="spdx"?C.accent:C.dim
                }}
              >
                {exportingSBOM==="spdx"?"...":"SPDX"}
              </Btn>
              <div style={{position:"relative"}}>
                <Btn
                  small
                  onClick={()=>setExportMenuOpen((prev)=>!prev)}
                  disabled={Boolean(exportingSBOM)}
                  style={{height:30,fontSize:11}}
                >
                  Export
                </Btn>
                {exportMenuOpen?<div style={{position:"absolute",right:0,top:34,minWidth:120,background:C.card,border:`1px solid ${C.border}`,borderRadius:10,padding:6,zIndex:20}}>
                  <Btn
                    small
                    onClick={()=>{setExportMenuOpen(false);void exportSBOMFile("pdf");}}
                    disabled={Boolean(exportingSBOM)}
                    style={{width:"100%",justifyContent:"flex-start",height:28,borderColor:"transparent",fontSize:11}}
                  >
                    {exportingSBOM==="pdf"?"Exporting...":"PDF"}
                  </Btn>
                  <Btn
                    small
                    onClick={()=>{setExportMenuOpen(false);exportSBOMCSV();}}
                    disabled={Boolean(exportingSBOM)}
                    style={{width:"100%",justifyContent:"flex-start",height:28,borderColor:"transparent",fontSize:11}}
                  >
                    {exportingSBOM==="csv"?"Exporting...":"CSV"}
                  </Btn>
                </div>:null}
              </div>
            </div>
          </div>
          <div style={{display:"grid",gap:2}}>
            {sbomRows.map((row)=><div key={row.label} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"10px 0",borderBottom:`1px solid ${C.border}`}}>
              <div style={{display:"flex",alignItems:"center",gap:8}}>
                <div style={{fontSize:12,color:C.text,fontWeight:700,minWidth:120}}>{row.label}</div>
                <button
                  type="button"
                  onClick={()=>openDependencyList(row)}
                  style={{
                    fontSize:11,
                    color:(depListOpen&&selectedDepCategory===row.label)?C.text:C.dim,
                    background:"transparent",
                    border:"none",
                    padding:0,
                    cursor:"pointer",
                    fontWeight:(depListOpen&&selectedDepCategory===row.label)?700:500
                  }}
                >
                  {`${Number(row.count||0)} deps`}
                </button>
              </div>
              <B c={String(row.sev?.tone||"green")}>{String(row.sev?.label||"0 CVEs")}</B>
            </div>)}
          </div>
          <div style={{marginTop:12,paddingTop:10,borderTop:`1px solid ${C.border}`}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
              <div style={{fontSize:10,color:C.dim,fontWeight:700,letterSpacing:.3}}>Dependency Trend (history)</div>
              <div style={{fontSize:10,color:C.muted}}>
                {sbomTrend.length?`${Number(latestTrend?.total||0)} total (${trendDelta>=0?"+":""}${trendDelta} vs prev)`:"No history"}
              </div>
            </div>
            <div style={{height:128,border:`1px solid ${C.border}`,borderRadius:8,background:C.surface,padding:8,overflow:"hidden"}}>
              {sbomTrend.length?<div style={{height:"100%",display:"grid",gridTemplateColumns:"36px 1fr",gap:6}}>
                <div style={{display:"flex",flexDirection:"column",justifyContent:"space-between",fontSize:9,color:C.muted,overflow:"hidden"}}>
                  {trendTicks.map((tick:number)=><span key={tick}>{tick}</span>)}
                </div>
                <div style={{display:"flex",flexDirection:"column",height:"100%",overflow:"hidden"}}>
                  <div style={{flex:1,minHeight:0,overflow:"hidden"}}>
                    <svg viewBox="0 0 100 100" preserveAspectRatio="none" style={{width:"100%",height:"100%",display:"block",overflow:"hidden"}}>
                      {trendTicks.map((tick:number)=><line key={`grid-${tick}`} x1="0" x2="100" y1={trendTickY(tick)} y2={trendTickY(tick)} stroke={C.border} strokeWidth="0.6"/>)}
                      <polyline
                        fill="none"
                        stroke={C.accent}
                        strokeWidth="2.2"
                        points={trendPoints}
                      />
                      {trendChartPoints.map((point:any,index:number)=><circle key={`${point.at}-${index}`} cx={point.x} cy={point.y} r="2" fill={C.accent}/>)}
                    </svg>
                  </div>
                  <div style={{display:"flex",justifyContent:"space-between",fontSize:9,color:C.muted,paddingTop:4}}>
                    <span>{trendChartPoints[0]?.label||"-"}</span>
                    <span>{trendChartPoints[trendChartPoints.length-1]?.label||"-"}</span>
                  </div>
                </div>
              </div>:<div style={{height:"100%",display:"flex",alignItems:"center",justifyContent:"center",fontSize:10,color:C.muted}}>No historical SBOM snapshots yet.</div>}
            </div>
            <div style={{display:"flex",justifyContent:"space-between",fontSize:9,color:C.muted,marginTop:4}}>
              <span>Total dependency count per snapshot</span>
              <span>{`${sbomTrend.length} snapshots`}</span>
            </div>
          </div>
          <div style={{marginTop:10,fontSize:10,color:C.muted}}>
            {`Generated ${sbomGenerated?new Date(sbomGenerated).toLocaleString():"-"}`}
          </div>
        </Card>

        <Card style={{padding:"12px 14px"}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:10}}>
            <div style={{fontSize:12,fontWeight:700,color:C.text,letterSpacing:-.2}}>Cryptographic BOM</div>
            <div style={{display:"flex",gap:8}}>
              <Btn small onClick={()=>void exportCBOMFile()} disabled={exportingCBOM} style={{height:30,fontSize:11}}>
                {exportingCBOM?"Exporting...":"Export CBOM"}
              </Btn>
              <Btn small onClick={()=>void openDiff()} style={{height:30,fontSize:11}}>View Diff</Btn>
            </div>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"240px 1fr",gap:10,alignItems:"center"}}>
            <div style={{display:"flex",alignItems:"center",justifyContent:"center"}}>
              <div style={{position:"relative",width:138,height:138,borderRadius:"50%",background:donutBackground,border:`1px solid ${C.border}`}}>
                <div style={{position:"absolute",inset:20,borderRadius:"50%",background:C.card,border:`1px solid ${C.border}`,display:"flex",alignItems:"center",justifyContent:"center",flexDirection:"column"}}>
                  <div style={{fontSize:24,color:C.text,fontWeight:800}}>{totalAssets.toLocaleString()}</div>
                  <div style={{fontSize:9,color:C.muted}}>assets</div>
                </div>
              </div>
            </div>
            <div style={{display:"grid",gap:6}}>
              {distItems.map((item)=>{
                const pct=distTotal?Math.round((Number(item.value||0)/distTotal)*100):0;
                return <div key={item.label} style={{display:"flex",alignItems:"center",justifyContent:"space-between",fontSize:11}}>
                  <div style={{display:"flex",alignItems:"center",gap:8}}>
                    <span style={{width:10,height:10,borderRadius:2,background:item.color,display:"inline-block"}}/>
                    <span style={{color:C.text}}>{item.label}</span>
                  </div>
                  <span style={{color:C.dim}}>{`${pct}%`}</span>
                </div>;
              })}
              <div style={{marginTop:6,paddingTop:8,borderTop:`1px solid ${C.border}`,display:"grid",gap:2}}>
                {cbomCategoryRows.map((row:any)=><div key={String(row.label)} style={{display:"flex",alignItems:"center",justifyContent:"space-between",fontSize:10,padding:"3px 0"}}>
                  <button
                    type="button"
                    onClick={()=>openCBOMAssetList(row)}
                    style={{
                      border:"none",
                      background:"transparent",
                      color:(cbomAssetListOpen&&selectedCBOMCategory===row.label)?C.text:C.dim,
                      fontWeight:(cbomAssetListOpen&&selectedCBOMCategory===row.label)?700:500,
                      cursor:"pointer",
                      padding:0
                    }}
                  >
                    {String(row.label)}
                  </button>
                  <button
                    type="button"
                    onClick={()=>openCBOMAssetList(row)}
                    style={{
                      border:"none",
                      background:"transparent",
                      color:(cbomAssetListOpen&&selectedCBOMCategory===row.label)?C.text:C.dim,
                      fontWeight:700,
                      cursor:"pointer",
                      padding:0
                    }}
                  >
                    {Number(row.count||0).toLocaleString()}
                  </button>
                </div>)}
              </div>
            </div>
          </div>
          <div style={{marginTop:10,fontSize:10,color:C.muted}}>
            {`Generated ${cbomGenerated?new Date(cbomGenerated).toLocaleString():"-"} • Auto-scheduled daily and refreshed from live inventory.`}
          </div>
        </Card>
      </div>
      {!loading&&!refreshing&&!sbomLatest?<Card style={{marginTop:10}}><div style={{fontSize:10,color:C.muted}}>No SBOM snapshot available yet.</div></Card>:null}
    </Section>

    <Modal open={diffOpen} onClose={()=>setDiffOpen(false)} title="CBOM Diff (Latest vs Previous)">
      <div style={{fontSize:10,color:C.dim,marginBottom:8}}>
        Changes between the latest two CBOM snapshots for tenant {String(session?.tenantId||"-")}.
      </div>
      <Row3>
        <Card><div style={{fontSize:10,color:C.muted}}>Added</div><div style={{fontSize:20,color:C.green,fontWeight:700}}>{Number(diffData?.metrics?.added||0)}</div></Card>
        <Card><div style={{fontSize:10,color:C.muted}}>Removed</div><div style={{fontSize:20,color:C.red,fontWeight:700}}>{Number(diffData?.metrics?.removed||0)}</div></Card>
        <Card><div style={{fontSize:10,color:C.muted}}>Changed</div><div style={{fontSize:20,color:C.amber,fontWeight:700}}>{Number(diffData?.metrics?.changed||0)}</div></Card>
      </Row3>
      <div style={{height:8}}/>
      <Card style={{maxHeight:260,overflowY:"auto"}}>
        <div style={{fontSize:11,color:C.text,fontWeight:700,marginBottom:6}}>Algorithm delta</div>
        {Object.entries(diffData?.metrics?.algorithm_delta||{}).map(([alg,val])=><div key={alg} style={{display:"flex",justifyContent:"space-between",fontSize:10,padding:"3px 0",borderBottom:`1px solid ${C.border}`}}>
          <span style={{color:C.dim}}>{alg}</span>
          <span style={{color:Number(val)>=0?C.green:C.red,fontWeight:700}}>{`${Number(val)>=0?"+":""}${Number(val||0)}`}</span>
        </div>)}
        {!Object.keys(diffData?.metrics?.algorithm_delta||{}).length?<div style={{fontSize:10,color:C.muted}}>No algorithm distribution changes detected.</div>:null}
      </Card>
      <div style={{display:"flex",justifyContent:"flex-end",marginTop:10}}>
        <Btn onClick={()=>setDiffOpen(false)}>Close</Btn>
      </div>
    </Modal>

    <Modal open={depListOpen} onClose={()=>{setDepListOpen(false);setSelectedDepCategory("");}} title={`${depListTitle} Dependencies`}>
      <div style={{fontSize:10,color:C.dim,marginBottom:8}}>
        Clicked dependency count now opens the exact package list for this category.
      </div>
      <Inp
        value={depListFilter}
        onChange={(e:any)=>setDepListFilter(e.target.value)}
        placeholder="Search name, version, type, ecosystem..."
      />
      <div style={{height:8}}/>
      <Card style={{maxHeight:360,overflowY:"auto"}}>
        <div style={{display:"grid",gap:6}}>
          {filteredDepList.map((item:any,idx:number)=>{
            const key=String(item?.name||"").trim().toLowerCase();
            const vuln=componentVulnStats[key];
            const top=String(vuln?.top||"none");
            const tone=top==="critical"||top==="high"?"red":top==="medium"||top==="low"?"amber":"green";
            return <div key={`${String(item?.name||"dep")}-${String(item?.version||"")}-${idx}`} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"7px 0",borderBottom:`1px solid ${C.border}`}}>
              <div style={{display:"grid",gap:2}}>
                <div style={{fontSize:11,color:C.text,fontWeight:700}}>{String(item?.name||"-")}</div>
                <div style={{fontSize:10,color:C.dim}}>
                  {`${String(item?.version||"-")} • ${String(item?.type||"-")}${String(item?.ecosystem||"")?` • ${String(item?.ecosystem||"")}`:""}`}
                </div>
              </div>
              <div style={{display:"flex",alignItems:"center",gap:6}}>
                <B c={tone}>{vuln?`${Number(vuln.count||0)} CVEs`:"0 CVEs"}</B>
              </div>
            </div>;
          })}
          {!filteredDepList.length?<div style={{fontSize:10,color:C.muted}}>No dependencies found for current filter.</div>:null}
        </div>
      </Card>
      <div style={{display:"flex",justifyContent:"space-between",marginTop:10}}>
        <span style={{fontSize:10,color:C.muted}}>{`${filteredDepList.length} of ${depListItems.length} shown`}</span>
        <Btn onClick={()=>{setDepListOpen(false);setSelectedDepCategory("");}}>Close</Btn>
      </div>
    </Modal>

    <Modal open={cbomAssetListOpen} onClose={()=>{setCBOMAssetListOpen(false);setSelectedCBOMCategory("");}} title={cbomAssetListTitle||"CBOM Assets"}>
      <div style={{fontSize:10,color:C.dim,marginBottom:8}}>
        Filtered cryptographic assets from the current CBOM snapshot.
      </div>
      <Inp
        value={cbomAssetListFilter}
        onChange={(e:any)=>setCBOMAssetListFilter(e.target.value)}
        placeholder="Search name, id, algorithm, source, status..."
      />
      <div style={{height:8}}/>
      <Card style={{maxHeight:360,overflowY:"auto"}}>
        <div style={{display:"grid",gap:6}}>
          {filteredCBOMAssetList.map((asset:any,idx:number)=>{
            const tone=Boolean(asset?.deprecated)||isWeakLegacyAsset(asset)?"red":Boolean(asset?.pqc_ready)?"green":"blue";
            return <div key={`${String(asset?.id||"asset")}-${idx}`} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"7px 0",borderBottom:`1px solid ${C.border}`}}>
              <div style={{display:"grid",gap:2}}>
                <div style={{fontSize:11,color:C.text,fontWeight:700}}>{String(asset?.name||asset?.id||"-")}</div>
                <div style={{fontSize:10,color:C.dim}}>
                  {`${String(asset?.algorithm||"-")} • ${String(asset?.asset_type||"-")} • ${String(asset?.source||"-")} • ${Number(asset?.strength_bits||0)||"-"} bits`}
                </div>
              </div>
              <div style={{display:"flex",alignItems:"center",gap:6}}>
                <B c={tone}>{String(asset?.status||"unknown")}</B>
              </div>
            </div>;
          })}
          {!filteredCBOMAssetList.length?<div style={{fontSize:10,color:C.muted}}>No assets found for current filter.</div>:null}
        </div>
      </Card>
      <div style={{display:"flex",justifyContent:"space-between",marginTop:10}}>
        <span style={{fontSize:10,color:C.muted}}>{`${filteredCBOMAssetList.length} of ${cbomAssetListItems.length} shown`}</span>
        <Btn onClick={()=>{setCBOMAssetListOpen(false);setSelectedCBOMCategory("");}}>Close</Btn>
      </div>
    </Modal>
  </div>;
};


