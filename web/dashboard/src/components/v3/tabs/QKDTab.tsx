// @ts-nocheck
import { useEffect, useMemo, useState } from "react";
import {
  getQKDConfig,
  getQKDOverview,
  injectQKDKey,
  listQKDKeys,
  listQKDLogs,
  runQKDTestGenerate,
  updateQKDConfig
} from "../../../lib/qkd";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { B, Bar, Btn, Card, Chk, FG, Inp, Modal, Row2, Row3, Section, Sel, Stat } from "../legacyPrimitives";
export const QKDTab=({session,onToast})=>{
  const [modal,setModal]=useState<null|"config"|"inject"|"keys">(null);
  const [loading,setLoading]=useState(false);
  const [refreshing,setRefreshing]=useState(false);
  const [savingConfig,setSavingConfig]=useState(false);
  const [runningTest,setRunningTest]=useState(false);
  const [injecting,setInjecting]=useState(false);
  const [slaveSAEID,setSlaveSAEID]=useState("");
  const [overview,setOverview]=useState<any>(null);
  const [qkdConfig,setQKDConfig]=useState<any>(null);
  const [configDraft,setConfigDraft]=useState<any>({
    qber_threshold:0.11,
    pool_low_threshold:10,
    pool_capacity:1250000,
    auto_inject:false,
    service_enabled:true,
    etsi_api_enabled:true,
    protocol:"ETSI GS QKD 014",
    distance_km:47
  });
  const [keys,setKeys]=useState<any[]>([]);
  const [logs,setLogs]=useState<any[]>([]);
  const [selectedKeyID,setSelectedKeyID]=useState("");
  const [injectPurpose,setInjectPurpose]=useState("encrypt");
  const [injectConsume,setInjectConsume]=useState(true);
  const [testCount,setTestCount]=useState("64");
  const [testKeyBits,setTestKeyBits]=useState("256");
  const [testQberMin,setTestQberMin]=useState("0.01");
  const [testQberMax,setTestQberMax]=useState("0.08");

  const activeSlave=String(overview?.slave_sae_id||slaveSAEID||"");
  const loadData=async(silent=false)=>{
    if(!session?.token){
      return;
    }
    if(!silent){
      setLoading(true);
    }else{
      setRefreshing(true);
    }
    try{
      const [cfg,ov]=await Promise.all([
        getQKDConfig(session),
        getQKDOverview(session,slaveSAEID||"")
      ]);
      const slave=String(ov?.slave_sae_id||slaveSAEID||"");
      const [keyItems,logItems]=await Promise.all([
        slave?listQKDKeys(session,{slave_sae_id:slave,status:["available","reserved","injected"],limit:300}):Promise.resolve([]),
        listQKDLogs(session,120)
      ]);
      setQKDConfig(cfg);
      setOverview(ov);
      setKeys(Array.isArray(keyItems)?keyItems:[]);
      setLogs(Array.isArray(logItems)?logItems:[]);
      if(slave&&!slaveSAEID){
        setSlaveSAEID(slave);
      }
      const firstInjectable=(Array.isArray(keyItems)?keyItems:[]).find((item)=>String(item?.status||"").toLowerCase()==="available"||String(item?.status||"").toLowerCase()==="reserved");
      setSelectedKeyID(String(firstInjectable?.id||""));
    }catch(error){
      onToast?.(`QKD load failed: ${errMsg(error)}`);
    }finally{
      if(!silent){
        setLoading(false);
      }else{
        setRefreshing(false);
      }
    }
  };

  useEffect(()=>{
    if(!session?.token){
      return;
    }
    void loadData(false);
    const id=setInterval(()=>{void loadData(true);},15000);
    return()=>clearInterval(id);
  },[session?.token,session?.tenantId,slaveSAEID]);

  const openConfig=()=>{
    setConfigDraft({
      qber_threshold:Number(qkdConfig?.qber_threshold||0.11),
      pool_low_threshold:Number(qkdConfig?.pool_low_threshold||10),
      pool_capacity:Number(qkdConfig?.pool_capacity||1250000),
      auto_inject:Boolean(qkdConfig?.auto_inject),
      service_enabled:Boolean(qkdConfig?.service_enabled),
      etsi_api_enabled:Boolean(qkdConfig?.etsi_api_enabled),
      protocol:String(qkdConfig?.protocol||"ETSI GS QKD 014"),
      distance_km:Number(qkdConfig?.distance_km||47)
    });
    setModal("config");
  };

  const saveConfig=async()=>{
    if(!session?.token){
      return;
    }
    setSavingConfig(true);
    try{
      const updated=await updateQKDConfig(session,{
        qber_threshold:Math.max(0,Math.min(1,Number(configDraft.qber_threshold||0.11))),
        pool_low_threshold:Math.max(1,Math.trunc(Number(configDraft.pool_low_threshold||10))),
        pool_capacity:Math.max(1,Math.trunc(Number(configDraft.pool_capacity||1250000))),
        auto_inject:Boolean(configDraft.auto_inject),
        service_enabled:Boolean(configDraft.service_enabled),
        etsi_api_enabled:Boolean(configDraft.etsi_api_enabled),
        protocol:String(configDraft.protocol||"ETSI GS QKD 014").trim()||"ETSI GS QKD 014",
        distance_km:Math.max(0,Number(configDraft.distance_km||47))
      });
      setQKDConfig(updated);
      onToast?.("QKD runtime configuration updated.");
      setModal(null);
      await loadData(true);
    }catch(error){
      onToast?.(`QKD config update failed: ${errMsg(error)}`);
    }finally{
      setSavingConfig(false);
    }
  };

  const runSelfTest=async()=>{
    if(!session?.token){
      return;
    }
    if(!activeSlave){
      onToast?.("Set a slave SAE ID first.");
      return;
    }
    setRunningTest(true);
    try{
      const result=await runQKDTestGenerate(session,{
        slave_sae_id:activeSlave,
        device_id:`selftest-${activeSlave}`,
        device_name:`QKD SelfTest ${activeSlave}`,
        role:"peer",
        link_status:"up",
        count:Math.max(1,Math.min(500,Math.trunc(Number(testCount||64)))),
        key_size_bits:Math.max(128,Math.min(4096,Math.trunc(Number(testKeyBits||256)))),
        qber_min:Math.max(0,Math.min(1,Number(testQberMin||0.01))),
        qber_max:Math.max(0,Math.min(1,Number(testQberMax||0.08)))
      });
      onToast?.(`QKD test complete: accepted ${Number(result?.accepted_count||0)}, discarded ${Number(result?.discarded_count||0)}.`);
      await loadData(true);
    }catch(error){
      onToast?.(`QKD test failed: ${errMsg(error)}`);
    }finally{
      setRunningTest(false);
    }
  };

  const injectSelected=async()=>{
    if(!session?.token){
      return;
    }
    const keyID=String(selectedKeyID||"").trim();
    if(!keyID){
      onToast?.("Select a QKD key ID.");
      return;
    }
    setInjecting(true);
    try{
      const out=await injectQKDKey(session,keyID,{
        name:`qkd-${keyID}`,
        purpose:injectPurpose,
        consume:injectConsume
      });
      onToast?.(`Injected ${out.qkd_key_id} -> ${out.keycore_key_id}`);
      setModal(null);
      await loadData(true);
    }catch(error){
      onToast?.(`QKD inject failed: ${errMsg(error)}`);
    }finally{
      setInjecting(false);
    }
  };

  const poolAvailable=Number(overview?.pool?.available_keys||0);
  const poolPct=Math.max(0,Math.min(100,Number(overview?.pool?.pool_fill_pct||0)));
  const usedToday=Number(overview?.pool?.used_today||0);
  const createdToday=Number(overview?.status?.keys_received_today||0);
  const qberAvg=Number(overview?.status?.qber_avg||0);
  const keyRate=Number(overview?.status?.key_rate||0);
  const active=Boolean(overview?.status?.active);
  const serviceEnabled=Boolean(overview?.config?.service_enabled);
  const etsiEnabled=Boolean(overview?.config?.etsi_api_enabled);

  return <div>
    <Section
      title="QKD Interface"
      actions={<div style={{display:"flex",gap:8,alignItems:"center"}}>
        <Inp
          w={180}
          placeholder="slave_sae_id"
          value={slaveSAEID}
          onChange={(e)=>setSlaveSAEID(e.target.value)}
          mono
        />
        <Btn small onClick={()=>void loadData(false)} disabled={loading||refreshing}>{loading||refreshing?"Refreshing...":"Refresh"}</Btn>
        <Btn small onClick={openConfig}>Configure</Btn>
        <Btn small primary onClick={()=>void runSelfTest()} disabled={runningTest||!serviceEnabled}>{runningTest?"Testing...":"Run QKD Test"}</Btn>
      </div>}
    >
      <Row2>
        <Card>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
            <div style={{fontSize:13,color:C.text,fontWeight:700}}>QKD Link Status</div>
            <B c={active&&serviceEnabled&&etsiEnabled?"green":"red"}>{active&&serviceEnabled&&etsiEnabled?"Active":"Inactive"}</B>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"4px 14px"}}>
            {[["Protocol",String(overview?.config?.protocol||qkdConfig?.protocol||"ETSI GS QKD 014")],["Status",active?"Key streaming":"Link down"],["Source",String(overview?.status?.source||"-")],["Destination",String(overview?.status?.destination||"-")],["Key Rate",`${keyRate.toFixed(3)} keys/sec`],["QBER",`${(qberAvg*100).toFixed(2)}% (OK < ${(Number(overview?.config?.qber_threshold||qkdConfig?.qber_threshold||0.11)*100).toFixed(2)}%)`],["Distance",`${Number(overview?.config?.distance_km||qkdConfig?.distance_km||47).toFixed(1)} km fiber`],["Keys Received",`${createdToday} (today)`]].map(([k,v])=>
              <div key={k} style={{display:"flex",justifyContent:"space-between",fontSize:10,padding:"2px 0",gap:8}}>
                <span style={{color:C.muted}}>{k}</span>
                <span style={{color:C.text,fontFamily:"'JetBrains Mono',monospace",textAlign:"right"}}>{v}</span>
              </div>
            )}
          </div>
          <div style={{display:"flex",gap:6,marginTop:8,flexWrap:"wrap"}}>
            <B c={serviceEnabled?"green":"red"}>{serviceEnabled?"Service ON":"Service OFF"}</B>
            <B c={etsiEnabled?"blue":"amber"}>{etsiEnabled?"ETSI API ON":"ETSI API OFF"}</B>
          </div>
        </Card>

        <Card>
          <div style={{fontSize:13,color:C.text,fontWeight:700,marginBottom:8}}>QKD Key Pool</div>
          <div style={{fontSize:46,lineHeight:1,color:C.green,fontWeight:700,letterSpacing:1,textAlign:"center"}}>
            {poolAvailable.toLocaleString()}
          </div>
          <div style={{fontSize:11,color:C.dim,textAlign:"center",marginBottom:10}}>available quantum keys</div>
          <Bar pct={poolPct} color={Number(overview?.pool?.low)?C.red:C.green}/>
          <div style={{display:"flex",justifyContent:"space-between",fontSize:10,color:C.dim,marginTop:6}}>
            <span>{`Used today: ${usedToday.toLocaleString()}`}</span>
            <span>{`Pool: ${poolPct.toFixed(1)}% full`}</span>
          </div>
          <div style={{display:"flex",gap:8,marginTop:10}}>
            <Btn small primary onClick={()=>setModal("inject")} disabled={!serviceEnabled||!keys.length}>Inject into Key Core</Btn>
            <Btn small onClick={()=>setModal("keys")} disabled={!keys.length}>View Key IDs</Btn>
          </div>
        </Card>
      </Row2>
      <div style={{height:10}}/>
      <Card>
        <div style={{fontSize:11,color:C.muted,fontWeight:700,marginBottom:4}}>ETSI GS QKD 004 - Key Delivery API</div>
        <div style={{fontSize:11,color:C.dim}}>
          QKD-derived keys are delivered through ETSI REST endpoints and can be injected into KeyCore as AES-256 keys with source labels.
        </div>
      </Card>
    </Section>

    <Section title="QKD Logs" actions={<Btn small onClick={()=>void loadData(true)} disabled={refreshing}>{refreshing?"Refreshing...":"Refresh Logs"}</Btn>}>
      <Card style={{padding:0,overflow:"hidden"}}>
        <div style={{display:"grid",gridTemplateColumns:"160px 140px 100px 1fr",padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>
          <div>Time</div><div>Action</div><div>Level</div><div>Message</div>
        </div>
        <div style={{maxHeight:220,overflowY:"auto"}}>
          {logs.map((item)=>(
            <div key={item.id} style={{display:"grid",gridTemplateColumns:"160px 140px 100px 1fr",padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:10,alignItems:"center"}}>
              <div style={{color:C.dim,fontFamily:"'JetBrains Mono',monospace"}}>{item.created_at?new Date(item.created_at).toLocaleString():"-"}</div>
              <div style={{color:C.accent,fontFamily:"'JetBrains Mono',monospace"}}>{String(item.action||"-")}</div>
              <div><B c={String(item.level||"info").toLowerCase()==="error"?"red":String(item.level||"info").toLowerCase()==="warn"?"amber":"blue"}>{String(item.level||"info")}</B></div>
              <div style={{color:C.text}}>{String(item.message||"-")}</div>
            </div>
          ))}
          {!logs.length&&<div style={{padding:"12px",fontSize:10,color:C.dim}}>{loading?"Loading QKD logs...":"No QKD logs yet."}</div>}
        </div>
      </Card>
    </Section>

    <Modal open={modal==="config"} onClose={()=>setModal(null)} title="Configure QKD Interface" wide>
      <Row2>
        <FG label="Protocol"><Inp value={String(configDraft.protocol||"")} onChange={(e)=>setConfigDraft((prev:any)=>({...prev,protocol:e.target.value}))}/></FG>
        <FG label="Distance (km)"><Inp type="number" min={0} value={String(configDraft.distance_km||47)} onChange={(e)=>setConfigDraft((prev:any)=>({...prev,distance_km:Number(e.target.value||47)}))}/></FG>
      </Row2>
      <Row2>
        <FG label="QBER Threshold"><Inp type="number" step="0.0001" min={0} max={1} value={String(configDraft.qber_threshold||0.11)} onChange={(e)=>setConfigDraft((prev:any)=>({...prev,qber_threshold:Number(e.target.value||0.11)}))}/></FG>
        <FG label="Pool Low Threshold"><Inp type="number" min={1} value={String(configDraft.pool_low_threshold||10)} onChange={(e)=>setConfigDraft((prev:any)=>({...prev,pool_low_threshold:Number(e.target.value||10)}))}/></FG>
      </Row2>
      <Row2>
        <FG label="Pool Capacity"><Inp type="number" min={1} value={String(configDraft.pool_capacity||1250000)} onChange={(e)=>setConfigDraft((prev:any)=>({...prev,pool_capacity:Number(e.target.value||1250000)}))}/></FG>
        <FG label="Auto Inject"><Chk label="Inject accepted keys to KeyCore automatically" checked={Boolean(configDraft.auto_inject)} onChange={()=>setConfigDraft((prev:any)=>({...prev,auto_inject:!Boolean(prev.auto_inject)}))}/></FG>
      </Row2>
      <FG label="Runtime Toggles">
        <Chk label="Enable QKD service" checked={Boolean(configDraft.service_enabled)} onChange={()=>setConfigDraft((prev:any)=>({...prev,service_enabled:!Boolean(prev.service_enabled)}))}/>
        <Chk label="Enable ETSI QKD API endpoints" checked={Boolean(configDraft.etsi_api_enabled)} onChange={()=>setConfigDraft((prev:any)=>({...prev,etsi_api_enabled:!Boolean(prev.etsi_api_enabled)}))}/>
      </FG>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)} disabled={savingConfig}>Cancel</Btn>
        <Btn primary onClick={()=>void saveConfig()} disabled={savingConfig}>{savingConfig?"Saving...":"Save Configuration"}</Btn>
      </div>
    </Modal>

    <Modal open={modal==="inject"} onClose={()=>setModal(null)} title="Inject QKD Key into Key Core">
      <FG label="QKD Key ID" required>
        <Sel value={selectedKeyID} onChange={(e)=>setSelectedKeyID(e.target.value)}>
          {keys.filter((item)=>String(item.status||"").toLowerCase()==="available"||String(item.status||"").toLowerCase()==="reserved").map((item)=><option key={item.id} value={item.id}>{`${item.id} (${item.status})`}</option>)}
          {!keys.some((item)=>String(item.status||"").toLowerCase()==="available"||String(item.status||"").toLowerCase()==="reserved")&&<option value="">No injectable keys</option>}
        </Sel>
      </FG>
      <Row2>
        <FG label="Purpose">
          <Sel value={injectPurpose} onChange={(e)=>setInjectPurpose(e.target.value)}>
            <option value="encrypt">Encrypt</option>
            <option value="decrypt">Decrypt</option>
            <option value="wrap">Wrap</option>
          </Sel>
        </FG>
        <FG label="Options">
          <Chk label="Consume key after injection" checked={injectConsume} onChange={()=>setInjectConsume((v)=>!v)}/>
        </FG>
      </Row2>
      <div style={{display:"flex",justifyContent:"flex-end",gap:8,marginTop:12}}>
        <Btn onClick={()=>setModal(null)} disabled={injecting}>Cancel</Btn>
        <Btn primary onClick={()=>void injectSelected()} disabled={injecting||!selectedKeyID}>{injecting?"Injecting...":"Inject Key"}</Btn>
      </div>
    </Modal>

    <Modal open={modal==="keys"} onClose={()=>setModal(null)} title={`QKD Key IDs${activeSlave?` - ${activeSlave}`:""}`} wide>
      <FG label="Self-Test Generator" hint="Generates cryptographically random test keys and ingests via ETSI enc_keys path.">
        <Row3>
          <Inp type="number" min={1} max={500} value={testCount} onChange={(e)=>setTestCount(e.target.value)} placeholder="Count"/>
          <Inp type="number" min={128} max={4096} step={8} value={testKeyBits} onChange={(e)=>setTestKeyBits(e.target.value)} placeholder="Key bits"/>
          <Btn primary onClick={()=>void runSelfTest()} disabled={runningTest||!serviceEnabled}>{runningTest?"Running...":"Run Test"}</Btn>
        </Row3>
        <Row2>
          <Inp type="number" step="0.0001" min={0} max={1} value={testQberMin} onChange={(e)=>setTestQberMin(e.target.value)} placeholder="QBER min"/>
          <Inp type="number" step="0.0001" min={0} max={1} value={testQberMax} onChange={(e)=>setTestQberMax(e.target.value)} placeholder="QBER max"/>
        </Row2>
      </FG>
      <Card style={{padding:0,overflow:"hidden"}}>
        <div style={{display:"grid",gridTemplateColumns:"1.6fr .8fr .6fr .8fr",padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>
          <div>Key ID</div><div>Status</div><div>QBER</div><div>Created</div>
        </div>
        <div style={{maxHeight:280,overflowY:"auto"}}>
          {keys.map((item)=>(
            <div key={item.id} style={{display:"grid",gridTemplateColumns:"1.6fr .8fr .6fr .8fr",padding:"8px 12px",borderBottom:`1px solid ${C.border}`,fontSize:10}}>
              <div style={{color:C.text,fontFamily:"'JetBrains Mono',monospace"}}>{item.id}</div>
              <div><B c={String(item.status||"").toLowerCase()==="available"?"green":String(item.status||"").toLowerCase()==="discarded"?"red":"blue"}>{item.status}</B></div>
              <div style={{color:C.dim}}>{`${(Number(item.qber||0)*100).toFixed(3)}%`}</div>
              <div style={{color:C.dim}}>{item.created_at?new Date(item.created_at).toLocaleString():"-"}</div>
            </div>
          ))}
          {!keys.length&&<div style={{padding:"12px",fontSize:10,color:C.dim}}>No QKD keys in pool.</div>}
        </div>
      </Card>
      <div style={{display:"flex",justifyContent:"flex-end",marginTop:10}}>
        <Btn onClick={()=>setModal(null)}>Close</Btn>
      </div>
    </Modal>
  </div>;
};




