import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { B, Btn, Card, Chk, FG, Inp, Row2, Section, Sel, Txt } from "../../components/v3/legacyPrimitives";
import { errMsg } from "../../components/v3/runtimeUtils";
import { C } from "../../components/v3/theme";
import type { AuthSession } from "../../lib/auth";
import {
  createGovernanceBackup,
  deleteGovernanceBackup,
  downloadGovernanceBackupArtifact,
  downloadGovernanceBackupKey,
  governanceBackupKeyDownloadable,
  governanceBackupKeyRetained,
  listGovernanceBackups,
  restoreGovernanceBackup,
  verifyGovernanceBackup,
  type GovernanceBackupJob,
  type GovernanceBackupKeyFile,
  type GovernanceVerifyBackupResult
} from "../../lib/governance";
import { isSealedKeyFile, unsealKeyFile } from "../../lib/backupSchedules";

// Encrypted backups: create, verify, restore, download and delete
// (governance; root administrators only). Their one home is Backup & Restore
// (owner, 2026-10-20); until 13.26.0-beta they were a section of System
// Administration.

const tone=(status:string):"green"|"amber"|"red"|"blue"=>{
  const s=String(status||"").toLowerCase();
  if(s==="running") return "green";
  if(s==="restarting") return "amber";
  if(s==="degraded") return "amber";
  if(s==="down") return "red";
  return "blue";
};

const dl=(name:string,b64:string,type:string)=>{
  const raw=atob(String(b64||""));
  const bytes=new Uint8Array(raw.length);
  for(let i=0;i<raw.length;i+=1){bytes[i]=raw.charCodeAt(i);}  
  const blob=new Blob([bytes],{type:type||"application/octet-stream"});
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a");
  a.href=url; a.download=String(name||"download.bin");
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
};

const BACKUP_ARTIFACT_EXTENSION = ".vbk";
const BACKUP_KEY_EXTENSION = ".key.json";

const fileToBase64 = (file: File): Promise<string> =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("failed to read file"));
    reader.onload = () => {
      const raw = String(reader.result || "");
      const idx = raw.indexOf(",");
      resolve(idx >= 0 ? raw.slice(idx + 1) : raw);
    };
    reader.readAsDataURL(file);
  });

const formatBackupFileSize = (bytes: number): string => {
  const size = Math.max(0, Number(bytes || 0));
  if (size >= 1024 * 1024) {
    return `${(size / (1024 * 1024)).toFixed(1).replace(/\.0$/, "")} MB`;
  }
  if (size >= 1024) {
    return `${Math.max(1, Math.round(size / 1024))} KB`;
  }
  return `${size} B`;
};

const BackupRestoreFilePicker = ({
  accept,
  file,
  onFileChange,
  emptyLabel,
  hint
}: {
  accept: string;
  file: File | null;
  onFileChange: (file: File | null) => void;
  emptyLabel: string;
  hint: string;
}) => {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const hasFile = Boolean(file);

  return (
    <div style={{ display: "grid", gap: 8 }}>
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        onChange={(e) => onFileChange((e.target.files && e.target.files[0]) ? e.target.files[0] : null)}
        style={{ display: "none" }}
      />
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          minHeight: 72,
          padding: "12px 14px",
          borderRadius: 6,
          border: `1px solid ${hasFile ? C.accent : C.borderHi}`,
          background: hasFile ? C.accentDim : C.surface,
          boxShadow: hasFile
            ? `0 0 0 1px ${C.glow} inset, 0 12px 28px rgba(2,8,23,.35)`
            : `0 10px 22px rgba(2,8,23,.22)`,
          boxSizing: "border-box"
        }}
      >
        <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
          <Btn
            type="button"
            small
            primary
            onClick={() => inputRef.current?.click()}
            style={{
              padding: "8px 14px",
              borderRadius: 4,
              boxShadow: `0 0 18px ${C.glowStrong}`
            }}
          >
            {hasFile ? "Replace" : "Upload"}
          </Btn>
          {hasFile ? (
            <Btn
              type="button"
              small
              onClick={() => {
                onFileChange(null);
                if (inputRef.current) {
                  inputRef.current.value = "";
                }
              }}
              style={{
                borderColor: C.borderHi,
                color: C.dim,
                background: "rgba(15,21,33,.72)",
                borderRadius: 4,
                padding: "8px 12px"
              }}
            >
              Clear
            </Btn>
          ) : null}
        </div>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div
            style={{
              fontSize: 11,
              color: hasFile ? C.text : C.dim,
              fontWeight: hasFile ? 700 : 500,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap"
            }}
          >
            {hasFile ? file?.name : emptyLabel}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6, flexWrap: "wrap" }}>
            <B c={hasFile ? "accent" : "blue"}>{hasFile ? formatBackupFileSize(file?.size || 0) : accept}</B>
            <span style={{ fontSize: 10, color: C.muted }}>{hint}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export function EncryptedBackupsPanel({ session, onToast, onLogout }: {
  session: AuthSession | null;
  onToast: (message: string) => void;
  onLogout: () => void;
}) {
  const [jobs,setJobs]=useState<GovernanceBackupJob[]>([]);
  const [jobsLoading,setJobsLoading]=useState(false);
  const [backupCreating,setBackupCreating]=useState(false);
  const [backupDeleting,setBackupDeleting]=useState("");
  const [backupDownloading,setBackupDownloading]=useState("");
  const [backupScope,setBackupScope]=useState<"system"|"tenant">("system");
  const [backupTenant,setBackupTenant]=useState("");
  const [backupBindToHsm,setBackupBindToHsm]=useState(true);
  const [backupRestoreArtifactFile,setBackupRestoreArtifactFile]=useState<File|null>(null);
  const [backupRestoreKeyFile,setBackupRestoreKeyFile]=useState<File|null>(null);
  const [backupRestoreShareFiles,setBackupRestoreShareFiles]=useState<File[]>([]);
  const backupShareInputRef=useRef<HTMLInputElement|null>(null);
  const [backupSplit,setBackupSplit]=useState(false);
  const [backupGuardians,setBackupGuardians]=useState("");
  const [backupThreshold,setBackupThreshold]=useState(3);
  const [backupCreatedShares,setBackupCreatedShares]=useState<GovernanceBackupKeyFile[]>([]);
  const [backupRestoring,setBackupRestoring]=useState(false);
  const [backupVerifying,setBackupVerifying]=useState(false);
  const [backupVerifyResult,setBackupVerifyResult]=useState<GovernanceVerifyBackupResult|null>(null);
  // A scheduled backup's key file is sealed to the administrator's public
  // key: the private key opens it here, in the browser, and is never sent.
  const [keySealed,setKeySealed]=useState(false);
  const [privateKeyFile,setPrivateKeyFile]=useState<File|null>(null);
  useEffect(()=>{
    let live=true;
    setKeySealed(false);
    if(backupRestoreKeyFile) void fileToBase64(backupRestoreKeyFile).then((b64)=>{if(live) setKeySealed(isSealedKeyFile(b64));});
    return ()=>{live=false;};
  },[backupRestoreKeyFile]);

  const sessionGuard=useCallback((error:unknown)=>{
    const msg=errMsg(error).toLowerCase();
    if(msg.includes("invalid token")||msg.includes("unauthorized")){
      onToast("Session expired. Please login again.");
      onLogout();
      return true;
    }
    return false;
  },[onLogout,onToast]);

  const loadJobs=useCallback(async()=>{
    if(!session?.token){setJobs([]);return;}
    setJobsLoading(true);
    try{setJobs(await listGovernanceBackups(session,{limit:100}));}
    catch(error){if(!sessionGuard(error)) onToast(`Backup list load failed: ${errMsg(error)}`);} 
    finally{setJobsLoading(false);} 
  },[onToast,session,sessionGuard]);

  // Reads the selected artifact and key file (or guardian shares) into the
  // body restore and verify share; toasts and returns null if incomplete.
  const readBackupFiles=useCallback(async()=>{
    const useShares=backupRestoreShareFiles.length>0;
    if(!backupRestoreArtifactFile||(!useShares&&!backupRestoreKeyFile)){
      onToast("Select the backup artifact and its key package, or the guardian share files.");
      return null;
    }
    const artifactName=String(backupRestoreArtifactFile.name||"").trim();
    const keyFiles=useShares?backupRestoreShareFiles:[backupRestoreKeyFile as File];
    if(!artifactName.toLowerCase().endsWith(BACKUP_ARTIFACT_EXTENSION)){
      onToast(`Artifact must use ${BACKUP_ARTIFACT_EXTENSION} extension.`);
      return null;
    }
    if(keyFiles.some((f)=>!String(f.name||"").toLowerCase().endsWith(BACKUP_KEY_EXTENSION))){
      onToast(`Key files must use ${BACKUP_KEY_EXTENSION} extension.`);
      return null;
    }
    const [artifactB64,...keyB64s]=await Promise.all([fileToBase64(backupRestoreArtifactFile),...keyFiles.map(fileToBase64)]);
    if(!useShares&&isSealedKeyFile(String(keyB64s[0]||""))){
      if(!privateKeyFile){onToast("This key file is sealed: choose the private key that opens it."); return null;}
      try{keyB64s[0]=await unsealKeyFile(String(keyB64s[0]||""),await privateKeyFile.text());}
      catch(error){onToast(errMsg(error)); return null;}
    }
    return {
      artifact_file_name:artifactName,
      artifact_content_base64:artifactB64,
      ...(useShares
        ?{key_shares:keyFiles.map((f,i)=>({file_name:String(f.name||"").trim(),content_base64:String(keyB64s[i]||"")}))}
        :{key_file_name:String(keyFiles[0]?.name||"").trim(),key_content_base64:String(keyB64s[0]||"")})
    };
  },[backupRestoreArtifactFile,backupRestoreKeyFile,backupRestoreShareFiles,onToast,privateKeyFile]);

  const restoreBackup=useCallback(async()=>{
    if(!session?.token){return;}
    setBackupRestoring(true);
    try{
      const files=await readBackupFiles();
      if(!files) return;
      const out=await restoreGovernanceBackup(session,files);
      setBackupRestoreArtifactFile(null);
      setBackupRestoreKeyFile(null);
      setBackupRestoreShareFiles([]);
      setPrivateKeyFile(null);
      setBackupVerifyResult(null);
      onToast(`Backup restored. Rows: ${Number(out.rows_restored||0)} | Tables: ${Number(out.tables_processed||0)}.`);
      await loadJobs();
    }catch(error){
      if(!sessionGuard(error)) onToast(`Backup restore failed: ${errMsg(error)}`);
    }finally{
      setBackupRestoring(false);
    }
  },[loadJobs,onToast,readBackupFiles,session,sessionGuard]);

  const verifyBackup=useCallback(async()=>{
    if(!session?.token){return;}
    setBackupVerifying(true);
    setBackupVerifyResult(null);
    try{
      const files=await readBackupFiles();
      if(!files) return;
      const out=await verifyGovernanceBackup(session,files);
      setBackupVerifyResult(out);
      onToast("Backup verified: it opens with the key given. Nothing was restored.");
    }catch(error){
      if(!sessionGuard(error)) onToast(`Backup verification failed: ${errMsg(error)}`);
    }finally{
      setBackupVerifying(false);
    }
  },[onToast,readBackupFiles,session,sessionGuard]);

  const sortedJobs=useMemo(()=>[...jobs].sort((a,b)=>new Date(String(b.created_at||0)).getTime()-new Date(String(a.created_at||0)).getTime()),[jobs]);

  useEffect(()=>{ void loadJobs(); },[loadJobs]);

  return <>
    <Section title="Encrypted Backups" actions={<div style={{display:"flex",gap:6}}><Btn small onClick={()=>void loadJobs()}>{jobsLoading?"Refreshing...":"Refresh Jobs"}</Btn></div>}>
      <Card style={{padding:10,borderRadius:4,marginBottom:8}}>
        <div style={{fontSize:10,color:C.muted,marginBottom:8}}>Create Backup</div>
        <Row2><FG label="Scope"><Sel value={backupScope} onChange={(e)=>setBackupScope(String(e.target.value||"system") as "system"|"tenant")}><option value="system">System</option><option value="tenant">Tenant</option></Sel></FG><FG label="Target Tenant ID (tenant scope)"><Inp value={backupTenant} onChange={(e)=>setBackupTenant(e.target.value)} placeholder="tenant-id"/></FG></Row2>
        <Chk label="Bind backup key package to HSM (when configured)" checked={backupBindToHsm&&!backupSplit} onChange={()=>setBackupBindToHsm((v)=>!v)} disabled={backupSplit}/>
        <Chk label="Split the key among guardians (M-of-N shares)" checked={backupSplit} onChange={()=>setBackupSplit((v)=>!v)}/>
        {backupSplit&&<Row2>
          <FG label="Guardians (one per line)"><Txt rows={4} value={backupGuardians} onChange={(e)=>setBackupGuardians(e.target.value)} placeholder={"CISO\nHead of Legal\nCTO\nOps lead\nExternal notary"}/></FG>
          <FG label="Shares needed to restore"><Inp type="number" min={2} value={String(backupThreshold)} onChange={(e)=>setBackupThreshold(Math.max(2,Math.trunc(Number(e.target.value||2))))}/></FG>
        </Row2>}
        <div style={{fontSize:10,color:C.dim,marginTop:4}}>{backupSplit
          ?"Each guardian gets one share file. Any of them up to the number above restore the backup; fewer can't, and no one holds the whole key. The platform keeps no copy of the key or the shares. A split key is never HSM-bound."
          :"The key file downloads when the backup is created. Without an HSM binding the platform keeps no copy of the key: store the file safely, apart from the artifact."}</div>
        <div style={{display:"flex",justifyContent:"flex-end",alignItems:"center",marginTop:10}}><Btn small primary onClick={async()=>{
          if(!session?.token) return;
          if(backupScope==="tenant"&&!String(backupTenant||"").trim()){onToast("Provide target tenant ID for tenant scope backup."); return;}
          const guardians=backupGuardians.split(/\n|,/).map((g)=>g.trim()).filter(Boolean);
          if(backupSplit&&(guardians.length<2||backupThreshold<2||backupThreshold>guardians.length)){onToast("Name at least 2 guardians, and set shares needed between 2 and the number of guardians."); return;}
          setBackupCreating(true);
          try{
            const created=await createGovernanceBackup(session,{scope:backupScope,target_tenant_id:backupScope==="tenant"?String(backupTenant||"").trim():"",bind_to_hsm:backupBindToHsm,created_by:session.username,...(backupSplit?{key_split:{threshold:backupThreshold,guardians}}:{})});
            if(created.key_shares?.length){
              setBackupCreatedShares(created.key_shares);
              onToast(`Backup job created. Hand each guardian their share now: they are shown once, and any ${backupThreshold} of ${created.key_shares.length} restore the backup.`);
            }else if(created.key_file){
              dl(created.key_file.file_name,created.key_file.content_base64,created.key_file.content_type);
              onToast(governanceBackupKeyRetained(created.job)?"Backup job created. Its key file was saved.":"Backup job created. Its key file was saved: keep it safe, the platform does not keep a copy.");
            }
            await loadJobs();
          }catch(error){if(!sessionGuard(error)) onToast(`Backup create failed: ${errMsg(error)}`);} finally{setBackupCreating(false);}
        }} disabled={backupCreating}>{backupCreating?"Creating...":"Create Backup"}</Btn></div>
        {backupCreatedShares.length>0&&<div role="region" aria-label="Guardian key shares" style={{marginTop:10,padding:10,borderRadius:4,border:`1px solid ${C.amber}`,background:C.amberDim}}>
          <div style={{fontSize:11,fontWeight:700,color:C.text,marginBottom:4}}>Guardian key shares: shown once</div>
          <div data-keep="" style={{fontSize:10,color:C.dim,marginBottom:8}}>Give each file to its guardian only. Close this panel once every share is handed out; the platform can't produce them again.</div>
          {backupCreatedShares.map((sh)=>(
            <div key={sh.file_name} style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8,padding:"4px 0",borderTop:`1px solid ${C.border}`}}>
              <span style={{fontSize:11,color:C.text}}>{`Share ${sh.share_index} · ${sh.guardian}`}</span>
              <Btn small onClick={()=>dl(sh.file_name,sh.content_base64,sh.content_type)}>Download</Btn>
            </div>
          ))}
          <div style={{display:"flex",justifyContent:"flex-end",marginTop:8}}><Btn small onClick={()=>setBackupCreatedShares([])}>All shares handed out: close</Btn></div>
        </div>}
      </Card>
      <Card style={{padding:10,borderRadius:4,marginBottom:8}}>
        <div style={{fontSize:10,color:C.muted,marginBottom:8}}>Restore Backup</div>
        <Row2>
          <FG label={`Artifact (${BACKUP_ARTIFACT_EXTENSION})`}>
            <BackupRestoreFilePicker
              accept={BACKUP_ARTIFACT_EXTENSION}
              file={backupRestoreArtifactFile}
              onFileChange={setBackupRestoreArtifactFile}
              emptyLabel="Upload encrypted backup artifact"
              hint="Encrypted Vecta backup bundle"
            />
          </FG>
          <FG label={`Key Package (${BACKUP_KEY_EXTENSION})`}>
            <BackupRestoreFilePicker
              accept=".json,.key.json"
              file={backupRestoreKeyFile}
              onFileChange={setBackupRestoreKeyFile}
              emptyLabel="Upload companion key package"
              hint="JSON key material envelope"
            />
          </FG>
        </Row2>
        {keySealed&&<div style={{marginTop:8}}><FG label="Private key (PEM): opened in this browser, never sent">
          <BackupRestoreFilePicker
            accept=".pem,.key"
            file={privateKeyFile}
            onFileChange={setPrivateKeyFile}
            emptyLabel="Upload the private key the schedule's backups are sealed to"
            hint="PKCS#8 (BEGIN PRIVATE KEY)"
          />
        </FG></div>}
        <div style={{display:"flex",alignItems:"center",gap:8,marginTop:8,fontSize:10,color:C.dim}}>
          <input ref={backupShareInputRef} type="file" accept=".json,.key.json" multiple style={{display:"none"}} onChange={(e)=>setBackupRestoreShareFiles(Array.from(e.target.files||[]))}/>
          <span>Split key? Upload the guardians' share files instead of a key package.</span>
          <Btn small type="button" onClick={()=>backupShareInputRef.current?.click()}>{backupRestoreShareFiles.length?"Replace share files":"Upload share files"}</Btn>
          {backupRestoreShareFiles.length>0&&<Btn small type="button" onClick={()=>{setBackupRestoreShareFiles([]); if(backupShareInputRef.current) backupShareInputRef.current.value="";}}>Clear</Btn>}
        </div>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginTop:10,gap:10}}>
          <div style={{fontSize:10,color:C.dim,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{`${backupRestoreArtifactFile?.name||"artifact not selected"} | ${backupRestoreShareFiles.length?`${backupRestoreShareFiles.length} guardian share file(s)`:backupRestoreKeyFile?.name||"key package not selected"}`}</div>
          <div style={{display:"flex",gap:6,flexShrink:0}}>
            <Btn small onClick={()=>void verifyBackup()} disabled={backupVerifying||backupRestoring}>{backupVerifying?"Verifying...":"Verify Backup"}</Btn>
            <Btn small primary onClick={()=>void restoreBackup()} disabled={backupRestoring||backupVerifying}>{backupRestoring?"Restoring...":"Restore Backup"}</Btn>
          </div>
        </div>
        <div className="vk-fold" tabIndex={0} style={{fontSize:10,color:C.dim,marginTop:6}}>Verify opens the backup with the key file or guardian shares and reports what it holds, without changing any data. Use it to prove your backups and keys still work.</div>
        {backupVerifyResult&&<div role="status" style={{marginTop:8,padding:10,borderRadius:4,border:`1px solid ${C.green}`,background:C.greenDim,fontSize:11,color:C.text}}>
          <div style={{fontWeight:700,marginBottom:4}}>Backup opens: verified</div>
          <div>{`Scope ${backupVerifyResult.scope}${backupVerifyResult.target_tenant_id?` (${backupVerifyResult.target_tenant_id})`:""} · captured ${backupVerifyResult.backup_captured_at||"unknown"}`}</div>
          <div>{`${backupVerifyResult.table_count} tables · ${backupVerifyResult.row_count_total} rows · opened in ${backupVerifyResult.elapsed_ms} ms`}</div>
          <div>{backupVerifyResult.key_source==="guardian_shares"?`Key rebuilt from shares of: ${(backupVerifyResult.share_guardians||[]).join(", ")}`:"Key: key file"}</div>
          <div data-keep="" style={{color:C.dim,marginTop:4}}>No data was changed. A restore also needs each service to re-wrap rows under retired master keys; it checks that before applying anything.</div>
        </div>}
      </Card>
      <Card style={{marginTop:8,padding:10,borderRadius:4}}>
        <div style={{display:"grid",gridTemplateColumns:"1.2fr 0.8fr 0.8fr 0.8fr 1fr",gap:8,paddingBottom:8,borderBottom:`1px solid ${C.border}`}}>{["Backup","Scope","Status","Rows","Actions"].map((h)=><div key={h} style={{fontSize: 10,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>{h}</div>)}</div>
        {sortedJobs.map((job)=>{const id=String(job.id||""); const st=String(job.status||"unknown"); return <div key={id} style={{display:"grid",gridTemplateColumns:"1.2fr 0.8fr 0.8fr 0.8fr 1fr",gap:8,alignItems:"center",borderBottom:`1px solid ${C.border}`,padding:"9px 0"}}><div style={{minWidth:0}}><div style={{fontSize:12,color:C.text,fontWeight:700,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{id}</div><div style={{fontSize:10,color:C.dim}}>{`${String(job.created_at||"-")}${job.schedule_id?" · scheduled":""}`}</div></div><div style={{fontSize:11,color:C.text}}>{String(job.scope||"-")}</div><div style={{fontSize:11,color:C[tone(st)]}}>{st}</div><div style={{fontSize:11,color:C.text}}>{Number(job.row_count_total||0)}</div><div style={{display:"flex",gap:6,flexWrap:"wrap",justifyContent:"flex-end"}}><Btn small onClick={async()=>{if(!session?.token||!id) return; setBackupDownloading(`${id}:artifact`); try{const p=await downloadGovernanceBackupArtifact(session,id); dl(p.file_name,p.content_base64,p.content_type); onToast("Backup artifact downloaded.");}catch(error){if(!sessionGuard(error)) onToast(`Backup download failed: ${errMsg(error)}`);} finally{setBackupDownloading("");}}} disabled={backupDownloading===`${id}:artifact`}>Artifact</Btn>{governanceBackupKeyDownloadable(job)&&<Btn small onClick={async()=>{if(!session?.token||!id) return; setBackupDownloading(`${id}:key`); try{const p=await downloadGovernanceBackupKey(session,id); dl(p.file_name,p.content_base64,p.content_type); onToast("Backup key package downloaded.");}catch(error){if(!sessionGuard(error)) onToast(`Backup download failed: ${errMsg(error)}`);} finally{setBackupDownloading("");}}} disabled={backupDownloading===`${id}:key`}>Key</Btn>}<Btn small danger onClick={async()=>{if(!session?.token||!id) return; setBackupDeleting(id); try{await deleteGovernanceBackup(session,id,session.username); onToast("Backup deleted."); await loadJobs();}catch(error){if(!sessionGuard(error)) onToast(`Backup delete failed: ${errMsg(error)}`);} finally{setBackupDeleting("");}}} disabled={backupDeleting===id}>Delete</Btn></div></div>;})}
        {!sortedJobs.length?<div style={{fontSize:10,color:C.muted,paddingTop:10}}>No backups found.</div>:null}
      </Card>
    </Section>
  </>;
}
