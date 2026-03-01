import { B, Btn, Card, FG, Inp, Row2, Section, Sel } from "../legacyPrimitives";
import { C } from "../theme";

type ClusterTabViewProps = {
  clusterView: string;
  loading: boolean;
  refresh: (silent?: boolean) => Promise<void>;
  nodes: any[];
  selectiveNote: string;
  strictRoleBadge: (role: string, status: string) => JSX.Element;
  statusMeta: (status: string) => any;
  clusterComponentLabel: (value: string) => string;
  roleBadge: (role: string, status: string) => JSX.Element;
  nodeStatusColor: (status: string) => string;
  roleDrafts: Record<string,string>;
  setRoleDrafts: (updater: any) => void;
  roleUpdatingNode: string;
  updateNodeRoleAction: (node: any) => Promise<void>;
  removeBusyNode: string;
  removeNodeAction: (node: any) => Promise<void>;
  summary: any;
  profileName: string;
  setProfileName: (value: string) => void;
  profileDescription: string;
  setProfileDescription: (value: string) => void;
  profileComponents: string[];
  toggleProfileComponent: (componentID: string) => void;
  profileDefault: boolean;
  setProfileDefault: (value: boolean) => void;
  savingProfile: boolean;
  saveProfile: () => Promise<void>;
  profiles: any[];
  removeProfile: (profile: any) => Promise<void>;
  directNodeForm: any;
  setDirectNodeForm: (updater: any) => void;
  profileComponentScope: (profileID: string) => string[];
  toggleDirectComponent: (componentID: string) => void;
  directNodeBusy: boolean;
  addExistingNode: () => Promise<void>;
  componentChoices: Array<{id:string;label:string}>;
};

export const ClusterTabView = ({
  clusterView,
  loading,
  refresh,
  nodes,
  selectiveNote,
  strictRoleBadge,
  statusMeta,
  clusterComponentLabel,
  roleBadge,
  nodeStatusColor,
  roleDrafts,
  setRoleDrafts,
  roleUpdatingNode,
  updateNodeRoleAction,
  removeBusyNode,
  removeNodeAction,
  summary,
  profileName,
  setProfileName,
  profileDescription,
  setProfileDescription,
  profileComponents,
  toggleProfileComponent,
  profileDefault,
  setProfileDefault,
  savingProfile,
  saveProfile,
  profiles,
  removeProfile,
  directNodeForm,
  setDirectNodeForm,
  profileComponentScope,
  toggleDirectComponent,
  directNodeBusy,
  addExistingNode,
  componentChoices
}: ClusterTabViewProps) => {
  if(clusterView==="health"){
    return <div>
      <Section
        title="Cluster Health"
        actions={<div style={{display:"flex",gap:8,alignItems:"center"}}>
          {loading?<B c="blue">Loading</B>:null}
          <Btn onClick={()=>void refresh(false)}>Refresh</Btn>
        </div>}
      >
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(290px,1fr))",gap:12}}>
          {nodes.map((node:any)=>{
            const role=String(node?.role||"follower").trim().toLowerCase();
            const status=String(node?.status||"unknown");
            const components=(Array.isArray(node?.enabled_components)?node.enabled_components:[]).map((item:any)=>String(item||"").trim()).filter(Boolean);
            return <div
              key={`cluster-health-${String(node?.id||Math.random())}`}
              style={{
                background:C.card,
                border:role==="leader"?`1px solid ${C.accent}`:`1px solid ${C.border}`,
                borderRadius:12,
                padding:14
              }}
            >
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:8}}>
                <div>
                  <div style={{fontSize:29/2,color:C.white,fontWeight:700,lineHeight:1.2}}>{String(node?.name||node?.id||"-")}</div>
                  <div style={{fontSize:10,color:C.muted,fontFamily:"'JetBrains Mono',monospace",marginTop:2}}>{String(node?.endpoint||"unknown")}</div>
                </div>
                {strictRoleBadge(role,status)}
              </div>
              <div style={{display:"flex",marginTop:8}}>
                <span style={{
                  display:"inline-flex",
                  alignItems:"center",
                  gap:6,
                  padding:"4px 10px",
                  borderRadius:999,
                  fontSize:10,
                  fontWeight:700,
                  color:statusMeta(status).color,
                  background:statusMeta(status).bg
                }}>
                  <span className={statusMeta(status).dotClass} style={{width:6,height:6,borderRadius:999,background:statusMeta(status).color}}/>
                  {statusMeta(status).label}
                </span>
              </div>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginTop:12}}>
                <div>
                  <div style={{fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>CPU</div>
                  <div style={{fontSize:24/2,color:C.white,fontWeight:700,marginTop:3}}>{Number(node?.cpu_percent||0).toFixed(1)}%</div>
                </div>
                <div>
                  <div style={{fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:1}}>RAM</div>
                  <div style={{fontSize:24/2,color:C.white,fontWeight:700,marginTop:3}}>{Number(node?.ram_gb||0).toFixed(1)} GB</div>
                </div>
              </div>
              <div style={{display:"flex",flexWrap:"wrap",gap:6,marginTop:12}}>
                {components.map((component:string)=><span key={`${String(node?.id||"node")}-strict-${component}`} style={{
                  border:`1px solid ${C.border}`,
                  borderRadius:999,
                  background:C.blueDim,
                  color:C.blue,
                  fontSize:11,
                  fontWeight:700,
                  padding:"4px 9px"
                }}>{clusterComponentLabel(component)}</span>)}
              </div>
            </div>;
          })}
        </div>
        {!nodes.length?<Card style={{marginTop:10}}><div style={{fontSize:10,color:C.dim}}>No cluster nodes discovered yet.</div></Card>:null}
        <div style={{
          marginTop:12,
          border:`1px solid ${C.borderHi}`,
          borderRadius:12,
          background:C.card,
          padding:"14px 16px"
        }}>
          <span style={{fontSize:12,color:C.accent,fontWeight:700}}>Selective Component Sync:</span>
          <span style={{fontSize:12,color:C.dim,marginLeft:6}}>{selectiveNote}</span>
        </div>
      </Section>
    </div>;
  }

  return <div>
    <Section
      title="Cluster Settings"
      actions={<div style={{display:"flex",gap:8,alignItems:"center"}}>
        {loading?<B c="blue">Loading</B>:null}
        <Btn onClick={()=>void refresh(false)}>Refresh</Btn>
      </div>}
    >
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(260px,1fr))",gap:10}}>
        {nodes.map((node:any)=>{
          const status=String(node?.status||"unknown");
          const components=(Array.isArray(node?.enabled_components)?node.enabled_components:[]).map((item:any)=>String(item||"").trim()).filter(Boolean);
          return <Card key={String(node?.id||Math.random())} style={{borderColor:C.borderHi,padding:12}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
              <div style={{fontSize:18,fontWeight:700,color:C.text}}>{String(node?.name||node?.id||"-")}</div>
              {roleBadge(String(node?.role||"follower"),status)}
            </div>
            <div style={{fontSize:10,color:C.dim,fontFamily:"'JetBrains Mono',monospace"}}>{String(node?.endpoint||"unknown")}</div>
            <div style={{marginTop:6}}>
              <span style={{
                display:"inline-flex",
                alignItems:"center",
                gap:6,
                padding:"3px 9px",
                borderRadius:999,
                fontSize:10,
                fontWeight:700,
                color:statusMeta(status).color,
                background:statusMeta(status).bg
              }}>
                <span className={statusMeta(status).dotClass} style={{width:6,height:6,borderRadius:999,background:statusMeta(status).color}}/>
                {statusMeta(status).label}
              </span>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginTop:8}}>
              <div>
                <div style={{fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:.7}}>CPU</div>
                <div style={{fontSize:16,color:C.text,fontWeight:700}}>{Number(node?.cpu_percent||0).toFixed(1)}%</div>
              </div>
              <div>
                <div style={{fontSize:9,color:C.muted,textTransform:"uppercase",letterSpacing:.7}}>RAM</div>
                <div style={{fontSize:16,color:C.text,fontWeight:700}}>{Number(node?.ram_gb||0).toFixed(1)} GB</div>
              </div>
            </div>
            <div style={{display:"flex",gap:6,flexWrap:"wrap",marginTop:10}}>
              {components.map((component:string)=><B key={`${String(node?.id||"node")}-${component}`} c={nodeStatusColor(String(node?.status||"unknown"))}>{clusterComponentLabel(component)}</B>)}
            </div>
            <div style={{display:"grid",gridTemplateColumns:"minmax(120px,1fr) auto auto",gap:6,marginTop:10,alignItems:"center"}}>
              <Sel
                value={String(roleDrafts[String(node?.id||"")]||node?.role||"follower").trim().toLowerCase()==="leader"?"leader":"follower"}
                onChange={(e)=>setRoleDrafts((prev:any)=>({...prev,[String(node?.id||"")]:e.target.value}))}
              >
                <option value="follower">Follower</option>
                <option value="leader">Leader</option>
              </Sel>
              <Btn
                small
                disabled={roleUpdatingNode===String(node?.id||"")||String(roleDrafts[String(node?.id||"")]||node?.role||"follower").trim().toLowerCase()===String(node?.role||"follower").trim().toLowerCase()}
                onClick={()=>void updateNodeRoleAction(node)}
              >
                {roleUpdatingNode===String(node?.id||"")?"Applying...":"Apply Role"}
              </Btn>
              <Btn
                small
                danger
                disabled={removeBusyNode===String(node?.id||"")}
                onClick={()=>void removeNodeAction(node)}
              >
                {removeBusyNode===String(node?.id||"")?"Removing...":"Remove"}
              </Btn>
            </div>
          </Card>;
        })}
      </div>
      {!nodes.length?<Card style={{marginTop:10}}><div style={{fontSize:10,color:C.dim}}>No nodes registered yet. Use Add Existing Instance to register cluster members.</div></Card>:null}
      <Card style={{marginTop:10,borderColor:C.borderHi}}>
        <div style={{fontSize:12,color:C.accent,fontWeight:700,marginBottom:3}}>Selective Component Sync</div>
        <div style={{fontSize:10,color:C.dim}}>{selectiveNote}</div>
      </Card>
      <div style={{display:"flex",gap:8,marginTop:8,flexWrap:"wrap"}}>
        <B c="blue">Leader: {String(summary?.leader_node_id||"not elected")}</B>
        <B c="green">Online: {Number(summary?.online_nodes||0)}</B>
        <B c="amber">Degraded: {Number(summary?.degraded_nodes||0)}</B>
        <B c="red">Down: {Number(summary?.down_nodes||0)}</B>
      </div>
    </Section>

    <Row2>
      <Card style={{padding:12}}>
        <div style={{fontSize:12,color:C.text,fontWeight:700,marginBottom:8}}>Cluster Replication Profiles</div>
        <FG label="Profile Name" required><Inp value={profileName} onChange={(e)=>setProfileName(e.target.value)} placeholder="payment-replication"/></FG>
        <FG label="Description"><Inp value={profileDescription} onChange={(e)=>setProfileDescription(e.target.value)} placeholder="Sync only base KMS + payment components"/></FG>
        <FG label="Components to Sync">
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:6}}>
            {componentChoices.map((component)=><label key={component.id} style={{display:"flex",gap:6,alignItems:"center",fontSize:10,color:C.dim}}>
              <input type="checkbox" checked={profileComponents.includes(component.id)} onChange={()=>toggleProfileComponent(component.id)}/>
              {component.label}
            </label>)}
          </div>
        </FG>
        <label style={{display:"flex",gap:6,alignItems:"center",fontSize:10,color:C.dim,marginTop:8}}>
          <input type="checkbox" checked={profileDefault} onChange={(e)=>setProfileDefault(Boolean(e.target.checked))}/>
          Set as default profile for new nodes
        </label>
        <div style={{display:"flex",justifyContent:"flex-end",marginTop:10}}>
          <Btn primary disabled={savingProfile} onClick={()=>void saveProfile()}>{savingProfile?"Saving...":"Save Profile"}</Btn>
        </div>
        <div style={{display:"grid",gap:8,marginTop:10}}>
          {profiles.map((profile:any)=><Card key={String(profile?.id||Math.random())} style={{padding:8,borderColor:C.border}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:8}}>
              <div>
                <div style={{fontSize:11,color:C.text,fontWeight:700}}>{String(profile?.name||profile?.id||"-")}</div>
                <div style={{fontSize:9,color:C.dim,fontFamily:"'JetBrains Mono',monospace"}}>{String(profile?.id||"-")}</div>
              </div>
              <div style={{display:"flex",alignItems:"center",gap:6}}>
                {profile?.is_default?<B c="green">Default</B>:null}
                {!profile?.is_default?<Btn small onClick={()=>void removeProfile(profile)}>Delete</Btn>:null}
              </div>
            </div>
            <div style={{display:"flex",flexWrap:"wrap",gap:4,marginTop:6}}>
              {(Array.isArray(profile?.components)?profile.components:[]).map((component:any)=><B key={`${String(profile?.id||"profile")}-${String(component)}`} c="blue">{clusterComponentLabel(String(component||""))}</B>)}
            </div>
          </Card>)}
        </div>
      </Card>

      <Card style={{padding:12}}>
        <div style={{fontSize:12,color:C.text,fontWeight:700,marginBottom:8}}>Add Existing Instance To Cluster</div>
        <FG label="Node ID" required><Inp value={directNodeForm.node_id} onChange={(e)=>setDirectNodeForm((p:any)=>({...p,node_id:e.target.value}))} placeholder="vecta-kms-03"/></FG>
        <FG label="Node Name"><Inp value={directNodeForm.node_name} onChange={(e)=>setDirectNodeForm((p:any)=>({...p,node_name:e.target.value}))} placeholder="vecta-kms-03"/></FG>
        <FG label="Node Endpoint"><Inp value={directNodeForm.endpoint} onChange={(e)=>setDirectNodeForm((p:any)=>({...p,endpoint:e.target.value}))} placeholder="10.0.2.100"/></FG>
        <FG label="Role">
          <Sel value={String(directNodeForm.role||"follower")} onChange={(e)=>setDirectNodeForm((p:any)=>({...p,role:e.target.value}))}>
            <option value="follower">Follower</option>
            <option value="leader">Leader</option>
          </Sel>
        </FG>
        <FG label="Replication Profile" required>
          <Sel
            value={String(directNodeForm.profile_id||"")}
            onChange={(e)=>{
              const nextProfileID=String(e.target.value||"");
              const allowed=profileComponentScope(nextProfileID);
              setDirectNodeForm((p:any)=>({...p,profile_id:nextProfileID,components:allowed}));
            }}
          >
            <option value="">Select profile</option>
            {profiles.map((profile:any)=><option key={`direct-${String(profile?.id||Math.random())}`} value={String(profile?.id||"")}>{String(profile?.name||profile?.id||"-")}</option>)}
          </Sel>
        </FG>
        <FG label="Sync Components (profile scope)">
          <div style={{display:"grid",gridTemplateColumns:"repeat(3,minmax(0,1fr))",gap:6}}>
            {profileComponentScope(String(directNodeForm?.profile_id||"")).map((componentID:string)=><label key={`direct-comp-${componentID}`} style={{display:"flex",gap:6,alignItems:"center",fontSize:10,color:C.dim}}>
              <input
                type="checkbox"
                checked={(Array.isArray(directNodeForm?.components)?directNodeForm.components:[]).map((value:any)=>String(value||"").trim().toLowerCase()).includes(componentID)}
                onChange={()=>toggleDirectComponent(componentID)}
              />
              {clusterComponentLabel(componentID)}
            </label>)}
          </div>
        </FG>
        <label style={{display:"flex",gap:6,alignItems:"center",fontSize:10,color:C.dim,marginTop:8}}>
          <input type="checkbox" checked={Boolean(directNodeForm?.seed_sync)} onChange={(e)=>setDirectNodeForm((p:any)=>({...p,seed_sync:Boolean(e.target.checked)}))}/>
          Seed realtime profile sync events immediately after add
        </label>
        <div style={{display:"flex",justifyContent:"flex-end",marginTop:10}}>
          <Btn primary disabled={directNodeBusy} onClick={()=>void addExistingNode()}>{directNodeBusy?"Adding...":"Add Existing KMS Instance"}</Btn>
        </div>
      </Card>
    </Row2>
  </div>;
};

