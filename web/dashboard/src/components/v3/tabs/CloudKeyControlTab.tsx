// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { lazy, Suspense, useState } from "react";
import { Btn } from "../legacyPrimitives";
import { BYOKTab } from "./BYOKTab";
import { HYOKTab } from "./HYOKTab";

const EKMTab = lazy(() => import("./EKMTab").then(m => ({ default: m.EKMTab })));
const SubFallback = <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 200, fontSize: 12, color: "#888" }}>Loading...</div>;

export const CloudKeyControlTab=({
  session,
  keyCatalog,
  onToast,
  subView,
  onSubViewChange
})=>{
  const [cloudSubtab,setCloudSubtab]=useState("byok");
  const currentSubtab=String(subView||cloudSubtab||"byok");
  const selectSubtab=(next:string)=>{
    if(onSubViewChange){
      onSubViewChange(next);
      return;
    }
    setCloudSubtab(next);
  };
  const showInlineSubTabs=!onSubViewChange;

  return <div>
    {showInlineSubTabs&&<div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap"}}>
      <Btn small primary={currentSubtab==="byok"} onClick={()=>selectSubtab("byok")}>BYOK</Btn>
      <Btn small primary={currentSubtab==="hyok"} onClick={()=>selectSubtab("hyok")}>HYOK</Btn>
      <Btn small primary={currentSubtab==="google-cse"} onClick={()=>selectSubtab("google-cse")}>Google CSE</Btn>
      <Btn small primary={currentSubtab==="azure"} onClick={()=>selectSubtab("azure")}>Azure EKM</Btn>
    </div>}
    {currentSubtab==="hyok" && <HYOKTab session={session} keyCatalog={keyCatalog} onToast={onToast}/>}
    {(currentSubtab==="google-cse"||currentSubtab==="azure") && (
      <Suspense fallback={SubFallback}>
        <EKMTab session={session} keyCatalog={keyCatalog} onToast={onToast} subView={currentSubtab}/>
      </Suspense>
    )}
    {currentSubtab!=="hyok" && currentSubtab!=="google-cse" && currentSubtab!=="azure" && <BYOKTab session={session} keyCatalog={keyCatalog} onToast={onToast}/>}
  </div>;
};
