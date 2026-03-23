// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { useState } from "react";
import { Btn } from "../legacyPrimitives";
import { BYOKTab } from "./BYOKTab";
import { HYOKTab } from "./HYOKTab";

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
  const BYOKView=BYOKTab;
  const HYOKView=HYOKTab;

  return <div>
    {showInlineSubTabs&&<div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap"}}>
      <Btn small primary={currentSubtab==="byok"} onClick={()=>selectSubtab("byok")}>BYOK</Btn>
      <Btn small primary={currentSubtab==="hyok"} onClick={()=>selectSubtab("hyok")}>HYOK</Btn>
    </div>}
    {currentSubtab==="hyok"
      ? <HYOKView session={session} keyCatalog={keyCatalog} onToast={onToast}/>
      : <BYOKView session={session} keyCatalog={keyCatalog} onToast={onToast}/>}
  </div>;
};
