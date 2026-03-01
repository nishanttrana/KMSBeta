// @ts-nocheck
import { RestAPITab } from "../../components/v3/tabs/RestAPITab";
import { CryptoTab } from "./CryptoTab";
import { DataEncryptionTab, TokenizeTab } from "./TokenizeTab";
import { PaymentTab } from "./PaymentTab";

export const WorkbenchTab=({session,keyCatalog,onToast,subView,fipsMode})=>{
  const active=String(subView||"crypto");
  if(active==="restapi"){
    return <RestAPITab session={session} keyCatalog={keyCatalog} onToast={onToast}/>;
  }
  if(active==="tokenize"){
    return <TokenizeTab session={session} keyCatalog={keyCatalog} onToast={onToast}/>;
  }
  if(active==="dataenc"){
    return <DataEncryptionTab session={session} keyCatalog={keyCatalog} onToast={onToast}/>;
  }
  if(active==="payment"){
    return <PaymentTab session={session} keyCatalog={keyCatalog} onToast={onToast}/>;
  }
  return <CryptoTab session={session} keyCatalog={keyCatalog} onToast={onToast} fipsMode={fipsMode}/>;
};

