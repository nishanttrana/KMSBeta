// @ts-nocheck
import { C } from "../theme";
import { Btn, Inp, Sel } from "../legacyPrimitives";

export const AuditLogTab=()=><div>
  <div style={{display:"flex",gap:6,marginBottom:10}}><Inp placeholder="Search audit events..." w={240}/>
    <Sel w={120}><option>All Services</option><option>kms-keycore</option><option>kms-auth</option><option>kms-payment</option><option>kms-pkcs11</option></Sel>
    <Sel w={100}><option>All Results</option><option>Success</option><option>Failure</option><option>Denied</option></Sel>
    <Sel w={100}><option>Last 24h</option><option>Last 7d</option><option>Last 30d</option></Sel>
    <Btn small>Export CSV</Btn><Btn small>Export CEF</Btn><Btn small primary>Verify Chain</Btn>
  </div>
  <div style={{fontSize:10,color:C.green}}>250+ event types - Hash chain: intact - Fail-closed: active - Every operation -&gt; audit + alert</div>
</div>;

