// @ts-nocheck -- legacy tab: strict typing deferred, do not add new suppressions
import { useEffect, useMemo, useState } from "react";
import { Copy } from "lucide-react";
import { getHYOKDKEPublicKey, hyokCrypto } from "../../../lib/hyok";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { Btn, Card, FG, Inp, Row2, Section, Sel, Txt } from "../legacyPrimitives";

const HYOK_PROTOCOL_KEY_HINTS: Record<string, string> = {
  dke: "Requires RSA key (2048+ bits). Public key is served via DKE endpoint for Microsoft clients.",
  salesforce: "Supports AES-256 or RSA keys for wrap/unwrap operations.",
  google: "Supports AES-256 or RSA keys for wrap/unwrap operations with Google Cloud CMEK.",
  generic: "Any symmetric or asymmetric key supported by your Vecta KMS instance.",
  servicenow: "Supports AES-256 keys for wrap/unwrap operations using AES-KWP (RFC 5649).",
  alibaba: "Supports AES-256 keys for encrypt/decrypt operations using AES-256-GCM."
};

const HYOK_OPS_BY_PROTOCOL: Record<string, string[]> = {
  dke: ["decrypt", "publickey"],
  salesforce: ["wrap", "unwrap"],
  google: ["wrap", "unwrap"],
  generic: ["encrypt", "decrypt", "wrap", "unwrap"],
  servicenow: ["wrap", "unwrap"],
  alibaba: ["encrypt", "decrypt"]
};

function normalizeKeyState(state: string): string {
  const raw = String(state || "").toLowerCase().trim();
  if (raw === "destroyed" || raw === "deleted") return "deleted";
  if (raw === "destroy-pending" || raw === "delete-pending" || raw === "deletion-pending") return "destroy-pending";
  if (raw === "preactive" || raw === "pre-active") return "pre-active";
  if (raw === "retired" || raw === "deactivated") return "deactivated";
  return raw || "unknown";
}

function copyToClipboard(text: string) {
  try { navigator.clipboard.writeText(text); } catch { /* ignore */ }
}

export const HYOKLiveTestPane = ({ session, keyCatalog, onToast }) => {
  const keyChoices = useMemo(() =>
    Array.isArray(keyCatalog) ? keyCatalog.filter((k) => normalizeKeyState(String(k?.state || "")) !== "deleted") : []
  , [keyCatalog]);

  const [testProtocol, setTestProtocol] = useState("generic");
  const [testOperation, setTestOperation] = useState("encrypt");
  const [testKeyID, setTestKeyID] = useState("");
  const [testPlaintext, setTestPlaintext] = useState("");
  const [testCiphertext, setTestCiphertext] = useState("");
  const [testIV, setTestIV] = useState("");
  const [testRefID, setTestRefID] = useState("");
  const [testRequester, setTestRequester] = useState("");
  const [testRequesterEmail, setTestRequesterEmail] = useState("");
  const [testOutput, setTestOutput] = useState("// HYOK result will appear here...");
  const [executing, setExecuting] = useState(false);

  useEffect(() => {
    if (testKeyID) return;
    const first = keyChoices[0];
    if (first?.id) setTestKeyID(String(first.id));
  }, [keyChoices, testKeyID]);

  useEffect(() => {
    const allowed = HYOK_OPS_BY_PROTOCOL[testProtocol] || [];
    if (!allowed.includes(testOperation)) setTestOperation(String(allowed[0] || "encrypt"));
  }, [testProtocol, testOperation]);

  const allowedOps = HYOK_OPS_BY_PROTOCOL[testProtocol] || [];

  const executeTest = async () => {
    if (!session?.token) return;
    const keyID = String(testKeyID || "").trim();
    if (!keyID) { onToast?.("Select a key."); return; }
    const protocol = String(testProtocol || "generic");
    const operation = String(testOperation || "encrypt");
    setExecuting(true);
    setTestOutput("// Executing...");
    try {
      if (protocol === "dke" && operation === "publickey") {
        const out = await getHYOKDKEPublicKey(session, keyID);
        setTestOutput(JSON.stringify(out, null, 2));
      } else {
        const out = await hyokCrypto(session, protocol, operation, keyID, {
          plaintext: testPlaintext,
          ciphertext: testCiphertext,
          iv: testIV,
          reference_id: testRefID,
          requester_id: testRequester,
          requester_email: testRequesterEmail
        });
        setTestOutput(JSON.stringify(out, null, 2));
      }
      onToast?.(`HYOK ${operation} completed.`);
    } catch (error) {
      setTestOutput(`// Error: ${errMsg(error)}`);
      onToast?.(`HYOK ${operation} failed: ${errMsg(error)}`);
    } finally {
      setExecuting(false);
    }
  };

  const renderKeyOptions = (choices: any[]) => {
    if (!choices.length) return [<option key="no-keys" value="">No customer keys available</option>];
    return choices.map((k) => (
      <option key={k.id} value={k.id}>{k.name} {k.algo ? `(${k.algo})` : ""}</option>
    ));
  };

  return (
    <Section title="HYOK Live Test Console">
      <div style={{ fontSize: 10, color: C.muted, marginBottom: 12, padding: "6px 8px", background: C.bg, borderRadius: 4 }}>
        Test HYOK crypto operations against your configured endpoints. All requests go through the full policy + governance pipeline.
      </div>
      <Row2>
        <Card>
          <Row2>
            <FG label="Protocol" required>
              <Sel value={testProtocol} onChange={(e) => setTestProtocol(e.target.value)}>
                <option value="dke">Microsoft DKE</option>
                <option value="salesforce">Salesforce Cache-Only</option>
                <option value="google">Google Cloud EKM</option>
                <option value="generic">Generic HYOK</option>
                <option value="servicenow">ServiceNow HYOK</option>
                <option value="alibaba">Alibaba Cloud EKM</option>
              </Sel>
            </FG>
            <FG label="Operation" required>
              <Sel value={testOperation} onChange={(e) => setTestOperation(e.target.value)}>
                {allowedOps.map((op) => <option key={op} value={op}>{op}</option>)}
              </Sel>
            </FG>
          </Row2>
          <FG label="Vecta Key" required hint={HYOK_PROTOCOL_KEY_HINTS[testProtocol]}>
            <Sel value={testKeyID} onChange={(e) => setTestKeyID(e.target.value)}>
              {renderKeyOptions(keyChoices)}
            </Sel>
          </FG>
          {(testOperation === "encrypt" || testOperation === "wrap") && (
            <FG label="Plaintext (base64)" required>
              <Txt rows={3} value={testPlaintext} onChange={(e) => setTestPlaintext(e.target.value)} placeholder="SGVsbG8gd29ybGQ=" />
            </FG>
          )}
          {(testOperation === "decrypt" || testOperation === "unwrap") && (
            <FG label="Ciphertext (base64)" required>
              <Txt rows={3} value={testCiphertext} onChange={(e) => setTestCiphertext(e.target.value)} placeholder="Paste ciphertext base64" />
            </FG>
          )}
          {testOperation !== "publickey" && (
            <Row2>
              <FG label="IV (base64)">
                <Inp value={testIV} onChange={(e) => setTestIV(e.target.value)} placeholder="Optional" mono />
              </FG>
              <FG label="Reference ID">
                <Inp value={testRefID} onChange={(e) => setTestRefID(e.target.value)} placeholder="txn-..." mono />
              </FG>
            </Row2>
          )}
          <Row2>
            <FG label="Requester ID">
              <Inp value={testRequester} onChange={(e) => setTestRequester(e.target.value)} placeholder="svc-app-01" mono />
            </FG>
            <FG label="Requester Email">
              <Inp value={testRequesterEmail} onChange={(e) => setTestRequesterEmail(e.target.value)} placeholder="security@example.com" mono />
            </FG>
          </Row2>
          <Btn primary onClick={() => void executeTest()} disabled={executing} style={{ width: "100%" }}>
            {executing ? "Executing..." : `Execute ${testOperation.toUpperCase()}`}
          </Btn>
        </Card>
        <Card>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
            <div style={{ fontSize: 11, color: C.muted, fontWeight: 700 }}>OUTPUT</div>
            <button onClick={() => copyToClipboard(testOutput)} style={{ background: "transparent", border: "none", color: C.dim, cursor: "pointer" }} title="Copy output">
              <Copy size={12} />
            </button>
          </div>
          <Txt rows={22} value={testOutput} readOnly />
        </Card>
      </Row2>
    </Section>
  );
};
