import { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";
import type { AuthSession } from "../../../../lib/auth";
import { createEKMClient, getEKMClient, issueEKMClientToken, type EKMClient, type EKMRegistrationToken } from "../../../../lib/ekmClients";
import { Btn, Chk, FG, Inp, Modal, Row2, Sel } from "../../legacyPrimitives";
import { errMsg } from "../../runtimeUtils";
import { C } from "../../theme";
import { CLIENT_NAME, ENGINES, MONO, engineLabel, fmtTime, installSteps, type TargetOS } from "./meta";

type Props = {
  session: AuthSession;
  // A client to issue a token for: one still awaiting registration, or a
  // registered one being re-enrolled. Absent when adding a new client.
  resume?: EKMClient | null;
  existingNames: string[];
  onClose: () => void;
  onChanged: () => void;
};

const STEPS = ["Client details", "Registration token", "Install on client"];

const codeBox = { background: C.card, border: `1px solid ${C.border}`, borderRadius: "var(--radius-md)", padding: "8px 10px", fontFamily: MONO, fontSize: 11.5, color: C.text, overflowWrap: "anywhere" as const, whiteSpace: "pre-wrap" as const };

function CopyBtn({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(text);
    setDone(true);
    setTimeout(() => setDone(false), 2000);
  };
  return <Btn small onClick={() => void copy()}>{done ? <Check size={12} /> : <Copy size={12} />}{done ? "Copied" : label}</Btn>;
}

// Add a database client: name it, get its one-time registration token, run
// the agent on the host. The last step ends only when the agent has really
// presented the token; until then the client stays "awaiting registration".
export function AddClientWizard({ session, resume = null, existingNames, onClose, onChanged }: Props) {
  const [step, setStep] = useState(resume ? 2 : 1);
  const [name, setName] = useState("");
  const [engine, setEngine] = useState("oracle");
  const [host, setHost] = useState("");
  const [autoKey, setAutoKey] = useState(true);
  const [client, setClient] = useState<EKMClient | null>(resume);
  const [token, setToken] = useState<EKMRegistrationToken | null>(null);
  const [os, setOS] = useState<TargetOS>("linux");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [enrolled, setEnrolled] = useState<EKMClient | null>(null);
  // What the client's registration time was before this token was issued.
  const [before] = useState(resume?.registered_at ?? "");

  const issue = async (c: EKMClient) => {
    setBusy(true);
    setError("");
    try {
      setToken(await issueEKMClientToken(session, c.id));
      onChanged();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const create = async () => {
    const n = name.trim();
    if (!CLIENT_NAME.test(n)) { setError("Use 3 to 40 letters, digits, dots, dashes or underscores."); return; }
    if (existingNames.some((x) => x.toLowerCase() === n.toLowerCase())) { setError(`A client named ${n} already exists.`); return; }
    setBusy(true);
    setError("");
    try {
      const c = await createEKMClient(session, { name: n, db_engine: engine, host, auto_provision_tde: autoKey });
      setClient(c);
      setStep(2);
      onChanged();
      await issue(c);
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  // Wait for the agent: the client is registered when the service says so.
  // The parent re-renders every second, so its callback is read through a
  // ref; as a dependency it would restart the poll before it ever fired.
  const changedRef = useRef(onChanged);
  changedRef.current = onChanged;
  const clientId = client?.id ?? "";
  const waiting = step === 3 && clientId !== "" && !enrolled;
  useEffect(() => {
    if (!waiting) return;
    const poll = setInterval(() => {
      getEKMClient(session, clientId, true)
        .then((d) => {
          if (d.client.registration === "registered" && (d.client.registered_at ?? "") !== before) {
            setEnrolled(d.client);
            changedRef.current();
          }
        })
        .catch(() => { /* next poll */ });
    }, 3000);
    return () => clearInterval(poll);
  }, [waiting, clientId, session, before]);

  const again = () => {
    setStep(1); setName(""); setHost(""); setClient(null); setToken(null); setEnrolled(null); setError("");
  };
  const server = `${window.location.origin}/svc/ekm`;
  const reenrol = client?.registration === "registered" && !enrolled;

  return (
    <Modal open title={resume ? `Registration token · ${resume.name}` : "Add client"} onClose={onClose} width={600}>
      <div data-testid="ekm-wizard" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, marginBottom: 16 }}>
        {STEPS.map((s, i) => {
          const state = enrolled || i + 1 < step ? "done" : i + 1 === step ? "on" : "todo";
          return (
            <div key={s} data-state={state} style={{ fontSize: 11.5, color: state === "todo" ? C.muted : C.text, fontWeight: state === "on" ? 600 : 400 }}>
              <div style={{ height: 3, borderRadius: 2, background: state === "todo" ? C.border : C.accentFg, opacity: state === "done" ? 0.55 : 1, marginBottom: 6 }} />
              {i + 1}. {s}
            </div>
          );
        })}
      </div>

      {step === 1 && (<>
        <FG label="Client name" required>
          <Inp value={name} onChange={(e) => setName(e.target.value)} placeholder="ORCL-PROD-04" maxLength={40} autoFocus title="3 to 40 letters, digits, dots, dashes or underscores" onKeyDown={(e) => { if (e.key === "Enter") void create(); }} />
        </FG>
        <Row2>
          <FG label="Database">
            <Sel value={engine} onChange={(e: { target: { value: string } }) => setEngine(e.target.value)}>
              {ENGINES.map((e) => <option key={e.id} value={e.id}>{e.label}</option>)}
            </Sel>
          </FG>
          <FG label="Host name (optional)">
            <Inp value={host} onChange={(e) => setHost(e.target.value)} placeholder="db-host.corp.local" />
          </FG>
        </Row2>
        <Chk label="Create a TDE key in the KMS for this client" checked={autoKey} onChange={() => setAutoKey(!autoKey)} />
      </>)}

      {step === 2 && client && (<>
        <div style={{ fontSize: 12, color: C.dim, marginBottom: 12 }}><span style={{ color: C.text, fontWeight: 600 }}>{client.name}</span> · {engineLabel(client.db_engine)}{client.host ? ` · ${client.host}` : ""}</div>
        {token ? (<>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <span style={{ fontSize: 11.5, color: C.muted }}>One use · expires {fmtTime(token.expires_at)}</span>
            <CopyBtn text={token.token} label="Copy token" />
          </div>
          <div data-testid="ekm-token" style={codeBox}>{token.token}</div>
          <div data-keep="" style={{ fontSize: 12, color: C.amberFg, marginTop: 10 }}>Shown once. Copy it now; a new token replaces this one.</div>
        </>) : (
          <Btn primary onClick={() => void issue(client)} disabled={busy}>{busy ? "Creating…" : "Create registration token"}</Btn>
        )}
        {reenrol && <div data-keep="" style={{ fontSize: 12, color: C.amberFg, marginTop: 10 }}>When the new token is used, this client's current key stops working.</div>}
      </>)}

      {step === 3 && client && (enrolled ? (
        <div data-testid="ekm-enrolled" style={{ display: "flex", gap: 12, alignItems: "center", background: C.greenDim, borderRadius: "var(--radius-md)", padding: "14px 16px" }}>
          <span style={{ width: 34, height: 34, borderRadius: 17, background: C.card, color: C.greenFg, display: "inline-flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}><Check size={16} /></span>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, color: C.greenFg }}>Client registered</div>
            <div data-keep="" style={{ fontSize: 12, color: C.dim, marginTop: 2 }}>{enrolled.name} checked in at {fmtTime(enrolled.registered_at)} from {enrolled.source_ip || "an unknown address"}{enrolled.version ? ` (${enrolled.version})` : ""}.</div>
          </div>
        </div>
      ) : (<>
        <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
          {(["linux", "windows"] as const).map((o) => <Btn key={o} small primary={os === o} onClick={() => setOS(o)}>{o === "linux" ? "Linux" : "Windows (PowerShell)"}</Btn>)}
        </div>
        {installSteps(os, server).map((s, i) => (
          <div key={s.label} style={{ marginBottom: 10 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, marginBottom: 4 }}>
              <span style={{ fontSize: 12, color: C.dim }}>{i + 1}. {s.label}</span>
              <CopyBtn text={s.cmd} />
            </div>
            <div style={codeBox}>{s.cmd}</div>
          </div>
        ))}
        <div data-testid="ekm-waiting" aria-live="polite" style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 14, padding: "10px 12px", border: `1px dashed ${C.borderHi}`, borderRadius: "var(--radius-md)", fontSize: 12, color: C.text }}>
          <span style={{ width: 8, height: 8, borderRadius: 4, background: C.accentFg, animation: "pulse 2s infinite" }} />
          Waiting for {client.name} to register…
        </div>
      </>))}

      {error && <div data-keep="" style={{ fontSize: 12, color: C.redFg, marginTop: 10 }}>{error}</div>}

      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 18 }}>
        {step === 1 && (<><Btn onClick={onClose}>Cancel</Btn><Btn primary onClick={() => void create()} disabled={busy}>{busy ? "Creating…" : "Continue"}</Btn></>)}
        {step === 2 && (<><Btn onClick={onClose}>Finish later</Btn><Btn primary onClick={() => setStep(3)} disabled={!token}>I've copied it</Btn></>)}
        {step === 3 && !enrolled && <Btn onClick={onClose}>Finish later</Btn>}
        {step === 3 && enrolled && (<>{!resume && <Btn onClick={again}>Add another</Btn>}<Btn primary onClick={onClose}>Done</Btn></>)}
      </div>
    </Modal>
  );
}
