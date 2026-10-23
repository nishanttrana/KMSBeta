import { useCallback, useEffect, useState } from "react";
import { B, Btn, Card, Chk, FG, Inp, Row2, Section, Sel, Txt } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import { SSH_EXTENSIONS, createSSHCA, hours, lines, listSSHCAs, type SSHCA } from "../../../lib/sshCerts";
import { SSHCADetail } from "./SSHCADetail";

// SSH certificates (docs/CERTIFICATES.md "SSH certificates"): SSH CAs whose
// keys stay in the KMS, each with a policy of what it signs. The page shows
// state and controls; what each means is in the docs.

type Props = { session: any; onToast?: ((msg: string) => void) | undefined };

export function SSHCertificatesPanel({ session, onToast }: Props) {
  const [cas, setCAs] = useState<SSHCA[] | null>(null);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState("");
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    try {
      const items = await listSSHCAs(session);
      setCAs(items);
      setError("");
      setSelected((cur) => cur || items[0]?.id || "");
    } catch (e) {
      setError(errMsg(e));
    }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const current = cas?.find((c) => c.id === selected);
  return (
    <div>
      <Section title="SSH certificate authorities" actions={<Btn small primary onClick={() => setCreating(!creating)}>{creating ? "Cancel" : "New SSH CA"}</Btn>}>
        {creating && <CreateSSHCA session={session} onDone={(ca) => { setCreating(false); setSelected(ca.id); onToast?.(`SSH CA ${ca.name} created.`); void load(); }} />}
        {error ? <div style={{ fontSize: 11, color: C.redFg }}>{`SSH CAs unavailable: ${error}`}</div>
          : cas === null ? <div style={{ fontSize: 11, color: C.muted }}>Loading…</div>
            : cas.length === 0 ? <div style={{ fontSize: 11, color: C.muted }}>No SSH CAs yet.</div>
              : (
                <div style={{ display: "grid", gap: 6 }}>
                  {cas.map((ca) => (
                    <Card key={ca.id} onClick={() => setSelected(ca.id)} style={{ cursor: "pointer", borderColor: ca.id === selected ? C.accentFg : undefined }}>
                      <div data-testid="ssh-ca-row" style={{ display: "flex", justifyContent: "space-between", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                        <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{ca.name}</span>
                        <span style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          {ca.cert_types.map((t) => <B key={t} c="neutral">{t}</B>)}
                          <B c="neutral">{ca.algorithm}</B>
                          {ca.key_backend === "hsm" && <B c="neutral">HSM</B>}
                          <B c={ca.status === "active" ? "green" : "neutral"}>{ca.status}</B>
                        </span>
                      </div>
                      <div style={{ fontSize: 10.5, color: C.muted, marginTop: 4, fontFamily: "var(--font-mono)", overflowWrap: "anywhere" }}>{ca.fingerprint}</div>
                      <div style={{ fontSize: 10.5, color: C.dim, marginTop: 2 }}>
                        {`Signs ${ca.allowed_principals.join(", ")} · up to ${hours(ca.max_validity_seconds)}`}
                      </div>
                    </Card>
                  ))}
                </div>
              )}
      </Section>
      {current && <SSHCADetail key={current.id} session={session} ca={current} onToast={onToast} onChanged={() => void load()} />}
    </div>
  );
}

function CreateSSHCA({ session, onDone }: { session: any; onDone: (ca: SSHCA) => void }) {
  const [name, setName] = useState("");
  const [algorithm, setAlgorithm] = useState("ECDSA-P384");
  const [backend, setBackend] = useState("software");
  const [user, setUser] = useState(true);
  const [host, setHost] = useState(false);
  const [principals, setPrincipals] = useState("");
  const [maxHours, setMaxHours] = useState("8");
  const [exts, setExts] = useState<string[]>(["permit-pty"]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async () => {
    setBusy(true);
    setError("");
    try {
      const ca = await createSSHCA(session, {
        name: name.trim(), algorithm, key_backend: backend,
        cert_types: [user && "user", host && "host"].filter(Boolean) as string[],
        allowed_principals: lines(principals),
        max_validity_seconds: Math.round(Number(maxHours) * 3600),
        default_extensions: user ? exts : []
      });
      onDone(ca);
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };
  const toggle = (e: string) => setExts((cur) => (cur.includes(e) ? cur.filter((x) => x !== e) : [...cur, e]));

  return (
    <Card style={{ marginBottom: 10 }}>
      <Row2>
        <FG label="Name" required><Inp aria-label="SSH CA name" value={name} onChange={(e: any) => setName(e.target.value)} placeholder="prod-users" /></FG>
        <FG label="Key">
          <div style={{ display: "flex", gap: 6 }}>
            <Sel aria-label="SSH CA algorithm" value={algorithm} onChange={(e: any) => setAlgorithm(String(e.target.value))}>
              {["ECDSA-P384", "ECDSA-P256", "ED25519", "RSA-3072", "RSA-4096"].map((a) => <option key={a} value={a}>{a}</option>)}
            </Sel>
            <Sel aria-label="SSH CA key storage" value={backend} onChange={(e: any) => setBackend(String(e.target.value))}>
              <option value="software">KMS (sealed)</option>
              <option value="hsm">HSM (ECDSA)</option>
            </Sel>
          </div>
        </FG>
      </Row2>
      <Row2>
        <FG label="Signs" required>
          <div style={{ display: "flex", gap: 12 }}>
            <Chk label="User certificates" checked={user} onChange={() => setUser(!user)} />
            <Chk label="Host certificates" checked={host} onChange={() => setHost(!host)} />
          </div>
        </FG>
        <FG label="Longest validity (hours)"><Inp aria-label="SSH CA longest validity" value={maxHours} onChange={(e: any) => setMaxHours(e.target.value)} /></FG>
      </Row2>
      <FG label="Allowed principals" required hint="One per line; * and ? match. * alone allows any principal.">
        <Txt aria-label="SSH CA allowed principals" rows={3} value={principals} onChange={(e: any) => setPrincipals(e.target.value)} placeholder={"deploy\nweb-*"} />
      </FG>
      {user && (
        <FG label="Default user extensions">
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            {SSH_EXTENSIONS.map((e) => <Chk key={e} label={e} checked={exts.includes(e)} onChange={() => toggle(e)} />)}
          </div>
        </FG>
      )}
      {error && <div style={{ fontSize: 11, color: C.redFg, marginBottom: 6 }}>{error}</div>}
      <Btn small primary disabled={busy || !name.trim() || !lines(principals).length || (!user && !host)} onClick={() => void submit()}>{busy ? "Creating…" : "Create SSH CA"}</Btn>
    </Card>
  );
}
