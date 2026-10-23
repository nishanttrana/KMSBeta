import { useCallback, useEffect, useState } from "react";
import { B, Btn, Card, Chk, FG, Inp, Row2, Section, Sel, Txt, usePromptDialog } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  SSH_EXTENSIONS,
  downloadSSHKRL,
  hours,
  lines,
  getSSHCA,
  listSSHCertificates,
  revokeSSHCertificate,
  signSSH,
  updateSSHCA,
  type SSHCA,
  type SSHCertificate,
  type SSHTrust
} from "../../../lib/sshCerts";

// One SSH CA: the lines servers and clients install, signing a public key,
// and the certificates it issued (revoke, KRL).

type Props = { session: any; ca: SSHCA; onToast?: ((msg: string) => void) | undefined; onChanged: () => void };

const copy = (text: string, onToast?: ((msg: string) => void) | undefined) => {
  void navigator.clipboard?.writeText(text).then(() => onToast?.("Copied."), () => undefined);
};

const day = (iso?: string) => (iso ? new Date(iso).toISOString().slice(0, 16).replace("T", " ") : "");

export function SSHCADetail({ session, ca, onToast, onChanged }: Props) {
  const [trust, setTrust] = useState<SSHTrust | null>(null);
  const [certs, setCerts] = useState<SSHCertificate[] | null>(null);
  const [error, setError] = useState("");
  const prompt = usePromptDialog();

  const load = useCallback(async () => {
    try {
      const [detail, items] = await Promise.all([getSSHCA(session, ca.id), listSSHCertificates(session, ca.id)]);
      setTrust(detail.trust);
      setCerts(items);
      setError("");
    } catch (e) {
      setError(errMsg(e));
    }
  }, [session, ca.id]);
  useEffect(() => { void load(); }, [load]);

  const setStatus = async (status: string) => {
    try {
      await updateSSHCA(session, ca.id, { status });
      onToast?.(status === "active" ? "SSH CA enabled." : "SSH CA disabled: it signs nothing until enabled.");
      onChanged();
    } catch (e) {
      onToast?.(errMsg(e));
    }
  };
  const editPrincipals = async () => {
    const next = await prompt.prompt({ title: "Allowed principals", message: "Comma-separated; * and ? match.", defaultValue: ca.allowed_principals.join(", ") });
    if (next === null || next === undefined) return;
    try {
      await updateSSHCA(session, ca.id, { allowed_principals: lines(String(next)) });
      onToast?.("Policy saved.");
      onChanged();
    } catch (e) {
      onToast?.(errMsg(e));
    }
  };
  const revoke = async (c: SSHCertificate) => {
    const reason = await prompt.prompt({ title: `Revoke serial ${c.serial}`, message: "Reason (recorded in the audit trail).", defaultValue: "", confirmLabel: "Revoke", danger: true });
    if (reason === null || reason === undefined) return;
    try {
      await revokeSSHCertificate(session, c.id, String(reason));
      onToast?.("Revoked. Servers refuse it once they load the new KRL.");
      void load();
    } catch (e) {
      onToast?.(errMsg(e));
    }
  };

  return (
    <Section
      title={ca.name}
      actions={
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          <Btn small onClick={() => void editPrincipals()}>Edit principals</Btn>
          <Btn small onClick={() => void downloadSSHKRL(session, ca).catch((e) => onToast?.(errMsg(e)))}>Download KRL</Btn>
          {ca.status === "active" ? <Btn small danger onClick={() => void setStatus("disabled")}>Disable</Btn> : <Btn small onClick={() => void setStatus("active")}>Enable</Btn>}
        </div>
      }
    >
      {prompt.ui}
      {error && <div style={{ fontSize: 11, color: C.redFg, marginBottom: 6 }}>{`Unavailable: ${error}`}</div>}
      {trust && (
        <Card style={{ marginBottom: 10 }}>
          <TrustLine label="Servers trust user certificates (TrustedUserCAKeys)" value={trust.trusted_user_ca_keys} onToast={onToast} show={ca.cert_types.includes("user")} />
          <TrustLine label="Clients trust host certificates (known_hosts)" value={trust.known_hosts} onToast={onToast} show={ca.cert_types.includes("host")} />
        </Card>
      )}
      {ca.status === "active" && <SignForm session={session} ca={ca} onToast={onToast} onIssued={() => void load()} />}
      <div style={{ fontSize: 12, fontWeight: 600, color: C.text, margin: "12px 0 6px" }}>Issued certificates</div>
      {certs === null ? <div style={{ fontSize: 11, color: C.muted }}>Loading…</div>
        : certs.length === 0 ? <div style={{ fontSize: 11, color: C.muted }}>None issued yet.</div>
          : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                <thead>
                  <tr style={{ color: C.muted, textAlign: "left" }}>
                    {["Serial", "Type", "Principals", "Key ID", "Valid until", "Issued by", "Status", ""].map((h) => <th key={h} style={{ padding: "4px 6px", fontWeight: 600 }}>{h}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {certs.map((c) => (
                    <tr key={c.id} data-testid="ssh-cert-row" style={{ borderTop: `1px solid ${C.border}`, color: C.text }}>
                      <td style={{ padding: "4px 6px", fontFamily: "var(--font-mono)" }}>{c.serial}</td>
                      <td style={{ padding: "4px 6px" }}>{c.cert_type}</td>
                      <td style={{ padding: "4px 6px" }}>{c.principals.join(", ")}</td>
                      <td style={{ padding: "4px 6px", overflowWrap: "anywhere" }}>{c.key_id}</td>
                      <td style={{ padding: "4px 6px" }}>{day(c.valid_before)}</td>
                      <td style={{ padding: "4px 6px" }}>{c.issued_by}</td>
                      <td style={{ padding: "4px 6px" }} title={c.revoke_reason || undefined}>
                        {c.revoked_at ? <B c="red">revoked</B> : new Date(c.valid_before).getTime() < Date.now() ? <B c="neutral">expired</B> : <B c="green">valid</B>}
                      </td>
                      <td style={{ padding: "4px 6px" }}>{!c.revoked_at && <Btn small danger onClick={() => void revoke(c)}>Revoke</Btn>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
    </Section>
  );
}

function TrustLine({ label, value, onToast, show }: { label: string; value: string; onToast?: ((msg: string) => void) | undefined; show: boolean }) {
  if (!show) return null;
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
        <span style={{ fontSize: 11, color: C.dim }}>{label}</span>
        <Btn small onClick={() => copy(value, onToast)}>Copy</Btn>
      </div>
      <div style={{ fontSize: 10.5, fontFamily: "var(--font-mono)", color: C.text, overflowWrap: "anywhere", marginTop: 2 }}>{value}</div>
    </div>
  );
}

function SignForm({ session, ca, onToast, onIssued }: { session: any; ca: SSHCA; onToast?: ((msg: string) => void) | undefined; onIssued: () => void }) {
  const [publicKey, setPublicKey] = useState("");
  const [certType, setCertType] = useState(ca.cert_types[0] || "user");
  const [principals, setPrincipals] = useState("");
  const [validHours, setValidHours] = useState(String(Math.min(8, ca.max_validity_seconds / 3600)));
  const [keyID, setKeyID] = useState("");
  const [exts, setExts] = useState<string[]>(ca.default_extensions);
  const [forceCommand, setForceCommand] = useState("");
  const [sources, setSources] = useState("");
  const [issued, setIssued] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async () => {
    setBusy(true);
    setError("");
    setIssued("");
    try {
      const out = await signSSH(session, ca.id, {
        public_key: publicKey.trim(), cert_type: certType, principals: lines(principals),
        valid_seconds: Math.round(Number(validHours) * 3600), key_id: keyID.trim() || undefined,
        extensions: certType === "user" ? exts : [], force_command: forceCommand.trim() || undefined,
        source_address: lines(sources).length ? lines(sources) : undefined
      });
      setIssued(out.certificate);
      onToast?.(`Certificate issued, serial ${out.record.serial}.`);
      onIssued();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };
  const toggle = (e: string) => setExts((cur) => (cur.includes(e) ? cur.filter((x) => x !== e) : [...cur, e]));

  return (
    <Card>
      <div style={{ fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 6 }}>Sign a public key</div>
      <FG label="Public key" required hint="The .pub file's one line, for example ~/.ssh/id_ed25519.pub.">
        <Txt aria-label="SSH public key" rows={2} value={publicKey} onChange={(e: any) => setPublicKey(e.target.value)} placeholder="ssh-ed25519 AAAA… user@laptop" />
      </FG>
      <Row2>
        <FG label="Principals" required hint={`Allowed: ${ca.allowed_principals.join(", ")}`}>
          <Inp aria-label="SSH principals" value={principals} onChange={(e: any) => setPrincipals(e.target.value)} placeholder={certType === "host" ? "web-01.example.com" : "deploy"} />
        </FG>
        <FG label={`Valid for (hours, up to ${hours(ca.max_validity_seconds)})`}>
          <div style={{ display: "flex", gap: 6 }}>
            <Inp aria-label="SSH validity hours" value={validHours} onChange={(e: any) => setValidHours(e.target.value)} />
            {ca.cert_types.length > 1 && (
              <Sel aria-label="SSH certificate type" value={certType} onChange={(e: any) => setCertType(String(e.target.value))}>
                {ca.cert_types.map((t) => <option key={t} value={t}>{t}</option>)}
              </Sel>
            )}
          </div>
        </FG>
      </Row2>
      {certType === "user" && (
        <>
          <FG label="Extensions">
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              {SSH_EXTENSIONS.map((e) => <Chk key={e} label={e} checked={exts.includes(e)} onChange={() => toggle(e)} />)}
            </div>
          </FG>
          <Row2>
            <FG label="Force command"><Inp aria-label="SSH force command" value={forceCommand} onChange={(e: any) => setForceCommand(e.target.value)} placeholder="/usr/local/bin/backup" /></FG>
            <FG label="Source addresses"><Inp aria-label="SSH source addresses" value={sources} onChange={(e: any) => setSources(e.target.value)} placeholder="10.0.0.0/8" /></FG>
          </Row2>
        </>
      )}
      <FG label="Key ID" hint="Shown in server logs; defaults to tenant, user and serial."><Inp aria-label="SSH key ID" value={keyID} onChange={(e: any) => setKeyID(e.target.value)} /></FG>
      {error && <div style={{ fontSize: 11, color: C.redFg, marginBottom: 6 }}>{error}</div>}
      <Btn small primary disabled={busy || !publicKey.trim() || !lines(principals).length} onClick={() => void submit()}>{busy ? "Signing…" : "Sign"}</Btn>
      {issued && (
        <div style={{ marginTop: 10 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 11, color: C.dim }}>Save as id_ed25519-cert.pub next to the key (or the key's name with -cert.pub).</span>
            <Btn small onClick={() => copy(issued, onToast)}>Copy</Btn>
          </div>
          <div data-testid="ssh-issued-cert" style={{ fontSize: 10.5, fontFamily: "var(--font-mono)", color: C.text, overflowWrap: "anywhere", marginTop: 4 }}>{issued}</div>
        </div>
      )}
    </Card>
  );
}
