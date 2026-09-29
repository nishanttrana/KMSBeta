import { useCallback, useEffect, useMemo, useState } from "react";
import { B, Btn, Card, Inp, Section, Sel, Txt } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import {
  createEdgeCSR,
  getEdgeTLS,
  installEdgeCertificate,
  listCAs,
  setEdgeCertificateSource,
  type CertCA,
  getInternalMTLS,
  rotateAllInternalMTLS,
  rotateInternalMTLS,
  setEdgeTLS,
  setInternalMTLSPolicy,
  type EdgeTLS,
  type MTLSIdentity,
  type MTLSInventory,
  type MTLSRestartMode
} from "../../../lib/certs";

// Service mTLS (docs/SECURITY/INTERNAL_TLS.md): every internal identity's
// certificate from the internal-services Sub CA, its key and key-exchange
// policy, and what its instances actually run (reported by the service, not
// assumed). Changes and rotations restart the service (graceful or forced)
// or, for Envoy, the dashboard and the daemons, rewrite the certificate they
// reload. Root administrators only; every action is audited.

type Props = { session: any; onToast?: (msg: string) => void };

const PROFILE_LABEL: Record<string, string> = {
  "pqc-required": "PQC required: hybrid ML-KEM only",
  "pqc-preferred": "PQC preferred: hybrid ML-KEM, classical fallback",
  classical: "Classical: no ML-KEM"
};

const ago = (iso?: string) => {
  if (!iso) return "";
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 90) return `${s}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
};

const day = (iso?: string) => (iso ? new Date(iso).toISOString().slice(0, 10) : "");

export const ServiceMTLSPanel = ({ session, onToast }: Props) => {
  const [inv, setInv] = useState<MTLSInventory | null>(null);
  const [error, setError] = useState("");
  const [draft, setDraft] = useState<Record<string, { key_algorithm: string; kx_profile: string }>>({});
  const [confirmForce, setConfirmForce] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState("");
  const [allMode, setAllMode] = useState<MTLSRestartMode>("graceful");
  const [allConfirm, setAllConfirm] = useState("");
  const [filter, setFilter] = useState("");
  const [edge, setEdge] = useState<EdgeTLS | null>(null);
  const [edgeError, setEdgeError] = useState("");
  const [edgeDraft, setEdgeDraft] = useState("");
  const [cas, setCAs] = useState<CertCA[]>([]);
  const [certDraft, setCertDraft] = useState<{ source: string; ca_id: string; key_algorithm: string } | null>(null);
  const [csrCN, setCsrCN] = useState("");
  const [csrSANs, setCsrSANs] = useState("");
  const [csrPem, setCsrPem] = useState("");
  const [signedPem, setSignedPem] = useState("");
  const [chainPem, setChainPem] = useState("");

  const load = useCallback(async () => {
    if (!session?.token) return;
    try {
      setInv(await getInternalMTLS(session));
      setError("");
    } catch (e) {
      setError(errMsg(e));
    }
    try {
      setEdge(await getEdgeTLS(session));
      setEdgeError("");
    } catch (e) {
      setEdgeError(errMsg(e));
    }
    try {
      setCAs((await listCAs(session)).filter((c) => String(c.status || "").toLowerCase() === "active" && String((c as any).key_backend || "") !== "hsm"));
    } catch {
      setCAs([]);
    }
  }, [session]);

  useEffect(() => { void load(); }, [load]);
  const pending = useMemo(() => (inv?.items || []).filter((i) => !i.applied).length + (edge && !edge.applied ? 1 : 0), [inv, edge]);
  // Poll while changes are being applied (services restart and report back).
  useEffect(() => {
    const id = window.setInterval(() => void load(), pending > 0 ? 5000 : 30000);
    return () => window.clearInterval(id);
  }, [pending, load]);

  const run = async (key: string, fn: () => Promise<unknown>, done: string) => {
    setBusy(key);
    try {
      await fn();
      onToast?.(done);
      await load();
    } catch (e) {
      onToast?.(`${key}: ${errMsg(e)}`);
    } finally {
      setBusy("");
    }
  };

  if (error) return <Card style={{ padding: 12 }}><div style={{ fontSize: 11, color: C.red }}>Service mTLS unavailable: {error}</div></Card>;
  if (!inv) return <Card style={{ padding: 12 }}><div style={{ fontSize: 11, color: C.dim }}>Loading internal mTLS inventory...</div></Card>;

  const items = inv.items.filter((i) => !filter || i.identity.includes(filter.toLowerCase()) || i.host.includes(filter.toLowerCase()));

  const row = (i: MTLSIdentity) => {
    const d = draft[i.identity] || { key_algorithm: i.policy.key_algorithm, kx_profile: i.policy.kx_profile };
    const changed = d.key_algorithm !== i.policy.key_algorithm || (i.kind === "service" && d.kx_profile !== i.policy.kx_profile);
    const observed = i.observed || [];
    const live = i.kind === "service" ? observed[0] : i.served_file;
    const cert = (i.certificates || [])[0];
    const set = (patch: Partial<typeof d>) => setDraft((prev) => ({ ...prev, [i.identity]: { ...d, ...patch } }));
    return (
      <div key={i.identity} style={{ display: "grid", gridTemplateColumns: "1.3fr 1.5fr 1.6fr 1.2fr 1.6fr", gap: 8, padding: "8px 10px", borderTop: `1px solid ${C.border}`, alignItems: "center", fontSize: 11 }}>
        <div>
          <div style={{ fontWeight: 700, color: C.text }}>{i.identity}</div>
          <div style={{ color: C.dim, fontSize: 10 }}>{i.host} · {i.kind === "service" ? "service (enrols itself)" : "daemon (certs writes its files)"}</div>
        </div>
        <div>
          <div style={{ color: C.text }}>{live?.key_algorithm || cert?.key_algorithm || "not reported"}</div>
          <div style={{ color: C.dim, fontSize: 10 }}>
            {live?.serial || cert?.serial ? `serial ${(live?.serial || cert?.serial || "").slice(0, 16)}` : "no active certificate"}
            {(live?.not_after || cert?.not_after) ? ` · until ${day(live?.not_after || cert?.not_after)}` : ""}
          </div>
          <Sel value={d.key_algorithm} onChange={(e: any) => set({ key_algorithm: String(e.target.value) })} style={{ marginTop: 4 }}>
            {inv.meta.key_algorithms.map((a) => <option key={a} value={a}>{a}</option>)}
          </Sel>
        </div>
        <div>
          {i.kind === "service" ? (
            <>
              <div style={{ color: C.text }}>{PROFILE_LABEL[live?.kx_profile || ""] || live?.kx_profile || "not reported"}</div>
              <div style={{ color: C.dim, fontSize: 10 }}>
                {live?.last_handshake_group ? `last handshake ${live.last_handshake_group} ${ago(live.last_handshake_at)}` : "no handshake reported yet"}
              </div>
              <Sel value={d.kx_profile} onChange={(e: any) => set({ kx_profile: String(e.target.value) })} style={{ marginTop: 4 }}>
                {(i.kx_profiles || inv.meta.kx_profiles).map((p) => <option key={p} value={p}>{PROFILE_LABEL[p] || p}</option>)}
              </Sel>
            </>
          ) : (
            <div style={{ color: C.dim, fontSize: 10 }}>{i.note}</div>
          )}
        </div>
        <div>
          {i.applied
            ? <B c="green">{`generation ${i.policy.generation} · running`}</B>
            : <B c="amber" pulse>{observed.length === 0 && i.kind === "service" ? "not reported yet" : `applying generation ${i.policy.generation}`}</B>}
          {i.kind === "service" && observed.length > 1 && <div style={{ color: C.dim, fontSize: 10, marginTop: 2 }}>{observed.length} instances</div>}
          {live?.started_at && i.kind === "service" && <div style={{ color: C.dim, fontSize: 10, marginTop: 2 }}>started {ago(live.started_at)}</div>}
        </div>
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
          <Btn small primary disabled={!changed || busy !== ""} onClick={() => void run(i.identity, () => setInternalMTLSPolicy(session, i.identity,
            i.kind === "service" ? { key_algorithm: d.key_algorithm, kx_profile: d.kx_profile, reason } : { key_algorithm: d.key_algorithm, reason }), `${i.identity}: policy saved; ${i.kind === "service" ? "the service restarts gracefully to apply it" : "certificate reissued, the daemon reloads it"}`)}>
            Apply
          </Btn>
          <Btn small disabled={busy !== ""} onClick={() => void run(i.identity, () => rotateInternalMTLS(session, i.identity, "graceful", reason),
            `${i.identity}: certificate revoked; ${i.kind === "service" ? "graceful restart with a fresh key" : "new certificate written"}`)}>
            {i.kind === "service" ? "Rotate" : "Rotate (reload)"}
          </Btn>
          {i.restart_modes.includes("force") && (confirmForce === i.identity ? (
            <Btn small danger disabled={busy !== ""} onClick={() => { setConfirmForce(""); void run(i.identity, () => rotateInternalMTLS(session, i.identity, "force", reason),
              `${i.identity}: certificate revoked (key compromise); forced restart`); }}>
              Confirm force
            </Btn>
          ) : (
            <Btn small danger disabled={busy !== ""} onClick={() => setConfirmForce(i.identity)}>Force restart</Btn>
          ))}
        </div>
      </div>
    );
  };

  return (
    <Section title="Service mTLS" actions={<B c={pending > 0 ? "amber" : "green"}>{pending > 0 ? `${pending} applying` : "all applied"}</B>}>
      <Card style={{ padding: 12, marginBottom: 10 }}>
        <div style={{ fontSize: 11, color: C.text }}>
          Every internal connection is TLS 1.3 with mutual authentication. Certificates come from <b>{inv.meta.sub_ca}</b>.
          {" "}FIPS mode is {inv.meta.fips_mode ? "on (X25519 alone is not offered)" : "off"}.
        </div>
        <div style={{ fontSize: 10, color: C.dim, marginTop: 4 }}>
          A service with <b>PQC required</b> accepts only {(inv.meta.groups["pqc-required"] || []).join(", ")}. Every platform client offers all
          groups, so no choice cuts a service off from its callers. {inv.meta.signature_note}
        </div>
        <div style={{ fontSize: 10, color: C.dim, marginTop: 4 }}>
          Rotate revokes the current certificate. A service then restarts: gracefully (drains requests) or forced (at once, for a
          suspected key compromise); the new process generates a fresh key. The state below is what each service reports it runs.
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 8, marginTop: 8 }}>
          <Inp placeholder="Reason (recorded in the audit log)" value={reason} onChange={(e: any) => setReason(String(e.target.value || ""))} />
          <Inp placeholder="Filter identities" value={filter} onChange={(e: any) => setFilter(String(e.target.value || ""))} />
        </div>
        <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 8, flexWrap: "wrap" }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>Rotate all</div>
          <Sel value={allMode} onChange={(e: any) => setAllMode(e.target.value as MTLSRestartMode)} w={150}>
            <option value="graceful">graceful restarts</option>
            <option value="force">forced restarts</option>
          </Sel>
          <Inp placeholder='Type "rotate-all" to confirm' value={allConfirm} onChange={(e: any) => setAllConfirm(String(e.target.value || ""))} w={200} />
          <Btn small danger={allMode === "force"} primary={allMode === "graceful"} disabled={busy !== "" || allConfirm !== "rotate-all"}
            onClick={() => void run("rotate-all", async () => {
              const out = await rotateAllInternalMTLS(session, allMode, reason, allConfirm);
              setAllConfirm("");
              onToast?.(`Every internal certificate revoked; services restart one every ${inv.meta.rotate_all_step}s (about ${Math.round(out.restart_span_seconds / 60)} min, certs last).`);
            }, "Rotation of every internal certificate started")}>
            Rotate every certificate
          </Btn>
        </div>
      </Card>
      <Card style={{ padding: 12, marginBottom: 10 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>External edge key exchange</div>
        {edgeError ? (
          <div style={{ fontSize: 11, color: C.red, marginTop: 4 }}>Edge key exchange unavailable: {edgeError}</div>
        ) : !edge ? (
          <div style={{ fontSize: 11, color: C.dim, marginTop: 4 }}>Loading...</div>
        ) : (
          <>
            <div style={{ fontSize: 10, color: C.dim, marginTop: 4 }}>
              The TLS 1.3 groups the HTTPS edge (Envoy) and the KMIP listener accept from clients outside the platform. One
              choice for this node; Envoy applies it by a hot restart (no connection refused), KMIP on the next handshake.
              The groups below are measured by a handshake with each listener, one group at a time.
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr 1fr", gap: 8, marginTop: 8, fontSize: 11 }}>
              {edge.listeners.map((l) => (
                <div key={l.name} style={{ gridColumn: "1 / -1", display: "grid", gridTemplateColumns: "1fr 2fr 1fr", gap: 8 }}>
                  <div><div style={{ fontWeight: 700, color: C.text }}>{l.name}</div><div style={{ color: C.dim, fontSize: 10 }}>{l.address}</div></div>
                  <div>
                    <div style={{ color: C.text }}>{l.observed ? `accepts ${(l.observed.server_groups || []).join(", ") || "no probed group"}` : "not measured yet"}</div>
                    <div style={{ color: C.dim, fontSize: 10 }}>
                      required: {l.expected_groups.join(", ")}
                      {l.observed?.last_handshake_at ? ` · measured ${ago(l.observed.last_handshake_at)}` : ""}
                    </div>
                  </div>
                  <div>{l.applied ? <B c="green">in force</B> : <B c="amber" pulse>{l.observed ? "differs from the choice" : "not measured"}</B>}</div>
                </div>
              ))}
            </div>
            <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 8, flexWrap: "wrap" }}>
              <Sel value={edgeDraft || edge.policy.kx_profile} onChange={(e: any) => setEdgeDraft(String(e.target.value))} w={320}>
                {edge.kx_profiles.map((p) => <option key={p} value={p}>{PROFILE_LABEL[p] || p}</option>)}
              </Sel>
              <Btn small primary disabled={busy !== "" || !edgeDraft || edgeDraft === edge.policy.kx_profile}
                onClick={() => void run("edge", async () => { await setEdgeTLS(session, edgeDraft, reason); setEdgeDraft(""); },
                  "Edge key exchange saved; Envoy and KMIP apply it within about 20 s")}>
                Apply to the edge
              </Btn>
              <div style={{ fontSize: 10, color: C.dim }}>
                {PROFILE_LABEL[edgeDraft || edge.policy.kx_profile]}: {(edge.groups[edgeDraft || edge.policy.kx_profile] || []).join(", ")}.
                {" "}PQC required refuses clients without ML-KEM support, including every TLS 1.2 KMIP client.
              </div>
            </div>
          </>
        )}
      </Card>
      {edge && (() => {
        const cert = edge.certificate;
        const d = certDraft || { source: cert.choice.source, ca_id: cert.choice.ca_id || "", key_algorithm: cert.choice.key_algorithm || "ECDSA-P256" };
        const changed = d.source !== cert.choice.source || (d.source === "ca" && (d.ca_id !== (cert.choice.ca_id || "") || d.key_algorithm !== (cert.choice.key_algorithm || "")));
        const inst = cert.installed;
        return (
          <Card style={{ padding: 12, marginBottom: 10 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>Edge certificate (HTTPS)</div>
            <div style={{ fontSize: 10, color: C.dim, marginTop: 4 }}>
              The certificate the HTTPS edge serves on this node. vecta-runtime-root is the default; a CA from the PKI tab is
              issued and renewed by certs; an external CA signs a CSR this node generates, and the key never leaves the node
              (in a cluster, request and install on each node).
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 8, marginTop: 8, fontSize: 11 }}>
              <div>
                {inst ? <>
                  <div style={{ color: C.text }}>{inst.subject} · issued by {inst.issuer}</div>
                  <div style={{ color: C.dim, fontSize: 10 }}>serial {inst.serial.slice(0, 16)} · {inst.key_algorithm} · until {day(inst.not_after)} · SANs {(inst.sans || []).join(", ") || "none"}</div>
                </> : <div style={{ color: C.dim }}>no certificate installed</div>}
              </div>
              <div>
                {inst && inst.from_choice && cert.served ? <B c="green">served, from the chosen source</B>
                  : inst && inst.from_choice ? <B c="amber" pulse>installed; not measured as served yet</B>
                  : <B c="amber">{cert.choice.source === "external" ? "external certificate not installed on this node" : "being issued"}</B>}
              </div>
            </div>
            <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 8, flexWrap: "wrap" }}>
              <Sel value={d.source} onChange={(e: any) => setCertDraft({ ...d, source: String(e.target.value) })} w={220}>
                <option value="runtime">vecta-runtime-root (default)</option>
                <option value="ca">A CA from the PKI tab</option>
                <option value="external">An external CA (CSR)</option>
              </Sel>
              {d.source === "ca" && <>
                <Sel value={d.ca_id} onChange={(e: any) => setCertDraft({ ...d, ca_id: String(e.target.value) })} w={220}>
                  <option value="">Choose a CA</option>
                  {cas.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                </Sel>
                <Sel value={d.key_algorithm} onChange={(e: any) => setCertDraft({ ...d, key_algorithm: String(e.target.value) })} w={140}>
                  {(inv.meta.key_algorithms || []).map((a) => <option key={a} value={a}>{a}</option>)}
                </Sel>
              </>}
              <Btn small primary disabled={busy !== "" || !changed || (d.source === "ca" && !d.ca_id)}
                onClick={() => void run("edge-cert", async () => { await setEdgeCertificateSource(session, { ...d, reason }); setCertDraft(null); },
                  d.source === "external" ? "External source chosen; request a CSR on each node" : "Edge certificate issued; Envoy reloads it")}>
                Apply
              </Btn>
            </div>
            {cert.choice.source === "external" && (
              <div style={{ marginTop: 10, display: "grid", gap: 6 }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr auto", gap: 6 }}>
                  <Inp placeholder="Subject CN (e.g. kms.example.com)" value={csrCN} onChange={(e: any) => setCsrCN(String(e.target.value || ""))} />
                  <Inp placeholder="SANs, comma separated" value={csrSANs} onChange={(e: any) => setCsrSANs(String(e.target.value || ""))} />
                  <Btn small disabled={busy !== "" || (!csrCN && !csrSANs)} onClick={() => void run("edge-csr", async () => {
                    const out = await createEdgeCSR(session, { subject_cn: csrCN, sans: csrSANs.split(",").map((v) => v.trim()).filter(Boolean) });
                    setCsrPem(out.csr_pem);
                  }, "CSR created on this node; have your CA sign it")}>Create CSR</Btn>
                </div>
                {(csrPem || cert.pending_csr?.csr_pem) && <Txt rows={5} readOnly value={csrPem || cert.pending_csr?.csr_pem || ""} />}
                {cert.pending_csr && <>
                  <Txt rows={4} placeholder="Signed certificate (PEM)" value={signedPem} onChange={(e: any) => setSignedPem(String(e.target.value || ""))} />
                  <Txt rows={4} placeholder="Issuing CA chain (PEM)" value={chainPem} onChange={(e: any) => setChainPem(String(e.target.value || ""))} />
                  <div><Btn small primary disabled={busy !== "" || !signedPem} onClick={() => void run("edge-install", async () => {
                    await installEdgeCertificate(session, signedPem, chainPem, reason);
                    setSignedPem(""); setChainPem(""); setCsrPem("");
                  }, "Certificate installed on this node; Envoy reloads it")}>Install on this node</Btn></div>
                </>}
              </div>
            )}
          </Card>
        );
      })()}
      <Card style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1.3fr 1.5fr 1.6fr 1.2fr 1.6fr", gap: 8, padding: "8px 10px", fontSize: 10, fontWeight: 700, color: C.dim }}>
          <div>Identity</div><div>Certificate key</div><div>Key exchange (server)</div><div>State</div><div>Actions</div>
        </div>
        {items.map(row)}
      </Card>
    </Section>
  );
};
