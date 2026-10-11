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
//
// The page shows state and controls only. What each control means is in
// docs/SECURITY/INTERNAL_TLS.md ("Reading the Service mTLS page"); a hint
// that fits in a tooltip goes in a title.

type Props = { session: any; onToast?: (msg: string) => void };

const PROFILE_LABEL: Record<string, string> = {
  "pqc-required": "PQC required",
  "pqc-preferred": "PQC preferred",
  classical: "Classical"
};

const ago = (iso?: string) => {
  if (!iso) return "";
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 90) return `${s}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
};

const day = (iso?: string) => (iso ? new Date(iso).toISOString().slice(0, 10) : "");

const EXPIRING_DAYS = 30;
const expiresSoon = (i: MTLSIdentity) => {
  const until = (i.kind === "service" ? i.observed?.[0]?.not_after : i.served_file?.not_after) || i.certificates?.[0]?.not_after;
  return Boolean(until) && new Date(until!).getTime() - Date.now() < EXPIRING_DAYS * 86_400_000;
};

// The views of the identity list. Each chip shows the number of rows it lists.
const VIEWS: { id: string; label: string; has: (i: MTLSIdentity) => boolean }[] = [
  { id: "all", label: "All", has: () => true },
  { id: "applying", label: "Applying", has: (i) => !i.applied },
  { id: "pqc-required", label: PROFILE_LABEL["pqc-required"]!, has: (i) => i.kind === "service" && i.policy.kx_profile === "pqc-required" },
  { id: "pqc-preferred", label: PROFILE_LABEL["pqc-preferred"]!, has: (i) => i.kind === "service" && i.policy.kx_profile === "pqc-preferred" },
  { id: "classical", label: PROFILE_LABEL.classical!, has: (i) => i.kind === "service" && i.policy.kx_profile === "classical" },
  { id: "expiring", label: `Expiring ≤${EXPIRING_DAYS}d`, has: expiresSoon }
];

const HEAD = { fontSize: 12, fontWeight: 600, color: C.text } as const;
const SUB = { fontSize: 10.5, color: C.dim, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" } as const;
const COLS = "1.1fr 1.7fr 1.5fr 1fr 1.3fr";

const Groups = ({ list, missing = false }: { list: string[]; missing?: boolean }) => (
  <span style={{ display: "inline-flex", gap: 4, flexWrap: "wrap" }}>
    {list.map((g) => (
      <span key={g} style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, padding: "1px 6px", borderRadius: 3, border: `1px ${missing ? "dashed" : "solid"} ${missing ? C.amberFg : C.border}`, color: missing ? C.amberFg : C.text }}>{g}</span>
    ))}
  </span>
);

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
  const [view, setView] = useState("all");
  const [edge, setEdge] = useState<EdgeTLS | null>(null);
  const [edgeError, setEdgeError] = useState("");
  const [edgeDraft, setEdgeDraft] = useState("");
  const [cas, setCAs] = useState<CertCA[]>([]);
  // Per listener (https, kmip).
  const [certDraft, setCertDraftMap] = useState<Record<string, { source: string; ca_id: string; key_algorithm: string } | null>>({});
  const [csrForm, setCsrForm] = useState<Record<string, { cn: string; sans: string; csr: string; signed: string; chain: string }>>({});

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

  if (error) return <Card style={{ padding: 12 }}><div style={{ fontSize: 11, color: C.redFg }}>Service mTLS unavailable: {error}</div></Card>;
  if (!inv) return <Card style={{ padding: 12 }}><div style={{ fontSize: 11, color: C.dim }}>Loading...</div></Card>;

  const q = filter.trim().toLowerCase();
  const shown = VIEWS.find((v) => v.id === view) || VIEWS[0]!;
  const items = inv.items.filter((i) => shown.has(i) && (!q || i.identity.includes(q) || i.host.includes(q)));

  const row = (i: MTLSIdentity) => {
    const d = draft[i.identity] || { key_algorithm: i.policy.key_algorithm, kx_profile: i.policy.kx_profile };
    const changed = d.key_algorithm !== i.policy.key_algorithm || (i.kind === "service" && d.kx_profile !== i.policy.kx_profile);
    const observed = i.observed || [];
    const live = i.kind === "service" ? observed[0] : i.served_file;
    const cert = (i.certificates || [])[0];
    const set = (patch: Partial<typeof d>) => setDraft((prev) => ({ ...prev, [i.identity]: { ...d, ...patch } }));
    return (
      <div key={i.identity} data-testid="mtls-identity" style={{ display: "grid", gridTemplateColumns: COLS, gap: 8, padding: "8px 10px", borderTop: `1px solid ${C.border}`, alignItems: "center", fontSize: 11 }}>
        <div>
          <div style={{ fontWeight: 600, color: C.text }}>{i.identity}</div>
          <div style={SUB}>{i.host} · {i.kind === "service" ? "service" : "daemon"}</div>
        </div>
        <div style={{ minWidth: 0 }}>
          <div style={SUB} title={live?.serial || cert?.serial}>
            {[live?.key_algorithm || cert?.key_algorithm || "not reported", (live?.serial || cert?.serial || "").slice(0, 16) || "no certificate",
              (live?.not_after || cert?.not_after) ? `until ${day(live?.not_after || cert?.not_after)}` : ""].filter(Boolean).join(" · ")}
          </div>
          <Sel aria-label={`${i.identity} certificate key`} value={d.key_algorithm} onChange={(e: any) => set({ key_algorithm: String(e.target.value) })} style={{ marginTop: 4 }}>
            {inv.meta.key_algorithms.map((a) => <option key={a} value={a}>{a}</option>)}
          </Sel>
        </div>
        <div style={{ minWidth: 0 }} title={i.kind === "service" ? undefined : i.note}>
          {i.kind === "service" ? (
            <>
              <div style={SUB}>
                {[PROFILE_LABEL[live?.kx_profile || ""] || live?.kx_profile || "not reported",
                  live?.last_handshake_group ? `${live.last_handshake_group} · ${ago(live.last_handshake_at)}` : "no handshake yet"].join(" · ")}
              </div>
              <Sel aria-label={`${i.identity} key exchange`} value={d.kx_profile} onChange={(e: any) => set({ kx_profile: String(e.target.value) })} style={{ marginTop: 4 }}>
                {(i.kx_profiles || inv.meta.kx_profiles).map((p) => <option key={p} value={p}>{PROFILE_LABEL[p] || p}</option>)}
              </Sel>
            </>
          ) : (
            <div style={SUB}>set by the daemon</div>
          )}
        </div>
        <div>
          {i.applied
            ? <B c="green">{`gen ${i.policy.generation} · running`}</B>
            : <B c="amber" pulse>{observed.length === 0 && i.kind === "service" ? "not reported" : `applying gen ${i.policy.generation}`}</B>}
          {i.kind === "service" && (observed.length > 1 || live?.started_at) && (
            <div style={{ ...SUB, marginTop: 2 }}>{[observed.length > 1 ? `${observed.length} instances` : "", live?.started_at ? `up ${ago(live.started_at).replace(" ago", "")}` : ""].filter(Boolean).join(" · ")}</div>
          )}
        </div>
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
          <Btn small primary disabled={!changed || busy !== ""} onClick={() => void run(i.identity, () => setInternalMTLSPolicy(session, i.identity,
            i.kind === "service" ? { key_algorithm: d.key_algorithm, kx_profile: d.kx_profile, reason } : { key_algorithm: d.key_algorithm, reason }), `${i.identity}: policy saved; ${i.kind === "service" ? "the service restarts gracefully to apply it" : "certificate reissued, the daemon reloads it"}`)}>
            Apply
          </Btn>
          <Btn small disabled={busy !== ""} title={i.kind === "service" ? "Revoke the certificate, then a graceful restart with a new key" : "Revoke and reissue; the daemon reloads it"}
            onClick={() => void run(i.identity, () => rotateInternalMTLS(session, i.identity, "graceful", reason),
              `${i.identity}: certificate revoked; ${i.kind === "service" ? "graceful restart with a fresh key" : "new certificate written"}`)}>
            Rotate
          </Btn>
          {i.restart_modes.includes("force") && (confirmForce === i.identity ? (
            <Btn small danger disabled={busy !== ""} onClick={() => { setConfirmForce(""); void run(i.identity, () => rotateInternalMTLS(session, i.identity, "force", reason),
              `${i.identity}: certificate revoked (key compromise); forced restart`); }}>
              Confirm force
            </Btn>
          ) : (
            <Btn small danger disabled={busy !== ""} title="Revoke as key compromise and restart at once" onClick={() => setConfirmForce(i.identity)}>Force</Btn>
          ))}
        </div>
      </div>
    );
  };

  const edgeChoice = edge ? edgeDraft || edge.policy.kx_profile : "";

  return (
    <div data-testid="service-mtls">
    <Section title="Service mTLS" actions={<>
      <span title="Issuing CA"><B c="accent">{inv.meta.sub_ca}</B></span>
      <B c={inv.meta.fips_mode ? "green" : "blue"}>{inv.meta.fips_mode ? "FIPS on" : "FIPS off"}</B>
      <B c={pending > 0 ? "amber" : "green"}>{pending > 0 ? `${pending} applying` : "all applied"}</B>
    </>}>
      <Card style={{ padding: 12, marginBottom: 10 }}>
        <div style={HEAD}>Edge key exchange</div>
        {edgeError ? (
          <div style={{ fontSize: 11, color: C.redFg, marginTop: 4 }}>Edge key exchange unavailable: {edgeError}</div>
        ) : !edge ? (
          <div style={{ ...SUB, marginTop: 4 }}>Loading...</div>
        ) : (
          <>
            {edge.listeners.map((l) => {
              const accepted = l.observed?.server_groups || [];
              const missing = l.expected_groups.filter((g) => !accepted.includes(g));
              return (
                <div key={l.name} data-testid="edge-listener" style={{ display: "grid", gridTemplateColumns: "150px 1fr auto", gap: 10, alignItems: "center", padding: "8px 0", borderBottom: `1px solid ${C.border}`, fontSize: 11 }}>
                  <div><div style={{ fontWeight: 600, color: C.text }}>{l.name}</div><div style={SUB}>{l.address}</div></div>
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                    {l.observed ? <Groups list={accepted} /> : <span style={SUB}>not measured</span>}
                    {l.observed && !l.applied && <Groups list={missing} missing />}
                  </div>
                  <div style={{ display: "flex", gap: 6, alignItems: "center" }} title={`Chosen: ${l.expected_groups.join(", ")}`}>
                    {l.observed?.last_handshake_at && <span style={SUB}>{ago(l.observed.last_handshake_at)}</span>}
                    {l.applied ? <B c="green">in force</B> : <B c="amber" pulse>{l.observed ? "differs" : "not measured"}</B>}
                  </div>
                </div>
              );
            })}
            <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 10, flexWrap: "wrap" }}>
              <Sel aria-label="Edge key exchange" value={edgeChoice} onChange={(e: any) => setEdgeDraft(String(e.target.value))} w={200}>
                {edge.kx_profiles.map((p) => <option key={p} value={p}>{PROFILE_LABEL[p] || p}</option>)}
              </Sel>
              <Btn small primary disabled={busy !== "" || !edgeDraft || edgeDraft === edge.policy.kx_profile}
                onClick={() => void run("edge", async () => { await setEdgeTLS(session, edgeDraft, reason); setEdgeDraft(""); },
                  "Edge key exchange saved; Envoy and KMIP apply it within about 20 s")}>
                Apply
              </Btn>
              {edgeChoice !== edge.policy.kx_profile && <Groups list={edge.groups[edgeChoice] || []} />}
            </div>
            {edgeChoice === "pqc-required" && edgeChoice !== edge.policy.kx_profile && (
              <div data-keep="" style={{ fontSize: 11, color: C.amberFg, marginTop: 6 }}>Refuses clients without ML-KEM, including every TLS 1.2 KMIP client.</div>
            )}
          </>
        )}
      </Card>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(420px, 1fr))", gap: 10, marginBottom: 10 }}>
        {edge && ([["https", "HTTPS certificate", edge.certificate], ["kmip", "KMIP certificate", edge.kmip_certificate]] as const).map(([listener, title, cert]) => {
          if (!cert) return null;
          const d = certDraft[listener] || { source: cert.choice.source, ca_id: cert.choice.ca_id || "", key_algorithm: cert.choice.key_algorithm || "ECDSA-P256" };
          const setD = (next: typeof d | null) => setCertDraftMap((p) => ({ ...p, [listener]: next }));
          const f = csrForm[listener] || { cn: "", sans: "", csr: "", signed: "", chain: "" };
          const setF = (patch: Partial<typeof f>) => setCsrForm((p) => ({ ...p, [listener]: { ...f, ...patch } }));
          const changed = d.source !== cert.choice.source || (d.source === "ca" && (d.ca_id !== (cert.choice.ca_id || "") || d.key_algorithm !== (cert.choice.key_algorithm || "")));
          const inst = cert.installed;
          return (
            <Card key={listener} style={{ padding: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
                <div style={HEAD}>{title}</div>
                {inst && inst.from_choice && cert.served ? <B c="green">served</B>
                  : inst && inst.from_choice ? <B c="amber" pulse>installed, not measured</B>
                  : <B c="amber">{cert.choice.source === "external" ? "not installed on this node" : "being issued"}</B>}
              </div>
              {inst ? <>
                <div style={{ fontSize: 11, color: C.text, marginTop: 6 }}>{inst.subject}</div>
                <div style={SUB}>{inst.issuer}</div>
                <div style={SUB}>{inst.serial.slice(0, 16)} · {inst.key_algorithm} · until {day(inst.not_after)} · {(inst.sans || []).join(", ") || "no SANs"}</div>
              </> : <div style={{ ...SUB, marginTop: 6 }}>no certificate installed</div>}
              <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 8, flexWrap: "wrap" }}>
                <Sel aria-label={`${title} source`} value={d.source} onChange={(e: any) => setD({ ...d, source: String(e.target.value) })} w={200}>
                  <option value="runtime">vecta-runtime-root (default)</option>
                  <option value="ca">PKI tab CA</option>
                  <option value="external">External CA (CSR)</option>
                </Sel>
                {d.source === "ca" && <>
                  <Sel aria-label={`${title} CA`} value={d.ca_id} onChange={(e: any) => setD({ ...d, ca_id: String(e.target.value) })} w={200}>
                    <option value="">Choose a CA</option>
                    {cas.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                  </Sel>
                  <Sel aria-label={`${title} key`} value={d.key_algorithm} onChange={(e: any) => setD({ ...d, key_algorithm: String(e.target.value) })} w={140}>
                    {(inv.meta.key_algorithms || []).map((a) => <option key={a} value={a}>{a}</option>)}
                  </Sel>
                </>}
                <Btn small primary disabled={busy !== "" || !changed || (d.source === "ca" && !d.ca_id)}
                  onClick={() => void run(`${listener}-cert`, async () => { await setEdgeCertificateSource(session, { listener, ...d, reason }); setD(null); },
                    d.source === "external" ? "External source chosen; request a CSR on each node" : `${title}: issued; the listener reloads it`)}>
                  Apply
                </Btn>
              </div>
              {cert.choice.source === "external" && (
                <div style={{ marginTop: 10, display: "grid", gap: 6 }}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr auto", gap: 6 }}>
                    <Inp placeholder="Subject CN (e.g. kms.example.com)" value={f.cn} onChange={(e: any) => setF({ cn: String(e.target.value || "") })} />
                    <Inp placeholder="SANs, comma separated" value={f.sans} onChange={(e: any) => setF({ sans: String(e.target.value || "") })} />
                    <Btn small disabled={busy !== "" || (!f.cn && !f.sans)} onClick={() => void run(`${listener}-csr`, async () => {
                      const out = await createEdgeCSR(session, { listener, subject_cn: f.cn, sans: f.sans.split(",").map((v) => v.trim()).filter(Boolean) });
                      setF({ csr: out.csr_pem });
                    }, "CSR created on this node; have your CA sign it")}>Create CSR</Btn>
                  </div>
                  {(f.csr || cert.pending_csr?.csr_pem) && <Txt rows={5} readOnly value={f.csr || cert.pending_csr?.csr_pem || ""} />}
                  {cert.pending_csr && <>
                    <Txt rows={4} placeholder="Signed certificate (PEM)" value={f.signed} onChange={(e: any) => setF({ signed: String(e.target.value || "") })} />
                    <Txt rows={4} placeholder="Issuing CA chain (PEM)" value={f.chain} onChange={(e: any) => setF({ chain: String(e.target.value || "") })} />
                    <div><Btn small primary disabled={busy !== "" || !f.signed} onClick={() => void run(`${listener}-install`, async () => {
                      await installEdgeCertificate(session, listener, f.signed, f.chain, reason);
                      setF({ signed: "", chain: "", csr: "" });
                    }, "Certificate installed on this node; the listener reloads it")}>Install on this node</Btn></div>
                  </>}
                </div>
              )}
            </Card>
          );
        })}
      </div>
      <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 8, flexWrap: "wrap" }}>
        {VIEWS.map((v) => {
          const n = inv.items.filter(v.has).length;
          const on = v.id === shown.id;
          return (
            <button key={v.id} aria-pressed={on} onClick={() => setView(v.id)} style={{ display: "inline-flex", gap: 6, alignItems: "center", height: 26, padding: "0 9px", borderRadius: 3, cursor: "pointer", fontSize: 11.5, border: `1px solid ${on ? C.accentFg : C.border}`, background: on ? C.accentDim : "transparent", color: on ? C.text : C.dim }}>
              {v.label}<span className="vk-num" style={{ fontFamily: "var(--font-mono)", fontWeight: 600, color: C.text }}>{n}</span>
            </button>
          );
        })}
        <span style={{ flex: 1 }} />
        <Inp aria-label="Filter identities" placeholder="Filter" value={filter} onChange={(e: any) => setFilter(String(e.target.value || ""))} w={160} />
        <Inp aria-label="Reason, recorded in the audit log" placeholder="Reason (audited)" value={reason} onChange={(e: any) => setReason(String(e.target.value || ""))} w={220} />
      </div>
      <Card style={{ padding: 0, overflow: "hidden", marginBottom: 10 }}>
        <div style={{ display: "grid", gridTemplateColumns: COLS, gap: 8, padding: "8px 10px", fontSize: 10.5, fontWeight: 500, fontFamily: "var(--font-mono)", textTransform: "uppercase", letterSpacing: "0.06em", color: C.muted }}>
          <div>Identity</div><div>Certificate key</div><div title={inv.meta.signature_note}>Key exchange</div><div>State</div><div>Actions</div>
        </div>
        {items.map(row)}
        {items.length === 0 && <div style={{ ...SUB, padding: "10px", borderTop: `1px solid ${C.border}` }}>No identity matches.</div>}
      </Card>
      <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
        <Sel aria-label="Restart mode" value={allMode} onChange={(e: any) => setAllMode(e.target.value as MTLSRestartMode)} w={150}>
          <option value="graceful">Graceful restarts</option>
          <option value="force">Forced restarts</option>
        </Sel>
        <Inp aria-label="Confirm rotating every certificate" placeholder='Type "rotate-all"' value={allConfirm} onChange={(e: any) => setAllConfirm(String(e.target.value || ""))} w={150} />
        <Btn small danger={allMode === "force"} primary={allMode === "graceful"} disabled={busy !== "" || allConfirm !== "rotate-all"}
          onClick={() => void run("rotate-all", async () => {
            const out = await rotateAllInternalMTLS(session, allMode, reason, allConfirm);
            setAllConfirm("");
            onToast?.(`Every internal certificate revoked; services restart one every ${inv.meta.rotate_all_step}s (about ${Math.round(out.restart_span_seconds / 60)} min, certs last).`);
          }, "Rotation of every internal certificate started")}>
          Rotate every certificate
        </Btn>
      </div>
    </Section>
    </div>
  );
};
