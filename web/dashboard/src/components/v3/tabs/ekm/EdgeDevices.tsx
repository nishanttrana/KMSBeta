import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../../../lib/auth";
import {
  createEdgeDevice,
  issueEdgeToken,
  listEdgeDevices,
  listEdgeLeases,
  listEdgeReceipts,
  revokeEdgeDevice,
  revokeEdgeLease,
  type EdgeDevice,
  type EdgeLease,
  type EdgeReceipt
} from "../../../../lib/edge";
import { errMsg } from "../../runtimeUtils";
import { C } from "../../theme";
import { B, Btn, Card, FG, Inp, Row2, Section, usePromptDialog } from "../../legacyPrimitives";

// Edge devices (docs/SECURITY/EDGE_DEVICES.md): devices that lease data
// keys, encrypt offline and report signed receipts. The page shows state and
// controls; what each means is in the docs.

const when = (iso?: string) => (iso ? new Date(iso).toISOString().slice(0, 16).replace("T", " ") : "never");
const list = (text: string) => text.split(",").map((s) => s.trim()).filter(Boolean);
const STATUS: Record<string, "green" | "amber" | "red"> = { active: "green", pending: "amber", revoked: "red" };

export function EdgeDevices({ session }: { session: AuthSession }) {
  const [items, setItems] = useState<EdgeDevice[] | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [adding, setAdding] = useState(false);
  const [token, setToken] = useState<{ device: string; token: string; expires_at: string } | null>(null);
  const [open, setOpen] = useState("");
  const prompt = usePromptDialog();

  const load = useCallback(async () => {
    try {
      setItems(await listEdgeDevices(session));
      setError("");
    } catch (e) {
      setError(errMsg(e));
    }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const issue = async (d: EdgeDevice) => {
    try {
      const out = await issueEdgeToken(session, d.id);
      setToken({ device: d.name, token: out.token, expires_at: out.expires_at });
      void load();
    } catch (e) {
      setNotice(errMsg(e));
    }
  };
  const revoke = async (d: EdgeDevice) => {
    const reason = await prompt.prompt({ title: `Revoke ${d.name}`, message: "It can lease nothing more, and drops its leases at its next sync.", confirmLabel: "Revoke", danger: true });
    if (reason === null || reason === undefined) return;
    try {
      await revokeEdgeDevice(session, d.id, String(reason));
      setNotice(`${d.name} revoked.`);
      void load();
    } catch (e) {
      setNotice(errMsg(e));
    }
  };

  return (
    <Section title="Edge devices" actions={<Btn small primary onClick={() => setAdding(!adding)}>{adding ? "Cancel" : "Add device"}</Btn>}>
      {prompt.ui}
      {notice && <div style={{ fontSize: 11, color: C.dim, marginBottom: 6 }}>{notice}</div>}
      {adding && <AddDevice session={session} onDone={(d) => { setAdding(false); setNotice(`${d.name} added: issue its registration token.`); void load(); }} />}
      {token && (
        <Card style={{ marginBottom: 10 }}>
          <div style={{ fontSize: 11, color: C.dim }}>{`Registration token for ${token.device}, shown once, valid until ${when(token.expires_at)}:`}</div>
          <div data-testid="edge-token" style={{ fontSize: 10.5, fontFamily: "var(--font-mono)", color: C.text, overflowWrap: "anywhere", margin: "4px 0" }}>{token.token}</div>
          <div style={{ fontSize: 10.5, fontFamily: "var(--font-mono)", color: C.dim }}>edge-agent enroll -server https://&lt;kms&gt;/svc/ekm -token-file &lt;file&gt;</div>
          <Btn small onClick={() => setToken(null)}>Done</Btn>
        </Card>
      )}
      {error ? <div style={{ fontSize: 11, color: C.redFg }}>{`Edge devices unavailable: ${error}`}</div>
        : items === null ? <div style={{ fontSize: 11, color: C.muted }}>Loading…</div>
          : items.length === 0 ? <div style={{ fontSize: 11, color: C.muted }}>No edge devices.</div>
            : items.map((d) => (
              <div key={d.id} data-testid="edge-device-row" style={{ borderTop: `1px solid ${C.border}`, padding: "8px 0" }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: C.text, cursor: "pointer" }} onClick={() => setOpen(open === d.id ? "" : d.id)}>{d.name}</span>
                  <span style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <B c={STATUS[d.status] || "neutral"}>{d.status}</B>
                    {d.status !== "revoked" && <Btn small onClick={() => void issue(d)}>{d.status === "active" ? "Re-enrol token" : "Registration token"}</Btn>}
                    {d.status !== "revoked" && <Btn small danger onClick={() => void revoke(d)}>Revoke</Btn>}
                  </span>
                </div>
                <div style={{ fontSize: 10.5, color: C.dim, marginTop: 3 }}>
                  {`Keys ${d.allowed_key_ids.join(", ")} · leases up to ${Math.round(d.max_lease_seconds / 3600)} h · last seen ${when(d.last_seen_at)}${d.last_source_ip ? ` from ${d.last_source_ip}` : ""} · receipts to ${d.last_receipt_seq}`}
                  {d.revoked_at && ` · revoked ${when(d.revoked_at)} by ${d.revoked_by}${d.revoke_reason ? `: ${d.revoke_reason}` : ""}`}
                </div>
                {open === d.id && <DeviceDetail session={session} device={d} onNotice={setNotice} />}
              </div>
            ))}
    </Section>
  );
}

function AddDevice({ session, onDone }: { session: AuthSession; onDone: (d: EdgeDevice) => void }) {
  const [name, setName] = useState("");
  const [keys, setKeys] = useState("");
  const [hours, setHours] = useState("24");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true);
    try {
      onDone(await createEdgeDevice(session, { name: name.trim(), allowed_key_ids: list(keys), max_lease_seconds: Math.round(Number(hours) * 3600) }));
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card style={{ marginBottom: 10 }}>
      <Row2>
        <FG label="Name" required><Inp aria-label="Edge device name" value={name} onChange={(e: any) => setName(e.target.value)} placeholder="pump-17" /></FG>
        <FG label="Longest lease (hours)"><Inp aria-label="Edge device longest lease" value={hours} onChange={(e: any) => setHours(e.target.value)} /></FG>
      </Row2>
      <FG label="Keys it may lease" required hint="Key IDs, comma-separated. You must be able to wrap with each.">
        <Inp aria-label="Edge device keys" value={keys} onChange={(e: any) => setKeys(e.target.value)} />
      </FG>
      {error && <div style={{ fontSize: 11, color: C.redFg, marginBottom: 6 }}>{error}</div>}
      <Btn small primary disabled={busy || !name.trim() || !list(keys).length} onClick={() => void submit()}>{busy ? "Checking keys…" : "Add device"}</Btn>
    </Card>
  );
}

function DeviceDetail({ session, device, onNotice }: { session: AuthSession; device: EdgeDevice; onNotice: (s: string) => void }) {
  const [leases, setLeases] = useState<EdgeLease[] | null>(null);
  const [receipts, setReceipts] = useState<EdgeReceipt[] | null>(null);
  const load = useCallback(async () => {
    try {
      const [l, r] = await Promise.all([listEdgeLeases(session, device.id), listEdgeReceipts(session, device.id)]);
      setLeases(l);
      setReceipts(r);
    } catch (e) {
      onNotice(errMsg(e));
    }
  }, [session, device.id, onNotice]);
  useEffect(() => { void load(); }, [load]);
  const revoke = async (l: EdgeLease) => {
    try {
      await revokeEdgeLease(session, l.id);
      onNotice("Lease revoked: the device drops it at its next sync.");
      void load();
    } catch (e) {
      onNotice(errMsg(e));
    }
  };
  const now = Date.now();
  return (
    <div style={{ fontSize: 10.5, marginTop: 6, display: "grid", gap: 6 }}>
      <div>
        <div style={{ color: C.dim }}>Leases</div>
        {leases === null ? "Loading…" : leases.length === 0 ? <span style={{ color: C.muted }}>None.</span> : leases.map((l) => (
          <div key={l.id} data-testid="edge-lease-row" style={{ display: "flex", gap: 8, alignItems: "center", color: C.text }}>
            <span style={{ fontFamily: "var(--font-mono)" }}>{l.id}</span>
            <span>{`${l.key_id} v${l.key_version} until ${when(l.expires_at)}`}</span>
            {l.revoked_at ? <B c="red">revoked</B> : new Date(l.expires_at).getTime() < now ? <B c="neutral">expired</B> : <Btn small danger onClick={() => void revoke(l)}>Revoke</Btn>}
          </div>
        ))}
      </div>
      <div>
        <div style={{ color: C.dim }}>Latest receipts</div>
        {receipts === null ? "Loading…" : receipts.length === 0 ? <span style={{ color: C.muted }}>None.</span> : receipts.slice(0, 20).map((r) => (
          <div key={r.seq} style={{ color: C.text }}>{`#${r.seq} ${r.operation} ${r.bytes} bytes under ${r.lease_id} at ${when(r.at)}`}</div>
        ))}
      </div>
    </div>
  );
}
