import { useEffect, useState } from "react";
import { CheckCircle2, Lock, Plus, X } from "lucide-react";
import { Btn, Inp, Modal, Sel } from "../../legacyPrimitives";
import { C } from "../../theme";
import { errMsg } from "../../runtimeUtils";
import {
  BUCKET_CONNECTION_TYPE, addDiscoveryBucket, listSourceConnections, removeDiscoveryBucket, testDiscoveryBucket,
  type DiscoveryBucket, type SourceConnection,
} from "../../../../lib/discovery";
import type { AuthSession } from "../../../../lib/auth";
import { MONO } from "./meta";

// Each service is one of the two APIs the scan speaks: S3 (signed requests)
// or Azure Blob (a SAS token). endpoint/region set here are fixed for it.
type Service = { id: string; label: string; provider: DiscoveryBucket["provider"]; endpoint?: string; region?: string; endpointHint: string };
const SERVICES: Service[] = [
  { id: "aws", label: "Amazon S3", provider: "s3", endpoint: "", endpointHint: "set by the region" },
  { id: "s3", label: "S3-compatible (MinIO, Ceph, R2)", provider: "s3", endpointHint: "https://storage.example.com" },
  { id: "gcs", label: "Google Cloud Storage", provider: "s3", endpoint: "https://storage.googleapis.com", region: "auto", endpointHint: "" },
  { id: "azure", label: "Azure Blob Storage", provider: "azure", region: "", endpointHint: "https://account.blob.core.windows.net" },
];
const PROVIDER_LABEL: Record<string, string> = { s3: "S3", azure: "Azure" };

type Props = {
  open: boolean;
  onClose: () => void;
  session: AuthSession;
  buckets: DiscoveryBucket[];
  error: string;
  onChanged: () => void;
  onToast?: (msg: string) => void;
  onNavigate?: (tab: string) => void;
};

type TestState = { busy?: boolean; ok?: string; fail?: string };

export function BucketsModal({ open, onClose, session, buckets, error, onChanged, onToast, onNavigate }: Props) {
  const [serviceId, setServiceId] = useState("aws");
  const [endpoint, setEndpoint] = useState("");
  const [region, setRegion] = useState("");
  const [name, setName] = useState("");
  const [prefix, setPrefix] = useState("");
  const [connection, setConnection] = useState("");
  const [busy, setBusy] = useState(false);
  const [connections, setConnections] = useState<SourceConnection[]>([]);
  const [connError, setConnError] = useState("");
  const [tests, setTests] = useState<Record<string, TestState>>({});
  const service = SERVICES.find((s) => s.id === serviceId) ?? SERVICES[0]!;
  const fixedEndpoint = service.endpoint !== undefined;
  const fixedRegion = service.region !== undefined;

  useEffect(() => {
    if (!open) return;
    listSourceConnections(session, Object.values(BUCKET_CONNECTION_TYPE))
      .then((c) => { setConnections(c); setConnError(""); })
      .catch((e) => { setConnections([]); setConnError(errMsg(e)); });
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: reload the connection list each time the dialog opens.
  }, [open, session?.tenantId, session?.token]);

  const offered = connections.filter((c) => c.type === BUCKET_CONNECTION_TYPE[service.provider]);
  const pickService = (id: string) => { setServiceId(id); setConnection(""); };
  const ready = !!name.trim() && (fixedEndpoint || !!endpoint.trim());

  const add = async () => {
    if (!ready) return;
    setBusy(true);
    try {
      await addDiscoveryBucket(session, {
        provider: service.provider, endpoint: fixedEndpoint ? service.endpoint! : endpoint.trim(),
        bucket: name.trim(), prefix: prefix.trim(), region: fixedRegion ? service.region! : region.trim(), connection_id: connection,
      });
      setName(""); setPrefix("");
      onChanged();
    } catch (e) {
      onToast?.(`Add bucket failed: ${errMsg(e)}`);
    } finally {
      setBusy(false);
    }
  };
  const remove = async (b: DiscoveryBucket) => {
    try {
      await removeDiscoveryBucket(session, b.id);
      onChanged();
    } catch (e) {
      onToast?.(`Remove bucket failed: ${errMsg(e)}`);
    }
  };
  const test = async (b: DiscoveryBucket) => {
    setTests((t) => ({ ...t, [b.id]: { busy: true } }));
    try {
      const res = await testDiscoveryBucket(session, b.id);
      setTests((t) => ({ ...t, [b.id]: { ok: `${res.objects_listed} objects listed, ${res.objects_read} read` } }));
    } catch (e) {
      setTests((t) => ({ ...t, [b.id]: { fail: errMsg(e) } }));
    }
  };
  const connName = (id: string) => connections.find((c) => c.id === id)?.name || id;
  const row = { display: "grid", gap: 8, alignItems: "center", marginBottom: 8 } as const;

  return (
    <Modal open={open} onClose={onClose} title="Object storage" width={860}>
      <div style={{ ...row, gridTemplateColumns: "minmax(200px,1.3fr) minmax(220px,2fr) minmax(110px,.8fr)" }}>
        <Sel value={serviceId} onChange={(e) => pickService(e.target.value)}>
          {SERVICES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
        </Sel>
        <Inp mono placeholder={service.endpointHint} disabled={fixedEndpoint} value={fixedEndpoint ? service.endpoint : endpoint} onChange={(e) => setEndpoint(e.target.value)} />
        <Inp mono placeholder={service.provider === "azure" ? "no region" : "region (us-east-1)"} disabled={fixedRegion} value={fixedRegion ? service.region : region} onChange={(e) => setRegion(e.target.value)} />
      </div>
      <div style={{ ...row, gridTemplateColumns: "minmax(150px,1.2fr) minmax(130px,1fr) minmax(170px,1.3fr) auto" }}>
        <Inp mono placeholder={service.provider === "azure" ? "container" : "bucket"} value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void add(); }} />
        <Inp mono placeholder="prefix (optional)" value={prefix} onChange={(e) => setPrefix(e.target.value)} />
        <Sel value={connection} onChange={(e) => setConnection(e.target.value)}>
          <option value="">Public (no credential)</option>
          {offered.map((c) => <option key={c.id} value={c.id}>{c.name} · {c.endpoint}</option>)}
        </Sel>
        <Btn primary onClick={() => void add()} disabled={busy || !ready}><Plus size={12} />{busy ? "Adding..." : "Add"}</Btn>
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, fontSize: 10.5, color: C.muted, marginBottom: 12 }}>
        <span>{connError ? `Connections unavailable: ${connError}` : "Source, config, key and certificate files are read in memory. A private bucket reads with a connection's credential."}</span>
        <button type="button" onClick={() => onNavigate?.("playbooks")} style={{ background: "none", border: "none", color: C.accentFg, cursor: "pointer", fontSize: 10.5, padding: 0, whiteSpace: "nowrap" }}>New storage connection</button>
      </div>
      {error ? (
        <div style={{ fontSize: 11, color: C.redFg }}>Buckets unavailable: {error}</div>
      ) : buckets.length ? (
        <div style={{ border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
          {buckets.map((b, i) => {
            const t = tests[b.id] || {};
            return (
              <div key={b.id} style={{ borderTop: i ? `1px solid ${C.border}` : "none", padding: "8px 12px" }}>
                <div style={{ display: "grid", gridTemplateColumns: "70px 1fr auto auto 28px", alignItems: "center", gap: 10 }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: C.blueFg }}>{PROVIDER_LABEL[b.provider] ?? b.provider}</span>
                  <span style={{ fontFamily: MONO, fontSize: 11.5, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {b.endpoint.replace(/^https:\/\//, "")}/{b.bucket}{b.prefix ? <span style={{ color: C.muted }}>/{b.prefix}</span> : null}
                  </span>
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 10.5, color: C.muted }}>
                    {b.connection_id ? <><Lock size={11} />{connName(b.connection_id)}</> : "public"}
                  </span>
                  <Btn small onClick={() => void test(b)} disabled={t.busy}>{t.busy ? "Testing..." : "Test"}</Btn>
                  <button type="button" aria-label={`Remove ${b.bucket}`} onClick={() => void remove(b)} style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", display: "inline-flex" }}><X size={13} /></button>
                </div>
                {t.ok && <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 10.5, color: C.greenFg, marginTop: 5, paddingLeft: 80 }}><CheckCircle2 size={11} />Readable · {t.ok}</div>}
                {t.fail && <div style={{ fontSize: 10.5, color: C.redFg, marginTop: 5, paddingLeft: 80, wordBreak: "break-word" }}>Not readable: {t.fail}</div>}
              </div>
            );
          })}
        </div>
      ) : (
        <div style={{ fontSize: 11, color: C.muted, textAlign: "center", padding: 18, border: `1px dashed ${C.border}`, borderRadius: 8 }}>No buckets yet</div>
      )}
    </Modal>
  );
}
