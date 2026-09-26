import { useCallback, useEffect, useState } from "react";
import { B, Btn, Inp } from "../../components/v3/legacyPrimitives";
import { C } from "../../components/v3/theme";
import { errMsg } from "../../components/v3/runtimeUtils";
import {
  EXPOSURE_SERVICES,
  acknowledgeExposure,
  listExposureReports,
  summarize,
  type ExposureItem,
  type ExposureReport
} from "../../lib/mekExposure";

// Items stored under a public development key before 1.2.0-beta. The live data
// has been moved to a keycore-held key; this list tracks what an older database
// copy or backup could still reveal until the material itself is replaced.
// docs/SECURITY/SERVICE_MASTER_KEYS.md

type Props = { session: any; onToast?: (msg: string) => void };

export const ExposurePanel = ({ session, onToast }: Props) => {
  const [reports, setReports] = useState<ExposureReport[] | null>(null);
  const [ack, setAck] = useState<{ service: string; item: ExposureItem } | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [showClosed, setShowClosed] = useState(false);

  const load = useCallback(async () => {
    if (!session?.token) return;
    try {
      setReports(await listExposureReports(session));
    } catch (error) {
      setReports(null);
      onToast?.(`Exposure register unavailable: ${errMsg(error)}`);
    }
  }, [session, onToast]);

  useEffect(() => { void load(); }, [load]);

  const acknowledge = async () => {
    if (!ack) return;
    setBusy(true);
    try {
      await acknowledgeExposure(session, ack.service, ack.item, reason.trim());
      onToast?.(`Acknowledged ${ack.item.item_id}; recorded in the audit log.`);
      setAck(null);
      setReason("");
      await load();
    } catch (error) {
      onToast?.(`Acknowledge failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  if (!reports) return <div style={{ fontSize: 10, color: C.dim }}>Key exposure register: not assessed.</div>;
  const sum = summarize(reports);

  return (
    <div style={{ display: "grid", gap: 6, padding: "10px 12px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>Key exposure register</div>
        {sum.open > 0 ? <B c="red">{`${sum.open} open`}</B> : sum.servicesChecked > 0 ? <B c="green">none open</B> : <B c="amber">not assessed</B>}
      </div>
      <div style={{ fontSize: 10, color: C.dim }}>
        Before 1.2.0-beta these items were stored under a key published in the source code. They are now under a
        keycore-held key, but a database copy or backup made earlier can still reveal them. Each closes when its
        material is replaced; acknowledge only with a recorded reason.
      </div>
      {reports.map((r) => {
        const meta = EXPOSURE_SERVICES.find((s) => s.service === r.service);
        const open = r.items.filter((i) => !i.remediated_at);
        const closed = r.items.filter((i) => i.remediated_at);
        return (
          <div key={r.service} style={{ borderTop: `1px solid ${C.border}`, paddingTop: 6 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10 }}>
              <b style={{ color: C.text }}>{r.label}</b>
              <span style={{ color: r.status === "ok" ? (open.length ? C.red : C.green) : C.dim }}>
                {r.status === "ok" ? `${open.length} open · ${closed.length} closed` : r.status === "no_access" ? "no access" : "not deployed or unreachable"}
              </span>
            </div>
            {open.length > 0 && <div style={{ fontSize: 10, color: C.dim }}>{meta?.remedy}</div>}
            {open.map((i) => (
              <div key={i.item_type + i.item_id} style={{ display: "flex", justifyContent: "space-between", gap: 8, fontSize: 10, color: C.text }}>
                <span>{i.item_type} <b>{i.item_id}</b> · since {new Date(i.exposed_since).toLocaleString()}</span>
                <Btn small onClick={() => { setAck({ service: r.service, item: i }); setReason(""); }}>Acknowledge</Btn>
              </div>
            ))}
            {showClosed && closed.map((i) => (
              <div key={i.item_type + i.item_id} style={{ fontSize: 10, color: C.dim }}>
                {i.item_type} {i.item_id}: {i.remediation} by {i.remediated_by || "system"}
              </div>
            ))}
          </div>
        );
      })}
      {sum.remediated > 0 && (
        <Btn small onClick={() => setShowClosed((v) => !v)}>{showClosed ? "Hide closed" : `Show ${sum.remediated} closed`}</Btn>
      )}
      {ack && (
        <div style={{ border: `1px solid ${C.amber}`, borderRadius: 8, padding: 8, display: "grid", gap: 6 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: C.amber }}>Acknowledge {ack.item.item_type} {ack.item.item_id}</div>
          <div style={{ fontSize: 10, color: C.dim }}>
            Only when the material is not in use or its exposure is accepted. The reason is recorded in the audit log.
          </div>
          <Inp placeholder="Reason (at least 10 characters)" value={reason} onChange={(e: any) => setReason(String(e.target.value || ""))} />
          <div style={{ display: "flex", gap: 6 }}>
            <Btn small onClick={() => setAck(null)}>Cancel</Btn>
            <Btn small primary disabled={busy || reason.trim().length < 10} onClick={() => void acknowledge()}>
              {busy ? "Saving..." : "Acknowledge"}
            </Btn>
          </div>
        </div>
      )}
    </div>
  );
};
