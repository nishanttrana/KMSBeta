import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../../../lib/auth";
import {
  BYOKRunError, getBYOKKey, runBYOKOperation,
  type BYOKCapabilities, type BYOKDetail, type BYOKKey, type BYOKOperation, type BYOKRun,
} from "../../../../lib/byok";
import { errMsg } from "../../runtimeUtils";
import { B, Btn, Inp, Modal, usePromptDialog } from "../../legacyPrimitives";
import { C } from "../../theme";
import { MONO, SOURCE_LABEL, STATES, cloudLabel, fmtDate, stateOf } from "./meta";
import { RunSteps } from "./RunSteps";

type Props = {
  session: AuthSession;
  id: string;
  // The listed row: a cloud-generated key has no BYOK record to fetch.
  listed?: BYOKKey | undefined;
  caps?: BYOKCapabilities | undefined;
  onClose: () => void;
  onChanged: () => void;
  onToast?: ((msg: string) => void) | undefined;
};

const Fact = ({ l, v, mono }: { l: string; v: string; mono?: boolean }) => (
  <div style={{ minWidth: 0 }}>
    <div style={{ fontSize: 10, color: C.muted }}>{l}</div>
    <div title={v} style={{ fontSize: 11.5, color: C.text, fontFamily: mono ? MONO : "inherit", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v || "-"}</div>
  </div>
);

export function BYOKKeyDetail({ session, id, listed, caps, onClose, onChanged, onToast }: Props) {
  const [detail, setDetail] = useState<BYOKDetail | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [days, setDays] = useState("");
  const [lastRun, setLastRun] = useState<BYOKRun | null>(null);
  const [open, setOpen] = useState("");
  const prompt = usePromptDialog();

  const load = useCallback(async () => {
    if (listed?.origin === "cloud-generated") {
      setDetail({ key: listed, materials: [], runs: [] });
      return;
    }
    try {
      setDetail(await getBYOKKey(session, id));
      setError("");
    } catch (e) {
      setError(errMsg(e));
    }
  }, [session, id, listed]);
  useEffect(() => { void load(); }, [load]);

  const k = detail?.key;
  const state = k ? stateOf(k) : "pending";
  const hasRevoked = !!detail?.materials.some((m) => m.state === "revoked");
  const pending = k?.material_state === "pending_import" || k?.material_state === "failed";
  const byok = k?.origin === "byok";

  const act = async (op: BYOKOperation) => {
    if (!k) return;
    if (op === "revoke") {
      const ok = await prompt.confirm({
        title: caps?.revoke_deletes ? "Delete the key material in the cloud" : "Disable the key in the cloud",
        message: `${cloudLabel(k.provider)} stops using this key's current material until it is restored. The material stays in the KMS (version history), so restore brings it back.`,
        confirmLabel: caps?.revoke_deletes ? "Delete material" : "Disable", danger: true,
      });
      if (!ok) return;
    }
    setBusy(op);
    try {
      const n = Number(days);
      const out = await runBYOKOperation(session, k.id, op, n > 0 ? { validity_days: n } : {});
      setLastRun(out.run);
      onToast?.(`${op}: done`);
    } catch (e) {
      if (e instanceof BYOKRunError && e.run) setLastRun(e.run);
      onToast?.(`${op} failed: ${errMsg(e)}`);
    } finally {
      setBusy("");
      await load();
      onChanged();
    }
  };

  const action = (op: BYOKOperation, label: string, show: boolean, danger = false) =>
    show ? <Btn key={op} small danger={danger} disabled={!!busy} onClick={() => void act(op)}>{busy === op ? `${label}…` : label}</Btn> : null;

  return (
    <Modal open onClose={onClose} title={k ? `${cloudLabel(k.provider)} · ${k.alias || k.cloud_key_id || k.id}` : "Cloud key"} wide>
      <div style={{ padding: 20, display: "grid", gap: 14 }}>
        {error && <div style={{ fontSize: 11, color: C.redFg }}>Unavailable: {error}</div>}
        {k && <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 10 }}>
            <Fact l="KMS key" v={k.key_id} mono />
            <Fact l="Material from" v={k.origin === "byok" ? (SOURCE_LABEL[k.source] ?? k.source) : "the cloud"} />
            <Fact l="Key spec" v={k.key_spec} />
            <Fact l="Cloud key" v={k.cloud_key_ref || k.cloud_key_id} mono />
            <Fact l="Region" v={k.region} />
            <Fact l="Cloud state" v={k.cloud_state} />
            <Fact l="Material" v={STATES.find((s) => s.id === state)?.label ?? state} />
            <Fact l="Expires" v={k.expires_at ? fmtDate(k.expires_at) : "does not expire"} />
          </div>

          {byok ? (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              {action("rotate", "Rotate", !!caps?.rotate && state === "current")}
              {action("reimport", pending ? "Import material" : "Reimport", pending || (!!caps?.reimport && state === "current"))}
              {action("restore", "Restore", hasRevoked)}
              {action("verify", "Verify", !!caps?.verify && state === "current")}
              {action("sync", "Sync", true)}
              {action("revoke", caps?.revoke_deletes ? "Delete material" : "Disable", !!caps?.revoke && state === "current", true)}
              {caps?.expiry && <span style={{ display: "flex", gap: 6, alignItems: "center", fontSize: 10.5, color: C.muted }}>
                valid for <Inp w="70px" value={days} onChange={(e) => setDays(e.target.value.replace(/\D/g, ""))} placeholder="days" /> days (empty: no expiry)
              </span>}
            </div>
          ) : (
            <div className="vk-fold" tabIndex={0} style={{ fontSize: 11, color: C.muted }}>The cloud generated this key's material (created before 10.0.0-beta). It is listed for inventory; bring a KMS key to the cloud to manage material here.</div>
          )}

          {lastRun && <div style={{ border: `1px solid ${C.border}`, borderRadius: 4, padding: 10 }}><RunSteps run={lastRun} /></div>}

          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 6 }}>Custody</div>
            <div style={{ display: "grid", gridTemplateColumns: "60px 70px 1.4fr 90px 1fr 60px 1fr", gap: 8, fontSize: 10, color: C.muted, padding: "0 4px 4px", borderBottom: `1px solid ${C.border}` }}>
              <span>KMS ver.</span><span>KCV</span><span>Cloud material</span><span>State</span><span>Wrapped with</span><span>In</span><span>Imported</span>
            </div>
            {(detail?.materials ?? []).map((m) => (
              <div key={m.id} style={{ display: "grid", gridTemplateColumns: "60px 70px 1.4fr 90px 1fr 60px 1fr", gap: 8, fontSize: 11, padding: "5px 4px", borderBottom: `1px solid ${C.border}`, alignItems: "center" }}>
                <span style={{ fontFamily: MONO }}>v{m.kms_version}</span>
                <span style={{ fontFamily: MONO }}>{m.kcv}</span>
                <span title={m.cloud_material_id} style={{ fontFamily: MONO, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{m.cloud_material_id || "-"}</span>
                <span><B c={m.state === "current" ? "green" : m.state === "revoked" ? "red" : "blue"}>{m.state}</B></span>
                <span title={`wrapping key SHA-256 ${m.wrapping_key_sha256}`} style={{ fontFamily: MONO, fontSize: 10 }}>{m.scheme}</span>
                <span>{SOURCE_LABEL[m.source] ?? m.source}</span>
                <span style={{ color: C.dim }}>{fmtDate(m.imported_at)}</span>
              </div>
            ))}
            {!detail?.materials.length && <div style={{ fontSize: 11, color: C.muted, padding: 6 }}>No material imported yet.</div>}
          </div>

          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 6 }}>Runs</div>
            <div style={{ display: "grid", gap: 6 }}>
              {(detail?.runs ?? []).map((r) => (
                <div key={r.id} style={{ border: `1px solid ${C.border}`, borderRadius: 4, padding: "6px 10px" }}>
                  <button type="button" onClick={() => setOpen(open === r.id ? "" : r.id)} style={{ all: "unset", cursor: "pointer", display: "flex", justifyContent: "space-between", width: "100%", fontSize: 11 }}>
                    <span style={{ color: C.text }}>{r.operation} · {r.steps.length} steps</span>
                    <span style={{ display: "flex", gap: 8, color: C.muted }}>{r.actor} · {fmtDate(r.started_at)} <B c={r.status === "succeeded" ? "green" : "red"}>{r.status}</B></span>
                  </button>
                  {open === r.id && <div style={{ marginTop: 8 }}><RunSteps run={r} compact /></div>}
                </div>
              ))}
              {!detail?.runs.length && <div style={{ fontSize: 11, color: C.muted }}>No runs.</div>}
            </div>
          </div>
        </>}
      </div>
      {prompt.ui}
    </Modal>
  );
}
