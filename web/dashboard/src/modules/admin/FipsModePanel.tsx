import { useCallback, useEffect, useState } from "react";
import { B, Btn, Inp } from "../../components/v3/legacyPrimitives";
import { C } from "../../components/v3/theme";
import { errMsg } from "../../components/v3/runtimeUtils";
import {
  getFipsModeImpact,
  getFipsModeStatus,
  setFipsMode,
  type FipsMode,
  type FipsModeImpact,
  type FipsModeStatus
} from "../../lib/governance";

// Platform FIPS 140-3 mode: the customer's choice, changed here (root admin).
// Services apply it with a staggered, graceful restart and report the mode they
// actually run, shown below as rollout progress. docs/SECURITY/FIPS.md

type Props = { session: any; onToast?: (msg: string) => void };

const MODE_LABEL: Record<FipsMode, string> = {
  on: "On: certified module in FIPS mode",
  only: "Only: strict, non-approved algorithms refused",
  off: "Off: FIPS mode disabled"
};

export const FipsModePanel = ({ session, onToast }: Props) => {
  const [status, setStatus] = useState<FipsModeStatus | null>(null);
  const [target, setTarget] = useState<FipsMode | "">("");
  const [impact, setImpact] = useState<FipsModeImpact | null>(null);
  const [confirm, setConfirm] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!session?.token) return;
    try {
      setStatus(await getFipsModeStatus(session));
    } catch (error) {
      setStatus(null);
      onToast?.(`FIPS mode status unavailable: ${errMsg(error)}`);
    }
  }, [session, onToast]);

  useEffect(() => { void load(); }, [load]);
  // Poll while a change is rolling out.
  useEffect(() => {
    if (!status || status.converged) return;
    const id = window.setInterval(() => void load(), 5000);
    return () => window.clearInterval(id);
  }, [status, load]);

  const review = async (mode: FipsMode) => {
    setTarget(mode);
    setConfirm("");
    setImpact(null);
    if (!status || mode === status.effective) return;
    try {
      setImpact(await getFipsModeImpact(session, mode));
    } catch (error) {
      onToast?.(`Impact analysis failed: ${errMsg(error)}`);
    }
  };

  const apply = async () => {
    if (!target || !impact) return;
    setBusy(true);
    try {
      await setFipsMode(session, target, confirm, reason);
      onToast?.(`FIPS mode set to ${target}. Services restart in tiers over about ${impact.estimated_seconds}s.`);
      setImpact(null);
      setTarget("");
      setConfirm("");
      await load();
    } catch (error) {
      onToast?.(`FIPS mode change failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  if (!status) return <div style={{ fontSize: 10, color: C.dim }}>Platform FIPS mode: not assessed.</div>;

  const list = (title: string, color: string, items: FipsModeImpact["stops"]) =>
    items.length === 0 ? null : (
      <div style={{ marginTop: 6 }}>
        <div style={{ fontSize: 10, fontWeight: 700, color }}>{title}</div>
        {items.map((i) => (
          <div key={i.service + i.feature} style={{ fontSize: 10, color: C.text }}>
            <b>{i.service}</b>: {i.feature}. <span style={{ color: C.dim }}>{i.detail}</span>
          </div>
        ))}
      </div>
    );

  return (
    <div style={{ display: "grid", gap: 6, padding: "10px 12px", border: `1px solid ${C.border}`, borderRadius: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: C.text }}>Platform FIPS 140-3 mode</div>
        {status.converged ? <B c="green">{`${status.effective} · all services`}</B> : <B c="amber">{`applying ${status.effective} · ${status.pending} pending`}</B>}
      </div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {(["on", "only", "off"] as FipsMode[]).map((m) => (
          <Btn key={m} small primary={target === m || (!target && status.effective === m)} disabled={busy} onClick={() => void review(m)}>
            {MODE_LABEL[m]}
          </Btn>
        ))}
      </div>
      {impact && (
        <div style={{ border: `1px solid ${impact.downgrade ? C.red : C.amber}`, borderRadius: 8, padding: 8 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: impact.downgrade ? C.red : C.amber }}>
            {impact.downgrade ? "Security downgrade: " : ""}{impact.from} to {impact.to}
          </div>
          {list("Stops working", C.red, impact.stops)}
          {list("Starts working", C.green, impact.starts)}
          {impact.notes.map((n) => <div key={n} style={{ fontSize: 10, color: C.dim, marginTop: 4 }}>{n}</div>)}
          <div style={{ fontSize: 10, color: C.dim, marginTop: 4 }}>
            Restarts ({impact.restarts.length}): {impact.restarts.join(", ") || "all services"}. About {impact.estimated_seconds}s; core services restart last.
          </div>
          <div style={{ display: "grid", gap: 6, marginTop: 8 }}>
            <Inp placeholder="Reason (recorded in the audit log)" value={reason} onChange={(e: any) => setReason(String(e.target.value || ""))} />
            <Inp placeholder={`Type "${impact.to}" to confirm`} value={confirm} onChange={(e: any) => setConfirm(String(e.target.value || ""))} />
            <Btn small danger={impact.downgrade} primary={!impact.downgrade} disabled={busy || confirm.trim().toLowerCase() !== impact.to} onClick={() => void apply()}>
              {busy ? "Applying..." : `Switch to ${impact.to} and restart services`}
            </Btn>
          </div>
        </div>
      )}
      {status.services.length > 0 && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(180px,1fr))", gap: 4, marginTop: 4 }}>
          {status.services.map((s) => (
            <div key={s.service + s.instance} style={{ fontSize: 10, color: s.mode === status.effective ? C.dim : C.amber }}>
              {s.service}: {s.mode}{s.validated ? " · validated" : ""}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
