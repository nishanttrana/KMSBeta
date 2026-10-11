import { useEffect, useState } from "react";
import type { AuthSession } from "../../lib/auth";
import { listHSMTargets, openCredentials, topologyLabel, type HSMTarget, type HSMTargets } from "../../lib/credentials";
import { clickable } from "../../components/v3/chartDrill";
import { B, Chk } from "../../components/v3/legacyPrimitives";
import { errMsg } from "../../components/v3/runtimeUtils";
import { C } from "../../components/v3/theme";

type Props = {
  session: AuthSession;
  // Whether this key's algorithm can live in an HSM, and why not if it can't.
  supported: boolean;
  unsupportedReason: string;
  // "generated": the HSM generates the key. "imported": material from
  // outside (an imported key, or one formed from components) is placed in it.
  material: "generated" | "imported";
  checked: boolean;
  onChecked: (on: boolean) => void;
  // "" is the tenant's HSM (HSM tab); otherwise an HSM credential's ID.
  connection: string;
  onConnection: (id: string) => void;
  onNavigate?: ((tab: string) => void) | undefined;
};

const device = (t: HSMTarget) => [t.status.manufacturer, t.status.model].filter(Boolean).join(" ")
  + (t.status.token_label ? ` · token ${t.status.token_label}` : "") + (t.status.serial_number ? ` · serial ${t.status.serial_number}` : "");

// "Create in HSM", then which HSM: the tenant's own (HSM tab) or one added
// as a credential, each shown as a single HSM or an HA group with what the
// library reports for it now.
export function HSMTargetPicker({ session, supported, unsupportedReason, material, checked, onChecked, connection, onConnection, onNavigate }: Props) {
  const [data, setData] = useState<HSMTargets | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    listHSMTargets(session).then((d) => { if (live) setData(d); }).catch((e) => { if (live) setError(errMsg(e)); });
    return () => { live = false; };
  }, [session]);

  const targets = data?.targets ?? [];
  const usable = targets.filter((t) => t.usable);
  // Checking the box picks the first HSM a key can go on.
  useEffect(() => {
    if (checked && !usable.some((t) => t.id === connection) && usable[0]) onConnection(usable[0].id);
  }, [checked, connection, usable, onConnection]);

  const add = <span onClick={() => openCredentials(onNavigate)} style={{ ...clickable, color: C.accentFg }}>Add an HSM in Playbooks, Credentials</span>;
  if (error) return <div style={{ fontSize: 11, color: C.amberFg, marginBottom: 10 }}>HSMs unavailable: {error}</div>;
  if (!data) return null;
  const note = data.credentials_state === "unavailable" ? `HSM credentials unavailable: ${data.credentials_error || "no answer"}. `
    : data.credentials_state === "not_permitted" ? "HSM credentials need the compliance.connection.use permission. " : "";
  if (targets.length === 0) {
    return <div style={{ fontSize: 11, color: C.muted, marginBottom: 10 }}>{note}No HSM is set up for keys. {data.credentials_state === "not_deployed" ? "Turn on HSM keys in the HSM tab." : add}{data.credentials_state === "not_deployed" ? "" : "."}</div>;
  }
  return (
    <div style={{ padding: "10px 12px", marginBottom: 10, borderRadius: 4, border: `1px solid ${checked ? C.accent : C.border}`, background: C.card }}>
      <Chk disabled={!supported || usable.length === 0}
        label={material === "generated" ? "Create in HSM (generated and used only inside the HSM)" : "Place in HSM (the material is kept only in the HSM)"}
        checked={checked && supported} onChange={() => onChecked(!checked)} />
      {!supported ? <div style={{ fontSize: 10.5, color: C.muted, margin: "-4px 0 6px" }}>{unsupportedReason}</div> : null}
      {supported && usable.length === 0 ? <div style={{ fontSize: 10.5, color: C.amberFg, margin: "-4px 0 6px" }}>No HSM is ready for keys.</div> : null}
      {checked && supported ? (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(240px,1fr))", gap: 8 }}>
          {targets.map((t) => {
            const on = t.id === connection;
            return (
              <div key={t.id || "tenant"} role="radio" aria-checked={on} tabIndex={t.usable ? 0 : -1} title={t.usable ? "" : t.reason}
                onClick={() => { if (t.usable) onConnection(t.id); }} onKeyDown={(e) => { if (e.key === "Enter" && t.usable) onConnection(t.id); }}
                style={{ cursor: t.usable ? "pointer" : "not-allowed", opacity: t.usable ? 1 : 0.55, borderRadius: 4, padding: "8px 10px", border: `1px solid ${on ? C.accent : C.border}`, background: on ? C.accentDim : "transparent" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 6 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{t.name}</span>
                  <B c={t.kind === "tenant_profile" ? "blue" : t.topology === "ha_group" ? "purple" : "accent"}>{t.kind === "tenant_profile" ? "Tenant HSM" : topologyLabel(t.topology)}</B>
                </div>
                <div style={{ fontSize: 10.5, color: t.usable ? C.dim : C.amberFg, marginTop: 3 }}>{t.usable ? (device(t) || "connected") : (t.reason || "not connected")}</div>
              </div>
            );
          })}
        </div>
      ) : null}
      <div style={{ fontSize: 10.5, color: C.muted, marginTop: 6 }}>{note}{data.credentials_state === "not_deployed" ? null : <>{add}.</>}</div>
    </div>
  );
}
