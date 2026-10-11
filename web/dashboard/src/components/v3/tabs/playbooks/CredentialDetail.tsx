import { useEffect, useState } from "react";
import type { AuthSession } from "../../../../lib/auth";
import { credentialUsage, topologyLabel, type Credential, type CredentialType } from "../../../../lib/credentials";
import { clickable } from "../../chartDrill";
import { B, Btn, Modal } from "../../legacyPrimitives";
import { errMsg } from "../../runtimeUtils";
import { C } from "../../theme";
import { USED_IN, ageDays, categoryLabel, expiryBucket, fmtAgo, fmtDate, health, rotationDue } from "./credentialMeta";

type Props = {
  session: AuthSession;
  credential: Credential;
  type?: CredentialType | undefined;
  exposedSince?: string | undefined;
  now: number;
  busy: boolean;
  onNavigate?: ((tab: string) => void) | undefined;
  onClose: () => void;
  onTest: () => void;
  onEdit: () => void;
  onDelete: () => void;
};

const Line = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <div style={{ display: "grid", gridTemplateColumns: "150px 1fr", gap: 10, padding: "6px 0", borderBottom: `1px solid ${C.border}`, fontSize: 11 }}>
    <span style={{ color: C.muted }}>{label}</span><span style={{ color: C.text, overflowWrap: "anywhere" }}>{children}</span>
  </div>
);

// One credential: what it is, whether it works, how old its secret is and
// everything that uses it. No field value is shown, only which are set.
export function CredentialDetail({ session, credential: c, type, exposedSince, now, busy, onNavigate, onClose, onTest, onEdit, onDelete }: Props) {
  const [usedBy, setUsedBy] = useState<string[] | null>(null);
  const [usageError, setUsageError] = useState("");
  useEffect(() => {
    let live = true;
    setUsedBy(null);
    setUsageError("");
    credentialUsage(session, c.id).then((u) => { if (live) setUsedBy(u); }).catch((e) => { if (live) setUsageError(errMsg(e)); });
    return () => { live = false; };
  }, [session, c.id]);

  const h = health(c);
  const home = USED_IN[type?.category ?? ""];
  const expiry = expiryBucket(c, now);
  return (
    <Modal open onClose={onClose} title={c.name} width={600}>
      {exposedSince ? (
        <div style={{ padding: "8px 10px", marginBottom: 10, borderRadius: 3, border: `1px solid ${C.redFg}`, color: C.redFg, fontSize: 11 }}>
          Stored in plaintext by an earlier release (exposed since {fmtDate(exposedSince)}). Rotate it where it was issued, then edit this credential and enter every new value.
        </div>
      ) : null}
      <Line label="Type">{type?.label ?? c.type} <span style={{ color: C.muted }}>· {categoryLabel(type?.category ?? "")}</span></Line>
      <Line label="Endpoint">{c.endpoint || "-"}</Line>
      {c.type === "pkcs11_hsm" ? <Line label="Topology">{topologyLabel(c.attributes?.topology)} <span style={{ color: C.muted }}>(as declared)</span></Line> : null}
      {Object.entries(c.attributes ?? {}).filter(([k]) => k !== "topology").map(([k, v]) => <Line key={k} label={k}>{v}</Line>)}
      <Line label="Fields set">{(c.fields_set ?? []).join(", ") || "-"}</Line>
      <Line label="Health">
        {h === "ok" ? <B c="green">Test passed</B> : h === "failing" ? <B c="red">Test failed</B> : <B c="blue">Not tested</B>}
        <span style={{ marginLeft: 8, color: C.muted }}>{c.last_tested_at ? fmtAgo(c.last_tested_at) : "since the secret last changed"}</span>
        {c.last_test_error ? <div style={{ color: C.redFg, marginTop: 4 }}>{c.last_test_error}</div> : null}
      </Line>
      <Line label="Secret age">{ageDays(c, now)} days{c.rotate_after_days ? ` · rotate every ${c.rotate_after_days} days` : ""}{rotationDue(c, now) ? <span style={{ marginLeft: 8 }}><B c="amber">Rotation due</B></span> : null}</Line>
      <Line label="Expires">{c.expires_at ? fmtDate(c.expires_at) : "no expiry set"}{expiry === "expired" ? <span style={{ marginLeft: 8 }}><B c="red">Expired</B></span> : ["7d", "30d"].includes(expiry) ? <span style={{ marginLeft: 8 }}><B c="amber">Expiring</B></span> : null}</Line>
      <Line label="Used by">
        {usageError ? <span style={{ color: C.amberFg }}>unavailable: {usageError}</span>
          : usedBy === null ? <span style={{ color: C.muted }}>checking…</span>
            : usedBy.length === 0 ? <span style={{ color: C.muted }}>nothing yet</span>
              : usedBy.map((u) => <div key={u}>{u}</div>)}
        {home && onNavigate ? <div style={{ marginTop: 4 }}><span onClick={() => onNavigate(home.tab)} style={{ ...clickable, color: C.accentFg }}>Choose it in {home.label}</span></div> : null}
      </Line>
      <Line label="ID"><span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5 }}>{c.id}</span></Line>
      <Line label="Added">{fmtDate(c.created_at)} by {c.created_by || "-"}</Line>
      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 14 }}>
        <Btn danger onClick={onDelete}>Delete</Btn>
        <Btn onClick={onEdit}>Edit</Btn>
        <Btn primary disabled={busy} onClick={onTest}>{busy ? "Testing…" : "Test now"}</Btn>
      </div>
    </Modal>
  );
}
