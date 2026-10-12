import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../../../lib/auth";
import {
  AUTOMATION_PLAYBOOKS, automationOf, automationPlaybooks, createAutomationPlaybook, setBYOKAutomation,
  type BYOKCapabilities, type BYOKKey,
} from "../../../../lib/byok";
import { errMsg } from "../../runtimeUtils";
import { B, Btn, FG, Inp, Row2 } from "../../legacyPrimitives";
import { C } from "../../theme";

// Automation: rules on this key, and the tenant playbooks that act on them.
// The cloud service only announces that material is expiring or due; a
// playbook renews or rotates it through the same routes a person uses, on
// the authority of whoever created it.
export function BYOKAutomationPanel({ session, k, caps, onSaved, onToast }: {
  session: AuthSession; k: BYOKKey; caps?: BYOKCapabilities | undefined; onSaved: () => void; onToast?: ((m: string) => void) | undefined;
}) {
  const a = automationOf(k);
  const [renew, setRenew] = useState(a.renew_before_days ? String(a.renew_before_days) : "");
  const [validity, setValidity] = useState(a.renew_validity_days ? String(a.renew_validity_days) : "");
  const [rotate, setRotate] = useState(a.rotate_every_days ? String(a.rotate_every_days) : "");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [books, setBooks] = useState<Record<string, unknown> | null>(null);
  const [booksError, setBooksError] = useState("");

  const loadBooks = useCallback(() => {
    automationPlaybooks(session).then((b) => { setBooks(b); setBooksError(""); }).catch((e) => setBooksError(errMsg(e)));
  }, [session]);
  useEffect(() => { loadBooks(); }, [loadBooks]);

  const num = (s: string) => Number(s || 0) || 0;
  const save = async () => {
    setBusy(true);
    setError("");
    try {
      await setBYOKAutomation(session, k.id, { renew_before_days: num(renew), renew_validity_days: num(validity), rotate_every_days: num(rotate) });
      onToast?.("Automation saved");
      onSaved();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };
  const digits = (set: (v: string) => void) => (e: { target: { value: string } }) => set(e.target.value.replace(/\D/g, ""));
  const needed = AUTOMATION_PLAYBOOKS.filter((p) => (p.trigger === "byok_material_expiring" ? num(renew) > 0 : num(rotate) > 0));

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <Row2>
        {caps?.expiry ? (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            <FG label="Renew before expiry (days)" hint="Same material, new expiry. Empty: off.">
              <Inp value={renew} onChange={digits(setRenew)} placeholder="30" />
            </FG>
            <FG label="Renewed for (days)" hint="At most 365.">
              <Inp value={validity} onChange={digits(setValidity)} placeholder="90" />
            </FG>
          </div>
        ) : <div style={{ fontSize: 11, color: C.muted, alignSelf: "center" }}>This cloud's imported material doesn't expire.</div>}
        {caps?.rotate ? (
          <FG label="Rotate every (days)" hint="A new KMS version imported as new material. Empty: off.">
            <Inp value={rotate} onChange={digits(setRotate)} placeholder="365" />
          </FG>
        ) : <div style={{ fontSize: 11, color: C.muted, alignSelf: "center" }}>This cloud can't take new material on a key.</div>}
      </Row2>
      <div><Btn small primary disabled={busy} onClick={() => void save()}>{busy ? "Saving…" : "Save rules"}</Btn></div>
      {error && <div style={{ fontSize: 11, color: C.redFg }}>{error}</div>}

      <div>
        <div style={{ fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 6 }}>Playbooks that act on the rules</div>
        {booksError && <div style={{ fontSize: 11, color: C.redFg }}>Playbooks unavailable: {booksError}</div>}
        {books && AUTOMATION_PLAYBOOKS.map((p) => (
          <div key={p.trigger} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, padding: "5px 0", borderBottom: `1px solid ${C.border}`, fontSize: 11 }}>
            <span style={{ color: C.text }}>{p.name}</span>
            {books[p.trigger] ? <B c="green">active</B> : (
              <Btn small primary={needed.includes(p)} onClick={() => {
                createAutomationPlaybook(session, p.trigger).then(() => { onToast?.(`Playbook created: ${p.name}`); loadBooks(); })
                  .catch((e) => setBooksError(errMsg(e)));
              }}>Create playbook</Btn>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
