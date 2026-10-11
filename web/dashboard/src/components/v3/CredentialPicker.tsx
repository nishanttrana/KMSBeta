import { useEffect, useState } from "react";
import type { AuthSession } from "../../lib/auth";
import { listCredentialChoices, openCredentials, type Credential } from "../../lib/credentials";
import { clickable } from "./chartDrill";
import { Sel } from "./legacyPrimitives";
import { errMsg } from "./runtimeUtils";
import { C } from "./theme";

type Props = {
  session: AuthSession | null;
  // The credential type a feature uses (one of them).
  type: string;
  value: string;
  onChange: (id: string) => void;
  onNavigate?: ((tab: string) => void) | undefined;
  disabled?: boolean;
};

// Chooses a credential that was added in Playbooks → Credentials. A feature
// never takes a secret itself: when none of the type exists yet, the picker
// says so and links to where one is added.
export function CredentialPicker({ session, type, value, onChange, onNavigate, disabled = false }: Props) {
  const [items, setItems] = useState<Credential[] | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    setItems(null);
    setError("");
    if (!type || !session) return undefined;
    listCredentialChoices(session, { type }).then((list) => { if (live) setItems(list); }).catch((e) => { if (live) setError(errMsg(e)); });
    return () => { live = false; };
  }, [session, type]);

  const add = (
    <span onClick={() => openCredentials(onNavigate)} style={{ ...clickable, color: C.accentFg }}>Add one in Playbooks, Credentials</span>
  );
  const chosen = items?.find((c) => c.id === value);
  return (
    <div>
      <Sel value={value} disabled={disabled || !items || items.length === 0} onChange={(e: { target: { value: string } }) => onChange(e.target.value)}>
        <option value="">{error ? "unavailable" : items === null ? "loading…" : items.length ? "choose a credential…" : "none of this type yet"}</option>
        {(items ?? []).map((c) => <option key={c.id} value={c.id}>{c.name}{c.endpoint ? ` (${c.endpoint})` : ""}</option>)}
      </Sel>
      <div style={{ fontSize: 10.5, color: C.muted, marginTop: 4 }}>
        {error ? <span style={{ color: C.amberFg }}>Credentials unavailable: {error}. </span> : null}
        {chosen && chosen.last_tested_at && !chosen.last_test_ok ? <span style={{ color: C.redFg }}>Its last test failed: {chosen.last_test_error || "see Credentials"}. </span> : null}
        {chosen && !chosen.last_tested_at ? <span>Not tested yet. </span> : null}
        {items && items.length === 0 && !error ? <>No credential of this type. {add}.</> : <>{add}.</>}
      </div>
    </div>
  );
}
