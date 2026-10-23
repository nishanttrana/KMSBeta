import { useEffect, useState } from "react";
import type { AuthSession } from "../../../lib/auth";
import { getClientRole, listAuthRoles, setClientRole, type AuthRole, type ClientRole } from "../../../lib/authAdmin";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { Btn, FG, Sel } from "../legacyPrimitives";

// A REST client's granted role (docs/CI_CD_AUTOMATION.md "A role for a
// client"): its tokens hold the role's permissions, so it can be given key
// operations. Without one it reads and writes secrets and signs only.

export function RestClientRole({ session, client, onToast }: { session: AuthSession; client: any; onToast?: ((m: string) => void) | undefined }) {
  const id = String(client?.id || "");
  const [current, setCurrent] = useState<ClientRole | null>(null);
  const [roles, setRoles] = useState<AuthRole[]>([]);
  const [choice, setChoice] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    let live = true;
    void Promise.all([getClientRole(session, id), listAuthRoles(session)]).then(([r, all]) => {
      if (!live) return;
      setCurrent(r);
      setChoice(r.role || "");
      setRoles(all);
      setError("");
    }, (e) => live && setError(errMsg(e)));
    return () => { live = false; };
  }, [session, id]);

  if (!id || String(client?.status || "") === "revoked") return null;
  const save = async () => {
    try {
      const r = await setClientRole(session, id, choice);
      setCurrent(r);
      onToast?.(r.role ? `Client tokens now hold the ${r.role} role's permissions.` : "Client tokens hold the default permissions again.");
    } catch (e) {
      onToast?.(errMsg(e));
    }
  };
  return (
    <FG label="Granted role" hint="Its tokens hold this role's permissions. None: secrets and signing only.">
      {error ? <div style={{ fontSize: 11, color: C.redFg }}>{`Role unavailable: ${error}`}</div> : (
        <>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <Sel aria-label="Client granted role" value={choice} onChange={(e: any) => setChoice(String(e.target.value))}>
              <option value="">None (secrets and signing)</option>
              {roles.map((r) => <option key={r.role_name} value={r.role_name}>{r.role_name}</option>)}
            </Sel>
            <Btn small primary disabled={current === null || choice === (current?.role || "")} onClick={() => void save()}>Save role</Btn>
          </div>
          {current && <div data-testid="client-role-permissions" style={{ fontSize: 10.5, color: C.dim, marginTop: 4 }}>{`Tokens hold: ${current.permissions.join(", ") || "nothing"}`}</div>}
        </>
      )}
    </FG>
  );
}
