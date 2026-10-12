import { useEffect, useState } from "react";
import type { AuthSession } from "../../lib/auth";
import { setKeyDescription } from "../../lib/keycore";
import { Btn, FG, Inp } from "../../components/v3/legacyPrimitives";
import { errMsg } from "../../components/v3/runtimeUtils";

// A key's description in its detail view, editable in place
// (PUT /keys/{id}/description, permission key.update). It is display text:
// no access decision reads it.

export const MAX_KEY_DESCRIPTION = 512;

type Props = {
  session: AuthSession | null;
  keyItem: { id: string; description?: string };
  readOnly?: boolean;
  onSaved: (description: string) => void;
  onToast?: (msg: string) => void;
};

export function KeyDescription({ session, keyItem, readOnly, onSaved, onToast }: Props) {
  const stored = String(keyItem.description || "");
  const [text, setText] = useState(stored);
  const [busy, setBusy] = useState(false);
  useEffect(() => setText(stored), [keyItem.id, stored]);

  const save = async () => {
    if (!session) return;
    setBusy(true);
    try {
      const out = await setKeyDescription(session, keyItem.id, text);
      onSaved(out);
      onToast?.("Description saved");
    } catch (error) {
      onToast?.(`Description not saved: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <FG label="Description">
      <div style={{ display: "flex", gap: 8 }}>
        <Inp aria-label="Key description" placeholder={readOnly ? "None" : "What this key protects"} maxLength={MAX_KEY_DESCRIPTION} value={text} readOnly={readOnly} onChange={(e) => setText(e.target.value)} />
        {!readOnly && <Btn small primary disabled={busy || text.trim() === stored} onClick={() => void save()}>{busy ? "Saving..." : "Save"}</Btn>}
      </div>
    </FG>
  );
}
