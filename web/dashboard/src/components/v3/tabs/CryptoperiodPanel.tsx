import { useCallback, useEffect, useState } from "react";
import { Btn, Card, Inp, Section } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import { listCryptoperiods, resetCryptoperiod, setCryptoperiod, type Cryptoperiod } from "../../../lib/rotationScheduler";

const LABELS: Record<string, string> = {
  symmetric_encrypt: "Symmetric encryption",
  symmetric_mac: "MAC",
  key_wrap: "Key wrapping",
  signing: "Signing",
  ephemeral: "DEK / ephemeral",
  master: "Master / KEK",
};

// Cryptoperiods the key lifecycle scan uses: an active key older than its
// category's period is rotated by the reconciler.
export const CryptoperiodPanel = ({ session }: { session: any }) => {
  const [items, setItems] = useState<Cryptoperiod[]>([]);
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    try {
      const rows = await listCryptoperiods(session);
      setItems(rows);
      setDraft(Object.fromEntries(rows.map((r) => [r.category, String(r.days)])));
      setError("");
    } catch (e) {
      setError(`Cryptoperiods unavailable: ${errMsg(e)}`);
    }
  }, [session]);
  useEffect(() => { void load(); }, [load]);

  const run = async (category: string, fn: () => Promise<void>) => {
    setBusy(category);
    try { await fn(); await load(); } catch (e) { setError(errMsg(e)); } finally { setBusy(""); }
  };

  return (
    <Section title="Cryptoperiods">
      {error && <div style={{ fontSize: 11, color: C.red, marginBottom: 8 }}>{error}</div>}
      <Card style={{ padding: 0, overflow: "hidden" }}>
        {items.map((r) => (
          <div key={r.category} style={{ display: "grid", gridTemplateColumns: "1.4fr 0.8fr 0.8fr 1.2fr", gap: 8, alignItems: "center", padding: "8px 14px", borderBottom: `1px solid ${C.border}`, fontSize: 11 }}>
            <div style={{ color: C.text }}>{LABELS[r.category] || r.category}{r.custom ? "" : <span style={{ color: C.muted }}> (default)</span>}</div>
            <div style={{ color: C.muted }}>default {r.default_days} d</div>
            <Inp type="number" min={1} max={3650} value={draft[r.category] ?? ""} onChange={(e: any) => setDraft({ ...draft, [r.category]: e.target.value })} />
            <div style={{ display: "flex", gap: 6 }}>
              <Btn small primary disabled={busy === r.category} onClick={() => void run(r.category, () => setCryptoperiod(session, r.category, Number(draft[r.category])))}>Save</Btn>
              {r.custom && <Btn small disabled={busy === r.category} onClick={() => void run(r.category, () => resetCryptoperiod(session, r.category))}>Reset</Btn>}
            </div>
          </div>
        ))}
      </Card>
    </Section>
  );
};
