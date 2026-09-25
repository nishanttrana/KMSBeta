import { useCallback, useEffect, useState } from "react";
import { B, Btn, Card, Section } from "../legacyPrimitives";
import { C } from "../theme";
import { errMsg } from "../runtimeUtils";
import { kdfReprotectVault, kdfTransition, listKeyKDF, type KeyKDFState } from "../../../lib/dataprotect";

// Working-key derivation migration for data protection keys. Keys that
// predate 2026-09-25 derive working keys from public identifiers (v1); this
// panel shows each key's state and walks it to keycore-derived keys (v2).
// docs/SECURITY/DATAPROTECT_KEY_DERIVATION.md

type Props = { session: any; onToast?: (msg: string) => void };

const stateBadge = (s: string) =>
  s === "v2" ? <B c="green">v2 · keycore-derived</B> : s === "migrating" ? <B c="amber">migrating</B> : <B c="red">legacy · identifier-derived</B>;

export const KeyDerivationPanel = ({ session, onToast }: Props) => {
  const [items, setItems] = useState<KeyKDFState[] | null>(null);
  const [busy, setBusy] = useState("");

  const load = useCallback(async () => {
    if (!session?.token) return;
    try {
      setItems(await listKeyKDF(session));
    } catch (error) {
      setItems(null);
      onToast?.(`Key-derivation status unavailable: ${errMsg(error)}`);
    }
  }, [session, onToast]);

  useEffect(() => { void load(); }, [load]);

  const run = async (keyId: string, label: string, fn: () => Promise<unknown>) => {
    setBusy(keyId);
    try {
      const out: any = await fn();
      if (out && typeof out.converted === "number") {
        onToast?.(`${keyId}: re-protected ${out.converted}, failed ${out.failed}, remaining ${out.remaining}.`);
      } else {
        onToast?.(`${keyId}: ${label} done.`);
      }
      await load();
    } catch (error) {
      onToast?.(`${keyId}: ${label} failed: ${errMsg(error)}`);
    } finally {
      setBusy("");
    }
  };

  const legacy = (items || []).filter((i) => i.state !== "v2").length;

  return (
    <Section title="Working-Key Derivation" actions={<Btn small onClick={() => void load()}>Refresh</Btn>}>
      <Card>
        <div style={{ fontSize: 10, color: C.dim, lineHeight: 1.5, marginBottom: 8 }}>
          Legacy keys derive tokenization, FPE and field-protection keys from public identifiers (KCV / key id). Migrate each
          key: start, re-protect your data (read with header <code>X-Vecta-KDF-Version: v1</code>, write with <code>v2</code>;
          stored vault tokens are re-protected here), then complete. After completion v1 is refused.
        </div>
        {items === null ? (
          <div style={{ fontSize: 11, color: C.dim }}>Status not assessed.</div>
        ) : items.length === 0 ? (
          <div style={{ fontSize: 11, color: C.dim }}>No data protection keys have been used yet.</div>
        ) : (
          <>
            {legacy > 0 && <div style={{ fontSize: 11, color: C.red, marginBottom: 8 }}>{legacy} key(s) still use identifier-derived working keys.</div>}
            <div style={{ display: "grid", gap: 6 }}>
              {items.map((k) => (
                <div key={k.key_id} style={{ display: "grid", gridTemplateColumns: "minmax(0,1.4fr) auto minmax(0,1fr) auto", gap: 8, alignItems: "center", fontSize: 11, color: C.text }}>
                  <span style={{ fontFamily: "'JetBrains Mono',monospace", overflow: "hidden", textOverflow: "ellipsis" }}>{k.key_id}</span>
                  {stateBadge(k.state)}
                  <span style={{ color: C.dim }}>
                    {k.state === "v2" ? `pinned to key version ${k.key_version}` : `legacy uses ${k.legacy_uses} · v1 vault tokens ${k.legacy_vault_tokens}`}
                  </span>
                  <span style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}>
                    {k.state === "legacy" && (
                      <Btn small primary disabled={busy === k.key_id} onClick={() => void run(k.key_id, "start migration", () => kdfTransition(session, k.key_id, "start-migration"))}>Start migration</Btn>
                    )}
                    {k.state === "migrating" && (
                      <>
                        <Btn small disabled={busy === k.key_id} onClick={() => void run(k.key_id, "re-protect vault tokens", () => kdfReprotectVault(session, k.key_id))}>Re-protect vault</Btn>
                        <Btn small primary disabled={busy === k.key_id || k.legacy_vault_tokens > 0} onClick={() => void run(k.key_id, "complete", () => kdfTransition(session, k.key_id, "complete"))}>Complete</Btn>
                        <Btn small danger disabled={busy === k.key_id} onClick={() => void run(k.key_id, "abort", () => kdfTransition(session, k.key_id, "abort"))}>Abort</Btn>
                      </>
                    )}
                  </span>
                </div>
              ))}
            </div>
          </>
        )}
      </Card>
    </Section>
  );
};
