import { useEffect, useState } from "react";
import type { AuthSession } from "../../lib/auth";
import { exportKey } from "../../lib/keycore";
import { Btn, FG, Inp, Modal, Sel } from "../../components/v3/legacyPrimitives";
import { errMsg } from "../../components/v3/runtimeUtils";
import { C } from "../../components/v3/theme";

// Export a key: its material wrapped under another key, or a public
// component in the clear. keycore refuses key material without a reason and
// records it in audit.key.export (12.0.0-beta), so the dialog asks for one.

type Props = {
  session: AuthSession | null;
  open: boolean;
  keyItem: { id: string; name: string } | null;
  // A public component may leave unwrapped.
  publicComponent: boolean;
  wrappingKeys: { id: string; name: string }[];
  onClose: () => void;
  onToast?: (msg: string) => void;
};

const MAX_REASON = 256;

export function ExportKeyDialog({ session, open, keyItem, publicComponent, wrappingKeys, onClose, onToast }: Props) {
  const [mode, setMode] = useState<"wrapped" | "public-plaintext">("wrapped");
  const [wrappingKeyId, setWrappingKeyId] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const wrapped = mode === "wrapped";

  useEffect(() => {
    if (!open) return;
    setMode(publicComponent ? "public-plaintext" : "wrapped");
    setReason("");
    setWrappingKeyId((prev) => (wrappingKeys.some((k) => k.id === prev) ? prev : wrappingKeys[0]?.id || ""));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reset when the dialog opens for a key, not on every list refresh
  }, [open, keyItem?.id]);

  const run = async () => {
    if (!session || !keyItem?.id) return;
    setBusy(true);
    try {
      const payload = await exportKey(session, keyItem.id, { export_mode: mode, wrapping_key_id: wrapped ? wrappingKeyId : "", reason: reason.trim() });
      const artifact = {
        key_id: payload.key_id,
        tenant_id: session.tenantId,
        kcv: payload.kcv,
        wrapped_material: payload.wrapped_material,
        material_iv: payload.material_iv,
        wrapped_dek: payload.wrapped_dek,
        public_key_plaintext: payload.public_key_plaintext || "",
        plaintext_encoding: payload.plaintext_encoding || "",
        component_type: payload.component_type || "",
        wrapping_key_id: payload.wrapping_key_id || (wrapped ? wrappingKeyId : ""),
        wrapping_key_kcv: payload.wrapping_key_kcv || "",
        export_format: payload.export_format || mode,
        exported_at: new Date().toISOString()
      };
      const url = URL.createObjectURL(new Blob([JSON.stringify(artifact, null, 2)], { type: "application/json" }));
      const a = document.createElement("a");
      const safeName = String(keyItem.name || payload.key_id || "key-export").replace(/[^a-z0-9._-]+/gi, "-");
      a.href = url;
      a.download = wrapped ? `${safeName}.wrapped.json` : `${safeName}.public.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      onClose();
      onToast?.(wrapped ? `Key exported: ${keyItem.name}` : `Public key exported: ${keyItem.name}`);
    } catch (error) {
      onToast?.(`Export key failed: ${errMsg(error)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal open={open} onClose={onClose} title={`Export Key: ${keyItem?.name || ""}`}>
      <div data-keep="" style={{ background: C.amberDim, border: `1px solid ${C.amber}`, borderRadius: 4, padding: 10, marginBottom: 12, fontSize: 11, color: C.amberFg }}>
        {wrapped ? "Key material leaves the KMS, wrapped. The export and its reason are audited." : "The public key is exported in the clear."}
      </div>
      <FG label="Export Mode" required>
        <Sel aria-label="Export mode" value={mode} onChange={(e) => setMode(e.target.value === "public-plaintext" ? "public-plaintext" : "wrapped")}>
          <option value="wrapped">Wrapped with a KEK</option>
          {publicComponent && <option value="public-plaintext">Public key, in the clear</option>}
        </Sel>
      </FG>
      {wrapped && (
        <FG label="Wrapping Key (KEK)" required>
          <Sel aria-label="Wrapping key" value={wrappingKeyId} onChange={(e) => setWrappingKeyId(e.target.value)}>
            <option value="">Select wrapping key...</option>
            {wrappingKeys.map((item) => <option key={item.id} value={item.id}>{`${item.name} (${item.id})`}</option>)}
          </Sel>
          {!wrappingKeys.length && <div style={{ marginTop: 6, fontSize: 10, color: C.amberFg }}>No active wrap/unwrap key available.</div>}
        </FG>
      )}
      <FG label="Reason" required={wrapped}>
        <Inp aria-label="Reason for the export" placeholder={wrapped ? "Why this key is leaving (recorded in the audit log)" : "Optional"} maxLength={MAX_REASON} value={reason} onChange={(e) => setReason(e.target.value)} />
      </FG>
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 8 }}>
        <Btn onClick={onClose}>Cancel</Btn>
        <Btn primary onClick={() => void run()} disabled={busy || (wrapped && (!wrappingKeyId || !reason.trim()))}>{busy ? "Exporting..." : "Export Key"}</Btn>
      </div>
    </Modal>
  );
}
