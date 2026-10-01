import { useEffect, useState, type ReactNode } from "react";
import { Trash2 } from "lucide-react";
import { Btn, Inp, Modal } from "../../legacyPrimitives";
import { C } from "../../theme";
import { errMsg } from "../../runtimeUtils";
import { removeDiscoveryAsset, reviewAsset, type CryptoAsset } from "../../../../lib/discovery";
import type { AuthSession } from "../../../../lib/auth";
import { MONO, REVIEW_LABEL, REVIEW_STATUSES, absTime, daysUntil, relTime, reviewOf, sourceMeta, typeLabel } from "./meta";
import { ClassPill } from "./Inventory";

const yesNo = (v: unknown) => (v ? "Yes" : "No");
const expiry = (v: unknown) => {
  const d = daysUntil(String(v));
  if (d === null) return String(v);
  return `${absTime(String(v))} · ${d < 0 ? `expired ${-d}d ago` : `in ${d}d`}`;
};

// Facts a scan recorded, in reading order. Only keys present are shown.
const FACTS: [string, string, ((v: unknown) => ReactNode)?][] = [
  ["protocol", "Protocol"],
  ["cipher_suite", "Cipher suite"],
  ["key_exchange", "Key exchange"],
  ["server", "Server software"],
  ["selection", "Algorithm shown"],
  ["subject", "Subject"],
  ["issuer", "Issuer"],
  ["not_before", "Valid from", (v) => absTime(String(v))],
  ["not_after", "Expires", expiry],
  ["signature_algorithm", "Signature"],
  ["chain_trusted", "Chain", (v) => (v ? "Trusted" : "Not trusted")],
  ["self_signed", "Self-signed", yesNo],
  ["is_ca", "CA certificate", yesNo],
  ["serial", "Serial"],
  ["dns_names", "DNS names", (v) => (Array.isArray(v) ? v.join(", ") : String(v))],
  ["key_type", "Key type"],
  ["key_error", "Key", (v) => `not read: ${v}`],
  ["fingerprint", "Fingerprint"],
  ["fingerprint_sha256_prefix", "SHA-256 prefix"],
  ["provider", "Provider"],
  ["account_id", "Account"],
  ["cloud_key_ref", "Key reference"],
  ["managed_by_vecta", "Managed by this KMS", yesNo],
  ["cert_id", "Certificate ID"],
  ["repository", "Repository"],
  ["ref", "Branch or tag"],
  ["commit", "Commit"],
  ["file", "File"],
  ["format", "Format"],
];

// SSH algorithm lists with the weak entries the scan flagged.
const OFFERED: [string, string, string][] = [
  ["key_exchange_offered", "weak_key_exchange_offered", "Key exchange offered"],
  ["host_key_algorithms", "", "Host key algorithms"],
  ["ciphers_offered", "weak_ciphers_offered", "Ciphers offered"],
  ["macs_offered", "weak_macs_offered", "MACs offered"],
];

const Fact = ({ label, children }: { label: string; children: ReactNode }) => (
  <div style={{ display: "grid", gridTemplateColumns: "130px 1fr", gap: 10, padding: "6px 0", borderBottom: `1px solid ${C.border}`, fontSize: 11.5 }}>
    <span style={{ color: C.muted }}>{label}</span>
    <span style={{ color: C.text, wordBreak: "break-word" }}>{children}</span>
  </div>
);

type Props = {
  asset: CryptoAsset | null;
  stale: boolean;
  session: AuthSession;
  onClose: () => void;
  onChanged: (next: CryptoAsset | null) => void;
  onToast?: (msg: string) => void;
};

export function AssetDetail({ asset, stale, session, onClose, onChanged, onToast }: Props) {
  const [status, setStatus] = useState("active");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);
  useEffect(() => {
    setStatus(asset ? reviewOf(asset) : "active");
    setNotes(String(asset?.metadata?.review_notes || ""));
    setConfirmRemove(false);
  }, [asset]);
  if (!asset) return null;
  const md = asset.metadata || {};
  const S = sourceMeta(asset.source);

  const save = async () => {
    setBusy(true);
    try {
      onChanged(await reviewAsset(session, asset.id, status, notes));
      onToast?.("Review saved");
    } catch (e) {
      onToast?.(`Review failed: ${errMsg(e)}`);
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    setBusy(true);
    try {
      await removeDiscoveryAsset(session, asset.id);
      onChanged(null);
      onToast?.("Removed from the inventory");
    } catch (e) {
      onToast?.(`Remove failed: ${errMsg(e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal open onClose={onClose} title={asset.name || typeLabel(asset.asset_type)} wide>
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 12, marginBottom: 14 }}>
        <ClassPill cls={asset.classification} />
        <span style={{ fontFamily: MONO, fontSize: 12, color: C.text }}>{asset.algorithm || "-"}</span>
        <span style={{ fontSize: 11, color: C.muted }}>{asset.strength_bits > 0 ? `${asset.strength_bits}-bit` : "strength not assessed"}</span>
        {asset.pqc_ready && <span style={{ fontSize: 10, fontWeight: 700, color: C.greenFg, background: C.greenDim, borderRadius: 4, padding: "2px 6px" }}>POST-QUANTUM</span>}
        {stale && <span style={{ fontSize: 10.5, color: C.amberFg }}>Not seen in the last {S.label.toLowerCase()} scan</span>}
      </div>

      <Fact label="Type">{typeLabel(asset.asset_type)}</Fact>
      <Fact label="Source">{S.label}</Fact>
      {asset.location && <Fact label="Location"><span style={{ fontFamily: MONO }}>{asset.location}</span></Fact>}
      {asset.status && <Fact label="Observed status">{asset.status.replace(/_/g, " ")}</Fact>}
      {FACTS.filter(([k]) => md[k] !== undefined && md[k] !== "" && md[k] !== null).map(([k, label, fmt]) => (
        <Fact key={k} label={label}>{fmt ? fmt(md[k]) : <span style={{ fontFamily: /fingerprint|serial|cert_id|cloud_key_ref|commit|repository/.test(k) ? MONO : "inherit" }}>{String(md[k])}</span>}</Fact>
      ))}
      {OFFERED.filter(([k]) => Array.isArray(md[k]) && md[k].length).map(([k, weakKey, label]) => {
        const weak: string[] = Array.isArray(md[weakKey]) ? md[weakKey] : [];
        return (
          <Fact key={k} label={label}>
            <span style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
              {(md[k] as string[]).map((n) => (
                <span key={n} style={{ fontFamily: MONO, fontSize: 10.5, borderRadius: 4, padding: "1px 6px", border: `1px solid ${weak.includes(n) ? C.redFg : C.border}`, color: weak.includes(n) ? C.redFg : C.dim }}>
                  {n}{weak.includes(n) ? " · weak" : ""}
                </span>
              ))}
            </span>
          </Fact>
        );
      })}
      <Fact label="First seen">{absTime(asset.first_seen)}</Fact>
      <Fact label="Last seen">{absTime(asset.last_seen)} · {relTime(asset.last_seen)}</Fact>

      <div style={{ marginTop: 16, padding: 12, border: `1px solid ${C.border}`, borderRadius: 10 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 8 }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>Review</span>
          {md.reviewed_by ? <span style={{ fontSize: 10.5, color: C.muted }}>{String(md.reviewed_by)} · {relTime(String(md.reviewed_at || ""))}</span> : null}
        </div>
        <div style={{ display: "inline-flex", flexWrap: "wrap", padding: 2, border: `1px solid ${C.border}`, borderRadius: 8, marginBottom: 8 }}>
          {REVIEW_STATUSES.map((s) => (
            <button key={s} type="button" onClick={() => setStatus(s)}
              style={{ border: "none", borderRadius: 6, padding: "5px 10px", fontSize: 11, fontWeight: 600, cursor: "pointer", background: status === s ? C.accentDim : "transparent", color: status === s ? C.accentFg : C.muted }}>
              {REVIEW_LABEL[s]}
            </button>
          ))}
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Inp placeholder="Notes (owner, ticket, decision)" value={notes} onChange={(e) => setNotes(e.target.value)} />
          <Btn primary onClick={() => void save()} disabled={busy}>Save</Btn>
        </div>
        <div style={{ fontSize: 10.5, color: C.muted, marginTop: 6 }}>The class comes from the algorithm and can't be changed. A rescan keeps the review.</div>
      </div>

      <div style={{ display: "flex", justifyContent: "flex-end", alignItems: "center", gap: 8, marginTop: 14 }}>
        {confirmRemove && <span style={{ fontSize: 11, color: C.muted }}>A later scan that finds it adds it back.</span>}
        <Btn small danger={confirmRemove} onClick={() => (confirmRemove ? void remove() : setConfirmRemove(true))} disabled={busy}>
          <Trash2 size={12} />{confirmRemove ? "Confirm remove" : "Remove from inventory"}
        </Btn>
      </div>
    </Modal>
  );
}
