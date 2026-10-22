import { useCallback, useEffect, useState } from "react";
import { ShieldOff } from "lucide-react";
import { B, Btn, Card, FG, Inp, Stat, Txt } from "../../legacyPrimitives";
import { C } from "../../theme";
import { errMsg } from "../../runtimeUtils";
import { clickable, DrillPanel } from "../../chartDrill";
import type { AuthSession } from "../../../../lib/auth";
import type { CryptoAsset } from "../../../../lib/discovery";
import {
  addDistrustedCA, listDistrustedCAs, listDistrustFindings, removeDistrustedCA,
  type DistrustFinding, type DistrustedCA
} from "../../../../lib/discoveryTrust";
import { MONO, relTime } from "./meta";

// Certificates found under a CA that is distrusted: the platform's list (the
// CA keys the Go toolchain refuses, such as the compromised eMudhra emSign
// G3 intermediates) and the tenant's own. Counts come from the discovery
// service over the whole inventory; a CA's count lists its certificates.
const PAGE = 100;

export function DistrustedCAs({ session, onOpen, onToast, reloadKey }: {
  session: AuthSession;
  onOpen: (a: CryptoAsset) => void;
  onToast?: (m: string) => void;
  reloadKey: number;
}) {
  const [cas, setCAs] = useState<DistrustedCA[] | null>(null);
  const [unrecorded, setUnrecorded] = useState(0);
  const [error, setError] = useState("");
  const [drill, setDrill] = useState<DistrustedCA | "all" | null>(null);
  const [rows, setRows] = useState<DistrustFinding[]>([]);
  const [drillTotal, setDrillTotal] = useState(0);
  const [drillError, setDrillError] = useState("");
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState({ label: "", spki_sha256: "", certificate_pem: "" });

  const load = useCallback(async () => {
    try {
      const [list, findings] = await Promise.all([listDistrustedCAs(session), listDistrustFindings(session, { limit: 1, offset: 0 })]);
      setCAs(list);
      setUnrecorded(findings.chain_unrecorded);
      setError("");
    } catch (e) {
      setCAs(null);
      setError(errMsg(e));
    }
  }, [session]);
  useEffect(() => { void load(); }, [load, reloadKey]);

  const page = useCallback(async (which: DistrustedCA | "all", offset: number) => {
    try {
      const out = await listDistrustFindings(session, { spki: which === "all" ? "" : which.spki_sha256, limit: PAGE, offset });
      setRows((prev) => (offset === 0 ? out.items : [...prev, ...out.items]));
      setDrillTotal(out.total);
      setDrillError("");
    } catch (e) {
      setDrillError(errMsg(e));
    }
  }, [session]);
  const open = (which: DistrustedCA | "all") => { setDrill(which); setRows([]); void page(which, 0); };

  const affected = (cas ?? []).reduce((n, c) => n + c.affected, 0);
  const add = async () => {
    try {
      const d = await addDistrustedCA(session, form);
      onToast?.(d.affected ? `Distrusted. ${d.affected} discovered certificate(s) run through it.` : "Distrusted. No discovered certificate runs through it.");
      setAdding(false);
      setForm({ label: "", spki_sha256: "", certificate_pem: "" });
      await load();
    } catch (e) {
      onToast?.(errMsg(e));
    }
  };

  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", margin: "4px 0 8px" }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>Distrusted CAs</span>
        <Btn small onClick={() => setAdding((v) => !v)}>{adding ? "Cancel" : "Distrust a CA"}</Btn>
      </div>
      {error ? <div style={{ fontSize: 11.5, color: C.redFg }}>{`Distrusted CAs unavailable: ${error}`}</div> : cas && <>
        <div style={{ display: "flex", gap: 10, marginBottom: 10, flexWrap: "wrap" }}>
          <Stat l="Distrusted CAs" v={cas.length} s={`${cas.filter((c) => c.source === "tenant").length} added here`} i={ShieldOff} />
          <div onClick={affected ? () => open("all") : undefined} style={affected ? clickable : undefined}>
            <Stat l="Certificates under them" v={affected} c={affected ? "red" : "green"} />
          </div>
          <Stat l="Chain not recorded" v={unrecorded} s={unrecorded ? "found before chains were recorded; rescan" : "every certificate"} c={unrecorded ? "amber" : "green"} />
        </div>
        {adding && (
          <Card style={{ padding: 10, marginBottom: 10, borderColor: C.accent }}>
            <FG label="CA certificate (PEM)"><Txt rows={4} value={form.certificate_pem} onChange={(e: { target: { value: string } }) => setForm({ ...form, certificate_pem: e.target.value })} placeholder={"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"} /></FG>
            <FG label="or its key's SHA-256 (SPKI, 64 hex)"><Inp value={form.spki_sha256} onChange={(e: { target: { value: string } }) => setForm({ ...form, spki_sha256: e.target.value })} placeholder="ebed6475..." /></FG>
            <FG label="Label"><Inp value={form.label} onChange={(e: { target: { value: string } }) => setForm({ ...form, label: e.target.value })} placeholder="Defaults to the certificate's subject" /></FG>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 6 }}><Btn small primary onClick={() => void add()}>Distrust</Btn></div>
          </Card>
        )}
        <Card style={{ padding: 0 }}>
          {cas.map((c) => (
            <div key={c.spki_sha256} style={{ display: "grid", gridTemplateColumns: "1fr 150px 90px 70px", gap: 10, alignItems: "center", padding: "7px 10px", borderBottom: `1px solid ${C.border}`, fontSize: 11 }}>
              <span style={{ minWidth: 0 }}>
                <div style={{ color: C.text, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={c.label}>{c.label}</div>
                <div style={{ fontFamily: MONO, fontSize: 10, color: C.muted }} title={c.spki_sha256}>{`SPKI ${c.spki_sha256.slice(0, 16)}…`}</div>
              </span>
              <span><B c="neutral">{c.source === "platform" ? "platform" : `added by ${c.added_by || "-"}`}</B></span>
              <span onClick={c.affected ? () => open(c) : undefined} style={{ ...(c.affected ? clickable : {}), color: c.affected ? C.redFg : C.muted, fontWeight: 600 }}>
                {`${c.affected} cert${c.affected === 1 ? "" : "s"}`}
              </span>
              <span style={{ textAlign: "right" }}>
                {c.source === "tenant" && <Btn small onClick={() => void removeDistrustedCA(session, c.spki_sha256).then(load, (e) => onToast?.(errMsg(e)))}>Remove</Btn>}
              </span>
            </div>
          ))}
        </Card>
      </>}
      {drill && (
        <DrillPanel label={drill === "all" ? "Certificates under a distrusted CA" : `Under ${drill.label}`} count={drillTotal} onClear={() => setDrill(null)}
          loaded={rows.length} error={drillError} onMore={rows.length < drillTotal ? () => void page(drill, rows.length) : undefined}>
          {rows.map((f) => (
            <div key={f.asset.id} data-testid="distrust-finding" onClick={() => onOpen(f.asset)} style={{ ...clickable, display: "grid", gridTemplateColumns: "2fr 2fr 1fr 70px", gap: 10, padding: "7px 4px", borderBottom: `1px solid ${C.border}`, fontSize: 11 }}>
              <span style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 600, color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.asset.name || "-"}</div>
                <div style={{ fontFamily: MONO, fontSize: 10, color: C.muted }}>{f.asset.location}</div>
              </span>
              <span style={{ color: C.dim, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={String(f.asset.metadata?.issuer || "")}>{String(f.asset.metadata?.issuer || "-")}</span>
              <span style={{ color: C.redFg, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={f.matches.map((m) => m.label).join(", ")}>{f.matches.map((m) => m.label).join(", ")}</span>
              <span style={{ color: C.muted, textAlign: "right" }}>{relTime(f.asset.last_seen)}</span>
            </div>
          ))}
        </DrillPanel>
      )}
    </div>
  );
}
