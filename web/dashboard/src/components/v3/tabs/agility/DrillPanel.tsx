import { useEffect, useState } from "react";
import { FlaskConical, RefreshCw } from "lucide-react";
import { C } from "../../theme";
import { listAgilityDrills, runAgilityDrill, type AgilityDrill, type DrillMeasure } from "../../../../lib/cryptoAgility";
import { Badge, errText, Field, inputStyle, S } from "./ui";

// Algorithm-swap drill: a real rehearsal on a keycore node. Throwaway keys
// from keycore's own key generation, checked round trips through the key
// engine, medians in microseconds; nothing enters the key inventory. The
// target must pass the tenant's FIPS mode and migration policy first.

const OP: Record<DrillMeasure["operation"], string> = {
  sign_verify: "sign / verify", encrypt_decrypt: "encrypt / decrypt", encapsulate_decapsulate: "encapsulate / decapsulate",
};
const us = (v: number) => (v >= 1000 ? `${(v / 1000).toFixed(v >= 10000 ? 0 : 1)} ms` : `${v} µs`);
const ratio = (r: number) => (r > 0 ? `×${r}` : "—");
const signed = (n: number) => (n > 0 ? `+${n}` : String(n));

export function DrillPanel({ session, suggestions }: { session: any; suggestions: string[] }) {
  const [drills, setDrills] = useState<AgilityDrill[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [iterations, setIterations] = useState(5);
  const [running, setRunning] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  async function load() {
    setError(null);
    try { setDrills(await listAgilityDrills(session)); } catch (e) { setDrills([]); setError(errText(e)); } finally { setLoading(false); }
  }
  // eslint-disable-next-line react-hooks/exhaustive-deps -- reviewed: run once on mount; load is a per-render closure.
  useEffect(() => { void load(); }, []);

  async function run() {
    setRunning(true); setNotice(null);
    try {
      const d = await runAgilityDrill(session, { from_algorithm: from.trim(), to_algorithm: to.trim(), iterations });
      setNotice(d.result === "passed" ? `Drill passed: ${d.from.algorithm} → ${d.to.algorithm}.` : `Drill failed: ${d.error ?? "round trip failed"}`);
      await load();
    } catch (e) { setNotice(`Refused: ${errText(e)}`); } finally { setRunning(false); }
  }

  const latest = drills[0];
  return (
    <div>
      <div style={{ fontSize: 12, color: C.dim, maxWidth: 760, marginBottom: 16 }}>
        Rehearse a swap before you schedule it. Keycore generates throwaway keys for both algorithms, runs each one's operation through the same engine your keys use, checks every round trip and times it on this node. Nothing is added to your key inventory. The target must be allowed by your FIPS mode and your migration policy, as it would be for a real key.
      </div>
      <div style={{ ...S.panel, padding: 16, display: "flex", gap: 12, alignItems: "flex-end", flexWrap: "wrap" }}>
        <datalist id="drill-algorithms">{suggestions.map(a => <option key={a} value={a} />)}</datalist>
        <div style={{ flex: 1, minWidth: 180 }}><Field label="From (current algorithm)"><input list="drill-algorithms" style={inputStyle} value={from} onChange={e => setFrom(e.target.value)} placeholder="e.g. RSA-2048" /></Field></div>
        <div style={{ flex: 1, minWidth: 180 }}><Field label="To (candidate)"><input list="drill-algorithms" style={inputStyle} value={to} onChange={e => setTo(e.target.value)} placeholder="e.g. ML-DSA-65" /></Field></div>
        <div style={{ width: 110 }}><Field label="Iterations (1–10)"><input type="number" min={1} max={10} style={inputStyle} value={iterations} onChange={e => setIterations(Number(e.target.value) || 1)} /></Field></div>
        <button style={S.primary} disabled={running || !from.trim() || !to.trim()} onClick={() => void run()}>
          <FlaskConical size={13} /> {running ? "Running…" : "Run drill"}
        </button>
      </div>
      {notice && <div style={{ fontSize: 12, color: notice.startsWith("Drill passed") ? C.green : C.red, marginTop: 10 }}>{notice}</div>}

      {latest && latest.result === "passed" && (
        <div style={{ ...S.panel, padding: "12px 16px", marginTop: 16, fontSize: 12, color: C.dim }} data-testid="drill-latest">
          Latest: <b style={{ color: C.text }}>{latest.from.algorithm} → {latest.to.algorithm}</b>. Key generation {ratio(latest.comparison.keygen_ratio)}, {OP[latest.to.operation].split(" / ")[0]} {ratio(latest.comparison.operation_ratio)}, {OP[latest.to.operation].split(" / ")[1]} {ratio(latest.comparison.check_ratio)} the time; output {signed(latest.comparison.output_bytes_diff)} bytes{latest.from.public_key_bytes && latest.to.public_key_bytes ? `, public key ${signed(latest.comparison.public_key_bytes_diff)} bytes` : ""}.
        </div>
      )}

      <div style={S.divider} />
      <div style={S.sectionTitle}>Drill history</div>
      <div style={S.sectionHint}>Medians over the round trips run, measured on the keycore node that served the request. Each algorithm gets 20 seconds; slow ones may run fewer round trips than asked.</div>
      {loading ? <div style={{ ...S.empty, display: "flex", gap: 8, justifyContent: "center" }}><RefreshCw size={14} /> Loading drills…</div>
      : error ? <div style={{ ...S.empty, color: C.red }}>Drill history unavailable: {error}</div>
      : drills.length === 0 ? <div style={S.empty}>No drills run yet.</div> : (
        <div style={S.panel}><div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr style={{ borderBottom: `1px solid ${C.border}` }}>{["When", "Algorithm", "Operation", "Key gen", "Operation", "Check", "Output", "Public key", "Result"].map((h, i) => <th key={i} style={S.th}>{h}</th>)}</tr></thead>
            <tbody>{drills.flatMap(d => [d.from, d.to].map((m, i) => (
              <tr key={`${d.id}-${i}`} style={{ borderBottom: `1px solid ${i === 1 ? C.border : "transparent"}` }}>
                <td style={{ ...S.td, fontSize: 11, color: C.muted }}>{i === 0 ? <>{new Date(d.created_at).toLocaleString()}<div>by {d.run_by || "—"}</div></> : ""}</td>
                <td style={{ ...S.td, ...S.mono, fontSize: 11 }}>{i === 0 ? "" : "→ "}{m.algorithm}</td>
                <td style={S.td}>{m.round_trips > 0 ? <>{OP[m.operation]}<div style={{ fontSize: 10, color: C.muted }}>{m.round_trips} of {d.iterations} round trips</div></> : "—"}</td>
                <td style={S.td}>{m.round_trips > 0 ? us(m.keygen_us) : "—"}</td>
                <td style={S.td}>{m.round_trips > 0 ? us(m.operation_us) : "—"}</td>
                <td style={S.td}>{m.round_trips > 0 ? us(m.check_us) : "—"}</td>
                <td style={S.td}>{m.round_trips > 0 ? `${m.output_bytes} B` : "—"}</td>
                <td style={S.td}>{m.public_key_bytes ? `${m.public_key_bytes} B` : "—"}</td>
                <td style={S.td}>{i === 0 ? (d.result === "passed"
                  ? <Badge color={C.green} bg={C.greenDim}>passed</Badge>
                  : <><Badge color={C.red} bg={C.redDim}>failed</Badge><div style={{ fontSize: 10, color: C.muted, marginTop: 2, maxWidth: 240 }}>{d.error}</div></>) : ""}</td>
              </tr>
            )))}</tbody>
          </table>
        </div></div>
      )}
    </div>
  );
}
