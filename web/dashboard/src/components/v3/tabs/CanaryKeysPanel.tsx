import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../../lib/auth";
import {
  createCanaryKey,
  deactivateCanaryKey,
  listCanaryKeys,
  listCanaryTrips,
  type CanaryKey,
  type CanaryTrip
} from "../../../lib/keycore";
import { errMsg } from "../runtimeUtils";
import { C } from "../theme";
import { Btn, Inp } from "../legacyPrimitives";

const fmt = (iso?: string) => (iso ? new Date(iso).toLocaleString() : "-");

const cell = { padding: "7px 10px", fontSize: 11, color: C.text, borderBottom: `1px solid ${C.border}` } as const;
const head = { ...cell, fontSize: 9, color: C.muted, textTransform: "uppercase", letterSpacing: 0.8, textAlign: "left" } as const;

// Canary keys live with the other keys: create a decoy ID, plant it where an
// attacker would look, and any use of it through the key API trips it.
export function CanaryKeysPanel({ session }: { session: AuthSession }) {
  const [items, setItems] = useState<CanaryKey[]>([]);
  const [name, setName] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<CanaryKey | null>(null);
  const [tripsFor, setTripsFor] = useState<CanaryKey | null>(null);
  const [trips, setTrips] = useState<CanaryTrip[]>([]);

  const load = useCallback(async () => {
    setErr("");
    try {
      setItems(await listCanaryKeys(session));
    } catch (e) {
      setErr(`Canary keys unavailable: ${errMsg(e)}`);
    }
  }, [session]);

  useEffect(() => { void load(); }, [load]);

  const create = async () => {
    setBusy(true); setErr("");
    try {
      setCreated(await createCanaryKey(session, name.trim()));
      setName("");
      await load();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const deactivate = async (k: CanaryKey) => {
    setBusy(true); setErr("");
    try {
      await deactivateCanaryKey(session, k.id);
      await load();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const showTrips = async (k: CanaryKey) => {
    setTripsFor(k); setTrips([]);
    try {
      setTrips(await listCanaryTrips(session, k.id));
    } catch (e) {
      setErr(errMsg(e));
    }
  };

  return (
    <div style={{ padding: 16 }}>
      <div style={{ fontSize: 11, color: C.dim, lineHeight: 1.5, marginBottom: 12 }}>
        A canary key is a key ID with no key material behind it. Plant it where only an attacker would find and use it, for
        example in a config file or a vault entry. Any use of it through the key API returns "not found" to the caller,
        records a trip and raises a critical finding in Posture and an alert in the Alert Center.
      </div>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <Inp value={name} onChange={(e) => setName(e.target.value)} placeholder="Name, e.g. payments-master-backup" />
        <Btn primary onClick={create} disabled={busy || !name.trim()}>Create canary</Btn>
      </div>
      {created && (
        <div style={{ padding: "8px 10px", marginBottom: 12, borderRadius: 6, border: `1px solid ${C.accent}`, fontSize: 11, color: C.text }}>
          Created <b>{created.name}</b>. Plant this key ID: <span style={{ fontFamily: "'JetBrains Mono',monospace" }}>{created.id}</span>
        </div>
      )}
      {err && <div style={{ padding: "8px 10px", marginBottom: 12, borderRadius: 6, background: C.redDim, color: C.red, fontSize: 11 }}>{err}</div>}
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead><tr>{["Name", "Key ID", "Status", "Trips", "Last tripped", ""].map((h) => <th key={h} style={head}>{h}</th>)}</tr></thead>
        <tbody>
          {items.length === 0 && <tr><td colSpan={6} style={{ ...cell, color: C.muted, textAlign: "center" }}>No canary keys.</td></tr>}
          {items.map((k) => (
            <tr key={k.id}>
              <td style={cell}>{k.name}</td>
              <td style={{ ...cell, fontFamily: "'JetBrains Mono',monospace" }}>{k.id}</td>
              <td style={cell}>{k.active ? "Active" : "Deactivated"}</td>
              <td style={{ ...cell, color: k.trip_count > 0 ? C.red : C.text, fontWeight: k.trip_count > 0 ? 700 : 400 }}>{k.trip_count}</td>
              <td style={cell}>{fmt(k.last_tripped)}</td>
              <td style={{ ...cell, textAlign: "right", whiteSpace: "nowrap" }}>
                {k.trip_count > 0 && <Btn small onClick={() => showTrips(k)}>Trips</Btn>}{" "}
                {k.active && <Btn small danger disabled={busy} onClick={() => deactivate(k)}>Deactivate</Btn>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ fontSize: 10, color: C.muted, marginTop: 8 }}>
        Trip counts are from this node's trip log. Every trip on any node reaches Posture and the Alert Center.
      </div>
      {tripsFor && (
        <div style={{ marginTop: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 6 }}>Trips of {tripsFor.name}</div>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead><tr>{["When", "Actor", "Source IP", "Request"].map((h) => <th key={h} style={head}>{h}</th>)}</tr></thead>
            <tbody>
              {trips.map((t) => (
                <tr key={t.id}>
                  <td style={cell}>{fmt(t.tripped_at)}</td>
                  <td style={cell}>{t.actor_id || "-"}</td>
                  <td style={cell}>{t.actor_ip || "-"}</td>
                  <td style={cell}>{t.raw_request}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
