import { useState } from "react";
import type { EKMClientCheckIn } from "../../../../lib/ekmClients";
import { clickable } from "../../chartDrill";
import { C } from "../../theme";
import { BAR, MONO, ago, checkInBars, fmtTime, gap, type BarKind } from "./meta";

type Props = { checkIns: EKMClientCheckIn[]; intervalSec: number; serverTime: string };

const cell = { padding: "3px 6px", textAlign: "left" as const };

// The last check-ins of a client, one bar each. A bar is as tall as the
// check-in was punctual; clicking it shows that check-in, and "List" shows
// all of them as a table.
export function CheckInStrip({ checkIns, intervalSec, serverTime }: Props) {
  const [picked, setPicked] = useState<string | null>(null);
  const [list, setList] = useState(false);
  const bars = checkInBars(checkIns, intervalSec);
  if (bars.length === 0) {
    return <div style={{ fontSize: 12, color: C.muted }}>{checkIns.length === 1 ? `One check-in so far, ${fmtTime(checkIns[0]!.at)}.` : "No check-ins yet."}</div>;
  }
  const sinceFirst = (new Date(serverTime).getTime() - new Date(bars[0]!.entry.at).getTime()) / 1000;
  const shown = bars.find((b) => b.entry.at === picked);
  const kinds = (Object.keys(BAR) as BarKind[]).filter((k) => bars.some((b) => b.kind === k));

  return (
    <div>
      <div role="group" aria-label={`Last ${bars.length} check-ins`} data-testid="ekm-checkin-strip" style={{ display: "flex", alignItems: "flex-end", gap: 2, height: 56, borderBottom: `1px solid ${C.border}` }}>
        {bars.map((b) => (
          <button
            key={b.entry.at}
            type="button"
            onClick={() => setPicked(picked === b.entry.at ? null : b.entry.at)}
            title={`${fmtTime(b.entry.at)} · ${gap(b.gapSec)} after the one before · ${BAR[b.kind].label}`}
            aria-label={`Check-in ${fmtTime(b.entry.at)}, ${gap(b.gapSec)} after the one before, ${BAR[b.kind].label}`}
            aria-pressed={picked === b.entry.at}
            data-kind={b.kind}
            style={{ ...clickable, flex: 1, minWidth: 0, height: "100%", display: "flex", alignItems: "flex-end", background: picked === b.entry.at ? C.dimTint : "transparent", border: "none", padding: 0 }}
          >
            <span style={{ display: "block", width: "100%", height: `${b.heightPct}%`, background: BAR[b.kind].fill, borderRadius: "2px 2px 0 0" }} />
          </button>
        ))}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: C.muted, marginTop: 4 }}>
        <span>{ago(sinceFirst)}</span>
        <span>Latest</span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap", fontSize: 11, color: C.dim, marginTop: 6 }}>
        {kinds.map((k) => (
          <span key={k} style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: BAR[k].fill }} />{BAR[k].label}
          </span>
        ))}
        <button type="button" onClick={() => setList(!list)} style={{ ...clickable, marginLeft: "auto", background: "transparent", border: "none", color: C.accentFg, fontSize: 11, padding: 0 }}>{list ? "Hide list" : "List"}</button>
      </div>
      {shown && !list && (
        <div data-testid="ekm-checkin-entry" style={{ marginTop: 8, padding: "8px 10px", border: `1px solid ${C.border}`, borderRadius: "var(--radius-md)", fontSize: 12, color: C.text }}>
          <div>{fmtTime(shown.entry.at)}</div>
          <div style={{ color: C.muted, marginTop: 2 }}>{gap(shown.gapSec)} after the one before · {BAR[shown.kind].label}</div>
          <div style={{ color: C.muted, marginTop: 2, fontFamily: MONO }}>{shown.entry.source_ip || "no address"} · {shown.entry.version || "version not reported"} · {shown.entry.status || "-"}</div>
        </div>
      )}
      {list && (
        <table data-testid="ekm-checkin-list" style={{ width: "100%", marginTop: 8, fontSize: 11.5, color: C.text }}>
          <thead><tr style={{ color: C.muted }}><th style={cell}>Time</th><th style={cell}>After</th><th style={cell}>From</th><th style={cell}>Reported</th></tr></thead>
          <tbody>
            {[...bars].reverse().map((b) => (
              <tr key={b.entry.at}>
                <td style={cell}>{fmtTime(b.entry.at)}</td>
                <td style={cell}>{gap(b.gapSec)}</td>
                <td style={{ ...cell, fontFamily: MONO }}>{b.entry.source_ip || "-"}</td>
                <td style={cell}>{b.entry.status || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
