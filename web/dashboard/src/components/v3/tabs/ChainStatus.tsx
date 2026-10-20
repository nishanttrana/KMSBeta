import type { ChainVerifyResult } from "../../../lib/audit";
import { B } from "../legacyPrimitives";

// What a chain check proved: the quick check covers each chain from its
// newest signed checkpoint, so it says so, and says when the hourly full
// walk last passed (docs/SECURITY/AUDIT_INTEGRITY.md).
export function ChainStatus({ result }: { result: ChainVerifyResult | null }) {
  // Not checked yet is not a pass: no green until a verification passes.
  if (!result) return <B c="neutral">CHAIN: NOT CHECKED</B>;
  const since = Object.values(result.from_sequence || {});
  const label = !result.ok ? "CHAIN: BROKEN"
    : result.scope === "since_checkpoint" && since.length ? `CHAIN: INTACT since #${Math.min(...since)}` : "CHAIN: INTACT";
  const full = result.last_full_verification;
  return (
    <>
      <B c={result.ok ? "green" : "red"} pulse={!result.ok}>{label}</B>
      <B c={full ? "accent" : "amber"}>{full ? `Full check passed ${new Date(full).toLocaleString()}` : "Full check: not yet passed"}</B>
    </>
  );
}
