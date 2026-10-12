import { useCallback, useEffect, useState } from "react";
import type { AuthSession } from "../../../../lib/auth";
import { ConsoleError, listConsoleOperations, runConsoleOperation, type ConsoleOp } from "../../../../lib/byok";
import { errMsg } from "../../runtimeUtils";

// One account's console: which operations its cloud supports, and a runner
// that keeps the last call's CLI equivalent and error.
export function useConsole(session: AuthSession, accountId: string) {
  const [ops, setOps] = useState<ConsoleOp[]>([]);
  const [opsError, setOpsError] = useState("");
  const [cli, setCli] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");

  useEffect(() => {
    if (!accountId) return;
    listConsoleOperations(session, accountId)
      .then((o) => { setOps(o.items); setOpsError(""); })
      .catch((e) => setOpsError(errMsg(e)));
  }, [session, accountId]);

  const supported = useCallback((name: string) => ops.some((o) => o.name === name && o.supported), [ops]);

  const run = useCallback(async (op: string, call: { key?: string; version?: string; params?: Record<string, string> }) => {
    setBusy(op);
    setError("");
    try {
      const out = await runConsoleOperation(session, op, { account_id: accountId, ...call });
      setCli(out.cli);
      return out.result;
    } catch (e) {
      if (e instanceof ConsoleError) setCli(e.cli);
      setError(errMsg(e));
      return undefined;
    } finally {
      setBusy("");
    }
  }, [session, accountId]);

  return { ops, opsError, supported, run, cli, error, busy };
}

export const toB64 = (text: string) => {
  const bytes = new TextEncoder().encode(text);
  let s = "";
  bytes.forEach((b) => { s += String.fromCharCode(b); });
  return btoa(s);
};
