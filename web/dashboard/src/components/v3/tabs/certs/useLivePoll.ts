import { useCallback, useEffect, useRef, useState } from "react";
import { errMsg } from "../../runtimeUtils";

// Re-reads a page's data while it is open and visible. A failure is page
// state (shown once, with a retry), never a toast on every poll. The timer
// reads the latest poll through a ref.
export function useLivePoll(enabled: boolean, poll: () => Promise<void>, everyMs = 15000) {
  const ref = useRef(poll);
  ref.current = poll;
  const [at, setAt] = useState(() => Date.now());
  const [error, setError] = useState("");
  const run = useCallback(async () => {
    if (typeof document !== "undefined" && document.hidden) return;
    try {
      await ref.current();
      setAt(Date.now());
      setError("");
    } catch (e) {
      setError(errMsg(e));
    }
  }, []);
  useEffect(() => {
    if (!enabled) return undefined;
    const id = setInterval(() => void run(), everyMs);
    return () => clearInterval(id);
  }, [enabled, everyMs, run]);
  return { at, error, retry: run };
}

export type LiveState = ReturnType<typeof useLivePoll>;
