// Hardened QueryClient — centralised so every consumer gets the same config.
import { QueryClient } from "@tanstack/react-query";

function isAuthError(error: unknown): boolean {
  const msg = error instanceof Error ? error.message : String(error);
  return (
    msg.includes("401") ||
    msg.includes("403") ||
    msg.includes("Unauthorized") ||
    msg.includes("Forbidden")
  );
}

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Retry up to 2× for transient errors; never retry auth failures.
      retry: (count, error) => count < 2 && !isAuthError(error),
      retryDelay: (attempt) => Math.min(1000 * 2 ** attempt, 10_000),
      // Data stays fresh for 30 s — reduces redundant network round-trips.
      staleTime: 30_000,
      // Keep unused query data in cache for 10 min before GC.
      gcTime: 10 * 60 * 1000,
      // Don't re-fetch when the user switches browser tabs.
      refetchOnWindowFocus: false,
      // Always attempt the fetch even when navigator.onLine reports false
      // (onLine is unreliable on many networks).
      networkMode: "always",
    },
    mutations: {
      // Mutations are not idempotent — never auto-retry.
      retry: 0,
      networkMode: "always",
    },
  },
});
