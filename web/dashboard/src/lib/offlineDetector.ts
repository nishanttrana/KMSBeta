/**
 * offlineDetector — subscribes to browser online/offline events and notifies
 * registered listeners.  Returns an unsubscribe function for cleanup.
 */

type Listener = (online: boolean) => void;

const listeners = new Set<Listener>();

function emit(online: boolean): void {
  listeners.forEach((fn) => {
    try {
      fn(online);
    } catch {
      /* ignore */
    }
  });
}

// Register once at module load time.
window.addEventListener("online", () => emit(true));
window.addEventListener("offline", () => emit(false));

export function subscribeOnlineStatus(listener: Listener): () => void {
  listeners.add(listener);
  // Immediately notify with current state.
  listener(navigator.onLine);
  return () => listeners.delete(listener);
}

export function isOnline(): boolean {
  return navigator.onLine;
}
