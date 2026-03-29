/**
 * toast — lightweight pub/sub notification manager.
 * Zero dependencies, no React required.  Components subscribe via
 * subscribeToasts(); call toast.success / .error / .info / .warn anywhere.
 */

export type ToastVariant = "success" | "error" | "info" | "warn";

export type Toast = {
  id: string;
  variant: ToastVariant;
  message: string;
  /** Auto-dismiss delay in ms. */
  duration: number;
};

type Listener = (toasts: Toast[]) => void;

let toasts: Toast[] = [];
const listeners = new Set<Listener>();

function emit(): void {
  const snapshot = [...toasts];
  listeners.forEach((fn) => {
    try {
      fn(snapshot);
    } catch {
      /* ignore */
    }
  });
}

function push(
  variant: ToastVariant,
  message: string,
  duration?: number
): string {
  const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
  const ms = duration ?? (variant === "error" ? 6000 : 4000);
  // Keep at most 5 toasts on screen.
  toasts = [...toasts.slice(-4), { id, variant, message, duration: ms }];
  emit();
  setTimeout(() => dismiss(id), ms);
  return id;
}

export function dismiss(id: string): void {
  toasts = toasts.filter((t) => t.id !== id);
  emit();
}

export const toast = {
  success: (msg: string, duration?: number) => push("success", msg, duration),
  error:   (msg: string, duration?: number) => push("error",   msg, duration),
  info:    (msg: string, duration?: number) => push("info",    msg, duration),
  warn:    (msg: string, duration?: number) => push("warn",    msg, duration),
  dismiss,
};

export function subscribeToasts(fn: Listener): () => void {
  listeners.add(fn);
  fn([...toasts]);
  return () => listeners.delete(fn);
}
