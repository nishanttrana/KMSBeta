import { toast } from "./toast";

/**
 * copyToClipboard — writes text to the clipboard and fires a toast
 * confirming success or reporting the failure reason.
 *
 * @param text  The string to copy.
 * @param label Optional human-readable label for the toast (e.g. "Key ID").
 */
export async function copyToClipboard(text: string, label?: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    toast.success(label ? `${label} copied to clipboard` : "Copied to clipboard");
    return true;
  } catch {
    // Clipboard API may be blocked in insecure contexts; fall back to
    // execCommand (deprecated but still works in most browsers).
    try {
      const el = document.createElement("textarea");
      el.value = text;
      el.style.cssText = "position:fixed;top:-9999px;left:-9999px;opacity:0";
      document.body.appendChild(el);
      el.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(el);
      if (ok) {
        toast.success(label ? `${label} copied to clipboard` : "Copied to clipboard");
        return true;
      }
    } catch {
      /* fall through */
    }
    toast.error("Could not copy to clipboard — please copy manually");
    return false;
  }
}
