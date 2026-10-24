// Saving SBOM/CBOM exports as files in the browser.

function saveBlob(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function downloadTextFile(filename: string, content: string, mime = "application/json"): void {
  saveBlob(String(filename || "download.txt"), new Blob([String(content || "")], { type: mime }));
}

// Throws on content that isn't base64; the caller reports the export failed.
export function downloadBase64File(filename: string, b64: string, mime = "application/octet-stream"): void {
  const bin = atob(String(b64 || ""));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
  saveBlob(String(filename || "download.bin"), new Blob([bytes], { type: mime }));
}
