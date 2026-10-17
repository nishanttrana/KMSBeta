import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// The ⓘ build popover, the clock's timezone menu and the SBOM Export menu
// closed only on a second press of their own button (13.12.0-beta). A panel
// floated over the page from a boolean state is a popover, and its state comes
// from usePopover, which also closes it on an outside press or Escape.

const SRC = join(__dirname, "..", "..", "src");

function sources(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) sources(path, out);
    else if (name.endsWith(".tsx")) out.push(path);
  }
  return out;
}

describe("popovers close on an outside press or Escape", () => {
  it("no floating panel is gated by a plain useState boolean", () => {
    const hits: string[] = [];
    for (const file of sources(SRC)) {
      const text = readFileSync(file, "utf8");
      for (const m of text.matchAll(/const \[(\w+), set\w+\] = useState(?:<boolean>)?\(false\)/g)) {
        const name = m[1]!;
        for (const g of text.matchAll(new RegExp(`\\{${name} (?:&&|\\?) \\(?\\s*<div[^>]{0,200}?position: "absolute"`, "g"))) {
          hits.push(`${file.slice(SRC.length + 1)}:${text.slice(0, g.index).split("\n").length} ${name}`);
        }
      }
    }
    expect(hits).toEqual([]);
  });
});
