import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// A tab asks the shell to open another tab with onNavigate("<id>"). The
// shell opens only ids in its NAV list; any other id falls back to its first
// tab, the Command Center, with no error. Crypto Discovery's "Connect" and
// "Open PKI" buttons did exactly that until 7.34.0-beta ("byok" and
// "certificates" are sub-pane and module ids, not tabs).

const SRC = join(__dirname, "..", "..", "src");

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? sources(join(dir, e.name)) : /\.tsx?$/.test(e.name) ? [join(dir, e.name)] : []);
}

function navIds(): Set<string> {
  const shell = readFileSync(join(SRC, "components", "VectaDashboardV3Shell.tsx"), "utf8");
  const start = shell.indexOf("const NAV = [");
  const block = shell.slice(start, shell.indexOf("\n];", start));
  return new Set([...block.matchAll(/\{ id: "([^"]+)"/g)].map((m) => m[1]!));
}

describe("navigation targets", () => {
  const ids = navIds();

  it("reads the shell's tab list", () => {
    expect(ids.has("home")).toBe(true);
    expect(ids.has("discovery")).toBe(true);
    expect(ids.size).toBeGreaterThan(20);
  });

  it("every onNavigate target is a tab the shell has", () => {
    const targets: string[] = [];
    const unknown: string[] = [];
    for (const file of sources(SRC)) {
      for (const m of readFileSync(file, "utf8").matchAll(/onNavigate(?:\?\.)?\(\s*["'`]([^"'`$]+)["'`]/g)) {
        targets.push(m[1]!);
        if (!ids.has(m[1]!)) unknown.push(`${file.slice(SRC.length + 1)}: onNavigate("${m[1]}")`);
      }
    }
    expect(targets).toContain("cloudctl");
    expect(unknown).toEqual([]);
  });
});
