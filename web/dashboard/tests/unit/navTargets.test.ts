import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SUB_PANES } from "../../src/components/v3/SidebarSubNav";
import { NAV } from "../../src/components/v3/shellNav";

// A tab asks the shell to open another tab with onNavigate("<id>"). The
// shell opens only ids in its NAV list; any other id falls back to its first
// tab, the Command Center, with no error. Crypto Discovery's "Connect" and
// "Open PKI" buttons did exactly that until 7.34.0-beta ("byok" and
// "certificates" are sub-pane and module ids, not tabs).
// A target may name a sub-option too, "admin/users" (13.23.0-beta): both
// parts must exist.

const SRC = join(__dirname, "..", "..", "src");

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? sources(join(dir, e.name)) : /\.tsx?$/.test(e.name) ? [join(dir, e.name)] : []);
}

function navIds(): Set<string> {
  return new Set(NAV.flatMap((g) => g.items.map((it) => it.id)));
}

describe("navigation targets", () => {
  const ids = navIds();

  it("reads the shell's tab list", () => {
    expect(ids.has("home")).toBe(true);
    expect(ids.has("discovery")).toBe(true);
    expect(ids.size).toBeGreaterThan(20);
  });

  const known = (target: string) => {
    const [tab = "", sub] = target.split("/");
    return ids.has(tab) && (sub === undefined || (SUB_PANES[tab] || []).some((p) => p.id === sub));
  };

  it("every onNavigate target is a tab the shell has", () => {
    const targets: string[] = [];
    const unknown: string[] = [];
    for (const file of sources(SRC)) {
      for (const m of readFileSync(file, "utf8").matchAll(/onNavigate(?:\?\.)?\(\s*["'`]([^"'`$]+)["'`]/g)) {
        targets.push(m[1]!);
        if (!known(m[1]!)) unknown.push(`${file.slice(SRC.length + 1)}: onNavigate("${m[1]}")`);
      }
    }
    expect(targets).toContain("cloudctl");
    expect(targets).toContain("home/recommendations");
    expect(unknown).toEqual([]);
  });

  it("every recommendation opens a tab and section the shell has", () => {
    const engine = readFileSync(join(SRC, "lib", "recommendations.ts"), "utf8");
    const tabs = [...engine.matchAll(/action: \{ tab: "([^"]+)"/g)].map((m) => m[1]!);
    expect(tabs).toContain("admin/backup");
    expect(tabs.filter((t) => !known(t))).toEqual([]);
  });
});
