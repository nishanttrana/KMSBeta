import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

// The component size gate is a ratchet (scripts/check-component-size.mjs):
// listed files may not grow, unlisted files must be within the limit, and
// an entry that is no longer needed must be removed.
const SCRIPT = path.resolve(__dirname, "../../scripts/check-component-size.mjs");
const lines = (n: number) => Array.from({ length: n }, (_, i) => `// ${i}`).join("\n");

function run(files: Record<string, number>, burndown: Record<string, number>, ...args: string[]) {
  const dir = mkdtempSync(path.join(tmpdir(), "size-gate-"));
  mkdirSync(path.join(dir, "scripts"));
  mkdirSync(path.join(dir, "src/components"), { recursive: true });
  for (const [name, n] of Object.entries(files)) writeFileSync(path.join(dir, "src/components", name), lines(n));
  writeFileSync(path.join(dir, "scripts/component-size-burndown.json"), JSON.stringify(burndown));
  const out = spawnSync(process.execPath, [SCRIPT, ...args], { cwd: dir, encoding: "utf8" });
  return { code: out.status, text: out.stdout + out.stderr, list: () => JSON.parse(readFileSync(path.join(dir, "scripts/component-size-burndown.json"), "utf8")) };
}

describe("component size gate", () => {
  it("passes when listed files are at their ceiling and the rest are small", () => {
    expect(run({ "Big.tsx": 800, "Small.tsx": 500 }, { "src/components/Big.tsx": 800 }).code).toBe(0);
  });
  it("fails when a listed file grows", () => {
    const r = run({ "Big.tsx": 801 }, { "src/components/Big.tsx": 800 });
    expect(r.code).toBe(1);
    expect(r.text).toContain("grew to 801 lines (ceiling 800)");
  });
  it("fails when an unlisted file is over the limit", () => {
    const r = run({ "New.tsx": 501 }, {});
    expect(r.code).toBe(1);
    expect(r.text).toContain("New.tsx has 501 lines (max 500)");
  });
  it("fails on an entry that is no longer needed", () => {
    expect(run({ "Fixed.tsx": 400 }, { "src/components/Fixed.tsx": 900 }).text).toContain("Remove its entry");
    expect(run({}, { "src/components/Gone.tsx": 900 }).code).toBe(1);
  });
  it("--tighten lowers ceilings and drops fixed files, never raises", () => {
    const r = run({ "Shrunk.tsx": 700, "Grown.tsx": 950, "Fixed.tsx": 300 },
      { "src/components/Shrunk.tsx": 900, "src/components/Grown.tsx": 900, "src/components/Fixed.tsx": 900 }, "--tighten");
    expect(r.code).toBe(0);
    expect(r.list()).toEqual({ "src/components/Grown.tsx": 900, "src/components/Shrunk.tsx": 700 });
  });
});
