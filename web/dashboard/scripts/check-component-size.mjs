import { promises as fs } from "node:fs";
import path from "node:path";

// Component size gate. A component file may have at most MAX_LINES lines.
//
// Files that were already larger when the gate became enforceable are listed
// in component-size-burndown.json with a ceiling: the line count they had
// then. The list only shrinks:
//   - a listed file may not grow past its ceiling;
//   - a listed file that is now within MAX_LINES, or gone, must be removed
//     from the list;
//   - a file not on the list must be within MAX_LINES.
// Lower a ceiling when you shrink a file (`--tighten` rewrites the list to
// the current counts, never upward). Never raise one: split the file instead.
const ROOTS = ["src/components", "src/modules"];
const MAX_LINES = 500;
const BURNDOWN = path.resolve(process.cwd(), "scripts", "component-size-burndown.json");

async function walk(dir) {
  const out = [];
  let entries = [];
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return out; // a root may be missing in a partial checkout
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...(await walk(full)));
    } else if (entry.isFile() && entry.name.endsWith(".tsx")) {
      out.push(full);
    }
  }
  return out;
}

async function main() {
  const tighten = process.argv.includes("--tighten");
  const ceilings = JSON.parse(await fs.readFile(BURNDOWN, "utf8"));
  const sizes = {};
  for (const root of ROOTS) {
    for (const file of await walk(path.resolve(process.cwd(), root))) {
      if (file.includes(`${path.sep}legacy${path.sep}`)) continue;
      const rel = path.relative(process.cwd(), file).split(path.sep).join("/");
      sizes[rel] = (await fs.readFile(file, "utf8")).split(/\r?\n/).length;
    }
  }

  if (tighten) {
    const next = {};
    for (const [file, ceiling] of Object.entries(ceilings).sort(([a], [b]) => a.localeCompare(b))) {
      if (sizes[file] > MAX_LINES) next[file] = Math.min(ceiling, sizes[file]);
    }
    await fs.writeFile(BURNDOWN, `${JSON.stringify(next, null, 2)}\n`);
    console.log(`Burn-down list tightened: ${Object.keys(next).length} file(s) still over ${MAX_LINES} lines.`);
    return;
  }

  const errors = [];
  for (const [file, lines] of Object.entries(sizes)) {
    const ceiling = ceilings[file];
    if (ceiling === undefined && lines > MAX_LINES) {
      errors.push(`${file} has ${lines} lines (max ${MAX_LINES}). Split it.`);
    } else if (ceiling !== undefined && lines > ceiling) {
      errors.push(`${file} grew to ${lines} lines (ceiling ${ceiling}). Move the new code into its own file.`);
    }
  }
  for (const [file, ceiling] of Object.entries(ceilings)) {
    if (sizes[file] === undefined) {
      errors.push(`${file} is on the burn-down list but no longer exists. Remove its entry.`);
    } else if (sizes[file] <= MAX_LINES) {
      errors.push(`${file} is now ${sizes[file]} lines, within the limit. Remove its entry (ceiling ${ceiling}).`);
    }
  }
  if (errors.length) {
    console.error("Component size gate failed:");
    errors.forEach((e) => console.error(` - ${e}`));
    process.exit(1);
  }
  console.log(`Component size gate passed (${Object.keys(ceilings).length} file(s) on the burn-down list).`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
