import { promises as fs } from "node:fs";
import path from "node:path";

const ROOTS = [
  path.resolve(process.cwd(), "src", "components"),
  path.resolve(process.cwd(), "src", "modules")
];
const MAX_LINES = 500;
const QUARANTINE_ALLOWLIST = new Set([]);

async function walk(dir) {
  const out = [];
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...(await walk(full)));
      continue;
    }
    if (!entry.isFile() || !entry.name.endsWith(".tsx")) {
      continue;
    }
    out.push(full);
  }
  return out;
}

async function main() {
  const files = [];
  for (const root of ROOTS) {
    try {
      files.push(...(await walk(root)));
    } catch {
      // Ignore missing roots; this script is used in mixed repo states.
    }
  }
  const violations = [];
  for (const file of files) {
    if (file.includes(`${path.sep}legacy${path.sep}`)) {
      continue;
    }
    if (QUARANTINE_ALLOWLIST.has(path.basename(file))) {
      continue;
    }
    const content = await fs.readFile(file, "utf8");
    const lineCount = content.split(/\r?\n/).length;
    if (lineCount > MAX_LINES) {
      violations.push({ file, lineCount });
    }
  }

  if (violations.length) {
    console.error(`Component size gate failed (${MAX_LINES} lines max):`);
    violations.forEach((item) => {
      console.error(` - ${path.relative(process.cwd(), item.file)} (${item.lineCount} lines)`);
    });
    process.exit(1);
  }
  console.log("Component size gate passed.");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
