// Files marked @ts-nocheck skip every type check, including the one that
// matters at runtime: a name that doesn't exist. Two such bugs shipped (the
// Certificates tab threw "pqc is not defined" on every render; a payment
// policy panel called functions it never imported). This check reads those
// files without the marker and fails only on undefined names and broken
// imports, leaving their loose typing alone.
import path from "node:path";
import ts from "typescript";

// Cannot find name / namespace / module; no value for a shorthand property
// ({ pqc }); used before declaration; missing or misnamed export.
const RUNTIME_CODES = new Set([2304, 2552, 18004, 2448, 2454, 2305, 2724, 2614, 2307]);
// Names that exist only in the type system (no runtime effect).
const TYPE_ONLY = /Cannot find namespace 'JSX'/;

const configPath = ts.findConfigFile(process.cwd(), ts.sys.fileExists, "tsconfig.json");
const { config } = ts.readConfigFile(configPath, ts.sys.readFile);
const parsed = ts.parseJsonConfigFileContent(config, ts.sys, path.dirname(configPath));

const host = ts.createCompilerHost(parsed.options);
const nocheck = new Set();
const readFile = host.readFile.bind(host);
host.readFile = (file) => {
  const text = readFile(file);
  if (text && !file.includes("node_modules") && /^\s*\/\/\s*@ts-nocheck/m.test(text)) {
    nocheck.add(path.resolve(file));
    return text.replace(/^(\s*)\/\/\s*@ts-nocheck.*$/m, "$1// (ts-nocheck lifted by check-nocheck-names)");
  }
  return text;
};

const program = ts.createProgram(parsed.fileNames, parsed.options, host);
const problems = [];
for (const sf of program.getSourceFiles()) {
  if (!nocheck.has(path.resolve(sf.fileName))) continue;
  for (const d of program.getSemanticDiagnostics(sf)) {
    const msg = ts.flattenDiagnosticMessageText(d.messageText, "\n");
    if (!RUNTIME_CODES.has(d.code) || TYPE_ONLY.test(msg)) continue;
    const { line, character } = sf.getLineAndCharacterOfPosition(d.start ?? 0);
    problems.push(`${path.relative(process.cwd(), sf.fileName)}:${line + 1}:${character + 1} TS${d.code} ${msg}`);
  }
}

if (problems.length) {
  console.error(`Undefined names or broken imports in @ts-nocheck files:\n${problems.join("\n")}`);
  process.exit(1);
}
console.log(`check-nocheck-names: ${nocheck.size} @ts-nocheck files, no undefined names.`);
