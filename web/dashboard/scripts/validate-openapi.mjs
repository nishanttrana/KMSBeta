import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..", "..", "..");
const generatedPaths = [
  "docs/openapi/ai.openapi.yaml",
  "docs/openapi/ai.openapi.json",
  "docs/openapi/sbom.openapi.yaml",
  "docs/openapi/sbom.openapi.json",
  "docs/openapi/posture.openapi.yaml",
  "docs/openapi/posture.openapi.json",
  "docs/openapi/compliance.openapi.yaml",
  "docs/openapi/compliance.openapi.json",
  "docs/openapi/reporting.openapi.yaml",
  "docs/openapi/reporting.openapi.json",
  "web/dashboard/public/openapi",
];

function run(cmd, args) {
  return execFileSync(cmd, args, {
    cwd: repoRoot,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

try {
  process.stdout.write(run("node", [path.join("web", "dashboard", "scripts", "generate-openapi.mjs")]));
  const status = run("git", [
    "status",
    "--porcelain",
    "--untracked-files=all",
    "--",
    ...generatedPaths,
  ]).toString().trim();
  if (status) {
    console.error(status);
    throw new Error("generated files changed");
  }
  console.log("OpenAPI artifacts are up to date.");
} catch (error) {
  console.error("OpenAPI artifacts drifted from generated output. Run `npm.cmd --prefix web/dashboard run generate:openapi` and commit the updated files.");
  process.exitCode = 1;
}
