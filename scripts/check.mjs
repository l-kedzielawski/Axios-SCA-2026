#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const MALICIOUS = new Map([
  ["axios", new Set(["1.14.1", "0.30.4"])],
  ["plain-crypto-js", new Set(["4.2.1"])],
  ["@shadanai/openclaw", new Set(["2026.3.28-2", "2026.3.28-3", "2026.3.31-1", "2026.3.31-2"])],
  ["@qqbrowser/openclaw-qbot", new Set(["0.0.130"])],
]);

const LOCKFILE_NAMES = new Set(["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "package.json"]);
const DEFAULT_MAX_DEPTH = 4;
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  ".hg",
  ".svn",
  "dist",
  "build",
  "out",
  ".next",
  ".turbo",
  "coverage",
  ".cache",
]);

function printUsage() {
  const lines = [
    "Axios-SCA-2026 check",
    "",
    "Scans lockfiles for known malicious versions:",
    "  - axios@1.14.1",
    "  - axios@0.30.4",
    "  - plain-crypto-js@4.2.1",
    "  - @shadanai/openclaw@2026.3.28-2/3 and 2026.3.31-1/2",
    "  - @qqbrowser/openclaw-qbot@0.0.130",
    "",
    "Usage:",
    "  node check.mjs [path] [--no-recursive] [--max-depth N]",
    "",
    "Exit codes:",
    "  0 = no malicious versions found",
    "  1 = malicious version found",
    "  2 = error reading/parsing lockfiles",
  ];
  console.log(lines.join("\n"));
}

function parseArgs(argv) {
  let targetPath = ".";
  let recursive = true;
  let maxDepth = DEFAULT_MAX_DEPTH;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "-h" || arg === "--help") {
      return { help: true };
    }
    if (arg === "--no-recursive") {
      recursive = false;
      continue;
    }
    if (arg === "--max-depth") {
      const next = argv[i + 1];
      if (!next) {
        return { error: "Missing value for --max-depth" };
      }
      const parsed = Number.parseInt(next, 10);
      if (!Number.isFinite(parsed) || parsed < 0) {
        return { error: `Invalid --max-depth value: ${next}` };
      }
      maxDepth = parsed;
      i += 1;
      continue;
    }
    if (arg.startsWith("-")) {
      return { error: `Unknown option: ${arg}` };
    }
    targetPath = arg;
  }

  return {
    help: false,
    targetPath,
    recursive,
    maxDepth,
  };
}

function escapeRegex(input) {
  return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function record(map, key, value) {
  const existing = map.get(key);
  if (!existing) {
    map.set(key, new Set([value]));
    return;
  }
  existing.add(value);
}

function isMalicious(name, version) {
  const badVersions = MALICIOUS.get(name);
  return badVersions ? badVersions.has(version) : false;
}

function walkForFiles(startDir, recursive, maxDepth) {
  const found = [];
  const stack = [{ dir: startDir, depth: 0 }];

  while (stack.length > 0) {
    // Depth-first.
    const current = stack.pop();
    if (!current) break;

    let entries;
    try {
      entries = fs.readdirSync(current.dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(current.dir, entry.name);
      if (entry.isFile() && LOCKFILE_NAMES.has(entry.name)) {
        found.push(fullPath);
        continue;
      }

      if (!recursive || !entry.isDirectory()) continue;
      if (SKIP_DIRS.has(entry.name)) continue;
      if (current.depth >= maxDepth) continue;

      stack.push({ dir: fullPath, depth: current.depth + 1 });
    }
  }

  return found;
}

function scanPackageJson(text, filePath) {
  const findings = [];
  let pkg;
  try {
    pkg = JSON.parse(text);
  } catch (error) {
    return {
      findings,
      error: `Failed to parse ${filePath} as JSON: ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  const sections = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
  for (const section of sections) {
    const deps = pkg?.[section];
    if (!deps || typeof deps !== "object") continue;

    for (const [name, spec] of Object.entries(deps)) {
      if (typeof spec !== "string") continue;
      const badVersions = MALICIOUS.get(name);
      if (!badVersions) continue;

      if (badVersions.has(spec)) {
        findings.push({ name, version: spec, filePath, source: `package.json (${section})` });
      }
    }
  }

  return { findings, error: null };
}

function scanPackageLock(text, filePath) {
  const findings = [];
  let lock;
  try {
    lock = JSON.parse(text);
  } catch (error) {
    return {
      findings,
      error: `Failed to parse ${filePath} as JSON: ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  const seen = new Map();

  // npm v7+: packages["node_modules/<name>"].version
  if (lock && typeof lock === "object" && lock.packages && typeof lock.packages === "object") {
    for (const [pkgPath, info] of Object.entries(lock.packages)) {
      if (typeof pkgPath !== "string") continue;
      const lastNodeModulesIdx = pkgPath.lastIndexOf("node_modules/");
      if (lastNodeModulesIdx === -1) continue;

      const name = pkgPath.slice(lastNodeModulesIdx + "node_modules/".length);
      const version = info && typeof info === "object" ? info.version : undefined;
      if (typeof name !== "string" || typeof version !== "string") continue;

      record(seen, name, version);
    }
  }

  // npm v6 and older: dependencies tree
  const walkDeps = (deps) => {
    if (!deps || typeof deps !== "object") return;
    for (const [name, depInfo] of Object.entries(deps)) {
      if (!depInfo || typeof depInfo !== "object") continue;
      const version = depInfo.version;
      if (typeof version === "string") record(seen, name, version);
      if (depInfo.dependencies) walkDeps(depInfo.dependencies);
    }
  };
  if (lock && typeof lock === "object" && lock.dependencies && typeof lock.dependencies === "object") {
    walkDeps(lock.dependencies);
  }

  for (const [name, versions] of seen.entries()) {
    for (const version of versions) {
      if (isMalicious(name, version)) {
        findings.push({ name, version, filePath, source: "package-lock.json" });
      }
    }
  }

  return { findings, error: null };
}

function scanYarnLock(text, filePath) {
  const findings = [];
  for (const [name, badVersions] of MALICIOUS.entries()) {
    for (const version of badVersions) {
      const nameEscaped = escapeRegex(name);
      const versionEscaped = escapeRegex(version);

      // Yarn v1 lockfile stanza:
      //   <selectors>:
      //     version "<version>"
      //
      // We keep the match window bounded to avoid spanning too far.
      const re = new RegExp(
        `(^|\\n)"?[^\\n]*${nameEscaped}@[^\\n]*:\\n[\\s\\S]{0,4000}?\\n\\s*version\\s+"${versionEscaped}"`,
        "m",
      );

      if (re.test(text)) {
        findings.push({ name, version, filePath, source: "yarn.lock" });
      }
    }
  }

  return { findings, error: null };
}

function scanPnpmLock(text, filePath) {
  const findings = [];
  for (const [name, badVersions] of MALICIOUS.entries()) {
    for (const version of badVersions) {
      const nameEscaped = escapeRegex(name);
      const versionEscaped = escapeRegex(version);

      // pnpm-lock.yaml package key examples:
      //   /axios@1.14.1:
      //   /axios@1.14.1(peer@x.y.z):
      //   /@scope/pkg@1.2.3:
      const re = new RegExp(`(^|\\n)\\s*\\/${nameEscaped}@${versionEscaped}(?:\\(|:)`, "m");
      if (re.test(text)) {
        findings.push({ name, version, filePath, source: "pnpm-lock.yaml" });
      }
    }
  }

  return { findings, error: null };
}

function readTextFile(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function main() {
  const parsed = parseArgs(process.argv.slice(2));
  if ("help" in parsed && parsed.help) {
    printUsage();
    process.exitCode = 0;
    return;
  }
  if ("error" in parsed && parsed.error) {
    console.error(parsed.error);
    console.error("");
    printUsage();
    process.exitCode = 2;
    return;
  }

  const targetPath = path.resolve(parsed.targetPath);
  const files = walkForFiles(targetPath, parsed.recursive, parsed.maxDepth);

  console.log("Axios-SCA-2026 check");
  console.log(`Target: ${targetPath}`);

  if (files.length === 0) {
    console.log("");
    console.log(
      "No lockfiles found (package-lock.json, yarn.lock, pnpm-lock.yaml, package.json). Point this check at a project root.",
    );
    process.exitCode = 0;
    return;
  }

  const allFindings = [];
  const errors = [];

  for (const filePath of files) {
    let text;
    try {
      text = readTextFile(filePath);
    } catch (error) {
      errors.push(
        `Failed to read ${filePath}: ${error instanceof Error ? error.message : String(error)}`,
      );
      continue;
    }

    const base = path.basename(filePath);
    if (base === "package-lock.json") {
      const { findings, error } = scanPackageLock(text, filePath);
      allFindings.push(...findings);
      if (error) errors.push(error);
      continue;
    }
    if (base === "yarn.lock") {
      const { findings, error } = scanYarnLock(text, filePath);
      allFindings.push(...findings);
      if (error) errors.push(error);
      continue;
    }
    if (base === "pnpm-lock.yaml") {
      const { findings, error } = scanPnpmLock(text, filePath);
      allFindings.push(...findings);
      if (error) errors.push(error);
      continue;
    }
    if (base === "package.json") {
      const { findings, error } = scanPackageJson(text, filePath);
      allFindings.push(...findings);
      if (error) errors.push(error);
      continue;
    }
  }

  const unique = new Map();
  for (const finding of allFindings) {
    const key = `${finding.filePath}::${finding.name}::${finding.version}`;
    unique.set(key, finding);
  }
  const dedupedFindings = Array.from(unique.values()).sort((a, b) => {
    if (a.name !== b.name) return a.name.localeCompare(b.name);
    if (a.version !== b.version) return a.version.localeCompare(b.version);
    return a.filePath.localeCompare(b.filePath);
  });

  if (dedupedFindings.length === 0 && errors.length === 0) {
    console.log("");
    console.log("No known malicious versions found in scanned files.");
    process.exitCode = 0;
    return;
  }

  if (dedupedFindings.length > 0) {
    console.log("");
    console.log("Findings:");
    for (const finding of dedupedFindings) {
      console.log(`- [ALERT] ${finding.filePath}: ${finding.name}@${finding.version} (${finding.source})`);
    }
  }

  if (errors.length > 0) {
    console.log("");
    console.log("Errors:");
    for (const err of errors) {
      console.log(`- ${err}`);
    }
  }

  if (dedupedFindings.length > 0) {
    process.exitCode = 1;
    return;
  }
  process.exitCode = 2;
}

main();
