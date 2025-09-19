#!/usr/bin/env node
import { existsSync, readFileSync } from "fs";
import { join, isAbsolute, dirname } from "path";
import { fileURLToPath } from "url";
import util from "util";
import CONFIG from "../config/config.js";
import { logToRoot } from "./logger.js";

// Create a debug logger for the "threats" namespace
const debug = util.debuglog("threats");

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { threatsFile } = CONFIG;
if (!threatsFile) throw new Error("Set threatsFile in config");

debug("CONFIG.threatsFile = %s", threatsFile);

let resolvedThreatsPath;

if (isAbsolute(threatsFile)) {
  debug("Path is absolute");
  resolvedThreatsPath = threatsFile;
} else {
  debug("Path is relative");

  const localPath = join(process.cwd(), threatsFile);
  debug("Checking local path: %s -> %s", localPath, existsSync(localPath));

  const cliPath = join(__dirname, "..", threatsFile);
  debug("Checking CLI path: %s -> %s", cliPath, existsSync(cliPath));

  if (existsSync(localPath)) {
    resolvedThreatsPath = localPath;
  } else if (existsSync(cliPath)) {
    resolvedThreatsPath = cliPath;
  }
}

if (!resolvedThreatsPath || !existsSync(resolvedThreatsPath)) {
  console.error(`❌ ${threatsFile} not found in project or CLI directory.`);
  process.exit(1);
}

debug("Using threats file: %s", resolvedThreatsPath);

function loadThreats() {
  debug("Loading threats from %s", resolvedThreatsPath);
  try {
    const raw = readFileSync(resolvedThreatsPath, "utf8");
    const parsed = JSON.parse(raw);
    debug("Loaded %d packages from threats file", Object.keys(parsed).length);
    return parsed;
  } catch (err) {
    console.error(`❌ Failed to parse ${resolvedThreatsPath}:`, err.message);
    process.exit(1);
  }
}

const compromised = loadThreats();

const filesToCheck = [
  "package.json",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml"
];

function escRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function getCompromisedMap() {
  debug("Building compromised map");
  const map = new Map();
  for (const [pkg, versions] of Object.entries(compromised)) {
    map.set(pkg, new Set(versions));
  }
  debug("Compromised map contains %d packages", map.size);
  return map;
}

function recordFinding(findings, type, file, pkg, version, where) {
  debug("Recording finding: %s %s@%s in %s (%s)", type, pkg, version, file, where);
  findings.push({ type, file, pkg, version, where });
}

// -------- Scanners --------

function scanPackageJson(content, bad) {
  debug("Scanning package.json");
  const findings = [];
  try {
    const json = JSON.parse(content);
    const allDeps = {
      ...(json.dependencies || {}),
      ...(json.devDependencies || {}),
      ...(json.peerDependencies || {}),
      ...(json.optionalDependencies || {})
    };
    debug("Found %d dependencies in package.json", Object.keys(allDeps).length);
    for (const [pkg, range] of Object.entries(allDeps)) {
      if (!bad.has(pkg)) continue;
      let type = "warn";
      for (const v of bad.get(pkg)) {
        if (range === v || range === `=${v}`) {
          type = "bad";
          break;
        }
      }
      recordFinding(findings, type, "package.json", pkg, range, "declared dependency");
    }
  } catch (err) {
    debug("Error parsing package.json: %s", err.message);
  }
  debug("package.json scan complete: %d findings", findings.length);
  return findings;
}

function scanPackageLock(content, bad) {
  debug("Scanning package-lock.json");
  const findings = [];
  try {
    const lock = JSON.parse(content);

    function visitDeps(obj, pathArr = []) {
      if (!obj) return;
      const deps = obj.dependencies || {};
      for (const [name, meta] of Object.entries(deps)) {
        const version = meta.version;
        if (bad.has(name)) {
          const type = bad.get(name).has(version) ? "bad" : "warn";
          recordFinding(findings, type, "package-lock.json", name, version, pathArr.concat(name).join(" > "));
        }
        visitDeps(meta, pathArr.concat(name));
      }
    }

    if (lock.packages && typeof lock.packages === "object") {
      debug("Detected npm v7+ lockfile format");
      for (const [pkgPath, meta] of Object.entries(lock.packages)) {
        if (!meta || !meta.version) continue;
        const name = meta.name || (pkgPath.includes("node_modules/") ? pkgPath.split("node_modules/").pop() : null);
        if (!name) continue;
        if (bad.has(name)) {
          const type = bad.get(name).has(meta.version) ? "bad" : "warn";
          recordFinding(findings, type, "package-lock.json", name, meta.version, pkgPath || "(root)");
        }
      }
    } else {
      debug("Detected npm v6 lockfile format");
      visitDeps(lock, []);
    }
  } catch (err) {
    debug("Error parsing package-lock.json: %s", err.message);
  }
  debug("package-lock.json scan complete: %d findings", findings.length);
  return findings;
}

function scanYarnLockV1(content, bad) {
  debug("Scanning yarn.lock v1");
  const findings = [];
  const entries = content.split(/\n{2,}/g);
  for (const entry of entries) {
    const headerMatch = entry.match(/^"([^"]+)"\s*:\s*$/m);
    if (!headerMatch) continue;
    const header = headerMatch[1];
    const versionMatch = entry.match(/^\s*version\s+"([^"]+)"/m);
    if (!versionMatch) continue;
    const version = versionMatch[1];
    const keys = header.split(/,\s*/g);
    const packageNames = new Set();
    for (const key of keys) {
      if (key.startsWith("@")) {
        const parts = key.split("@");
        if (parts.length >= 2) packageNames.add("@" + parts[1]);
      } else {
        const at = key.lastIndexOf("@");
        if (at > 0) packageNames.add(key.slice(0, at));
      }
    }
    for (const name of packageNames) {
      if (bad.has(name)) {
        const type = bad.get(name).has(version) ? "bad" : "warn";
        recordFinding(findings, type, "yarn.lock", name, version, header);
      }
    }
  }
  debug("yarn.lock v1 scan complete: %d findings", findings.length);
  return findings;
}

function scanYarnBerryLock(content, bad) {
  debug("Scanning Yarn Berry lockfile");
  const findings = [];
  const blockRe = /^("?([^"\n]+)"?):\n((?: {2}.+\n)+)/gm;
  let m;
  while ((m = blockRe.exec(content))) {
    const key = m[2];
    const block = m[3];
    const v = block.match(/^\s{2}version:\s+("?)([^"\n]+)\1/m);
    if (!v) continue;
    const version = v[2];
    let name = key;
    const protoAt = key.indexOf("@npm:");
    if (protoAt !== -1) name = key.slice(0, protoAt);
    else {
      const at = key.lastIndexOf("@");
      if (at > 0) name = key.slice(0, at);
    }
    if (bad.has(name)) {
      const type = bad.get(name).has(version) ? "bad" : "warn";
      recordFinding(findings, type, "yarn.lock", name, version, key);
    }
  }
  debug("Yarn Berry scan complete: %d findings", findings.length);
  return findings;
}

function scanPnpmLock(content, bad) {
  debug("Scanning pnpm-lock.yaml");
  const findings = [];
  const re = /^\s*\/?(@?[^@\s/][^@:\s/]*\/?[^@:\s/]*)@([0-9][^:\s]+):/gm;
  let m;
  while ((m = re.exec(content))) {
    const name = m[1];
    const version = m[2];
    if (bad.has(name)) {
      const type = bad.get(name).has(version) ? "bad" : "warn";
      recordFinding(findings, type, "pnpm-lock.yaml", name, version, `${name}@${version}`);
    }
  }
  debug("pnpm-lock.yaml scan complete: %d findings", findings.length);
  return findings;
}

// -------- Runner --------
(function main() {
  debug("Starting main scan");
  const bad = getCompromisedMap();
  const allFindings = [];

  for (const file of filesToCheck) {
    debug("Checking for %s", file);
    const filePath = join(process.cwd(), file);
    if (!existsSync(filePath)) {
      debug("Skipping %s (not found)", file);
      continue;
    }
    const content = readFileSync(filePath, "utf8");
    debug("Found %s, size %d bytes", file, content.length);

    if (file === "package.json") {
      allFindings.push(...scanPackageJson(content, bad));
    } else if (file === "package-lock.json") {
      allFindings.push(...scanPackageLock(content, bad));
    } else if (file === "yarn.lock") {
      const f1 = scanYarnLockV1(content, bad);
      const f2 = f1.length ? [] : scanYarnBerryLock(content, bad);
      allFindings.push(...f1, ...f2);
    } else if (file === "pnpm-lock.yaml") {
      allFindings.push(...scanPnpmLock(content, bad));
    }
  }

  debug("Total findings collected: %d", allFindings.length);

  const badFindings = allFindings.filter(f => f.type === "bad");
  const warnFindings = allFindings.filter(f => f.type === "warn");

  debug("Bad findings: %d, Warn findings: %d", badFindings.length, warnFindings.length);

  warnFindings.forEach(f =>
    logToRoot(`WARNING: ${f.pkg}@${f.version} in ${f.file} (${f.where}) — package had previous vulnerability, but version is not flagged with advisory.`)
  );

  badFindings.forEach(f => {
    console.log(`❌ ALERT: ${f.pkg}@${f.version} in ${f.file} (${f.where}) — known advisory`);
    logToRoot(`ALERT: ${f.pkg}@${f.version} in ${f.file} (${f.where}) — known advisory`);
  });

  if (badFindings.length === 0) {
    console.log("✅ No known advisories detected.");
    logToRoot("No known advisories detected.");
    console.log("Scan completed, results can be found in scan-compromised.log");
  } else {
    debug("Exiting with code 1 due to bad findings");
    process.exit(1);
  }
  debug("Scan complete");
})();
