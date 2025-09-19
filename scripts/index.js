#!/usr/bin/env node
import { existsSync, readFileSync } from "fs";
import { join } from "path";
import CONFIG from '../config/config.js';

const {
  threatsFile,
} = CONFIG;

if (!threatsFile) throw new Error('Set threatsFile in config');

function loadThreats() {
  if (!existsSync(threatsFile)) {
    console.error(`❌ ${threatsFile} not found in CLI directory.`);
    process.exit(1);
  }
  try {
    const raw = readFileSync(threatsFile, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    console.error(`"❌ Failed to parse ${threatsFile}:"`, err.message);
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
  const map = new Map();
  for (const [pkg, versions] of Object.entries(compromised)) {
    map.set(pkg, new Set(versions));
  }
  return map;
}

function recordFinding(findings, type, file, pkg, version, where) {
  findings.push({ type, file, pkg, version, where });
}

// -------- Scanners --------

// package.json
function scanPackageJson(content, bad) {
  const findings = [];
  try {
    const json = JSON.parse(content);
    const allDeps = {
      ...(json.dependencies || {}),
      ...(json.devDependencies || {}),
      ...(json.peerDependencies || {}),
      ...(json.optionalDependencies || {})
    };
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
  } catch {}
  return findings;
}

// package-lock.json
function scanPackageLock(content, bad) {
  const findings = [];
  try {
    const lock = JSON.parse(content);
    const stack = [];

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
      visitDeps(lock, []);
    }
  } catch {}
  return findings;
}

// yarn.lock v1
function scanYarnLockV1(content, bad) {
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
  return findings;
}

// Yarn Berry (v2+)
function scanYarnBerryLock(content, bad) {
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
  return findings;
}

// pnpm-lock.yaml
function scanPnpmLock(content, bad) {
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
  return findings;
}

// -------- Runner --------
(function main() {
  const bad = getCompromisedMap();
  const allFindings = [];

  for (const file of filesToCheck) {
    const filePath = join(process.cwd(), file);
    if (!existsSync(filePath)) continue;
    const content = readFileSync(filePath, "utf8");

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

  const badFindings = allFindings.filter(f => f.type === "bad");
  const warnFindings = allFindings.filter(f => f.type === "warn");

  warnFindings.forEach(f =>
    console.log(`⚠️  WARNING: ${f.pkg}@${f.version} in ${f.file} (${f.where}) — package was targeted in past attack, but version is not flagged as malicious`)
  );

  badFindings.forEach(f =>
    console.log(`❌ ALERT: ${f.pkg}@${f.version} in ${f.file} (${f.where}) — known malicious version`)
  );

  if (badFindings.length === 0) {
    console.log("✅ No known malicious versions detected.");
  } else {
    process.exit(1);
  }
})();