import fs from 'fs';
import https from 'https';
import CONFIG from '../config/config.js';

const {
  registryUrl,
  threatsFile,
  advisoriesFile,
  lastUpdatedFile,
  lastUpdatedTempFile,
  concurrencyLimit,
  progressBarLength,
} = CONFIG;

if (!registryUrl) throw new Error('Set registryUrl in config');
if (!threatsFile) throw new Error('Set threatsFile in config');
if (!advisoriesFile) throw new Error('Set advisoriesFile in config');
if (!lastUpdatedFile) throw new Error('Set lastUpdatedFile in config');
if (!lastUpdatedTempFile) throw new Error('Set lastUpdatedTempFile in config');
if (!concurrencyLimit) throw new Error('Set concurrencyLimit in config');
if (!progressBarLength) throw new Error('Set progressBarLength in config');

// --- Semver parsing and comparison ---
function parseVersionFull(v) {
  const [core, pre] = v.split('-');
  const [maj, min, pat] = core.split('.').map(n => parseInt(n, 10));
  const preParts = pre ? pre.split('.').map(p => (isNaN(p) ? p : parseInt(p, 10))) : [];
  return { major: maj, minor: min, patch: pat, pre: preParts };
}

function compareFull(a, b) {
  if (a.major !== b.major) return a.major > b.major ? 1 : -1;
  if (a.minor !== b.minor) return a.minor > b.minor ? 1 : -1;
  if (a.patch !== b.patch) return a.patch > b.patch ? 1 : -1;
  if (a.pre.length === 0 && b.pre.length === 0) return 0;
  if (a.pre.length === 0) return 1;
  if (b.pre.length === 0) return -1;
  for (let i = 0; i < Math.max(a.pre.length, b.pre.length); i++) {
    const apr = a.pre[i], bpr = b.pre[i];
    if (apr === undefined) return -1;
    if (bpr === undefined) return 1;
    if (typeof apr === 'number' && typeof bpr === 'number') {
      if (apr > bpr) return 1;
      if (apr < bpr) return -1;
    } else {
      if (String(apr) > String(bpr)) return 1;
      if (String(apr) < String(bpr)) return -1;
    }
  }
  return 0;
}

function satisfiesFull(version, range) {
  const v = parseVersionFull(version);
  const orClauses = range.split('||').map(c => c.trim());
  for (const clause of orClauses) {
    const andParts = clause.split(',').map(p => p.trim()).filter(Boolean);
    let ok = true;
    for (const part of andParts) {
      const m = part.match(/^(>=|<=|>|<|=)?\s*(.+)$/);
      if (!m) continue;
      const op = m[1] || '=';
      const ver = parseVersionFull(m[2]);
      const cmp = compareFull(v, ver);
      switch (op) {
        case '>=': if (cmp < 0) ok = false; break;
        case '<=': if (cmp > 0) ok = false; break;
        case '>':  if (cmp <= 0) ok = false; break;
        case '<':  if (cmp >= 0) ok = false; break;
        case '=':  if (cmp !== 0) ok = false; break;
      }
      if (!ok) break;
    }
    if (ok) return true;
  }
  return false;
}

// --- Registry fetch with retry ---
function httpsRequest(url, options) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, options, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(JSON.parse(data));
        } else {
          reject(new Error(`${res.statusCode} ${res.statusMessage}: ${data}`));
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function getVulnerableVersions(pkg, range) {
  try {
    const encodedName = encodeURIComponent(pkg);
    const url = `${registryUrl}${encodedName}`;
    const data = await httpsRequest(url, {
      method: 'GET',
      headers: { 'User-Agent': 'npm-threat-resolver/1.0' }
    });
    const versions = Object.keys(data.versions || {});
    versions.sort((a, b) => compareFull(parseVersionFull(b), parseVersionFull(a)));
    return versions.filter(v => satisfiesFull(v, range));
  } catch (err) {
    console.warn(`Failed to fetch versions for ${pkg}: ${err.message}`);
    return [];
  }
}

async function getVulnerableVersionsWithRetry(pkg, range, retries = 3) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await getVulnerableVersions(pkg, range);
    } catch (err) {
      if (attempt === retries) throw err;
      await new Promise(res => setTimeout(res, 500 * (attempt + 1)));
    }
  }
}

// --- Throttling ---
function throttle(items, limit, fn) {
  const results = [];
  let i = 0;

  return new Promise((resolve) => {
    let active = 0;

    function next() {
      while (active < limit && i < items.length) {
        const index = i++;
        active++;
        fn(items[index])
          .then(result => results[index] = result)
          .catch(() => results[index] = null)
          .finally(() => {
            active--;
            next();
          });
      }
      if (i >= items.length && active === 0) resolve(results);
    }

    next();
  });
}

// --- Progress helpers ---
function formatTime(seconds) {
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return `${mins}m ${secs}s`;
}

function drawProgressBar(completed, total, eta) {
  const percent = Math.floor((completed / total) * 100);
  const filled = Math.floor((percent / 100) * progressBarLength);
  const bar = '█'.repeat(filled) + '░'.repeat(progressBarLength - filled);
  return `processing ${completed} of ${total} packages ${bar} ${percent}% — ETA: ${eta}`;
}

function printProgress(message, newLine = false) {
  process.stdout.cursorTo(0);
  process.stdout.clearLine();
  process.stdout.write(message);
  if (newLine) process.stdout.write('\n');
}

// --- Main merge logic ---
async function resolveVersions() {
  try {
    const advisories = JSON.parse(fs.readFileSync(advisoriesFile, 'utf8'));
    const threats = fs.existsSync(threatsFile)
      ? JSON.parse(fs.readFileSync(threatsFile, 'utf8'))
      : {};

    const tasks = [];
    for (const [pkg, ranges] of Object.entries(advisories)) {
      for (const range of ranges) {
        tasks.push({ pkg, range });
      }
    }

    let completed = 0;
    const total = tasks.length;
    const startTime = Date.now();

    const resolved = await throttle(tasks, concurrencyLimit, async ({ pkg, range }) => {
      const versions = await getVulnerableVersionsWithRetry(pkg, range);
      completed++;
      const elapsed = (Date.now() - startTime) / 1000;
      const avgPerTask = elapsed / completed;
      const remaining = total - completed;
      const estRemaining = avgPerTask * remaining;
      const eta = formatTime(estRemaining);
      printProgress(drawProgressBar(completed, total, eta));
      return { pkg, versions };
    });

    printProgress('', true); // newline after final progress

    for (const { pkg, versions } of resolved) {
      if (!pkg || !versions) continue;
      if (!threats[pkg]) threats[pkg] = [];
      const existing = new Set(threats[pkg]);
      for (const v of versions) existing.add(v);
      threats[pkg] = Array.from(existing).sort();
    }

    fs.writeFileSync(threatsFile, JSON.stringify(threats, null, 2));
  } catch (err) {
    console.error('Error in resolveVersions:', err);
    const lastUpdatedTemp = fs.existsSync(lastUpdatedTempFile)
      ? fs.readFileSync(lastUpdatedTempFile, 'utf8')
      : null;
    fs.writeFileSync(lastUpdatedFile, lastUpdatedTemp || JSON.stringify({ lastUpdated: null }, null, 2));
    process.exitCode = 1;
  }
  console.log(`Resolved and merged ${Object.keys(advisories).length} packages into ../data/threats.json`);
}

resolveVersions();
