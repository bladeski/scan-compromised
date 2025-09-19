import fs from 'fs';
import https from 'https';
import CONFIG from '../config/config.js';

const {
  advisoriesApiUrl,
  githubToken,
  advisoriesFile,
  lastUpdatedFile,
  lastUpdatedTempFile
} = CONFIG;

if (!advisoriesApiUrl) throw new Error('Set advisoriesApiUrl in config');
if (!advisoriesFile) throw new Error('Set advisoriesFile in config');
if (!lastUpdatedFile) throw new Error('Set lastUpdatedFile in config');
if (!lastUpdatedTempFile) throw new Error('Set lastUpdatedTempFile in config');

if (!githubToken) throw new Error('Set GITHUB_TOKEN');

let lastUpdated = '2000-01-01T00:00:00Z';
if (fs.existsSync(lastUpdatedFile)) {
  lastUpdated = JSON.parse(fs.readFileSync(lastUpdatedFile, 'utf8')).lastUpdated;
  fs.writeFileSync(lastUpdatedTempFile, JSON.stringify({ lastUpdated }, null, 2));
}

function httpsRequest(url, options, body) {
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
    if (body) req.write(body);
    req.end();
  });
}

async function fetchAdvisories() {
  let cursor = null;
  let more = true;
  let maxUpdated = lastUpdated;
  let page = 1;
  printProgress(`Fetching advisories updated since ${lastUpdated}...`, true);
  const advisories = {};

  while (more) {
    printProgress(`Fetching page ${page++}...`);
    const after = cursor ? `"${cursor}"` : 'null';
    const query = {
      query: `
        {
          securityAdvisories(
            updatedSince: "${lastUpdated}"
            first: 100
            after: ${after}
          ) {
            pageInfo { hasNextPage endCursor }
            nodes {
              updatedAt
              vulnerabilities(first: 50) {
                nodes {
                  package { name ecosystem }
                  vulnerableVersionRange
                }
              }
            }
          }
        }
      `
    };

    const data = await httpsRequest(
      advisoriesApiUrl,
      {
        method: 'POST',
        headers: {
          Authorization: `bearer ${githubToken}`,
          'Content-Type': 'application/json',
          'User-Agent': 'npm-threat-fetcher/1.0'
        }
      },
      JSON.stringify(query)
    );

    const advisoriesData = data.data?.securityAdvisories;
    if (!advisoriesData) {
      console.error('GraphQL errors:', data.errors);
      throw new Error('securityAdvisories not returned');
    }

    for (const adv of advisoriesData.nodes) {
      if (adv.updatedAt > maxUpdated) maxUpdated = adv.updatedAt;
      for (const vuln of adv.vulnerabilities.nodes) {
        if (vuln.package.ecosystem !== 'NPM') continue;
        const pkg = vuln.package.name;
        const range = vuln.vulnerableVersionRange;
        if (!advisories[pkg]) advisories[pkg] = [];
        if (!advisories[pkg].includes(range)) advisories[pkg].push(range);
      }
    }

    cursor = advisoriesData.pageInfo.endCursor;
    more = advisoriesData.pageInfo.hasNextPage;
  }

  fs.writeFileSync(advisoriesFile, JSON.stringify(advisories, null, 2));
  fs.writeFileSync(lastUpdatedFile, JSON.stringify({ lastUpdated: maxUpdated }, null, 2));
  console.log(`Fetched ${Object.keys(advisories).length} packages into ${advisoriesFile}`);
}

function printProgress(message, newLine = false) {
  process.stdout.cursorTo(0);
  process.stdout.write(`${message}`);
  if (newLine) process.stdout.write('\n');
}

fetchAdvisories();
