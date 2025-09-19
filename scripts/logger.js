import { appendFileSync, existsSync } from 'node:fs';
import { resolve, dirname, join, parse } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Walk up from a starting directory until we find a package.json,
 * then return that directory as the project root.
 */
function findProjectRoot(startDir = dirname(fileURLToPath(import.meta.url))) {
  let dir = startDir;
  while (dir !== parse(dir).root) {
    if (existsSync(join(dir, 'package.json'))) {
      return dir;
    }
    dir = dirname(dir);
  }
  return process.cwd(); // fallback
}

const projectRoot = findProjectRoot();
const logFilePath = resolve(projectRoot, 'scan-compromised.log');

/**
 * Append a message to scan-compromised.log in the project root.
 * @param {string} message - The text to log.
 */
export function logToRoot(message) {
  const timestamp = new Date().toISOString();
  const entry = `[${timestamp}] ${message}\n`;
  appendFileSync(logFilePath, entry, { encoding: 'utf8' });
}
