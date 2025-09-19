import https from 'https';

export function printProgress(message, newLine = false) {
  process.stdout.write(`\r${message}`);
  if (newLine) process.stdout.write('\n');
}

export function httpsRequest(url, options, body) {
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

// --- Throttling ---
export function throttle(items, limit, fn) {
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
export function formatTime(seconds) {
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return `${mins}m ${secs}s`;
}

export function drawProgressBar(completed, total, eta) {
  const percent = Math.floor((completed / total) * 100);
  const filled = Math.floor((percent / 100) * progressBarLength);
  const bar = '█'.repeat(filled) + '░'.repeat(progressBarLength - filled);
  return `processing ${completed} of ${total} packages ${bar} ${percent}% — ETA: ${eta}`;
}