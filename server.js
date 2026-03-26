const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const PORT = 3000;
const CONFIG_PATH = path.join(__dirname, 'config.local.js');
const API_KEY = loadApiKey();
const PUBLIC_DIR = path.join(__dirname, 'public');
const INDEX_FILE = path.join(PUBLIC_DIR, 'index.html');

function loadApiKey() {
  // Preferred for hosting/CI: environment variable
  if (typeof process.env.ABUSEIPDB_API_KEY === 'string' && process.env.ABUSEIPDB_API_KEY.trim()) {
    return process.env.ABUSEIPDB_API_KEY.trim();
  }

  try {
    // config.local.js should be gitignored and created locally.
    const cfg = require(CONFIG_PATH);
    if (!cfg || typeof cfg.ABUSEIPDB_API_KEY !== 'string' || !cfg.ABUSEIPDB_API_KEY.trim()) {
      throw new Error('ABUSEIPDB_API_KEY missing in config.local.js');
    }
    return cfg.ABUSEIPDB_API_KEY.trim();
  } catch (err) {
    throw new Error(
      'Missing AbuseIPDB API key.\n' +
        '- For hosting: set environment variable ABUSEIPDB_API_KEY\n' +
        '- For local dev: create config.local.js (see config.example.js)\n' +
        `Details: ${err.message}`
    );
  }
}

function sendJson(res, statusCode, body) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(body));
}

function sendText(res, statusCode, body) {
  res.writeHead(statusCode, {
    'Content-Type': 'text/plain; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function isValidIPv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return false;
    const n = Number(part);
    if (n < 0 || n > 255) return false;
  }
  return true;
}

function checkAbuseIPDB(ip) {
  return new Promise((resolve, reject) => {
    const abuseUrl = new URL('https://api.abuseipdb.com/api/v2/check');
    abuseUrl.searchParams.set('ipAddress', ip);
    abuseUrl.searchParams.set('maxAgeInDays', '90');

    const req = https.get(
      abuseUrl,
      {
        headers: {
          Key: API_KEY,
          Accept: 'application/json',
        },
      },
      (apiRes) => {
        let raw = '';
        apiRes.on('data', (chunk) => {
          raw += chunk;
        });
        apiRes.on('end', () => {
          if (apiRes.statusCode < 200 || apiRes.statusCode >= 300) {
            return reject(new Error(`AbuseIPDB HTTP ${apiRes.statusCode}`));
          }
          try {
            const parsed = JSON.parse(raw);
            resolve(parsed && parsed.data ? parsed.data : null);
          } catch (err) {
            reject(new Error('Invalid JSON from AbuseIPDB'));
          }
        });
      }
    );

    req.on('error', (err) => reject(err));
    req.setTimeout(10000, () => {
      req.destroy(new Error('AbuseIPDB request timed out'));
    });
  });
}

const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url, `http://${req.headers.host}`);

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return sendText(res, 405, 'Method Not Allowed');
  }

  if (reqUrl.pathname === '/api/abuseipdb') {
    const ip = (reqUrl.searchParams.get('ip') || '').trim();
    if (!ip) {
      return sendJson(res, 400, { error: 'Missing "ip" query parameter' });
    }
    if (!isValidIPv4(ip)) {
      return sendJson(res, 400, { error: 'Invalid IPv4 address' });
    }

    try {
      const data = await checkAbuseIPDB(ip);
      return sendJson(res, 200, data || { error: 'No data returned' });
    } catch (err) {
      return sendJson(res, 502, { error: err.message || 'Proxy request failed' });
    }
  }

  if (reqUrl.pathname === '/' || reqUrl.pathname === '/index.html') {
    fs.readFile(INDEX_FILE, 'utf8', (err, data) => {
      if (err) {
        return sendText(res, 500, 'Failed to read index file');
      }
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'X-Content-Type-Options': 'nosniff',
      });
      return res.end(data);
    });
    return;
  }

  // Serve static frontend assets from /public
  const safePath = path.normalize(reqUrl.pathname).replace(/^(\.\.[\/\\])+/, '');
  const assetPath = path.join(PUBLIC_DIR, safePath);
  if (assetPath.startsWith(PUBLIC_DIR) && fs.existsSync(assetPath) && fs.statSync(assetPath).isFile()) {
    const ext = path.extname(assetPath).toLowerCase();
    const contentType =
      ext === '.css'
        ? 'text/css; charset=utf-8'
        : ext === '.js'
        ? 'application/javascript; charset=utf-8'
        : ext === '.html'
        ? 'text/html; charset=utf-8'
        : 'application/octet-stream';

    fs.readFile(assetPath, (err, data) => {
      if (err) {
        return sendText(res, 500, 'Failed to read asset');
      }
      res.writeHead(200, {
        'Content-Type': contentType,
        'X-Content-Type-Options': 'nosniff',
      });
      return res.end(data);
    });
    return;
  }

  return sendText(res, 404, 'Not Found');
});

server.listen(PORT, () => {
  console.log(`PhishScan server running at http://localhost:${PORT}`);
});
