# PhishScan - Email Threat Analyzer

A clean, local-first phishing email header analyzer with server-side AbuseIPDB reputation checks.

## Highlights

- Real-time parsing of raw email headers
- SPF, DKIM, and DMARC signal scoring
- Typosquat and display-name spoof checks
- URL extraction with VirusTotal quick links
- AbuseIPDB checks through a backend proxy (key never exposed to browser)

## Security Model

Your AbuseIPDB key is **not stored in frontend code**.  
It is loaded by `server.js` from a local config file and used only on the backend endpoint:

- `GET /api/abuseipdb?ip=<IPv4>`

This keeps the key hidden from public client-side source.

## Project Structure

- `public/index.html` - analyzer UI
- `public/styles.css` - UI styles
- `public/app.js` - frontend logic and scoring engine
- `server.js` - local HTTP server and AbuseIPDB proxy
- `config.example.js` - sample local secret config
- `config.local.js` - local secret file (gitignored)
- `.gitignore` - excludes secrets and local artifacts

## Quick Start

### 1) Prerequisites

- Node.js 18+

### 2) Install

```bash
npm install
```

### 3) Configure your AbuseIPDB key (local or hosting)

#### Option A (recommended, hosting-friendly): environment variable

Set `ABUSEIPDB_API_KEY` in your hosting provider’s environment variables.

For local PowerShell (current session):

```powershell
$env:ABUSEIPDB_API_KEY="YOUR_KEY_HERE"
npm start
```

#### Option B (local dev fallback): `config.local.js`

Copy `config.example.js` to `config.local.js` and set:

```js
module.exports = {
  ABUSEIPDB_API_KEY: "YOUR_KEY_HERE",
};
```

### 4) Run

```bash
npm start
```

Open: [http://localhost:3000](http://localhost:3000)

## GitHub Ready Checklist

- [x] Single app page (`public/index.html`)
- [x] Frontend key input removed
- [x] Backend-only AbuseIPDB key usage
- [x] `config.local.js` ignored by Git
- [x] Clear setup and run instructions

## Important Notes

- Never commit `config.local.js`.
- Never commit `.env` files.
- Rotate your AbuseIPDB key immediately if it was ever leaked.
- This project is designed to run locally unless you add production hardening and deployment config.
