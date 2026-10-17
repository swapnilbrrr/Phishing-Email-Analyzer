
# Phishing Email Analyzer

An explainable, local-first email threat analysis system.

The v2 rebuild separates the **analysis engine** from the interface. The engine is the source of truth; the UI is a consumer of structured findings.

## What changed in v2

- Python analysis engine with Pydantic data models
- RFC-aware parsing through Python's standard email parser
- Authentication, identity, delivery, content, URL, and correlation signals
- Explainable detections with severity, confidence, score, and evidence
- Risk score that is explicitly **not** presented as phishing probability
- React + TypeScript investigation workspace
- Safe rendering of untrusted email-derived text
- No automatic URL fetching
- Input size guard and baseline browser security headers
- Test fixtures for phishing and benign cases
- GitHub Actions CI for backend tests and frontend build

## Architecture

    Raw email
       |
       v
    Email parser
       |
       +--> identity
       +--> authentication
       +--> delivery path
       +--> body/content signals
       +--> URLs / domains / IPs
       |
       v
    Detection engine
       |
       v
    Evidence correlation
       |
       v
    Risk + confidence + verdict
       |
       v
    FastAPI
       |
       v
    React investigation UI

External enrichment providers such as AbuseIPDB, VirusTotal, RDAP, and DNS are deliberately kept out of the first core milestone so the detection logic can be tested independently.

## UX direction

The interface is designed around the user's main task instead of mirroring the internal architecture:

- one dominant task: analyze an email
- visible feedback while the system parses and analyzes
- clear paste and .eml file affordances
- progressive disclosure through result tabs
- findings explain what was observed, why it matters, and confidence
- recognition over recall: familiar email concepts, plain labels, minimal decoration
- error prevention: file type and size checks before submission
- keyboard access and visible focus states
- severity color is supplementary, not the only signal

## Local development

### Backend

Requires Python 3.10+.

    python -m venv .venv
    .venv\Scripts\Activate.ps1
    pip install -r backend/requirements.txt
    .\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload --port 8000

Authentication-Results headers are attacker-controlled when an analyst pastes or uploads a raw email. The analyzer displays parsed SPF/DKIM/DMARC values as reported for context, but never treats an `authserv-id` match as proof of provenance and never uses these header claims in risk scoring. A future trusted-ingestion integration would need to establish provenance outside the submitted message (for example, from a controlled mail gateway or verified message trace) before authentication results could affect scoring.

API endpoints:

- GET /health
- POST /api/v1/analyze
- GET /docs for local OpenAPI exploration

### Frontend

Requires a Node.js release supported by the current Vite toolchain.

    cd frontend
    npm install
    npm run dev

Open http://localhost:5173.

The Vite development server proxies /api and /health to the FastAPI backend.

## Tests

From the repository root:

    python -m pytest backend/tests

## Security posture

Email is attacker-controlled input. Treat every parsed value as untrusted.

The current rebuild therefore:

- never injects raw email content with HTML rendering
- does not visit URLs during analysis
- caps analysis input at 300 KB in the application model
- rejects oversized requests before normal processing when Content-Length is available
- sets baseline security headers
- keeps enrichment/network access outside the core engine

Future hardening includes stronger request limiting, attachment/MIME abuse controls, SSRF-safe enrichment workers, dependency auditing, secret scanning, and container isolation.

## Roadmap

1. Core parser and analysis model
2. Detection coverage and evaluation corpus
3. External enrichment providers
4. Deeper header and delivery reasoning
5. Attachment analysis with strict isolation
6. Analyst report and JSON export
7. CI security gates and deployment
8. Rename/rebrand only after the engine earns its final identity


## MIME and HTML link analysis

The parser identifies MIME attachments by filename or content disposition and reports their metadata without executing or analyzing attachment payloads as ordinary message-body text. MIME traversal is bounded by a maximum part count and nesting depth. Excessive MIME structures return a controlled validation error.

For HTML email bodies, the analyzer extracts anchor text and hyperlink destinations separately. When visible link text itself contains an HTTP(S) URL, the analyzer compares its registrable organization with the hyperlink destination and raises `URL-008` when they differ. This is a heuristic signal, not proof of malicious intent. Relative links, non-URL anchor text, obfuscated rendering, CSS-generated content, and browser-specific behavior are not fully interpreted.

The engine does not fetch destinations, resolve DNS, open attachments, or execute attachment content. The MIME limits bound application-level traversal and extraction; they do not replace process-level resource limits for hostile parser inputs.
