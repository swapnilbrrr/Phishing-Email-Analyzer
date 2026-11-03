# Veritas — Phishing Email Analyzer

**Veritas** is an explainable, local-first email threat analysis project. It parses raw email messages and presents structured findings so an analyst can inspect the evidence behind a risk assessment rather than relying on a black-box verdict.

The project separates the analysis engine from the investigation interface:

- **Backend:** Python, FastAPI, Pydantic
- **Frontend:** React, TypeScript, Vite
- **Testing:** pytest, a synthetic detection-evaluation corpus, and a frontend production build in GitHub Actions

> **Project status:** The core analyzer is implemented. Navigation/theme, sender-identity clarification, and two-message comparison are being developed in a stacked pull-request sequence (#8, #11, and #12). These feature branches are not yet merged into `main`. Browser-level integration testing remains outstanding.

## What it does

### Core email analysis

- Accepts raw email content and `.eml` files.
- Parses message structure using Python's standard email parsing facilities.
- Extracts sender and reply information, message metadata, authentication claims, delivery-path information, URLs, domains, IP addresses, and MIME attachment metadata.
- Produces explainable detections with severity, confidence, score, and supporting evidence.
- Calculates a heuristic risk score and verdict. The score is **not a probability that an email is phishing**.
- Presents results in an analyst-oriented React interface.

### Identity and authentication context

The current feature stack distinguishes:

| Field | Meaning | Important limitation |
|---|---|---|
| From | Visible message author (P2) | A displayed header value is not proof of authenticated identity. |
| SMTP MAIL FROM claim | A value parsed from a submitted Authentication-Results header (P1 claim) | Untrusted message content; not independently verified envelope provenance. |
| Return-Path | Recorded message header | Not proof of the original SMTP transaction. |
| Reply-To | Suggested reply destination | May differ from the visible From address. |

SPF, DKIM, DMARC, and SMTP MAIL FROM values parsed from user-submitted Authentication-Results headers are displayed as reported context. A raw message cannot prove that the header was added by a trusted receiver. These claims are not used as trusted evidence for risk scoring or detection decisions.

### MIME and HTML link analysis

- Identifies MIME attachments by filename or content disposition and reports metadata.
- Bounds MIME traversal by a maximum part count and nesting depth.
- Extracts HTML anchor text and hyperlink destinations separately.
- Flags a heuristic mismatch when visible anchor text itself contains an HTTP(S) URL whose registrable organization differs from the hyperlink destination.

Attachment payloads are not executed or treated as ordinary message-body text. HTML rendering behavior, CSS-generated content, relative links, and browser-specific interpretation are not fully modeled.

### Two-message comparison (feature branch)

The Stage 3 branch adds a comparison workflow that independently submits two messages to the existing analysis endpoint and compares:

- Risk scores and verdicts
- Visible sender and Return-Path values
- URL and attachment counts
- Detection IDs shared by both analyses and unique to either message

Shared detection IDs do **not** establish common campaign membership, common authorship, or that either message is safe or malicious. The comparison is intended to help an analyst prioritize further inspection.

## Architecture

```text
Raw email / .eml
       |
       v
Input validation
       |
       v
Email structure and MIME parser
       |
       +--> Message identity
       +--> Authentication claims
       +--> Received / delivery headers
       +--> Body and HTML links
       +--> URLs, domains, and IPs
       +--> Attachment metadata
       |
       v
Detection engine
       |
       v
Evidence correlation
       |
       v
Risk score + confidence + verdict
       |
       v
FastAPI JSON API
       |
       v
React / TypeScript investigation UI
```

The analysis engine is the source of truth. The frontend consumes structured API responses and presents findings; it does not independently decide whether a message is malicious.

## Security model and limitations

Email is attacker-controlled input. Parsed headers, body content, URLs, and attachment metadata must be treated as untrusted.

Current safety boundaries:

- **No URL fetching:** analysis does not visit extracted destinations.
- **No DNS enrichment:** domains and IPs are not resolved as part of core analysis.
- **No attachment execution:** attachment content is not executed.
- **Authentication trust boundary:** Authentication-Results values supplied inside the raw message are untrusted claims and do not influence risk scoring.
- **Input limit:** the application model limits a message to 300 KB; the API also checks the request Content-Length when provided.
- **MIME traversal limits:** part count and nesting depth are bounded.
- **Safe UI rendering:** email-derived text is displayed as data rather than injected as HTML.
- **Baseline response headers:** the API sets headers including `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control`, and a baseline Content Security Policy.

These controls reduce risk but do not make hostile parser input harmless. MIME traversal limits are not a substitute for process-level CPU and memory limits. The current project does not claim comprehensive malware analysis, attachment sandboxing, trusted mail-gateway ingestion, or production-grade multi-user deployment.

## Tech stack

| Area | Technology |
|---|---|
| API | FastAPI |
| Data models | Pydantic |
| Email parsing | Python standard library |
| Backend tests | pytest |
| Frontend | React + TypeScript |
| Build tooling | Vite |
| CI | GitHub Actions |
| Evaluation | Synthetic detection corpus |

## Local development

### Requirements

- Python 3.10 or newer
- Node.js 22 (the CI build currently uses Node.js 22)
- npm

### 1. Clone the repository

```bash
git clone https://github.com/swapnilbrrr/Phishing-Email-Analyzer.git
cd Phishing-Email-Analyzer
```

### 2. Set up the backend

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend/requirements.txt
python -m uvicorn backend.app.main:app --reload --port 8000
```

If PowerShell blocks activation scripts, you can run the virtual environment's interpreter directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload --port 8000
```

The API is available at:

- Health check: http://127.0.0.1:8000/health
- OpenAPI documentation: http://127.0.0.1:8000/docs
- Analysis endpoint: `POST /api/v1/analyze`

### 3. Set up the frontend

In a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:5173.

The Vite development server proxies `/api` and `/health` requests to the local FastAPI backend. Start the backend before using the analysis workflow.

## Tests and evaluation

Run backend tests from the repository root:

```bash
python -m pytest backend/tests
```

Run the synthetic detection-evaluation corpus:

```bash
python -m scripts.evaluate_corpus
```

Build the frontend:

```bash
cd frontend
npm install
npm run build
```

GitHub Actions runs the backend test suite, synthetic corpus evaluation, and frontend production build for pushes and pull requests. A green CI run confirms those automated checks passed; it does not by itself confirm browser behavior, usability, or detection quality against real-world mail.

The evaluation corpus is synthetic and should be treated as a regression baseline, not a representative measure of real-world phishing detection performance.

## Current development sequence

The active feature work is organized as stacked pull requests:

1. **Stage 1 — Navigation and theme:** [PR #8](https://github.com/swapnilbrrr/Phishing-Email-Analyzer/pull/8)
2. **Stage 2 — Sender identity and SMTP provenance:** [PR #11](https://github.com/swapnilbrrr/Phishing-Email-Analyzer/pull/11), based on Stage 1
3. **Stage 3 — Two-email comparison:** [PR #12](https://github.com/swapnilbrrr/Phishing-Email-Analyzer/pull/12), based on Stage 2

The older unstacked PRs #9 and #10 are backups and are not the active feature sequence.

## Roadmap

- [x] Local-first analysis API and structured findings
- [x] Synthetic evaluation corpus and automated CI
- [x] MIME attachment metadata and HTML link mismatch analysis
- [x] Authentication-Results trust boundary
- [ ] Complete and verify the navigation/theme experience
- [ ] Complete and verify sender identity presentation
- [ ] Complete and verify two-message comparison
- [ ] Add frontend behavior tests and broader parser edge-case tests
- [ ] Perform local end-to-end and responsive browser testing
- [ ] Add security-focused CI checks and dependency maintenance
- [ ] Evaluate future enrichment options behind explicit, isolated safety boundaries
- [ ] Consider analyst-friendly report/export capabilities

## Design principles

- Explain evidence instead of presenting an unexplained verdict.
- Keep untrusted message claims separate from verified facts.
- Prefer deterministic local analysis before optional external enrichment.
- Make limitations visible instead of implying capabilities the tool does not have.
- Keep the interface focused on analyst tasks and readable findings.
- Treat tests and evaluation as ongoing engineering work, not a one-time checkbox.

---

**Veritas is a learning and engineering project.** Findings are heuristic and should support, not replace, analyst judgment and independent validation.
