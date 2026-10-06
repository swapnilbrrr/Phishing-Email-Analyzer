
import type { DragEvent, KeyboardEvent, ReactNode } from "react";
import { useMemo, useState } from "react";
import type { EmailAnalysis, Verdict } from "./types";

const SAMPLE_EMAIL = [
  'From: "PayPal Security" <security@paypa1-example.com>',
  "Reply-To: collect@evil.example",
  "Return-Path: bounce@mailer.evil.example",
  "Subject: URGENT: Verify your account immediately",
  "Authentication-Results: mx.example; spf=fail smtp.mailfrom=paypa1-example.com; dkim=fail header.d=paypa1-example.com; dmarc=fail",
  "Received: from mx.evil.example (198.51.100.23) by mx.example with ESMTP",
  "Message-ID: <abc@example>",
  "Date: Tue, 6 Oct 2026 10:00:00 +0000",
  "",
  "We detected unusual activity. Verify your password and sign in here:",
  "https://paypa1-example.com/login"
].join("\n");

type Tab = "overview" | "auth" | "delivery" | "urls" | "evidence";

const verdictCopy: Record<Verdict, { label: string; description: string }> = {
  low_risk: {
    label: "Low risk",
    description: "No strong phishing indicators were established."
  },
  suspicious: {
    label: "Suspicious",
    description: "Several anomalies need analyst validation."
  },
  malicious: {
    label: "Malicious",
    description: "Multiple independent indicators point to phishing."
  }
};

export default function App() {
  const [rawEmail, setRawEmail] = useState("");
  const [result, setResult] = useState<EmailAnalysis | null>(null);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("Ready for analysis.");
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<Tab>("overview");

  const topDetections = useMemo(
    () => result?.detections.slice(0, 3) ?? [],
    [result]
  );

  async function analyzeEmail() {
    const payload = rawEmail.trim();

    if (!payload) {
      setError("Paste an email or load an .eml file before analyzing.");
      return;
    }

    setBusy(true);
    setError("");
    setStatus("Parsing structure and extracting evidence…");

    try {
      const response = await fetch("/api/v1/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw_email: payload })
      });

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(body?.detail ?? body?.error ?? ("Analysis failed (" + response.status + ")."));
      }

      const data = (await response.json()) as EmailAnalysis;
      setResult(data);
      setActiveTab("overview");
      setStatus("Analysis complete.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Analysis failed.");
      setStatus("Analysis could not be completed.");
    } finally {
      setBusy(false);
    }
  }

  function handleKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
      event.preventDefault();
      void analyzeEmail();
    }
  }

  function loadSample() {
    setRawEmail(SAMPLE_EMAIL);
    setResult(null);
    setError("");
    setStatus("Sample loaded. Analyze it when ready.");
  }

  async function loadFile(file: File) {
    if (!file.name.toLowerCase().endsWith(".eml")) {
      setError("Please choose an .eml file.");
      return;
    }

    if (file.size > 300_000) {
      setError("That email is larger than the 300 KB analysis limit.");
      return;
    }

    setRawEmail(await file.text());
    setResult(null);
    setError("");
    setStatus("Loaded " + file.name + ". Analyze it when ready.");
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    const file = event.dataTransfer.files[0];
    if (file) void loadFile(file);
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <div className="mark" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
          <div>
            <div className="brand">Phishing Email Analyzer</div>
            <div className="brand-caption">analysis engine · v0.1</div>
          </div>
        </div>

        <div className="system-status">
          <span className="status-dot" aria-hidden="true" />
          Local-first
        </div>
      </header>

      <main className="workspace">
        <section className="hero">
          <p className="eyebrow">EMAIL THREAT ANALYSIS</p>
          <h1>Find the evidence behind the verdict.</h1>
          <p className="hero-copy">
            Paste raw email content or load an <code>.eml</code> file. The engine
            parses identity, authentication, delivery, URLs, and behavioral
            signals without visiting external links.
          </p>
        </section>

        <section className="input-panel" aria-labelledby="input-heading">
          <div className="section-heading">
            <div>
              <p className="section-kicker">01 · INPUT</p>
              <h2 id="input-heading">Email to analyze</h2>
            </div>
            <button className="ghost-button" type="button" onClick={loadSample}>
              Load sample
            </button>
          </div>

          <div
            className="dropzone"
            onDragOver={(event) => event.preventDefault()}
            onDrop={handleDrop}
          >
            <label className="dropzone-label" htmlFor="email-file">
              Drop <strong>.eml</strong> here
              <span>or choose a file</span>
            </label>
            <input
              id="email-file"
              type="file"
              accept=".eml,message/rfc822"
              onChange={(event) => {
                const file = event.target.files?.[0];
                if (file) void loadFile(file);
              }}
            />
          </div>

          <div className="or-divider">
            <span>or paste raw email</span>
          </div>

          <label className="sr-only" htmlFor="raw-email">
            Raw email content
          </label>
          <textarea
            id="raw-email"
            value={rawEmail}
            onChange={(event) => {
              setRawEmail(event.target.value);
              if (error) setError("");
            }}
            onKeyDown={handleKeyDown}
            placeholder={'From: sender@example.com\nSubject: Example message\nAuthentication-Results: ...\nReceived: from ...'}
            spellCheck={false}
          />

          <div className="input-footer">
            <div className="input-hint">
              <span>{rawEmail.length.toLocaleString()} chars</span>
              <span>Ctrl / Cmd + Enter</span>
            </div>
            <button
              className="primary-button"
              type="button"
              onClick={() => void analyzeEmail()}
              disabled={busy || !rawEmail.trim()}
            >
              {busy ? "Analyzing…" : "Analyze email"}
              {!busy && <span aria-hidden="true">→</span>}
            </button>
          </div>

          {error && (
            <div className="inline-error" role="alert">
              {error}
            </div>
          )}

          <div className="status-line" aria-live="polite">
            <span className={busy ? "status-dot pulse" : "status-dot"} />
            {status}
          </div>
        </section>

        {result && (
          <section className="results" aria-labelledby="findings-heading">
            <div className="result-header">
              <div>
                <p className="section-kicker">02 · FINDINGS</p>
                <h2 id="findings-heading">Investigation workspace</h2>
              </div>
              <div className={"verdict-pill verdict-" + result.risk.verdict}>
                {verdictCopy[result.risk.verdict].label}
              </div>
            </div>

            <div className="overview-grid">
              <div className={"risk-card risk-" + result.risk.verdict}>
                <div>
                  <span className="metric-label">Risk score</span>
                  <div className="risk-score">
                    {result.risk.score}
                    <span>/100</span>
                  </div>
                  <p>{verdictCopy[result.risk.verdict].description}</p>
                </div>
                <div className="confidence">
                  <span>confidence</span>
                  <strong>{Math.round(result.risk.confidence * 100)}%</strong>
                </div>
              </div>

              <div className="identity-card">
                <span className="metric-label">Sender identity</span>
                <strong>{result.sender.address ?? "Not found"}</strong>
                <span>{result.metadata.subject ?? "No subject"}</span>
                <div className="identity-row">
                  <span>Reply-To</span>
                  <b>{result.reply_to.address ?? "Not present"}</b>
                </div>
              </div>

              <div className="top-findings-card">
                <div className="card-header-row">
                  <span className="metric-label">Why it matters</span>
                  <span>{result.detections.length} signals</span>
                </div>
                <p>{result.risk.rationale}</p>
                {topDetections.map((item) => (
                  <div className="mini-finding" key={item.id}>
                    <span className={"mini-severity mini-" + item.severity} />
                    <span>{item.name}</span>
                  </div>
                ))}
              </div>
            </div>

            <nav className="tabbar" aria-label="Analysis sections">
              {(
                [
                  ["overview", "Overview"],
                  ["auth", "Authentication"],
                  ["delivery", "Delivery path"],
                  ["urls", "URLs (" + result.urls.length + ")"],
                  ["evidence", "Evidence (" + result.detections.length + ")"]
                ] as [Tab, string][]
              ).map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  className={activeTab === id ? "tab active" : "tab"}
                  onClick={() => setActiveTab(id)}
                  aria-current={activeTab === id ? "page" : undefined}
                >
                  {label}
                </button>
              ))}
            </nav>

            <div className="tab-panel">
              {activeTab === "overview" && (
                <div className="detail-grid">
                  <Detail title="Authentication">
                    <AuthRow label="SPF" result={result.authentication.spf.result} />
                    <AuthRow label="DKIM" result={result.authentication.dkim.result} />
                    <AuthRow label="DMARC" result={result.authentication.dmarc.result} />
                  </Detail>

                  <Detail title="Infrastructure">
                    <DataRow label="Earliest public IP" value={result.delivery.earliest_public_ip ?? "Not detected"} />
                    <DataRow label="Received hops" value={String(result.delivery.hop_count)} />
                    <DataRow label="Domains" value={String(result.domains.length)} />
                    <DataRow label="URLs" value={String(result.urls.length)} />
                  </Detail>

                  <Detail title="Identity checks" wide>
                    <DataRow label="From" value={result.sender.address ?? "Not found"} />
                    <DataRow label="Reply-To" value={result.reply_to.address ?? "Not present"} />
                    <DataRow label="Return-Path" value={result.return_path.address ?? "Not present"} />
                  </Detail>
                </div>
              )}

              {activeTab === "auth" && (
                <Detail title="Authentication evidence">
                  <AuthEvidence label="SPF" signal={result.authentication.spf} />
                  <AuthEvidence label="DKIM" signal={result.authentication.dkim} />
                  <AuthEvidence label="DMARC" signal={result.authentication.dmarc} />
                </Detail>
              )}

              {activeTab === "delivery" && (
                <div className="timeline">
                  {result.delivery.received.length ? (
                    result.delivery.received.map((hop) => (
                      <div className="timeline-item" key={hop.index}>
                        <div className="timeline-index">{hop.index}</div>
                        <div>
                          <strong>{hop.from_host ?? "Unknown source"}</strong>
                          <span>→ {hop.by_host ?? "Unknown receiver"}</span>
                          <small>{hop.public_ips.join(", ") || "No public IP on this hop"}</small>
                        </div>
                      </div>
                    ))
                  ) : (
                    <EmptyState text="No Received headers were parsed." />
                  )}
                </div>
              )}

              {activeTab === "urls" && (
                <div className="url-list">
                  {result.urls.length ? (
                    result.urls.map((item, index) => (
                      <div className="url-item" key={item.url + index}>
                        <div className="url-main">
                          <code>{item.url}</code>
                          <span>{item.hostname ?? "Unknown host"}</span>
                        </div>
                        <div className="url-flags">
                          {item.has_ip_host && <Flag text="IP host" tone="bad" />}
                          {item.is_punycode && <Flag text="Punycode" tone="warn" />}
                          {item.has_userinfo && <Flag text="Userinfo" tone="bad" />}
                          {item.is_shortener && <Flag text="Shortener" tone="warn" />}
                          {item.suspicious_path && <Flag text="Credential path" tone="warn" />}
                          {!item.has_ip_host &&
                            !item.is_punycode &&
                            !item.has_userinfo &&
                            !item.is_shortener &&
                            !item.suspicious_path && <Flag text="No URL pattern flag" tone="good" />}
                        </div>
                      </div>
                    ))
                  ) : (
                    <EmptyState text="No URLs were extracted." />
                  )}
                </div>
              )}

              {activeTab === "evidence" && (
                <div className="evidence-list">
                  {result.detections.length ? (
                    result.detections.map((item) => (
                      <article className="finding" key={item.id}>
                        <div className="finding-top">
                          <span className={"severity severity-" + item.severity}>
                            {item.severity}
                          </span>
                          <span className="finding-score">+{item.score}</span>
                        </div>
                        <h3>{item.name}</h3>
                        <p className="finding-meta">
                          {item.id} · {Math.round(item.confidence * 100)}% confidence
                        </p>
                        <ul>
                          {item.evidence.map((evidence, evidenceIndex) => (
                            <li key={item.id + "-" + evidenceIndex}>{evidence}</li>
                          ))}
                        </ul>
                      </article>
                    ))
                  ) : (
                    <EmptyState text="No detections were generated." />
                  )}
                </div>
              )}
            </div>
          </section>
        )}

        <footer className="footer">
          <span>Offline analysis by default · external URLs are never fetched</span>
          <span>Phishing Email Analyzer</span>
        </footer>
      </main>
    </div>
  );
}

function Detail({
  title,
  children,
  wide = false
}: {
  title: string;
  children: ReactNode;
  wide?: boolean;
}) {
  return (
    <section className={wide ? "detail-card wide" : "detail-card"}>
      <div className="card-title">{title}</div>
      <div className="detail-content">{children}</div>
    </section>
  );
}

function DataRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="data-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function AuthRow({ label, result }: { label: string; result: string }) {
  return (
    <div className="data-row">
      <span>{label}</span>
      <span className={"auth-state auth-" + result}>{result}</span>
    </div>
  );
}

function AuthEvidence({
  label,
  signal
}: {
  label: string;
  signal: EmailAnalysis["authentication"]["spf"];
}) {
  return (
    <div className="evidence-row">
      <div>
        <strong>{label}</strong>
        <span>{signal.domain ? "Identity: " + signal.domain : "No identity domain parsed"}</span>
      </div>
      <div className="auth-cluster">
        <span className={"auth-state auth-" + signal.result}>{signal.result}</span>
        {signal.aligned !== null && (
          <span className={signal.aligned ? "align-good" : "align-bad"}>
            {signal.aligned ? "aligned" : "not aligned"}
          </span>
        )}
      </div>
    </div>
  );
}

function Flag({
  text,
  tone
}: {
  text: string;
  tone: "good" | "warn" | "bad";
}) {
  return <span className={"flag flag-" + tone}>{text}</span>;
}

function EmptyState({ text }: { text: string }) {
  return <div className="empty-state">{text}</div>;
}
