
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

async function requestAnalysis(rawEmail: string): Promise<EmailAnalysis> {
  const response = await fetch("/api/v1/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ raw_email: rawEmail })
  });

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.detail ?? body?.error ?? ("Analysis failed (" + response.status + ")."));
  }

  return (await response.json()) as EmailAnalysis;
}

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
  const [compareMode, setCompareMode] = useState(false);
  const [comparisonEmail, setComparisonEmail] = useState("");
  const [comparison, setComparison] = useState<{ left: EmailAnalysis; right: EmailAnalysis } | null>(null);
  const [compareBusy, setCompareBusy] = useState(false);
  const [compareError, setCompareError] = useState("");

  const topDetections = useMemo(
    () => result?.detections.slice(0, 3) ?? [],
    [result]
  );

  const comparisonSummary = useMemo(() => {
    if (!comparison) return null;
    const leftIds = new Set(comparison.left.detections.map((item) => item.id));
    const rightIds = new Set(comparison.right.detections.map((item) => item.id));
    return {
      shared: comparison.left.detections.filter((item) => rightIds.has(item.id)),
      leftOnly: comparison.left.detections.filter((item) => !rightIds.has(item.id)),
      rightOnly: comparison.right.detections.filter((item) => !leftIds.has(item.id)),
      scoreDelta: comparison.right.risk.score - comparison.left.risk.score
    };
  }, [comparison]);

  async function analyzeEmail() {
    const payload = rawEmail.trim();

    if (!payload) {
      setError("Paste an email or load an .eml file before analyzing.");
      return;
    }

    if (new Blob([payload]).size > 300_000) {
      setError("Email content exceeds the 300 KB analysis limit.");
      return;
    }

    setBusy(true);
    setResult(null);
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

  async function compareEmails() {
    const left = rawEmail.trim();
    const right = comparisonEmail.trim();

    if (!left || !right) {
      setCompareError("Provide both email messages before comparing.");
      return;
    }
    if (new Blob([left]).size > 300_000 || new Blob([right]).size > 300_000) {
      setCompareError("Each email must be 300 KB or smaller.");
      return;
    }

    setCompareBusy(true);
    setComparison(null);
    setCompareError("");
    setStatus("Analyzing both emails independently…");
    try {
      const [leftResult, rightResult] = await Promise.all([
        requestAnalysis(left),
        requestAnalysis(right)
      ]);
      setComparison({ left: leftResult, right: rightResult });
      setStatus("Comparison complete.");
    } catch (cause) {
      setCompareError(cause instanceof Error ? cause.message : "Comparison could not be completed.");
      setStatus("Comparison could not be completed.");
    } finally {
      setCompareBusy(false);
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
    setComparison(null);
    setError("");
    setCompareError("");
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
    setComparison(null);
    setError("");
    setCompareError("");
    setStatus("Loaded " + file.name + ". Analyze it when ready.");
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    if (busy) return;
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

        <div className="mode-switch" role="group" aria-label="Analysis mode">
          <button type="button" className={!compareMode ? "mode-button active" : "mode-button"} onClick={() => setCompareMode(false)}>Single analysis</button>
          <button type="button" className={compareMode ? "mode-button active" : "mode-button"} onClick={() => setCompareMode(true)}>Compare two emails</button>
        </div>

        {compareMode && (
          <section className="compare-panel" aria-labelledby="compare-heading">
            <div className="section-heading">
              <div>
                <p className="section-kicker">01 · COMPARISON INPUT</p>
                <h2 id="compare-heading">Compare two messages</h2>
              </div>
              <button className="ghost-button" type="button" onClick={loadSample} disabled={compareBusy}>Load sample into A</button>
            </div>
            <p className="compare-intro">Both messages are sent through the same local analysis endpoint independently. Comparison highlights differences; it does not establish that either message is safe or malicious by itself.</p>
            <div className="compare-input-grid">
              <label className="compare-input">
                <span>Email A <small>Baseline</small></span>
                <textarea value={rawEmail} disabled={compareBusy} onChange={(event) => { setRawEmail(event.target.value); setComparison(null); setCompareError(""); }} placeholder="Paste the first raw email here…" spellCheck={false} />
                <small>{rawEmail.length.toLocaleString()} characters</small>
              </label>
              <label className="compare-input">
                <span>Email B <small>Message to compare</small></span>
                <textarea value={comparisonEmail} disabled={compareBusy} onChange={(event) => { setComparisonEmail(event.target.value); setComparison(null); setCompareError(""); }} placeholder="Paste the second raw email here…" spellCheck={false} />
                <small>{comparisonEmail.length.toLocaleString()} characters</small>
              </label>
            </div>
            <div className="compare-actions">
              <button className="ghost-button" type="button" onClick={() => { setComparisonEmail(rawEmail); setComparison(null); setCompareError(""); }} disabled={compareBusy || !rawEmail.trim()}>Copy A to B</button>
              <button className="primary-button" type="button" onClick={() => void compareEmails()} disabled={compareBusy || !rawEmail.trim() || !comparisonEmail.trim()}>{compareBusy ? "Comparing…" : "Compare emails"} {!compareBusy && <span aria-hidden="true">→</span>}</button>
            </div>
            {compareError && <div className="inline-error" role="alert">{compareError}</div>}
            <div className="status-line" aria-live="polite"><span className={compareBusy ? "status-dot pulse" : "status-dot"} />{compareBusy ? "Analyzing both messages…" : comparison ? "Comparison ready." : "Ready to compare."}</div>
          </section>
        )}

        {!compareMode && <section className="input-panel" aria-labelledby="input-heading">
          <div className="section-heading">
            <div>
              <p className="section-kicker">01 · INPUT</p>
              <h2 id="input-heading">Email to analyze</h2>
            </div>
            <button className="ghost-button" type="button" onClick={loadSample} disabled={busy}>
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
              disabled={busy}
              onChange={(event) => {
                const file = event.target.files?.[0];
                event.currentTarget.value = "";
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
            disabled={busy}
            onChange={(event) => {
              setRawEmail(event.target.value);
              if (result) setResult(null);
              if (error) setError("");
              setStatus("Input changed. Analyze again to refresh findings.");
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
        </section>}

        {!compareMode && result && (
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
                <span className="metric-label">Visible sender · P2</span>
                <strong>{result.sender.address ?? "Not found"}</strong>
                <span>{result.metadata.subject ?? "No subject"}</span>
                <div className="identity-row">
                  <span>Reply-To</span>
                  <b>{result.reply_to.address ?? "Not present"}</b>
                </div>
                <div className="identity-row">
                  <span>Return-Path</span>
                  <b>{result.return_path.address ?? "Not present"}</b>
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
                    <p className="auth-trust-note">{result.authentication.trust_note}</p>
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

                  <Detail title="Sender identity · P1 vs P2" wide>
                    <p className="identity-trust-note">
                      From (P2) is the address shown to the recipient. SMTP MAIL FROM (P1) is the envelope sender used during transport, but this raw message only exposes unverified claims from Authentication-Results. Return-Path is a recorded message header and is not proof of the original SMTP transaction.
                    </p>
                    <DataRow label="From · visible sender (P2)" value={result.sender.address ?? "Not found"} />
                    <DataRow label="Reported SMTP MAIL FROM · unverified (P1 claim)" value={result.authentication.smtp_mail_from_claims.length ? result.authentication.smtp_mail_from_claims.join(", ") : "Not reported in Authentication-Results"} />
                    <DataRow label="Return-Path · recorded header" value={result.return_path.address ?? "Not present"} />
                    <DataRow label="Reply-To · reply destination" value={result.reply_to.address ?? "Not present"} />
                  </Detail>

                  <Detail title="Attachments" wide>
                    {result.metadata.attachments.length ? (
                      result.metadata.attachments.map((attachment, index) => (
                        <div className="evidence-row" key={(attachment.filename ?? "attachment") + index}>
                          <div>
                            <strong>{attachment.filename ?? "Unnamed attachment"}</strong>
                            <span>{attachment.content_type} · {attachment.disposition ?? "disposition unspecified"}</span>
                          </div>
                          <span>{attachment.size_bytes == null ? "Size unavailable" : attachment.size_bytes.toLocaleString() + " bytes"}</span>
                        </div>
                      ))
                    ) : (
                      <EmptyState text="No MIME attachments were identified. This does not mean the message has no risk." />
                    )}
                  </Detail>
                </div>
              )}

              {activeTab === "auth" && (
                <Detail title="Authentication evidence">
                  <p className="auth-trust-note">{result.authentication.trust_note}</p>
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
                <>
                  {result.html_links.length > 0 && (
                    <section className="url-list" aria-label="HTML hyperlink destinations">
                      <h3>HTML hyperlink destinations</h3>
                      {result.html_links.map((link, index) => (
                        <div className="url-item" key={link.href + index}>
                          <div className="url-main">
                            <strong>{link.text || "(no visible link text)"}</strong>
                            <code>{link.href}</code>
                            <span>{link.href_hostname ?? "Hostname not parsed"}</span>
                          </div>
                          <div className="url-flags">
                            {link.destination_mismatch ? (
                              <Flag text="Displayed URL mismatch" tone="bad" />
                            ) : link.displayed_hostname ? (
                              <Flag text="Displayed URL organization matches" tone="good" />
                            ) : (
                              <span className="flag">Link text is not a URL</span>
                            )}
                          </div>
                        </div>
                      ))}
                    </section>
                  )}
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
                </>
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

        {compareMode && comparison && comparisonSummary && (
          <section className="compare-results" aria-labelledby="comparison-results-heading">
            <div className="result-header">
              <div>
                <p className="section-kicker">02 · COMPARISON RESULTS</p>
                <h2 id="comparison-results-heading">What changed?</h2>
              </div>
              <span className="compare-delta">{comparisonSummary.scoreDelta === 0 ? "Same risk score" : comparisonSummary.scoreDelta > 0 ? "Email B scores " + comparisonSummary.scoreDelta + " points higher" : "Email B scores " + Math.abs(comparisonSummary.scoreDelta) + " points lower"}</span>
            </div>

            <div className="compare-score-grid">
              <article className={"compare-score-card risk-" + comparison.left.risk.verdict}>
                <span className="metric-label">Email A · baseline</span>
                <div className="compare-score-number">{comparison.left.risk.score}<small>/100</small></div>
                <span className={"verdict-pill verdict-" + comparison.left.risk.verdict}>{verdictCopy[comparison.left.risk.verdict].label}</span>
                <p>{comparison.left.metadata.subject ?? "No subject"}</p>
                <small>{comparison.left.sender.address ?? "Visible sender not found"}</small>
              </article>
              <article className={"compare-score-card risk-" + comparison.right.risk.verdict}>
                <span className="metric-label">Email B · comparison</span>
                <div className="compare-score-number">{comparison.right.risk.score}<small>/100</small></div>
                <span className={"verdict-pill verdict-" + comparison.right.risk.verdict}>{verdictCopy[comparison.right.risk.verdict].label}</span>
                <p>{comparison.right.metadata.subject ?? "No subject"}</p>
                <small>{comparison.right.sender.address ?? "Visible sender not found"}</small>
              </article>
            </div>

            <Detail title="Message differences" wide>
              <DataRow label="Visible From (A)" value={comparison.left.sender.address ?? "Not found"} />
              <DataRow label="Visible From (B)" value={comparison.right.sender.address ?? "Not found"} />
              <DataRow label="Return-Path (A)" value={comparison.left.return_path.address ?? "Not present"} />
              <DataRow label="Return-Path (B)" value={comparison.right.return_path.address ?? "Not present"} />
              <DataRow label="URLs (A / B)" value={comparison.left.urls.length + " / " + comparison.right.urls.length} />
              <DataRow label="Attachments (A / B)" value={comparison.left.metadata.attachments.length + " / " + comparison.right.metadata.attachments.length} />
            </Detail>

            <div className="compare-detection-grid">
              <Detail title={"Signals in both (" + comparisonSummary.shared.length + ")"}>
                {comparisonSummary.shared.length ? comparisonSummary.shared.map((item) => <div className="compare-detection" key={item.id}><strong>{item.name}</strong><small>{item.id}</small></div>) : <EmptyState text="No matching detection IDs were found in both messages." />}
              </Detail>
              <Detail title={"Only in A (" + comparisonSummary.leftOnly.length + ")"}>
                {comparisonSummary.leftOnly.length ? comparisonSummary.leftOnly.map((item) => <div className="compare-detection" key={item.id}><strong>{item.name}</strong><small>{item.id}</small></div>) : <EmptyState text="No detections unique to Email A." />}
              </Detail>
              <Detail title={"Only in B (" + comparisonSummary.rightOnly.length + ")"}>
                {comparisonSummary.rightOnly.length ? comparisonSummary.rightOnly.map((item) => <div className="compare-detection" key={item.id}><strong>{item.name}</strong><small>{item.id}</small></div>) : <EmptyState text="No detections unique to Email B." />}
              </Detail>
            </div>
            <p className="compare-caveat">Detection IDs are compared as engine outputs, not proof of shared campaign or common authorship. Risk scores are heuristic indicators and should be interpreted alongside the underlying evidence.</p>
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
