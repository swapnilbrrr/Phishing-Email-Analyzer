
// ─────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────

// Domains that are inherently trusted — scoring is massively discounted
const TRUSTED = new Set([
  'github.com','githubnotifications.com','githubusercontent.com','github.io',
  'google.com','googlemail.com','gmail.com','google.co.uk','google.com.np',
  'microsoft.com','outlook.com','hotmail.com','live.com','office.com','office365.com',
  'amazon.com','amazonaws.com','amazon.co.uk',
  'apple.com','icloud.com','me.com',
  'linkedin.com','twitter.com','x.com','facebook.com','meta.com','instagram.com',
  'stripe.com','paypal.com','shopify.com','slack.com','zoom.us','zoom.com',
  'netflix.com','spotify.com','dropbox.com','atlassian.com','notion.so',
  'cloudflare.com','fastmail.com','protonmail.com','proton.me','tutanota.com',
]);

// Brands to check for typosquatting (just the base name, no TLD)
const BRANDS = [
  'paypal','google','microsoft','amazon','apple','linkedin','twitter',
  'facebook','netflix','spotify','dropbox','github','stripe','outlook',
  'office365','instagram','cloudflare','godaddy','namecheap',
];

// Subject/body urgency signals
const URGENCY = [
  'urgent','immediately','suspended','verify your','confirm your',
  'unusual activity','security alert','limited time','act now',
  'action required','unauthorized access','account locked','account disabled',
  'click here','you have won','congratulations','prize','winner selected',
  'validate your','update your payment','verify identity',
];

// ─────────────────────────────────────────
// UTILS
// ─────────────────────────────────────────

const $  = id => document.getElementById(id);
const qs = sel => document.querySelector(sel);

function sleep(ms){ return new Promise(r => setTimeout(r, ms)) }

function setStatus(msg, type = ''){
  const el = $('st');
  el.className = 'status show ' + type;
  const spinner = (type === '' || type === '') ? '<div class="spin"></div>' : '';
  el.innerHTML = spinner + msg;
}

function setProgress(pct){
  $('progFill').style.width = pct + '%';
}

function badge(id, text, cls){
  const el = $(id);
  if(!el) return;
  el.textContent = text;
  el.className = 'badge ' + cls;
}

// Unfold RFC 2822 folded headers (continuation lines start with whitespace)
function unfoldHeaders(raw){
  return raw.replace(/\r\n([ \t])/g, ' ').replace(/\n([ \t])/g, ' ');
}

// Extract a single header value by name (case-insensitive, handles folding)
function getHeader(unfolded, name){
  const re = new RegExp(`^${name}:\\s*(.+)`, 'im');
  const m  = unfolded.match(re);
  return m ? m[1].trim() : null;
}

// Pull email address out of "Display Name <addr@domain.com>" or bare address
function parseEmail(str){
  if(!str) return { addr: null, display: null, domain: null };
  const angle = str.match(/<([^>]+)>/);
  const addr  = angle ? angle[1].toLowerCase() : str.toLowerCase().trim();
  const dispM = str.match(/^"?([^"<]+)"?\s*</);
  const display = dispM ? dispM[1].trim() : null;
  const domM  = addr.match(/@([\w.\-]+)$/);
  const domain = domM ? domM[1].toLowerCase() : null;
  return { addr, display, domain };
}

// Extract the ORIGINATING sender IP from Received headers.
// The originating IP is in the LAST (bottom-most) Received header — that's
// the first hop, closest to the actual sender.
function getOriginatingIP(unfolded){
  const lines = unfolded.split(/\n/);
  const received = [];
  for(const line of lines){
    if(/^received:/i.test(line)) received.push(line);
  }
  // Last Received header = first hop = originating server
  const target = received[received.length - 1] || '';
  const ips = extractPublicIPs(target);
  return ips[0] || null;
}

// Extract all public (non-RFC1918) IPv4 addresses from a string
function extractPublicIPs(text){
  const re   = /\b(\d{1,3}\.){3}\d{1,3}\b/g;
  const priv = [/^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./, /^127\./, /^0\./];
  return [...new Set((text.match(re) || []).filter(ip => !priv.some(r => r.test(ip))))]
}

// Extract all http/https URLs from the raw header text
function extractURLs(raw){
  const re = /https?:\/\/[^\s"'<>\])}]+/gi;
  return [...new Set(raw.match(re) || [])];
}

// Levenshtein distance (used for typosquat detection)
function lev(a, b){
  const d = Array.from({length: a.length+1}, (_,i) => [i]);
  for(let j=0;j<=b.length;j++) d[0][j]=j;
  for(let i=1;i<=a.length;i++)
    for(let j=1;j<=b.length;j++)
      d[i][j] = a[i-1]===b[j-1] ? d[i-1][j-1] : 1+Math.min(d[i-1][j],d[i][j-1],d[i-1][j-1]);
  return d[a.length][b.length];
}

// Check if a domain is typosquatting a known brand
// Returns { brand, domain } or null
function checkTyposquat(domain){
  if(!domain) return null;
  // Split off subdomain — only check the registrable part
  const parts = domain.split('.');
  const base  = parts.length >= 2 ? parts[parts.length-2] : parts[0];
  for(const brand of BRANDS){
    if(base === brand) return null; // exact match = legit
    const dist = lev(base, brand);
    // Only flag if: edit distance 1-2 AND length is close (prevents "n" matching "amazon")
    if(dist >= 1 && dist <= 2 && Math.abs(base.length - brand.length) <= 2){
      return { brand, domain };
    }
  }
  return null;
}

// Parse auth results from Authentication-Results or received headers
function parseAuth(unfolded){
  const s = unfolded.toLowerCase();
  const pick = (keyword) => {
    const re = new RegExp(keyword + '=(\\w+)');
    const m  = s.match(re);
    return m ? m[1] : 'none';
  };
  return {
    spf:  pick('spf'),
    dkim: pick('dkim'),
    dmarc:pick('dmarc'),
  };
}

// ─────────────────────────────────────────
// API CALL — Backend proxy
// AbuseIPDB key is stored server-side and never exposed in frontend code.
// ─────────────────────────────────────────
async function queryAbuseIPDB(ip){
  try {
    const res = await fetch(`/api/abuseipdb?ip=${encodeURIComponent(ip)}`);
    if(!res.ok) return { error: `HTTP ${res.status}` };
    return await res.json();
  } catch(e) {
    return { error: e.message };
  }
}

// ─────────────────────────────────────────
// SCORING ENGINE
// Each check returns { delta, indicator } objects.
// Trusted senders get a hard cap — score can never exceed 20 for them.
// ─────────────────────────────────────────

function scoreAuth(auth, isTrusted){
  const results = [];
  let score = 0;
  let authPct = 0;

  const authMap = { pass:'pass', fail:'fail', softfail:'warn', none:'muted', neutral:'muted' };
  badge('aSPF',   auth.spf.toUpperCase(),   authMap[auth.spf]  || 'muted');
  badge('aDKIM',  auth.dkim.toUpperCase(),  authMap[auth.dkim] || 'muted');
  badge('aDMARC', auth.dmarc.toUpperCase(), authMap[auth.dmarc]|| 'muted');

  // SPF
  if(auth.spf === 'pass')     { authPct += 34; results.push({icon:'ok',   text:'SPF passed',           delta:0}); }
  else if(auth.spf === 'fail'){ if(!isTrusted) score += 15; results.push({icon:'bad', text:'SPF failed',           delta:isTrusted?0:15}); }
  else if(auth.spf === 'softfail'){ if(!isTrusted) score += 8; results.push({icon:'warn',text:'SPF softfail',          delta:isTrusted?0:8}); }
  else                        { results.push({icon:'warn',text:'SPF not present in headers', delta:0}); }

  // DKIM
  if(auth.dkim === 'pass')     { authPct += 33; results.push({icon:'ok',  text:'DKIM signature valid',  delta:0}); }
  else if(auth.dkim === 'fail'){ if(!isTrusted) score += 15; results.push({icon:'bad', text:'DKIM signature failed', delta:isTrusted?0:15}); }
  else                         { results.push({icon:'warn',text:'DKIM not present in headers', delta:0}); }

  // DMARC
  if(auth.dmarc === 'pass')     { authPct += 33; results.push({icon:'ok',  text:'DMARC passed',          delta:0}); }
  else if(auth.dmarc === 'fail'){ if(!isTrusted) score += 10; results.push({icon:'bad', text:'DMARC policy failed',  delta:isTrusted?0:10}); }
  else                          { results.push({icon:'warn',text:'DMARC policy not in headers', delta:0}); }

  // Update auth bar
  const color = authPct > 60 ? 'g' : authPct > 30 ? 'a' : 'r';
  $('authBar').style.width  = authPct + '%';
  $('authBar').className    = 'bar-fill ' + color;
  $('authNum').textContent  = authPct + '%';

  return { score, results };
}

// ─────────────────────────────────────────
// MAIN RUN
// ─────────────────────────────────────────
async function run(){
  const raw = $('headerInput').value.trim();
  if(!raw){ setStatus('⚠ Paste raw email headers above.','err'); return; }

  const doIPDB   = $('chkIPDB').checked;
  const doAuth   = $('chkAuth').checked;
  const doTypo   = $('chkTypo').checked;
  const doURLs   = $('chkURLs').checked;

  const btn = $('runBtn');
  btn.disabled = true; btn.textContent = 'Scanning...';
  $('prog').className = 'prog-bar active';
  $('results').className = '';
  $('trustedBanner').className = 'trusted-banner';
  $('corsNote').className = 'cors-note';

  let totalScore = 0;
  const indicators = [];

  // ── Step 1: Unfold + parse fields
  setStatus('Parsing headers…'); setProgress(10);
  await sleep(100);

  const unfolded = unfoldHeaders(raw);
  const fromRaw  = getHeader(unfolded, 'From');
  const rtRaw    = getHeader(unfolded, 'Reply-To');
  const subject  = getHeader(unfolded, 'Subject') || '(no subject)';

  const from  = parseEmail(fromRaw);
  const rt    = parseEmail(rtRaw);
  const origIP = getOriginatingIP(unfolded);

  // Populate header fields
  $('hFrom').textContent    = from.addr  || fromRaw || 'not found';
  $('hReplyTo').textContent = rt.addr    || rtRaw   || 'not present';
  $('hIP').textContent      = origIP     || 'not detected';
  $('hSubject').textContent = subject.length > 48 ? subject.slice(0,48)+'…' : subject;

  // ── Step 2: Trusted sender check
  setStatus('Checking sender trust…'); setProgress(20);
  await sleep(80);

  const isTrusted = !!(from.domain && TRUSTED.has(from.domain));
  if(isTrusted){
    $('trustedBanner').className = 'trusted-banner show';
    $('trustedText').textContent =
      `Sender domain "${from.domain}" is a verified provider. Trust discount applied.`;
    indicators.push({icon:'ok', text:`Known trusted sender domain: ${from.domain}`, delta:-20});
    totalScore -= 20; // baseline discount for trusted senders
  }

  // ── Step 3: Auth checks
  if(doAuth){
    setStatus('Validating SPF / DKIM / DMARC…'); setProgress(35);
    await sleep(80);
    const auth   = parseAuth(unfolded);
    const scored = scoreAuth(auth, isTrusted);
    totalScore  += scored.score;
    indicators.push(...scored.results);
  }

  // ── Step 4: Header logic signals
  setStatus('Analyzing header signals…'); setProgress(50);
  await sleep(80);

  // Reply-To mismatch
  if(rt.domain && from.domain && rt.domain !== from.domain){
    badge('hDomain', 'MISMATCH', 'fail');
    $('hReplyTo').className = 'rv danger';
    if(!isTrusted){
      totalScore += 30;
      indicators.push({icon:'bad', text:`Reply-To domain "${rt.domain}" ≠ From domain "${from.domain}"`, delta:30});
    } else {
      indicators.push({icon:'warn', text:`Reply-To domain differs from From (suppressed — trusted sender)`, delta:0});
    }
  } else {
    badge('hDomain', from.domain ? 'MATCH' : 'N/A', from.domain ? 'pass' : 'muted');
  }

  // Typosquat
  if(doTypo && from.domain){
    const typo = checkTyposquat(from.domain);
    if(typo && !TRUSTED.has(from.domain)){
      badge('hTypo', `${typo.domain} → ${typo.brand}`, 'fail');
      totalScore += 35;
      indicators.push({icon:'bad', text:`Typosquat detected: "${typo.domain}" mimics "${typo.brand}"`, delta:35});
    } else {
      badge('hTypo', 'NONE', 'pass');
    }
  }

  // Display name spoofing — display name contains a brand but domain doesn't match
  if(from.display && from.domain){
    const dispLower = from.display.toLowerCase();
    const spoofed = BRANDS.find(b => dispLower.includes(b) && !from.domain.includes(b) && !TRUSTED.has(from.domain));
    if(spoofed){
      badge('hSpoof', `claims "${spoofed}"`, 'fail');
      totalScore += 25;
      indicators.push({icon:'bad', text:`Display name claims to be "${spoofed}" but domain is "${from.domain}"`, delta:25});
    } else {
      badge('hSpoof', 'NONE', 'pass');
    }
  } else {
    badge('hSpoof', 'N/A', 'muted');
  }

  // Urgency signals in subject
  const subL = subject.toLowerCase();
  const hits  = URGENCY.filter(w => subL.includes(w));
  if(hits.length > 0){
    const d = Math.min(hits.length * 5, 20);
    if(!isTrusted) totalScore += d;
    indicators.push({icon:'warn', text:`Urgency language in subject: "${hits.slice(0,3).join('", "')}"`, delta:isTrusted?0:d});
  }

  // Numeric-only subdomain (common in phishing infrastructure)
  if(from.domain){
    const subdomains = from.domain.split('.');
    if(subdomains.length > 2 && /^\d+$/.test(subdomains[0])){
      if(!isTrusted){
        totalScore += 15;
        indicators.push({icon:'bad', text:`Numeric subdomain in sender domain (common phishing pattern)`, delta:15});
      }
    }
  }

  // ── Step 5: IP Reputation
  setStatus('Querying AbuseIPDB…'); setProgress(70);

  const tbody = $('ipBody');
  tbody.innerHTML = '';

  if(!origIP){
    tbody.innerHTML = '<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:.75rem">No public IPs found in headers</td></tr>';
  } else {
    let ipData = null;
    if(doIPDB){
      ipData = await queryAbuseIPDB(origIP);
      if(ipData && ipData.error){
        $('corsNote').className = 'cors-note show';
        ipData = null;
      }
    }

    const conf    = ipData ? ipData.abuseConfidenceScore : null;
    const reports = ipData ? ipData.totalReports : null;

    let badgeText, badgeClass;
    if(conf === null)       { badgeText = doIPDB ? 'CHECK FAILED' : 'SKIPPED'; badgeClass = doIPDB ? 'warn' : 'muted'; }
    else if(conf >= 70)     { badgeText = 'MALICIOUS';     badgeClass = 'dirty'; totalScore += 30; indicators.push({icon:'bad', text:`Sender IP ${origIP} — ${conf}% abuse confidence, ${reports} reports`, delta:30}); }
    else if(conf >= 25)     { badgeText = 'SUSPICIOUS';    badgeClass = 'warn';  totalScore += 15; indicators.push({icon:'warn',text:`Sender IP ${origIP} — moderate abuse score (${conf}%)`, delta:15}); }
    else                    { badgeText = 'CLEAN';          badgeClass = 'clean'; indicators.push({icon:'ok', text:`Sender IP ${origIP} is clean on AbuseIPDB (${conf}%)`, delta:0}); }

    const tr = document.createElement('tr');
    tr.innerHTML =
      `<td>${origIP}</td>` +
      `<td>${conf !== null ? conf+'%' : '—'}</td>` +
      `<td>${reports !== null ? reports : '—'}</td>` +
      `<td><span class="badge ${badgeClass}">${badgeText}</span></td>`;
    tbody.appendChild(tr);
  }

  // ── Step 6: URL extraction
  if(doURLs){
    const urls = extractURLs(raw);
    if(urls.length > 0){
      $('urlCard').style.display = 'block';
      const ul = $('urlList');
      ul.innerHTML = '';
      for(const url of urls.slice(0, 20)){
        const li = document.createElement('li');
        const encoded = btoa(url).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
        li.innerHTML =
          `<span>${url.length > 70 ? url.slice(0,70)+'…' : url}</span>` +
          `<a class="url-vt" href="https://www.virustotal.com/gui/url/${encoded}" target="_blank">VT ↗</a>`;
        ul.appendChild(li);
      }
      // Suspicious URL patterns
      const suspPatterns = [/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, /bit\.ly|tinyurl|t\.co|goo\.gl/, /[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.[a-z]{2,3}\//];
      const suspURLs = urls.filter(u => suspPatterns.some(p => p.test(u)));
      if(suspURLs.length > 0 && !isTrusted){
        totalScore += Math.min(suspURLs.length * 10, 20);
        indicators.push({icon:'bad', text:`${suspURLs.length} suspicious URL pattern(s) detected (IP-based or URL shortener)`, delta:Math.min(suspURLs.length*10,20)});
      }
    }
  }

  // ── Step 7: Final score render
  setProgress(95);
  await sleep(100);

  totalScore = Math.max(0, Math.min(100, totalScore));

  const banner = $('riskBanner');
  if(totalScore >= 60){
    banner.className = 'risk high';
    $('rVerdict').textContent = 'High Risk — Likely Phishing';
    $('rDetail').textContent  = 'Multiple strong indicators detected. Do not click any links or provide credentials.';
  } else if(totalScore >= 30){
    banner.className = 'risk med';
    $('rVerdict').textContent = 'Medium Risk — Suspicious';
    $('rDetail').textContent  = 'Some indicators present. Verify the sender through a separate channel before acting.';
  } else {
    banner.className = 'risk low';
    $('rVerdict').textContent = 'Low Risk — Appears Legitimate';
    $('rDetail').textContent  = 'No significant phishing signals detected.';
  }
  $('rNum').textContent = totalScore;

  // Render indicator list
  const list = $('indList');
  list.innerHTML = '';
  if(indicators.length === 0){
    list.innerHTML = '<li><span class="ind-icon ok">✓</span><span class="ind-text">No suspicious indicators found</span></li>';
  } else {
    for(const ind of indicators){
      const li = document.createElement('li');
      const d  = typeof ind.delta === 'number' ? ind.delta : parseInt(ind.delta) || 0;
      const dStr = d > 0 ? '+'+d : d < 0 ? String(d) : '';
      const dCls = d > 0 ? 'pos' : d < 0 ? 'neg' : '';
      const icon = ind.icon === 'ok' ? '✓' : ind.icon === 'bad' ? '✗' : '!';
      li.innerHTML =
        `<span class="ind-icon ${ind.icon}">${icon}</span>` +
        `<span class="ind-text">${ind.text}</span>` +
        (dStr ? `<span class="ind-delta ${dCls}">${dStr}</span>` : '');
      list.appendChild(li);
    }
  }

  setProgress(100);
  await sleep(100);
  $('prog').className = 'prog-bar';
  setStatus('Analysis complete.', 'ok');
  btn.disabled = false;
  btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 13 13" fill="none"><circle cx="5.5" cy="5.5" r="4" stroke="white" stroke-width="1.3"/><path d="M9 9L12 12" stroke="white" stroke-width="1.3" stroke-linecap="round"/></svg> Analyze';

  $('results').className = 'show';
  $('results').scrollIntoView({ behavior:'smooth', block:'start' });
}

// ─────────────────────────────────────────
// INIT
// ─────────────────────────────────────────

$('headerInput').addEventListener('input', function(){
  $('charCount').textContent = this.value.length.toLocaleString() + ' chars';
});

$('headerInput').addEventListener('keydown', e => {
  if(e.ctrlKey && e.key === 'Enter') run();
});

