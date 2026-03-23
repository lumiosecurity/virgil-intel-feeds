// Virgil — Shared Agent Tools
// Common utilities used by all five AI agents.
// All external I/O goes through here — agents stay focused on logic.

import { execSync } from 'child_process';

// ── Configuration (all from environment) ──────────────────────────────────────

export const cfg = {
  anthropicKey:    process.env.ANTHROPIC_API_KEY,
  githubToken:     process.env.GITHUB_TOKEN,
  safeBrowsingKey: process.env.SAFE_BROWSING_API_KEY,
  d1Database:      process.env.D1_DATABASE    || 'virgil-telemetry',
  orgName:         process.env.ORG_NAME        || 'lumiosecurity',
  coreRulesRepo:   process.env.CORE_RULES_REPO || 'core-rules',
  communityRepo:   process.env.COMMUNITY_REPO  || 'rules',
  model:           'claude-sonnet-4-20250514',
};

// ── D1 Query ──────────────────────────────────────────────────────────────────

export function d1(sql) {
  try {
    const escaped = sql.replace(/"/g, '\\"').replace(/\n/g, ' ').replace(/\s+/g, ' ').trim();
    const output = execSync(
      `wrangler d1 execute ${cfg.d1Database} --remote --command="${escaped}" --json`,
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    );
    const result = JSON.parse(output);
    return result?.[0]?.results || [];
  } catch (e) {
    console.error('[D1] Query failed:', e.message.slice(0, 200));
    return [];
  }
}

// ── Claude API ─────────────────────────────────────────────────────────────────
// All agent Claude calls go here — consistent model, temperature, token budget

export async function claude(systemPrompt, userContent, maxTokens = 2000) {
  if (!cfg.anthropicKey) throw new Error('ANTHROPIC_API_KEY not set');

  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type':      'application/json',
      'x-api-key':         cfg.anthropicKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model:      cfg.model,
      max_tokens: maxTokens,
      system:     systemPrompt,
      messages:   [{ role: 'user', content: userContent }],
    }),
  });

  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Claude API ${resp.status}: ${err.slice(0, 200)}`);
  }

  const data = await resp.json();
  return data.content?.[0]?.text || '';
}

// ── GitHub API ─────────────────────────────────────────────────────────────────

async function gh(method, path, body = null) {
  if (!cfg.githubToken) throw new Error('GITHUB_TOKEN not set');

  const resp = await fetch(`https://api.github.com${path}`, {
    method,
    headers: {
      'Authorization':        `Bearer ${cfg.githubToken}`,
      'Accept':               'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type':         'application/json',
      'User-Agent':           'Virgil-Agents/1.0',
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!resp.ok && resp.status !== 404) {
    const err = await resp.text();
    throw new Error(`GitHub ${method} ${path} → ${resp.status}: ${err.slice(0, 200)}`);
  }

  return resp.status === 204 ? null : resp.json().catch(() => null);
}

export const github = {
  getIssue:       (repo, n)         => gh('GET',   `/repos/${cfg.orgName}/${repo}/issues/${n}`),
  commentOnIssue: (repo, n, body)   => gh('POST',  `/repos/${cfg.orgName}/${repo}/issues/${n}/comments`, { body }),
  closeIssue:     (repo, n, reason) => gh('PATCH', `/repos/${cfg.orgName}/${repo}/issues/${n}`, { state: 'closed', state_reason: reason || 'completed' }),
  addLabel:       (repo, n, labels) => gh('POST',  `/repos/${cfg.orgName}/${repo}/issues/${n}/labels`, { labels }),
  removeLabel:    (repo, n, label)  => gh('DELETE',`/repos/${cfg.orgName}/${repo}/issues/${n}/labels/${encodeURIComponent(label)}`),
  getPR:          (repo, n)         => gh('GET',   `/repos/${cfg.orgName}/${repo}/pulls/${n}`),
  getPRFiles:     (repo, n)         => gh('GET',   `/repos/${cfg.orgName}/${repo}/pulls/${n}/files`),
  reviewPR:       (repo, n, event, body, comments=[]) => gh('POST', `/repos/${cfg.orgName}/${repo}/pulls/${n}/reviews`, { event, body, comments }),
  createIssue:    (repo, title, body, labels=[]) => gh('POST', `/repos/${cfg.orgName}/${repo}/issues`, { title, body, labels }),
  getFileContent: (repo, path, ref='main') => gh('GET', `/repos/${cfg.orgName}/${repo}/contents/${path}?ref=${ref}`),
  createOrUpdateFile: (repo, path, message, content, sha=null) => gh('PUT', `/repos/${cfg.orgName}/${repo}/contents/${path}`, { message, content: Buffer.from(content).toString('base64'), ...(sha && { sha }) }),
};

// ── Certificate Transparency ───────────────────────────────────────────────────

export async function getCTAge(domain) {
  try {
    const resp = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`,
      { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(6000) }
    );
    if (!resp.ok) return null;
    const certs = await resp.json();
    if (!Array.isArray(certs) || certs.length === 0) return null;

    let earliest = null;
    for (const c of certs) {
      const ts = new Date(c.not_before || c.entry_timestamp).getTime();
      if (!isNaN(ts) && (earliest === null || ts < earliest)) earliest = ts;
    }
    if (!earliest) return null;

    const ageDays = (Date.now() - earliest) / 86_400_000;
    return { firstSeenTs: earliest, ageDays: Math.round(ageDays * 10) / 10 };
  } catch { return null; }
}

// ── Google Safe Browsing ───────────────────────────────────────────────────────

export async function checkSafeBrowsing(url) {
  if (!cfg.safeBrowsingKey) return null;
  try {
    const resp = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${cfg.safeBrowsingKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'virgil-agents', clientVersion: '1.0' },
          threatInfo: {
            threatTypes:      ['MALWARE', 'SOCIAL_ENGINEERING'],
            platformTypes:    ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries:    [{ url }],
          },
        }),
        signal: AbortSignal.timeout(4000),
      }
    );
    if (!resp.ok) return null;
    const data = await resp.json();
    return (data.matches || []).length > 0
      ? { matched: true, threatTypes: data.matches.map(m => m.threatType) }
      : { matched: false };
  } catch { return null; }
}

// ── Domain intelligence ────────────────────────────────────────────────────────

export async function getDomainIntel(domain) {
  const [ct, gsb] = await Promise.allSettled([
    getCTAge(domain),
    checkSafeBrowsing(`https://${domain}`),
  ]);

  // Corpus hit count
  const corpusRows = d1(`
    SELECT COUNT(DISTINCT install_id) as reports, AVG(confidence) as avg_conf,
           MAX(risk_level) as max_risk
    FROM verdicts
    WHERE registered_domain = '${domain.replace(/'/g,"''")}' AND risk_level != 'safe'
  `);

  // Ingested feed hit count
  const feedRows = d1(`
    SELECT COUNT(*) as hits, AVG(risk_score) as avg_score,
           GROUP_CONCAT(DISTINCT feed_source) as feeds
    FROM ingested_urls
    WHERE registered_domain = '${domain.replace(/'/g,"''")}' AND risk_score >= 0.5
  `);

  return {
    domain,
    ct:     ct.status === 'fulfilled' ? ct.value : null,
    gsb:    gsb.status === 'fulfilled' ? gsb.value : null,
    corpus: corpusRows[0] || { reports: 0, avg_conf: null, max_risk: null },
    feeds:  feedRows[0]   || { hits: 0, avg_score: null, feeds: null },
  };
}

// ── Heuristic analysis (same logic as ingest-feeds.js) ────────────────────────

export function analyzeUrl(url) {
  try {
    const parsed     = new URL(url);
    const hostname   = parsed.hostname.toLowerCase();
    const parts      = hostname.split('.');
    const tld        = '.' + parts[parts.length - 1];
    const regDomain  = parts.slice(-2).join('.');
    const subdomains = parts.slice(0, -2).join('.');
    const fullUrl    = url.toLowerCase();
    const signals    = [];
    let   score      = 0;

    const addSig = (type, desc, severity, weight) => {
      signals.push({ type, desc, severity, weight });
      score += weight;
    };

    const BRANDS = ['paypal','chase','wellsfargo','bankofamerica','microsoft','google',
      'okta','github','slack','zoom','amazon','apple','netflix','coinbase','binance',
      'metamask','ledger','opensea','stripe','docusign','dropbox','adobe','linkedin',
      'facebook','instagram','steam','ebay'];

    const brandSub = BRANDS.find(b => subdomains.includes(b) && !regDomain.startsWith(b));
    if (brandSub) addSig('brand-in-subdomain', `"${brandSub}" in subdomain`, 'high', 0.40);

    const norm = str => str.replace(/0/g,'o').replace(/1/g,'l').replace(/3/g,'e').replace(/4/g,'a').replace(/5/g,'s').replace(/vv/g,'w').replace(/rn/g,'m');
    const brandGlyph = BRANDS.find(b => !hostname.includes(b) && norm(hostname).includes(b));
    if (brandGlyph) addSig('homoglyph', `Normalises to "${brandGlyph}"`, 'high', 0.45);

    const TLD_RISK = {'.xyz':0.20,'.top':0.20,'.club':0.15,'.online':0.15,'.site':0.15,
      '.live':0.15,'.click':0.20,'.loan':0.25,'.win':0.20,'.gq':0.30,'.ml':0.30,
      '.cf':0.30,'.ga':0.30,'.tk':0.30,'.pw':0.20};
    if (TLD_RISK[tld]) addSig('high-risk-tld', `TLD ${tld}`, 'medium', TLD_RISK[tld]);

    if (parts.length >= 4) addSig('deep-subdomain', `${parts.length-2} levels`, 'low', 0.10);
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) addSig('ip-hostname', 'IP as hostname', 'high', 0.35);
    if (parsed.protocol === 'http:') addSig('no-tls', 'Plain HTTP', 'high', 0.25);

    const CRED = ['login','signin','verify','secure','account','password','recover','unlock'];
    const credHits = CRED.filter(k => fullUrl.includes(k));
    if (credHits.length >= 2) addSig('credential-keywords', credHits.join(','), 'medium', 0.15);

    const hyphens = (regDomain.replace(/\.[^.]+$/,'').match(/-/g)||[]).length;
    if (hyphens >= 2) addSig('hyphenated-domain', `${hyphens} hyphens`, hyphens>=3?'high':'medium', hyphens>=3?0.25:0.15);

    return { url, hostname, registeredDomain: regDomain, tld, score: Math.min(score,1.0), signals };
  } catch { return null; }
}

// ── Formatting helpers ─────────────────────────────────────────────────────────

export function fmtIntel(intel) {
  const lines = [];
  if (intel.ct) {
    lines.push(`**CT log age:** ${intel.ct.ageDays} days (first cert ${new Date(intel.ct.firstSeenTs).toISOString().slice(0,10)})`);
  } else {
    lines.push('**CT log age:** not found (domain may be very new or use private CA)');
  }
  if (intel.gsb?.matched)   lines.push(`**Safe Browsing:** ⚠ MATCHED — ${intel.gsb.threatTypes.join(', ')}`);
  else if (intel.gsb)       lines.push('**Safe Browsing:** clean');
  else                       lines.push('**Safe Browsing:** not checked (no key)');
  lines.push(`**Corpus reports:** ${intel.corpus.reports} distinct installs, avg confidence ${intel.corpus.avg_conf?.toFixed(2) || 'N/A'}, max verdict ${intel.corpus.max_risk || 'none'}`);
  lines.push(`**Feed hits:** ${intel.feeds.hits} ingested URLs, avg score ${intel.feeds.avg_score?.toFixed(2) || 'N/A'}, sources: ${intel.feeds.feeds || 'none'}`);
  return lines.join('\n');
}

export function fmtHeuristics(result) {
  if (!result) return 'Could not parse URL.';
  if (result.signals.length === 0) return `Score: 0.00 — no signals fired`;
  const sigs = result.signals.map(s => `  - \`${s.type}\` (${s.severity}, +${s.weight}): ${s.desc}`).join('\n');
  return `Score: ${result.score.toFixed(2)}/1.00\n${sigs}`;
}
