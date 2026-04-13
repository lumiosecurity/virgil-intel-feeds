// Virgil — Shared Agent Tools
// Common utilities used by all five AI agents.
// All external I/O goes through here — agents stay focused on logic.

import { execSync } from 'child_process';
import { writeFileSync, unlinkSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// ── Configuration (all from environment) ──────────────────────────────────────

export const cfg = {
  anthropicKey:    process.env.ANTHROPIC_API_KEY,
  githubToken:     process.env.GITHUB_TOKEN,
  d1Database:      process.env.D1_DATABASE    || 'virgil-telemetry',
  orgName:         process.env.ORG_NAME        || 'lumiosecurity',
  coreRulesRepo:   process.env.CORE_RULES_REPO || 'virgil-core-rules',
  communityRepo:   process.env.COMMUNITY_REPO  || 'virgil-rules',
  model:           'claude-sonnet-4-20250514',
};

// ── D1 Query ──────────────────────────────────────────────────────────────────
//
// Use parameterized queries to prevent SQL injection:
//   d1`SELECT * FROM verdicts WHERE registered_domain = ${domain}`
//
// For static SQL without user-controlled values, use d1raw():
//   d1raw('SELECT COUNT(*) as cnt FROM verdicts')

export function d1(strings, ...values) {
  // Tagged template literal: strings are the static parts, values are interpolations
  let sql = strings[0];
  for (let i = 0; i < values.length; i++) {
    sql += '?' + strings[i + 1];
  }
  return _executeD1(sql, values);
}

export function d1raw(sql) {
  return _executeD1(sql, []);
}

function _executeD1(sql, params) {
  const cleanSql = sql.replace(/\n/g, ' ').replace(/\s+/g, ' ').trim();
  const tmpFile = join(tmpdir(), `virgil-query-${Date.now()}.sql`);
  try {
    const finalSql = _interpolateSafe(cleanSql, params);
    writeFileSync(tmpFile, finalSql);
    const rawOutput = execSync(
      `wrangler d1 execute ${cfg.d1Database} --remote --file="${tmpFile}" --json 2>/dev/null`,
      {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env },
      }
    );
    // Strip any non-JSON lines (wrangler progress output) — find the JSON array
    const jsonMatch = rawOutput.match(/(\[[\s\S]*\])/);
    if (!jsonMatch) return [];
    const result = JSON.parse(jsonMatch[1]);
    return result?.[0]?.results || [];
  } catch (e) {
    console.error('[D1] Query failed:', e.message.slice(0, 300));
    return [];
  } finally {
    try { unlinkSync(tmpFile); } catch {}
  }
}

function _interpolateSafe(sql, params) {
  if (params.length === 0) return sql;
  let paramIndex = 0;
  return sql.replace(/\?/g, () => {
    if (paramIndex >= params.length) {
      throw new Error('D1 query has more ? placeholders than parameters');
    }
    return _escapeSqlValue(params[paramIndex++]);
  });
}

function _escapeSqlValue(val) {
  if (val === null || val === undefined) return 'NULL';
  if (typeof val === 'number') {
    if (!Number.isFinite(val)) throw new Error(`D1: non-finite number in query: ${val}`);
    return String(val);
  }
  if (typeof val === 'boolean') return val ? '1' : '0';
  if (typeof val === 'string') {
    if (val.includes('\0')) throw new Error('D1: null byte in query parameter');
    return `'${val.replace(/'/g, "''")}'`;
  }
  throw new Error(`D1: unsupported parameter type: ${typeof val}`);
}

// ── Claude API ─────────────────────────────────────────────────────────────────
// All agent Claude calls go here — consistent model, temperature, token budget

// ── Reasoning preamble ────────────────────────────────────────────────────────
// Prepended to every system prompt sent to Opus or Sonnet.
// Sets the baseline reasoning posture for all agent calls.

const REASONING_PREAMBLE = `Always reason thoroughly and deeply. Treat every request as complex unless explicitly told otherwise. Never optimize for brevity at the expense of quality. Think step-by-step, consider tradeoffs, and provide comprehensive analysis.\n\n`;

export async function claude(systemPrompt, userContent, maxTokens = 2000, imageUrl = null, model = null) {
  if (!cfg.anthropicKey) throw new Error('ANTHROPIC_API_KEY not set');
  const useModel = model || cfg.model;
  const fullSystemPrompt = REASONING_PREAMBLE + systemPrompt;

  // Build message content — optionally prepend screenshot
  let messageContent;
  if (imageUrl) {
    try {
      const imgResp = await fetch(imageUrl, { signal: AbortSignal.timeout(8000) });
      if (imgResp.ok) {
        const imgBuffer = await imgResp.arrayBuffer();
        const base64 = Buffer.from(imgBuffer).toString('base64');
        const mediaType = imgResp.headers.get('content-type') || 'image/jpeg';
        messageContent = [
          {
            type: 'image',
            source: { type: 'base64', media_type: mediaType, data: base64 },
          },
          { type: 'text', text: userContent },
        ];
        console.log('Screenshot included in Claude request, size:', base64.length);
      } else {
        console.warn('Could not fetch screenshot for Claude:', imgResp.status);
        messageContent = userContent;
      }
    } catch (e) {
      console.warn('Screenshot fetch failed:', e.message);
      messageContent = userContent;
    }
  } else {
    messageContent = userContent;
  }

  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type':      'application/json',
      'x-api-key':         cfg.anthropicKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model:      useModel,
      max_tokens: maxTokens,
      system:     fullSystemPrompt,
      messages:   [{ role: 'user', content: messageContent }],
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
  getIssueComments: (repo, n)       => gh('GET',   `/repos/${cfg.orgName}/${repo}/issues/${n}/comments?per_page=100`),
  commentOnIssue: (repo, n, body)   => gh('POST',  `/repos/${cfg.orgName}/${repo}/issues/${n}/comments`, { body }),
  closeIssue:     (repo, n, reason) => gh('PATCH', `/repos/${cfg.orgName}/${repo}/issues/${n}`, { state: 'closed', state_reason: reason || 'completed' }),
  addLabel:       (repo, n, labels) => gh('POST',  `/repos/${cfg.orgName}/${repo}/issues/${n}/labels`, { labels }),
  removeLabel:    (repo, n, label)  => gh('DELETE',`/repos/${cfg.orgName}/${repo}/issues/${n}/labels/${encodeURIComponent(label)}`),
  getPR:          (repo, n)         => gh('GET',   `/repos/${cfg.orgName}/${repo}/pulls/${n}`),
  getPRFiles:     (repo, n)         => gh('GET',   `/repos/${cfg.orgName}/${repo}/pulls/${n}/files`),
  reviewPR:       (repo, n, event, body, comments=[]) => gh('POST', `/repos/${cfg.orgName}/${repo}/pulls/${n}/reviews`, { event, body, comments }),
  createIssue:    (repo, title, body, labels=[]) => gh('POST', `/repos/${cfg.orgName}/${repo}/issues`, { title, body, labels }),
  getFileContent: (repo, path, ref='main') => gh('GET', `/repos/${cfg.orgName}/${repo}/contents/${path}?ref=${ref}`),
  createOrUpdateFile: (repo, path, message, content, sha=null, branch=null) => gh('PUT', `/repos/${cfg.orgName}/${repo}/contents/${path}`, { message, content: Buffer.from(content).toString('base64'), ...(sha && { sha }), ...(branch && { branch }) }),
  // Branch management — used by graduation agent to create PRs
  getRef:         (repo, ref)       => gh('GET',  `/repos/${cfg.orgName}/${repo}/git/ref/${ref}`),
  createRef:      (repo, ref, sha)  => gh('POST', `/repos/${cfg.orgName}/${repo}/git/refs`, { ref, sha }),
  createPullRequest: (repo, title, body, head, base='main') =>
    gh('POST', `/repos/${cfg.orgName}/${repo}/pulls`, { title, body, head, base }),
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


// ── Domain utilities ──────────────────────────────────────────────────────────
// Canonical registered domain extraction — matches the extension's
// src/background/registered-domain.js (agents run in Node, not the extension)

const SECOND_LEVEL_TLDS = new Set([
  'com.mx','com.au','com.br','com.ar','com.co','com.pe','com.ve',
  'co.uk','org.uk','me.uk','net.uk','ac.uk','gov.uk','sch.uk','nhs.uk',
  'co.nz','org.nz','net.nz','govt.nz','ac.nz',
  'co.za','org.za','net.za','gov.za','ac.za',
  'co.jp','or.jp','ne.jp','ac.jp','go.jp','ed.jp',
  'co.in','org.in','net.in','gen.in','firm.in','ind.in',
  'co.kr','or.kr','ne.kr','re.kr','pe.kr',
  'com.sg','org.sg','edu.sg','gov.sg',
  'com.hk','org.hk','edu.hk','gov.hk',
  'com.tw','org.tw','edu.tw','gov.tw',
  'com.cn','org.cn','net.cn','edu.cn','gov.cn',
  'com.ph','org.ph','edu.ph','gov.ph',
  'com.my','org.my','edu.my','gov.my',
  'co.th','or.th','ac.th','go.th','in.th',
  'co.id','or.id','ac.id','go.id','web.id','biz.id',
  'com.vn','org.vn','edu.vn','gov.vn',
  'com.pk','org.pk','edu.pk','gov.pk',
  'com.bd','org.bd','edu.bd','gov.bd',
  'com.tr','org.tr','edu.tr','gov.tr',
  'com.sa','org.sa','edu.sa','gov.sa',
  'com.eg','org.eg','edu.eg','gov.eg',
  'com.ng','org.ng','edu.ng','gov.ng',
  'co.ke','or.ke','ac.ke','go.ke',
  'co.tz','or.tz','ac.tz','go.tz',
  'com.ua','org.ua','edu.ua','gov.ua','net.ua',
  'co.il','org.il','ac.il','gov.il','net.il',
  'org.au','net.au','edu.au','gov.au','id.au',
]);

export function extractRegisteredDomain(hostname) {
  if (!hostname) return '';
  hostname = hostname.toLowerCase().split(':')[0].replace(/\.+$/, '');
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) return hostname;
  hostname = hostname.replace(/^www\./, '');
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  const lastTwo = parts.slice(-2).join('.');
  if (SECOND_LEVEL_TLDS.has(lastTwo) && parts.length >= 3) return parts.slice(-3).join('.');
  return lastTwo;
}

// ── Domain intelligence ────────────────────────────────────────────────────────

export async function getDomainIntel(hostname) {
  const registeredDomain = extractRegisteredDomain(hostname);

  const [ct] = await Promise.allSettled([
    getCTAge(hostname),                          // CT on full hostname
  ]);

  // Corpus queries use registered_domain column — parameterized
  const corpusRows = d1`
    SELECT COUNT(DISTINCT install_id) as reports, AVG(confidence) as avg_conf,
           MAX(risk_level) as max_risk
    FROM verdicts
    WHERE registered_domain = ${registeredDomain} AND risk_level != 'safe'
  `;

  const feedRows = d1`
    SELECT COUNT(*) as hits, AVG(risk_score) as avg_score,
           GROUP_CONCAT(DISTINCT feed_source) as feeds
    FROM ingested_urls
    WHERE registered_domain = ${registeredDomain} AND risk_score >= 0.5
  `;

  return {
    hostname,
    registeredDomain,
    ct:     ct.status === 'fulfilled' ? ct.value : null,
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
    const regDomain  = extractRegisteredDomain(hostname);
    const subdomains = parts.slice(0, parts.length - regDomain.split('.').length).join('.');
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
  const label = intel.hostname !== intel.registeredDomain
    ? `\`${intel.hostname}\` (registered: \`${intel.registeredDomain}\`)`
    : `\`${intel.hostname}\``;
  lines.push(`**Checked:** ${label}`);
  if (intel.ct) {
    lines.push(`**CT log age:** ${intel.ct.ageDays} days (first cert ${new Date(intel.ct.firstSeenTs).toISOString().slice(0,10)}) — note: subdomain certs may differ from root domain`);
  } else {
    lines.push('**CT log age:** not found for this specific hostname (may be new, using wildcard cert, or private CA)');
  }
  lines.push(`**Corpus reports (${intel.registeredDomain}):** ${intel.corpus.reports} distinct installs, avg confidence ${intel.corpus.avg_conf?.toFixed(2) || 'N/A'}, max verdict ${intel.corpus.max_risk || 'none'}`);
  lines.push(`**Feed hits (${intel.registeredDomain}):** ${intel.feeds.hits} ingested URLs, avg score ${intel.feeds.avg_score?.toFixed(2) || 'N/A'}, sources: ${intel.feeds.feeds || 'none'}`);
  return lines.join('\n');
}

export function fmtHeuristics(result) {
  if (!result) return 'Could not parse URL.';
  if (result.signals.length === 0) return `Score: 0.00 — no URL-structure signals (expected if phishing relies on page content rather than suspicious URL patterns)`;
  const sigs = result.signals.map(s => `  - \`${s.type}\` (${s.severity}, +${s.weight}): ${s.desc}`).join('\n');
  return `Score: ${result.score.toFixed(2)}/1.00\n${sigs}`;
}
