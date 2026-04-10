#!/usr/bin/env node
// Virgil — Manual URL Ingestion
//
// Accepts a newline-separated list of URLs from stdin or URLS env var.
// Runs the same full analysis pipeline as ingest-feeds.js:
//   1. URL heuristics
//   2. Page source fetch + 1,109 source pattern matching
//   3. POST results to /v1/ingest worker endpoint
//
// Usage (local):
//   echo "https://evil.com/login" | node scripts/ingest-manual.js
//   cat urls.txt | node scripts/ingest-manual.js --dry-run
//
// Usage (GitHub Actions):
//   Set URLS env var to newline-separated URL list

import { createHash, createHmac } from 'crypto';
import { readFileSync }           from 'node:fs';
import { readFile }               from 'node:fs/promises';

const TELEMETRY_ENDPOINT = process.env.TELEMETRY_ENDPOINT;
const PIPELINE_SECRET    = process.env.PIPELINE_SECRET || '';
const CORE_RULES_PATH    = process.env.CORE_RULES_PATH || '../virgil-core-rules/rules/source';
const DRY_RUN            = process.argv.includes('--dry-run');
const CONCURRENCY        = 10;

// ── Load URLs ─────────────────────────────────────────────────────────────────

async function loadUrls() {
  // Priority: URLS env var → stdin → error
  if (process.env.URLS) {
    return process.env.URLS
      .split(/[\n,]+/)
      .map(u => u.trim())
      .filter(isValidUrl);
  }

  // Read from stdin
  if (!process.stdin.isTTY) {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf8')
      .split(/[\n,]+/)
      .map(u => u.trim())
      .filter(isValidUrl);
  }

  console.error('No URLs provided. Set URLS env var or pipe URLs via stdin.');
  process.exit(1);
}

// ── Source patterns ───────────────────────────────────────────────────────────

let SOURCE_PATTERNS = null;

async function loadSourcePatterns() {
  if (SOURCE_PATTERNS) return SOURCE_PATTERNS;
  const PATTERN_FILES = [
    'phishkitSignatures','credentialHarvesting','brandImpersonation',
    'socialEngineering','obfuscation','botEvasion','captchaGating',
    'cdnGating','cookieTheft','hostingPatterns','titleImpersonation',
    'typosquatPatterns','urlHeuristics',
  ];
  const patterns = [];
  for (const name of PATTERN_FILES) {
    try {
      const raw  = readFileSync(`${CORE_RULES_PATH}/${name}.json`, 'utf8');
      const data = JSON.parse(raw);
      patterns.push(...(data.patterns || data.sourcePatterns || []));
    } catch {}
  }
  SOURCE_PATTERNS = patterns;
  return patterns;
}

function runSourcePatterns(html, js, patterns) {
  const hits = [];
  for (const p of patterns) {
    try {
      let matched = false;
      if (p.patternString) {
        const target = p.source === 'js' ? js : p.source === 'html' ? html : html + '\n' + js;
        matched = new RegExp(p.patternString, p.patternFlags || 'i').test(target);
      } else if (p.match && p.condition) {
        const target = p.source === 'js' ? js : p.source === 'html' ? html : html + '\n' + js;
        const results = p.match.map(m =>
          m.content ? target.includes(m.content)
          : m.pattern ? new RegExp(m.pattern, m.flags || 'i').test(target)
          : false
        );
        const expr = p.condition.replace(/(\d+)/g, (_, i) => results[parseInt(i)] ? '1' : '0');
        matched = eval(expr.replace(/&/g, '&&').replace(/\|/g, '||')) === 1;
      }
      if (matched) hits.push({ type: p.id, description: p.description, severity: p.severity || 'medium', weight: p.weight || 0.10, group: p.group || 'unknown' });
    } catch {}
  }
  return hits;
}

function extractInlineJs(html) {
  const scripts = [];
  const scriptRe = /<script(?![^>]*\bsrc\b)[^>]*>([\s\S]*?)<\/script>/gi;
  const eventRe  = /\bon\w+\s*=\s*["']([^"']+)["']/gi;
  let m;
  while ((m = scriptRe.exec(html)) !== null) scripts.push(m[1]);
  while ((m = eventRe.exec(html))   !== null) scripts.push(m[1]);
  return scripts.join('\n');
}

// ── URL heuristics ────────────────────────────────────────────────────────────

function analyseUrl(url, feedSource = 'manual', pageData = null, sourcePatternHits = []) {
  try {
    const parsed    = new URL(url);
    const hostname  = parsed.hostname.toLowerCase();
    const parts     = hostname.split('.');
    const tld       = '.' + parts[parts.length - 1];
    const regDomain = parts.slice(-2).join('.');
    const subdomains = parts.slice(0, -2).join('.');
    const fullUrl   = url.toLowerCase();
    const signals   = [];
    let score       = 0;

    const addSig = (type, desc, severity, weight, meta = {}) => {
      signals.push({ type, desc, severity, weight, ...meta });
      score += weight;
    };

    const BRANDS = ['paypal','chase','wellsfargo','bankofamerica','citibank','capitalone',
      'coinbase','binance','metamask','ledger','trezor','opensea','microsoft','google',
      'okta','github','slack','zoom','amazon','apple','netflix','steam','ebay','stripe',
      'docusign','dropbox','adobe','linkedin','facebook','instagram'];
    const brandSub = BRANDS.find(b => subdomains.includes(b) && !regDomain.startsWith(b));
    if (brandSub) addSig('brand-in-subdomain', `"${brandSub}" in subdomain`, 'high', 0.40, { brand: brandSub });

    const norm = s => s.replace(/0/g,'o').replace(/1/g,'l').replace(/3/g,'e').replace(/4/g,'a').replace(/5/g,'s').replace(/vv/g,'w').replace(/rn/g,'m');
    const brandGlyph = BRANDS.find(b => !hostname.includes(b) && norm(hostname).includes(b));
    if (brandGlyph) addSig('homoglyph-substitution', `Normalises to "${brandGlyph}"`, 'high', 0.45, { brand: brandGlyph });

    const TLD_RISK = {'.xyz':0.20,'.top':0.20,'.club':0.15,'.online':0.15,'.site':0.15,'.live':0.15,'.click':0.20,'.loan':0.25,'.win':0.20,'.gq':0.30,'.ml':0.30,'.cf':0.30,'.ga':0.30,'.tk':0.30,'.pw':0.20};
    if (TLD_RISK[tld]) addSig('high-risk-tld', `TLD ${tld}`, TLD_RISK[tld] >= 0.25 ? 'high' : 'medium', TLD_RISK[tld], { tld });
    if (parts.length >= 4) addSig('deep-subdomain', `${parts.length - 2} subdomain levels`, 'low', 0.10);
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) addSig('ip-as-hostname', 'IP as hostname', 'high', 0.35);
    if (parsed.protocol === 'http:') addSig('no-tls', 'Plain HTTP', 'high', 0.25);
    const CRED = ['login','signin','verify','secure','account','password','recover','unlock'];
    const credHits = CRED.filter(k => fullUrl.includes(k));
    if (credHits.length >= 2) addSig('credential-keywords', `${credHits.length} keywords`, 'medium', 0.15, { keywords: credHits });
    const hyphens = (regDomain.replace(/\.[^.]+$/, '').match(/-/g) || []).length;
    if (hyphens >= 3) addSig('hyphenated-domain', `${hyphens} hyphens`, 'high', 0.25, { hyphens });
    else if (hyphens >= 2) addSig('hyphenated-domain', `${hyphens} hyphens`, 'medium', 0.15, { hyphens });
    if (/seed[-_]?phrase|recovery[-_]?phrase|private[-_]?key|connect[-_]?wallet/i.test(fullUrl)) addSig('crypto-attack', 'Crypto attack keyword', 'high', 0.45);

    const allSourceSignals = sourcePatternHits.map(h => ({ type: h.type, severity: h.severity, weight: h.weight, description: h.description }));
    const finalScore = Math.min(score + allSourceSignals.reduce((s, h) => s + h.weight, 0), 1.0);

    return {
      url, urlHash: sha256(url), registeredDomain: regDomain, tld,
      riskScore: finalScore,
      signals: [...signals.map(s => ({ type: s.type, severity: s.severity, weight: s.weight })), ...allSourceSignals],
      detectedBrand:   brandSub || brandGlyph || null,
      feedSource,
      pageTitle:       pageData?.title || null,
      hadPageContent:  !!pageData,
      urlFinal:        pageData?.url   || null,
      ingestedAt:      new Date().toISOString(),
    };
  } catch { return null; }
}

// ── Fetch page source ─────────────────────────────────────────────────────────

async function fetchPageSource(url) {
  if (!TELEMETRY_ENDPOINT) return null;
  try {
    const resp = await fetch(`${TELEMETRY_ENDPOINT}/fetch-source`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'Virgil-Intel-Sync/1.0' },
      body: JSON.stringify({ url, timeout: 8000 }),
      signal: AbortSignal.timeout(12000),
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    return data.ok ? data : null;
  } catch { return null; }
}

// ── POST to worker ────────────────────────────────────────────────────────────

async function postResult(result) {
  if (!TELEMETRY_ENDPOINT) throw new Error('TELEMETRY_ENDPOINT not set');
  const body      = JSON.stringify(result);
  const timestamp = Date.now();
  const sig       = createHmac('sha256', PIPELINE_SECRET).update(body + timestamp).digest('hex');
  const resp = await fetch(`${TELEMETRY_ENDPOINT}/ingest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Pipeline-Sig': sig, 'X-Pipeline-Ts': String(timestamp), 'User-Agent': 'Virgil-Intel-Sync/1.0' },
    body,
  });
  if (!resp.ok) throw new Error(`Worker ${resp.status}: ${(await resp.text()).slice(0, 100)}`);
}

function sha256(str) { return createHash('sha256').update(str).digest('hex'); }
function isValidUrl(u) { try { const p = new URL(u); return p.protocol === 'http:' || p.protocol === 'https:'; } catch { return false; } }

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const urls     = await loadUrls();
  const patterns = await loadSourcePatterns();

  console.log(`\nVirgil — Manual URL Ingestion`);
  console.log(`Mode:     ${DRY_RUN ? 'DRY RUN' : 'LIVE'}`);
  console.log(`URLs:     ${urls.length}`);
  console.log(`Patterns: ${patterns.length}`);
  if (!TELEMETRY_ENDPOINT) console.log(`⚠  TELEMETRY_ENDPOINT not set — page fetch + posting disabled`);
  console.log('');

  const results  = [];
  let done       = 0;

  for (let i = 0; i < urls.length; i += CONCURRENCY) {
    const batch = urls.slice(i, i + CONCURRENCY);
    const analysed = await Promise.all(batch.map(async url => {
      const urlResult = analyseUrl(url, 'manual');
      if (!urlResult) return null;
      if (patterns.length > 0 && TELEMETRY_ENDPOINT) {
        const pageData = await fetchPageSource(url);
        if (pageData?.source) {
          const html = pageData.source;
          const js   = extractInlineJs(html);
          const hits = runSourcePatterns(html, js, patterns);
          return analyseUrl(url, 'manual', pageData, hits);
        }
      }
      return urlResult;
    }));
    results.push(...analysed.filter(Boolean));
    done += batch.length;
    process.stdout.write(`\r  Analysing... ${done}/${urls.length}`);
  }
  console.log('');

  // Print results table
  console.log(`\n${'─'.repeat(80)}`);
  console.log(`${'URL'.padEnd(55)} ${'Score'.padEnd(7)} ${'Signals'}`);
  console.log('─'.repeat(80));
  for (const r of results.sort((a, b) => b.riskScore - a.riskScore)) {
    const urlShort  = r.url.length > 52 ? r.url.slice(0, 49) + '...' : r.url;
    const scoreStr  = r.riskScore.toFixed(2);
    const topSignal = r.signals[0]?.type || 'none';
    const content   = r.hadPageContent ? ' [+content]' : '';
    console.log(`${urlShort.padEnd(55)} ${scoreStr.padEnd(7)} ${topSignal}${content}`);
  }
  console.log('─'.repeat(80));
  console.log(`Analysed: ${results.length}/${urls.length} | Page content: ${results.filter(r => r.hadPageContent).length}`);

  if (DRY_RUN) {
    console.log('\n[dry-run] Skipping POST to worker');
    return;
  }

  // Post results
  console.log('');
  let posted = 0, skipped = 0, errors = 0;
  for (const result of results) {
    try {
      await postResult(result);
      posted++;
    } catch (e) {
      if (e.message?.includes('duplicate')) { skipped++; }
      else { errors++; console.error(`  ✗ ${result.registeredDomain}: ${e.message}`); }
    }
  }

  console.log(`\nPosted: ${posted} | Skipped (duplicate): ${skipped} | Errors: ${errors}`);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
