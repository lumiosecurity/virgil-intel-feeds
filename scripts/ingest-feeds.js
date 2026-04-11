#!/usr/bin/env node
// Virgil — Threat Feed Ingestion Pipeline
//
// Fetches phishing URLs from four public threat intelligence feeds,
// runs the same heuristic analysis used in the extension, and posts
// the results to the telemetry worker to build up the corpus.
//
// Usage:
//   node scripts/ingest-feeds.js                    # all feeds
//   node scripts/ingest-feeds.js openphish urlhaus  # specific feeds
//   node scripts/ingest-feeds.js --dry-run          # analyse only, no POST
//   node scripts/ingest-feeds.js --limit 100        # cap per feed
//
// Required env vars:
//   TELEMETRY_ENDPOINT   https://virgil-telemetry.example.workers.dev/v1
//   URLSCAN_API_KEY      free key from urlscan.io
//   PHISHTANK_APP_KEY    free key from phishtank.com/api_register.php
//   URLHAUS_AUTH_KEY     free key from auth.abuse.ch
//   PIPELINE_SECRET      HMAC secret shared with the worker (set in GH Secrets)
//
// OpenPhish requires no key.

import { createHash, createHmac }      from 'crypto';
import { execSync }        from 'node:child_process';
import { writeFileSync, readFileSync, unlinkSync } from 'node:fs';


// ── Source pattern matching (mirrors phishkit-detector.js logic) ──────────────

let SOURCE_PATTERNS = null;

async function loadSourcePatterns() {
  if (SOURCE_PATTERNS) return SOURCE_PATTERNS;

  // Load all pattern files from virgil-core-rules (cloned in CI alongside this script)
  // Falls back to empty set if not available
  const PATTERN_FILES = [
    'phishkitSignatures','credentialHarvesting','brandImpersonation',
    'socialEngineering','obfuscation','botEvasion','captchaGating',
    'cdnGating','cookieTheft','hostingPatterns','titleImpersonation',
    'typosquatPatterns','urlHeuristics',
  ];

  const patterns = [];
  const baseDir = process.env.CORE_RULES_PATH || '../virgil-core-rules/rules/source';

  for (const name of PATTERN_FILES) {
    try {
      const { readFileSync } = await import('node:fs');
      const raw  = readFileSync(`${baseDir}/${name}.json`, 'utf8');
      const data = JSON.parse(raw);
      const pats = data.patterns || data.sourcePatterns || [];
      patterns.push(...pats);
    } catch { /* file not available in this environment */ }
  }

  SOURCE_PATTERNS = patterns;
  if (patterns.length > 0) {
    console.log(`  Loaded ${patterns.length} source patterns`);
  }
  return patterns;
}

function runSourcePatterns(html, js, patterns) {
  const hits = [];

  for (const p of patterns) {
    try {
      let matched = false;

      if (p.patternString) {
        // Single-regex format
        const target = p.source === 'js' ? js : p.source === 'html' ? html : html + '\n' + js;
        const re = new RegExp(p.patternString, p.patternFlags || 'i');
        matched = re.test(target);
      } else if (p.match && p.condition) {
        // Multi-match format — evaluate boolean condition
        const target = p.source === 'js' ? js : p.source === 'html' ? html : html + '\n' + js;
        const results = p.match.map(m => {
          if (m.content)  return target.includes(m.content);
          if (m.pattern)  return new RegExp(m.pattern, m.flags || 'i').test(target);
          return false;
        });
        // Evaluate condition string: "0 & 1 & (2 | 3)" etc.
        const expr = p.condition.replace(/(\d+)/g, (_, i) => results[parseInt(i)] ? '1' : '0');
        matched = eval(expr.replace(/&/g, '&&').replace(/\|/g, '||')) === 1;
      }

      if (matched) {
        hits.push({
          type:        p.id,
          description: p.description,
          severity:    p.severity || 'medium',
          weight:      p.weight   || 0.10,
          group:       p.group    || 'unknown',
        });
      }
    } catch { /* bad regex — skip */ }
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

// ── Config ────────────────────────────────────────────────────────────────────

const TELEMETRY_ENDPOINT = process.env.TELEMETRY_ENDPOINT;
const PIPELINE_SECRET    = process.env.PIPELINE_SECRET || '';
const DRY_RUN  = process.argv.includes('--dry-run');
const LIMIT    = parseInt(process.argv.find(a => a.startsWith('--limit='))?.split('=')[1] || '500');
const TARGETS  = process.argv.slice(2).filter(a => !a.startsWith('--'));

// Concurrency: how many URLs to analyse simultaneously
const CONCURRENCY = 20;

// Dedup window: skip URLs we've seen recently (keyed by hash in memory)
const seen = new Set();


// ── Feed definitions ──────────────────────────────────────────────────────────

const FEEDS = [
  {
    name: 'openphish',
    description: 'OpenPhish Community Feed — active phishing URLs, 12h refresh',
    fetch: fetchOpenPhish,
  },
  {
    name: 'phishtank',
    description: 'PhishTank online-valid — community-verified active phishes',
    fetch: fetchPhishTank,
  },
  {
    name: 'urlhaus',
    description: 'abuse.ch URLhaus — recent malware distribution URLs',
    fetch: fetchURLhaus,
  },
  {
    name: 'urlscan',
    description: 'URLScan.io — malicious verdict scans from last 24h',
    fetch: fetchURLScan,
  },
];


// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const feedsToRun = TARGETS.length
    ? FEEDS.filter(f => TARGETS.includes(f.name))
    : FEEDS;

  if (feedsToRun.length === 0) {
    console.error('No matching feeds. Available:', FEEDS.map(f => f.name).join(', '));
    process.exit(1);
  }

  console.log(`\nVirgil — Threat Feed Ingestion`);
  console.log(`Mode:   ${DRY_RUN ? 'DRY RUN (no POST)' : 'LIVE'}`);
  console.log(`Limit:  ${LIMIT} URLs per feed`);
  console.log(`Feeds:  ${feedsToRun.map(f => f.name).join(', ')}\n`);

  const totals = { fetched: 0, analysed: 0, posted: 0, errors: 0, skipped: 0 };

  for (const feed of feedsToRun) {
    console.log(`\n▸ ${feed.name}: ${feed.description}`);

    let urls = [];
    try {
      process.stdout.write('  Fetching... ');
      urls = await feed.fetch();
      urls = urls.slice(0, LIMIT);
      console.log(`${urls.length} URLs`);
      totals.fetched += urls.length;
    } catch (e) {
      console.log(`✗ fetch failed: ${e.message}`);
      totals.errors++;
      continue;
    }

    // Load source patterns once per run
    const patterns = await loadSourcePatterns();

    // Analyse in concurrent batches
    let done = 0;
    const results = [];

    for (let i = 0; i < urls.length; i += CONCURRENCY) {
      const batch = urls.slice(i, i + CONCURRENCY);
      const analysed = await Promise.all(batch.map(async url => {
        // Step 1: URL heuristics (fast, no network)
        const urlResult = analyseUrl(url, feed.name);
        if (!urlResult) return null;

        // Step 2: Fetch page source via worker proxy and run source patterns.
        // NOTE: do NOT call analyseUrl() again — the URL hash is already in `seen`
        // from step 1 and a second call would hit the dedup guard and return null.
        // Instead, merge source hits directly into the result from step 1.
        if (patterns.length > 0 && TELEMETRY_ENDPOINT) {
          const pageData = await fetchPageSource(url);
          if (pageData?.source) {
            const html       = pageData.source;
            const js         = extractInlineJs(html);
            const sourceHits = runSourcePatterns(html, js, patterns);

            // Merge source pattern signals and re-cap the score
            const sourceSignals = sourceHits.map(h => ({
              type:        h.type,
              severity:    h.severity,
              weight:      h.weight,
              description: h.description,
            }));
            const sourceScore = sourceSignals.reduce((s, h) => s + h.weight, 0);

            urlResult.signals.push(...sourceSignals);
            urlResult.riskScore     = Math.min(urlResult.riskScore + sourceScore, 1.0);
            urlResult.pageTitle     = pageData.title || null;
            urlResult.hadPageContent = true;
          }
        }
        return urlResult;
      }));
      results.push(...analysed.filter(Boolean));
      done += batch.length;
      process.stdout.write(`\r  Analysing... ${done}/${urls.length}`);
    }
    const sourceCount = results.filter(r => r.hadPageContent).length;
    console.log(`\r  Analysed: ${results.length} with signals (${sourceCount} with page content)`);
    totals.analysed += results.length;

    // Post results
    if (!DRY_RUN && results.length > 0) {
      process.stdout.write(`  Posting ${results.length} results... `);
      let posted = 0;
      let skipped = 0;
      for (const result of results) {
        try {
          const res = await postResult(result);
          if (res?.skipped) {
            skipped++;
          } else {
            posted++;
          }
        } catch (e) {
          totals.errors++;
        }
      }
      console.log(`✓ ${posted} new, ${skipped} skipped (already seen)`);
      totals.posted  += posted;
      totals.skipped += skipped;
    } else if (DRY_RUN && results.length > 0) {
      console.log(`  [dry-run] Would post ${results.length} results`);
      // Print a sample
      const sample = results.slice(0, 3);
      sample.forEach(r => {
        console.log(`  Sample: ${r.registeredDomain} riskScore=${r.riskScore.toFixed(2)} signals=${r.signals.length}`);
      });
    }
  }

  console.log(`\n${'─'.repeat(50)}`);
  console.log(`Fetched:   ${totals.fetched}`);
  console.log(`Analysed:  ${totals.analysed}`);
  console.log(`Posted:    ${totals.posted}`);
  console.log(`Skipped:   ${totals.skipped}`);
  console.log(`Errors:    ${totals.errors}`);

  if (totals.errors > 0 && !DRY_RUN) process.exit(1);
}


// ── Feed fetchers ─────────────────────────────────────────────────────────────

async function fetchOpenPhish() {
  const resp = await get('https://openphish.com/feed.txt', {
    'User-Agent': 'Virgil-Intel-Sync/1.0 (github.com/lumiosecurity)',
  });
  return resp.trim().split('\n').map(u => u.trim()).filter(isValidUrl);
}

async function fetchPhishTank() {
  const key = process.env.PHISHTANK_APP_KEY;
  const url = key
    ? `https://data.phishtank.com/data/${key}/online-valid.json.bz2`
    : 'https://data.phishtank.com/data/online-valid.json.bz2';

  const resp = await fetch(url, {
    headers: { 'User-Agent': 'phishtank/virgil (github.com/lumiosecurity)' },
  });

  if (!resp.ok) throw new Error(`PhishTank HTTP ${resp.status}`);

  // Write bz2 to temp file, decompress with system bunzip2
  const tmpBz2  = '/tmp/phishtank.json.bz2';
  const tmpJson = '/tmp/phishtank.json';
  const buf = Buffer.from(await resp.arrayBuffer());
  writeFileSync(tmpBz2, buf);

  try {
    execSync(`bunzip2 -f -k ${tmpBz2}`, { stdio: 'pipe' });
  } catch (e) {
    throw new Error(`bunzip2 failed: ${e.message}`);
  }

  const json = JSON.parse(readFileSync(tmpJson, 'utf8'));

  try { unlinkSync(tmpBz2); unlinkSync(tmpJson); } catch {}

  return json
    .filter(e => e.online === 'yes' && e.verified === 'yes')
    .map(e => e.url)
    .filter(isValidUrl);
}

async function fetchURLhaus() {
  // Public CSV feed — no auth required, updated every 5 minutes
  // https://urlhaus.abuse.ch/downloads/csv_recent/
  const resp = await fetch('https://urlhaus.abuse.ch/downloads/csv_recent/', {
    headers: { 'User-Agent': 'Virgil-Intel-Sync/1.0 (github.com/lumiosecurity)' },
    signal: AbortSignal.timeout(15000),
  });

  if (!resp.ok) throw new Error(`URLhaus HTTP ${resp.status}`);
  const text = await resp.text();

  // CSV: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
  // Lines starting with # are comments
  return text
    .split('\n')
    .filter(line => line && !line.startsWith('#'))
    .map(line => {
      // URL is the 3rd column — strip surrounding quotes
      const cols = line.match(/(".*?"|[^,]+)/g) || [];
      return cols[2]?.replace(/^"|"$/g, '').trim();
    })
    .filter(isValidUrl)
    .slice(0, 500);
}

async function fetchURLScan() {
  const key = process.env.URLSCAN_API_KEY;
  if (!key) {
    console.log('  [skip] URLSCAN_API_KEY not set');
    return [];
  }

  // Query: malicious verdicts from last 24 hours
  const params = new URLSearchParams({
    q:    'verdicts.malicious:true AND date:>now-24h',
    size: '500',
  });

  const resp = await fetch(`https://urlscan.io/api/v1/search/?${params}`, {
    headers: {
      'API-Key':    key,
      'User-Agent': 'Virgil-Intel-Sync/1.0',
    },
  });

  if (resp.status === 403) {
    console.log('  [skip] URLScan API key invalid or not set — get a free key at urlscan.io');
    return [];
  }
  if (!resp.ok) throw new Error(`URLScan HTTP ${resp.status}`);
  const data = await resp.json();

  return (data.results || [])
    .map(r => r.page?.url)
    .filter(isValidUrl);
}


// ── Heuristic analysis (port of domain-analyzer.js logic to Node) ─────────────
// Mirrors the extension's signal detection — same weights, same logic.
// This is the source of truth for the corpus signal data.

function analyseUrl(url, feedSource, pageData = null, sourcePatternHits = []) {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    if (!hostname) return null;

    // Dedup
    const hash = simpleHash(url);
    if (seen.has(hash)) return null;
    seen.add(hash);

    const parts    = hostname.split('.');
    const tld      = '.' + parts[parts.length - 1];
    const regDomain= parts.slice(-2).join('.');
    const subdomains = parts.slice(0, -2).join('.');
    const fullUrl  = url.toLowerCase();

    const signals  = [];
    let score      = 0;

    function addSig(type, description, severity, weight, meta = {}) {
      signals.push({ type, description, severity, weight, ...meta });
      score += weight;
    }

    // S01: Brand in subdomain
    const BRANDS = [
      'paypal','chase','wellsfargo','bankofamerica','citibank','capitalone',
      'coinbase','binance','metamask','ledger','trezor','opensea',
      'microsoft','google','okta','github','slack','zoom',
      'amazon','apple','netflix','steam','ebay','stripe',
      'docusign','dropbox','adobe','linkedin','facebook','instagram',
    ];
    const brandSub = BRANDS.find(b => subdomains.includes(b) && !regDomain.startsWith(b));
    if (brandSub) addSig('brand-in-subdomain', `"${brandSub}" in subdomain of ${regDomain}`, 'high', 0.40, { brand: brandSub });

    // S02: Homoglyph
    const normalized = normalizeHomoglyphs(hostname);
    const brandGlyph = BRANDS.find(b => !hostname.includes(b) && normalized.includes(b));
    if (brandGlyph) addSig('homoglyph-substitution', `Hostname normalizes to "${brandGlyph}"`, 'high', 0.45, { brand: brandGlyph });

    // S03: Suspicious TLD
    const TLD_RISK = {
      '.xyz':0.20,'.top':0.20,'.club':0.15,'.online':0.15,'.site':0.15,
      '.live':0.15,'.click':0.20,'.buzz':0.15,'.loan':0.25,'.win':0.20,
      '.gq':0.30,'.ml':0.30,'.cf':0.30,'.ga':0.30,'.tk':0.30,
      '.pw':0.20,'.cc':0.15,'.su':0.20,'.download':0.20,'.stream':0.15,
    };
    const tldRisk = TLD_RISK[tld];
    if (tldRisk) addSig('high-risk-tld', `TLD ${tld} has elevated abuse rate`, tldRisk >= 0.25 ? 'high' : 'medium', tldRisk, { tld });

    // S04: Deep subdomain
    if (parts.length >= 4) addSig('deep-subdomain', `${parts.length - 2} subdomain levels`, 'low', 0.10);

    // S05: IP hostname
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      addSig('ip-as-hostname', 'IP address as hostname', 'high', 0.35);
    }

    // S06: No TLS
    if (parsed.protocol === 'http:') addSig('no-tls', 'Plain HTTP', 'high', 0.25);

    // S07: Credential keywords
    const CRED = ['login','signin','verify','verification','secure','account','password','recover','unlock','suspended','expired','validate'];
    const credHits = CRED.filter(k => fullUrl.includes(k));
    if (credHits.length >= 2) addSig('credential-keywords', `${credHits.length} credential keywords: ${credHits.slice(0,3).join(',')}`, 'medium', 0.15, { keywords: credHits });

    // S08: Hyphens in registered domain
    const domainLabel = regDomain.replace(/\.[^.]+$/, '');
    const hyphens = (domainLabel.match(/-/g) || []).length;
    if (hyphens >= 3) addSig('hyphenated-domain', `${hyphens} hyphens in domain label`, 'high', 0.25, { hyphens });
    else if (hyphens >= 2) addSig('hyphenated-domain', `${hyphens} hyphens in domain label`, 'medium', 0.15, { hyphens });

    // S09: Crypto attack patterns
    const CRYPTO = /seed[-_]?phrase|recovery[-_]?phrase|private[-_]?key|connect[-_]?wallet|wallet[-_]?verif|claim[-_]?token|airdrop/i;
    if (CRYPTO.test(fullUrl)) addSig('crypto-attack-pattern', 'Crypto/wallet attack keyword in URL', 'high', 0.45);

    // S10: High entropy domain
    const entropy = shannonEntropy(domainLabel);
    if (entropy > 3.8 && domainLabel.length > 8) addSig('high-entropy-domain', `Domain entropy ${entropy.toFixed(2)}`, 'medium', 0.15);

    score = Math.min(score, 1.0);

    // Only return if meaningful signal
    if (score < 0.10 && signals.length === 0) return null;

    // Merge source pattern hits into signals
    const allSourceSignals = sourcePatternHits.map(h => ({
      type:        h.type,
      severity:    h.severity,
      weight:      h.weight,
      description: h.description,
    }));

    // Add source pattern weights to score
    const sourceScore = allSourceSignals.reduce((s, h) => s + h.weight, 0);
    const finalScore  = Math.min(score + sourceScore, 1.0);

    return {
      url,
      urlHash:          sha256Sync(url),
      registeredDomain: regDomain,
      tld,
      riskScore:        finalScore,
      signals:          [
        ...signals.map(s => ({ type: s.type, severity: s.severity, weight: s.weight })),
        ...allSourceSignals,
      ],
      detectedBrand:    brandSub || brandGlyph || null,
      feedSource,
      pageTitle:        pageData?.title || null,
      hadPageContent:   !!pageData,
      ingestedAt:       new Date().toISOString(),
    };

  } catch {
    return null;
  }
}



// ── Fetch page source via worker proxy ───────────────────────────────────────

async function fetchPageSource(url) {
  if (!TELEMETRY_ENDPOINT) return null;
  try {
    const resp = await fetch(`${TELEMETRY_ENDPOINT}/fetch-source`, {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent':   'Virgil-Intel-Sync/1.0',
        // fetch-source accepts requests from localhost/file origins — no HMAC needed
      },
      body:    JSON.stringify({ url, timeout: 8000 }),
      signal:  AbortSignal.timeout(12000),
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    return data.ok ? data : null;
  } catch { return null; }
}

// ── POST to telemetry worker ───────────────────────────────────────────────────

async function postResult(result) {
  if (!TELEMETRY_ENDPOINT) throw new Error('TELEMETRY_ENDPOINT not set');

  const body      = JSON.stringify(result);
  const timestamp = Date.now();
  const sig       = hmacSign(PIPELINE_SECRET, body + timestamp);

  const resp = await fetch(`${TELEMETRY_ENDPOINT}/ingest`, {
    method:  'POST',
    headers: {
      'Content-Type':      'application/json',
      'X-Pipeline-Sig':    sig,
      'X-Pipeline-Ts':     String(timestamp),
      'User-Agent':        'Virgil-Intel-Sync/1.0',
    },
    body,
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`Worker ${resp.status}: ${text.slice(0, 100)}`);
  }

  return resp.json().catch(() => ({}));
}


// ── Utilities ─────────────────────────────────────────────────────────────────

function isValidUrl(u) {
  if (!u || typeof u !== 'string') return false;
  try {
    const p = new URL(u.trim());
    return p.protocol === 'http:' || p.protocol === 'https:';
  } catch { return false; }
}

function normalizeHomoglyphs(str) {
  const MAP = { '0':'o','1':'l','3':'e','4':'a','5':'s','6':'b','8':'b','9':'g','vv':'w','rn':'m' };
  let r = str;
  for (const [k,v] of Object.entries(MAP)) r = r.replaceAll(k, v);
  return r;
}

function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch]||0)+1;
  const len = str.length;
  return Object.values(freq).reduce((s,c) => { const p=c/len; return s - p*Math.log2(p); }, 0);
}

function sha256Sync(str) {
  return createHash('sha256').update(str).digest('hex');
}

function simpleHash(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return h.toString(16);
}

function hmacSign(secret, data) {
  return createHmac('sha256', secret).update(data).digest('hex');
}

async function get(url, headers = {}) {
  const resp = await fetch(url, { headers: { 'User-Agent': 'Virgil-Intel-Sync/1.0', ...headers } });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${url}`);
  return resp.text();
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
