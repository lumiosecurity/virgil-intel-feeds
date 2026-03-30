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
import { createBunzip2 }   from 'node:zlib';
import { pipeline }        from 'node:stream/promises';
import { Writable }        from 'node:stream';

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

    // Analyse in concurrent batches
    let done = 0;
    const results = [];

    for (let i = 0; i < urls.length; i += CONCURRENCY) {
      const batch = urls.slice(i, i + CONCURRENCY);
      const analysed = await Promise.all(batch.map(url => analyseUrl(url, feed.name)));
      results.push(...analysed.filter(Boolean));
      done += batch.length;
      process.stdout.write(`\r  Analysing... ${done}/${urls.length}`);
    }
    console.log(`\r  Analysed: ${results.length} produced signals`);
    totals.analysed += results.length;

    // Post results
    if (!DRY_RUN && results.length > 0) {
      process.stdout.write(`  Posting ${results.length} results... `);
      let posted = 0;
      for (const result of results) {
        try {
          await postResult(result);
          posted++;
        } catch (e) {
          totals.errors++;
        }
      }
      console.log(`✓ ${posted} posted`);
      totals.posted += posted;
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
    headers: {
      'User-Agent': 'phishtank/virgil (github.com/lumiosecurity)',
    },
  });

  if (!resp.ok) throw new Error(`PhishTank HTTP ${resp.status}`);

  // Decompress bz2 stream
  const chunks = [];
  const bz2 = createBunzip2();
  const collect = new Writable({
    write(chunk, _enc, cb) { chunks.push(chunk); cb(); }
  });

  await pipeline(resp.body, bz2, collect);
  const json = JSON.parse(Buffer.concat(chunks).toString('utf8'));

  return json
    .filter(e => e.online === 'yes' && e.verified === 'yes')
    .map(e => e.url)
    .filter(isValidUrl);
}

async function fetchURLhaus() {
  const key = process.env.URLHAUS_AUTH_KEY;
  if (!key) throw new Error('URLHAUS_AUTH_KEY not set');

  const resp = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/', {
    method: 'POST',
    headers: {
      'Auth-Key': key,
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'Virgil-Intel-Sync/1.0',
    },
    body: 'limit=1000',
  });

  if (!resp.ok) throw new Error(`URLhaus HTTP ${resp.status}`);
  const data = await resp.json();

  return (data.urls || [])
    .filter(e => e.url_status === 'online')
    .map(e => e.url)
    .filter(isValidUrl);
}

async function fetchURLScan() {
  const key = process.env.URLSCAN_API_KEY;
  if (!key) throw new Error('URLSCAN_API_KEY not set');

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

  if (!resp.ok) throw new Error(`URLScan HTTP ${resp.status}`);
  const data = await resp.json();

  return (data.results || [])
    .map(r => r.page?.url)
    .filter(isValidUrl);
}


// ── Heuristic analysis (port of domain-analyzer.js logic to Node) ─────────────
// Mirrors the extension's signal detection — same weights, same logic.
// This is the source of truth for the corpus signal data.

function analyseUrl(url, feedSource) {
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

    return {
      url,
      urlHash: sha256Sync(url),
      registeredDomain: regDomain,
      tld,
      riskScore: score,
      signals: signals.map(s => ({ type: s.type, severity: s.severity, weight: s.weight })),
      detectedBrand: brandSub || brandGlyph || null,
      feedSource,
      ingestedAt: new Date().toISOString(),
    };

  } catch {
    return null;
  }
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
