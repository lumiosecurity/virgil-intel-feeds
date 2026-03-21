#!/usr/bin/env node
// Virgil — Sublime Security Static Files Sync
// Fetches all relevant lists from sublime-security/static-files on GitHub
// and normalizes them into Virgil's intel-feed JSON format.
//
// Usage:
//   node scripts/sync-sublime.js              # sync all feeds
//   node scripts/sync-sublime.js suspicious_tlds free_subdomain_hosts
//   node scripts/sync-sublime.js --dry-run    # print what would change, no writes
//   GITHUB_TOKEN=ghp_... node scripts/sync-sublime.js  # higher rate limit
//
// Output: feeds/{name}.json  — one file per Sublime list
//         feeds/compiled.json — merged runtime file consumed by the extension

import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FEEDS_DIR = join(__dirname, '../feeds');
const COMPILED_PATH = join(FEEDS_DIR, 'compiled.json');

const RAW_BASE = 'https://raw.githubusercontent.com/sublime-security/static-files/master';

// ── Feed definitions ──────────────────────────────────────────────────────────
// Each entry describes one Sublime list file and how to parse + use it.
// 'parser' controls how the raw text is turned into a JS array.
// 'role' is what Virgil uses it for (informational + drives compiled output).

const FEEDS = [
  {
    name: 'suspicious_tlds',
    file: 'suspicious_tlds.txt',
    parser: 'lines',           // one entry per line, strip comments (#)
    role:  'tld_risk',         // replaces/augments TLD_RISK in domain-analyzer
    description: 'TLDs frequently abused, free to register, or rarely used legitimately',
    defaultWeight: 0.20,       // weight assigned when added to TLD_RISK
  },
  {
    name: 'free_subdomain_hosts',
    file: 'free_subdomain_hosts.txt',
    parser: 'lines',
    role:  'free_subdomain_hosts',  // new signal: brand on free subdomain host
    description: 'Sites allowing anyone to create subdomains and host arbitrary content',
  },
  {
    name: 'free_file_hosts',
    file: 'free_file_hosts.txt',
    parser: 'lines',
    role:  'free_file_hosts',
    description: 'Sites allowing anyone to upload and serve files publicly',
  },
  {
    name: 'url_shorteners',
    file: 'url_shorteners.txt',
    parser: 'lines',
    role:  'url_shorteners',
    description: 'URL shorteners that can mask phishing destinations',
  },
  {
    name: 'disposable_email_providers',
    file: 'disposable_email_providers.txt',
    parser: 'lines',
    role:  'disposable_email',
    description: 'Throwaway email providers — suspicious as form submission targets',
  },
  {
    name: 'free_email_providers',
    file: 'free_email_providers.txt',
    parser: 'lines',
    role:  'free_email',
    description: 'Free email providers — suspicious as credential form POST destinations',
  },
  {
    name: 'suspicious_content',
    file: 'suspicious_content.txt',
    parser: 'lines',
    role:  'suspicious_content_phrases',
    description: 'Words and phrases suspicious in phishing page body content',
  },
  {
    name: 'suspicious_subjects',
    file: 'suspicious_subjects.txt',
    parser: 'lines',
    role:  'suspicious_subject_phrases',
    description: 'Words and phrases suspicious in phishing lure subjects/headings',
  },
  {
    name: 'suspicious_subjects_regex',
    file: 'suspicious_subjects_regex.txt',
    parser: 'lines',
    role:  'suspicious_subject_regex',
    description: 'Regex patterns for suspicious subject/heading lures',
  },
  {
    name: 'file_extensions_macros',
    file: 'file_extensions_macros.txt',
    parser: 'lines',
    role:  'macro_extensions',
    description: 'Macro-capable file extensions — suspicious as download links on credential pages',
  },
  {
    name: 'file_extensions_common_archives',
    file: 'file_extensions_common_archives.txt',
    parser: 'lines',
    role:  'archive_extensions',
    description: 'Archive extensions used to deliver malicious payloads',
  },
];

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const args    = process.argv.slice(2);
  const dryRun  = args.includes('--dry-run');
  const targets = args.filter(a => !a.startsWith('--'));
  const token   = process.env.GITHUB_TOKEN;

  const feedsToSync = targets.length
    ? FEEDS.filter(f => targets.includes(f.name))
    : FEEDS;

  if (feedsToSync.length === 0) {
    console.error('No matching feeds. Available:', FEEDS.map(f => f.name).join(', '));
    process.exit(1);
  }

  if (!dryRun) mkdirSync(FEEDS_DIR, { recursive: true });

  console.log(`\nVirgil — Sublime Security Feed Sync`);
  console.log(`Mode: ${dryRun ? 'DRY RUN' : 'LIVE WRITE'}`);
  console.log(`Feeds: ${feedsToSync.map(f => f.name).join(', ')}\n`);

  const results = {};
  let hasErrors = false;

  for (const feed of feedsToSync) {
    process.stdout.write(`  ${feed.name} ... `);
    try {
      const raw      = await fetchFile(feed.file, token);
      const entries  = parse(raw, feed.parser);
      const outPath  = join(FEEDS_DIR, `${feed.name}.json`);

      // Load existing to detect changes
      let existing = [];
      if (existsSync(outPath)) {
        try { existing = JSON.parse(readFileSync(outPath, 'utf8')).entries || []; } catch {}
      }

      const added   = entries.filter(e => !existing.includes(e)).length;
      const removed = existing.filter(e => !entries.includes(e)).length;

      const feedDoc = {
        _meta: {
          source:      `https://github.com/sublime-security/static-files/blob/master/${feed.file}`,
          syncedAt:    new Date().toISOString(),
          role:        feed.role,
          description: feed.description,
          count:       entries.length,
          ...(feed.defaultWeight && { defaultWeight: feed.defaultWeight }),
        },
        entries,
      };

      if (!dryRun) writeFileSync(outPath, JSON.stringify(feedDoc, null, 2));

      console.log(`✓ ${entries.length} entries (+${added} -${removed})`);
      results[feed.name] = feedDoc;

    } catch (err) {
      console.log(`✗ FAILED: ${err.message}`);
      hasErrors = true;
    }
  }

  // Compile all feeds into single runtime file
  console.log('\n  Compiling runtime feeds...');
  const compiled = compileFeeds(results);
  if (!dryRun) {
    writeFileSync(COMPILED_PATH, JSON.stringify(compiled, null, 2));
    console.log(`  ✓ Written to feeds/compiled.json (${JSON.stringify(compiled).length} bytes)`);
  } else {
    console.log(`  [dry-run] Would write feeds/compiled.json`);
  }

  // Print summary
  console.log('\nSummary:');
  for (const [name, doc] of Object.entries(results)) {
    console.log(`  ${name}: ${doc._meta.count} entries`);
  }

  process.exit(hasErrors ? 1 : 0);
}

// ── Compiler — merges feeds into the structure the extension loads at runtime ──

function compileFeeds(results) {
  // Load all existing feed files if not passed in this run
  const all = { ...results };
  for (const feed of FEEDS) {
    if (all[feed.name]) continue;
    const outPath = join(FEEDS_DIR, `${feed.name}.json`);
    if (existsSync(outPath)) {
      try { all[feed.name] = JSON.parse(readFileSync(outPath, 'utf8')); } catch {}
    }
  }

  // Build TLD risk map from suspicious_tlds
  const tldRisk = {};
  const tldFeed = all['suspicious_tlds'];
  if (tldFeed) {
    for (const tld of (tldFeed.entries || [])) {
      const key = tld.startsWith('.') ? tld : `.${tld}`;
      // Preserve any existing weight, default to feed's defaultWeight
      tldRisk[key] = tldFeed._meta.defaultWeight || 0.20;
    }
  }

  return {
    _meta: {
      compiledAt: new Date().toISOString(),
      sources: Object.values(all).map(f => f._meta?.source).filter(Boolean),
    },
    tldRisk,
    freeSubdomainHosts: toSet(all, 'free_subdomain_hosts'),
    freeFileHosts:      toSet(all, 'free_file_hosts'),
    urlShorteners:      toSet(all, 'url_shorteners'),
    disposableEmail:    toSet(all, 'disposable_email_providers'),
    freeEmail:          toSet(all, 'free_email_providers'),
    suspiciousContent:  toSet(all, 'suspicious_content'),
    suspiciousSubjects: toSet(all, 'suspicious_subjects'),
    suspiciousSubjectsRegex: toSet(all, 'suspicious_subjects_regex'),
    macroExtensions:    toSet(all, 'file_extensions_macros'),
    archiveExtensions:  toSet(all, 'file_extensions_common_archives'),
  };
}

function toSet(all, name) {
  return (all[name]?.entries || []);
}

// ── Fetcher ───────────────────────────────────────────────────────────────────

async function fetchFile(filename, token) {
  const url = `${RAW_BASE}/${filename}`;
  const headers = { 'User-Agent': 'virgil-intel-sync/1.0' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const resp = await fetch(url, { headers });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} fetching ${filename}`);
  return resp.text();
}

// ── Parsers ───────────────────────────────────────────────────────────────────

function parse(raw, parserType) {
  if (parserType === 'lines') {
    return raw
      .split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#'))
      .map(l => l.toLowerCase());
  }
  throw new Error(`Unknown parser: ${parserType}`);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
