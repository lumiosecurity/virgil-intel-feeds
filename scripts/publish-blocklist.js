#!/usr/bin/env node
// Virgil — Community Blocklist Publisher
//
// Queries the telemetry D1 database for high-confidence phishing domains
// and publishes blocklist.json to the docs/ directory (served via GitHub Pages).
//
// Qualification criteria:
//   - riskLevel = 'dangerous'
//   - confidence >= 0.85
//   - Reported by >= 3 distinct install IDs (prevents single-user false positives)
//   - First seen within last 30 days (entries expire automatically)
//   - Not in the hardcoded allowlist
//
// Usage:
//   node scripts/publish-blocklist.js
//   WRANGLER_ENV=production node scripts/publish-blocklist.js
//
// Requires:
//   wrangler installed and authenticated
//   D1 database bound as DB in wrangler.toml

import { execSync }    from 'child_process';
import { writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR   = join(__dirname, '../docs');
const OUT_FILE  = join(OUT_DIR, 'blocklist.json');

// Must match HARDCODED_ALLOWLIST in blocklist.js
const ALLOWLIST = new Set([
  'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
  'paypal.com', 'github.com', 'twitter.com', 'linkedin.com', 'netflix.com',
  'cloudflare.com', 'stripe.com', 'okta.com', 'coinbase.com', 'chase.com',
]);

const MIN_REPORTS    = 3;
const MIN_CONFIDENCE = 0.85;
const MAX_AGE_DAYS   = 30;

async function main() {
  console.log('\nVirgil — Blocklist Publisher');

  // Query D1 via wrangler
  console.log('Querying D1 corpus...');
  const sql = `
    SELECT
      registered_domain,
      COUNT(DISTINCT install_id) as report_count,
      AVG(confidence)           as avg_confidence,
      MAX(created_at)           as last_seen,
      MIN(created_at)           as first_seen,
      risk_level
    FROM verdicts
    WHERE
      risk_level = 'dangerous'
      AND confidence >= ${MIN_CONFIDENCE}
      AND created_at >= datetime('now', '-${MAX_AGE_DAYS} days')
      AND registered_domain IS NOT NULL
      AND registered_domain != ''
    GROUP BY registered_domain
    HAVING COUNT(DISTINCT install_id) >= ${MIN_REPORTS}
    ORDER BY report_count DESC, avg_confidence DESC
    LIMIT 10000
  `.trim().replace(/\s+/g, ' ');

  let rows = [];
  try {
    const output = execSync(
      `wrangler d1 execute virgil-telemetry --remote --command="${sql.replace(/"/g, '\\"')}" --json`,
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    );
    const result = JSON.parse(output);
    rows = result?.[0]?.results || [];
  } catch (e) {
    console.error('D1 query failed:', e.message);
    rows = [];
  }

  console.log(`  Raw results: ${rows.length} candidate domains`);

  // Filter allowlist + validate domain format
  const qualified = rows
    .map(r => r.registered_domain?.toLowerCase().trim())
    .filter(d => d && /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d))
    .filter(d => !ALLOWLIST.has(d))
    .filter((d, i, arr) => arr.indexOf(d) === i); // deduplicate

  console.log(`  Qualified:   ${qualified.length} domains after filtering`);

  // Also pull from ingested feed URLs (confirmed by multiple feed sources)
  const feedSql = `
    SELECT
      registered_domain,
      COUNT(DISTINCT feed_source) as feed_count,
      AVG(risk_score)             as avg_score,
      MAX(ingested_at)            as last_seen
    FROM ingested_urls
    WHERE
      risk_score >= 0.80
      AND ingested_at >= datetime('now', '-7 days')
      AND registered_domain IS NOT NULL
    GROUP BY registered_domain
    HAVING COUNT(DISTINCT feed_source) >= 2
    ORDER BY feed_count DESC, avg_score DESC
    LIMIT 5000
  `.trim().replace(/\s+/g, ' ');

  let feedRows = [];
  try {
    const feedOutput = execSync(
      `wrangler d1 execute virgil-telemetry --remote --command="${feedSql.replace(/"/g, '\\"')}" --json`,
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    );
    const feedResult = JSON.parse(feedOutput);
    feedRows = feedResult?.[0]?.results || [];
  } catch (e) {
    console.warn('Feed D1 query failed (non-fatal):', e.message);
  }

  const feedDomains = feedRows
    .map(r => r.registered_domain?.toLowerCase().trim())
    .filter(d => d && /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d))
    .filter(d => !ALLOWLIST.has(d))
    .filter(d => !qualified.includes(d));

  console.log(`  Feed-confirmed: ${feedDomains.length} additional domains`);

  const allDomains = [...qualified, ...feedDomains];
  console.log(`  Total:       ${allDomains.length} domains in blocklist`);

  // Build output
  const blocklist = {
    version:      new Date().toISOString().slice(0, 10),
    generatedAt:  new Date().toISOString(),
    domainCount:  allDomains.length,
    criteria: {
      minReports:    MIN_REPORTS,
      minConfidence: MIN_CONFIDENCE,
      maxAgeDays:    MAX_AGE_DAYS,
    },
    domains: allDomains,
  };

  // Write output
  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(OUT_FILE, JSON.stringify(blocklist, null, 2));
  console.log(`\n✓ Written to ${OUT_FILE}`);
  console.log(`  ${allDomains.length} domains, ${JSON.stringify(blocklist).length} bytes`);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
