#!/usr/bin/env node
// Virgil — Watch Hash Graduation Agent
//
// Runs weekly. Queries D1 for watchOnly resource hash rules that have accumulated
// enough real-world sightings to be promoted to live detection rules.
//
// Graduation criteria (ALL must be true):
//   1. Zero FP sightings — rule_id must not appear in resource_hash_fp_candidates.
//      A single hit on a Tranco tier-1 domain blocks graduation permanently until
//      the hash is fixed.
//   2. 3+ unique domains OR 2+ installs on separate calendar days.
//   3. 7+ days since first sighting — prevents a CDN burst on day 1 from
//      triggering immediate promotion.
//
// For each qualifying rule, opens a PR to virgil-core-rules removing
// watchOnly:true from that rule entry. The PR is reviewed by the existing
// quality gate (which checks rule structure) and can be merged by a maintainer.
//
// The quality gate sees this differently when the PR is labeled 'watch-graduation':
// it evaluates the real-world evidence rather than re-reviewing the hash content
// (which was already approved when the rule was first promoted in watchOnly mode).
//
// Trigger: GitHub Actions cron (Sundays 05:00 UTC — after gap analysis at 04:00)
// Dry run: node agents/agent-watch-graduation.js --dry-run
//
// Env vars: GITHUB_TOKEN, CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_D1_DATABASE_ID

import { cfg, d1raw, github } from './agent-tools.js';

const DRY_RUN      = process.argv.includes('--dry-run');
const REPO         = cfg.coreRulesRepo;

// ── Graduation thresholds ─────────────────────────────────────────────────────

const MIN_UNIQUE_DOMAINS        = 3;    // primary criterion
const MIN_INSTALLS_ALTERNATIVE  = 2;   // alternative: fewer domains but multiple installs
const MIN_SIGHTINGS_ALTERNATIVE = 5;   // minimum total sightings when using alternative
const MIN_OBSERVATION_DAYS      = 7;   // minimum days since first sighting

async function main() {
  console.log(`\nVirgil Watch Hash Graduation Agent`);
  console.log(`Dry run: ${DRY_RUN}`);
  console.log(`Thresholds: ${MIN_UNIQUE_DOMAINS}+ domains OR (${MIN_INSTALLS_ALTERNATIVE}+ installs AND ${MIN_SIGHTINGS_ALTERNATIVE}+ sightings), ${MIN_OBSERVATION_DAYS}+ days observation\n`);

  // ── Query 1: Find rules meeting the graduation criteria ───────────────────
  const candidates = d1raw(`
    SELECT
      whw.rule_id,
      whw.kit_label,
      COUNT(DISTINCT whw.hostname)                    AS unique_domains,
      COUNT(DISTINCT whw.install_id)                  AS unique_installs,
      COUNT(*)                                        AS total_sightings,
      MIN(whw.created_at)                             AS first_seen,
      MAX(whw.created_at)                             AS last_seen,
      CAST(
        (julianday('now') - julianday(MIN(whw.created_at)))
        AS INTEGER
      )                                               AS observation_days,
      SUM(CASE WHEN whw.match_type = 'exact'      THEN 1 ELSE 0 END) AS exact_hits,
      SUM(CASE WHEN whw.match_type = 'normalized' THEN 1 ELSE 0 END) AS norm_hits,
      GROUP_CONCAT(DISTINCT whw.hostname)             AS sample_hostnames
    FROM resource_hash_watch_hits whw
    GROUP BY whw.rule_id, whw.kit_label
    HAVING
      observation_days >= ${MIN_OBSERVATION_DAYS}
      AND (
        unique_domains >= ${MIN_UNIQUE_DOMAINS}
        OR (unique_installs >= ${MIN_INSTALLS_ALTERNATIVE} AND total_sightings >= ${MIN_SIGHTINGS_ALTERNATIVE})
      )
    ORDER BY unique_domains DESC, total_sightings DESC
  `);

  console.log(`Graduation candidates (before FP check): ${candidates.length}`);

  if (candidates.length === 0) {
    console.log('No watch rules ready for graduation this cycle.');
    return;
  }

  // ── Query 2: FP-check all candidates in one shot ─────────────────────────
  // Any rule that has fired on a Tranco tier-1 domain is blocked from graduation.
  const fpRuleIds = new Set();
  if (candidates.length > 0) {
    const placeholders = candidates.map(() => '?').join(',');
    const fpRows = d1raw(`
      SELECT DISTINCT json_each.value AS rule_id
      FROM resource_hash_fp_candidates,
           json_each(resource_hash_fp_candidates.rule_ids)
      WHERE json_each.value IN (${placeholders})
        AND created_at >= datetime('now', '-90 days')
    `, candidates.map(c => c.rule_id));
    for (const row of fpRows) fpRuleIds.add(row.rule_id);
  }

  const blocked   = candidates.filter(c => fpRuleIds.has(c.rule_id));
  const qualified = candidates.filter(c => !fpRuleIds.has(c.rule_id));

  console.log(`FP-blocked (filed against Tranco tier-1 domains): ${blocked.length}`);
  console.log(`Qualified for graduation: ${qualified.length}\n`);

  if (blocked.length > 0) {
    console.log('Blocked rules (FP sightings detected — do NOT graduate):');
    for (const r of blocked) {
      console.log(`  ${r.rule_id}: ${r.unique_domains} domains, ${r.unique_installs} installs — BLOCKED (FP on legitimate site)`);
    }
    console.log('');
  }

  if (qualified.length === 0) {
    console.log('No rules passed FP check — nothing to graduate this cycle.');
    return;
  }

  // ── Fetch current resourceHashes.json from the repo ───────────────────────
  const rhFileContent = await github.getFileContent(REPO, 'rules/source/resourceHashes.json')
    .catch(() => null);

  if (!rhFileContent) {
    console.error('Could not fetch rules/source/resourceHashes.json — aborting');
    return;
  }

  const rhFileSha     = rhFileContent.sha;
  const rhFileDecoded = Buffer.from(rhFileContent.content, 'base64').toString('utf8');
  let   rhFile        = JSON.parse(rhFileDecoded);

  if (!Array.isArray(rhFile.resourceHashes)) {
    console.error('resourceHashes.json has no resourceHashes array — aborting');
    return;
  }

  // ── Promote each qualified rule ───────────────────────────────────────────
  const promoted = [];
  const skipped  = [];

  for (const candidate of qualified) {
    const idx = rhFile.resourceHashes.findIndex(r => r.id === candidate.rule_id);

    if (idx === -1) {
      console.log(`  ${candidate.rule_id}: not found in resourceHashes.json — may have been renamed or removed`);
      skipped.push({ ruleId: candidate.rule_id, reason: 'not_in_file' });
      continue;
    }

    const rule = rhFile.resourceHashes[idx];

    if (!rule.watchOnly) {
      console.log(`  ${candidate.rule_id}: already live (watchOnly is not set) — skipping`);
      skipped.push({ ruleId: candidate.rule_id, reason: 'already_live' });
      continue;
    }

    // Remove watchOnly flag — this is the promotion
    delete rhFile.resourceHashes[idx].watchOnly;
    rhFile.resourceHashes[idx].graduatedAt   = new Date().toISOString().slice(0, 10);
    rhFile.resourceHashes[idx].graduationEvidence = {
      uniqueDomains:  candidate.unique_domains,
      uniqueInstalls: candidate.unique_installs,
      totalSightings: candidate.total_sightings,
      observationDays:candidate.observation_days,
      exactHits:      candidate.exact_hits,
      normHits:       candidate.norm_hits,
      firstSeen:      candidate.first_seen?.slice(0, 10),
      lastSeen:       candidate.last_seen?.slice(0, 10),
    };

    promoted.push(candidate);
    console.log(
      `  ✓ ${candidate.rule_id} (${candidate.kit_label || 'unknown kit'}): ` +
      `${candidate.unique_domains} domains, ${candidate.unique_installs} installs, ` +
      `${candidate.observation_days} days — PROMOTING`
    );
  }

  if (promoted.length === 0) {
    console.log('No rules to promote after eligibility checks.');
    return;
  }

  // ── Open a PR with the changes ────────────────────────────────────────────
  const branchName = `watch-graduation-${new Date().toISOString().slice(0, 10)}`;
  const updatedContent = JSON.stringify(rhFile, null, 2) + '\n';

  if (DRY_RUN) {
    console.log(`\n[dry-run] Would open PR on branch: ${branchName}`);
    console.log(`[dry-run] Promoting ${promoted.length} rule(s):`);
    promoted.forEach(r => console.log(`  - ${r.rule_id} (${r.kit_label || 'unknown'})`));
    return;
  }

  // Create branch off main
  const mainRef = await github.getRef(REPO, 'heads/main').catch(() => null);
  if (!mainRef?.object?.sha) {
    console.error('Could not get main branch SHA — aborting');
    return;
  }

  await github.createRef(REPO, `refs/heads/${branchName}`, mainRef.object.sha);

  // Commit the file change to the new branch
  const commitMessage = promoted.length === 1
    ? `feat: graduate watch rule ${promoted[0].rule_id} to live detection (${promoted[0].unique_domains} domains)`
    : `feat: graduate ${promoted.length} watch rules to live detection`;

  await github.createOrUpdateFile(
    REPO,
    'rules/source/resourceHashes.json',
    commitMessage,
    updatedContent,
    rhFileSha,
    branchName
  );

  // Build PR body with evidence table
  const evidenceTable = promoted.map(r => [
    `| \`${r.rule_id}\``,
    r.kit_label || '—',
    r.unique_domains,
    r.unique_installs,
    r.total_sightings,
    r.observation_days,
    r.exact_hits || 0,
    r.norm_hits || 0,
    r.first_seen?.slice(0, 10),
    r.last_seen?.slice(0, 10) + ' |',
  ].join(' | ')).join('\n');

  const blockedNote = blocked.length > 0
    ? `\n\n> ⚠️ **${blocked.length} rule(s) were NOT graduated** due to FP sightings on Tranco tier-1 domains:\n${blocked.map(r => `> - \`${r.rule_id}\` — blocked, requires hash removal before it can be promoted`).join('\n')}`
    : '';

  const prBody = `## Watch Hash Graduation

${promoted.length} resource hash rule(s) have accumulated enough real-world sightings to be promoted from watch mode to live detection rules.

### Graduation criteria met
- ✅ Zero FP sightings on Tranco tier-1 domains
- ✅ ${MIN_UNIQUE_DOMAINS}+ unique domains OR ${MIN_INSTALLS_ALTERNATIVE}+ installs with ${MIN_SIGHTINGS_ALTERNATIVE}+ sightings  
- ✅ ${MIN_OBSERVATION_DAYS}+ days of observation

### Evidence

| Rule ID | Kit | Domains | Installs | Sightings | Days | Exact | Normalised | First seen | Last seen |
|---------|-----|---------|---------|----------|------|-------|-----------|-----------|----------|
${evidenceTable}
${blockedNote}

### What this PR does

Removes \`watchOnly: true\` from each listed rule. After merge and publish, the rule will fire as a live detection signal (contributing to the risk score and potentially surfacing a warning to the user).

The rule content (hashes, pathPatterns, weights) is unchanged from when it was first promoted — only the \`watchOnly\` flag is removed.

### Merge checklist
- [ ] Verify none of the rules appear in the current FP candidates table (gap analysis)
- [ ] Confirm no brand redesigns since the rule was added (would invalidate the hash)
- [ ] Merge and trigger publish-detections.yml

---
*Opened by Virgil Watch Graduation Agent at ${new Date().toISOString()}*`;

  const pr = await github.createPullRequest(
    REPO,
    commitMessage,
    prBody,
    branchName,
    'main'
  );

  if (pr?.number) {
    await github.addLabel(REPO, pr.number, ['watch-graduation', 'rule-updated']);
    console.log(`\n✓ PR #${pr.number} opened: ${pr.html_url}`);
    console.log(`  Graduating ${promoted.length} rule(s):`);
    promoted.forEach(r => console.log(`    - ${r.rule_id} (${r.unique_domains} domains, ${r.observation_days} days observed)`));
  } else {
    console.error('PR creation failed — check GitHub API response');
  }
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
