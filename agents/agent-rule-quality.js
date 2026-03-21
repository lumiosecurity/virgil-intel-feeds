#!/usr/bin/env node
// Virgil — Rule Quality Agent (Agent 3)
//
// Triggered when a PR is opened on the community rules repo.
// Tests submitted rules against the D1 corpus, checks for false positives,
// validates consistency with existing rules, and posts a structured review.
//
// Trigger: GitHub Actions pull_request webhook (types: opened, synchronize)
// Input:   PR_NUMBER env var
// Output:  GitHub PR review comment

import { cfg, d1, claude, github, analyzeUrl } from './agent-tools.js';

const PR_NUMBER = parseInt(process.env.PR_NUMBER || process.argv[2]);
const REPO      = cfg.communityRepo;

if (!PR_NUMBER) { console.error('PR_NUMBER required'); process.exit(1); }

async function main() {
  console.log(`\nAgent 3: Rule Quality Review — PR #${PR_NUMBER}`);

  // ── Load PR ─────────────────────────────────────────────────────────────────
  const [pr, files] = await Promise.all([
    github.getPR(REPO, PR_NUMBER),
    github.getPRFiles(REPO, PR_NUMBER),
  ]);

  if (!pr) { console.error('PR not found'); process.exit(1); }
  console.log(`PR: "${pr.title}" (${files?.length || 0} files)`);

  // Only process rule JSON files
  const ruleFiles = (files || []).filter(f =>
    f.filename.endsWith('.json') &&
    (f.filename.startsWith('rules/') || f.filename.startsWith('rules\\')) &&
    f.status !== 'removed'
  );

  if (ruleFiles.length === 0) {
    await github.reviewPR(REPO, PR_NUMBER, 'COMMENT',
      '🤖 **Rule Quality Agent:** No rule JSON files found in this PR. If this is a documentation or config change, no quality review is needed.');
    process.exit(0);
  }

  console.log(`Rule files: ${ruleFiles.map(f => f.filename).join(', ')}`);

  // ── Load and parse each rule file ───────────────────────────────────────────
  const rules = [];
  for (const file of ruleFiles) {
    try {
      const content = Buffer.from(file.patch || '', 'utf8');
      // Get the full file content from the PR branch
      const fileData = await github.getFileContent(REPO, file.filename, pr.head.sha);
      if (!fileData?.content) continue;
      const raw  = Buffer.from(fileData.content, 'base64').toString('utf8');
      const rule = JSON.parse(raw);
      rules.push({ filename: file.filename, rule });
    } catch (e) {
      console.warn(`Could not parse ${file.filename}:`, e.message);
    }
  }

  if (rules.length === 0) {
    await github.reviewPR(REPO, PR_NUMBER, 'COMMENT',
      '⚠️ **Rule Quality Agent:** Could not parse any rule files. Schema validation CI will catch syntax errors.');
    process.exit(0);
  }

  // ── Test each rule against the corpus ──────────────────────────────────────
  const reviews = [];

  for (const { filename, rule } of rules) {
    console.log(`\nAnalysing ${filename}...`);
    const review = await analyzeRule(filename, rule);
    reviews.push(review);
  }

  // ── Ask Claude to synthesise the review ────────────────────────────────────
  const systemPrompt = `You are Virgil's rule quality reviewer. You evaluate community-submitted detection rules for correctness, effectiveness, and false positive risk. Your review helps maintainers decide whether to merge, request changes, or reject a PR. Be specific, cite evidence from the corpus test results, and give clear merge/change-request/reject recommendations.`;

  const userContent = `
## PR Rule Quality Review

**PR:** #${PR_NUMBER} — "${pr.title}"
**Author:** ${pr.user?.login}
**Files:** ${rules.map(r => r.filename).join(', ')}

## Rule analysis results

${reviews.map(r => r.summary).join('\n\n---\n\n')}

## Your task

Write a comprehensive PR review with:

### Overall Recommendation
APPROVE / REQUEST_CHANGES / REJECT — and why in one sentence.

### Per-file assessment
For each file, rate: ✅ Good / ⚠️ Needs changes / ❌ Reject
Then explain the key finding.

### Specific concerns (if any)
- False positive risk
- Weight inconsistency with existing rules  
- Typosquat patterns that are too broad
- Missing patterns that would improve coverage
- Any safety issues

### Merge checklist
For APPROVE: what the maintainer should verify before merging.
For REQUEST_CHANGES: exact changes needed before this can be merged.

Keep it concise — bullet points over paragraphs.`;

  const reviewText = await claude(systemPrompt, userContent, 1500);

  // Determine overall review event
  const isApprove = reviewText.includes('APPROVE') && !reviewText.includes('REQUEST_CHANGES') && !reviewText.includes('REJECT');
  const isReject  = reviewText.includes('REJECT');
  const reviewEvent = isApprove ? 'APPROVE' : 'REQUEST_CHANGES';

  // Build the review body
  const body = `## 🤖 Rule Quality Review

${reviewText}

---

<details>
<summary>Corpus test details</summary>

${reviews.map(r => `### ${r.filename}\n${r.corpusDetail}`).join('\n\n')}
</details>

---
*Posted by Virgil Rule Quality Agent at ${new Date().toISOString()}*`;

  await github.reviewPR(REPO, PR_NUMBER, reviewEvent, body);
  console.log(`✓ Review posted (${reviewEvent})`);
}

async function analyzeRule(filename, rule) {
  const brandEntries  = rule.domainRules?.brandEntries  || [];
  const sourcePatterns= rule.sourcePatterns || [];
  const summary_lines = [`**File:** \`${filename}\``];
  let   corpusDetail  = '';

  // Test brand entries: how many typosquats appear in corpus?
  for (const entry of brandEntries) {
    const allTerms = [...(entry.typos || []), ...(entry.domains || [])];

    const corpusHits = d1(`
      SELECT registered_domain, COUNT(DISTINCT install_id) as reports, MAX(confidence) as max_conf
      FROM verdicts
      WHERE risk_level = 'dangerous'
        AND (${allTerms.map(t => `registered_domain LIKE '%${t.replace(/'/g,"''")}%'`).join(' OR ')})
      GROUP BY registered_domain
      ORDER BY reports DESC
      LIMIT 20
    `);

    const fpCheck = d1(`
      SELECT registered_domain, COUNT(DISTINCT install_id) as reports
      FROM verdicts
      WHERE risk_level = 'safe'
        AND (${allTerms.map(t => `registered_domain LIKE '%${t.replace(/'/g,"''")}%'`).join(' OR ')})
      GROUP BY registered_domain
      LIMIT 10
    `);

    const feedHits = d1(`
      SELECT registered_domain, COUNT(*) as hits
      FROM ingested_urls
      WHERE risk_score >= 0.6
        AND (${allTerms.map(t => `registered_domain LIKE '%${t.replace(/'/g,"''")}%'`).join(' OR ')})
      GROUP BY registered_domain
      LIMIT 20
    `);

    summary_lines.push(`**Brand: ${entry.name}** — ${entry.typos?.length || 0} typosquats`);
    summary_lines.push(`- Corpus phishing hits: ${corpusHits.length} domains (${corpusHits.reduce((s,r)=>s+r.reports,0)} reports total)`);
    summary_lines.push(`- Potential FP domains in corpus: ${fpCheck.length}`);
    summary_lines.push(`- Feed-confirmed hits: ${feedHits.length} domains`);

    corpusDetail += `#### Brand: ${entry.name}\n`;
    if (corpusHits.length > 0) {
      corpusDetail += `**Phishing hits in corpus:**\n`;
      corpusDetail += corpusHits.slice(0,8).map(r => `- \`${r.registered_domain}\` (${r.reports} reports, confidence ${r.max_conf?.toFixed(2)})`).join('\n') + '\n';
    }
    if (fpCheck.length > 0) {
      corpusDetail += `**⚠ Potential false positives:**\n`;
      corpusDetail += fpCheck.slice(0,5).map(r => `- \`${r.registered_domain}\` (${r.reports} safe verdicts)`).join('\n') + '\n';
    }
  }

  // Test source patterns: do they compile and match known phishkit signatures?
  for (const pat of sourcePatterns) {
    let compiles = false;
    try { new RegExp(pat.patternString, pat.patternFlags || ''); compiles = true; }
    catch {}

    const patternHits = d1(`
      SELECT signal_id, COUNT(*) as hits
      FROM phishkit_signals
      WHERE signal_id = '${pat.id.replace(/'/g,"''")}'
      GROUP BY signal_id
    `);

    summary_lines.push(`**Pattern: ${pat.id}** — ${compiles ? '✅ compiles' : '❌ compile error'}, corpus matches: ${patternHits[0]?.hits || 0}`);
    corpusDetail += `#### Pattern: ${pat.id}\n- Compiles: ${compiles ? 'yes' : 'NO — SYNTAX ERROR'}\n- Corpus hits: ${patternHits[0]?.hits || 0}\n`;
  }

  return {
    filename,
    summary: summary_lines.join('\n'),
    corpusDetail,
  };
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
