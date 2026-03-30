#!/usr/bin/env node
// Virgil — Detection Gap Analysis Agent (Agent 4)
//
// Runs weekly. Analyses false negative feedback and corpus misses to identify
// systematic gaps in detection coverage. Produces a prioritised list of
// proposed rule improvements and files a gap analysis issue.
//
// Trigger: GitHub Actions cron (Sundays 04:00 UTC)
// Output:  GitHub issue in core-rules repo with gap analysis + proposals

import { cfg, d1, d1raw, claude, github, analyzeUrl } from './agent-tools.js';

const LOOKBACK_DAYS = parseInt(process.env.LOOKBACK_DAYS || '14');
const DRY_RUN       = process.argv.includes('--dry-run');

async function main() {
  console.log(`\nAgent 4: Detection Gap Analysis`);
  console.log(`Lookback: ${LOOKBACK_DAYS} days, dry-run: ${DRY_RUN}`);

  // ── Load false negative feedback ───────────────────────────────────────────
  console.log('Loading FN feedback...');

  // FN feedback from feedback_stats (aggregated from extension)
  const fnStats = d1raw(`
    SELECT stats_json, created_at
    FROM feedback_stats
    WHERE created_at >= datetime('now', '-${LOOKBACK_DAYS} days')
    ORDER BY created_at DESC
    LIMIT 500
  `);

  // Count FN feedback events across all installs
  let totalFN = 0, totalFP = 0;
  for (const row of fnStats) {
    try {
      const stats = JSON.parse(row.stats_json);
      totalFN += stats.feedback_false_negative || 0;
      totalFP += stats.feedback_false_positive  || 0;
    } catch {}
  }

  console.log(`FN feedback events: ${totalFN}, FP feedback events: ${totalFP}`);

  // ── Find domains that fired signals but got safe verdicts ──────────────────
  // These are pages that triggered heuristics but not strongly enough to flag —
  // the most actionable gap source

  const almostCaught = d1raw(`
    SELECT
      v.registered_domain, v.tld, v.detected_brand,
      COUNT(DISTINCT v.install_id) as install_count,
      AVG(v.confidence) as avg_conf,
      GROUP_CONCAT(DISTINCT s.type) as signal_types,
      COUNT(s.id) as signal_count
    FROM verdicts v
    JOIN signals s ON s.verdict_id = v.id
    WHERE v.risk_level = 'safe'
      AND v.created_at >= datetime('now', '-${LOOKBACK_DAYS} days')
      AND v.confidence > 0.15
      AND v.signal_count >= 2
      AND v.registered_domain IS NOT NULL
    GROUP BY v.registered_domain
    HAVING COUNT(DISTINCT v.install_id) >= 2
    ORDER BY avg_conf DESC, install_count DESC
    LIMIT 50
  `);

  console.log(`Near-miss domains (safe verdict but signals fired): ${almostCaught.length}`);

  // ── Find signals that rarely fire alone but often appear with others ────────
  // Signals with weak standalone weight but strong correlation with phishing
  const signalCorrelation = d1raw(`
    SELECT
      s.type as signal_type,
      COUNT(CASE WHEN v.risk_level = 'dangerous' THEN 1 END) as phish_hits,
      COUNT(CASE WHEN v.risk_level = 'safe' THEN 1 END) as safe_hits,
      CAST(COUNT(CASE WHEN v.risk_level = 'dangerous' THEN 1 END) AS FLOAT) /
        (COUNT(*) + 1) as phish_rate,
      AVG(s.weight) as avg_weight
    FROM signals s
    JOIN verdicts v ON s.verdict_id = v.id
    WHERE v.created_at >= datetime('now', '-${LOOKBACK_DAYS} days')
    GROUP BY s.type
    HAVING phish_hits >= 5
    ORDER BY phish_rate DESC
    LIMIT 30
  `);

  // ── Find uncovered brands (target in domain but no brand entry matches) ────
  const uncoveredBrands = d1raw(`
    SELECT
      v.registered_domain,
      COUNT(DISTINCT v.install_id) as reports,
      MAX(v.confidence) as max_conf
    FROM verdicts v
    JOIN signals s ON s.verdict_id = v.id
    WHERE v.risk_level = 'dangerous'
      AND v.detected_brand IS NULL
      AND s.type = 'brand-in-subdomain'
      AND v.created_at >= datetime('now', '-${LOOKBACK_DAYS} days')
    GROUP BY v.registered_domain
    ORDER BY reports DESC
    LIMIT 20
  `);

  console.log(`Uncovered brand domains: ${uncoveredBrands.length}`);

  // ── TLD coverage gap ────────────────────────────────────────────────────────
  const tldGaps = d1raw(`
    SELECT
      v.tld,
      COUNT(CASE WHEN v.risk_level = 'dangerous' THEN 1 END) as phish_count,
      COUNT(CASE WHEN v.risk_level = 'safe' THEN 1 END) as safe_count,
      CAST(COUNT(CASE WHEN v.risk_level = 'dangerous' THEN 1 END) AS FLOAT) /
        (COUNT(*) + 1) as phish_rate
    FROM verdicts v
    WHERE v.tld IS NOT NULL
      AND v.created_at >= datetime('now', '-${LOOKBACK_DAYS} days')
    GROUP BY v.tld
    HAVING phish_count >= 5 AND phish_rate > 0.6
    ORDER BY phish_rate DESC, phish_count DESC
    LIMIT 15
  `);

  // ── Ask Claude for gap analysis ─────────────────────────────────────────────
  console.log('Calling Claude for gap analysis...');

  const systemPrompt = `You are Virgil's detection gap analyst. You identify patterns in missed detections and uncovered threats, then propose concrete, implementable improvements to the detection system. Think like a senior threat intelligence analyst closing coverage gaps. Be quantitative where data supports it, and always tie recommendations back to the evidence.`;

  const userContent = `
## Detection Gap Analysis — Last ${LOOKBACK_DAYS} Days

### User feedback summary
- False negatives reported: ${totalFN}
- False positives reported: ${totalFP}
- FP rate: ${totalFN + totalFP > 0 ? ((totalFP / (totalFN + totalFP)) * 100).toFixed(1) : 0}%

### Near-miss domains (had signals but classified safe)
These domains triggered multiple signals but didn't cross the detection threshold.
Top 15 by average confidence:
${almostCaught.slice(0,15).map(r =>
  `- \`${r.registered_domain}\` (conf ${r.avg_conf?.toFixed(2)}, ${r.install_count} installs, signals: ${r.signal_types?.split(',').slice(0,4).join(', ')})`
).join('\n') || '(none)'}

### Signal effectiveness breakdown
Signals with highest phishing correlation rate:
${signalCorrelation.slice(0,15).map(r =>
  `- \`${r.signal_type}\`: ${(r.phish_rate*100).toFixed(0)}% phish rate (${r.phish_hits} phish / ${r.safe_hits} safe hits), avg weight ${r.avg_weight?.toFixed(2)}`
).join('\n') || '(none)'}

### Uncovered brands (phishing detected but no brand entry matched)
${uncoveredBrands.slice(0,10).map(r =>
  `- \`${r.registered_domain}\` (${r.reports} reports, conf ${r.max_conf?.toFixed(2)})`
).join('\n') || '(none)'}

### TLD coverage gaps (high phishing rate, not in TLD_RISK or low weight)
${tldGaps.slice(0,10).map(r =>
  `- \`${r.tld}\`: ${(r.phish_rate*100).toFixed(0)}% phish rate (${r.phish_count} phish, ${r.safe_count} safe)`
).join('\n') || '(none)'}

## Your task

Write a gap analysis report with:

### Executive Summary
2-3 sentences on overall detection health and the most significant gaps.

### Priority Gaps (ranked 1–5, highest priority first)

For each gap:
- **Gap title** (one line)
- **Evidence**: what the data shows
- **Impact**: how many missed detections this likely explains
- **Proposed fix**: exact JSON/code change needed (brand entry, TLD weight, signal weight adjustment)

### Signal Weight Adjustments
Based on the phishing correlation data, which signals are under-weighted or over-weighted? List specific adjustments with reasoning.

### New TLD Risk Entries
Which TLDs from the gap analysis should be added to TLD_RISK? Propose specific weights.

### Quick Wins
2-3 changes that could be shipped via remote config today (no code change) with the highest expected impact.`;

  const analysis = await claude(systemPrompt, userContent, 2500);

  // ── Build and file the issue ────────────────────────────────────────────────
  const weekStr = new Date().toISOString().slice(0, 10);
  const title   = `[GAP ANALYSIS] Week of ${weekStr} — ${totalFN} FN reports, ${almostCaught.length} near-misses`;

  const body = `## 🤖 Weekly Detection Gap Analysis

**Period:** Last ${LOOKBACK_DAYS} days ending ${weekStr}
**FN feedback:** ${totalFN} | **FP feedback:** ${totalFP} | **Near-misses:** ${almostCaught.length}

---

${analysis}

---

## Raw data summary

<details>
<summary>Near-miss domains (top 20)</summary>

| Domain | Confidence | Installs | Signals |
|--------|-----------|---------|---------|
${almostCaught.slice(0,20).map(r =>
  `| \`${r.registered_domain}\` | ${r.avg_conf?.toFixed(2)} | ${r.install_count} | ${r.signal_types?.split(',').slice(0,3).join(', ')} |`
).join('\n')}

</details>

<details>
<summary>Signal correlation breakdown</summary>

| Signal | Phish rate | Phish hits | Safe hits | Avg weight |
|--------|-----------|-----------|----------|-----------|
${signalCorrelation.slice(0,20).map(r =>
  `| \`${r.signal_type}\` | ${(r.phish_rate*100).toFixed(0)}% | ${r.phish_hits} | ${r.safe_hits} | ${r.avg_weight?.toFixed(2)} |`
).join('\n')}

</details>

---

## Next steps

A maintainer should:
1. Review the Priority Gaps above
2. Ship Quick Wins via remote config (no Store push needed): edit \`core-rules\`, run compile-feeds, trigger Publish Detection Config
3. File separate issues for any changes requiring JS code updates

---
*Generated by Virgil Gap Analysis Agent at ${new Date().toISOString()}*`;

  if (DRY_RUN) {
    console.log(`[dry-run] Would create issue: "${title}"`);
    console.log(`Analysis preview:\n${analysis.slice(0, 500)}...`);
  } else {
    const issue = await github.createIssue(
      cfg.coreRulesRepo,
      title,
      body,
      ['gap-analysis', 'needs-triage']
    );
    console.log(`✓ Created issue #${issue?.number}: ${title}`);
  }
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
