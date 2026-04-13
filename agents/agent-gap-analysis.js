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

  // ── DOM structure hash template reuse gaps ─────────────────────────────────
  // Find structural fingerprints seen across 3+ unique dangerous domains that
  // have NOT yet been codified as domHashes rules — these are known phishkit
  // templates we've observed but haven't turned into instant-match rules yet.
  const uncodedTemplates = d1raw(`
    SELECT
      v.dom_structure_hash,
      COUNT(DISTINCT v.registered_domain)                                    AS unique_domains,
      COUNT(*)                                                                AS total_hits,
      SUM(CASE WHEN v.risk_level IN ('suspicious','dangerous') THEN 1 END)  AS threat_hits,
      GROUP_CONCAT(DISTINCT v.detected_brand)                                AS brands,
      MIN(v.created_at)                                                       AS first_seen
    FROM verdicts v
    WHERE v.dom_structure_hash IS NOT NULL
      AND v.risk_level IN ('suspicious', 'dangerous')
      AND v.created_at >= datetime('now', '-${LOOKBACK_DAYS} days')
    GROUP BY v.dom_structure_hash
    HAVING unique_domains >= 3
    ORDER BY unique_domains DESC
    LIMIT 20
  `);

  console.log(`Uncoded DOM template patterns (3+ unique domains): ${uncodedTemplates.length}`);

  // ── Resource hash rule effectiveness (Scenario A) ──────────────────────────
  // Which hash rules are firing most? Are they high-precision?
  // Also: which kit labels appear most in dangerous verdicts?
  // Answers "how much work are hashes doing?" and "which kits are active?"
  let resourceHashEffectiveness = [];
  let hashSavedDetections = [];
  try {
    resourceHashEffectiveness = d1raw(`
      SELECT
        rhs.rule_id,
        rhs.kit_label,
        COUNT(DISTINCT v.registered_domain)                                     AS unique_domains,
        COUNT(*)                                                                 AS total_fires,
        SUM(CASE WHEN v.risk_level IN ('suspicious','dangerous') THEN 1 END)   AS phish_fires,
        SUM(CASE WHEN v.risk_level = 'safe' THEN 1 END)                        AS safe_fires,
        CAST(SUM(CASE WHEN v.risk_level IN ('suspicious','dangerous') THEN 1 END)
             AS FLOAT) / (COUNT(*) + 1)                                         AS precision,
        SUM(CASE WHEN rhs.match_type = 'exact'      THEN 1 ELSE 0 END)        AS exact_matches,
        SUM(CASE WHEN rhs.match_type = 'normalized' THEN 1 ELSE 0 END)        AS normalized_matches
      FROM resource_hash_signals rhs
      JOIN verdicts v ON rhs.verdict_id = v.id
      WHERE v.created_at >= datetime('now', '-${LOOKBACK_DAYS} days')
      GROUP BY rhs.rule_id, rhs.kit_label
      ORDER BY phish_fires DESC
      LIMIT 20
    `);

    // ── Scenario B: Hash-saved detections with weak heuristics ───────────────
    // Verdicts where a resource hash signal fired AND the pre-async heuristic
    // score was low (< 0.35). These are pages where traditional rules missed
    // and only the hash caught it — the hash is doing more work than it should.
    // For each kit label, the signal_types from the verdict tells us what
    // heuristic signals DID fire, helping identify what rules to strengthen.
    hashSavedDetections = d1raw(`
      SELECT
        rhs.kit_label,
        rhs.rule_id,
        COUNT(DISTINCT v.registered_domain)                         AS unique_domains,
        COUNT(*)                                                     AS occurrences,
        AVG(v.heuristic_score_pre_async)                            AS avg_pre_hash_score,
        AVG(v.confidence)                                           AS avg_final_score,
        GROUP_CONCAT(DISTINCT v.detected_brand)                     AS brands,
        GROUP_CONCAT(DISTINCT v.tld)                                AS tlds
      FROM resource_hash_signals rhs
      JOIN verdicts v ON rhs.verdict_id = v.id
      WHERE v.risk_level IN ('suspicious', 'dangerous')
        AND v.heuristic_score_pre_async IS NOT NULL
        AND v.heuristic_score_pre_async < 0.35
        AND v.created_at >= datetime('now', '-${LOOKBACK_DAYS} days')
      GROUP BY rhs.kit_label, rhs.rule_id
      HAVING occurrences >= 2
      ORDER BY occurrences DESC, avg_pre_hash_score ASC
      LIMIT 15
    `);

    // For each hash-saved kit, pull what heuristic signals DID fire on those
    // pages — this tells us what the kit's "heuristic fingerprint" looks like
    // so Claude can propose complementary source/domain rules
    for (const kit of hashSavedDetections.slice(0, 5)) {
      const sigRows = d1raw(`
        SELECT s.type, COUNT(*) as hits, AVG(s.weight) as avg_weight
        FROM signals s
        JOIN verdicts v ON s.verdict_id = v.id
        JOIN resource_hash_signals rhs ON rhs.verdict_id = v.id
        WHERE rhs.rule_id = '${kit.rule_id}'
          AND v.heuristic_score_pre_async < 0.35
          AND v.risk_level IN ('suspicious', 'dangerous')
          AND v.created_at >= datetime('now', '-${LOOKBACK_DAYS} days')
          AND s.type NOT LIKE 'resource-hash-%'
        GROUP BY s.type
        ORDER BY hits DESC
        LIMIT 8
      `);
      kit.presentSignals = sigRows;
    }
  } catch (e) {
    console.warn('Resource hash queries failed (table may not exist yet):', e.message);
  }

  console.log(`Resource hash rule effectiveness: ${resourceHashEffectiveness.length} rules`);
  console.log(`Hash-saved detections (pre-hash score < 0.35): ${hashSavedDetections.length} kit/rule pairs`);

  // ── Nano concordance analysis ───────────────────────────────────────────────
  // Find cases where Nano said SAFE but Claude said DANGEROUS — these are
  // Nano blind spots that may indicate categories needing tighter thresholds
  // or where Nano should be skipped entirely.
  let nanoMisses = [];
  let nanoStats = { total: 0, concordant: 0, misses: 0 };
  try {
    nanoMisses = d1raw(`
      SELECT url_domain, nano_class, nano_confidence, claude_risk, claude_conf
      FROM nano_concordance
      WHERE concordant = 0 AND claude_risk = 'dangerous' AND nano_class = 'SAFE'
        AND created_at >= datetime('now', '-${LOOKBACK_DAYS} days')
      ORDER BY claude_conf DESC
      LIMIT 20
    `);

    const statsRow = d1raw(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN concordant = 1 THEN 1 ELSE 0 END) as concordant,
        SUM(CASE WHEN concordant = 0 AND claude_risk = 'dangerous' AND nano_class = 'SAFE' THEN 1 ELSE 0 END) as misses
      FROM nano_concordance
      WHERE created_at >= datetime('now', '-${LOOKBACK_DAYS} days')
    `);
    if (statsRow?.[0]) nanoStats = statsRow[0];
  } catch (e) {
    console.warn('Nano concordance query failed (table may not exist yet):', e.message);
  }

  console.log(`Nano concordance: ${nanoStats.total} total, ${nanoStats.concordant} concordant, ${nanoStats.misses} dangerous misses`);

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

### Uncoded DOM template patterns (seen 3+ unique domains, no rule yet)
These phishkit templates have been observed in the corpus but not yet added to
dom-hashes.json — each could be caught instantly without Claude once promoted.
${uncodedTemplates.slice(0,10).map(r =>
  `- \`${r.dom_structure_hash?.slice(0,16)}…\`: ${r.unique_domains} unique domains, ${r.total_hits} total hits, brands: ${r.brands || 'unknown'} (first seen: ${r.first_seen?.slice(0,10)})`
).join('\n') || '(none)'}

### Resource hash rule effectiveness (Scenario A: hash fires on confirmed phish)
How much work are CSS/JS file hash rules doing? Precision tells you whether
a rule is reliable or generating false positives.
${resourceHashEffectiveness.length > 0 ? resourceHashEffectiveness.slice(0,12).map(r =>
  `- \`${r.rule_id}\` (kit: ${r.kit_label || 'unknown'}): ` +
  `${r.phish_fires}/${r.total_fires} phish (${(r.precision*100).toFixed(0)}% precision), ` +
  `${r.unique_domains} unique domains, ` +
  `exact: ${r.exact_matches} normalized: ${r.normalized_matches}`
).join('\n') : '(no resource hash data yet — table populates as rules ship and detections accumulate)'}

### Hash-saved detections with weak heuristics (Scenario B: heuristics were light)
These are detections where a resource hash rule fired BUT the pre-hash heuristic
score was < 0.35. The hash did the heavy lifting — traditional rules were not
covering this kit adequately. Each kit here needs stronger source/domain rules
as backup so detections don't depend on the hash alone.
${hashSavedDetections.length > 0 ? hashSavedDetections.slice(0,8).map(r => {
  const sigList = (r.presentSignals || []).slice(0,5)
    .map(s => `${s.type}(w:${s.avg_weight?.toFixed(2)})`)
    .join(', ');
  return `- Kit: \`${r.kit_label || r.rule_id}\`: ` +
    `${r.occurrences} hash-saves across ${r.unique_domains} domains, ` +
    `avg pre-hash score: ${r.avg_pre_hash_score?.toFixed(2)}, ` +
    `avg final score: ${r.avg_final_score?.toFixed(2)}, ` +
    `brands: ${r.brands || 'unknown'}\n` +
    `  Heuristic signals that DID fire: ${sigList || '(none recorded)'}`;
}).join('\n') : '(no hash-saved detections yet — populates once pre_async scoring is live)'}

### Nano vs Claude concordance
Gemini Nano pre-screens pages before Claude. When Nano says SAFE but Claude says DANGEROUS, that's a dangerous miss — the page would have been skipped without Claude.
- Total comparisons: ${nanoStats.total}
- Agreement rate: ${nanoStats.total > 0 ? ((nanoStats.concordant / nanoStats.total) * 100).toFixed(1) : 'N/A'}%
- Dangerous misses (Nano SAFE → Claude DANGEROUS): ${nanoStats.misses}
${nanoMisses.length > 0 ? `\nTop missed domains:\n${nanoMisses.slice(0,10).map(r =>
  `- \`${r.url_domain}\`: Nano=${r.nano_class} (${(r.nano_confidence*100).toFixed(0)}%) → Claude=${r.claude_risk} (${(r.claude_conf*100).toFixed(0)}%)`
).join('\n')}` : '(no dangerous misses in this period)'}

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

### DOM Template Gaps
For any uncoded DOM template patterns with 5+ unique domains, propose a domHashes rule entry:
- Estimate the kitName based on the associated brands and hit pattern
- Weight: 0.30 for 3-4 domains, 0.40 for 5-9 domains, 0.45 for 10+
- These can ship via remote config immediately — highest ROI of any rule type

### Resource Hash Coverage Analysis
This section is NEW — address both directions:

**A. Hash rule health** (from the effectiveness table above):
- Which hash rules have high precision (>80%) and are safe to rely on?
- Which have low precision (<60%) and may need the pathPattern tightened?
- Are any rules firing exclusively on normalised matches (meaning operators always rotate tokens)? That's expected — just note it.

**B. Hash-dependent kits needing heuristic backup** (from the hash-saved detections above):
For each kit where the pre-hash score was low (< 0.35), propose concrete source or domain rules that would catch the same kit WITHOUT the hash — treating the hash-saved examples as a labelled training set:
- What do the "heuristic signals that DID fire" tell you about the kit's page structure?
- Propose 1-2 source pattern rules (regex against HTML/JS) or domain rules that would push the pre-hash score above 0.35 for this kit family
- Format each proposed rule as JSON in Virgil schema format so it can be auto-promoted
- Priority: kits with more occurrences and lower pre-hash scores first

**C. Detection layer balance**
Is the detection ratio healthy? If hash rules are saving >20% of dangerous verdicts that heuristics missed, that's a signal the heuristic layer is underpowered relative to the kits currently in circulation. Call it out explicitly with the numbers.

### Nano Blind Spots
If there are Nano dangerous misses (Nano SAFE → Claude DANGEROUS), identify patterns:
- Are specific verticals (crypto, financial, SSO) over-represented in misses?
- Should the Nano confidence threshold be raised for certain signal combinations?
- Are there categories where Nano should be bypassed entirely?
If no misses, state that Nano accuracy is acceptable for this period.

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

${nanoMisses.length > 0 ? `<details>
<summary>Nano dangerous misses (${nanoMisses.length})</summary>

| Domain | Nano | Nano conf | Claude | Claude conf |
|--------|------|----------|--------|------------|
${nanoMisses.slice(0,20).map(r =>
  `| \`${r.url_domain}\` | ${r.nano_class} | ${(r.nano_confidence*100).toFixed(0)}% | ${r.claude_risk} | ${(r.claude_conf*100).toFixed(0)}% |`
).join('\n')}

Nano agreement rate: ${nanoStats.total > 0 ? ((nanoStats.concordant / nanoStats.total) * 100).toFixed(1) : 'N/A'}% (${nanoStats.concordant}/${nanoStats.total})

</details>` : ''}

${resourceHashEffectiveness.length > 0 ? `<details>
<summary>Resource hash rule effectiveness (${resourceHashEffectiveness.length} rules)</summary>

| Rule ID | Kit | Phish fires | Total fires | Precision | Exact | Normalised | Domains |
|---------|-----|------------|------------|----------|-------|-----------|---------|
${resourceHashEffectiveness.slice(0,15).map(r =>
  `| \`${r.rule_id}\` | ${r.kit_label || '—'} | ${r.phish_fires} | ${r.total_fires} | ${(r.precision*100).toFixed(0)}% | ${r.exact_matches} | ${r.normalized_matches} | ${r.unique_domains} |`
).join('\n')}

</details>` : ''}

${hashSavedDetections.length > 0 ? `<details>
<summary>Hash-saved detections — heuristics were weak (${hashSavedDetections.length} kit/rule pairs)</summary>

These kits were caught by resource hash rules but would have been missed by heuristics alone (pre-hash score < 0.35).
Each represents a heuristic coverage gap that needs source/domain rules as backup.

| Kit | Rule | Domains | Occurrences | Pre-hash score | Final score | Heuristic signals present |
|-----|------|---------|------------|---------------|------------|--------------------------|
${hashSavedDetections.slice(0,12).map(r =>
  `| ${r.kit_label || '—'} | \`${r.rule_id}\` | ${r.unique_domains} | ${r.occurrences} | ${r.avg_pre_hash_score?.toFixed(2)} | ${r.avg_final_score?.toFixed(2)} | ${(r.presentSignals||[]).slice(0,3).map(s => s.type).join(', ') || '(none)'} |`
).join('\n')}

</details>` : ''}

---

## Next steps

A maintainer should:
1. Review the Priority Gaps above
2. For any **Hash-Dependent Kits** listed — prioritise the proposed source/domain rules so detection doesn't rely on hashes alone
3. Ship Quick Wins via remote config (no Store push needed): edit \`core-rules\`, run compile-feeds, trigger Publish Detection Config
4. File separate issues for any changes requiring JS code updates

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
