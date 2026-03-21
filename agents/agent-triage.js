#!/usr/bin/env node
// Virgil — FP/FN Triage Agent (Agent 1)
//
// Triggered when a user-feedback issue is opened in core-rules.
// Runs a full investigation on the domain and posts a structured
// analysis comment with a proposed resolution for maintainer approval.
//
// Trigger: GitHub Actions issues webhook (types: opened, labeled)
// Input:   ISSUE_NUMBER env var
// Output:  GitHub issue comment + labels

import { cfg, d1, claude, github, getDomainIntel, analyzeUrl, fmtIntel, fmtHeuristics } from './agent-tools.js';

const ISSUE_NUMBER = parseInt(process.env.ISSUE_NUMBER || process.argv[2]);
const REPO         = cfg.coreRulesRepo;

if (!ISSUE_NUMBER) { console.error('ISSUE_NUMBER required'); process.exit(1); }

async function main() {
  console.log(`\nAgent 1: FP/FN Triage — Issue #${ISSUE_NUMBER}`);

  // ── Load issue ──────────────────────────────────────────────────────────────
  const issue = await github.getIssue(REPO, ISSUE_NUMBER);
  if (!issue) { console.error('Issue not found'); process.exit(1); }

  // Only process user-feedback issues
  const labels = issue.labels.map(l => l.name);
  if (!labels.includes('user-feedback')) {
    console.log('Not a user-feedback issue — skipping');
    process.exit(0);
  }

  // Don't re-triage if already processed
  if (labels.includes('agent-triaged')) {
    console.log('Already triaged — skipping');
    process.exit(0);
  }

  console.log(`Issue: "${issue.title}"`);
  console.log(`Labels: ${labels.join(', ')}`);

  // ── Extract domain from issue body ──────────────────────────────────────────
  const domainMatch = issue.body?.match(/\| Domain \| `([^`]+)` \|/);
  const urlMatch    = issue.body?.match(/\| Full URL \| `([^`]+)` \|/);
  const typeMatch   = issue.body?.match(/\| Feedback type \| ([^\n|]+) \|/);
  const verdictMatch= issue.body?.match(/\| Verdict shown \| ([^\n|]+) \|/);
  const brandMatch  = issue.body?.match(/\| Detected brand \| ([^\n|]+) \|/);

  const domain       = domainMatch?.[1]?.trim();
  const url          = urlMatch?.[1]?.trim();
  const feedbackType = typeMatch?.[1]?.trim();
  const verdictShown = verdictMatch?.[1]?.trim();
  const detectedBrand= brandMatch?.[1]?.trim();

  if (!domain) {
    await github.commentOnIssue(REPO, ISSUE_NUMBER,
      '⚠️ **Triage agent:** Could not extract domain from issue body. Manual review required.');
    await github.addLabel(REPO, ISSUE_NUMBER, ['needs-triage']);
    process.exit(0);
  }

  console.log(`Domain: ${domain}, type: ${feedbackType}`);

  // ── Gather intelligence ─────────────────────────────────────────────────────
  console.log('Gathering intelligence...');
  const [intel, heuristics] = await Promise.all([
    getDomainIntel(domain),
    url ? Promise.resolve(analyzeUrl(url)) : Promise.resolve(null),
  ]);

  // ── Corpus signals breakdown ────────────────────────────────────────────────
  const signalRows = d1(`
    SELECT s.type, COUNT(*) as hits, AVG(s.weight) as avg_weight
    FROM signals s
    JOIN verdicts v ON s.verdict_id = v.id
    WHERE v.registered_domain = '${domain.replace(/'/g,"''")}'
    GROUP BY s.type ORDER BY hits DESC LIMIT 10
  `);

  // ── Ask Claude for analysis ─────────────────────────────────────────────────
  console.log('Calling Claude for analysis...');

  const systemPrompt = `You are Virgil's triage agent — a security analyst specialising in phishing detection false positive and false negative analysis. You receive evidence about a reported domain and produce a structured, actionable triage report for a maintainer to approve or reject. Be precise, cite the evidence, and always end with a clear recommended action.`;

  const userContent = `
## Triage Request

**Domain:** ${domain}
**Feedback type:** ${feedbackType}
**Verdict that was shown to user:** ${verdictShown}
**Detected brand:** ${detectedBrand || 'none'}

## Intelligence Gathered

### External checks
${fmtIntel(intel)}

### Heuristic analysis (re-run now)
${fmtHeuristics(heuristics)}

### Top signals in corpus for this domain
${signalRows.length > 0
  ? signalRows.map(r => `- \`${r.type}\`: ${r.hits} hits, avg weight ${r.avg_weight?.toFixed(2)}`).join('\n')
  : '- No corpus signals found for this domain'}

### Issue body
${issue.body?.slice(0, 1500)}

## Your task

Produce a triage report with these sections:
1. **Assessment** (2-3 sentences): Is this a genuine FP/FN or is the detection correct?
2. **Evidence summary**: What does the evidence say for and against the detection being correct?
3. **Root cause** (if FP): Which signal(s) caused the false positive and why?
4. **Recommended action**: Exactly ONE of:
   - ADD_TO_SAFELIST — domain is clearly legitimate, add to safe list
   - ADD_TYPOSQUAT — domain IS phishing, add as typosquat for brand X
   - ADJUST_WEIGHT — correct detection but over-triggered, reduce signal weight
   - ADD_BRAND_ENTRY — missing brand entry, add to core-rules
   - NO_ACTION — detection was correct, close as intended
   - NEEDS_MANUAL_REVIEW — evidence is ambiguous, escalate
5. **Proposed rule change** (if applicable): Exact JSON snippet for core-rules, or exact safe list entry

Be direct. Maintainers act on your recommendations.`;

  const analysis = await claude(systemPrompt, userContent, 1500);

  // ── Determine label to add ──────────────────────────────────────────────────
  const actionMatch = analysis.match(/ADD_TO_SAFELIST|ADD_TYPOSQUAT|ADJUST_WEIGHT|ADD_BRAND_ENTRY|NO_ACTION|NEEDS_MANUAL_REVIEW/);
  const action = actionMatch?.[0] || 'NEEDS_MANUAL_REVIEW';

  const actionLabel = {
    ADD_TO_SAFELIST:     'confirmed-fp',
    ADD_TYPOSQUAT:       'confirmed-fn',
    ADJUST_WEIGHT:       'rule-updated',
    ADD_BRAND_ENTRY:     'rule-updated',
    NO_ACTION:           'wont-fix',
    NEEDS_MANUAL_REVIEW: 'needs-triage',
  }[action] || 'needs-triage';

  // ── Post comment ────────────────────────────────────────────────────────────
  const comment = `## 🤖 Agent Triage Report

**Recommended action:** \`${action}\`

---

${analysis}

---

<details>
<summary>Raw intelligence data</summary>

**CT log:** ${intel.ct ? `${intel.ct.ageDays} days old (first seen ${new Date(intel.ct.firstSeenTs).toISOString().slice(0,10)})` : 'not found'}
**Safe Browsing:** ${intel.gsb?.matched ? '⚠ MATCHED' : intel.gsb ? 'clean' : 'not checked'}
**Corpus:** ${intel.corpus.reports} distinct install reports, max verdict: ${intel.corpus.max_risk || 'none'}
**Feed hits:** ${intel.feeds.hits} ingested from ${intel.feeds.feeds || 'no feeds'}

**Heuristic re-run:**
\`\`\`
${fmtHeuristics(heuristics)}
\`\`\`
</details>

---
*Triaged by Virgil Agent 1 at ${new Date().toISOString()}. A maintainer must approve before any action is taken.*`;

  await github.commentOnIssue(REPO, ISSUE_NUMBER, comment);
  await github.addLabel(REPO, ISSUE_NUMBER, ['agent-triaged', actionLabel]);

  console.log(`✓ Comment posted. Recommended action: ${action}`);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
