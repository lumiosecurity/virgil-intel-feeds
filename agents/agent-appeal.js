#!/usr/bin/env node
// Virgil — Blocklist Appeal Processor (Agent 5)
//
// Triggered when a GitHub issue is labeled 'feedback:false_positive'.
// Verifies the domain against multiple authoritative sources and either
// auto-approves removal (high confidence legitimate) or escalates.
//
// Trigger: GitHub Actions issues webhook (types: labeled)
// Input:   ISSUE_NUMBER env var
// Output:  GitHub issue comment + blocklist removal if auto-approved

import { cfg, d1, claude, github, getCTAge } from './agent-tools.js';

const ISSUE_NUMBER = parseInt(process.env.ISSUE_NUMBER || process.argv[2]);
const REPO         = cfg.coreRulesRepo;
const DRY_RUN      = process.argv.includes('--dry-run');

// Auto-approve removal if ALL of these pass:
const AUTO_APPROVE_CRITERIA = {
  minDomainAgeDays:  30,   // domain must be at least 30 days old
  maxCorpusReports:  2,    // at most 2 distinct reports in corpus
};

if (!ISSUE_NUMBER) { console.error('ISSUE_NUMBER required'); process.exit(1); }

async function main() {
  console.log(`\nAgent 5: Blocklist Appeal Processor — Issue #${ISSUE_NUMBER}`);

  const issue = await github.getIssue(REPO, ISSUE_NUMBER);
  if (!issue) { console.error('Issue not found'); process.exit(1); }

  const labels = issue.labels.map(l => l.name);

  // Only process FP feedback issues
  if (!labels.includes('feedback:false_positive') && !labels.includes('confirmed-fp')) {
    console.log('Not a false positive issue — skipping');
    process.exit(0);
  }

  // Don't re-process
  if (labels.includes('appeal-processed')) {
    console.log('Already processed — skipping');
    process.exit(0);
  }

  // ── Extract domain ──────────────────────────────────────────────────────────
  const domainMatch = issue.body?.match(/\| Domain \| `([^`]+)` \|/);
  const domain = domainMatch?.[1]?.trim();

  if (!domain) {
    await github.commentOnIssue(REPO, ISSUE_NUMBER,
      '⚠️ **Appeal Agent:** Could not extract domain from issue. Manual review required.');
    await github.addLabel(REPO, ISSUE_NUMBER, ['appeal-processed', 'needs-triage']);
    process.exit(0);
  }

  console.log(`Domain: ${domain}`);

  // ── Gather verification data ────────────────────────────────────────────────
  console.log('Gathering verification data...');

  const [ct] = await Promise.all([
    getCTAge(domain),
  ]);

  // Corpus reports for this domain
  const corpusReports = d1`
    SELECT
      COUNT(DISTINCT install_id) as distinct_installs,
      COUNT(*) as total_verdicts,
      AVG(confidence) as avg_conf,
      MAX(created_at) as last_seen,
      GROUP_CONCAT(DISTINCT risk_level) as risk_levels
    FROM verdicts
    WHERE registered_domain = ${domain}
  `;

  const report = corpusReports[0] || {};

  // Check if domain is actually in the blocklist
  const blocklistRows = d1`
    SELECT registered_domain, COUNT(DISTINCT install_id) as reports,
           AVG(confidence) as avg_conf
    FROM verdicts
    WHERE registered_domain = ${domain}
      AND risk_level = 'dangerous'
      AND created_at >= datetime('now', '-30 days')
    GROUP BY registered_domain
  `;

  const inBlocklistCriteria = blocklistRows.length > 0;

  // ── Evaluate auto-approve criteria ─────────────────────────────────────────
  const checks = {
    domainAge:    ct?.ageDays >= AUTO_APPROVE_CRITERIA.minDomainAgeDays,
    corpusReports:report.distinct_installs <= AUTO_APPROVE_CRITERIA.maxCorpusReports,
    notConfirmedPhish: !inBlocklistCriteria || (report.distinct_installs || 0) <= 2,
  };

  const autoApprove = Object.values(checks).every(Boolean);
  const checksPassed = Object.values(checks).filter(Boolean).length;

  console.log(`Auto-approve checks: ${checksPassed}/${Object.keys(checks).length} passed`);
  console.log(`CT age: ${ct?.ageDays || 'unknown'} days`);
  console.log(`Corpus reports: ${report.distinct_installs || 0}`);

  // ── Ask Claude for recommendation ───────────────────────────────────────────
  const systemPrompt = `You are Virgil's appeal processor. You evaluate false positive reports — domain owners or users claiming a domain was incorrectly blocked. Your job is to assess whether the domain is genuinely legitimate and should be removed from the blocklist, or whether the block is justified. Be conservative: only recommend removal when the evidence strongly supports legitimacy. A false removal is worse than a false retention.`;

  const userContent = `
## Blocklist Appeal

**Domain:** ${domain}
**Issue:** #${ISSUE_NUMBER} — "${issue.title}"

## Verification results

**Certificate Transparency:**
${ct ? `- First cert issued: ${new Date(ct.firstSeenTs).toISOString().slice(0,10)} (${ct.ageDays} days ago)` : '- Not found in CT logs — domain may be very new'}

**Corpus reports:**
- Distinct installs that reported this domain: ${report.distinct_installs || 0}
- Total verdicts: ${report.total_verdicts || 0}
- Average confidence: ${report.avg_conf?.toFixed(2) || 'N/A'}
- Verdict types: ${report.risk_levels || 'none'}
- Last seen: ${report.last_seen || 'never'}

**Currently blocking?** ${inBlocklistCriteria ? 'Yes — meets blocklist criteria in last 30 days' : 'No — does not currently meet blocklist threshold'}

**Auto-approve criteria:**
- Domain age ≥ 30 days: ${checks.domainAge ? '✅' : '❌'} (${ct?.ageDays || 'unknown'} days)
- ≤ 2 corpus reports: ${checks.corpusReports ? '✅' : '❌'} (${report.distinct_installs || 0} reports)
- Not confirmed phish: ${checks.notConfirmedPhish ? '✅' : '❌'}

**Auto-approve threshold met:** ${autoApprove ? 'YES' : 'NO'} (${checksPassed}/${Object.keys(checks).length})

## Issue body (user's explanation)
${issue.body?.slice(0, 800)}

## Your recommendation

Give ONE of:
- **REMOVE**: Remove from blocklist, add to safe list. Explain why the evidence supports this.
- **ESCALATE**: Evidence is ambiguous, human review needed. Explain what additional verification would resolve it.
- **REJECT_APPEAL**: Domain shows signs of being malicious. Explain the evidence.

Then provide:
- 2-3 sentence justification
- If REMOVE: exact safe list entry format: \`domain.com\`
- If ESCALATE: specific question that needs answering
- If REJECT_APPEAL: what malicious indicators remain`;

  const recommendation = await claude(systemPrompt, userContent, 800);

  const isRemove   = recommendation.includes('**REMOVE**') || recommendation.startsWith('REMOVE');
  const isReject   = recommendation.includes('**REJECT_APPEAL**') || recommendation.startsWith('REJECT_APPEAL');
  const isEscalate = !isRemove && !isReject;

  const action = isRemove ? 'REMOVE' : isReject ? 'REJECT_APPEAL' : 'ESCALATE';
  const confidence = autoApprove ? 'high' : checksPassed >= 3 ? 'medium' : 'low';

  // ── Act on recommendation ───────────────────────────────────────────────────
  let actionTaken = '';

  if (isRemove && autoApprove && !DRY_RUN) {
    // High-confidence auto-removal: add to safe list in core-rules
    try {
      // Get current safe list file
      const safeListFile = await github.getFileContent(cfg.coreRulesRepo, 'safe-list/domains.txt').catch(() => null);
      const currentContent = safeListFile
        ? Buffer.from(safeListFile.content, 'base64').toString('utf8')
        : '# Virgil community safe list\n# One domain per line\n';

      if (!currentContent.includes(domain)) {
        const newContent = currentContent.trimEnd() + `\n${domain}  # auto-added by appeal agent, issue #${ISSUE_NUMBER}\n`;
        await github.createOrUpdateFile(
          cfg.coreRulesRepo,
          'safe-list/domains.txt',
          `chore: add ${domain} to safe list (appeal #${ISSUE_NUMBER})`,
          newContent,
          safeListFile?.sha || null
        );
        actionTaken = `✅ **Auto-action taken:** \`${domain}\` has been added to the community safe list.`;
      } else {
        actionTaken = `ℹ️ \`${domain}\` is already in the safe list.`;
      }
    } catch (e) {
      actionTaken = `⚠️ Could not auto-update safe list: ${e.message}. Manual action required.`;
    }
  } else if (isRemove && autoApprove && DRY_RUN) {
    actionTaken = `[dry-run] Would add \`${domain}\` to safe-list/domains.txt`;
  } else if (isRemove && !autoApprove) {
    actionTaken = `⚠️ Removal recommended but not all auto-approve criteria met (${checksPassed}/${Object.keys(checks).length}). **A maintainer must manually approve this removal.**`;
  }

  // ── Post comment ────────────────────────────────────────────────────────────
  const labelToAdd = isRemove ? 'confirmed-fp' : isReject ? 'wont-fix' : 'needs-triage';

  const comment = `## 🤖 Appeal Processing Report

**Domain:** \`${domain}\`
**Recommendation:** \`${action}\`
**Confidence:** ${confidence}
**Auto-approve criteria:** ${checksPassed}/${Object.keys(checks).length} passed

---

${recommendation}

${actionTaken ? `\n---\n\n${actionTaken}` : ''}

---

| Check | Result |
|-------|--------|
| Domain age | ${checks.domainAge ? `✅ ${ct?.ageDays} days` : `❌ ${ct?.ageDays || 'unknown'} days (need ≥30)`} |
| Corpus reports | ${checks.corpusReports ? `✅ ${report.distinct_installs || 0} reports` : `❌ ${report.distinct_installs} reports (need ≤2)`} |
| Not confirmed phish | ${checks.notConfirmedPhish ? '✅' : '❌ Recently blocked with high confidence'} |

---
*Processed by Virgil Appeal Agent at ${new Date().toISOString()}*`;

  await github.commentOnIssue(REPO, ISSUE_NUMBER, comment);
  await github.addLabel(REPO, ISSUE_NUMBER, ['appeal-processed', labelToAdd]);

  if (isRemove && autoApprove && !DRY_RUN) {
    await github.closeIssue(REPO, ISSUE_NUMBER, 'completed');
  }

  console.log(`✓ Comment posted. Action: ${action}, confidence: ${confidence}`);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
