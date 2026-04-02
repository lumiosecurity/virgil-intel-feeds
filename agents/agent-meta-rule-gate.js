#!/usr/bin/env node
// Virgil — Meta-Rule Quality Gate Agent (Agent 8)
//
// Reviews proposed meta rules before they are committed. Validates structure,
// checks for logical errors, tests against known corpus data, and uses Opus
// to assess whether the rule is sound.
//
// Trigger: Called as a step inside auto-promote for meta-rule proposals,
//          or via GitHub Actions on PRs to rules/meta/ in virgil-rules.
// Input:   RULES_JSON env var (JSON string of proposed meta rules)
//          or ISSUE_NUMBER env var (issue with JSON blocks to extract)
// Output:  Exit 0 = approved, Exit 1 = rejected (with reasons)

import { cfg, d1raw, claude, github } from './agent-tools.js';

const DRY_RUN      = process.argv.includes('--dry-run');
const RULES_JSON   = process.env.RULES_JSON;
const ISSUE_NUMBER = process.env.ISSUE_NUMBER;
const PR_NUMBER    = process.env.PR_NUMBER;
const MODEL        = 'claude-opus-4-20250514';

// ── Valid values ──────────────────────────────────────────────────────────────

const VALID_SCOPES = new Set(['boost', 'replace', 'downscore']);
const VALID_SEVERITY = new Set(['high', 'medium', 'low', 'info']);
const VALID_GROUPS = new Set([
  'phishkitSignatures', 'cdnGating', 'captchaGating', 'botEvasion',
  'obfuscation', 'brandImpersonation', 'credentialHarvesting',
  'socialEngineering', 'titleImpersonation', 'typosquatPatterns',
  'urlHeuristics', 'hostingPatterns', 'suspiciousDomains',
]);
const VALID_NUMERIC_OPS = new Set(['lt', 'lte', 'gt', 'gte', 'eq', 'neq']);

const VALID_CONDITION_KEYS = new Set([
  'signal', 'signal_group', 'signal_prefix', 'where',
  'has_form', 'has_password_form', 'has_credit_card_form',
  'has_external_form', 'has_login_form',
  'has_visual_match', 'visual_match_confidence', 'visual_match_brand',
  'has_dom_hash_match', 'dom_hash_brand',
  'domain_age_hours', 'domain_age_days',
  'heuristic_score', 'not',
]);

async function main() {
  console.log('\nAgent 8: Meta-Rule Quality Gate');

  // ── Load rules to validate ──────────────────────────────────────────────────

  let rules = [];

  if (RULES_JSON) {
    try {
      rules = JSON.parse(RULES_JSON);
      if (!Array.isArray(rules)) rules = [rules];
    } catch (e) {
      fail(`Failed to parse RULES_JSON: ${e.message}`);
    }
  } else if (ISSUE_NUMBER) {
    rules = await extractRulesFromIssue(ISSUE_NUMBER);
  } else if (PR_NUMBER) {
    rules = await extractRulesFromPR(PR_NUMBER);
  } else {
    fail('No input: set RULES_JSON, ISSUE_NUMBER, or PR_NUMBER');
  }

  console.log(`Validating ${rules.length} meta rule(s)...`);

  if (rules.length === 0) {
    fail('No meta rules found in input');
  }

  // ── Structural validation ───────────────────────────────────────────────────

  const errors = [];

  for (const rule of rules) {
    const prefix = `Rule "${rule.id || '(no id)'}"`;

    // Required fields
    if (!rule.id) { errors.push(`${prefix}: missing id`); continue; }
    if (!/^[a-z0-9-]+$/.test(rule.id)) errors.push(`${prefix}: id must match ^[a-z0-9-]+$`);
    if (!rule.description || rule.description.length < 10) errors.push(`${prefix}: description too short (min 10 chars)`);
    if (!rule.conditions) { errors.push(`${prefix}: missing conditions`); continue; }
    if (!rule.action) { errors.push(`${prefix}: missing action`); continue; }

    // Conditions
    if (!rule.conditions.all && !rule.conditions.any) {
      errors.push(`${prefix}: conditions must have at least one of "all" or "any"`);
    }

    for (const cond of [...(rule.conditions.all || []), ...(rule.conditions.any || [])]) {
      validateCondition(cond, prefix, errors);
    }

    // Must have at least 2 conditions total (meta rules are combinations)
    const totalConditions = (rule.conditions.all || []).length + (rule.conditions.any || []).length;
    if (totalConditions < 2) {
      errors.push(`${prefix}: meta rules must combine at least 2 conditions (found ${totalConditions})`);
    }

    // Action
    if (!VALID_SCOPES.has(rule.action.scope)) {
      errors.push(`${prefix}: invalid scope "${rule.action.scope}" — must be boost, replace, or downscore`);
    }
    if (typeof rule.action.weight !== 'number') {
      errors.push(`${prefix}: weight must be a number`);
    } else {
      if (rule.action.scope === 'boost' && (rule.action.weight < 0.05 || rule.action.weight > 0.40)) {
        errors.push(`${prefix}: boost weight ${rule.action.weight} out of range [0.05, 0.40]`);
      }
      if (rule.action.scope === 'replace' && (rule.action.weight < 0.05 || rule.action.weight > 0.60)) {
        errors.push(`${prefix}: replace weight ${rule.action.weight} out of range [0.05, 0.60]`);
      }
      if (rule.action.scope === 'downscore' && (rule.action.weight < 0.0 || rule.action.weight > 0.50)) {
        errors.push(`${prefix}: downscore target weight ${rule.action.weight} out of range [0.00, 0.50]`);
      }
    }
    if (!VALID_SEVERITY.has(rule.action.severity)) {
      errors.push(`${prefix}: invalid severity "${rule.action.severity}"`);
    }

    // Logical checks
    if (rule.action.scope === 'downscore' && rule.action.severity === 'high') {
      errors.push(`${prefix}: downscore rules should not be severity "high" — they reduce risk`);
    }
  }

  if (errors.length > 0) {
    console.log(`\nStructural validation failed with ${errors.length} error(s):`);
    errors.forEach(e => console.log(`  ✗ ${e}`));
    fail(`Structural validation: ${errors.length} error(s)\n\n${errors.map(e => `- ${e}`).join('\n')}`);
  }

  console.log('Structural validation passed');

  // ── Corpus backtesting ──────────────────────────────────────────────────────

  console.log('Running corpus backtest...');

  let backtestResults = [];
  try {
    backtestResults = await backtestRules(rules);
  } catch (e) {
    console.warn(`Corpus backtest failed (non-fatal): ${e.message}`);
  }

  // ── Opus review ─────────────────────────────────────────────────────────────

  console.log('Requesting Opus review...');

  const opusSystemPrompt = `You are the quality gate for Virgil's meta-rule system. Meta rules combine weak detection signals into calibrated phishing detections, or prevent score inflation from correlated signals.

Your job is to determine if each proposed rule is:
1. LOGICALLY SOUND: Does the signal combination genuinely indicate phishing (for boost/replace) or score inflation (for downscore)?
2. APPROPRIATELY WEIGHTED: Is the weight proportional to the combination's specificity?
3. SAFE: Could this rule cause false positives (boost rules flagging legit pages) or false negatives (downscore rules suppressing real phish)?

Review each rule and respond with a JSON object:
{
  "approved": true/false,
  "rules": {
    "rule-id": {
      "verdict": "APPROVE" | "REJECT" | "ADJUST",
      "reason": "explanation",
      "suggestedWeight": 0.25  // only if ADJUST
    }
  }
}`;

  const opusUserContent = `## Proposed Meta Rules

${rules.map(r => `### \`${r.id}\` (${r.action.scope}, weight: ${r.action.weight}, severity: ${r.action.severity})
${r.description}
\`\`\`json
${JSON.stringify(r, null, 2)}
\`\`\`
`).join('\n')}

${backtestResults.length > 0 ? `## Corpus Backtest Results
${backtestResults.map(b => `- \`${b.id}\`: would fire on ${b.dangerousHits} dangerous, ${b.safeHits} safe verdicts (precision: ${b.precision}%)`).join('\n')}` : '## Corpus Backtest\nBacktest data unavailable.'}

Review each rule for logical soundness, weight calibration, and safety.`;

  const opusResponse = await claude(opusSystemPrompt, opusUserContent, 2000, null, MODEL);

  let opusVerdict;
  try {
    const clean = opusResponse.replace(/```json|```/g, '').trim();
    opusVerdict = JSON.parse(clean);
  } catch (e) {
    console.warn('Could not parse Opus response as JSON, treating as text review');
    opusVerdict = { approved: !opusResponse.toLowerCase().includes('reject'), raw: opusResponse };
  }

  console.log(`Opus verdict: ${opusVerdict.approved ? 'APPROVED' : 'REJECTED'}`);
  if (opusVerdict.rules) {
    for (const [id, review] of Object.entries(opusVerdict.rules)) {
      console.log(`  ${id}: ${review.verdict} — ${review.reason}`);
    }
  }

  // ── Output result ───────────────────────────────────────────────────────────

  const report = formatReport(rules, errors, backtestResults, opusVerdict);

  if (DRY_RUN) {
    console.log('\n[DRY RUN] Gate report:');
    console.log(report);
    process.exit(opusVerdict.approved ? 0 : 1);
  }

  // Post report as comment if we have an issue or PR
  if (ISSUE_NUMBER) {
    await github.commentOnIssue(cfg.coreRulesRepo, ISSUE_NUMBER, report);
    if (!opusVerdict.approved) {
      await github.addLabel(cfg.coreRulesRepo, ISSUE_NUMBER, ['needs-review']);
    }
  }
  if (PR_NUMBER) {
    const event = opusVerdict.approved ? 'APPROVE' : 'REQUEST_CHANGES';
    await github.reviewPR(cfg.communityRepo, PR_NUMBER, event, report);
  }

  process.exit(opusVerdict.approved ? 0 : 1);
}


// ── Condition validation ──────────────────────────────────────────────────────

function validateCondition(cond, prefix, errors) {
  const keys = Object.keys(cond);

  if (keys.length === 0) {
    errors.push(`${prefix}: empty condition object`);
    return;
  }

  for (const key of keys) {
    if (!VALID_CONDITION_KEYS.has(key)) {
      errors.push(`${prefix}: unknown condition key "${key}"`);
    }
  }

  if (cond.signal_group && !VALID_GROUPS.has(cond.signal_group)) {
    errors.push(`${prefix}: invalid signal_group "${cond.signal_group}"`);
  }

  // Validate numeric operator objects
  for (const numField of ['visual_match_confidence', 'domain_age_hours', 'domain_age_days', 'heuristic_score']) {
    if (cond[numField] && typeof cond[numField] === 'object') {
      for (const op of Object.keys(cond[numField])) {
        if (!VALID_NUMERIC_OPS.has(op)) {
          errors.push(`${prefix}: invalid numeric operator "${op}" in ${numField}`);
        }
      }
    }
  }

  // Recurse into not
  if (cond.not) {
    validateCondition(cond.not, `${prefix} (negated)`, errors);
  }

  // Validate where clause
  if (cond.where && typeof cond.where === 'object') {
    for (const [field, constraint] of Object.entries(cond.where)) {
      if (typeof constraint === 'object') {
        for (const op of Object.keys(constraint)) {
          if (!VALID_NUMERIC_OPS.has(op)) {
            errors.push(`${prefix}: invalid operator "${op}" in where.${field}`);
          }
        }
      }
    }
  }
}


// ── Corpus backtesting ────────────────────────────────────────────────────────

async function backtestRules(rules) {
  // Load recent verdicts with full signal data
  const verdicts = d1raw(`
    SELECT risk_level, signals_json, heuristic_score
    FROM verdicts
    WHERE created_at >= datetime('now', '-14 days')
      AND signals_json IS NOT NULL
    ORDER BY created_at DESC
    LIMIT 1000
  `);

  const results = [];

  for (const rule of rules) {
    let dangerousHits = 0, safeHits = 0;

    for (const v of verdicts) {
      let signals;
      try { signals = JSON.parse(v.signals_json); } catch { continue; }

      // Simplified condition matching for backtesting
      // (only checks signal/signal_group/signal_prefix — not form/visual/dom conditions
      // since those aren't stored in the verdict table)
      const signalTypes = new Set(signals.map(s => s.type));
      const signalGroups = new Set(signals.map(s => s.group).filter(Boolean));

      let allMatch = true;
      for (const cond of (rule.conditions.all || [])) {
        if (cond.signal && !signalTypes.has(cond.signal)) { allMatch = false; break; }
        if (cond.signal_group && !signalGroups.has(cond.signal_group)) { allMatch = false; break; }
        if (cond.signal_prefix && ![...signalTypes].some(t => t.startsWith(cond.signal_prefix))) { allMatch = false; break; }
        // Skip form/visual/dom conditions — can't backtest these from verdict data
      }

      let anyMatch = !rule.conditions.any;
      if (rule.conditions.any) {
        for (const cond of rule.conditions.any) {
          if (cond.signal && signalTypes.has(cond.signal)) { anyMatch = true; break; }
          if (cond.signal_group && signalGroups.has(cond.signal_group)) { anyMatch = true; break; }
        }
      }

      if (allMatch && anyMatch) {
        if (v.risk_level === 'dangerous' || v.risk_level === 'suspicious') dangerousHits++;
        else safeHits++;
      }
    }

    const total = dangerousHits + safeHits;
    results.push({
      id: rule.id,
      dangerousHits,
      safeHits,
      precision: total > 0 ? Math.round(dangerousHits / total * 100) : 0,
    });
  }

  return results;
}


// ── Helpers ───────────────────────────────────────────────────────────────────

async function extractRulesFromIssue(issueNumber) {
  const issue = await github.getIssue(cfg.coreRulesRepo, issueNumber);
  const body = issue.body || '';
  const jsonBlocks = body.match(/```json\s*([\s\S]*?)```/g) || [];
  const rules = [];
  for (const block of jsonBlocks) {
    try {
      const json = block.replace(/```json|```/g, '').trim();
      const parsed = JSON.parse(json);
      if (parsed.id && parsed.conditions) rules.push(parsed);
      if (Array.isArray(parsed)) rules.push(...parsed.filter(r => r.id && r.conditions));
    } catch {}
  }
  return rules;
}

async function extractRulesFromPR(prNumber) {
  const files = await github.getPRFiles(cfg.communityRepo, prNumber);
  const rules = [];
  for (const file of files) {
    if (!file.filename.startsWith('rules/meta/') || !file.filename.endsWith('.json')) continue;
    try {
      const content = await github.getFileContent(cfg.communityRepo, file.filename, file.sha);
      const decoded = Buffer.from(content.content, 'base64').toString('utf-8');
      const parsed = JSON.parse(decoded);
      rules.push(...(parsed.metaRules || []));
    } catch {}
  }
  return rules;
}

function formatReport(rules, structErrors, backtest, opus) {
  let report = `## Meta-Rule Quality Gate Report\n\n`;
  report += `**Rules reviewed:** ${rules.length}\n`;
  report += `**Structural errors:** ${structErrors.length}\n`;
  report += `**Opus verdict:** ${opus.approved ? '✅ APPROVED' : '❌ REJECTED'}\n\n`;

  if (backtest.length > 0) {
    report += `### Corpus Backtest\n\n| Rule | Dangerous hits | Safe hits | Precision |\n|------|---------------|-----------|----------|\n`;
    for (const b of backtest) {
      report += `| \`${b.id}\` | ${b.dangerousHits} | ${b.safeHits} | ${b.precision}% |\n`;
    }
    report += '\n';
  }

  if (opus.rules) {
    report += `### Opus Review\n\n`;
    for (const [id, review] of Object.entries(opus.rules)) {
      const icon = review.verdict === 'APPROVE' ? '✅' : review.verdict === 'ADJUST' ? '⚠️' : '❌';
      report += `${icon} **\`${id}\`**: ${review.verdict} — ${review.reason}\n`;
      if (review.suggestedWeight !== undefined) {
        report += `  → Suggested weight: ${review.suggestedWeight}\n`;
      }
    }
  }

  return report;
}

function fail(message) {
  console.error(`\n❌ GATE FAILED: ${message}`);
  process.exit(1);
}

main().catch(err => {
  console.error('Agent 8 failed:', err);
  process.exit(1);
});
