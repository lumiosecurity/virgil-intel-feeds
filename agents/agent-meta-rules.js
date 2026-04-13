#!/usr/bin/env node
// Virgil — Meta-Rule Engineer Agent (Agent 7)
//
// Runs weekly. Queries the D1 telemetry corpus for signal co-occurrence
// patterns that correlate with Claude "dangerous" verdicts. Proposes meta
// rules that bind weak signals into high-confidence detections, or that
// downscore correlated signals to prevent score creep.
//
// Trigger: GitHub Actions cron (Wednesdays 05:00 UTC)
// Output:  GitHub issue in core-rules repo with proposed meta rules

import { cfg, d1, d1raw, claude, github } from './agent-tools.js';

const LOOKBACK_DAYS = parseInt(process.env.LOOKBACK_DAYS || '14');
const DRY_RUN       = process.argv.includes('--dry-run');
const MODEL         = 'claude-opus-4-20250514';

async function main() {
  console.log(`\nAgent 7: Meta-Rule Engineer`);
  console.log(`Lookback: ${LOOKBACK_DAYS} days, dry-run: ${DRY_RUN}`);

  // ── Load verdicts with signal data ──────────────────────────────────────────
  console.log('Loading corpus verdicts...');

  const dangerousVerdicts = d1raw(`
    SELECT
      v.registered_domain, v.tld, v.detected_brand, v.risk_level,
      v.confidence, v.signals_json, v.heuristic_score, v.created_at
    FROM verdicts v
    WHERE v.risk_level IN ('dangerous', 'suspicious')
      AND v.confidence >= 0.70
      AND v.created_at >= datetime('now', '-${LOOKBACK_DAYS} days')
    ORDER BY v.created_at DESC
    LIMIT 500
  `);

  const safeVerdicts = d1raw(`
    SELECT
      v.registered_domain, v.tld, v.signals_json, v.heuristic_score
    FROM verdicts v
    WHERE v.risk_level = 'safe'
      AND v.created_at >= datetime('now', '-${LOOKBACK_DAYS} days')
    ORDER BY RANDOM()
    LIMIT 500
  `);

  console.log(`Loaded ${dangerousVerdicts.length} dangerous/suspicious, ${safeVerdicts.length} safe verdicts`);

  if (dangerousVerdicts.length < 10) {
    console.log('Insufficient corpus data for meaningful analysis. Exiting.');
    return;
  }

  // ── Extract signal co-occurrence patterns ───────────────────────────────────

  const dangerousPairs = extractCooccurrences(dangerousVerdicts);
  const safePairs = extractCooccurrences(safeVerdicts);

  // Find pairs that appear frequently in dangerous verdicts but rarely in safe ones
  const candidates = [];
  for (const [pair, dangerousCount] of dangerousPairs.entries()) {
    if (dangerousCount < 3) continue; // need minimum support
    const safeCount = safePairs.get(pair) || 0;
    const precision = dangerousCount / (dangerousCount + safeCount);
    const support = dangerousCount / dangerousVerdicts.length;

    if (precision >= 0.80 && support >= 0.05) {
      candidates.push({
        pair,
        dangerousCount,
        safeCount,
        precision: Math.round(precision * 100),
        support: Math.round(support * 100),
      });
    }
  }

  candidates.sort((a, b) => b.precision - a.precision || b.dangerousCount - a.dangerousCount);
  console.log(`Found ${candidates.length} high-precision signal pair candidates`);

  // ── Also find potential score creep ─────────────────────────────────────────

  const scoreCreepCandidates = findScoreCreep(dangerousVerdicts);
  console.log(`Found ${scoreCreepCandidates.length} potential score creep patterns`);

  if (candidates.length === 0 && scoreCreepCandidates.length === 0) {
    console.log('No actionable patterns found. Exiting.');
    return;
  }

  // ── Load existing meta rules to avoid duplicates ────────────────────────────

  let existingRules = [];
  try {
    const files = await github.getFileContent(cfg.coreRulesRepo, 'rules/meta');
    if (Array.isArray(files)) {
      for (const file of files) {
        if (!file.name.endsWith('.json')) continue;
        const content = await github.getFileContent(cfg.coreRulesRepo, file.path);
        const decoded = Buffer.from(content.content, 'base64').toString('utf-8');
        const parsed = JSON.parse(decoded);
        existingRules.push(...(parsed.metaRules || []));
      }
    }
  } catch (e) {
    console.log(`Could not load existing meta rules: ${e.message}`);
  }

  const existingIds = new Set(existingRules.map(r => r.id));
  console.log(`${existingIds.size} existing meta rules loaded`);

  // ── Ask Claude to propose meta rules ────────────────────────────────────────

  const systemPrompt = `You are Virgil's meta-rule engineer. You analyse signal co-occurrence data from the phishing detection corpus and propose meta rules.

Meta rules are JSON objects with this structure:
{
  "id": "lowercase-hyphenated-name",
  "description": "Human-readable explanation of what this rule detects and why the combination matters",
  "conditions": {
    "all": [  // AND — every condition must match
      { "signal": "signal-type-name" },
      { "signal_group": "groupName" },
      { "has_password_form": true },
      { "domain_age_days": { "lt": 7 } },
      { "visual_match_confidence": { "gte": 0.5 } },
      { "has_dom_hash_match": true },
      { "not": { "signal": "some-signal" } }
    ],
    "any": [  // OR — at least one must match (optional)
      { "signal": "option-a" },
      { "signal": "option-b" }
    ]
  },
  "action": {
    "scope": "boost|replace|downscore",
    "weight": 0.30,
    "severity": "high|medium|low|info"
  }
}

Scopes:
- "boost": adds bonus weight when the combination appears (for binding weak signals)
- "replace": zeros out matched signals' weights and injects a single calibrated weight (for dedup/calibration)
- "downscore": reduces combined weight of matched signals to the target weight (for score creep prevention)

Available condition types:
- signal: exact signal type (e.g. "new-domain-whois", "known-typosquat", "brand-in-subdomain")
- signal_group: any signal from a phishkit group (phishkitSignatures, credentialHarvesting, botEvasion, obfuscation, brandImpersonation, socialEngineering, titleImpersonation, cdnGating, captchaGating, typosquatPatterns, urlHeuristics, hostingPatterns)
- signal_prefix: any signal whose type starts with X (e.g. "source-" for all source patterns)
- signal_prefix_count: { prefix: "X", gte: N } — count of distinct signals matching a prefix
- has_form, has_password_form, has_credit_card_form, has_external_form, has_login_form: boolean
- has_visual_match, visual_match_confidence, visual_match_brand: screenshot hash conditions
- has_dom_hash_match, dom_hash_brand: DOM structure hash conditions
- domain_age_hours, domain_age_days: numeric comparisons on WHOIS/CT age
- heuristic_score: numeric comparison on the running risk score
- not: negation wrapper
- where: filter on signal metadata fields (e.g. { "ageDays": { "lt": 7 } })
- behavioral_shape_score: numeric comparison on behavioral model shape score
- behavioral_dimension: true if a specific dimension ("arrival", "relationship", "intent", "pressure", "coherence", "isolation") has signals
- behavioral_pattern: substring match on the named behavioral shape (e.g. "CANONICAL", "AiTM")
- behavioral_credential_gated: true if the behavioral model activated (password field present)
- is_first_visit: true if the user has never visited this domain before (from chrome.history)
- chain_signal: a specific attack chain signal is present — valid values include:
    "chain-origin-webmail", "chain-origin-messaging",
    "chain-intermediate-abused-hosting", "chain-intermediate-url-shortener",
    "chain-parent-dangerous", "chain-parent-suspicious",
    "chain-depth-credential-harvest", "chain-depth-deep", "chain-brand-mismatch"
- chain_pattern: a named multi-stage attack funnel was detected — valid values:
    "aitm" (email → abused trusted hosting → credential harvest),
    "email-shortener-credential", "cascading-suspicious", "email-direct-credential"
- chain_depth: { gte: N } — number of navigation hops before this page
- chain_origin: "webmail" | "messaging" | "chat" — root page type of the chain
- chain_any_signal: true if any chain signal is present

Numeric operators: lt, lte, gt, gte, eq, neq

Rules:
1. Every proposed rule must be justified by the corpus data provided
2. Do not propose rules that already exist (existing IDs listed below)
3. Boost weights should be 0.10–0.35 — enough to push over a gate threshold, not enough to dominate
4. Replace weights should reflect the TRUE phishing probability of the combination
5. Downscore weights should be conservative — better to leave score slightly high than suppress a real phish
6. IDs must be lowercase hyphenated: ^[a-z0-9-]+$

Output ONLY a JSON array of meta rule objects. No markdown, no explanation outside the JSON.`;

  const userContent = `## Signal Co-occurrence Analysis (${LOOKBACK_DAYS}-day lookback)

### High-precision signal pairs (appear in dangerous verdicts, rarely in safe):
${candidates.slice(0, 20).map(c =>
    `  ${c.pair} — ${c.dangerousCount} dangerous, ${c.safeCount} safe (precision: ${c.precision}%, support: ${c.support}%)`
  ).join('\n') || '  (none found)'}

### Potential score creep patterns (multiple correlated signals inflating score):
${scoreCreepCandidates.slice(0, 10).map(c =>
    `  Signals: ${c.signals.join(' + ')} — avg combined weight: ${c.avgWeight.toFixed(2)}, fires together ${c.count} times`
  ).join('\n') || '  (none found)'}

### Existing meta rule IDs (do NOT duplicate these):
${[...existingIds].join(', ') || '(none)'}

### Corpus summary:
- ${dangerousVerdicts.length} dangerous/suspicious verdicts analysed
- ${safeVerdicts.length} safe verdicts as control group
- Lookback period: ${LOOKBACK_DAYS} days

Propose meta rules based on this data. Focus on:
1. Binding weak signal pairs with >= 80% precision into boost rules
2. Replacing correlated signal groups that inflate scores with calibrated weights
3. Only propose rules with clear corpus evidence — no speculative combinations
4. If chain signals (type prefix "chain-") appear in the high-precision pairs, propose chain-aware meta rules. Chain conditions are especially valuable for multi-stage AiTM funnels where each individual page scores low — the combination of chain_pattern + has_password_form is very high precision and low FP risk`;

  console.log('Asking Claude for meta rule proposals...');
  const response = await claude(systemPrompt, userContent, 4000, null, MODEL);

  // Parse proposals
  let proposals = [];
  try {
    const clean = response.replace(/```json|```/g, '').trim();
    proposals = JSON.parse(clean);
    if (!Array.isArray(proposals)) proposals = [proposals];
  } catch (e) {
    console.error('Failed to parse Claude response as JSON:', e.message);
    console.log('Raw response:', response.slice(0, 500));
    return;
  }

  // Filter out duplicates and invalid rules
  const validProposals = proposals.filter(r => {
    if (!r.id || !r.conditions || !r.action) return false;
    if (existingIds.has(r.id)) return false;
    if (!/^[a-z0-9-]+$/.test(r.id)) return false;
    return true;
  });

  console.log(`Claude proposed ${proposals.length} rules, ${validProposals.length} valid after filtering`);

  if (validProposals.length === 0) {
    console.log('No valid new rules proposed. Exiting.');
    return;
  }

  // ── File issue with proposals ───────────────────────────────────────────────

  const issueBody = `## Meta-Rule Engineer — Automated Proposals

**Lookback:** ${LOOKBACK_DAYS} days | **Corpus:** ${dangerousVerdicts.length} dangerous + ${safeVerdicts.length} safe verdicts
**Generated:** ${new Date().toISOString()}

### Signal Co-occurrence Evidence

${candidates.slice(0, 15).map(c =>
    `| \`${c.pair}\` | ${c.dangerousCount} dangerous | ${c.safeCount} safe | ${c.precision}% precision |`
  ).join('\n')}

### Proposed Meta Rules (${validProposals.length})

${validProposals.map(r => `#### \`${r.id}\` (${r.action.scope}, weight: ${r.action.weight})
${r.description}

\`\`\`json
${JSON.stringify(r, null, 2)}
\`\`\`
`).join('\n')}

---
*Auto-generated by Agent 7 (meta-rule engineer). Label \`/apply\` to commit, or close to discard.*`;

  if (DRY_RUN) {
    console.log('\n[DRY RUN] Would create issue:');
    console.log(issueBody.slice(0, 1000));
    console.log('\nProposed rules:');
    console.log(JSON.stringify(validProposals, null, 2));
  } else {
    const issue = await github.createIssue(
      cfg.coreRulesRepo,
      `meta-rule proposals: ${validProposals.length} rules from corpus analysis`,
      issueBody,
      ['meta-rule-proposal', 'agent-generated']
    );
    console.log(`Issue created: #${issue.number}`);
  }
}


// ── Helpers ───────────────────────────────────────────────────────────────────

function extractCooccurrences(verdicts) {
  const pairs = new Map();
  for (const v of verdicts) {
    let signals;
    try { signals = JSON.parse(v.signals_json || '[]'); } catch { continue; }
    const types = [...new Set(signals.map(s => s.type).filter(Boolean))];

    // Generate all pairs
    for (let i = 0; i < types.length; i++) {
      for (let j = i + 1; j < types.length; j++) {
        const pair = [types[i], types[j]].sort().join(' + ');
        pairs.set(pair, (pairs.get(pair) || 0) + 1);
      }
    }
  }
  return pairs;
}

function findScoreCreep(verdicts) {
  // Find groups of 3+ signals that always fire together — indicates correlated detection
  const triples = new Map();

  for (const v of verdicts) {
    let signals;
    try { signals = JSON.parse(v.signals_json || '[]'); } catch { continue; }
    const types = [...new Set(signals.map(s => s.type).filter(Boolean))].sort();
    const weights = {};
    for (const s of signals) { if (s.type) weights[s.type] = s.weight || 0; }

    // Generate all triples
    for (let i = 0; i < types.length; i++) {
      for (let j = i + 1; j < types.length; j++) {
        for (let k = j + 1; k < types.length; k++) {
          const key = `${types[i]}|${types[j]}|${types[k]}`;
          const w = (weights[types[i]] || 0) + (weights[types[j]] || 0) + (weights[types[k]] || 0);
          const entry = triples.get(key) || { signals: [types[i], types[j], types[k]], count: 0, totalWeight: 0 };
          entry.count++;
          entry.totalWeight += w;
          triples.set(key, entry);
        }
      }
    }
  }

  return [...triples.values()]
    .filter(t => t.count >= 5 && t.totalWeight / t.count > 0.60)
    .map(t => ({ ...t, avgWeight: t.totalWeight / t.count }))
    .sort((a, b) => b.avgWeight - a.avgWeight);
}

main().catch(err => {
  console.error('Agent 7 failed:', err);
  process.exit(1);
});
