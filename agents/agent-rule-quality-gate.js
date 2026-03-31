#!/usr/bin/env node
// Virgil — Rule Quality Gate (Agent 4)
//
// Runs BEFORE auto-promote commits rules to core-rules.
// Triggered when agent-triaged label is added to a rule-gap issue.
// Uses Claude Opus to evaluate quality, FP risk, and specificity.
//
// Exit codes:
//   0 = PASS  — auto-promote may proceed
//   1 = FAIL  — rules blocked, issue labeled needs-review
//
// Env vars: ISSUE_NUMBER, GITHUB_TOKEN, ANTHROPIC_API_KEY

import { cfg, d1, github } from './agent-tools.js';
import Anthropic from '@anthropic-ai/sdk';

const ISSUE_NUMBER = parseInt(process.env.ISSUE_NUMBER || process.argv[2]);
const REPO         = cfg.coreRulesRepo;

if (!ISSUE_NUMBER) { console.error('ISSUE_NUMBER required'); process.exit(1); }

// Tranco top domains — used for FP testing
// Subset of top-1000 most visited sites — if a pattern matches these, it's a FP risk
const TRANCO_TOP_1000_SAMPLE = [
  'google.com','youtube.com','facebook.com','twitter.com','instagram.com',
  'linkedin.com','reddit.com','wikipedia.org','amazon.com','netflix.com',
  'microsoft.com','apple.com','github.com','stackoverflow.com','dropbox.com',
  'slack.com','zoom.us','shopify.com','wordpress.com','tumblr.com',
  'pinterest.com','twitch.tv','discord.com','spotify.com','paypal.com',
  'ebay.com','etsy.com','airbnb.com','uber.com','lyft.com',
  'stripe.com','square.com','venmo.com','cashapp.com','robinhood.com',
  'coinbase.com','binance.com','chase.com','bankofamerica.com','wellsfargo.com',
  'citi.com','capitalone.com','amex.com','discover.com','usbank.com',
  'verizon.com','att.com','tmobile.com','comcast.com','spectrum.com',
  'adobe.com','salesforce.com','oracle.com','sap.com','servicenow.com',
  'okta.com','docusign.com','hubspot.com','zendesk.com','atlassian.com',
  'notion.so','figma.com','canva.com','miro.com','asana.com',
  'trello.com','monday.com','airtable.com','clickup.com','basecamp.com',
  'mailchimp.com','sendgrid.com','twilio.com','cloudflare.com','fastly.com',
  'aws.amazon.com','azure.microsoft.com','cloud.google.com','heroku.com','vercel.com',
];

async function claude(system, user, maxTokens = 2000) {
  const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
  const resp = await client.messages.create({
    model:      'claude-opus-4-6',
    max_tokens: maxTokens,
    system,
    messages:   [{ role: 'user', content: user }],
  });
  return resp.content?.[0]?.text || '';
}

async function main() {
  console.log(`\nAgent 4: Rule Quality Gate — Issue #${ISSUE_NUMBER}`);

  const issue = await github.getIssue(REPO, ISSUE_NUMBER);
  if (!issue) { console.error('Issue not found'); process.exit(1); }

  // Get triage agent comment with rule proposals
  const comments = await github.getIssueComments(REPO, ISSUE_NUMBER);
  const triageComment = [...comments].reverse().find(c =>
    c.body?.includes('🤖 Agent Triage Report') && c.body?.includes('Rule JSON')
  );

  if (!triageComment) {
    console.log('No triage comment found — skipping quality gate');
    process.exit(0);
  }

  // Extract proposed rules
  const blocks = [];
  const re = /```json\n([\s\S]*?)```/g;
  let m;
  while ((m = re.exec(triageComment.body)) !== null) {
    try { blocks.push(JSON.parse(m[1])); } catch {}
  }

  const PLACEHOLDER_IDS   = new Set(['example-source-pattern','my-pattern-id','pattern-id']);
  const PLACEHOLDER_NAMES = new Set(['example-brand','brand-name','brandname']);

  const rules = blocks.filter(b => {
    if (b.name && b.domains && b.typos) return !PLACEHOLDER_NAMES.has(b.name);
    if (b.id && b.patternString)        return !PLACEHOLDER_IDS.has(b.id);
    return false;
  });

  if (rules.length === 0) {
    console.log('No actionable rules to evaluate');
    process.exit(0);
  }

  console.log(`Evaluating ${rules.length} proposed rule(s)...`);

  // ── Evaluate each rule ────────────────────────────────────────────────────

  const evaluations = [];

  for (const rule of rules) {
    const eval_ = { rule, issues: [], warnings: [], fpMatches: [], corpusHits: 0 };

    if (rule.name && rule.domains && rule.typos) {
      // Brand entry evaluation

      // 1. Check typos aren't common English words
      const commonWords = new Set(['secure','login','account','online','bank','web','mail',
        'home','info','help','support','service','portal','access','auth','verify',
        'update','confirm','sign','user','pass','card','pay','shop','store','buy']);
      const genericTypos = rule.typos.filter(t => commonWords.has(t) || t.length <= 3);
      if (genericTypos.length > 0) {
        eval_.issues.push(`Typos too generic (common words or too short): ${genericTypos.join(', ')}`);
      }

      // 2. Check typos are plausibly related to the brand
      const unrelatedTypos = rule.typos.filter(t => {
        const brand = rule.name.toLowerCase();
        // Typo should share at least 4 chars with brand name
        const minMatch = brand.length >= 6 ? 4 : Math.floor(brand.length * 0.6);
        let maxCommon = 0;
        for (let i = 0; i <= brand.length - minMatch; i++) {
          if (t.includes(brand.slice(i, i + minMatch))) { maxCommon = minMatch; break; }
        }
        return maxCommon < minMatch && t.length > 5;
      });
      if (unrelatedTypos.length > 2) {
        eval_.warnings.push(`${unrelatedTypos.length} typos don't resemble brand name: ${unrelatedTypos.slice(0,3).join(', ')}`);
      }

      // 3. Check corpus for phishing hits
      try {
        let corpusTotal = 0;
        for (const typo of rule.typos.slice(0, 20)) {
          const rows = d1`
            SELECT registered_domain, COUNT(DISTINCT install_id) as reports
            FROM verdicts
            WHERE risk_level IN ('dangerous','suspicious')
              AND registered_domain = ${typo}
            GROUP BY registered_domain LIMIT 1
          `;
          corpusTotal += rows.reduce((s, r) => s + r.reports, 0);
        }
        eval_.corpusHits = corpusTotal;
      } catch {}

      // 4. Too narrow — only 1-2 typos and no corpus hits
      if (rule.typos.length <= 2 && eval_.corpusHits === 0) {
        eval_.warnings.push(`Only ${rule.typos.length} typo variant(s) with no corpus hits — may be too narrow to be useful`);
      }

      // 5. Duplicate — brand name already in existing rules
      try {
        const existing = d1`
          SELECT detected_brand FROM verdicts
          WHERE detected_brand = ${rule.name} LIMIT 1
        `;
        // Only warn if it's in verdicts but NOT as a phishing hit — suggests it's already covered
        const phishHits = d1`
          SELECT COUNT(*) as hits FROM verdicts
          WHERE detected_brand = ${rule.name} AND risk_level IN ('dangerous','suspicious') LIMIT 1
        `;
        if (existing.length > 0 && phishHits[0]?.hits > 10) {
          eval_.warnings.push(`Brand "${rule.name}" already has ${phishHits[0].hits} phishing verdicts in corpus — may duplicate existing coverage`);
        }
      } catch {}

      // 4. FP check — do any typos match legitimate domains?
      const fpRisk = rule.typos.filter(t =>
        TRANCO_TOP_1000_SAMPLE.some(d => d.includes(t) || t.includes(d.split('.')[0]))
      );
      if (fpRisk.length > 0) {
        eval_.issues.push(`FP risk: typos overlap with top sites: ${fpRisk.join(', ')}`);
        eval_.fpMatches.push(...fpRisk);
      }

    } else if (rule.id && rule.patternString) {
      // Source pattern evaluation
      const isPhishkitSig = rule.group === 'phishkitSignatures';

      // 1. Regex compiles
      let compilesOk = false;
      try {
        new RegExp(rule.patternString, rule.patternFlags || '');
        compilesOk = true;
      } catch (e) {
        eval_.issues.push(`Invalid regex: ${e.message}`);
      }

      if (compilesOk) {
        const patternLength = rule.patternString.replace(/[.*+?^${}()|[\]\\]/g, '').length;

        // ── PERFORMANCE CHECK ─────────────────────────────────────────────
        // Source patterns run against full page source (potentially 5MB+) on
        // every page load. Patterns with backtracking-prone constructs cause
        // measurable UI freezes on content-heavy sites (CNN, Yahoo).
        // These checks enforce linear-time-safe regex construction.
        const ps = rule.patternString;
        const flags = rule.patternFlags || '';
        const dotstarCount = (ps.match(/(?<!\\)\.\*/g) || []).length;
        const hasAlternation = /(?<!\\)\|/.test(ps);
        const hasDotall = flags.includes('s');
        const hasNestedQuant = /[+*]\)[+*?]/.test(ps);
        const lookaheadCount = (ps.match(/\(\?=/g) || []).length;
        const hasMultiDotstar = dotstarCount >= 2;

        let perfScore = 0;
        const perfIssues = [];

        // .* with DOTALL — spans entire multi-MB document as a single line
        if (hasDotall && dotstarCount > 0) {
          perfScore += dotstarCount * 2;
          perfIssues.push(`DOTALL flag with .* (×${dotstarCount}) — each .* scans the entire document as one line. Use [\\\\s\\\\S]{0,N} with a bounded quantifier instead.`);
        }

        // Multiple .* in sequence — A.*B.*C rescans from every position
        if (hasMultiDotstar && !hasDotall) {
          perfScore += dotstarCount;
          perfIssues.push(`${dotstarCount} sequential .* operators — causes O(n²) scanning. Use bounded quantifiers: A[^<]{0,2000}B[^<]{0,2000}C`);
        }

        // .* combined with alternation — tries each branch at every position
        if (dotstarCount > 0 && hasAlternation) {
          perfScore += 2;
          perfIssues.push(`.* with alternation (|) — backtracking engine tries each branch at every string position. Put the most specific literal first or use bounded quantifiers.`);
        }

        // Multiple lookaheads with .* — (?=.*X)(?=.*Y) is O(n) per lookahead per position
        if (lookaheadCount >= 2 && dotstarCount > 0) {
          perfScore += lookaheadCount;
          perfIssues.push(`${lookaheadCount} lookaheads with .* — each rescans from every position. Rewrite as: X[\\\\s\\\\S]{0,5000}Y|Y[\\\\s\\\\S]{0,5000}X or split into separate patterns.`);
        }

        // Nested quantifiers — catastrophic backtracking risk
        if (hasNestedQuant) {
          perfScore += 5;
          perfIssues.push(`Nested quantifiers detected — can cause catastrophic exponential backtracking. Restructure to avoid (a+)+ or (.*?)* patterns.`);
        }

        // Verdict: critical perf issues are blocking, moderate are warnings
        if (perfScore >= 5) {
          eval_.issues.push(`⚡ PERFORMANCE BLOCK (score ${perfScore}): ${perfIssues.join(' ')}`);
        } else if (perfScore >= 3) {
          eval_.issues.push(`⚡ Performance risk (score ${perfScore}): ${perfIssues.join(' ')}`);
        } else if (perfScore > 0) {
          eval_.warnings.push(`⚡ Minor performance concern (score ${perfScore}): ${perfIssues.join(' ')}`);
        }

        // 2. Broadness check
        if (/^\.\*$/.test(rule.patternString)) eval_.issues.push('Pattern is just .* — matches everything');
        if (patternLength < 5) eval_.issues.push(`Pattern too short (${patternLength} literal chars)`);

        // 3. FP test against legitimate HTML/JS samples
        // phishkitSignatures gets an expanded sample set — it runs on every page source
        const legitimateSamples = [
          '<form action="/login" method="post">',
          '<input type="password" name="password">',
          '<input type="text" name="username" placeholder="Email">',
          'document.getElementById("username").value',
          'document.querySelector("input[type=password]")',
          'window.location.href = "/dashboard"',
          '<title>Sign in to Google</title>',
          'fetch("/api/login", { method: "POST" })',
          'addEventListener("submit", function(e) { e.preventDefault(); })',
          'localStorage.setItem("token", response.token)',
          'document.cookie',
          'window.onload = function() {',
          '<script src="https://cdn.jsdelivr.net/npm/bootstrap',
          ...(isPhishkitSig ? [
            'function validateForm() { return true; }',
            'document.forms[0].submit()',
            '<input type="hidden" name="csrf_token">',
            'const password = document.getElementById("pwd").value',
            'if (username === "" || password === "") { alert("Please fill in all fields"); }',
            'fetch("/auth/callback", { credentials: "include" })',
            'history.pushState({}, "", "/login")',
            'document.querySelectorAll("input")',
            'const form = document.getElementById("loginForm")',
          ] : []),
        ];
        const pattern = new RegExp(rule.patternString, rule.patternFlags || '');
        const fpSamples = legitimateSamples.filter(s => pattern.test(s));
        if (fpSamples.length > 0) {
          // For phishkitSignatures, a legitimate match is an outright FAIL not just a warning
          const bucket = isPhishkitSig ? 'issues' : 'warnings';
          eval_[bucket].push(`Pattern matches legitimate HTML/JS (${fpSamples.length} sample${fpSamples.length > 1 ? 's' : ''}): "${fpSamples[0]}"`);
        }

        // 4. Weight vs specificity — stricter for phishkitSignatures
        const maxSafeWeight = isPhishkitSig ? 0.25 : 0.35;
        const minSpecificityForHighWeight = isPhishkitSig ? 15 : 10;
        if (rule.weight > maxSafeWeight && patternLength < minSpecificityForHighWeight) {
          eval_.issues.push(`Weight ${rule.weight} too high for ${patternLength}-char pattern in ${rule.group} (max safe: ${maxSafeWeight} unless pattern has ≥${minSpecificityForHighWeight} literal chars)`);
        }

        // 5. phishkitSignatures must have a specific anchor string
        if (isPhishkitSig) {
          const hasAnchor = /['"]\w{6,}['"]/.test(rule.patternString) ||
                            /\w{8,}/.test(rule.patternString.replace(/[.*+?^${}()|[\]\\]/g, ''));
          if (!hasAnchor) {
            eval_.issues.push('phishkitSignatures pattern lacks a specific anchor string (quoted string ≥6 chars or word ≥8 chars) — too broad for page source scanning');
          }
        }

        // 6. Duplicate check
        try {
          const existing = d1`SELECT signal_id FROM phishkit_signals WHERE signal_id = ${rule.id} LIMIT 1`;
          if (existing.length > 0) eval_.warnings.push(`Pattern ID "${rule.id}" already exists in corpus — may be a duplicate`);
        } catch {}

        // 7. Too narrow — highly specific but zero corpus hits
        if (eval_.corpusHits === 0 && patternLength > 40) {
          eval_.warnings.push(`Very specific pattern (${patternLength} literal chars) with 0 corpus hits — may be too narrow`);
        }

        // 8. Corpus hits
        try {
          const hits = d1`SELECT COUNT(*) as hits FROM phishkit_signals WHERE signal_id = ${rule.id} LIMIT 1`;
          eval_.corpusHits = hits[0]?.hits || 0;
        } catch {}
      }
    }

    evaluations.push(eval_);
    const severity = eval_.issues.length > 0 ? '❌' : eval_.warnings.length > 0 ? '⚠️' : '✅';
    console.log(`  ${severity} ${rule.name || rule.id}: ${eval_.issues.length} issues, ${eval_.warnings.length} warnings, ${eval_.corpusHits} corpus hits`);
  }

  // ── Ask Opus for final quality judgment ──────────────────────────────────

  const evalSummary = evaluations.map(e => {
    const r = e.rule;
    const name = r.name || r.id;
    return `### ${name} (${r.name ? 'brand entry' : 'source pattern'})
Issues: ${e.issues.length > 0 ? e.issues.join('; ') : 'none'}
Warnings: ${e.warnings.length > 0 ? e.warnings.join('; ') : 'none'}
Corpus hits: ${e.corpusHits}
FP matches: ${e.fpMatches.length > 0 ? e.fpMatches.join(', ') : 'none'}
Rule: ${JSON.stringify(r, null, 2)}`;
  }).join('\n\n');

  const systemPrompt = `You are Virgil's rule quality gate — a senior detection engineer reviewing proposed phishing detection rules before they ship to users.

Your job is to block rules that would cause false positives, provide no detection value, OR degrade browser performance. You are the last line of defense before a rule goes live. Be strict about FP risk and performance but don't block rules just because corpus coverage is low — new phishing campaigns won't have corpus hits yet.

CRITICAL: Rules in "phishkitSignatures" run against EVERY page source for EVERY user. A bad pattern here causes widespread false positives. Apply extra scrutiny to phishkitSignatures patterns — when in doubt, FAIL them. They can always be refined and resubmitted.

PERFORMANCE IS A HARD REQUIREMENT: Source patterns run against full page HTML (potentially 5-10MB on news sites, portals). There are currently 340+ patterns and this number grows with every auto-promote. Each pattern with .* and alternation causes the V8 regex engine to scan the entire string at every position — on a 5MB page this takes measurable seconds. Patterns flagged with ⚡ PERFORMANCE BLOCK must be rewritten before they can ship.

PASS criteria:
- Typosquats are plausibly related to the brand and not common English words
- Source patterns are specific enough to not match legitimate sites
- Weights are proportional to pattern specificity
- No critical issues found
- Regex patterns are performance-safe: no unanchored .* with DOTALL, no nested quantifiers, no multiple sequential .* without bounded quantifiers

FAIL criteria (any one of these = FAIL):
- Pattern matches >1% of top legitimate sites (FP risk)
- Regex is so broad it matches common page structures (login forms, password fields, etc.)
- Typosquats are generic English words unrelated to the brand
- Weight is disproportionately high relative to pattern specificity
- Pattern is too narrow/specific to ever match real phishing (0 corpus hits + very long literal string)
- Rule exactly duplicates existing detection logic already in the ruleset
- ⚡ Pattern has a performance score >= 5 (will cause browser timeouts on large pages)
- Pattern uses .* with the DOTALL (s) flag — this makes .* span the entire multi-MB document
- Pattern uses nested quantifiers like (a+)+ or (.*?)*
- Pattern has 3+ sequential .* operators without bounded quantifiers

When fixing patterns for performance, apply these rewrites:
- Replace .* with [^<]{0,2000} or [\\s\\S]{0,2000} (bounded quantifier)
- Replace (?=.*X)(?=.*Y) with X[\\s\\S]{0,5000}Y|Y[\\s\\S]{0,5000}X
- Remove the s (DOTALL) flag and use [\\s\\S]{0,N} explicitly where needed
- Start patterns with a literal prefix of 4+ chars for V8 fast-skip
- Split patterns with 3+ lookaheads into multiple simpler patterns

Respond with exactly: PASS or FAIL on the first line, then your reasoning.`;

  const userContent = `## Rule Quality Gate — Issue #${ISSUE_NUMBER}

**Issue:** ${issue.title}
**Rules proposed:** ${rules.length}

## Automated evaluation results

${evalSummary}

## Decision

Should these rules be auto-promoted to the detection ruleset? 
Respond PASS or FAIL on the first line, then explain your reasoning for each rule.`;

  console.log('\nAsking Opus for quality judgment...');
  const judgment = await claude(systemPrompt, userContent, 1500);
  const passed = judgment.trimStart().startsWith('PASS');

  console.log(`\nOpus judgment: ${passed ? 'PASS ✅' : 'FAIL ❌'}`);

  // ── If FAIL, ask Opus to fix the rules ───────────────────────────────────
  let fixedRules = null;
  let fixComment = '';

  if (!passed) {
    console.log('\nAsking Opus to fix the failing rules...');

    const fixPrompt = `You are Virgil's detection rule fixer. The quality gate failed these rules. Fix them so they pass.

For each rule that failed, produce a corrected version as a JSON code block.

Rules to fix:
${rules.map(r => '```json\n' + JSON.stringify(r, null, 2) + '\n```').join('\n\n')}

Quality gate findings:
${judgment}

For source patterns:
- Make the regex MORE specific to avoid FP — add brand-specific keywords, function names, or unique strings
- Reduce weight if pattern is too broad (max 0.25 for phishkitSignatures, 0.35 for others)
- If a pattern is unfixable (too generic, no way to make specific), output it with a comment field: "action": "remove"

For brand entries:
- Remove generic typos that are common English words
- Keep typos that clearly resemble the brand name

Output each fixed rule as a JSON code block. If a rule cannot be fixed, include "action": "remove" in the JSON.
Output ONLY the JSON blocks, no prose.`;

    const fixes = await claude(
      'You are a precise JSON generator. Output only valid JSON code blocks, no prose.',
      fixPrompt,
      2000
    );

    // Extract fixed rules from response
    const fixBlocks = [];
    const fixRe = /```json\n([\s\S]*?)```/g;
    let fm;
    while ((fm = fixRe.exec(fixes)) !== null) {
      try { fixBlocks.push(JSON.parse(fm[1])); } catch {}
    }

    if (fixBlocks.length > 0) {
      fixedRules = fixBlocks.filter(b => b.action !== 'remove');
      const removed = fixBlocks.filter(b => b.action === 'remove');
      console.log(`Opus produced ${fixedRules.length} fixed rule(s), ${removed.length} removal(s)`);

      fixComment = `\n\n---\n\n### 🔧 Auto-fix attempt\n\nOpus has proposed fixed versions of the failing rules:\n\n${fixedRules.map(r => '```json\n' + JSON.stringify(r, null, 2) + '\n```').join('\n\n')}${removed.length > 0 ? `\n\n**Rules recommended for removal** (too generic to fix):\n${removed.map(r => `- \`${r.id || r.name}\``).join('\n')}` : ''}\n\nComment \`/apply\` to apply the fixed rules, or \`/retriage\` to ask the triage agent for new proposals.`;
    }
  }

  // ── Post comment on issue ────────────────────────────────────────────────

  const autoResults = evaluations.map(e => {
    const r = e.rule;
    const name = r.name || r.id;
    const status = e.issues.length > 0 ? '❌' : e.warnings.length > 0 ? '⚠️' : '✅';
    const lines = [`**${status} ${name}**`];
    if (e.issues.length)   lines.push(...e.issues.map(i => `- 🚫 ${i}`));
    if (e.warnings.length) lines.push(...e.warnings.map(w => `- ⚠️ ${w}`));
    if (e.corpusHits > 0)  lines.push(`- 📊 ${e.corpusHits} corpus hit(s)`);
    return lines.join('\n');
  }).join('\n\n');

  const comment = `## 🔍 Rule Quality Gate

**Verdict: ${passed ? '✅ PASS — rules approved for auto-promote' : '❌ FAIL — rules blocked, fixes proposed below'}**

---

### Automated checks
${autoResults}

---

### Opus review
${judgment}${fixComment}

---

${passed
  ? '_Rules will be auto-promoted to `rules/` and shipped in the next detection config update._'
  : '_Rules blocked. See fixed versions above — comment `/apply` to apply them, or `/retriage` to start over._'
}

*Quality gate run at ${new Date().toISOString()}*`;

  await github.commentOnIssue(REPO, ISSUE_NUMBER, comment);

  if (!passed) {
    await github.addLabel(REPO, ISSUE_NUMBER, ['needs-review']);
    // Remove agent-triaged so auto-promote doesn't proceed
    try { await github.removeLabel(REPO, ISSUE_NUMBER, 'agent-triaged'); } catch {}
    console.log('Labels updated: added needs-review, removed agent-triaged');
    process.exit(1);
  }

  console.log('Quality gate passed — auto-promote may proceed');
  process.exit(0);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
