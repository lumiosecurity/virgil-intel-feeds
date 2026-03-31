#!/usr/bin/env node
// Virgil — Rule Quality Gate (Agent 4)
//
// Runs BEFORE auto-promote commits rules to core-rules.
// Triggered when agent-triaged label is added to a rule-gap issue.
//
// Escalation model:
//   Attempt 1:   Opus reviews Sonnet's rules, Sonnet fixes failures
//   Attempt 2:   Opus re-reviews Sonnet's fixes, Sonnet tries again
//   Attempt 3:   Opus rewrites rules from scratch using the full rule
//                writing guide + original issue evidence — not patching
//                Sonnet's broken output but starting clean
//
// Exit codes:
//   0 = PASS  — auto-promote may proceed
//   1 = FAIL  — rules blocked after 3 attempts, issue labeled needs-review
//
// Env vars: ISSUE_NUMBER, GITHUB_TOKEN, ANTHROPIC_API_KEY

import { cfg, d1, github } from './agent-tools.js';
import Anthropic from '@anthropic-ai/sdk';
import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const ISSUE_NUMBER = parseInt(process.env.ISSUE_NUMBER || process.argv[2]);
const REPO         = cfg.coreRulesRepo;
const MAX_ATTEMPTS = 3;

if (!ISSUE_NUMBER) { console.error('ISSUE_NUMBER required'); process.exit(1); }

// ── Load rule writing guide for Opus final-attempt rewrite ───────────────────
let RULE_WRITING_GUIDE = '';
try {
  RULE_WRITING_GUIDE = readFileSync(join(__dirname, 'rule-writing-guide.md'), 'utf8');
  console.log(`Loaded rule writing guide (${(RULE_WRITING_GUIDE.length / 1024).toFixed(1)}KB)`);
} catch (e) {
  console.warn('Could not load rule-writing-guide.md:', e.message);
}

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

const LEGITIMATE_SAMPLES = [
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
  'function validateForm() { return true; }',
  'document.forms[0].submit()',
  '<input type="hidden" name="csrf_token">',
  'const password = document.getElementById("pwd").value',
  'if (username === "" || password === "") { alert("Please fill in all fields"); }',
  'fetch("/auth/callback", { credentials: "include" })',
  'history.pushState({}, "", "/login")',
  'document.querySelectorAll("input")',
  'const form = document.getElementById("loginForm")',
];

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

async function claude(system, user, maxTokens = 2000, model = 'claude-sonnet-4-6') {
  const resp = await client.messages.create({
    model,
    max_tokens: maxTokens,
    system,
    messages:   [{ role: 'user', content: user }],
  });
  return resp.content?.[0]?.text || '';
}

// ── Automated rule evaluation ──────────────────────────────────────────────────
// Returns { evaluations, allPassed, passedRules, failedRules }

function evaluateRules(rules) {
  const evaluations = [];

  for (const rule of rules) {
    const eval_ = { rule, issues: [], warnings: [], fpMatches: [], corpusHits: 0 };

    if (rule.name && rule.domains && rule.typos) {
      // ── Brand entry evaluation ──────────────────────────────────────────

      const commonWords = new Set(['secure','login','account','online','bank','web','mail',
        'home','info','help','support','service','portal','access','auth','verify',
        'update','confirm','sign','user','pass','card','pay','shop','store','buy']);
      const genericTypos = rule.typos.filter(t => commonWords.has(t) || t.length <= 3);
      if (genericTypos.length > 0) {
        eval_.issues.push(`Typos too generic (common words or too short): ${genericTypos.join(', ')}`);
      }

      const unrelatedTypos = rule.typos.filter(t => {
        const brand = rule.name.toLowerCase();
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

      if (rule.typos.length <= 2 && eval_.corpusHits === 0) {
        eval_.warnings.push(`Only ${rule.typos.length} typo variant(s) with no corpus hits — may be too narrow`);
      }

      const fpRisk = rule.typos.filter(t =>
        TRANCO_TOP_1000_SAMPLE.some(d => d.includes(t) || t.includes(d.split('.')[0]))
      );
      if (fpRisk.length > 0) {
        eval_.issues.push(`FP risk: typos overlap with top sites: ${fpRisk.join(', ')}`);
        eval_.fpMatches.push(...fpRisk);
      }

    } else if (rule.id && rule.patternString) {
      // ── Source pattern evaluation ────────────────────────────────────────
      const isPhishkitSig = rule.group === 'phishkitSignatures';

      let compilesOk = false;
      try {
        new RegExp(rule.patternString, rule.patternFlags || '');
        compilesOk = true;
      } catch (e) {
        eval_.issues.push(`Invalid regex: ${e.message}`);
      }

      if (compilesOk) {
        const patternLength = rule.patternString.replace(/[.*+?^${}()|[\]\\]/g, '').length;

        // ── Performance check ───────────────────────────────────────────
        const ps = rule.patternString;
        const flags = rule.patternFlags || '';
        const dotstarCount = (ps.match(/(?<!\\)\.\*/g) || []).length;
        const hasAlternation = /(?<!\\)\|/.test(ps);
        const hasDotall = flags.includes('s');
        const hasNestedQuant = /[+*]\)[+*?]/.test(ps);
        const lookaheadCount = (ps.match(/\(\?=/g) || []).length;

        let perfScore = 0;
        const perfIssues = [];

        if (hasDotall && dotstarCount > 0) {
          perfScore += dotstarCount * 2;
          perfIssues.push(`DOTALL flag with .* (×${dotstarCount}) — spans entire document. Use [\\s\\S]{0,N} instead.`);
        }
        if (dotstarCount >= 2 && !hasDotall) {
          perfScore += dotstarCount;
          perfIssues.push(`${dotstarCount} sequential .* — use bounded quantifiers: [^<]{0,2000}`);
        }
        if (dotstarCount > 0 && hasAlternation) {
          perfScore += 2;
          perfIssues.push(`.* with alternation — put most specific literal first or use bounded quantifiers.`);
        }
        if (lookaheadCount >= 2 && dotstarCount > 0) {
          perfScore += lookaheadCount;
          perfIssues.push(`${lookaheadCount} lookaheads with .* — rewrite as ordered match or split into separate patterns.`);
        }
        if (hasNestedQuant) {
          perfScore += 5;
          perfIssues.push(`Nested quantifiers — catastrophic backtracking risk. Restructure pattern.`);
        }

        if (perfScore >= 5) {
          eval_.issues.push(`⚡ PERFORMANCE BLOCK (score ${perfScore}): ${perfIssues.join(' ')}`);
        } else if (perfScore >= 3) {
          eval_.issues.push(`⚡ Performance risk (score ${perfScore}): ${perfIssues.join(' ')}`);
        } else if (perfScore > 0) {
          eval_.warnings.push(`⚡ Minor performance concern (score ${perfScore}): ${perfIssues.join(' ')}`);
        }

        // ── Broadness check ───────────────────────────────────────────────
        if (/^\.\*$/.test(rule.patternString)) eval_.issues.push('Pattern is just .* — matches everything');
        if (patternLength < 5) eval_.issues.push(`Pattern too short (${patternLength} literal chars)`);

        // ── FP test ───────────────────────────────────────────────────────
        const pattern = new RegExp(rule.patternString, rule.patternFlags || '');
        const fpSamples = LEGITIMATE_SAMPLES.filter(s => pattern.test(s));
        if (fpSamples.length > 0) {
          const bucket = isPhishkitSig ? 'issues' : 'warnings';
          eval_[bucket].push(`Pattern matches legitimate HTML/JS (${fpSamples.length} sample${fpSamples.length > 1 ? 's' : ''}): "${fpSamples[0]}"`);
        }

        // ── Weight vs specificity ─────────────────────────────────────────
        const maxSafeWeight = isPhishkitSig ? 0.25 : 0.35;
        const minSpecificityForHighWeight = isPhishkitSig ? 15 : 10;
        if (rule.weight > maxSafeWeight && patternLength < minSpecificityForHighWeight) {
          eval_.issues.push(`Weight ${rule.weight} too high for ${patternLength}-char pattern in ${rule.group} (max safe: ${maxSafeWeight} unless pattern has ≥${minSpecificityForHighWeight} literal chars)`);
        }

        // ── Anchor requirement for phishkitSignatures ─────────────────────
        if (isPhishkitSig) {
          const hasAnchor = /['"]\w{6,}['"]/.test(rule.patternString) ||
                            /\w{8,}/.test(rule.patternString.replace(/[.*+?^${}()|[\]\\]/g, ''));
          if (!hasAnchor) {
            eval_.issues.push('phishkitSignatures pattern lacks a specific anchor string (≥8 literal chars) — too broad');
          }
        }
      }
    }

    evaluations.push(eval_);
  }

  const allPassed = evaluations.every(e => e.issues.length === 0);
  const passedRules = evaluations.filter(e => e.issues.length === 0).map(e => e.rule);
  const failedRules = evaluations.filter(e => e.issues.length > 0).map(e => e.rule);

  return { evaluations, allPassed, passedRules, failedRules };
}

// ── Format evaluation results for display ─────────────────────────────────────

function formatEvaluations(evaluations) {
  return evaluations.map(e => {
    const r = e.rule;
    const name = r.name || r.id;
    const status = e.issues.length > 0 ? '❌' : e.warnings.length > 0 ? '⚠️' : '✅';
    const lines = [`**${status} ${name}**`];
    if (e.issues.length)   lines.push(...e.issues.map(i => `- 🚫 ${i}`));
    if (e.warnings.length) lines.push(...e.warnings.map(w => `- ⚠️ ${w}`));
    if (e.corpusHits > 0)  lines.push(`- 📊 ${e.corpusHits} corpus hit(s)`);
    return lines.join('\n');
  }).join('\n\n');
}

// ── Ask Claude to review and optionally fix rules ─────────────────────────────

const REVIEW_SYSTEM_PROMPT = `You are Virgil's rule quality gate — a senior detection engineer reviewing proposed phishing detection rules before they ship to users.

Your job is to block rules that would cause false positives, provide no detection value, OR degrade browser performance. Be strict about FP risk and performance.

CRITICAL: Rules in "phishkitSignatures" run against EVERY page source for EVERY user.

PERFORMANCE IS A HARD REQUIREMENT: Source patterns run against full page HTML (5-10MB). 340+ patterns and growing. Patterns with .* and alternation cause V8 to scan the entire string at every position.

PASS criteria:
- Typosquats are plausibly related to the brand and not common English words
- Source patterns are specific enough to not match legitimate sites
- Weights are proportional to pattern specificity
- No critical issues found
- Regex patterns are performance-safe: no unanchored .* with DOTALL, no nested quantifiers, no multiple sequential .* without bounded quantifiers

FAIL criteria (any one = FAIL):
- Pattern matches legitimate sites (FP risk)
- Regex too broad for common page structures
- Generic typosquats unrelated to brand
- Weight disproportionate to specificity
- ⚡ Performance score >= 3
- .* with DOTALL flag
- Nested quantifiers
- 3+ sequential unbounded .*

Respond with exactly: PASS or FAIL on the first line, then your reasoning.`;

async function askClaudeToReview(rules, evaluations) {
  const evalSummary = evaluations.map(e => {
    const r = e.rule;
    const name = r.name || r.id;
    return `### ${name} (${r.name ? 'brand entry' : 'source pattern'})
Issues: ${e.issues.length > 0 ? e.issues.join('; ') : 'none'}
Warnings: ${e.warnings.length > 0 ? e.warnings.join('; ') : 'none'}
Rule: ${JSON.stringify(r, null, 2)}`;
  }).join('\n\n');

  // Opus reviews — a different, stronger model than the Sonnet that generated the rules
  const judgment = await claude(REVIEW_SYSTEM_PROMPT,
    `## Rule Quality Gate — Issue #${ISSUE_NUMBER}\n\n**Rules proposed:** ${rules.length}\n\n## Automated evaluation results\n\n${evalSummary}\n\n## Decision\n\nShould these rules be auto-promoted? Respond PASS or FAIL on the first line.`,
    1500,
    'claude-opus-4-6'
  );

  const passed = judgment.trimStart().startsWith('PASS');
  return { passed, judgment };
}

async function askClaudeToFix(failedRules, judgment) {
  const fixPrompt = `You are Virgil's detection rule fixer. The quality gate failed these rules. Fix them so they pass.

For each rule, produce a corrected version as a JSON code block.

Rules to fix:
${failedRules.map(r => '```json\n' + JSON.stringify(r, null, 2) + '\n```').join('\n\n')}

Quality gate findings:
${judgment}

For source patterns:
- Make the regex MORE specific — add brand-specific keywords, function names, or unique strings
- Replace .* with bounded quantifiers: [\\s\\S]{0,2000} for cross-line, [^<]{0,2000} for HTML context
- Replace (?=.*X)(?=.*Y) with X[\\s\\S]{0,5000}Y or split into separate patterns
- Remove the s (DOTALL) flag — use [\\s\\S]{0,N} explicitly instead
- Start patterns with a literal prefix of 4+ chars
- Reduce weight if pattern is too broad (max 0.25 for phishkitSignatures, 0.35 for others)
- If a pattern is unfixable, include "action": "remove" in the JSON

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

  const fixBlocks = [];
  const fixRe = /```json\n([\s\S]*?)```/g;
  let fm;
  while ((fm = fixRe.exec(fixes)) !== null) {
    try { fixBlocks.push(JSON.parse(fm[1])); } catch {}
  }

  const fixed = fixBlocks.filter(b => b.action !== 'remove');
  const removed = fixBlocks.filter(b => b.action === 'remove');
  return { fixed, removed };
}

// ── Opus escalation — clean rewrite on final attempt ──────────────────────────
// When Sonnet's fixes fail twice, Opus gets the original issue context and the
// full rule writing guide to produce rules from scratch. This is the last chance
// before the issue falls to manual review.

async function askOpusToRewrite(issue, failedRules, attemptLog) {
  if (!RULE_WRITING_GUIDE) {
    console.warn('No rule writing guide available — skipping Opus rewrite');
    return { fixed: [], removed: [] };
  }

  console.log('\n🔴 Escalating to Opus for clean rewrite...');

  // Extract page content and signals from the issue body for Opus context
  const issueBody = issue.body || '';
  const urlMatch = issueBody.match(/\| Full URL \| `([^`]+)` \|/);
  const url = urlMatch?.[1] || 'unknown';

  // Build a summary of what went wrong in previous attempts
  const failureSummary = attemptLog.map(a =>
    `Attempt ${a.attempt}: auto-checks ${a.autoPassCount} passed / ${a.autoFailCount} failed, Claude review: ${a.claudePassed ? 'PASS' : 'FAIL'}`
  ).join('\n');

  const failedRulesSummary = failedRules.map(r =>
    `- ${r.id || r.name}: ${JSON.stringify(r, null, 2)}`
  ).join('\n\n');

  const systemPrompt = `You are Virgil's senior detection engineer (Opus). Sonnet attempted to write detection rules for a phishing page but failed quality review twice. You are the last chance before this falls to manual human review.

Your job: write correct rules from scratch. Do NOT try to fix Sonnet's broken rules — start fresh using the original issue evidence.

${RULE_WRITING_GUIDE}`;

  const userPrompt = `## Clean Rewrite Request

**Original issue:** #${ISSUE_NUMBER} — ${issue.title}
**URL:** ${url}

## What Sonnet tried and failed
${failureSummary}

## Sonnet's failed rules (DO NOT fix these — write new ones from scratch)
${failedRulesSummary}

## Original issue body (your primary evidence)
${issueBody.slice(0, 20000)}

## Your task
Write 1-3 detection rules from scratch that would catch this phishing page. Use the original issue evidence — the URL, page content, signals, and screenshot — not Sonnet's failed attempts.

Output each rule as a separate \`\`\`json code block. Follow the rule writing guide exactly. If you cannot write a rule that would pass quality review, output nothing rather than a bad rule.`;

  const opusClient = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
  const resp = await opusClient.messages.create({
    model:      'claude-opus-4-6',
    max_tokens: 4000,
    system:     systemPrompt,
    messages:   [{ role: 'user', content: userPrompt }],
  });

  const text = resp.content?.[0]?.text || '';

  const fixBlocks = [];
  const fixRe = /```json\n([\s\S]*?)```/g;
  let fm;
  while ((fm = fixRe.exec(text)) !== null) {
    try { fixBlocks.push(JSON.parse(fm[1])); } catch {}
  }

  const fixed = fixBlocks.filter(b => b.action !== 'remove');
  const removed = fixBlocks.filter(b => b.action === 'remove');

  console.log(`Opus produced ${fixed.length} rule(s) from scratch, ${removed.length} removal(s)`);
  return { fixed, removed, opusResponse: text };
}

// ── Extract rules from the most recent triage/gate comment ────────────────────

function extractRulesFromComment(comment) {
  const blocks = [];
  const re = /```json\n([\s\S]*?)```/g;
  let m;
  while ((m = re.exec(comment)) !== null) {
    try { blocks.push(JSON.parse(m[1])); } catch {}
  }

  const PLACEHOLDER_IDS   = new Set(['example-source-pattern','my-pattern-id','pattern-id']);
  const PLACEHOLDER_NAMES = new Set(['example-brand','brand-name','brandname']);

  return blocks.filter(b => {
    if (b.action === 'remove') return false;
    if (b.name && b.domains && b.typos) return !PLACEHOLDER_NAMES.has(b.name);
    if (b.id && b.patternString)        return !PLACEHOLDER_IDS.has(b.id);
    return false;
  });
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`\nAgent 4: Rule Quality Gate — Issue #${ISSUE_NUMBER}`);
  console.log(`Max attempts: ${MAX_ATTEMPTS}\n`);

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

  let currentRules = extractRulesFromComment(triageComment.body);
  if (currentRules.length === 0) {
    console.log('No actionable rules to evaluate');
    process.exit(0);
  }

  // ── Retry loop: evaluate → fix → re-evaluate → fix → final evaluate ──────

  const attemptLog = [];   // track each attempt for the final comment
  let finalPassed = false;
  let finalRules = currentRules;
  let finalEvaluations = null;
  let finalJudgment = '';
  let removedRules = [];

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    console.log(`\n── Attempt ${attempt}/${MAX_ATTEMPTS} (${currentRules.length} rules) ──`);

    // 1. Automated checks
    const { evaluations, allPassed, passedRules, failedRules } = evaluateRules(currentRules);
    finalEvaluations = evaluations;

    console.log(`  Automated: ${passedRules.length} passed, ${failedRules.length} failed`);

    // 2. Claude review
    const { passed, judgment } = await askClaudeToReview(currentRules, evaluations);
    finalJudgment = judgment;

    console.log(`  Claude: ${passed ? 'PASS ✅' : 'FAIL ❌'}`);

    attemptLog.push({
      attempt,
      ruleCount: currentRules.length,
      autoPassCount: passedRules.length,
      autoFailCount: failedRules.length,
      claudePassed: passed,
      evaluations: formatEvaluations(evaluations),
      judgment,
    });

    if (passed && allPassed) {
      // Clean pass — all rules approved
      finalPassed = true;
      finalRules = currentRules;
      console.log(`  ✅ All rules passed on attempt ${attempt}`);
      break;
    }

    if (passed && !allPassed) {
      // Claude said PASS but automated checks found issues — trust automated checks,
      // but only fail the rules with issues and keep the ones that passed
      console.log(`  Claude approved but ${failedRules.length} rule(s) have automated issues — splitting`);
      if (passedRules.length > 0 && attempt === MAX_ATTEMPTS) {
        // On final attempt, accept whatever passed automated checks
        finalPassed = true;
        finalRules = passedRules;
        break;
      }
    }

    // Not passed — can we fix?
    if (attempt < MAX_ATTEMPTS - 1) {
      // Attempts 1-2: Sonnet tries to fix its own rules
      const rulesToFix = allPassed ? currentRules : evaluations.filter(e => e.issues.length > 0).map(e => e.rule);
      console.log(`  Asking Sonnet to fix ${rulesToFix.length} rule(s)...`);

      const { fixed, removed } = await askClaudeToFix(rulesToFix, judgment);
      removedRules.push(...removed);
      console.log(`  Sonnet produced ${fixed.length} fix(es), ${removed.length} removal(s)`);

      if (fixed.length === 0) {
        // Sonnet couldn't fix anything — keep rules that passed automated checks
        if (passedRules.length > 0) {
          finalPassed = true;
          finalRules = passedRules;
          console.log(`  No fixes possible — accepting ${passedRules.length} rule(s) that passed automated checks`);
        }
        break;
      }

      // Merge: rules that passed automated checks + fixed versions of failed rules
      const passedIds = new Set(passedRules.map(r => r.id || r.name));
      currentRules = [
        ...passedRules,
        ...fixed.filter(f => !passedIds.has(f.id || f.name)),
      ];
    } else {
      // Final attempt: escalate to Opus for a clean rewrite from scratch
      // Opus gets the original issue, the rule writing guide, and a summary of
      // what Sonnet tried — then writes rules from scratch, not fixing Sonnet's.
      const allFailed = evaluations.filter(e => e.issues.length > 0).map(e => e.rule);
      const { fixed: opusRules, removed: opusRemoved } = await askOpusToRewrite(issue, allFailed, attemptLog);
      removedRules.push(...opusRemoved);

      if (opusRules.length > 0) {
        // Run Opus's rules through automated checks (but NOT through Claude review again —
        // Opus IS the senior reviewer, we trust its output against automated checks only)
        const { passedRules: opusPassed } = evaluateRules(opusRules);
        if (opusPassed.length > 0) {
          finalPassed = true;
          finalRules = opusPassed;
          console.log(`  ✅ Opus rewrite: ${opusPassed.length} rule(s) passed automated checks`);
        } else {
          console.log(`  ❌ Opus rewrite failed automated checks — giving up`);
          // Last resort: accept any rules from Sonnet that passed automated checks earlier
          const { passedRules: lastPassed } = evaluateRules(currentRules);
          if (lastPassed.length > 0) {
            finalPassed = true;
            finalRules = lastPassed;
            console.log(`  Falling back to ${lastPassed.length} Sonnet rule(s) that passed automated checks`);
          }
        }
      } else {
        console.log(`  Opus produced no rules — falling back to automated-check survivors`);
        const { passedRules: lastPassed } = evaluateRules(currentRules);
        if (lastPassed.length > 0) {
          finalPassed = true;
          finalRules = lastPassed;
          console.log(`  Accepting ${lastPassed.length} rule(s) that passed automated checks`);
        }
      }
    }
  }

  // ── Build and post the summary comment ─────────────────────────────────────

  const attemptSummaries = attemptLog.map(a => {
    const icon = a.claudePassed ? '✅' : '❌';
    return `### Attempt ${a.attempt} — ${icon} Claude: ${a.claudePassed ? 'PASS' : 'FAIL'} | Auto: ${a.autoPassCount} passed, ${a.autoFailCount} failed

${a.evaluations}

<details>
<summary>Claude review</summary>

${a.judgment}
</details>`;
  }).join('\n\n---\n\n');

  const finalVerdict = finalPassed
    ? `✅ PASS — ${finalRules.length} rule(s) approved after ${attemptLog.length} attempt(s)`
    : `❌ FAIL — rules could not pass quality gate after ${MAX_ATTEMPTS} attempts`;

  const approvedSection = finalPassed && finalRules.length > 0
    ? `\n\n### Approved rules\n\n${finalRules.map(r => '```json\n' + JSON.stringify(r, null, 2) + '\n```').join('\n\n')}`
    : '';

  const removedSection = removedRules.length > 0
    ? `\n\n### Rules removed (unfixable)\n${removedRules.map(r => `- \`${r.id || r.name}\``).join('\n')}`
    : '';

  const comment = `## 🔍 Rule Quality Gate

**Verdict: ${finalVerdict}**

---

${attemptSummaries}${approvedSection}${removedSection}

---

${finalPassed
  ? '_Rules will be auto-promoted to `rules/` and shipped in the next detection config update._'
  : '_Rules blocked after 3 attempts. Manual review required — comment `/retriage` to start over with fresh proposals._'
}

*Quality gate run at ${new Date().toISOString()}*`;

  await github.commentOnIssue(REPO, ISSUE_NUMBER, comment);

  if (!finalPassed) {
    await github.addLabel(REPO, ISSUE_NUMBER, ['needs-review']);
    try { await github.removeLabel(REPO, ISSUE_NUMBER, 'agent-triaged'); } catch {}
    console.log('\nFinal: FAIL — labeled needs-review');
    process.exit(1);
  }

  // ── Write approved rules for the auto-promote step to pick up ──────────────
  // The auto-promote workflow reads from the most recent quality gate comment
  // that contains approved rule JSON blocks. The approved rules are already
  // in the comment above. Exit 0 so auto-promote proceeds.

  console.log(`\nFinal: PASS — ${finalRules.length} rule(s) approved`);
  process.exit(0);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
