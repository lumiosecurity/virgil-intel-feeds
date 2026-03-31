#!/usr/bin/env node
// Virgil — Source Pattern Audit
// Audits all existing source patterns for quality issues and asks Opus for fixes.
// Run via GitHub Actions workflow or locally:
//   GITHUB_TOKEN=... ANTHROPIC_API_KEY=... RULES_PATH=../virgil-core-rules node agents/audit-source-patterns.js

import { readdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { execSync } from 'child_process';
import Anthropic from '@anthropic-ai/sdk';
import { github, cfg } from './agent-tools.js';

const RULES_PATH = process.env.RULES_PATH || '.';
const REPO       = process.env.REPO_NAME || cfg.coreRulesRepo;
const ORG        = process.env.ORG_NAME  || cfg.org;
const DRY_RUN    = process.env.DRY_RUN === 'true';

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

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
  'fetch("/auth/callback", { credentials: "include" })',
  'history.pushState({}, "", "/login")',
  'document.querySelectorAll("input")',
  'const form = document.getElementById("loginForm")',
];

async function main() {
  console.log('\nVirgil Source Pattern Audit');
  console.log(`Rules path: ${RULES_PATH}`);

  const flagged    = [];
  const autoFixed  = [];
  const allPatterns = {};

  const sourceDir = join(RULES_PATH, 'rules/source');

  for (const fname of readdirSync(sourceDir)) {
    if (!fname.endsWith('.json') || fname.startsWith('_') || fname.startsWith('.')) continue;
    const filePath   = join(sourceDir, fname);
    const rule       = JSON.parse(readFileSync(filePath, 'utf8'));
    const isPhishkit = fname === 'phishkitSignatures.json';
    let changed      = false;

    for (let i = 0; i < (rule.sourcePatterns || []).length; i++) {
      const pat    = rule.sourcePatterns[i];
      const issues = [];
      const key    = `${fname}:${pat.id}`;
      allPatterns[key] = { ...pat, file: fname };

      // 1. Regex compiles
      let re;
      try {
        re = new RegExp(pat.patternString, pat.patternFlags || '');
      } catch (e) {
        issues.push(`invalid regex: ${e.message}`);
        flagged.push({ file: fname, id: pat.id, weight: pat.weight, issues, autoFixable: false });
        continue;
      }

      const literalLen = pat.patternString.replace(/[.*+?^${}()|[\]\\]/g, '').length;

      // ── PERFORMANCE CHECK ─────────────────────────────────────────────
      // Source patterns run against full page source (5-10MB on news sites).
      // 340+ patterns × multi-MB string = seconds of main-thread blocking
      // unless patterns are linear-time safe.
      const ps = pat.patternString;
      const pflags = pat.patternFlags || '';
      const dotstarCount = (ps.match(/(?<!\\)\.\*/g) || []).length;
      const hasAlternation = /(?<!\\)\|/.test(ps);
      const hasDotall = pflags.includes('s');
      const hasNestedQuant = /[+*]\)[+*?]/.test(ps);
      const lookaheadCount = (ps.match(/\(\?=/g) || []).length;

      let perfScore = 0;
      if (hasDotall && dotstarCount > 0) perfScore += dotstarCount * 2;
      if (dotstarCount >= 2 && !hasDotall) perfScore += dotstarCount;
      if (dotstarCount > 0 && hasAlternation) perfScore += 2;
      if (lookaheadCount >= 2 && dotstarCount > 0) perfScore += lookaheadCount;
      if (hasNestedQuant) perfScore += 5;

      if (perfScore >= 5) {
        issues.push(`⚡ CRITICAL PERF (score ${perfScore}): ${hasDotall && dotstarCount > 0 ? `DOTALL+.* (×${dotstarCount}) spans entire document` : ''}${dotstarCount >= 2 ? ` ${dotstarCount} sequential .*` : ''}${lookaheadCount >= 2 ? ` ${lookaheadCount} lookaheads` : ''}${hasNestedQuant ? ' nested quantifiers' : ''}`.replace(/^ /, ''));
      } else if (perfScore >= 3) {
        issues.push(`⚡ PERF RISK (score ${perfScore}): pattern has backtracking-prone constructs`);
      }

      // 2. FP test against legitimate samples
      const fpMatches = LEGITIMATE_SAMPLES.filter(s => re.test(s));
      if (fpMatches.length > 0) {
        issues.push(`matches ${fpMatches.length} legitimate sample(s): "${fpMatches[0]}"`);
      }

      // 3. Weight vs specificity
      const maxWeight    = isPhishkit ? 0.25 : 0.35;
      const minLiteral   = isPhishkit ? 15   : 10;
      if (pat.weight > maxWeight && literalLen < minLiteral) {
        issues.push(`weight ${pat.weight} too high for ${literalLen}-char pattern (max ${maxWeight})`);
        if (fpMatches.length === 0) {
          pat.weight = maxWeight;
          changed    = true;
          autoFixed.push({ file: fname, id: pat.id, fix: `weight clamped to ${maxWeight}` });
        }
      }

      // 4. phishkitSignatures anchor requirement
      if (isPhishkit && fpMatches.length === 0) {
        const hasAnchor = /["']\w{6,}["']/.test(pat.patternString) ||
                           /\w{8,}/.test(pat.patternString.replace(/[.*+?^${}()|[\]\\]/g, ''));
        if (!hasAnchor) {
          issues.push('lacks specific anchor string (quoted string >=6 chars or word >=8 chars)');
        }
      }

      // 5. Too narrow
      if (literalLen > 40 && fpMatches.length === 0) {
        issues.push(`very specific (${literalLen} literal chars) — verify it matches real phishing`);
      }

      if (issues.length > 0) {
        flagged.push({ file: fname, id: pat.id, weight: pat.weight, issues, autoFixable: fpMatches.length === 0 });
      }
    }

    if (changed && !DRY_RUN) {
      writeFileSync(filePath, JSON.stringify(rule, null, 2));
    }
  }

  console.log(`\nFlagged: ${flagged.length} patterns`);
  console.log(`Auto-fixed: ${autoFixed.length} weight issues`);

  // Commit auto-fixes
  if (autoFixed.length > 0 && !DRY_RUN) {
    try {
      execSync('git config user.name "virgil-rules[bot]"', { cwd: RULES_PATH });
      execSync('git config user.email "rules-bot@lumiosecurity"', { cwd: RULES_PATH });
      execSync('git add rules/source/', { cwd: RULES_PATH });
      execSync(`git commit -m "fix: audit auto-fix ${autoFixed.length} pattern weight(s)"`, { cwd: RULES_PATH });
      execSync('git push', { cwd: RULES_PATH });
      console.log('Auto-fixes committed and pushed');
    } catch (e) {
      console.warn('Auto-fix commit failed:', e.message);
    }
  }

  if (flagged.length === 0) {
    console.log('\nAll patterns passed audit');
    return;
  }

  // ── Ask Opus to review flagged patterns — with retry and incremental issue creation ──

  console.log(`\nAsking Sonnet to review ${flagged.length} flagged pattern(s)...`);

  // Group flagged patterns by file FIRST so we can create issues incrementally
  const byFile = {};
  for (const f of flagged) {
    if (!byFile[f.file]) byFile[f.file] = [];
    byFile[f.file].push(f);
  }

  // Retry wrapper — handles 529 overloaded and transient errors
  async function claudeWithRetry(system, userContent, maxRetries = 4) {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const resp = await client.messages.create({
          model:      'claude-sonnet-4-6',
          max_tokens: 2000,
          system,
          messages: [{ role: 'user', content: userContent }],
        });
        return resp.content?.[0]?.text || '';
      } catch (e) {
        const retryable = e.status === 529 || e.status === 500 || e.status === 502 || e.status === 503;
        if (!retryable || attempt === maxRetries) {
          console.warn(`  Opus call failed after ${attempt + 1} attempt(s): ${e.message}`);
          return null; // return null instead of crashing — we'll create the issue without Opus review
        }
        const delay = Math.min(2000 * Math.pow(2, attempt), 30000) + Math.random() * 1000;
        console.log(`  Opus returned ${e.status} — retrying in ${Math.round(delay / 1000)}s (attempt ${attempt + 1}/${maxRetries})...`);
        await new Promise(r => setTimeout(r, delay));
      }
    }
    return null;
  }

  const opusSystemPrompt = [
    'You are a Virgil detection engineer auditing existing phishing detection source patterns.',
    'For each pattern give: 1) KEEP / FIX / REMOVE verdict  2) One-line reason  3) If FIX: exact corrected patternString.',
    'KEEP = specific enough, low FP risk, and performance-safe.',
    'FIX = has merit but needs tightening — provide corrected patternString and patternFlags.',
    'REMOVE = too broad, duplicates logic, or no detection value.',
    'For phishkitSignatures: be strict. These run on every page source. When in doubt, REMOVE.',
    '',
    'PERFORMANCE IS A HARD REQUIREMENT. Patterns flagged with ⚡ MUST be fixed or removed.',
    'There are 340+ source patterns that all run against 5-10MB page source on every page load.',
    'Performance rewrites:',
    '- Replace .* with bounded quantifiers: [^<]{0,2000} for HTML context, [\\s\\S]{0,2000} for cross-line',
    '- Replace (?=.*X)(?=.*Y)(?=.*Z) with: X[\\s\\S]{0,5000}Y[\\s\\S]{0,5000}Z (ordered match)',
    '  or split into separate patterns if order cannot be guaranteed',
    '- Remove the s (DOTALL) flag — use [\\s\\S]{0,N} explicitly where cross-line matching is needed',
    '- Start patterns with a literal prefix of 4+ chars for V8 Boyer-Moore fast skip',
    '- Use [^>]* instead of .* inside HTML tag context, [^"\\n]* inside attribute values',
    '- NEVER use nested quantifiers like (a+)+ or (.*?)*',
    '',
    'When providing a FIX, the corrected pattern MUST:',
    '1. Have zero unanchored .* with the s flag',
    '2. Have no more than one .* without a bounded alternative',
    '3. Start with a literal string of 4+ characters where possible',
    '4. Detect the same phishing content as the original (no detection regression)',
  ].join('\n');

  // Process file by file — review patterns, then immediately create issue
  // This way if a later batch fails, earlier issues are already filed
  let issuesCreated = 0;
  let batchNum = 0;
  const totalBatches = Math.ceil(flagged.length / 10);

  for (const [file, patterns] of Object.entries(byFile)) {
    // Review this file's patterns in batches of 10
    const fileReviews = [];

    for (let i = 0; i < patterns.length; i += 10) {
      batchNum++;
      const batch = patterns.slice(i, i + 10);
      const batchText = batch.map(f => {
        const pat = allPatterns[`${f.file}:${f.id}`] || { id: f.id };
        return `### ${f.id} (${f.file})\nIssues found: ${f.issues.join('; ')}\nPattern: ${JSON.stringify(pat, null, 2)}`;
      }).join('\n\n');

      const review = await claudeWithRetry(
        opusSystemPrompt,
        `Review these ${batch.length} flagged patterns:\n\n${batchText}`
      );

      if (review) {
        fileReviews.push(review);
      }
      console.log(`  Batch ${batchNum}/${totalBatches} done${review ? '' : ' (no Opus review — API error)'}`);

      // Brief pause between batches to avoid rate limits
      await new Promise(r => setTimeout(r, 1000));
    }

    // ── Create issue for this file immediately ────────────────────────────
    if (DRY_RUN) {
      console.log(`  [DRY RUN] Would create issue for ${file} (${patterns.length} patterns)`);
      continue;
    }

    const opusSection = fileReviews.length > 0
      ? `## Opus Review\n\n${fileReviews.join('\n\n---\n\n').slice(0, 20000)}\n\n---\n\n`
      : '## Opus Review\n\n_Opus review unavailable (API errors during audit run). Automated findings below._\n\n---\n\n';

    const findingsSection = patterns.map(p =>
      `- **\`${p.id}\`** (weight: ${p.weight})\n` +
      p.issues.map(iss => `  - ${iss}`).join('\n')
    ).join('\n');

    const body = [
      `## Source Pattern Audit — \`rules/source/${file}\``,
      '',
      `Found **${patterns.length}** pattern(s) needing review.`,
      autoFixed.filter(f => f.file === file).length > 0
        ? `Auto-fixed ${autoFixed.filter(f => f.file === file).length} weight issue(s) already committed.`
        : '',
      '',
      '---',
      '',
      opusSection,
      '## Automated findings',
      '',
      findingsSection,
      '',
      '---',
      `*Generated at ${new Date().toISOString()}*`,
    ].filter(s => s !== null && s !== undefined).join('\n').slice(0, 65000);

    try {
      await github.createIssue(
        REPO,
        `[AUDIT] ${file} — ${patterns.length} pattern issue(s)`,
        body,
        ['needs-review']
      );
      issuesCreated++;
      console.log(`  ✓ Created issue for ${file}`);
    } catch (e) {
      console.warn(`  ✗ Failed to create issue for ${file}: ${e.message}`);
    }

    await new Promise(r => setTimeout(r, 500));
  }

  console.log(`\nCreated ${issuesCreated} audit issue(s)`);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
