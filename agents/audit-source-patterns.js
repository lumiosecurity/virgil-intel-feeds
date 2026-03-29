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

  // ── Ask Opus to review each flagged pattern ─────────────────────────────────

  console.log(`\nAsking Opus to review ${flagged.length} flagged pattern(s)...`);
  const opusReviews = [];

  for (let i = 0; i < flagged.length; i += 10) {
    const batch = flagged.slice(i, i + 10);
    const batchText = batch.map(f => {
      const pat = allPatterns[`${f.file}:${f.id}`] || { id: f.id };
      return `### ${f.id} (${f.file})\nIssues found: ${f.issues.join('; ')}\nPattern: ${JSON.stringify(pat, null, 2)}`;
    }).join('\n\n');

    const resp = await client.messages.create({
      model:      'claude-opus-4-6',
      max_tokens: 2000,
      system: [
        'You are a Virgil detection engineer auditing existing phishing detection source patterns.',
        'For each pattern give: 1) KEEP / FIX / REMOVE verdict  2) One-line reason  3) If FIX: exact corrected patternString.',
        'KEEP = specific enough, low FP risk.',
        'FIX = has merit but needs tightening — provide corrected patternString.',
        'REMOVE = too broad, duplicates logic, or no detection value.',
        'For phishkitSignatures: be strict. These run on every page source. When in doubt, REMOVE.',
      ].join('\n'),
      messages: [{ role: 'user', content: `Review these ${batch.length} flagged patterns:\n\n${batchText}` }],
    });

    opusReviews.push(resp.content?.[0]?.text || '');
    console.log(`  Batch ${Math.floor(i / 10) + 1}/${Math.ceil(flagged.length / 10)} done`);
  }

  // ── Create GitHub issues — one per file to stay under 65k char limit ────────

  const byFile = {};
  for (const f of flagged) {
    if (!byFile[f.file]) byFile[f.file] = [];
    byFile[f.file].push(f);
  }

  // Map Opus review text back to files by scanning for file names
  const reviewsByFile = {};
  for (const [file, patterns] of Object.entries(byFile)) {
    const baseName = file.replace('.json', '');
    reviewsByFile[file] = opusReviews
      .map(r => {
        // Extract sections mentioning this file's pattern IDs
        const patIds = patterns.map(p => p.id);
        const lines = r.split('\n');
        const relevant = [];
        let capturing = false;
        for (const line of lines) {
          if (patIds.some(id => line.includes(id))) capturing = true;
          if (capturing) {
            relevant.push(line);
            // Stop at next pattern heading
            if (relevant.length > 1 && line.startsWith('###') && !patIds.some(id => line.includes(id))) break;
          }
        }
        return relevant.join('\n').trim();
      })
      .filter(Boolean)
      .join('\n\n');
  }

  if (DRY_RUN) {
    console.log('\n--- DRY RUN ---');
    console.log(`Would create ${Object.keys(byFile).length} issues`);
    return;
  }

  let issuesCreated = 0;
  for (const [file, patterns] of Object.entries(byFile)) {
    const opusSection = reviewsByFile[file]
      ? `## Opus Review\n\n${reviewsByFile[file].slice(0, 20000)}\n\n---\n\n`
      : '';

    const findingsSection = patterns.map(p =>
      `- **\`${p.id}\`** (weight: ${p.weight})\n` +
      p.issues.map(i => `  - ${i}`).join('\n')
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

    await github.createIssue(
      REPO,
      `[AUDIT] ${file} — ${patterns.length} pattern issue(s)`,
      body,
      ['needs-review']
    );
    issuesCreated++;
    console.log(`  Created issue for ${file}`);

    // Rate limit
    await new Promise(r => setTimeout(r, 500));
  }

  console.log(`\nCreated ${issuesCreated} audit issue(s)`);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
