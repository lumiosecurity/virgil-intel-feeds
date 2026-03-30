#!/usr/bin/env node
// Virgil — Weekly Rule Quality Scan
// Scans all rule files for basic quality issues and creates a GitHub issue if found.
// Run via GitHub Actions or locally:
//   GITHUB_TOKEN=... RULES_PATH=../virgil-core-rules node agents/rule-quality-scan.js

import { readdirSync, readFileSync } from 'fs';
import { join } from 'path';
import { github, cfg } from './agent-tools.js';

const RULES_PATH = process.env.RULES_PATH || '.';
const REPO       = process.env.REPO_NAME || cfg.coreRulesRepo;
const DRY_RUN    = process.env.DRY_RUN === 'true';

const VALID_SOURCES   = new Set(['html','js','both','url','title','dom','text','hostname','css','domain']);
const VALID_SEVERITIES= new Set(['high','medium','low']);
const VALID_GROUPS    = new Set(['cdnGating','captchaGating','phishkitSignatures','botEvasion','obfuscation',
  'brandImpersonation','credentialHarvesting','socialEngineering','suspiciousDomains',
  'suspiciousHosting','suspiciousSubdomains','titleImpersonation','typosquat',
  'typosquatPatterns','typosquatDetection','urlHeuristics','hostingPatterns']);
const VALID_VERTICALS = new Set(['financial','crypto','sso','ecommerce','general','business',
  'cloud_storage','entertainment','gambling','gaming','government','logistics','messaging',
  'productivity','social','social-media-business','streaming','professional','cryptocurrency',
  'technology','telecom','telecommunications']);

async function main() {
  console.log('\nVirgil Rule Quality Scan');

  const issues = [];

  for (const dir of ['rules/domain', 'rules/source']) {
    const fullDir = join(RULES_PATH, dir);
    let files;
    try { files = readdirSync(fullDir); } catch { continue; }

    for (const fname of files) {
      if (!fname.endsWith('.json') || fname.startsWith('_') || fname.startsWith('.')) continue;
      const filePath = join(fullDir, fname);
      let rule;
      try { rule = JSON.parse(readFileSync(filePath, 'utf8')); }
      catch (e) { issues.push({ file: `${dir}/${fname}`, issue: `Invalid JSON: ${e.message}` }); continue; }

      // Brand entries
      for (const [i, entry] of (rule.domainRules?.brandEntries || []).entries()) {
        if (!entry.name) {
          issues.push({ file: `${dir}/${fname}`, issue: `brandEntries[${i}]: missing name` });
        } else if (!/^[a-z0-9-]+$/.test(entry.name)) {
          issues.push({ file: `${dir}/${fname}`, issue: `brandEntries[${i}]: name "${entry.name}" not lowercase alphanumeric` });
        }
        if (entry.vertical && !VALID_VERTICALS.has(entry.vertical)) {
          issues.push({ file: `${dir}/${fname}`, issue: `brandEntries[${i}] "${entry.name}": invalid vertical "${entry.vertical}"` });
        }
      }

      // Source patterns
      for (const [i, pat] of (rule.sourcePatterns || []).entries()) {
        const ctx = `sourcePatterns[${i}] "${pat.id}"`;

        // Regex compiles
        try { new RegExp(pat.patternString, pat.patternFlags || ''); }
        catch (e) { issues.push({ file: `${dir}/${fname}`, issue: `${ctx}: invalid regex — ${e.message}` }); }

        if (pat.source !== undefined && !VALID_SOURCES.has(pat.source)) {
          issues.push({ file: `${dir}/${fname}`, issue: `${ctx}: invalid source "${pat.source}"` });
        }
        if (pat.group && !VALID_GROUPS.has(pat.group)) {
          issues.push({ file: `${dir}/${fname}`, issue: `${ctx}: invalid group "${pat.group}"` });
        }
        if (typeof pat.weight === 'number' && (pat.weight < 0.05 || pat.weight > 0.50)) {
          issues.push({ file: `${dir}/${fname}`, issue: `${ctx}: weight ${pat.weight} out of range (0.05–0.50)` });
        }
      }
    }
  }

  console.log(`Found ${issues.length} issue(s)`);

  if (issues.length === 0) {
    console.log('All rules passed quality scan');
    return;
  }

  const body = [
    '## Weekly Rule Quality Scan',
    '',
    `Found **${issues.length}** issue(s) in rule files:`,
    '',
    ...issues.map(i => `- \`${i.file}\`: ${i.issue}`),
    '',
    '---',
    `*Generated at ${new Date().toISOString()}*`,
  ].join('\n');

  if (DRY_RUN) {
    console.log('\n--- DRY RUN ---');
    console.log(body);
    return;
  }

  await github.createIssue(
    REPO,
    `[QUALITY] Weekly scan — ${issues.length} rule issue(s)`,
    body,
    ['needs-review']
  );
  console.log('Issue created');
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
