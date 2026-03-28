#!/usr/bin/env node
// Virgil — FP/FN Triage Agent (Agent 1)
//
// Triggered when a user-feedback issue is opened in core-rules.
// Runs a full investigation on the FULL URL/hostname (not just registered domain)
// and posts a structured analysis comment with a proposed resolution.

import { cfg, d1, claude, github, getDomainIntel, analyzeUrl, fmtIntel, fmtHeuristics, extractRegisteredDomain } from './agent-tools.js';

const ISSUE_NUMBER = parseInt(process.env.ISSUE_NUMBER || process.argv[2]);
const REPO         = cfg.coreRulesRepo;

if (!ISSUE_NUMBER) { console.error('ISSUE_NUMBER required'); process.exit(1); }

async function main() {
  console.log(`\nAgent 1: FP/FN Triage — Issue #${ISSUE_NUMBER}`);

  const issue = await github.getIssue(REPO, ISSUE_NUMBER);
  if (!issue) { console.error('Issue not found'); process.exit(1); }

  const labels = issue.labels.map(l => l.name);
  if (!labels.includes('user-feedback') && !labels.includes('rule-gap')) {
    console.log('Not a user-feedback or rule-gap issue — skipping');
    process.exit(0);
  }

  // Allow manual retriage via /retriage comment even if already triaged
  const isRetriage = process.env.IS_RETRIAGE === 'true';
  if (labels.includes('agent-triaged') && !isRetriage) {
    console.log('Already triaged — skipping (use /retriage comment to force)');
    process.exit(0);
  }

  // On retriage, remove the old agent-triaged label so the new result is clear
  if (isRetriage && labels.includes('agent-triaged')) {
    await github.removeLabel(REPO, ISSUE_NUMBER, 'agent-triaged').catch(() => {});
    console.log('Removed old agent-triaged label for retriage');
  }

  console.log(`Issue: "${issue.title}"`);
  console.log(`Labels: ${labels.join(', ')}`);
  console.log(`isRuleGap: ${labels.includes('rule-gap')}`);

  // ── Extract all fields from issue body ──────────────────────────────────────
  const domainMatch    = issue.body?.match(/\| Domain \| `([^`]+)` \|/);
  const hostnameMatch  = issue.body?.match(/\| Full hostname \| `([^`]+)` \|/);
  const urlMatch       = issue.body?.match(/\| Full URL \| `([^`]+)` \|/);
  const typeMatch      = issue.body?.match(/\| Feedback type \| ([^\n|]+) \|/);
  const verdictMatch   = issue.body?.match(/\| Verdict shown \| ([^\n|]+) \|/) ||
                         issue.body?.match(/\| Risk level \| ([^\n|]+) \|/);
  const brandMatch     = issue.body?.match(/\| Detected brand \| ([^\n|]+) \|/) ||
                         issue.body?.match(/\| Impersonated brand \| ([^\n|]+) \|/);
  const confMatch      = issue.body?.match(/\| Confidence \| ([^\n|]+) \|/);
  const commentMatch   = issue.body?.match(/## User comment\n> ([^\n]+)/);
  const screenshotMatch = issue.body?.match(/!\[Page screenshot\]\((https:\/\/[^\)]+)\)/);
  // Rule-gap specific fields
  const threatMatch    = issue.body?.match(/\| Primary threat \| ([^\n|]+) \|/);

  // registeredDomain — try Domain field first, then derive from hostname/URL
  let registeredDomain = domainMatch?.[1]?.trim();
  if (!registeredDomain) {
    const hn = hostnameMatch?.[1]?.trim() || '';
    if (hn) registeredDomain = extractRegisteredDomain(hn);
  }
  if (!registeredDomain) {
    try {
      const u = urlMatch?.[1]?.trim();
      if (u) registeredDomain = extractRegisteredDomain(new URL(u).hostname);
    } catch {}
  }
  // Last resort — extract from issue title [RULE-GAP] hostname or [FN] hostname
  if (!registeredDomain) {
    const titleMatch = issue.title?.match(/\] ([a-z0-9.-]+\.[a-z]{2,})/i);
    if (titleMatch) registeredDomain = extractRegisteredDomain(titleMatch[1]);
  }

  const url              = urlMatch?.[1]?.trim();
  const feedbackType     = typeMatch?.[1]?.trim() || (labels.includes('rule-gap') ? 'rule_gap' : 'unknown');
  const verdictShown     = verdictMatch?.[1]?.trim();
  const detectedBrand    = brandMatch?.[1]?.trim();
  const confidence       = confMatch?.[1]?.trim();
  const userComment      = commentMatch?.[1]?.trim();
  const screenshotUrl    = screenshotMatch?.[1]?.trim();

  // Extract FULL hostname — prefer explicit field, fall back to URL parsing, then registered domain
  let fullHostname = hostnameMatch?.[1]?.trim();
  if (!fullHostname) { try { if (url) fullHostname = new URL(url).hostname; } catch {} }
  if (!fullHostname) fullHostname = registeredDomain;

  // Extract signals from issue body
  const signalsSection  = issue.body?.match(/## Signals that fired\n([\s\S]*?)(?:\n##|$)/);
  const signalsFromIssue = signalsSection?.[1]
    ?.split('\n').map(l => l.replace(/^- `?|`?$/g, '').trim()).filter(Boolean) || [];

  if (!registeredDomain) {
    await github.commentOnIssue(REPO, ISSUE_NUMBER, '⚠️ **Triage agent:** Could not extract domain. Manual review required.');
    await github.addLabel(REPO, ISSUE_NUMBER, ['needs-triage']);
    process.exit(0);
  }

  console.log(`Full hostname: ${fullHostname}, registered: ${registeredDomain}, type: ${feedbackType}`);

  // ── Extract page content from issue body ─────────────────────────────────────
  // Extension already captured this — no need to re-fetch
  const visibleTextMatch = issue.body?.match(/## Visible page text \(excerpt\)\n```\n([\s\S]*?)```/);
  const htmlSourceMatch  = issue.body?.match(/```html\n([\s\S]*?)```/);
  const inlineScriptMatches = [...(issue.body?.matchAll(/```js\n([\s\S]*?)```/g) || [])].map(m => m[1]);

  const pageIndicatorSection = issue.body?.match(/## Phishkit indicators detected\n([\s\S]*?)(?:\n##|$)/);
  const pageIndicators = pageIndicatorSection?.[1]
    ?.split('\n').map(l => l.replace(/^- `?|`?$/g, '').trim()).filter(Boolean) || [];

  const extScriptSection = issue.body?.match(/## External scripts loaded\n([\s\S]*?)(?:\n##|$)/);
  const externalScriptUrls = extScriptSection?.[1]
    ?.split('\n').map(l => l.replace(/^- `?|`?$/g, '').trim()).filter(Boolean) || [];

  const visibleText    = visibleTextMatch?.[1]?.trim() || null;
  const htmlSource     = htmlSourceMatch?.[1]?.trim() || null;
  const hasPageContent = !!(visibleText || htmlSource || inlineScriptMatches.length);

  console.log(`Page content from issue: visibleText=${!!visibleText}, html=${!!htmlSource}, scripts=${inlineScriptMatches.length}, indicators=${pageIndicators.length}`);

  // Only fetch live if issue has no page content (fallback)
  let liveFetch = null;
  if (!hasPageContent && url && url !== 'not provided') {
    console.log('No page content in issue — attempting live fetch...');
    try {
      const resp = await fetch(url, {
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; VirgilSecurityBot/1.0)' },
        signal: AbortSignal.timeout(8000),
      });
      if (resp.ok) {
        const html = await resp.text();
        const text = html.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/<style[\s\S]*?<\/style>/gi, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 3000);
        const indicators = [];
        if (/password|passwd/i.test(html))           indicators.push('password field');
        if (/login|sign.?in/i.test(html))            indicators.push('login UI');
        if (/paypal|apple|microsoft|google|amazon|chase|bank|coinbase/i.test(html)) indicators.push('brand mention in source');
        if (/telegram\.me|t\.me\//i.test(html))      indicators.push('Telegram exfil');
        if (/<form/i.test(html))                     indicators.push('HTML form');
        const actionM = html.match(/action=["']([^"']+)["']/i);
        if (actionM) indicators.push(`form action: ${actionM[1].slice(0,80)}`);
        liveFetch = { text, html: html.slice(0, 5000), indicators };
        console.log(`Live fetch: ${html.length} chars, indicators: ${indicators.join(', ') || 'none'}`);
      }
    } catch (e) {
      console.log(`Live fetch failed: ${e.message}`);
    }
  }

  // ── Gather domain intelligence ───────────────────────────────────────────────
  console.log('Gathering domain intelligence...');
  const [intel, heuristics] = await Promise.all([
    getDomainIntel(fullHostname),
    url ? Promise.resolve(analyzeUrl(url)) : Promise.resolve(null),
  ]);

  // ── Corpus signals ───────────────────────────────────────────────────────────
  const signalRows = d1(`
    SELECT s.type, COUNT(*) as hits, AVG(s.weight) as avg_weight
    FROM signals s JOIN verdicts v ON s.verdict_id = v.id
    WHERE v.registered_domain = '${registeredDomain.replace(/'/g,"''")}'
    GROUP BY s.type ORDER BY hits DESC LIMIT 15
  `);

  const verdictRows = d1(`
    SELECT risk_level, confidence, detected_brand, has_password_form,
           external_form_submit, phishkit_signal_count, created_at
    FROM verdicts
    WHERE registered_domain = '${registeredDomain.replace(/'/g,"''")}'
    ORDER BY created_at DESC LIMIT 5
  `);

  // ── Build Claude prompt ──────────────────────────────────────────────────────
  console.log('Calling Claude for analysis...');

  const pageSection = hasPageContent
    ? `## Page content (captured by extension at report time)

### Quick regex scan of page source
Note: These are raw string matches from a lightweight inline scan — NOT weighted detection signals. They did not drive the heuristic score.
${pageIndicators.length > 0 ? pageIndicators.map(i => `- \`${i}\``).join('\n') : '- None'}

### External scripts
${externalScriptUrls.length > 0 ? externalScriptUrls.map(u => `- \`${u}\``).join('\n') : '- None'}

${visibleText ? `### Visible page text\n\`\`\`\n${visibleText}\n\`\`\`` : ''}

${inlineScriptMatches.length > 0 ? `### Inline scripts (${inlineScriptMatches.length} found)\n${inlineScriptMatches.map((s,i) => `**Script ${i+1}:**\n\`\`\`js\n${s.slice(0,2000)}\n\`\`\``).join('\n\n')}` : ''}

${htmlSource ? `### Raw HTML\n\`\`\`html\n${htmlSource.slice(0, 15000)}\n\`\`\`` : ''}
`
    : liveFetch
    ? `## Page content (live fetch — extension data not available)

### Indicators
${liveFetch.indicators.length > 0 ? liveFetch.indicators.map(i => `- ${i}`).join('\n') : '- None'}

### Visible text
\`\`\`
${liveFetch.text}
\`\`\`

### HTML snippet
\`\`\`html
${liveFetch.html}
\`\`\`
`
    : '## Page content\nNot available — extension data absent and live fetch not attempted.\n';

  // Extract verdict risk level from issue
  const riskLevelMatch = issue.body?.match(/\| Risk level \| ([^\n|]+) \|/) ||
                         issue.body?.match(/\| Verdict shown \| ([^\n|]+) \|/);
  const verdictRiskLevel = riskLevelMatch?.[1]?.trim()?.toLowerCase() || '';

  const confidenceValue = (() => {
    const raw = parseFloat(confidence);
    if (isNaN(raw)) return 0;
    // "95%" parses as 95, "0.95" parses as 0.95
    // Values > 1 are already percentages, divide by 100
    // Exception: exactly 1.0 could mean 100% — treat > 1 as percentage format
    return raw > 1 ? raw / 100 : raw;
  })();

  const isRuleGap = labels.includes('rule-gap')
    || issue.title?.startsWith('[RULE-GAP]')
    // High-confidence detection submitted via report button — still needs a rule
    || (confidenceValue >= 0.75
        && (verdictRiskLevel === 'dangerous' || verdictRiskLevel === 'suspicious'));

  const systemPrompt = `You are Virgil's triage agent — a security analyst specialising in phishing detection. You investigate reported pages and produce actionable triage reports.

YOUR PRIMARY EVIDENCE IS THE PAGE CONTENT — not the domain name. Phishing pages are routinely hosted on legitimate platforms (webflow.io, github.io, netlify.app, weebly.com). The domain tells you almost nothing on its own. What matters is:

1. What does the page LOOK LIKE? (screenshot — examine this first)
2. What is the page ASKING FOR? (credential forms, password fields, wallet keys, personal info)
3. What BRAND is being impersonated? (logos, copy, color scheme, page title)
4. Where does submitted data GO? (form actions, JS fetch calls, external endpoints)
5. What TECHNIQUES are being used? (obfuscation, gating, bot evasion, image-as-page)

Domain analysis is secondary supporting context. Start with what you see.

${isRuleGap ? `CRITICAL — THIS IS A RULE-GAP ISSUE:
Claude's AI analysis already confirmed this page is phishing at high confidence. The detection WORKED. This is NOT a false positive investigation.
The heuristic signals listed in the issue fired but were too low-weight to trigger a warning on their own — that is WHY this is a rule gap.
Your job is to identify WHAT SPECIFIC RULE would catch this page locally without needing Claude. Focus on:
- What brand is being impersonated and is it missing from brand entries?
- Is there a URL pattern, subdomain structure, or typosquat that should be a detection rule?
- Is there a page source pattern (JS, form action, exfil endpoint) that's characteristic of this phishkit?
Do NOT recommend NO_ACTION. Do NOT say "detection was correct" as a final answer — the detection worked but the RULE GAP still needs to be closed.` : ''}`;

  const userContent = `
## Triage Request

**Full URL:** ${url || 'not provided'}
**Feedback type:** ${feedbackType}
**Verdict shown to user:** ${verdictShown} (confidence: ${confidence || 'unknown'})
**Detected brand:** ${detectedBrand || 'none'}
${userComment ? `**User comment:** "${userComment}"` : ''}

${pageSection}

## Signals that fired
${signalsFromIssue.length > 0 ? signalsFromIssue.map(s => `- \`${s}\``).join('\n') : '- (none recorded)'}

## URL-structure heuristics (URL only — no DOM data available to agent)
Note: DOM-based signals (password fields, login UI, brand mentions in page source) are captured by the extension at browse time and shown in "Page content" above. This section only re-analyzes the URL string itself.
${fmtHeuristics(heuristics)}

## Domain intelligence (supporting context only)
Hostname: \`${fullHostname}\` (registered: \`${registeredDomain}\`)
${fmtIntel(intel)}
Safe Browsing: ${intel.gsb?.matched ? `⚠ MATCHED — ${intel.gsb.threatTypes?.join(', ')}` : intel.gsb ? 'Clean' : 'Not checked'}

## Corpus history
${signalRows.length > 0 ? signalRows.map(r => `- \`${r.type}\`: ${r.hits} hit(s), avg weight ${r.avg_weight?.toFixed(2)}`).join('\n') : '- No prior reports'}

${verdictRows.length > 0 ? `## Prior verdicts\n${verdictRows.map(v => `- ${v.risk_level} conf:${v.confidence?.toFixed(2)} brand:${v.detected_brand||'none'} pwd-form:${v.has_password_form?'YES':'no'}`).join('\n')}` : ''}

## Your task

${isRuleGap ? `This is a rule-gap issue. Claude already confirmed this is phishing at ${confidence || 'high'} confidence. Your job is NOT to re-evaluate whether it's phishing — it is. Your job is to propose the 3 best local rules that would catch this without Claude.

1. **What is this page?** Describe what you see visually — brand, credential fields, impersonation technique.
2. **Why did local heuristics miss it?** The heuristic score was low — which signals are missing or underweighted?
3. **Top 3 proposed rules** — ranked by expected detection lift. Format each rule as follows:

---
### Rule 1 — [RULE_TYPE] (expected lift: ~X%)
**Why it works:** one sentence explanation

**Rule JSON:**
\`\`\`json
{
  "multi-line",
  "indented": "JSON here"
}
\`\`\`

---
### Rule 2 — [RULE_TYPE] (expected lift: ~X%)
**Why it works:** one sentence explanation

**Rule JSON:**
\`\`\`json
{
  "multi-line",
  "indented": "JSON here"
}
\`\`\`

---
### Rule 3 — [RULE_TYPE] (expected lift: ~X%)
**Why it works:** one sentence explanation

**Rule JSON:**
\`\`\`json
{
  "multi-line",
  "indented": "JSON here"
}
\`\`\`

---

Use these schemas (always write JSON as multi-line with 2-space indentation):

Brand entry:
\`\`\`json
{
  "name": "brandname",
  "domains": ["brand.com"],
  "typos": ["brannd", "br4nd"],
  "vertical": "financial"
}
\`\`\`
IMPORTANT — name must be lowercase alphanumeric only (no spaces, no capitals, no special chars). e.g. "paypal" not "PayPal", "kucoin" not "KuCoin".
Valid verticals (use ONLY these exact strings): "financial" | "crypto" | "sso" | "ecommerce" | "general" | "business" | "cloud_storage" | "entertainment" | "gambling" | "gaming" | "government" | "logistics" | "messaging" | "productivity" | "social" | "technology" | "telecom"

Source pattern:
\`\`\`json
{
  "id": "pattern-id",
  "group": "phishkitSignatures",
  "description": "...",
  "severity": "high",
  "weight": 0.40,
  "source": "js",
  "patternString": "regex here",
  "patternFlags": "i"
}
\`\`\`
IMPORTANT — use ONLY these exact values:
- id: lowercase alphanumeric with hyphens only (e.g. "telegram-exfil-pattern")
- group: "phishkitSignatures" | "cdnGating" | "captchaGating" | "botEvasion" | "obfuscation" | "brandImpersonation" | "credentialHarvesting" | "socialEngineering" | "titleImpersonation" | "typosquatPatterns" | "urlHeuristics"
- source: "html" | "js" | "both" (NOT "url", "title", "dom", "text", "hostname" — those are invalid)
- weight: number between 0.05 and 0.50
- severity: "high" | "medium" | "low"

4. **Recommended action** (primary rule type — NO_ACTION IS NOT VALID for rule-gap issues): ADD_BRAND_ENTRY / ADD_TYPOSQUAT / ADD_SOURCE_PATTERN / ADJUST_WEIGHT / NEEDS_MANUAL_REVIEW` : `Start by describing what you see on the page — use the screenshot and page content as your primary evidence.

1. **What is this page?** Describe what you see visually. What brand does it impersonate? What is it asking the user to do?
2. **Is this phishing?** Based on the page content. Be direct.
3. **Why did/didn't Virgil detect it?** Which signals fired or should have fired based on what you see?
4. **Root cause** (if FP): Which specific signal(s) over-triggered?
5. **Recommended action** — exactly ONE of:
   - ADD_TO_SAFELIST — legitimate page, add domain to safe list
   - ADD_TYPOSQUAT — confirmed phishing subdomain, add as detection rule
   - ADJUST_WEIGHT — detected but wrong confidence, tune signal weights
   - ADD_BRAND_ENTRY — impersonated brand is missing from detection rules
   - ADD_SOURCE_PATTERN — specific page pattern should be added as a source rule
   - NO_ACTION — detection was correct, close as intended
   - NEEDS_MANUAL_REVIEW — genuinely ambiguous
6. **Proposed rule change** (if applicable): Exact JSON in Virgil schema format`}

Be direct and specific. Focus on what the page does, not where it's hosted.`;

  if (screenshotUrl) {
    console.log('Passing screenshot to Claude:', screenshotUrl);
  }
  const analysis = await claude(systemPrompt, userContent, isRuleGap ? 3000 : 2000, screenshotUrl);

  const actionMatch2 = analysis.match(/ADD_TO_SAFELIST|ADD_TYPOSQUAT|ADJUST_WEIGHT|ADD_BRAND_ENTRY|ADD_SOURCE_PATTERN|NO_ACTION|NEEDS_MANUAL_REVIEW/);
  let action = actionMatch2?.[0] || 'NEEDS_MANUAL_REVIEW';

  // NO_ACTION is never valid for rule-gap issues — the detection worked but the gap still needs closing
  if (isRuleGap && action === 'NO_ACTION') {
    action = 'NEEDS_MANUAL_REVIEW';
    console.log('[Triage] Overrode NO_ACTION → NEEDS_MANUAL_REVIEW for rule-gap issue');
  }

  const actionLabel = {
    ADD_TO_SAFELIST:     'confirmed-fp',
    ADD_TYPOSQUAT:       'confirmed-fn',
    ADJUST_WEIGHT:       'rule-updated',
    ADD_BRAND_ENTRY:     'rule-updated',
    ADD_SOURCE_PATTERN:  'rule-updated',
    NO_ACTION:           'wont-fix',
    NEEDS_MANUAL_REVIEW: 'needs-triage',
  }[action] || 'needs-triage';

  const heuristicScore = confidenceValue;
  const heuristicPct = Math.round(heuristicScore * 100);

  const comment = `## 🤖 Agent Triage Report

**Recommended action:** \`${action}\`
**Analysed:** \`${fullHostname}\` (registered: \`${registeredDomain}\`)
**Page content source:** ${hasPageContent ? '✓ captured by extension' : liveFetch ? '✓ live fetch' : '✗ unavailable'}
${isRuleGap ? `> ⚠️ **Rule gap** — AI detected at ${heuristicPct}% confidence. Heuristic score was **${heuristicPct}%** — local rules did NOT trigger a warning. Rules proposed below are what should be added.` : ''}

---

${analysis}

---

<details>
<summary>Raw intelligence (for reference only)</summary>

**CT log:** ${intel.ct ? `${intel.ct.ageDays} days old (first seen ${new Date(intel.ct.firstSeenTs).toISOString().slice(0,10)})` : 'not found'}
**Safe Browsing:** ${intel.gsb?.matched ? '⚠ MATCHED' : intel.gsb ? 'clean' : 'not checked'}
**Corpus reports:** ${intel.corpus.reports} distinct installs
**Feed hits:** ${intel.feeds.hits}

**Quick regex scan of page source** (NOT weighted detection signals — these are raw string matches that did not drive the verdict):
${pageIndicators.map(i => `- \`${i}\``).join('\n') || '- (none)'}

**Low-weight heuristic signals from issue** (combined score was ${heuristicPct}% — below detection threshold):
${signalsFromIssue.map(s => `- \`${s}\``).join('\n') || '- (none)'}

**URL-only heuristic re-run:**
\`\`\`
${fmtHeuristics(heuristics)}
\`\`\`
</details>

---
*Triaged by Virgil Agent 1 at ${new Date().toISOString()}. Maintainer approval required before any action.*`;

  await github.commentOnIssue(REPO, ISSUE_NUMBER, comment);
  await github.addLabel(REPO, ISSUE_NUMBER, ['agent-triaged', actionLabel]);

  console.log(`✓ Done. Action: ${action}`);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
