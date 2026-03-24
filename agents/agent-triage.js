#!/usr/bin/env node
// Virgil — FP/FN Triage Agent (Agent 1)
//
// Triggered when a user-feedback issue is opened in core-rules.
// Runs a full investigation on the FULL URL/hostname (not just registered domain)
// and posts a structured analysis comment with a proposed resolution.

import { cfg, d1, claude, github, getDomainIntel, analyzeUrl, fmtIntel, fmtHeuristics } from './agent-tools.js';

const ISSUE_NUMBER = parseInt(process.env.ISSUE_NUMBER || process.argv[2]);
const REPO         = cfg.coreRulesRepo;

if (!ISSUE_NUMBER) { console.error('ISSUE_NUMBER required'); process.exit(1); }

async function main() {
  console.log(`\nAgent 1: FP/FN Triage — Issue #${ISSUE_NUMBER}`);

  const issue = await github.getIssue(REPO, ISSUE_NUMBER);
  if (!issue) { console.error('Issue not found'); process.exit(1); }

  const labels = issue.labels.map(l => l.name);
  if (!labels.includes('user-feedback')) { console.log('Not a user-feedback issue — skipping'); process.exit(0); }
  if (labels.includes('agent-triaged'))  { console.log('Already triaged — skipping'); process.exit(0); }

  console.log(`Issue: "${issue.title}"`);

  // ── Extract all fields from issue body ──────────────────────────────────────
  const domainMatch   = issue.body?.match(/\| Domain \| `([^`]+)` \|/);
  const hostnameMatch = issue.body?.match(/\| Full hostname \| `([^`]+)` \|/);
  const urlMatch      = issue.body?.match(/\| Full URL \| `([^`]+)` \|/);
  const typeMatch     = issue.body?.match(/\| Feedback type \| ([^\n|]+) \|/);
  const verdictMatch  = issue.body?.match(/\| Verdict shown \| ([^\n|]+) \|/);
  const brandMatch    = issue.body?.match(/\| Detected brand \| ([^\n|]+) \|/);
  const confMatch     = issue.body?.match(/\| Confidence \| ([^\n|]+) \|/);
  const commentMatch  = issue.body?.match(/## User comment\n> ([^\n]+)/);
  const screenshotMatch = issue.body?.match(/!\[Page screenshot\]\((https:\/\/[^\)]+)\)/);

  const registeredDomain = domainMatch?.[1]?.trim();
  const url              = urlMatch?.[1]?.trim();
  const feedbackType     = typeMatch?.[1]?.trim();
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

  const systemPrompt = `You are Virgil's triage agent — a security analyst specialising in phishing detection. You investigate reported detections and produce actionable triage reports.

CRITICAL: When analysing subdomain-based phishing (e.g. paypal-login.webflow.io, help--logie--kucuie.webflow.io), the FULL hostname is what matters — NOT the registered domain. A legitimate registered domain (webflow.io, github.io, netlify.app) hosting a phishing page is extremely common. Always analyse the full hostname and page content first.

IMPORTANT: Many phishing pages are built with JavaScript frameworks (React, Webflow, etc.) and render content dynamically. If the HTML source is sparse (< 5KB) but a screenshot is provided, the screenshot is your PRIMARY evidence of what the page actually looks like and contains. Describe what you see in the screenshot in detail — login forms, brand logos, credential fields, urgency language, etc.`;

  const pageSection = hasPageContent
    ? `## Page content (captured by extension at report time)

### Phishkit indicators
${pageIndicators.length > 0 ? pageIndicators.map(i => `- ${i}`).join('\n') : '- None detected'}

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

  const userContent = `
## Triage Request

**Full URL:** ${url || 'not provided'}
**Full hostname:** \`${fullHostname}\`
**Registered domain:** \`${registeredDomain}\`
**Feedback type:** ${feedbackType}
**Verdict shown:** ${verdictShown} (confidence: ${confidence || 'unknown'})
**Detected brand:** ${detectedBrand || 'none'}
${userComment ? `**User comment:** "${userComment}"` : ''}

## Signals that fired on this page
${signalsFromIssue.length > 0 ? signalsFromIssue.map(s => `- \`${s}\``).join('\n') : '- (none in issue body)'}

${pageSection}

## Heuristic re-analysis of full URL
${fmtHeuristics(heuristics)}

## External intelligence (queried for: ${fullHostname})
${fmtIntel(intel)}
Safe Browsing: ${intel.gsb?.matched ? `⚠ MATCHED — ${intel.gsb.threatTypes?.join(', ')}` : intel.gsb ? 'Clean' : 'Not checked'}

## Corpus history for ${registeredDomain}
${signalRows.length > 0 ? signalRows.map(r => `- \`${r.type}\`: ${r.hits} hit(s), avg weight ${r.avg_weight?.toFixed(2)}`).join('\n') : '- No corpus signals'}

${verdictRows.length > 0 ? `## Recent verdicts\n${verdictRows.map(v => `- ${v.risk_level} conf:${v.confidence?.toFixed(2)} brand:${v.detected_brand||'none'} pwd-form:${v.has_password_form?'YES':'no'}`).join('\n')}` : ''}

## Your task

Analyse \`${fullHostname}\` — NOT just \`${registeredDomain}\`.

For subdomain-based phishing on hosting platforms: the registered domain being legitimate means nothing if the subdomain impersonates a brand or the page harvests credentials. Use the live page content above as your primary evidence.

Produce a triage report:
1. **Assessment** (2-3 sentences): Is this a genuine FP/FN? Lead with the full URL analysis.
2. **Hostname analysis**: Does \`${fullHostname}\` suggest impersonation? What does the subdomain pattern mean?
3. **Page content analysis**: What does the live page content tell you? Are there credential forms, brand impersonation, exfil patterns?
4. **Signal analysis**: Which signals fired and are they appropriate?
5. **Evidence summary**: For and against the detection.
6. **Root cause** (if FP): Which signal(s) over-triggered and why?
7. **Recommended action** — exactly ONE of:
   - ADD_TO_SAFELIST — legitimate site, add to safe list
   - ADD_TYPOSQUAT — confirmed phishing, add hostname pattern as detection rule
   - ADJUST_WEIGHT — correct detection but over-triggered
   - ADD_BRAND_ENTRY — missing brand entry
   - NO_ACTION — detection was correct
   - NEEDS_MANUAL_REVIEW — ambiguous
8. **Proposed rule change** (if applicable): Exact JSON for core-rules

Be direct. Maintainers act on your recommendations.`;

  if (screenshotUrl) {
    console.log('Passing screenshot to Claude:', screenshotUrl);
  }
  const analysis = await claude(systemPrompt, userContent, 2000, screenshotUrl);

  const actionMatch2 = analysis.match(/ADD_TO_SAFELIST|ADD_TYPOSQUAT|ADJUST_WEIGHT|ADD_BRAND_ENTRY|NO_ACTION|NEEDS_MANUAL_REVIEW/);
  const action = actionMatch2?.[0] || 'NEEDS_MANUAL_REVIEW';

  const actionLabel = {
    ADD_TO_SAFELIST:     'confirmed-fp',
    ADD_TYPOSQUAT:       'confirmed-fn',
    ADJUST_WEIGHT:       'rule-updated',
    ADD_BRAND_ENTRY:     'rule-updated',
    NO_ACTION:           'wont-fix',
    NEEDS_MANUAL_REVIEW: 'needs-triage',
  }[action] || 'needs-triage';

  const comment = `## 🤖 Agent Triage Report

**Recommended action:** \`${action}\`
**Analysed:** \`${fullHostname}\` (registered: \`${registeredDomain}\`)
**Page content source:** ${hasPageContent ? '✓ captured by extension' : liveFetch ? '✓ live fetch' : '✗ unavailable'}
${pageIndicators.length > 0 ? `**Phishkit indicators:** ${pageIndicators.join(', ')}` : ''}

---

${analysis}

---

<details>
<summary>Raw intelligence</summary>

**CT log:** ${intel.ct ? `${intel.ct.ageDays} days old (first seen ${new Date(intel.ct.firstSeenTs).toISOString().slice(0,10)})` : 'not found'}
**Safe Browsing:** ${intel.gsb?.matched ? '⚠ MATCHED' : intel.gsb ? 'clean' : 'not checked'}
**Corpus reports:** ${intel.corpus.reports} distinct installs
**Feed hits:** ${intel.feeds.hits}

**Page indicators:**
${pageContent?.indicators?.map(i => `- ${i}`).join('\n') || '(none)'}

**Signals from issue:**
${signalsFromIssue.map(s => `- \`${s}\``).join('\n') || '(none)'}

**Heuristic re-run:**
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
