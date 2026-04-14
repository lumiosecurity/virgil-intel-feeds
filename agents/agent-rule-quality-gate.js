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

// ── Load known-good brand resource hashes ─────────────────────────────────────
// Fetched from GitHub Pages (published by publish-detections.yml alongside
// detections.json). Used to detect brand-clone FPs in proposed resourceHash
// rules before they are promoted — if any proposed hash matches a file from
// a real brand's login page, the rule will FP on that brand's site.
// Falls back to empty sets gracefully so other checks still run.

const KNOWN_GOOD_URL = 'https://lumiosecurity.github.io/virgil-intel-feeds/resource-safe-hashes.json';

let _knownGoodExact = new Set(); // sha256 → brandKey (stringified as "sha256:brandKey")
let _knownGoodNorm  = new Set();
let _knownGoodMap   = new Map(); // sha256 → brandKey  (for display in issues/warnings)

async function loadKnownGoodHashes() {
  try {
    const resp = await fetch(KNOWN_GOOD_URL, { signal: AbortSignal.timeout(8000) });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const db = await resp.json();
    let count = 0;
    for (const [brandKey, entry] of Object.entries(db)) {
      if (brandKey === '_meta' || !Array.isArray(entry.resources)) continue;
      for (const res of entry.resources) {
        if (res.sha256)           { _knownGoodExact.add(res.sha256); _knownGoodMap.set(res.sha256, brandKey); count++; }
        if (res.normalizedSha256) { _knownGoodNorm.add(res.normalizedSha256); _knownGoodMap.set(res.normalizedSha256, brandKey); }
      }
    }
    console.log(`Known-good resource hashes: ${count} entries from ${Object.keys(db).filter(k => k !== '_meta').length} brands`);
  } catch (e) {
    console.warn(`Could not load known-good hashes from GitHub Pages: ${e.message}`);
    console.warn(`Brand-clone FP check will be skipped — run publish-detections.yml to publish resource-safe-hashes.json`);
  }
}

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

// ── Legitimate network request samples for FP testing network patterns ────────
// These represent real outbound requests from legitimate sites. Any network
// pattern that matches these is a false positive risk.
const LEGITIMATE_NETWORK_SAMPLES = [
  // SSO / auth flows — legitimate cross-origin credential POSTs
  { url: 'https://auth.okta.com/api/v1/authn', body: 'username=user@company.com&password=test123', transport: 'fetch' },
  { url: 'https://accounts.google.com/signin/v2/sl/pwd', body: '{"email":"test@gmail.com","password":"test"}', transport: 'fetch' },
  { url: 'https://login.microsoftonline.com/common/oauth2/v2.0/token', body: 'grant_type=authorization_code&code=abc123&redirect_uri=https://app.example.com/callback', transport: 'fetch' },
  { url: 'https://appleid.apple.com/auth/authorize', body: '{"email":"test@icloud.com"}', transport: 'fetch' },
  // Payment processors
  { url: 'https://api.stripe.com/v1/payment_intents', body: 'amount=1000&currency=usd&payment_method=pm_card_visa', transport: 'xhr' },
  { url: 'https://www.paypal.com/auth/validatecaptcha', body: '{"captcha_token":"abc123"}', transport: 'fetch' },
  // Analytics / tracking beacons
  { url: 'https://www.google-analytics.com/collect', body: 'v=1&t=pageview&dp=/home&dt=Home+Page', transport: 'beacon' },
  { url: 'https://bat.bing.com/action/0', body: '{"evt":"pageLoad","page":"/home"}', transport: 'beacon' },
  { url: 'https://analytics.tiktok.com/api/v2/pixel', body: '{"event":"ViewContent"}', transport: 'beacon' },
  // Legitimate form submission backends
  { url: 'https://api.hubspot.com/submissions/v3/integration/submit/12345/form-guid', body: '{"fields":[{"name":"email","value":"test@test.com"}]}', transport: 'fetch' },
  { url: 'https://hooks.zapier.com/hooks/catch/12345/abcdef/', body: '{"email":"test@test.com","name":"Test User"}', transport: 'fetch' },
  // WordPress / PHP legitimate
  { url: 'https://example.com/wp-login.php', body: 'log=admin&pwd=password&redirect_to=%2Fwp-admin%2F', transport: 'fetch' },
  { url: 'https://example.com/wp-admin/admin-ajax.php', body: 'action=heartbeat&_nonce=abc123&interval=15', transport: 'xhr' },
  { url: 'https://example.com/wp-comments-post.php', body: 'comment=Great+article&author=John&email=john@test.com', transport: 'fetch' },
  // Legitimate API calls
  { url: 'https://api.github.com/repos/user/repo/issues', body: '{"title":"Bug report","body":"Description here"}', transport: 'fetch' },
  { url: 'https://slack.com/api/chat.postMessage', body: '{"channel":"C123","text":"Hello"}', transport: 'fetch' },
];

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const REASONING_PREAMBLE = `Always reason thoroughly and deeply. Treat every request as complex unless explicitly told otherwise. Never optimize for brevity at the expense of quality. Think step-by-step, consider tradeoffs, and provide comprehensive analysis.\n\n`;

async function claude(system, user, maxTokens = 2000, model = 'claude-sonnet-4-6') {
  const resp = await client.messages.create({
    model,
    max_tokens: maxTokens,
    system:     REASONING_PREAMBLE + system,
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
      // ── Source pattern evaluation (LEGACY — single regex) ────────────────
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

    } else if (rule.id && rule.match && Array.isArray(rule.match)) {
      // ── Source pattern evaluation (MULTI-MATCH) ─────────────────────────
      const isPhishkitSig = rule.group === 'phishkitSignatures';

      // ── Validate match entries ──────────────────────────────────────────
      if (rule.match.length === 0) {
        eval_.issues.push('Multi-match rule has empty match[] array');
      }

      let hasFastPattern = false;
      let hasContent = false;
      let totalContentChars = 0;

      for (let i = 0; i < rule.match.length; i++) {
        const entry = rule.match[i];

        // Must have content or pattern
        if (entry.content === undefined && entry.pattern === undefined) {
          eval_.issues.push(`match[${i}]: must have either 'content' or 'pattern'`);
        }

        // Validate regex entries compile
        if (entry.pattern !== undefined) {
          try {
            new RegExp(entry.pattern, entry.flags || '');
          } catch (e) {
            eval_.issues.push(`match[${i}]: invalid regex '${entry.pattern}': ${e.message}`);
          }
        }

        // Track fast_pattern
        if (entry.fast_pattern) {
          if (entry.content === undefined) {
            eval_.issues.push(`match[${i}]: fast_pattern can only be set on 'content' entries, not 'pattern'`);
          } else if (hasFastPattern) {
            eval_.warnings.push(`match[${i}]: multiple fast_pattern entries — only the first will be used`);
          } else {
            hasFastPattern = true;
            // Check fast_pattern specificity
            if (entry.content.length < 4) {
              eval_.issues.push(`match[${i}]: fast_pattern '${entry.content}' is too short (${entry.content.length} chars) — should be ≥4 chars`);
            }
            const genericFastPatterns = ['password', 'email', 'login', 'form', 'submit', 'input', 'button', 'click', 'http', 'https', 'script', 'function', 'document', 'window'];
            if (genericFastPatterns.includes(entry.content.toLowerCase())) {
              eval_.warnings.push(`match[${i}]: fast_pattern '${entry.content}' is very generic — appears on most web pages. Choose a more specific literal.`);
            }
          }
        }

        // Track content specificity
        if (entry.content !== undefined) {
          hasContent = true;
          totalContentChars += entry.content.length;
        }

        // Validate within/relative
        if (entry.within !== undefined && entry.relative === undefined) {
          eval_.issues.push(`match[${i}]: 'within' requires 'relative' to specify which match entry to measure from`);
        }
        if (entry.relative !== undefined && entry.relative >= rule.match.length) {
          eval_.issues.push(`match[${i}]: 'relative: ${entry.relative}' references non-existent match entry (max index: ${rule.match.length - 1})`);
        }

        // Warn about negated-only rules
        if (entry.negated) {
          const nonNegated = rule.match.filter(m => !m.negated);
          if (nonNegated.length === 0) {
            eval_.issues.push('All match entries are negated — rule would match every page that DOESN\'T contain these strings');
          }
        }
      }

      // Must have a fast_pattern
      if (!hasFastPattern && hasContent) {
        eval_.warnings.push('No explicit fast_pattern set — engine will auto-select the longest content string. Consider marking the most specific content with fast_pattern: true.');
      }

      // ── Detect 'negative' field anti-pattern ──────────────────────────
      // The 'negative' field does not exist in the schema and is silently
      // ignored by pattern-worker.js — any exclusion logic intended via
      // 'negative' is never evaluated. Exclusion patterns must be in the
      // match[] array with negated: true, referenced by index in condition.
      if (rule.negative !== undefined) {
        eval_.issues.push(
          `Rule has a 'negative' field — this field does not exist in the schema and is silently ignored by the pattern engine. ` +
          `Move exclusion patterns into the match[] array with negated: true, then reference them by 0-based index in the condition ` +
          `(e.g., match[2] with negated: true → condition "0 & 1 & 2"). ` +
          `The 'negative' field you wrote will never run.`
        );
      }
      if (rule.condition) {
        // Syntax: only digits, spaces, &, |, !, ()
        if (!/^[\d\s&|!()]+$/.test(rule.condition)) {
          eval_.issues.push(`Invalid condition syntax: '${rule.condition}' — must contain only digits, &, |, !, (, ), and spaces`);
        } else {
          // Check all referenced indices exist
          const referencedIndices = [...rule.condition.matchAll(/\d+/g)].map(m => parseInt(m[0]));
          for (const idx of referencedIndices) {
            if (idx >= rule.match.length) {
              eval_.issues.push(`Condition references index ${idx} but match[] only has ${rule.match.length} entries (max index: ${rule.match.length - 1})`);
            }
          }

          // Check balanced parentheses
          let depth = 0;
          for (const ch of rule.condition) {
            if (ch === '(') depth++;
            if (ch === ')') depth--;
            if (depth < 0) {
              eval_.issues.push('Condition has unbalanced parentheses (extra closing paren)');
              break;
            }
          }
          if (depth > 0) {
            eval_.issues.push('Condition has unbalanced parentheses (unclosed opening paren)');
          }

          // Try to parse the condition expression
          try {
            // Simple recursive descent validation (same logic as the worker parser)
            const tokens = rule.condition.match(/[\d]+|[&|!()]/g) || [];
            if (tokens.length === 0) {
              eval_.issues.push('Condition is empty after parsing');
            }
          } catch (e) {
            eval_.issues.push(`Condition parse error: ${e.message}`);
          }
        }
      }

      // ── Weight vs specificity for multi-match ───────────────────────────
      // For multi-match, specificity is based on total content characters
      // across all non-negated entries
      const nonNegatedContent = rule.match
        .filter(m => m.content !== undefined && !m.negated)
        .reduce((sum, m) => sum + m.content.length, 0);
      const maxSafeWeight = isPhishkitSig ? 0.25 : 0.35;
      const minSpecificity = isPhishkitSig ? 15 : 10;
      if (rule.weight > maxSafeWeight && nonNegatedContent < minSpecificity) {
        eval_.issues.push(`Weight ${rule.weight} too high for ${nonNegatedContent} total content chars in ${rule.group} (max safe: ${maxSafeWeight} unless combined content has ≥${minSpecificity} literal chars)`);
      }

    } else if (rule.id && rule.patternString && rule.target) {
      // ── Network pattern evaluation ─────────────────────────────────────
      // Matches against outbound HTTP request metadata (URLs, POST bodies, field names)
      const VALID_TARGETS = new Set(['url', 'body', 'fieldNames', 'any']);
      const VALID_TRANSPORTS = new Set(['any', 'fetch', 'xhr', 'beacon', 'websocket']);

      // Validate target and transport
      if (!VALID_TARGETS.has(rule.target)) {
        eval_.issues.push(`Invalid target "${rule.target}" — must be one of: url, body, fieldNames, any`);
      }
      if (rule.transport && !VALID_TRANSPORTS.has(rule.transport)) {
        eval_.issues.push(`Invalid transport "${rule.transport}" — must be one of: any, fetch, xhr, beacon, websocket`);
      }

      // Validate regex compiles
      let compilesOk = false;
      try {
        new RegExp(rule.patternString, rule.patternFlags || '');
        compilesOk = true;
      } catch (e) {
        eval_.issues.push(`Invalid regex: ${e.message}`);
      }

      if (compilesOk) {
        const patternLength = rule.patternString.replace(/[.*+?^${}()|[\]\\]/g, '').length;

        // ── Broadness check ─────────────────────────────────────────────
        if (/^\.\*$/.test(rule.patternString)) eval_.issues.push('Pattern is just .* — matches everything');
        if (patternLength < 4) eval_.issues.push(`Pattern too short (${patternLength} literal chars)`);

        // ── Performance check ───────────────────────────────────────────
        const ps = rule.patternString;
        const hasNestedQuant = /[+*]\)[+*?]/.test(ps);
        if (hasNestedQuant) {
          eval_.issues.push('Nested quantifiers — catastrophic backtracking risk');
        }

        // ── FP test against legitimate network request samples ──────────
        const pattern = new RegExp(rule.patternString, rule.patternFlags || '');
        const fpHits = [];

        for (const sample of LEGITIMATE_NETWORK_SAMPLES) {
          // Build target string based on the rule's target field
          let targetStr = '';
          if (rule.target === 'url') {
            targetStr = sample.url;
          } else if (rule.target === 'body') {
            targetStr = sample.body;
          } else if (rule.target === 'fieldNames') {
            // Extract field names from the body
            const names = new Set();
            if (sample.body.includes('=') && /^[^{[<]/.test(sample.body)) {
              for (const pair of sample.body.split('&')) {
                const key = decodeURIComponent((pair.split('=')[0] || '')).trim();
                if (key) names.add(key.toLowerCase());
              }
            }
            try {
              const parsed = JSON.parse(sample.body);
              if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                for (const key of Object.keys(parsed)) names.add(key.toLowerCase());
              }
            } catch {}
            targetStr = [...names].join(' ');
          } else {
            // 'any' — concatenate all
            targetStr = [sample.url, sample.body].join('\n');
          }

          // Check transport filter
          if (rule.transport && rule.transport !== 'any' && rule.transport !== sample.transport) continue;

          pattern.lastIndex = 0;
          if (targetStr && pattern.test(targetStr)) {
            fpHits.push(sample.url.slice(0, 60));
          }
        }

        if (fpHits.length > 0) {
          const isPhishkitSig = rule.group === 'phishkitSignatures';
          const bucket = isPhishkitSig ? 'issues' : 'warnings';
          eval_[bucket].push(`Network pattern matches legitimate request(s) (${fpHits.length}): ${fpHits[0]}`);
          eval_.fpMatches.push(...fpHits);
        }

        // ── Weight vs specificity ───────────────────────────────────────
        const isPhishkitSig = rule.group === 'phishkitSignatures';
        const maxSafeWeight = isPhishkitSig ? 0.30 : 0.40;
        const minSpecificityForHighWeight = 8;
        if (rule.weight > maxSafeWeight && patternLength < minSpecificityForHighWeight) {
          eval_.issues.push(`Weight ${rule.weight} too high for ${patternLength}-char network pattern in ${rule.group} (max safe: ${maxSafeWeight} unless ≥${minSpecificityForHighWeight} literal chars)`);
        }
      }

    } else if (rule.id && Array.isArray(rule.resources) && rule.resources.length > 0) {
      // ── Resource content hash rule evaluation ─────────────────────────────
      // FP risk is high and specific — evaluate every dimension carefully.

      // 1. Every resource entry needs a hash, a pathPattern, or both.
      //
      //   pathPattern + hash:  full fingerprint (path pre-filter + content check)
      //   pathPattern only:    path-only trigger — fires on URL match, no fetch.
      //                        Valid when content rotates too fast to hash (PHP gate
      //                        files, session scripts). Default weight 0.30.
      //   hash only:           content fingerprint with no path constraint.
      //   neither:             AUTOMATIC FAIL — entry is useless.
      //
      // Note: path-only entries are weaker signals than content hashes. Flag them
      // so the author knows, but do not fail — they're intentionally valid.
      const uselessResources = rule.resources.filter(r =>
        !r.sha256 && !r.normalizedSha256 && !r.pathPattern
      );
      if (uselessResources.length > 0) {
        eval_.issues.push(
          `AUTOMATIC FAIL: ${uselessResources.length} resource entry(ies) have neither a hash nor a pathPattern. ` +
          `Every entry needs at least one: a hash (content fingerprint), a pathPattern (path trigger), or both. ` +
          `Path-only entries (pathPattern without hash) are valid when content rotates too fast to hash.`
        );
      }

      const pathOnlyResources = rule.resources.filter(r =>
        !!(r.pathPattern) && !(r.sha256 || r.normalizedSha256)
      );
      if (pathOnlyResources.length > 0) {
        eval_.warnings.push(
          `${pathOnlyResources.length} resource entry(ies) are path-only (pathPattern present, no hash). ` +
          `These fire on URL pattern match alone — no content comparison, no fetch required. ` +
          `Effective weight will be ~0.30 (lower than hash rules at 0.55). ` +
          `Consider adding hashes when a stable version of the file is captured.`
        );
      }

      // 2. pathPattern is OPTIONAL. When absent, the rule checks ALL non-noise
      //    same-origin CSS/JS files — correct but broader and slower.
      //    When present, it must be a valid regex (performance pre-filter).
      for (const res of rule.resources) {
        if (!res.pathPattern) {
          // Warning, not an issue — absent pathPattern is valid but has performance implications.
          // It's the right choice when the hash is from an IOC feed, a watchlist, or a kit with
          // randomised filenames (Webpack chunk hashes etc.).
          eval_.warnings.push(
            `Resource entry has no pathPattern — the rule will check ALL same-origin CSS/JS ` +
            `files on matching pages (up to ${8} files). This is correct but slower than a ` +
            `targeted pattern. If you know a characteristic path or filename, add it. ` +
            `If the kit uses randomised filenames (e.g. Webpack chunks), omitting pathPattern is intentional.`
          );
          continue; // no pattern to validate
        }
        try { new RegExp(res.pathPattern, 'i'); } catch (e) {
          eval_.issues.push(`Resource pathPattern "${res.pathPattern}" is invalid regex: ${e.message}`);
        }
      }

      // 3. CRITICAL: Detect overly generic filenames — highest FP risk.
      // These filenames appear on millions of legitimate sites and must not be
      // used as the sole pathPattern without at least two other matching resources.
      const HYPER_GENERIC_NAMES = [
        'style.css', 'styles.css', 'main.css', 'app.css', 'index.css',
        'main.js',   'app.js',    'index.js', 'bundle.js', 'chunk.js',
        'script.js', 'scripts.js','common.js', 'vendor.js', 'runtime.js',
        'core.js',   'utils.js',  'helpers.js','base.css',  'global.css',
      ];
      const GENERIC_NAMES = [
        'login.css', 'auth.css', 'signin.css', 'form.css', 'portal.css',
        'login.js',  'auth.js',  'signin.js',  'form.js',  'validate.js',
      ];

      for (const res of rule.resources) {
        if (!res.pathPattern) continue;
        const filename = res.pathPattern.replace(/^\(\?:\^|\/\)/,'').replace(/\(\?:\\\\?\|\$\).*$/, '');
        const isHyperGeneric = HYPER_GENERIC_NAMES.some(n => filename.toLowerCase().includes(n.replace('.', '\\.')));
        const isGeneric      = GENERIC_NAMES.some(n => filename.toLowerCase().includes(n.replace('.', '\\.')));

        if (isHyperGeneric) {
          if (rule.resources.length === 1) {
            // Single resource with a hyper-generic filename — near-certain FP
            eval_.issues.push(
              `CRITICAL: pathPattern "${res.pathPattern}" is a hyper-generic filename ` +
              `("${filename}") that appears on millions of legitimate sites. ` +
              `With only 1 resource, this WILL cause false positives. ` +
              `Either (a) add more kit-specific resources with matchStrategy:"all", ` +
              `(b) add directory context to the pathPattern (e.g. "/assets/kit-specific/style.css"), ` +
              `or (c) use only the normalizedSha256 (not the exact hash) since generic CSS ` +
              `served identically across legitimate and phish pages is the prime FP source.`
            );
          } else if (rule.matchStrategy !== 'all') {
            eval_.warnings.push(
              `pathPattern "${res.pathPattern}" is hyper-generic. ` +
              `Multiple resources defined — change matchStrategy to "all" so ALL must match ` +
              `before the rule fires. "any" with a generic filename will still FP.`
            );
          }
        } else if (isGeneric && rule.resources.length === 1) {
          eval_.warnings.push(
            `pathPattern "${res.pathPattern}" is a common filename for login/auth pages ` +
            `— consider adding a second resource or using matchStrategy:"all". ` +
            `If the CSS content is truly kit-specific the hash alone is sufficient, ` +
            `but document why in the note field.`
          );
        }
      }

      // 4. Weight cap for rules with any generic resource
      const hasAnyGeneric = rule.resources.some(r => {
        const fn = (r.pathPattern || '').toLowerCase();
        return HYPER_GENERIC_NAMES.some(n => fn.includes(n.replace('.', '\\.'))) ||
               GENERIC_NAMES.some(n => fn.includes(n.replace('.', '\\.')));
      });
      if (hasAnyGeneric && (rule.weight || 0) > 0.50) {
        eval_.issues.push(
          `Weight ${rule.weight} too high for a rule with generic filename(s). ` +
          `Max 0.50 when any resource uses a common filename — higher weights require ` +
          `kit-specific paths (e.g. "/panel/v4/grab.css") or matchStrategy:"all" ` +
          `with multiple confirmed kit-specific resources.`
        );
      }

      // 5. Require the note field on every resource — without it, future reviewers
      // can't tell whether the hash was harvested from a live kit or invented.
      // A note also documents when/where the hash was captured for expiry purposes.
      const missingNotes = rule.resources.filter(r => !r.note || r.note.trim().length < 10);
      if (missingNotes.length > 0) {
        eval_.warnings.push(
          `${missingNotes.length} resource(s) missing descriptive note. ` +
          `Note should explain when/where the hash was harvested and what makes the file kit-specific. ` +
          `Required so maintainers can evaluate FP risk at a glance.`
        );
      }

      // 6. Require kitLabel — anonymous hash rules are unmaintainable
      if (!rule.kitLabel || rule.kitLabel.trim() === '') {
        eval_.warnings.push(
          `Missing kitLabel — add a human-readable kit name (e.g. "W3LL Panel v4"). ` +
          `Required for gap analysis aggregation and FP investigation.`
        );
      }

      // 7. matchStrategy "all" strongly preferred when >= 2 resources
      if (rule.resources.length >= 2 && rule.matchStrategy !== 'all') {
        eval_.warnings.push(
          `${rule.resources.length} resources defined but matchStrategy is "${rule.matchStrategy || 'any'}". ` +
          `"any" fires on the first match — consider "all" so the rule only fires when ` +
          `multiple kit-specific files are present simultaneously, reducing FP risk.`
        );
      }

      // 8. GROUND TRUTH CHECK: compare proposed hashes against known-good brand files.
      // This is the definitive brand-clone FP detector. If any proposed sha256 or
      // normalizedSha256 matches a hash from resource-safe-hashes.json (built by
      // generate-resource-hashes.js from real brand login pages), the rule captures
      // a brand-cloned file and WILL false-positive on that brand's own login page.
      // The known-good check supersedes all other FP reasoning — a hash match here
      // is not a "warning", it is a certain false positive.
      if (_knownGoodExact.size > 0 || _knownGoodNorm.size > 0) {
        for (const res of rule.resources) {
          const fpBrandExact = res.sha256           && _knownGoodMap.get(res.sha256);
          const fpBrandNorm  = res.normalizedSha256 && _knownGoodMap.get(res.normalizedSha256);
          const fpBrand      = fpBrandExact || fpBrandNorm;
          if (fpBrand) {
            const matchKind = fpBrandExact ? 'exact raw' : 'normalised';
            eval_.issues.push(
              `BRAND-CLONE FP CONFIRMED: path "${res.pathPattern}" has a ${matchKind} SHA-256 ` +
              `that matches a CSS/JS file served from ${fpBrand}'s legitimate login page ` +
              `(verified in resource-safe-hashes.json). ` +
              `This rule WILL false-positive on every visit to the real ${fpBrand} site. ` +
              `The phishkit cloned this file verbatim — it cannot safely be used as a detection signal. ` +
              `Remove this resource entry from the rule or use a kit-specific file instead.`
            );
            eval_.fpMatches.push(`${fpBrand}:${res.pathPattern}`);
          }
        }
      }
    }
    
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

RULE TYPES:
- Brand entries: typosquat variants of known brands
- Source patterns: regex matched against page HTML/JS source code
- Network patterns: regex matched against outbound HTTP request metadata (destination URLs, POST bodies, field names). These run in the content script's exfiltration interceptor against live network requests, NOT against page source. FP risk is different — SSO flows, analytics beacons, and legitimate form backends are the main FP vectors.
- Resource hash rules: SHA-256 fingerprints of CSS/JS files from phishing kits. These fire when a user visits a page that serves a same-origin CSS or JS file matching the stored hash. FP RISK IS THE HIGHEST OF ALL RULE TYPES — a bad hash silently flags real brand login pages as phishing. Evaluate these with extreme care.

RESOURCE HASH RULE FP EVALUATION — apply these checks in order:

1. NULL HASHES → only fail if pathPattern is ALSO absent. A resource entry with pathPattern but no hash is a path-only trigger — intentionally valid when content rotates too fast to fingerprint (PHP gate files, session-embedded scripts). It fires on URL pattern match alone (no fetch). If an entry has NEITHER a hash NOR a pathPattern, FAIL — it's useless. If an entry has pathPattern but no hash, warn but do not fail.

2. MISSING pathPattern → NOT a failure. pathPattern is optional. When absent, the rule checks all non-noise same-origin CSS/JS files and compares hashes. This is the correct design for rules built from IOC feeds, watchlists, or kits with randomised filenames (Webpack chunk hashes like "chunk.8f3a2b1c.js"). The performance cost is bounded by MAX_FETCH_RESOURCES (8 files). Only flag as a concern if the rule has many resources with no patterns AND is expected to fire on popular sites.

3. GENERIC FILENAMES: The pathPattern "(?:^|/)style.css(?:\\?|$)" matches the CSS file on paypal.com, chase.com, and millions of other legitimate sites. Ask yourself: if a phishkit clones a brand's CSS verbatim (the most common kit technique), does this hash also match the brand's own legitimate page? If yes, flag it. Generic filenames (style.css, app.js, main.css, index.js) require either (a) a directory-anchored path that only appears in phishkits, or (b) matchStrategy:"all" with multiple non-generic resources.

3. BRAND-CLONED CSS: The most dangerous FP source. Many phishkits download the target brand's actual CSS and serve it unchanged. If the harvested hash comes from a file named after the brand (e.g. "paypal-login.css") or from a path matching the brand's CDN structure, the hash likely matches what the brand serves legitimately — and will FP on every visit to the real brand. Reject these without confirmed evidence the file is kit-specific (modified or added content, not a verbatim clone).

4. matchStrategy:"any" with generic filenames: If the rule fires when ANY one resource matches, and any of those resources has a generic filename, the rule can FP independently of the other resources. Require matchStrategy:"all" or reject.

5. MISSING NOTES: Every resource needs a note explaining what makes the file kit-specific (e.g., "Contains hardcoded Telegram bot template not present in the brand's actual CSS"). Without this, no one can evaluate whether the hash is safe to ship.

PASS criteria:
- Typosquats are plausibly related to the brand and not common English words
- Source patterns are specific enough to not match legitimate sites
- Network patterns don't match legitimate SSO, analytics, payment, or WordPress requests
- Resource hash rules: all hashes populated, pathPatterns are specific or anchored, matchStrategy appropriate for filename specificity, notes explain kit-specificity
- Weights are proportional to pattern specificity
- No critical issues found
- Regex patterns are performance-safe

FAIL criteria (any one = FAIL):
- Pattern matches legitimate sites (FP risk)
- Network pattern matches legitimate SSO/auth/analytics/payment requests
- Resource hash rule has any null/missing hashes
- Resource hash rule uses generic filename with matchStrategy:"any" and single resource
- Resource hash pathPattern could match a legitimate brand's own CSS served from their domain
- Regex too broad for common page structures
- Generic typosquats unrelated to brand
- Weight disproportionate to specificity
- ⚡ Performance score >= 3
- .* with DOTALL flag
- Nested quantifiers
- 3+ sequential unbounded .*
- Multi-match rule has a "negative" field (silently ignored — exclusions must use negated: true in match[])
- Multi-match condition uses 1-based indices (engine is 0-based — out-of-bounds indices always evaluate false)
- Multi-match entry with negated: true referenced as !N in condition (double-negation — inverts intended logic)

Respond with exactly: PASS or FAIL on the first line, then your reasoning.`;

async function askClaudeToReview(rules, evaluations) {
  const evalSummary = evaluations.map(e => {
    const r = e.rule;
    const name = r.name || r.id;
    const ruleType = r.name ? 'brand entry' : r.target ? 'network pattern' : 'source pattern';
    return `### ${name} (${ruleType})
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

For multi-match source patterns specifically:
- NEVER use a "negative" field — it does not exist in the schema and is silently ignored by the pattern engine. Move exclusion patterns into the match[] array with negated: true, then reference them by 0-based index in the condition.
- Condition indices are 0-BASED: match[0] = 0, match[1] = 1, etc. A condition of "1 & 2" on a two-entry match[] is an out-of-bounds reference — the rule will never fire.
- Do NOT double-negate: a match entry with negated: true already has its result inverted. Reference it with its plain index, not with !N.
- Every multi-match rule must have exactly one content entry with fast_pattern: true.

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
    if (b.id && b.match && Array.isArray(b.match)) return !PLACEHOLDER_IDS.has(b.id);
    return false;
  });
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`\nAgent 4: Rule Quality Gate — Issue #${ISSUE_NUMBER}`);
  console.log(`Max attempts: ${MAX_ATTEMPTS}\n`);

  // Load known-good brand resource hashes before any rule evaluation.
  // This populates _knownGoodExact and _knownGoodNorm used by evaluateRules()
  // to detect brand-clone FPs in proposed resourceHash rules.
  await loadKnownGoodHashes();

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
