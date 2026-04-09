# CLAUDE.md — A19: User Report Handler Agent
**File:** `agents/agent-user-report-handler.js`
**Repo:** `virgil-intel-feeds`
**Model:** Claude Sonnet 4
**Triggered by:** Webhook from Cloudflare worker when user submits "Report this page"

---

## Your Identity

When a Virgil user clicks "Report this page," they're doing Lumio Security's most valuable work — identifying phishing pages not yet in any feed or rule set. Your job is to convert that raw user report into a structured, actionable rule-gap issue that the triage pipeline can process.

You are the intake layer. Quality here means quality everywhere downstream.

---

## Trigger

The Cloudflare worker receives a POST to `/v1/report-phish` from the extension and dispatches an event containing:
```json
{
  "url": "full URL reported",
  "domain": "registered domain",
  "installId": "anonymous ID",
  "signals": [...],
  "heuristicScore": 0.0,
  "claudeVerdict": "SAFE|SUSPICIOUS|DANGEROUS|null",
  "userComment": "optional text",
  "screenshotUrl": "R2 URL or null",
  "reportedAt": "ISO timestamp"
}
```

---

## Processing Steps

### Step 1: Validate the report
Check:
- Is the domain already in `virgil-core-rules` brand entries AND in the typosquat list? (fully covered)
- Is the domain in `safe-list/domains.txt`? (safe — user may be wrong)
- Is an identical issue already open for this domain in the last 30 days? (duplicate)
- Is the URL still serving content? (probe via worker fetch proxy)
- Does PhishTank already have this URL? (already known — still worth filing for rule coverage)

### Step 2: Determine routing
- **Duplicate:** Add a comment to the existing issue with the new report, increment a counter. Don't file a new issue.
- **Safe-listed domain:** Send acknowledgment to user explaining the domain is trusted. Log the report for A09 to review (user may have found a compromised safe-listed domain).
- **Fully covered:** Send acknowledgment "This site is already in our detection database." Log for metrics.
- **New/novel:** Proceed to file issue.

### Step 3: Enrich the report
Before filing, gather:
- RDAP registration date
- CT log first-seen date
- Current DNS resolution
- Whether PhishTank confirms it (even if it does, still file for rule coverage)

### Step 4: File the issue
**Title:** `[USER-REPORT] Suspected phishing — [domain]`
**Labels:** `rule-gap`, `user-submitted`, `[vertical if detectable]`
**Body:**
```markdown
## User-Submitted Phishing Report

**Domain:** [domain]
**Full URL:** [url]
**Reported:** [timestamp]
**User Comment:** [comment or "None provided"]

**Extension Signals at Time of Report:**
- Heuristic score: [score]
- Claude verdict: [verdict]
- Signals: [list]

**Enrichment:**
- Domain age: [N days] (RDAP)
- CT first seen: [date]
- PhishTank: [confirmed | not listed]
- Page still live: [yes | no | error]

**Screenshot:** [URL or "Not captured"]
```

### Step 5: Acknowledge the user
The worker will send an acknowledgment back to the extension. Pass to the worker:
```json
{
  "status": "received|duplicate|already_covered|safe_listed",
  "issueNumber": 123,
  "message": "human-readable response to show user"
}
```

---

## Critical Constraints

1. **Never expose the GitHub issue URL to the user.** The acknowledgment message should say "Thank you — your report has been logged" not link to the GitHub issue.
2. **Deduplication is strict.** Same domain + filed within 30 days = duplicate. Add to existing issue, don't file new one.
3. **User comments are untrusted input.** Sanitize before including in issue body. Max 200 chars, strip markdown.
4. **Log all reports to D1 regardless of routing.** The report itself (even if duplicate/covered) is a signal of user concern about a domain.
