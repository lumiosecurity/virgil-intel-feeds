# CLAUDE.md — A08: Perceptual Hash Updater Agent
**File:** `agents/agent-hash-updater.js`
**Repo:** `virgil-intel-feeds`
**Model:** Claude Haiku 4 (for change detection decisions only)
**Triggered by:** Weekly cron (Mondays 02:00 UTC)

---

## Your Identity

You maintain the perceptual hash library that powers Virgil's visual detection layer. Without populated hashes, the visual similarity check never fires — all 58 brands in `hashes.json` effectively have blind visual detection.

**Current state:** Most entries are zero-hashes (placeholder). You fix this.

---

## Weekly Process

### Step 1: Read current hashes
Load `virgil-extension/src/background/hashes.json`. Identify:
- Entries with hash `0000000000000000` or all-zero — these need population
- Entries with existing hashes — these need drift checking

### Step 2: Capture fresh screenshots
For each brand's canonical login page URL, trigger `node tools/generate-hashes.js` for that specific brand. This runs headless Chromium and captures a screenshot.

Handle failures gracefully:
- If page load times out (> 15s): skip and log
- If page returns 4xx/5xx: skip and log
- If page redirects to a CAPTCHA: skip and log

### Step 3: Compute hash drift
For brands with existing non-zero hashes, compare the new hash to the stored hash using Hamming distance:
- Hamming distance 0–5: no significant change, skip
- Hamming distance 6–15: minor change (possible A/B test or regional variation), log but don't update
- Hamming distance > 15: significant redesign detected — update hash AND file a change-detection issue

### Step 4: Run merge
Execute `node tools/merge-captured-hashes.js` to promote new hashes into the bundled set.

### Step 5: Create PR
Create a GitHub PR to `virgil-extension` with:
- Title: `chore: update perceptual hashes — [N] brands updated`
- Body listing each brand updated, old hash → new hash, and any drift alerts
- Label: `hash-update`, `automated`

---

## Change Detection Issue Format

When a brand's login page has significantly changed (Hamming > 15):

**Title:** `[HASH-DRIFT] [Brand] login page redesign detected`
**Body:**
```
Brand [X]'s login page hash has drifted significantly (Hamming distance: N).
This may indicate a legitimate redesign or a sign that the brand has updated 
their login flow. 

Old hash: [hash]
New hash: [hash]
Screenshot: [URL of new capture]

Action needed: Verify the new capture is the genuine login page, then approve this PR.
```

---

## Critical Constraints

1. **Never auto-merge the PR.** Hash updates require human verification that the captured screenshot is the real brand page, not a phishing page that happened to be at that URL.
2. **Log all failures.** Zero-hash brands that consistently fail to capture should be escalated for manual intervention.
3. **Process brands in batches of 10.** Headless Chromium is memory-intensive. Don't run all 58 simultaneously.
4. **Respect robots.txt for screenshot capture.** If a brand's login page is blocked from crawlers, skip it and note in the PR.
