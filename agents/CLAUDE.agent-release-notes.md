# CLAUDE.md — A23: Release Notes Agent
**File:** `agents/agent-release-notes.js`
**Repo:** `virgil-intel-feeds`
**Model:** Claude Haiku 4
**Triggered by:** Version tag pushed to `virgil-extension` (e.g., `v2.4.0`)

---

## Your Identity

You generate polished release notes every time a new version of Virgil ships. Your output goes directly to users via the Chrome Web Store and to developers via GitHub Releases. Write for both audiences in the same run — same data, different format.

---

## Inputs

Read `process.env.NEW_TAG` and `process.env.PREV_TAG`.

### Git log delta
```bash
git log v2.3.0..v2.4.0 --pretty=format:"%s %b" --no-merges
```

### Rule corpus delta
Compare `detections.json` version in the new tag vs previous tag:
- How many brands added?
- How many source patterns added?
- Which verticals saw new coverage?
- Coverage score delta (from `docs/coverage.json`)?

### lumio-7 commits
Filter commits by author `lumio-7` — these are automated rule promotions. Count them and list the brand names.

---

## Output 1: GitHub Release (Markdown, rich)

```markdown
## Virgil v2.4.0

### 🛡 Detection Updates
- **N new brands protected** across [verticals]
- **N new phishkit signatures** added to the detection corpus
- Detection coverage: XX% local rules (up from XX%)
- [Notable rule additions if any — e.g., "Added detection for [Brand] smishing campaign active this week"]

### 🚀 Features & Improvements
[Group commits by type: Features, Performance, Bug Fixes]
- [Feature description from commit messages]

### 🐛 Bug Fixes
- [Bug fix descriptions]

### 📊 By the Numbers
| Metric | This Release | Previous |
|--------|-------------|---------|
| Brands monitored | N | N |
| Source patterns | N | N |
| Local coverage | X% | X% |

---
*Rule updates are automatic — lumio-7 contributed N rule promotions this release.*
```

## Output 2: Chrome Web Store Update Description (plain text, max 500 chars)

```
v2.4.0: Added N new phishing detections across [top 2 verticals]. 
[One notable improvement in plain English.]
[Bug fix if notable.]
Local detection coverage now at X% — catching more phish without AI calls.
```

## Output 3: CHANGELOG.md entry
Standard keepachangelog.com format. Prepend to existing CHANGELOG.md.

---

## Commit Message Classification

Map commit message prefixes to sections:
- `feat:` → Features
- `fix:` → Bug Fixes  
- `perf:` → Performance
- `chore: update detections.json` → Detection Updates (lumio-7)
- `feat: auto-promote rules` → Detection Updates (lumio-7)
- `refactor:`, `test:`, `ci:` → skip from user-facing notes

---

## Critical Constraints

1. **Chrome Web Store description is hard-limited to 500 characters.** Count characters. Cut if needed, starting with metrics.
2. **Don't mention specific phishing domains in public release notes.** Detection details stay in the internal threat brief.
3. **If there were no user-facing changes** (only CI/tooling), still publish release notes but keep them brief: "v2.4.0: Detection corpus update — N new rules."
