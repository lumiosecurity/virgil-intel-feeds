# Virgil Intel Feeds

Automated threat intelligence feeds for the Virgil extension, synced from [Sublime Security's static-files](https://github.com/sublime-security/static-files).

## Contents

All files live in `feeds/`. One JSON file per source list, plus `compiled.json` which merges everything into the single runtime file consumed by the extension.

| Feed | Source | Role in Virgil |
|------|--------|--------------------|
| `suspicious_tlds.json` | `suspicious_tlds.txt` | Replaces/augments `TLD_RISK` in `domain-analyzer.js` |
| `free_subdomain_hosts.json` | `free_subdomain_hosts.txt` | Signal: brand impersonation via free subdomain host |
| `free_file_hosts.json` | `free_file_hosts.txt` | Signal: phishing page served from free file host |
| `url_shorteners.json` | `url_shorteners.txt` | Signal: redirect chain through URL shortener |
| `disposable_email_providers.json` | `disposable_email_providers.txt` | Signal: form POSTs to disposable email domain |
| `free_email_providers.json` | `free_email_providers.txt` | Context: free email as credential destination |
| `suspicious_content.json` | `suspicious_content.txt` | Augments DOM visible text analysis |
| `suspicious_subjects.json` | `suspicious_subjects.txt` | Augments page heading/title analysis |
| `suspicious_subjects_regex.json` | `suspicious_subjects_regex.txt` | Direct regex use in `phishkit-detector.js` |
| `file_extensions_macros.json` | `file_extensions_macros.txt` | Signal: macro file download links on credential pages |
| `file_extensions_common_archives.json` | `file_extensions_common_archives.txt` | Signal: archive download links |
| `compiled.json` | All of the above | **Runtime file loaded by the extension** |

## Sync schedule

Runs every Monday at 06:00 UTC via GitHub Actions. Also triggerable manually from the Actions tab.

## Manual sync

```bash
npm install
node scripts/sync-sublime.js                    # sync all
node scripts/sync-sublime.js suspicious_tlds    # sync one
node scripts/sync-sublime.js --dry-run          # preview changes
GITHUB_TOKEN=ghp_... node scripts/sync-sublime.js  # higher rate limit
```

## Attribution

All feed data originates from [sublime-security/static-files](https://github.com/sublime-security/static-files), maintained by [Sublime Security](https://sublime.security) and released under their license.
