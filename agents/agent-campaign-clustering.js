#!/usr/bin/env node
// Virgil — Campaign Clustering Agent (Agent 2)
//
// Runs nightly. Queries the telemetry corpus for recently seen phishing
// pages, clusters them by signal profile similarity, identifies shared
// infrastructure, and writes campaign briefs + proposed core-rules entries.
//
// Trigger: GitHub Actions cron (nightly 03:00 UTC)
// Output:  GitHub issue per discovered campaign in core-rules repo

import { cfg, d1, claude, github, getCTAge } from './agent-tools.js';

const LOOKBACK_DAYS = parseInt(process.env.LOOKBACK_DAYS || '3');
const MIN_CLUSTER   = parseInt(process.env.MIN_CLUSTER   || '3');  // min domains per campaign
const DRY_RUN       = process.argv.includes('--dry-run');

async function main() {
  console.log(`\nAgent 2: Campaign Clustering`);
  console.log(`Lookback: ${LOOKBACK_DAYS} days, min cluster: ${MIN_CLUSTER}, dry-run: ${DRY_RUN}`);

  // ── Load recent dangerous verdicts with signal profiles ────────────────────
  console.log('Loading recent corpus...');

  const verdicts = d1(`
    SELECT
      v.id, v.registered_domain, v.tld, v.detected_brand, v.detected_vertical,
      v.confidence, v.has_password_form, v.has_sensitive_form,
      v.external_form_submit, v.phishkit_signal_count,
      v.created_at,
      GROUP_CONCAT(s.type) as signal_types,
      GROUP_CONCAT(pk.signal_id) as phishkit_ids
    FROM verdicts v
    LEFT JOIN signals s ON s.verdict_id = v.id
    LEFT JOIN phishkit_signals pk ON pk.verdict_id = v.id
    WHERE v.risk_level = 'dangerous'
      AND v.created_at >= datetime('now', '-${LOOKBACK_DAYS} days')
      AND v.registered_domain IS NOT NULL
    GROUP BY v.id
    ORDER BY v.created_at DESC
    LIMIT 500
  `);

  if (verdicts.length === 0) {
    console.log('No recent dangerous verdicts — nothing to cluster');
    process.exit(0);
  }

  console.log(`Loaded ${verdicts.length} verdicts`);

  // Also load ingested feed data for the same period
  const ingested = d1(`
    SELECT
      iu.registered_domain, iu.tld, iu.detected_brand, iu.risk_score,
      GROUP_CONCAT(is2.type) as signal_types
    FROM ingested_urls iu
    LEFT JOIN ingested_signals is2 ON is2.ingest_id = iu.id
    WHERE iu.risk_score >= 0.70
      AND iu.ingested_at >= datetime('now', '-${LOOKBACK_DAYS} days')
      AND iu.registered_domain IS NOT NULL
    GROUP BY iu.id
    LIMIT 300
  `);

  console.log(`Loaded ${ingested.length} ingested URLs`);

  // ── Build signal fingerprint per domain ────────────────────────────────────
  // A fingerprint is a sorted set of signal types + key attributes.
  // Domains with identical/highly overlapping fingerprints are clustered.

  const domainMap = new Map(); // registeredDomain → aggregated profile

  for (const v of verdicts) {
    if (!domainMap.has(v.registered_domain)) {
      domainMap.set(v.registered_domain, {
        domain:       v.registered_domain,
        tld:          v.tld,
        brand:        v.detected_brand,
        vertical:     v.detected_vertical,
        signalTypes:  new Set(),
        phishkitIds:  new Set(),
        hasPassForm:  false,
        hasSensForm:  false,
        hasExtSubmit: false,
        count:        0,
        sources:      ['corpus'],
      });
    }
    const p = domainMap.get(v.registered_domain);
    p.count++;
    p.hasPassForm  = p.hasPassForm  || !!v.has_password_form;
    p.hasSensForm  = p.hasSensForm  || !!v.has_sensitive_form;
    p.hasExtSubmit = p.hasExtSubmit || !!v.external_form_submit;
    (v.signal_types   || '').split(',').filter(Boolean).forEach(s => p.signalTypes.add(s));
    (v.phishkit_ids   || '').split(',').filter(Boolean).forEach(s => p.phishkitIds.add(s));
  }

  for (const i of ingested) {
    if (!domainMap.has(i.registered_domain)) {
      domainMap.set(i.registered_domain, {
        domain:       i.registered_domain,
        tld:          i.tld,
        brand:        i.detected_brand,
        vertical:     null,
        signalTypes:  new Set(),
        phishkitIds:  new Set(),
        hasPassForm:  false, hasSensForm: false, hasExtSubmit: false,
        count:        1,
        sources:      ['feed'],
      });
    } else {
      domainMap.get(i.registered_domain).sources.push('feed');
    }
    const p = domainMap.get(i.registered_domain);
    (i.signal_types || '').split(',').filter(Boolean).forEach(s => p.signalTypes.add(s));
  }

  const profiles = [...domainMap.values()].map(p => ({
    ...p,
    fingerprint: [...p.signalTypes].sort().join('|'),
    phishkitFingerprint: [...p.phishkitIds].sort().join('|'),
  }));

  // ── Cluster by fingerprint similarity ─────────────────────────────────────
  const clusters = [];
  const assigned = new Set();

  // Primary clustering: identical signal fingerprint
  const byFingerprint = new Map();
  for (const p of profiles) {
    if (!p.fingerprint) continue;
    if (!byFingerprint.has(p.fingerprint)) byFingerprint.set(p.fingerprint, []);
    byFingerprint.get(p.fingerprint).push(p);
  }

  for (const [fp, members] of byFingerprint) {
    if (members.length < MIN_CLUSTER) continue;
    clusters.push({ type: 'signal-fingerprint', fingerprint: fp, members });
    members.forEach(m => assigned.add(m.domain));
  }

  // Secondary: group by brand + tld pattern for unassigned domains
  const byBrandTld = new Map();
  for (const p of profiles) {
    if (assigned.has(p.domain) || !p.brand || !p.tld) continue;
    const key = `${p.brand}|${p.tld}`;
    if (!byBrandTld.has(key)) byBrandTld.set(key, []);
    byBrandTld.get(key).push(p);
  }

  for (const [key, members] of byBrandTld) {
    if (members.length < MIN_CLUSTER) continue;
    clusters.push({ type: 'brand-tld', key, members });
    members.forEach(m => assigned.add(m.domain));
  }

  // Tertiary: group by phishkit fingerprint for remainder
  const byPhishkit = new Map();
  for (const p of profiles) {
    if (assigned.has(p.domain) || !p.phishkitFingerprint) continue;
    if (!byPhishkit.has(p.phishkitFingerprint)) byPhishkit.set(p.phishkitFingerprint, []);
    byPhishkit.get(p.phishkitFingerprint).push(p);
  }

  for (const [fp, members] of byPhishkit) {
    if (members.length < MIN_CLUSTER) continue;
    clusters.push({ type: 'phishkit-signature', fingerprint: fp, members });
  }

  console.log(`Found ${clusters.length} clusters`);

  if (clusters.length === 0) {
    console.log('No clusters meet minimum size — nothing to report');
    process.exit(0);
  }

  // ── Process each cluster ───────────────────────────────────────────────────
  for (const [idx, cluster] of clusters.entries()) {
    console.log(`\nProcessing cluster ${idx+1}/${clusters.length} (${cluster.members.length} domains, type: ${cluster.type})`);
    await processCluster(cluster, idx + 1);
    // Rate limit — don't hammer Claude
    if (idx < clusters.length - 1) await sleep(2000);
  }

  console.log('\n✓ Campaign clustering complete');
}

async function processCluster(cluster, clusterNum) {
  const { members } = cluster;
  const brands    = [...new Set(members.map(m => m.brand).filter(Boolean))];
  const tlds      = [...new Set(members.map(m => m.tld).filter(Boolean))];
  const domains   = members.map(m => m.domain).slice(0, 20);

  // Sample CT ages for a few domains
  const ctSample = await Promise.all(
    domains.slice(0, 5).map(d => getCTAge(d).then(r => ({ domain: d, ...r })).catch(() => ({ domain: d })))
  );

  // Check if we've already filed an issue for this cluster recently
  const clusterKey = `campaign-${cluster.type}-${cluster.fingerprint || cluster.key || clusterNum}`.slice(0, 80);

  // Ask Claude to write campaign brief + proposed rule
  const systemPrompt = `You are Virgil's campaign analysis agent. You identify phishing campaign patterns from clusters of similar domains and write concise threat intelligence briefs with actionable detection rules. Be factual, cite domain examples, and focus on what makes this campaign distinctive for detection purposes.`;

  const allSignals = [...new Set(members.flatMap(m => [...m.signalTypes]))];
  const allPhishkit= [...new Set(members.flatMap(m => [...m.phishkitIds]))];

  const userContent = `
## Campaign Cluster Analysis Request

**Cluster type:** ${cluster.type}
**Domain count:** ${members.length}
**Target brands:** ${brands.join(', ') || 'unknown'}
**TLDs used:** ${tlds.join(', ')}

**Sample domains (first 15):**
${domains.slice(0,15).map(d => `- ${d}`).join('\n')}

**Common signal types across all domains:**
${allSignals.map(s => `- ${s}`).join('\n') || '(none)'}

**Phishkit signatures present:**
${allPhishkit.map(s => `- ${s}`).join('\n') || '(none)'}

**Domain age sample:**
${ctSample.map(c => `- ${c.domain}: ${c.ageDays ? c.ageDays + ' days old' : 'unknown'}`).join('\n')}

**Infrastructure stats:**
- Domains with password forms: ${members.filter(m => m.hasPassForm).length}/${members.length}
- Domains with external form submit: ${members.filter(m => m.hasExtSubmit).length}/${members.length}
- Sources: corpus reports + feed ingestion

## Your task

Write a campaign brief with these sections:

### Campaign Summary
2-3 sentences: what brand(s) are being impersonated, what technique is being used, what makes this cluster distinctive.

### Campaign Tags
A comma-separated list of 3-5 tags (e.g. brand-name, technique, vertical).

### Proposed Rule (JSON)
A valid Virgil core-rules JSON entry that would catch this campaign. Include at minimum:
- One brand entry with typosquat patterns extracted from the domain list
- OR one source pattern if a phishkit signature is present
Use this exact schema:
\`\`\`json
{
  "_meta": {
    "schemaVersion": "1.0",
    "submittedAt": "${new Date().toISOString()}",
    "confidence": "high|medium",
    "campaignTags": [],
    "verticals": ["financial|crypto|sso|ecommerce|general"],
    "ruleType": "domain|source|combined",
    "coreRule": true,
    "author": "campaign-agent"
  },
  "summary": "...",
  "domainRules": {
    "brandEntries": [{ "name": "...", "vertical": "...", "domains": [], "typos": [] }]
  }
}
\`\`\`

### Detection Coverage
How many of the ${members.length} cluster domains would this rule catch?

### False Positive Risk
Low / Medium / High — and why.`;

  const brief = await claude(systemPrompt, userContent, 2000);

  // Extract proposed rule JSON from response
  const ruleMatch = brief.match(/```json\n([\s\S]*?)\n```/);
  let proposedRule = null;
  if (ruleMatch) {
    try { proposedRule = JSON.parse(ruleMatch[1]); } catch {}
  }

  // Build issue body
  const issueBody = `## 🤖 Campaign Cluster Detected

**Cluster type:** \`${cluster.type}\`
**Domains in cluster:** ${members.length}
**Lookback window:** ${LOOKBACK_DAYS} days

---

${brief}

---

## Sample domains
${domains.slice(0,15).map(d => `- \`${d}\``).join('\n')}

---

## Action required

A maintainer should:
1. Review the proposed rule above
2. If valid, add it to [\`core-rules\`](https://github.com/${cfg.orgName}/${cfg.coreRulesRepo}) as a new file
3. Run \`node tools/compile-feeds.js\` and trigger the Publish Detection Config workflow

---
*Generated by Virgil Campaign Clustering Agent at ${new Date().toISOString()}*
*Cluster key: \`${clusterKey}\`*`;

  const tagLines = brands.length > 0 ? `[${brands.join('/')}]` : '[unknown]';
  const issueTitle = `[CAMPAIGN] ${tagLines} — ${members.length} domains, type: ${cluster.type}`;

  if (DRY_RUN) {
    console.log(`  [dry-run] Would create issue: "${issueTitle}"`);
    console.log(`  Brief preview:\n${brief.slice(0, 300)}...`);
  } else {
    const issue = await github.createIssue(
      cfg.coreRulesRepo,
      issueTitle,
      issueBody,
      ['campaign-cluster', 'needs-triage', ...(brands.length > 0 ? [`brand:${brands[0]}`] : [])]
    );
    console.log(`  ✓ Created issue #${issue?.number}: ${issueTitle}`);
  }
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
