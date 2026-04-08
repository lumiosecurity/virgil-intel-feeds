// Virgil for Outlook — Shared Utilities
// Link extraction, worker API client, and configuration.

var Virgil = (function () {
  'use strict';

  var WORKER_URL = 'https://virgil-telemetry.lumiosecurity.workers.dev';
  var VERSION = '1.0.0';

  // ── Link Extraction ──────────────────────────────────────────────────────

  // Domains that should never be flagged (Microsoft infrastructure, Virgil's own)
  var SKIP_DOMAINS = [
    'microsoft.com', 'office.com', 'outlook.com', 'live.com',
    'office365.com', 'microsoftonline.com', 'sharepoint.com',
    'onedrive.com', 'onenote.com', 'skype.com', 'linkedin.com',
    'bing.com', 'msn.com', 'windows.net', 'azure.com',
    'aka.ms', 'goo.gl', 'lumiosecurity.com',
    'protection.outlook.com', 'safelinks.protection.outlook.com',
  ];

  function extractLinksFromHtml(html) {
    var parser = new DOMParser();
    var doc = parser.parseFromString(html, 'text/html');
    var anchors = doc.querySelectorAll('a[href]');
    var links = [];
    var seen = {};

    for (var i = 0; i < anchors.length; i++) {
      var a = anchors[i];
      var href = a.getAttribute('href');
      if (!href) continue;

      // Skip non-http links
      if (/^(mailto:|tel:|#|javascript:|data:)/i.test(href)) continue;

      // Unwrap Safe Links (Microsoft ATP wraps URLs)
      href = unwrapSafeLinks(href);

      // Skip Microsoft internal domains
      var dominated = false;
      try {
        var hostname = new URL(href).hostname.toLowerCase();
        for (var j = 0; j < SKIP_DOMAINS.length; j++) {
          if (hostname === SKIP_DOMAINS[j] || hostname.endsWith('.' + SKIP_DOMAINS[j])) {
            dominated = true;
            break;
          }
        }
      } catch (e) { continue; }

      if (dominated) continue;

      // Dedup by URL
      if (seen[href]) continue;
      seen[href] = true;

      links.push({
        url: href,
        text: (a.textContent || '').trim().slice(0, 200),
        position: links.length,
      });
    }

    return links;
  }

  // Microsoft Defender Safe Links wraps URLs like:
  // https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Freal-url.com&...
  function unwrapSafeLinks(url) {
    try {
      var parsed = new URL(url);
      if (parsed.hostname.endsWith('safelinks.protection.outlook.com')) {
        var realUrl = parsed.searchParams.get('url');
        if (realUrl) return realUrl;
      }
    } catch (e) {}
    return url;
  }

  // ── Worker API ───────────────────────────────────────────────────────────

  function scanLinks(links, sender, subject) {
    return fetch(WORKER_URL + '/v1/scan-links', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        links: links,
        sender: sender || '',
        subject: subject || '',
        source: 'outlook-addin',
        version: VERSION,
      }),
    })
    .then(function (resp) {
      if (!resp.ok) throw new Error('Worker returned ' + resp.status);
      return resp.json();
    })
    .then(function (data) {
      return data.results || [];
    });
  }

  // Post email context for behavioral bridge with Chrome extension
  function postEmailContext(urls, sender, subject) {
    if (!urls.length) return Promise.resolve();
    return fetch(WORKER_URL + '/v1/email-context', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        urls: urls,
        context: 'email-flagged',
        sender: sender,
        subject: subject,
        flaggedAt: new Date().toISOString(),
      }),
    }).catch(function () {}); // Best-effort, don't fail scan
  }

  // ── Verdict Classification ───────────────────────────────────────────────

  function classifyResult(result) {
    if (!result) return 'safe';
    var score = result.riskScore || 0;
    if (score >= 0.50 || result.verdict === 'dangerous') return 'dangerous';
    if (score >= 0.15 || result.verdict === 'suspicious') return 'suspicious';
    return 'safe';
  }

  function getSeverityColor(verdict) {
    if (verdict === 'dangerous') return '#ef4444';
    if (verdict === 'suspicious') return '#f97316';
    return '#22c55e';
  }

  function getSeverityLabel(verdict) {
    if (verdict === 'dangerous') return 'DANGEROUS';
    if (verdict === 'suspicious') return 'SUSPICIOUS';
    return 'SAFE';
  }

  // ── Public API ───────────────────────────────────────────────────────────

  return {
    extractLinksFromHtml: extractLinksFromHtml,
    scanLinks: scanLinks,
    postEmailContext: postEmailContext,
    classifyResult: classifyResult,
    getSeverityColor: getSeverityColor,
    getSeverityLabel: getSeverityLabel,
    WORKER_URL: WORKER_URL,
    VERSION: VERSION,
  };
})();
