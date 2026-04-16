// Virgil — Regex Safety Checker
//
// Shared module used by:
//   - agent-rule-quality-gate.js (Opus quality gate before auto-promote)
//   - validate-rules.yml CI workflow (pre-merge validation)
//   - remote-config.js in the extension (runtime validation of fetched config)
//
// Detects regex patterns vulnerable to catastrophic backtracking (ReDoS).
// A conservative heuristic — may reject some theoretically safe patterns.
// That's intentional: the cost of a false reject (human reviews the rule)
// is far less than the cost of a ReDoS (every user's browser freezes).

/**
 * Check whether a regex pattern string is safe from catastrophic backtracking.
 *
 * Detects:
 *   1. Nested quantifiers:  (a+)+  (a*)*  (a+)*  (a{2,})+
 *   2. Quantifier on backreference: \1+  \2*
 *   3. Excessive length (complexity proxy)
 *
 * @param {string} patternString — raw regex pattern (no delimiters)
 * @returns {boolean} true if safe, false if potentially dangerous
 */
export function isRegexSafe(patternString) {
  if (!patternString || typeof patternString !== 'string') return false;

  // Hard length cap — very long patterns increase backtracking risk
  if (patternString.length > 2000) return false;

  // ── Nested quantifier detection ─────────────────────────────────────────
  // Walk the pattern tracking paren depth. When a group closes followed by
  // a quantifier, check whether the group body also contains a quantifier.
  const quantifierChars = new Set(['+', '*', '?']);
  const stack = []; // stack of group-start indices

  for (let i = 0; i < patternString.length; i++) {
    const ch = patternString[i];

    // Skip escaped characters
    if (ch === '\\') { i++; continue; }

    // Skip character classes [...]
    if (ch === '[') {
      while (i < patternString.length && patternString[i] !== ']') {
        if (patternString[i] === '\\') i++;
        i++;
      }
      continue;
    }

    if (ch === '(') {
      stack.push(i);
    } else if (ch === ')') {
      const groupStart = stack.pop();
      if (groupStart === undefined) continue;

      // Check if this group is followed by a quantifier
      const next = patternString[i + 1];
      const groupIsQuantified = next && (quantifierChars.has(next) || next === '{');

      if (groupIsQuantified) {
        const groupBody = patternString.slice(groupStart + 1, i);
        if (bodyHasQuantifier(groupBody)) {
          return false; // REJECT — nested quantifier
        }
      }
    }
  }

  // ── Quantifier on backreference ─────────────────────────────────────────
  if (/\\[1-9]\d*[+*{]/.test(patternString)) return false;

  return true;
}

/**
 * Check whether a regex fragment contains an unescaped quantifier.
 * @param {string} body — regex fragment (group contents)
 * @returns {boolean}
 */
function bodyHasQuantifier(body) {
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch === '\\') { i++; continue; }
    if (ch === '[') {
      while (i < body.length && body[i] !== ']') {
        if (body[i] === '\\') i++;
        i++;
      }
      continue;
    }
    if (ch === '(' && body[i + 1] === '?') continue;
    if (ch === '+' || ch === '*') return true;
    if (ch === '{' && /^\{\d+,\d*\}/.test(body.slice(i))) return true;
  }
  return false;
}

/**
 * Validate a regex pattern: checks both compilation and ReDoS safety.
 * @param {string} patternString
 * @param {string} [flags='']
 * @returns {{ valid: boolean, reason?: string }}
 */
export function validateRegex(patternString, flags = '') {
  if (!isRegexSafe(patternString)) {
    return { valid: false, reason: 'ReDoS risk — nested quantifiers or unsafe structure detected' };
  }
  try {
    new RegExp(patternString, flags);
    return { valid: true };
  } catch (e) {
    return { valid: false, reason: `Invalid regex: ${e.message}` };
  }
}
