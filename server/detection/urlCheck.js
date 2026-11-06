/**
 * Local and offline URL security checks.
 * 
 * Rules:
 * - Local-only heuristic inspection. NO external HTTP requests.
 * - Whitelist exemption: Official banking domains are never marked as brand lookalikes.
 * - Levenshtein distance implemented locally (no 3rd-party library).
 * - Parse failures marked as 'unavailable', never 'safe'.
 */

import { OFFICIAL_DOMAINS, MONITORED_BRANDS } from '../data/brands.js';

const SHORTENER_HOSTS = new Set([
  'bit.ly',
  'tinyurl.com',
  'cutt.ly',
  'rb.gy',
  't.me',
  'is.gd',
  'goo.gl'
]);

const SUSPICIOUS_TLDS = new Set([
  '.xyz',
  '.top',
  '.click',
  '.shop',
  '.loan',
  '.icu',
  '.work',
  '.vip',
  '.link'
]);

/**
 * Calculates Levenshtein distance between two strings without third-party dependencies.
 * @param {string} a 
 * @param {string} b 
 * @returns {number}
 */
export function levenshteinDistance(a, b) {
  if (a === b) return 0;
  if (!a) return b.length;
  if (!b) return a.length;

  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,      // deletion
        dp[i][j - 1] + 1,      // insertion
        dp[i - 1][j - 1] + cost // substitution
      );
    }
  }
  return dp[m][n];
}

/**
 * Extracts URL strings from text and optional explicit URL parameter.
 * @param {string} text 
 * @param {string} [explicitUrl]
 * @returns {string[]}
 */
export function extractUrls(text, explicitUrl) {
  const urls = new Set();
  
  if (explicitUrl && typeof explicitUrl === 'string' && explicitUrl.trim()) {
    const cleanExplicit = explicitUrl.trim().replace(/[.,;:!?)\]]+$/, '');
    if (cleanExplicit) {
      urls.add(cleanExplicit);
    }
  }

  if (text && typeof text === 'string') {
    // Matches URLs with scheme or domain-like formats (including bit.ly, t.me, .xyz, etc.)
    const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`]+|(?:bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|t\.me|[a-zA-Z0-9-]+\.(?:xyz|top|click|shop|loan|icu|com|in|co\.in|org|net|gov\.in))\b[^\s<>"']*/gi;
    let match;
    while ((match = urlRegex.exec(text)) !== null) {
      // Strip trailing punctuation from sentence boundaries so TLD and host matching are not corrupted
      const cleanUrl = match[0].replace(/[.,;:!?)\]]+$/, '');
      if (cleanUrl) {
        urls.add(cleanUrl);
      }
    }
  }

  return Array.from(urls);
}

/**
 * Tests if a hostname is an exact match or subdomain of an official whitelist domain.
 * @param {string} hostname
 * @returns {boolean}
 */
function isOfficialDomain(hostname) {
  const cleanHost = hostname.toLowerCase();
  return OFFICIAL_DOMAINS.some(official => cleanHost === official || cleanHost.endsWith('.' + official));
}

/**
 * Evaluates a single URL string and returns forensic evidence flags.
 * @param {string} rawUrl 
 * @returns {{ url: string, status: 'checked' | 'unavailable', flags: string[] }}
 */
function evaluateUrl(rawUrl) {
  const flags = [];
  let parsed;

  try {
    const withProto = /^https?:\/\//i.test(rawUrl) ? rawUrl : 'http://' + rawUrl;
    parsed = new URL(withProto);
  } catch {
    return { url: rawUrl, status: 'unavailable', flags: [] };
  }

  const hostname = parsed.hostname.toLowerCase();

  // 1. HTTP without HTTPS check
  if (parsed.protocol === 'http:') {
    flags.push('no_https');
  }

  // 2. '@' symbol in URL (credential masquerading trick)
  if (rawUrl.includes('@')) {
    flags.push('at_sign');
  }

  // 3. Raw IP Address as host
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.startsWith('[');
  if (isIp) {
    flags.push('ip_address');
  }

  // 4. Punycode detection
  if (hostname.includes('xn--')) {
    flags.push('punycode');
  }

  // 5. Shortened URL hosts
  if (SHORTENER_HOSTS.has(hostname) || Array.from(SHORTENER_HOSTS).some(s => hostname.endsWith('.' + s))) {
    flags.push('url_shortener');
  }

  // 6. Suspicious TLD check
  for (const tld of SUSPICIOUS_TLDS) {
    if (hostname.endsWith(tld)) {
      flags.push('suspicious_tld');
      break;
    }
  }

  // 7. Excessive hyphens in host
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    flags.push('many_hyphens');
  }

  // If host is on official whitelist, it is exempt from lookalike and typosquat flags
  const isWhitelisted = isOfficialDomain(hostname);
  if (!isWhitelisted && !isIp) {
    const domainLabels = hostname.split('.');

    // 8. Brand lookalike check (domain contains brand name outside official site)
    for (const brand of MONITORED_BRANDS) {
      if (hostname.includes(brand)) {
        flags.push('brand_lookalike');
        break;
      }
    }

    // 9. Typosquatting check via Levenshtein distance (distance 1 or 2 from known brand)
    for (const label of domainLabels) {
      for (const brand of MONITORED_BRANDS) {
        if (label !== brand) {
          const dist = levenshteinDistance(label, brand);
          if (dist >= 1 && dist <= 2 && label.length >= 3) {
            flags.push('typosquat');
            break;
          }
        }
      }
      if (flags.includes('typosquat')) break;
    }

    // 10. Homoglyph character substitutions (e.g. 0 for o, 1 for l/i, rn for m)
    const normalizedHomoglyphs = hostname
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/rn/g, 'm');

    if (normalizedHomoglyphs !== hostname) {
      for (const brand of MONITORED_BRANDS) {
        if (!hostname.includes(brand) && normalizedHomoglyphs.includes(brand)) {
          flags.push('homoglyph');
          break;
        }
      }
    }
  }

  return {
    url: rawUrl,
    status: 'checked',
    flags: Array.from(new Set(flags))
  };
}

/**
 * Scans message and explicit URL for forensic indicators.
 * @param {string} text 
 * @param {string} [url] 
 * @returns {{ urlEvidence: Array<{ url: string, status: string, flags: string[] }>, flags: string[] }}
 */
export function checkUrls(text, url) {
  const extracted = extractUrls(text, url);
  const urlEvidence = extracted.map(evaluateUrl);
  
  const allFlags = new Set();
  for (const item of urlEvidence) {
    for (const flag of item.flags) {
      allFlags.add(flag);
    }
  }

  return {
    urlEvidence,
    flags: Array.from(allFlags)
  };
}
