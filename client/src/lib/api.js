/**
 * Client API Layer for Satark Scammer Detector.
 * 
 * Rules & Invariants:
 * - Zero network calls to external origins; only talks to VITE_API_URL (/api/analyze).
 * - 12-second timeout boundary via AbortController.
 * - Never log raw submitted user messages, responses, or error details to console.
 * - Zero-trust validation of server payloads before consumption.
 * - Ignore server-provided officialLinks, always use local vetted allowlist.
 */

import { getOfficialLinks } from './officialLinks.js';

const API_BASE_URL = (import.meta.env?.VITE_API_URL || 'http://127.0.0.1:5000').replace(/\/+$/, '');

export const ERROR_MESSAGES = {
  invalid_input: {
    en: 'Enter a message (up to 2000 characters) or a URL (up to 2048 characters).',
    hinglish: 'Message (2000 characters tak) ya URL (2048 characters tak) dein.'
  },
  too_large: {
    en: 'Please check the message (1 to 2000 characters).',
    hinglish: 'Message bahut lamba hai (max 2000 characters).'
  },
  unsupported: {
    en: 'Unsupported request format. Please try again.',
    hinglish: 'Request format support nahi karta. Kripya dobara try karein.'
  },
  rate_limited: {
    en: 'Too many requests. Please wait a minute and try again.',
    hinglish: 'Bahut zyada requests aayi hain. Kripya ek minute baad dobara try karein.'
  },
  server_error: {
    en: 'Server error occurred. Please try again later.',
    hinglish: 'Server par error aayi. Kripya thodi der baad dobara try karein.'
  },
  network_error: {
    en: 'Could not reach the Satark server. Is it running?',
    hinglish: 'Satark server se connect nahi ho paya. Kya server chal raha hai?'
  },
  timeout: {
    en: 'Analysis timed out after 12 seconds. Please try again.',
    hinglish: 'Analysis mein 12 seconds se zyada waqt lag gaya. Kripya dobara try karein.'
  },
  bad_response: {
    en: 'Received an invalid response from server. Please try again.',
    hinglish: 'Server se galat response mila. Kripya dobara try karein.'
  }
};

const VALID_CATEGORIES = new Set([
  'Suspicious',
  'Caution',
  'No known red flags found'
]);

const VALID_LEDGER_STATUSES = new Set([
  'triggered',
  'not_triggered',
  'unavailable',
  'not_used'
]);

const RULE_ID_REGEX = /^[A-Z_]{2,40}$/;

/**
 * Validates and sanitizes server detection results against client expectations.
 * @param {any} data - Untrusted server response
 * @param {string} submittedText - Exact message string sent by user
 * @returns {object | 'bad_response'}
 */
export function validateResult(data, submittedText) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return 'bad_response';
  }

  // 1. Category validation
  if (!VALID_CATEGORIES.has(data.category)) {
    return 'bad_response';
  }

  // 2. Score validation (integer or float 0..100)
  if (typeof data.score !== 'number' || Number.isNaN(data.score) || data.score < 0 || data.score > 100) {
    return 'bad_response';
  }

  const textLength = typeof submittedText === 'string' ? submittedText.length : 0;

  // 3. Indicators validation (drop invalid ones individually)
  const validIndicators = [];
  if (Array.isArray(data.indicators)) {
    const rawIndicators = data.indicators.slice(0, 100);
    for (const item of rawIndicators) {
      if (!item || typeof item !== 'object') continue;
      const { ruleId, start, end, text } = item;

      if (typeof ruleId !== 'string' || !RULE_ID_REGEX.test(ruleId)) continue;
      if (!Number.isInteger(start) || !Number.isInteger(end)) continue;
      if (start < 0 || start >= end || end > textLength) continue;
      if (typeof text !== 'string' || text !== submittedText.slice(start, end)) continue;

      validIndicators.push({ ruleId, start, end, text });
    }
  }

  // 4. Ledger validation
  const validLedger = [];
  if (Array.isArray(data.ledger)) {
    const rawLedger = data.ledger.slice(0, 50);
    for (const item of rawLedger) {
      if (!item || typeof item !== 'object') continue;
      const check = typeof item.check === 'string' ? item.check.slice(0, 100) : 'Security Check';
      const status = VALID_LEDGER_STATUSES.has(item.status) ? item.status : 'not_used';
      validLedger.push({ check, status });
    }
  }

  // 5. Explanation validation
  const cleanExplanation = { en: [], hi: [], hinglish: [] };
  if (data.explanation && typeof data.explanation === 'object') {
    for (const key of ['en', 'hi', 'hinglish']) {
      if (Array.isArray(data.explanation[key])) {
        cleanExplanation[key] = data.explanation[key]
          .slice(0, 20)
          .filter(s => typeof s === 'string')
          .map(s => s.slice(0, 500));
      }
    }
  }

  // 6. Actions validation
  let cleanActions = [];
  if (Array.isArray(data.actions)) {
    cleanActions = data.actions
      .slice(0, 20)
      .filter(s => typeof s === 'string')
      .map(s => s.slice(0, 200));
  }

  // 7. URL evidence validation
  const cleanUrlEvidence = [];
  if (Array.isArray(data.urlEvidence)) {
    for (const ev of data.urlEvidence.slice(0, 20)) {
      if (!ev || typeof ev !== 'object') continue;
      const urlStr = typeof ev.url === 'string' ? ev.url.slice(0, 2048) : '';
      const flags = Array.isArray(ev.flags)
        ? ev.flags.filter(f => typeof f === 'string').map(f => f.slice(0, 50))
        : [];
      cleanUrlEvidence.push({ url: urlStr, flags, status: ev.status || 'checked' });
    }
  }

  // 8. Official Links: Ignore server-provided links completely; use local vetted allowlist
  const officialLinks = getOfficialLinks().map(l => l.url);

  return {
    category: data.category,
    score: data.score,
    detectedScript: typeof data.detectedScript === 'string' ? data.detectedScript : 'roman',
    indicators: validIndicators,
    ledger: validLedger,
    explanation: cleanExplanation,
    actions: cleanActions,
    urlEvidence: cleanUrlEvidence,
    officialLinks,
    disclaimer: typeof data.disclaimer === 'string' 
      ? data.disclaimer.slice(0, 200) 
      : 'Red-flag guidance, not a guarantee of safety.'
  };
}

/**
 * Sends a message analysis request to the backend with 12s timeout and zero-trust validation.
 * 
 * @param {{ text: string, url?: string }} payload 
 * @param {AbortSignal} [callerSignal]
 * @returns {Promise<{ ok: boolean, data?: object, error?: string }>}
 */
export async function analyze({ text, url }, callerSignal) {
  const timeoutMs = 12000;
  const controller = new AbortController();
  let isTimedOut = false;

  const timeoutId = setTimeout(() => {
    isTimedOut = true;
    controller.abort();
  }, timeoutMs);

  const handleCallerAbort = () => controller.abort();

  // Link caller signal for this request only; release the listener in finally.
  if (callerSignal) {
    if (callerSignal.aborted) {
      controller.abort();
    } else {
      callerSignal.addEventListener('abort', handleCallerAbort, { once: true });
    }
  }

  try {
    const requestBody = { text };
    if (typeof url === 'string' && url.trim().length > 0) {
      requestBody.url = url.trim();
    }
    // Invariant: Never send "lang" to API

    const response = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      body: JSON.stringify(requestBody),
      signal: controller.signal
    });

    if (response.status === 200) {
      let json;
      try {
        json = await response.json();
      } catch (err) {
        // The deadline also covers reading the body after headers arrive.
        if (isTimedOut || controller.signal.aborted || err?.name === 'AbortError') {
          return { ok: false, error: 'timeout' };
        }
        return { ok: false, error: 'bad_response' };
      }

      const validated = validateResult(json, text);
      if (validated === 'bad_response') {
        return { ok: false, error: 'bad_response' };
      }
      return { ok: true, data: validated };
    }

    if (response.status === 400) return { ok: false, error: 'invalid_input' };
    if (response.status === 413) return { ok: false, error: 'too_large' };
    if (response.status === 415) return { ok: false, error: 'unsupported' };
    if (response.status === 429) return { ok: false, error: 'rate_limited' };
    if (response.status >= 500 && response.status < 600) return { ok: false, error: 'server_error' };

    return { ok: false, error: 'bad_response' };
  } catch (err) {
    if (isTimedOut || controller.signal.aborted || err?.name === 'AbortError') {
      return { ok: false, error: 'timeout' };
    }
    return { ok: false, error: 'network_error' };
  } finally {
    clearTimeout(timeoutId);
    callerSignal?.removeEventListener('abort', handleCallerAbort);
  }
}

