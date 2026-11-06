import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { analyze, validateResult } from '../src/lib/api.js';
import { getOfficialLinks } from '../src/lib/officialLinks.js';

describe('Client API Integration & Security Suite (TDD)', () => {
  const originalFetch = globalThis.fetch;
  let fetchSpy;
  let consoleLogSpy;
  let consoleErrorSpy;
  let consoleWarnSpy;

  beforeEach(() => {
    fetchSpy = vi.fn();
    globalThis.fetch = fetchSpy;
    consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  // 1. Request Shape & Protocol Conformance
  describe('Request shape and security attributes', () => {
    it('sends a URL-only request and accepts a response without message highlights', async () => {
      const url = 'https://example.com/qr';
      fetchSpy.mockResolvedValueOnce({
        status: 200,
        json: async () => ({
          category: 'No known red flags found', score: 0, indicators: [], ledger: [],
          explanation: { en: [], hi: [], hinglish: [] }, actions: [],
          urlEvidence: [{ url, status: 'checked', flags: [] }]
        })
      });
      const result = await analyze({ text: '', url });
      expect(JSON.parse(fetchSpy.mock.calls[0][1].body)).toEqual({ text: '', url });
      expect(result.ok).toBe(true);
      expect(result.data.indicators).toEqual([]);
      expect(result.data.urlEvidence[0].url).toBe(url);
    });

    it('sends correct method, headers, credentials, cache, referrerPolicy, and body', async () => {
      const mockSuccessResponse = {
        category: 'Caution',
        score: 3,
        indicators: [],
        ledger: [{ check: 'Rule: Urgency', status: 'triggered' }],
        explanation: { en: ['Notice'], hi: [], hinglish: ['Dhyan dein'] },
        actions: ['Do not share OTP'],
        urlEvidence: []
      };

      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockSuccessResponse
      });

      const submittedText = 'Notice from bank account';
      const result = await analyze({ text: submittedText, url: 'http://example.com' });

      expect(fetchSpy).toHaveBeenCalledTimes(1);
      const [url, init] = fetchSpy.mock.calls[0];

      // URL built from VITE_API_URL or fallback
      expect(url).toMatch(/http:\/\/(127\.0\.0\.1|localhost):5000\/api\/analyze/);
      expect(init.method).toBe('POST');
      expect(init.headers).toEqual({ 'Content-Type': 'application/json' });
      expect(init.credentials).toBe('omit');
      expect(init.cache).toBe('no-store');
      expect(init.referrerPolicy).toBe('no-referrer');
      expect(init.signal).toBeDefined();

      const parsedBody = JSON.parse(init.body);
      expect(parsedBody.text).toBe(submittedText);
      expect(parsedBody.url).toBe('http://example.com');
      // Invariant: Never send "lang" to API
      expect(parsedBody.lang).toBeUndefined();

      expect(result.ok).toBe(true);
      expect(result.data.category).toBe('Caution');
    });

    it('omits url property when url is empty or whitespace', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          category: 'No known red flags found',
          score: 0,
          indicators: [],
          ledger: [],
          explanation: { en: [], hi: [], hinglish: [] },
          actions: [],
          urlEvidence: []
        })
      });

      await analyze({ text: 'Some message', url: '   ' });
      const [, init] = fetchSpy.mock.calls[0];
      const parsedBody = JSON.parse(init.body);

      expect(parsedBody.text).toBe('Some message');
      expect(parsedBody.url).toBeUndefined();
    });
  });

  // 2. Status Code & Error Mapping
  describe('Status code error mapping', () => {
    const errorCases = [
      { status: 400, expectedError: 'invalid_input' },
      { status: 413, expectedError: 'too_large' },
      { status: 415, expectedError: 'unsupported' },
      { status: 429, expectedError: 'rate_limited' },
      { status: 500, expectedError: 'server_error' },
      { status: 502, expectedError: 'server_error' },
      { status: 503, expectedError: 'server_error' },
      { status: 404, expectedError: 'bad_response' }
    ];

    for (const { status, expectedError } of errorCases) {
      it(`maps HTTP ${status} strictly to ${expectedError} without exposing server response`, async () => {
        fetchSpy.mockResolvedValueOnce({
          ok: false,
          status,
          json: async () => ({ error: 'Detailed internal server message that must not leak' })
        });

        const res = await analyze({ text: 'Test text' });
        expect(res.ok).toBe(false);
        expect(res.error).toBe(expectedError);
        expect(res.data).toBeUndefined();
      });
    }

    it('maps network TypeError strictly to network_error', async () => {
      fetchSpy.mockRejectedValueOnce(new TypeError('Failed to fetch'));

      const res = await analyze({ text: 'Test text' });
      expect(res.ok).toBe(false);
      expect(res.error).toBe('network_error');
      expect(res.data).toBeUndefined();
    });

    it('maps AbortError or 12s timeout strictly to timeout', async () => {
      const abortError = new Error('The user aborted a request.');
      abortError.name = 'AbortError';
      fetchSpy.mockRejectedValueOnce(abortError);

      const res = await analyze({ text: 'Test text' });
      expect(res.ok).toBe(false);
      expect(res.error).toBe('timeout');
      expect(res.data).toBeUndefined();
    });

    it('keeps the 12-second deadline active while a response body stalls', async () => {
      vi.useFakeTimers();
      fetchSpy.mockImplementationOnce(async (_url, init) => ({
        status: 200,
        json: () => new Promise((_, reject) => {
          init.signal.addEventListener('abort', () => {
            reject(Object.assign(new Error('Body read aborted'), { name: 'AbortError' }));
          }, { once: true });
        })
      }));

      const pending = analyze({ text: 'Test message' });
      await vi.advanceTimersByTimeAsync(12000);

      expect(await pending).toEqual({ ok: false, error: 'timeout' });
      expect(fetchSpy.mock.calls[0][1].signal.aborted).toBe(true);
      expect(vi.getTimerCount()).toBe(0);
    });

    it('removes the caller abort listener and deadline after a completed request', async () => {
      vi.useFakeTimers();
      const caller = new AbortController();
      const addListener = vi.spyOn(caller.signal, 'addEventListener');
      const removeListener = vi.spyOn(caller.signal, 'removeEventListener');
      fetchSpy.mockResolvedValueOnce({ status: 400 });

      expect(await analyze({ text: 'Test message' }, caller.signal))
        .toEqual({ ok: false, error: 'invalid_input' });

      const handler = addListener.mock.calls[0][1];
      expect(removeListener).toHaveBeenCalledWith('abort', handler);
      expect(vi.getTimerCount()).toBe(0);
      caller.abort();
      expect(fetchSpy.mock.calls[0][1].signal.aborted).toBe(false);
    });

    it('cancels a pending response body when the caller aborts and releases its listener', async () => {
      vi.useFakeTimers();
      const caller = new AbortController();
      const removeListener = vi.spyOn(caller.signal, 'removeEventListener');
      fetchSpy.mockImplementationOnce(async (_url, init) => ({
        status: 200,
        json: () => new Promise((_, reject) => {
          init.signal.addEventListener('abort', () => {
            reject(Object.assign(new Error('Body read aborted'), { name: 'AbortError' }));
          }, { once: true });
        })
      }));

      const pending = analyze({ text: 'Test message' }, caller.signal);
      await vi.advanceTimersByTimeAsync(0);
      caller.abort();

      expect(await pending).toEqual({ ok: false, error: 'timeout' });
      expect(removeListener).toHaveBeenCalledTimes(1);
      expect(vi.getTimerCount()).toBe(0);
    });
  });

  // 3. validateResult & Zero-Trust Validation
  describe('validateResult() zero-trust sanitization', () => {
    const validSubmitted = 'Dear user aapka KYC expire ho jayega. Turant OTP bhejein';

    it('preserves an accepted standalone URL longer than 500 characters', () => {
      const url = `https://example.com/${'a'.repeat(700)}`;
      const result = validateResult({
        category: 'No known red flags found', score: 0,
        urlEvidence: [{ url, flags: [], status: 'checked' }]
      }, '');
      expect(result.urlEvidence[0].url).toBe(url);
    });

    it('accepts compliant server response with valid indicators', () => {
      const serverData = {
        category: 'Suspicious',
        score: 6,
        indicators: [
          { ruleId: 'KYC_LURE', start: 16, end: 26, text: 'KYC expire' },
          { ruleId: 'OTP_REQUEST', start: 45, end: 56, text: 'OTP bhejein' }
        ],
        ledger: [
          { check: 'Rule: KYC lure', status: 'triggered' },
          { check: 'URL reputation', status: 'unavailable' }
        ],
        explanation: {
          en: ['KYC threat detected'],
          hi: [],
          hinglish: ['KYC threat hai']
        },
        actions: ['Never share OTP'],
        urlEvidence: [],
        officialLinks: ['https://untrusted-spoofed-link.xyz'] // malicious injection attempt
      };

      const res = validateResult(serverData, validSubmitted);
      expect(res).not.toBe('bad_response');
      expect(res.category).toBe('Suspicious');
      expect(res.score).toBe(6);
      expect(res.indicators).toHaveLength(2);

      // Invariant: server-provided links MUST be ignored, using local allowlist only
      expect(res.officialLinks).not.toContain('https://untrusted-spoofed-link.xyz');
      expect(res.officialLinks).toEqual(getOfficialLinks().map(l => l.url));
    });

    it('drops indicators individually when indexes are invalid or text mismatches submitted substring', () => {
      const serverData = {
        category: 'Suspicious',
        score: 5,
        indicators: [
          // Valid
          { ruleId: 'KYC_LURE', start: 16, end: 26, text: 'KYC expire' },
          // Invalid: text mismatch
          { ruleId: 'BAD_TEXT', start: 16, end: 26, text: 'TAMPERED_TEXT' },
          // Invalid: negative start
          { ruleId: 'NEG_START', start: -1, end: 10, text: 'abc' },
          // Invalid: start >= end
          { ruleId: 'INVERTED', start: 20, end: 15, text: 'abc' },
          // Invalid: end beyond submittedText.length
          { ruleId: 'OUT_OF_BOUNDS', start: 50, end: 999, text: 'abc' },
          // Invalid: ruleId format
          { ruleId: 'lowercase_rule', start: 45, end: 56, text: 'OTP bhejein' }
        ],
        ledger: [],
        explanation: { en: [], hi: [], hinglish: [] },
        actions: [],
        urlEvidence: []
      };

      const res = validateResult(serverData, validSubmitted);
      expect(res).not.toBe('bad_response');
      // Only the first valid indicator survives
      expect(res.indicators).toHaveLength(1);
      expect(res.indicators[0].ruleId).toBe('KYC_LURE');
      expect(res.indicators[0].text).toBe('KYC expire');
    });

    it('returns bad_response for unknown category', () => {
      const badCategories = ['Safe', '100% Safe', 'Dangerous', 'UNKNOWN', '', null, 123];
      for (const cat of badCategories) {
        const res = validateResult({
          category: cat,
          score: 0,
          indicators: [],
          ledger: [],
          explanation: { en: [], hi: [], hinglish: [] }
        }, validSubmitted);
        expect(res).toBe('bad_response');
      }
    });

    it('returns bad_response for invalid score (out of 0-100 or non-number)', () => {
      const badScores = [-1, 101, NaN, '5', null, undefined];
      for (const score of badScores) {
        const res = validateResult({
          category: 'Suspicious',
          score,
          indicators: [],
          ledger: [],
          explanation: { en: [], hi: [], hinglish: [] }
        }, validSubmitted);
        expect(res).toBe('bad_response');
      }
    });
  });

  // 4. Privacy & Console Egress Checks
  describe('Zero-logging & Privacy protections', () => {
    it('never logs raw submitted text, response data, or error details to console', async () => {
      const sensitiveText = 'Secret OTP 998811 from user message';
      fetchSpy.mockRejectedValueOnce(new Error('Internal network crash with text: ' + sensitiveText));

      await analyze({ text: sensitiveText });

      for (const call of consoleLogSpy.mock.calls) {
        expect(JSON.stringify(call)).not.toContain(sensitiveText);
      }
      for (const call of consoleErrorSpy.mock.calls) {
        expect(JSON.stringify(call)).not.toContain(sensitiveText);
      }
      for (const call of consoleWarnSpy.mock.calls) {
        expect(JSON.stringify(call)).not.toContain(sensitiveText);
      }
    });
  });

  // 5. No Fallback to Mock Data on Failure
  describe('No Mock Fallback', () => {
    it('returns error without ever falling back to mock fixtures', async () => {
      fetchSpy.mockRejectedValueOnce(new TypeError('Failed to fetch'));
      const res = await analyze({ text: 'Aapka KYC expire ho jayega' });

      expect(res.ok).toBe(false);
      expect(res.error).toBe('network_error');
      expect(res.data).toBeUndefined();
    });
  });
});

