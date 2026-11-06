import { describe, it, expect, vi } from 'vitest';
import { analyzeMessage } from '../detection/analyzeMessage.js';
import { checkUrls } from '../detection/urlCheck.js';

describe('Satark Detection Engine (TDD Suite)', () => {

  // Test 1: Hinglish KYC Scam
  it('1. identifies a Hinglish KYC scam as Suspicious with accurate substring indices', () => {
    const text = 'Aapka KYC aaj expire ho jayega. Turant link kholein aur OTP bhejein, warna account band.';
    const result = analyzeMessage(text);

    expect(result.category).toBe('Suspicious');
    expect(result.score).toBeGreaterThanOrEqual(4);

    const ruleIds = result.indicators.map(i => i.ruleId);
    expect(ruleIds).toContain('KYC_LURE');
    expect(ruleIds).toContain('URGENCY');
    expect(ruleIds).toContain('OTP_REQUEST');
    expect(ruleIds).toContain('FEAR');

    // Verify indicators point to exact substrings in the original text
    for (const indicator of result.indicators) {
      const slice = text.substring(indicator.start, indicator.end);
      expect(slice.toLowerCase()).toBe(indicator.text.toLowerCase());
    }

    // Verify explanation contains triggered rules
    expect(result.explanation.en.length).toBeGreaterThan(0);
    expect(result.explanation.hinglish.length).toBeGreaterThan(0);
    expect(Array.isArray(result.explanation.hi)).toBe(true);
  });

  // Test 2: Genuine Bank SMS
  it('2. evaluates genuine bank SMS with negation guard as No known red flags found', () => {
    const text = 'Dear customer, OTP is 482913 for your transaction. Do not share OTP with anyone. -SBI';
    const result = analyzeMessage(text);

    expect(result.category).toBe('No known red flags found');
    expect(result.score).toBe(0);
    expect(result.indicators).toHaveLength(0);
    expect(result.explanation.en).toHaveLength(0);
    expect(result.disclaimer).toBeTruthy();
  });

  // Test 3: Guard Bypass Attempt (sentence-level isolation)
  it('3. prevents guard bypass when scam instruction and negation guard are in separate sentences', () => {
    const text = 'Security advisory: Do not share OTP with unverified callers. Turant OTP bhejein for KYC renewal.';
    const result = analyzeMessage(text);

    expect(result.category).toBe('Suspicious');
    const ruleIds = result.indicators.map(i => i.ruleId);
    expect(ruleIds).toContain('OTP_REQUEST');
  });

  // Test 4: URL Checks
  describe('4. URL Inspection Rules', () => {
    it('flags suspicious TLD and brand lookalikes on sbi-kyc-update.xyz', () => {
      const res = checkUrls('', 'http://sbi-kyc-update.xyz');
      expect(res.flags).toContain('suspicious_tld');
      expect(res.flags).toContain('brand_lookalike');
      expect(res.flags).toContain('many_hyphens');
    });

    it('flags shortened URL for bit.ly links', () => {
      const res = checkUrls('Please visit bit.ly/power-bill');
      expect(res.flags).toContain('url_shortener');
    });

    it('flags raw IP address hosts', () => {
      const res = checkUrls('Login at http://192.168.1.5/login');
      expect(res.flags).toContain('ip_address');
    });

    it('flags punycode internationalized domains', () => {
      const res = checkUrls('Visit http://xn--sbi-8ka.com');
      expect(res.flags).toContain('punycode');
    });

    it('flags typosquatting domains with Levenshtein distance 1-2', () => {
      const res = checkUrls('Visit http://hdfcc.com/login');
      expect(res.flags).toContain('typosquat');
    });

    it('flags homoglyph character substitutions', () => {
      // 0 substituted for o or rn for m
      const res = checkUrls('Visit http://paytrn.com/claim');
      expect(res.flags).toContain('homoglyph');
    });

    it('does NOT flag legitimate whitelisted official domains as lookalikes', () => {
      const res = checkUrls('Log into https://sbi.co.in/portal');
      expect(res.flags).not.toContain('brand_lookalike');
      expect(res.flags).not.toContain('suspicious_tld');
    });

    it('does NOT count a URL whose ONLY flag is no_https as risky (+0 score, no DECEPTIVE_LINK)', () => {
      const res = analyzeMessage('Visit our community blog at http://example-blog.org/news');
      expect(res.score).toBe(0);
      expect(res.category).toBe('No known red flags found');
      const hasDeceptiveLink = res.explanation.en.some(e => e.includes('The link looks suspicious'));
      expect(hasDeceptiveLink).toBe(false);
      const ledgerUrlEntry = res.ledger.find(l => l.check === 'URL heuristic analysis');
      if (ledgerUrlEntry) {
        expect(ledgerUrlEntry.status).toBe('not_triggered');
      }
    });

    it('safely strips trailing sentence punctuation from URLs and detects suspicious TLDs', () => {
      const res = checkUrls('Please verify your credentials at http://sbi-kyc-verify.xyz.');
      expect(res.flags).toContain('suspicious_tld');
      expect(res.flags).toContain('brand_lookalike');
      expect(res.urlEvidence[0].url).toBe('http://sbi-kyc-verify.xyz');
    });
  });

  // Test 5: Plain Data Handling (<script> safety)
  it('5. handles script tags as plain harmless text without execution or distortion', () => {
    const text = 'Aapka KYC expire ho jayega. <script>alert(1)</script> Turant update karein warna account band ho jayega';
    const result = analyzeMessage(text);

    expect(result.category).toBe('Suspicious');
    for (const ind of result.indicators) {
      expect(text.substring(ind.start, ind.end).toLowerCase()).toBe(ind.text.toLowerCase());
    }
  });

  // Test 6: Edge Cases
  describe('6. Boundary and Edge Cases', () => {
    it('handles empty or whitespace-only text gracefully', () => {
      const res1 = analyzeMessage('');
      expect(res1.category).toBe('No known red flags found');
      expect(res1.score).toBe(0);

      const res2 = analyzeMessage('   \n\t   ');
      expect(res2.category).toBe('No known red flags found');
    });

    it('handles text with emojis only', () => {
      const res = analyzeMessage('🔥🚨⚠️💰💸');
      expect(res.category).toBe('No known red flags found');
    });

    it('analyzes text containing only a URL', () => {
      const res = analyzeMessage('http://sbi-kyc.xyz');
      expect(res.urlEvidence.length).toBeGreaterThan(0);
      expect(res.score).toBeGreaterThanOrEqual(3);
    });

    it('handles maximum length 2000-character input', () => {
      const longText = 'Aapka KYC pending hai. '.repeat(85).substring(0, 2000);
      const res = analyzeMessage(longText);
      expect(res).toBeDefined();
      expect(res.category).toBe('Caution');
    });

    it('correctly tags detectedScript as roman, devanagari, or mixed', () => {
      const romanRes = analyzeMessage('Aapka KYC pending hai');
      expect(romanRes.detectedScript).toBe('roman');

      const devRes = analyzeMessage('आपका खाता बंद हो जाएगा');
      expect(devRes.detectedScript).toBe('devanagari');

      const mixedRes = analyzeMessage('Aapka खाता block ho jayega');
      expect(mixedRes.detectedScript).toBe('mixed');
    });
  });

  // Test 7: ReDoS and Performance
  it('7. completes analysis of 2000-character repetitive input in well under 100ms', () => {
    const adversarial = ('a'.repeat(20) + ' ' + 'kyc '.repeat(20)).repeat(50).substring(0, 2000);
    const start = performance.now();
    const res = analyzeMessage(adversarial);
    const duration = performance.now() - start;

    expect(res).toBeDefined();
    expect(duration).toBeLessThan(100);
  });

  // Test 8: Determinism and Purity (zero console logging)
  it('8. produces deterministic output and never logs to console', () => {
    const logSpy = vi.spyOn(console, 'log');
    const infoSpy = vi.spyOn(console, 'info');
    const warnSpy = vi.spyOn(console, 'warn');
    const errorSpy = vi.spyOn(console, 'error');

    const input = 'Pre-approved loan without documents! Call now to pay processing fee advance.';
    const run1 = analyzeMessage(input);
    const run2 = analyzeMessage(input);

    expect(run1).toEqual(run2);
    expect(logSpy).not.toHaveBeenCalled();
    expect(infoSpy).not.toHaveBeenCalled();
    expect(warnSpy).not.toHaveBeenCalled();
    expect(errorSpy).not.toHaveBeenCalled();

    logSpy.mockRestore();
    infoSpy.mockRestore();
    warnSpy.mockRestore();
    errorSpy.mockRestore();
  });

  // Test 9: Honest Wording and Disclaimers
  it('9. never outputs 100% safe, adheres strictly to honest wording', () => {
    const res = analyzeMessage('Hello, good morning!');
    const jsonStr = JSON.stringify(res).toLowerCase();

    expect(jsonStr).not.toContain('100% safe');
    expect(res.category).toBe('No known red flags found');
    expect(res.disclaimer).toBe('Red-flag guidance, not a guarantee of safety.');

    // Ledger checks
    const urlRep = res.ledger.find(l => l.check === 'URL reputation');
    expect(urlRep.status).toBe('unavailable');

    const classifier = res.ledger.find(l => l.check === 'Classifier');
    expect(classifier.status).toBe('not_used');
  });

});
