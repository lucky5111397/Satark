import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { splitByIndicators } from '../src/lib/highlight.js';
import { isOfficialLink, getOfficialLinks, HELPLINE_1930_TEL } from '../src/lib/officialLinks.js';

describe('Frontend TDD Suite', () => {

  // 1. splitByIndicators unit tests
  describe('splitByIndicators()', () => {
    it('returns a single plain segment when there are no indicators', () => {
      const text = 'Hello world';
      const segments = splitByIndicators(text, []);
      expect(segments).toEqual([
        { text: 'Hello world', marked: false, ruleIds: [] }
      ]);
      expect(segments.map(s => s.text).join('')).toBe(text);
    });

    it('correctly splits with a single valid indicator', () => {
      const text = 'Aapka KYC expire ho gaya';
      // "KYC expire" at 6..16
      const indicators = [
        { ruleId: 'KYC_LURE', start: 6, end: 16, text: 'KYC expire' }
      ];
      const segments = splitByIndicators(text, indicators);
      expect(segments).toEqual([
        { text: 'Aapka ', marked: false, ruleIds: [] },
        { text: 'KYC expire', marked: true, ruleIds: ['KYC_LURE'] },
        { text: ' ho gaya', marked: false, ruleIds: [] }
      ]);
      expect(segments.map(s => s.text).join('')).toBe(text);
    });

    it('merges overlapping indicators and combines ruleIds', () => {
      const text = 'Turant OTP bhejein abhi';
      // Ind 1: "Turant OTP" (0..10), Ind 2: "OTP bhejein" (7..18)
      const indicators = [
        { ruleId: 'URGENCY', start: 0, end: 10, text: 'Turant OTP' },
        { ruleId: 'OTP_REQUEST', start: 7, end: 18, text: 'OTP bhejein' }
      ];
      const segments = splitByIndicators(text, indicators);
      expect(segments).toEqual([
        { text: 'Turant OTP bhejein', marked: true, ruleIds: ['URGENCY', 'OTP_REQUEST'] },
        { text: ' abhi', marked: false, ruleIds: [] }
      ]);
      expect(segments.map(s => s.text).join('')).toBe(text);
    });

    it('merges touching indicators', () => {
      const text = 'ABCDEF';
      const indicators = [
        { ruleId: 'R1', start: 0, end: 3, text: 'ABC' },
        { ruleId: 'R2', start: 3, end: 6, text: 'DEF' }
      ];
      const segments = splitByIndicators(text, indicators);
      expect(segments).toEqual([
        { text: 'ABCDEF', marked: true, ruleIds: ['R1', 'R2'] }
      ]);
      expect(segments.map(s => s.text).join('')).toBe(text);
    });

    it('clamps or ignores out-of-range, negative, or invalid indices without throwing', () => {
      const text = 'Normal test string';
      const indicators = [
        { ruleId: 'BAD1', start: -5, end: 3 },
        { ruleId: 'BAD2', start: 10, end: 5 }, // start >= end
        { ruleId: 'BAD3', start: 50, end: 60 }, // beyond text length
        { ruleId: 'BAD4', start: 'nan', end: 10 },
        { ruleId: 'VALID', start: 0, end: 6, text: 'Normal' }
      ];
      const segments = splitByIndicators(text, indicators);
      expect(segments.length).toBeGreaterThan(0);
      expect(segments.map(s => s.text).join('')).toBe(text);
      expect(segments[0].ruleIds).toContain('VALID');
    });

    it('preserves text with multi-byte emoji characters', () => {
      const text = 'Alert 🚨 OTP share na karein ⚠️';
      const indicators = [
        { ruleId: 'OTP_REQUEST', start: 9, end: 12, text: 'OTP' }
      ];
      const segments = splitByIndicators(text, indicators);
      expect(segments.map(s => s.text).join('')).toBe(text);
    });

    it('treats <script>alert(1)</script> purely as plain text segments', () => {
      const text = 'Danger <script>alert(1)</script> detected';
      const indicators = [
        { ruleId: 'XSS_SIM', start: 7, end: 32, text: '<script>alert(1)</script>' }
      ];
      const segments = splitByIndicators(text, indicators);
      expect(segments.map(s => s.text).join('')).toBe(text);
      expect(segments[1].marked).toBe(true);
      expect(segments[1].text).toBe('<script>alert(1)</script>');
    });
  });

  // 2. officialLinks allowlist validation
  describe('officialLinks allowlist', () => {
    it('accepts the exact official links', () => {
      expect(isOfficialLink('https://cybercrime.gov.in')).toBe(true);
      expect(isOfficialLink('https://sancharsaathi.gov.in/sfc')).toBe(true);
    });

    it('rejects unapproved schemes, look-alikes, and external URLs', () => {
      expect(isOfficialLink('javascript:alert(1)')).toBe(false);
      expect(isOfficialLink('http://cybercrime.gov.in')).toBe(false);
      expect(isOfficialLink('https://cybercrime.gov.in.fake.xyz')).toBe(false);
      expect(isOfficialLink('https://google.com')).toBe(false);
      expect(isOfficialLink('')).toBe(false);
      expect(isOfficialLink(null)).toBe(false);
    });

    it('getOfficialLinks returns the fixed official references', () => {
      const links = getOfficialLinks();
      expect(links).toHaveLength(2);
      expect(links.every(l => isOfficialLink(l.url))).toBe(true);
    });

    it('exports the constant HELPLINE_1930_TEL with tel:1930', () => {
      expect(HELPLINE_1930_TEL).toBe('tel:1930');
    });
  });

  // 3. Static security scan across client/src
  describe('Static security source scan (client/src)', () => {
    it('ensures client/src has zero forbidden DOM manipulation or storage APIs', () => {
      const srcDir = path.resolve(__dirname, '../src');
      if (!fs.existsSync(srcDir)) return; // Pass if src not written yet

      const forbiddenPatterns = [
        'dangerouslySetInnerHTML',
        'innerHTML',
        'outerHTML',
        'insertAdjacentHTML',
        'document.write',
        'eval(',
        'new Function',
        'localStorage',
        'sessionStorage'
      ];

      function scanDir(dir) {
        const files = fs.readdirSync(dir);
        for (const file of files) {
          const fullPath = path.join(dir, file);
          const stat = fs.statSync(fullPath);
          if (stat.isDirectory()) {
            scanDir(fullPath);
          } else if (/\.(jsx?|tsx?|html)$/.test(file)) {
            const content = fs.readFileSync(fullPath, 'utf8');
            for (const pattern of forbiddenPatterns) {
              expect(content).not.toContain(pattern);
            }
          }
        }
      }

      scanDir(srcDir);
    });
  });

  // 4. Local QR Decoder (jsQR) verification
  describe('Local QR Decoder (jsQR) integration', () => {
    it('imports jsQR and executes locally with zero network calls', async () => {
      const { default: jsQR } = await import('jsqr');
      expect(typeof jsQR).toBe('function');

      // Test with blank 10x10 buffer
      const width = 10;
      const height = 10;
      const buffer = new Uint8ClampedArray(width * height * 4).fill(255);
      const result = jsQR(buffer, width, height);
      expect(result).toBeNull();
    });
  });

  // 5. Navigation & UI Branding verification
  describe('Navigation & UI Branding validation', () => {
    it('ensures all 4 primary features are present in navigation', () => {
      const headerPath = path.resolve(__dirname, '../src/components/Header.jsx');
      const headerContent = fs.readFileSync(headerPath, 'utf8');

      expect(headerContent).toContain("id: 'analyzer'");
      expect(headerContent).toContain("label: 'Analyzer'");

      expect(headerContent).toContain("id: 'ocr'");
      expect(headerContent).toContain("label: 'Screenshot / OCR'");

      expect(headerContent).toContain("id: 'qr'");
      expect(headerContent).toContain("label: 'QR Decoder'");

      expect(headerContent).toContain("id: 'validation'");
      expect(headerContent).toContain("label: 'How Satark Works'");
    });

    it('ensures zero hackathon or event-specific branding in client source files', () => {
      const srcDir = path.resolve(__dirname, '../src');
      const forbiddenWords = ['HackSprint', 'hackathon', '12-hour'];

      function checkDir(dir) {
        const files = fs.readdirSync(dir);
        for (const file of files) {
          const fullPath = path.join(dir, file);
          const stat = fs.statSync(fullPath);
          if (stat.isDirectory()) {
            checkDir(fullPath);
          } else if (/\.(jsx?|html)$/.test(file)) {
            const content = fs.readFileSync(fullPath, 'utf8');
            for (const word of forbiddenWords) {
              expect(content.toLowerCase()).not.toContain(word.toLowerCase());
            }
          }
        }
      }

      checkDir(srcDir);
    });

    it('ensures ReportCard summary formatting does not append a misleading /10 ceiling', () => {
      const reportCardPath = path.resolve(__dirname, '../src/components/ReportCard.jsx');
      const content = fs.readFileSync(reportCardPath, 'utf8');

      expect(content).toContain('(Score: ${result.score})');
      expect(content).not.toContain('(Score: ${result.score}/10)');
    });
  });
});
