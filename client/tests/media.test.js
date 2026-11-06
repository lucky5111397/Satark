import { describe, it, expect } from 'vitest';
import { canAnalyze, imageFileError, routeQrPayload } from '../src/lib/media.js';

describe('QR payload routing', () => {
  it.each(['https://example.com/qr', 'http://example.com/qr', 'HTTPS://example.com/qr'])('routes %s into the URL field', (value) => {
    expect(routeQrPayload(`  ${value}\n`)).toEqual({ field: 'url', value });
  });

  it.each([
    'upi://pay?pa=example@upi&pn=Demo',
    'UPI://PAY?pa=example@upi',
    'intent://pay?pa=example@upi#Intent;scheme=upi;end',
    'tez://upi/pay?pa=example@upi',
    'phonepe://pay?pa=example@upi',
    'pa=example@upi&pn=Demo',
    'pay?pa=example@upi&am=10'
  ])('keeps payment payload %s in message text', (value) => {
    expect(routeQrPayload(value)).toEqual({ field: 'text', value: `UPI payment request from QR code:\n${value}` });
  });

  it.each(['Some plain text', '<script>alert(1)</script>', 'javascript:alert(1)', 'user@example.com'])('keeps other payloads inert: %s', (value) => {
    expect(routeQrPayload(value)).toEqual({ field: 'text', value });
  });

  it('prioritizes an HTTP link even when it contains payment query parameters', () => {
    const value = 'https://example.com/pay?pa=example@upi';
    expect(routeQrPayload(value)).toEqual({ field: 'url', value });
  });
});

describe('Analyzer submission eligibility', () => {
  it('allows URL-only and text-only requests', () => {
    expect(canAnalyze('', 'https://example.com')).toBe(true);
    expect(canAnalyze(' \n ', 'https://example.com')).toBe(true);
    expect(canAnalyze('A message', '')).toBe(true);
  });
  it('rejects empty input, invalid types and oversized fields', () => {
    expect(canAnalyze(' \n ', ' ')).toBe(false);
    expect(canAnalyze(null, 'https://example.com')).toBe(false);
    expect(canAnalyze('a'.repeat(2001), 'https://example.com')).toBe(false);
    expect(canAnalyze('message', 'a'.repeat(2049))).toBe(false);
    expect(canAnalyze('a'.repeat(2000), 'a'.repeat(2048))).toBe(true);
  });
});

describe('Shared file picker and drop validation', () => {
  it.each(['image/png', 'image/jpeg', 'image/webp'])('accepts %s at the 4 MiB boundary', (type) => {
    expect(imageFileError({ type, size: 4 * 1024 * 1024 })).toBeNull();
  });
  it('rejects unsupported images and oversized files', () => {
    expect(imageFileError({ type: 'image/svg+xml', size: 100 })).toMatch(/format/);
    expect(imageFileError({ type: 'image/png', size: 4 * 1024 * 1024 + 1 })).toMatch(/4 MiB/);
  });
});
