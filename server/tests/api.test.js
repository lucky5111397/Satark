import { describe, it, expect, vi } from 'vitest';
import request from 'supertest';
import { createApp } from '../app.js';

describe('Satark Express API & Security Hardening (TDD Suite)', () => {
  const allowedOrigin = 'http://localhost:5173';
  const app = createApp({ clientOrigin: allowedOrigin, rateLimitMax: 30 });

  // 1. Health check endpoint
  it('GET /api/health returns 200 with status ok', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
    expect(res.headers['cache-control']).toBe('no-store');
  });

  // 2. Core Analyze success flows
  it('POST /api/analyze returns 200 Suspicious for Hinglish KYC scam', async () => {
    const payload = {
      text: 'Aapka KYC aaj expire ho jayega. Turant link kholein aur OTP bhejein, warna account band.',
      lang: 'hinglish'
    };
    const res = await request(app)
      .post('/api/analyze')
      .set('Origin', allowedOrigin)
      .send(payload);

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(res.body.category).toBe('Suspicious');
    expect(res.body.score).toBeGreaterThanOrEqual(4);
    expect(res.body).toHaveProperty('indicators');
    expect(res.body).toHaveProperty('ledger');
    expect(res.body).toHaveProperty('urlEvidence');
    expect(res.body).toHaveProperty('explanation');
    expect(res.body).toHaveProperty('actions');
    expect(res.body).toHaveProperty('officialLinks');
    expect(res.body).toHaveProperty('disclaimer');
  });

  it('POST /api/analyze returns 200 No known red flags found for genuine bank SMS', async () => {
    const payload = {
      text: 'Dear customer, OTP is 482913 for your transaction. Do not share OTP with anyone. -SBI'
    };
    const res = await request(app)
      .post('/api/analyze')
      .set('Origin', allowedOrigin)
      .send(payload);

    expect(res.status).toBe(200);
    expect(res.body.category).toBe('No known red flags found');
    expect(res.body.score).toBe(0);
  });

  // 3. Input Validation Failures (400)
  describe('Input Validation Failures (400)', () => {
    it('rejects empty text with 400 and generic message', async () => {
      const res = await request(app).post('/api/analyze').send({ text: '' });
      expect(res.status).toBe(400);
      expect(res.body.field).toBe('text');
      expect(res.body.error).toBeDefined();
    });

    it('rejects whitespace-only text with 400', async () => {
      const res = await request(app).post('/api/analyze').send({ text: '   \n\t  ' });
      expect(res.status).toBe(400);
      expect(res.body.field).toBe('text');
    });

    it('rejects non-string text (number) with 400', async () => {
      const res = await request(app).post('/api/analyze').send({ text: 12345 });
      expect(res.status).toBe(400);
      expect(res.body.field).toBe('text');
    });

    it('rejects text exceeding 2000 characters with 400', async () => {
      const res = await request(app).post('/api/analyze').send({ text: 'a'.repeat(2001) });
      expect(res.status).toBe(400);
      expect(res.body.field).toBe('text');
    });

    it('rejects url exceeding 2048 characters with 400', async () => {
      const res = await request(app).post('/api/analyze').send({
        text: 'Valid text',
        url: 'http://example.com/' + 'a'.repeat(2048)
      });
      expect(res.status).toBe(400);
      expect(res.body.field).toBe('url');
    });

    it('rejects invalid lang option with 400', async () => {
      const res = await request(app).post('/api/analyze').send({
        text: 'Valid text',
        lang: 'french'
      });
      expect(res.status).toBe(400);
      expect(res.body.field).toBe('lang');
    });

    it('rejects non-object body (array) with 400', async () => {
      const res = await request(app).post('/api/analyze').send(['some', 'array']);
      expect(res.status).toBe(400);
    });
  });

  // 4. Content-Type and Body Size Boundaries (413, 415, Malformed JSON)
  describe('Payload & Content-Type Security', () => {
    it('rejects content-type other than application/json with 415', async () => {
      const res = await request(app)
        .post('/api/analyze')
        .set('Content-Type', 'text/plain')
        .send('some raw string');
      expect(res.status).toBe(415);
      expect(res.body.error).toBeDefined();
    });

    it('rejects payloads exceeding 10kb limit with 413', async () => {
      const oversizedText = 'k'.repeat(12 * 1024);
      const res = await request(app)
        .post('/api/analyze')
        .set('Content-Type', 'application/json')
        .send(JSON.stringify({ text: oversizedText }));
      expect(res.status).toBe(413);
      expect(res.body.error).toBeDefined();
      expect(JSON.stringify(res.body)).not.toContain(oversizedText);
    });

    it('handles malformed JSON with 400 without echoing invalid input', async () => {
      const badJson = '{"text": "broken json...';
      const res = await request(app)
        .post('/api/analyze')
        .set('Content-Type', 'application/json')
        .send(badJson);
      expect(res.status).toBe(400);
      expect(res.body.error).toBeDefined();
      expect(JSON.stringify(res.body)).not.toContain('broken json');
    });
  });

  // 5. XSS Safety & MIME Types
  it('5. returns XSS payloads strictly as unexecuted JSON data', async () => {
    const xssPayload = '<script>alert(1)</script>';
    const submittedText = 'Aapka KYC expire ho jayega. ' + xssPayload + ' Turant OTP bhejein';
    const res = await request(app)
      .post('/api/analyze')
      .send({ text: submittedText });

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(res.headers['content-type']).not.toContain('text/html');

    // Every indicator text must exactly equal submittedText.slice(start, end)
    expect(res.body.indicators.length).toBeGreaterThan(0);
    for (const ind of res.body.indicators) {
      expect(ind.text).toBe(submittedText.slice(ind.start, ind.end));
    }

    // The response never executes HTML and does not echo unflagged HTML tags
    const responseJsonStr = JSON.stringify(res.body);
    expect(responseJsonStr).not.toContain('<script>');
  });

  it('preserves exact indicator character offsets for untrimmed messages with leading whitespace, newlines, and emojis', async () => {
    const prefix = '   \n\n🚨 Attention: ';
    const scamBody = 'Dear user aapka KYC expire ho gaya. Turant OTP bhejein';
    const submittedText = prefix + scamBody;

    const res = await request(app)
      .post('/api/analyze')
      .send({ text: submittedText });

    expect(res.status).toBe(200);
    expect(res.body.indicators.length).toBeGreaterThan(0);

    for (const indicator of res.body.indicators) {
      expect(indicator.start).toBeGreaterThanOrEqual(0);
      expect(indicator.end).toBeLessThanOrEqual(submittedText.length);
      expect(indicator.start).toBeLessThan(indicator.end);
      const extracted = submittedText.slice(indicator.start, indicator.end);
      expect(indicator.text).toBe(extracted);
    }
  });

  // 6. CORS Policy Enforcement
  describe('6. CORS Security Rules', () => {
    it('default allows only exact http://localhost:5173 and denies others', async () => {
      const defaultApp = createApp();
      const allowedRes = await request(defaultApp)
        .options('/api/analyze')
        .set('Origin', 'http://localhost:5173');
      expect(allowedRes.headers['access-control-allow-origin']).toBe('http://localhost:5173');
      expect(allowedRes.headers['access-control-allow-origin']).not.toBe('*');

      const ipRes = await request(defaultApp)
        .options('/api/analyze')
        .set('Origin', 'http://127.0.0.1:5173');
      expect(ipRes.headers['access-control-allow-origin']).toBeUndefined();

      const deniedRes = await request(defaultApp)
        .options('/api/analyze')
        .set('Origin', 'http://malicious-site.com');
      expect(deniedRes.headers['access-control-allow-origin']).toBeUndefined();
    });

    it('allows comma-separated list of exact origins and denies unlisted', async () => {
      const multiOriginApp = createApp({
        clientOrigin: 'http://localhost:5173, https://satark-demo.org, http://127.0.0.1:5173'
      });

      const res1 = await request(multiOriginApp)
        .options('/api/analyze')
        .set('Origin', 'http://localhost:5173');
      expect(res1.headers['access-control-allow-origin']).toBe('http://localhost:5173');

      const res2 = await request(multiOriginApp)
        .options('/api/analyze')
        .set('Origin', 'https://satark-demo.org');
      expect(res2.headers['access-control-allow-origin']).toBe('https://satark-demo.org');

      const res3 = await request(multiOriginApp)
        .options('/api/analyze')
        .set('Origin', 'http://127.0.0.1:5173');
      expect(res3.headers['access-control-allow-origin']).toBe('http://127.0.0.1:5173');

      const res4 = await request(multiOriginApp)
        .options('/api/analyze')
        .set('Origin', 'http://unlisted-origin.com');
      expect(res4.headers['access-control-allow-origin']).toBeUndefined();
    });

    it('ignores wildcards and malformed entries in the origin list', async () => {
      const sanitizedApp = createApp({
        clientOrigin: '*, not-a-url, http://trusted.org, '
      });

      const resAllowed = await request(sanitizedApp)
        .options('/api/analyze')
        .set('Origin', 'http://trusted.org');
      expect(resAllowed.headers['access-control-allow-origin']).toBe('http://trusted.org');

      const resWildcard = await request(sanitizedApp)
        .options('/api/analyze')
        .set('Origin', '*');
      expect(resWildcard.headers['access-control-allow-origin']).toBeUndefined();
    });
  });

  // 7. Security Headers (Helmet, Powered-By, Cache-Control)
  describe('7. Security Headers', () => {
    it('disables X-Powered-By header', async () => {
      const res = await request(app).get('/api/health');
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('includes Helmet standard security headers', async () => {
      const res = await request(app).get('/api/health');
      expect(res.headers['x-content-type-options']).toBe('nosniff');
    });

    it('sets Cache-Control: no-store on all /api responses', async () => {
      const res = await request(app).get('/api/health');
      expect(res.headers['cache-control']).toBe('no-store');
    });
  });

  // 8. Rate Limiting (429)
  it('8. triggers 429 when request rate exceeds configured limit', async () => {
    const rateLimitedApp = createApp({ clientOrigin: allowedOrigin, rateLimitMax: 2 });
    
    // Request 1: OK
    const res1 = await request(rateLimitedApp).get('/api/health');
    expect(res1.status).toBe(200);

    // Request 2: OK
    const res2 = await request(rateLimitedApp).get('/api/health');
    expect(res2.status).toBe(200);

    // Request 3: 429 Rate limited
    const res3 = await request(rateLimitedApp).get('/api/health');
    expect(res3.status).toBe(429);
    expect(res3.body.error).toBeDefined();
  });

  // 9. Method Not Allowed / 404
  it('9. returns 404 or 405 JSON when GET is called on /api/analyze', async () => {
    const res = await request(app).get('/api/analyze');
    expect([404, 405]).toContain(res.status);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(res.body.error).toBeDefined();
  });

  // 10. Privacy & Logging Guarantees
  it('10. never logs user input or sensitive error traces to stdout or stderr', async () => {
    const secretMsg = 'SECRET_TEST_MESSAGE_TOKEN_991823';
    const stdoutSpy = vi.spyOn(process.stdout, 'write');
    const stderrSpy = vi.spyOn(process.stderr, 'write');
    const logSpy = vi.spyOn(console, 'log');
    const errorSpy = vi.spyOn(console, 'error');

    // Test across normal and error routes
    await request(app).post('/api/analyze').send({ text: secretMsg });
    await request(app).post('/api/analyze').send({ text: secretMsg + 'a'.repeat(2000) }); // causes 400

    const stdoutCalls = stdoutSpy.mock.calls.map(c => String(c[0])).join('');
    const stderrCalls = stderrSpy.mock.calls.map(c => String(c[0])).join('');
    const logCalls = logSpy.mock.calls.map(c => String(c[0])).join('');
    const errorCalls = errorSpy.mock.calls.map(c => String(c[0])).join('');

    expect(stdoutCalls).not.toContain(secretMsg);
    expect(stderrCalls).not.toContain(secretMsg);
    expect(logCalls).not.toContain(secretMsg);
    expect(errorCalls).not.toContain(secretMsg);

    stdoutSpy.mockRestore();
    stderrSpy.mockRestore();
    logSpy.mockRestore();
    errorSpy.mockRestore();
  });
});
