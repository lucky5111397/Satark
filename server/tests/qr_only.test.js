import { afterEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import { createApp } from '../app.js';

const app = createApp({ rateLimitMax: 1000 });
afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); });

describe('URL-only analysis', () => {
  it('preserves an accepted standalone URL longer than 500 characters', async () => {
    const url = `https://example.com/${'a'.repeat(700)}`;
    const res = await request(app).post('/api/analyze').send({ url });
    expect(res.status).toBe(200);
    expect(res.body.urlEvidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ url })
    ]));
  });

  it.each([undefined, '', ' \n\t '])('analyzes a URL with text %s and never calls the ML service', async (text) => {
    vi.stubEnv('ML_ENABLED', 'true');
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    const url = 'http://example.xyz/qr-demo';
    const res = await request(app).post('/api/analyze').send({ text, url });
    expect(res.status).toBe(200);
    expect(res.body.indicators).toEqual([]);
    expect(res.body.urlEvidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ url, flags: expect.arrayContaining(['no_https']) })
    ]));
    expect(res.body.classifier.status).toBe('not_used');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it.each([{}, { text: '' }, { text: ' ', url: ' ' }])('rejects requests without either input: %j', async (payload) => {
    expect((await request(app).post('/api/analyze').send(payload)).status).toBe(400);
  });

  it.each([null, 42, false, {}, []])('still rejects invalid text %j when a URL is present', async (text) => {
    const res = await request(app).post('/api/analyze').send({ text, url: 'https://example.com' });
    expect(res.status).toBe(400);
    expect(res.body.field).toBe('text');
  });

  it.each([42, false, {}, []])('still rejects invalid URL type %j', async (url) => {
    const res = await request(app).post('/api/analyze').send({ text: '', url });
    expect(res.status).toBe(400);
    expect(res.body.field).toBe('url');
  });

  it('retains text, URL and language boundaries', async () => {
    for (const payload of [
      { text: 'a'.repeat(2001), url: 'https://example.com' },
      { text: '', url: `https://example.com/${'a'.repeat(2048)}` },
      { url: 'https://example.com', lang: 'invalid' }
    ]) expect((await request(app).post('/api/analyze').send(payload)).status).toBe(400);
  });
});
