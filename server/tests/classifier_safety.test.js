import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import { classifyMessage } from '../detection/classifier.js';
import { createApp } from '../app.js';

const validPrediction = (overrides = {}) => ({
  status: 'ok',
  model: 'service-model',
  prediction: 'BENIGN',
  confidence: 0.9,
  disclosure: 'Service display text is not trusted.',
  ...overrides
});

const respondWith = (data) => vi.fn().mockResolvedValue({
  ok: true,
  status: 200,
  json: async () => data
});

beforeEach(() => {
  vi.stubEnv('ML_SERVICE_URL', 'http://127.0.0.1:8000');
  vi.stubEnv('ML_MODEL_NAME', 'configured-local-model');
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('Local ML privacy boundary', () => {
  it.each([
    'https://example.com',
    'http://192.168.1.10:8000',
    'http://127.0.0.1.example.com:8000',
    'http://user:password@127.0.0.1:8000',
    'http://127.0.0.1:8000/private',
    'http://127.0.0.1:8000/?redirect=elsewhere',
    'http://127.0.0.1:8000/#fragment',
    'http://2130706433:8000',
    'http://127.0.0.1:99999',
    'file:///predict',
    ''
  ])('refuses a nonliteral or nonorigin endpoint before sending text: %s', async (serviceUrl) => {
    const fetchFn = respondWith(validPrediction());
    const result = await classifyMessage('PRIVATE_FIXTURE', { enabled: true, serviceUrl, fetchFn });
    expect(result.status).toBe('unavailable');
    expect(fetchFn).not.toHaveBeenCalled();
    expect(JSON.stringify(result)).not.toContain('PRIVATE_FIXTURE');
  });

  it.each([
    ['http://127.0.0.1:8000/', 'http://127.0.0.1:8000/predict'],
    ['http://[::1]:8000', 'http://[::1]:8000/predict'],
    ['http://localhost:8000', 'http://127.0.0.1:8000/predict']
  ])('uses a literal loopback destination for %s and forbids redirects', async (serviceUrl, endpoint) => {
    const fetchFn = respondWith(validPrediction());
    const result = await classifyMessage('Local fixture', { enabled: true, serviceUrl, fetchFn });
    expect(result.available).toBe(true);
    expect(fetchFn).toHaveBeenCalledWith(endpoint, expect.objectContaining({ redirect: 'error' }));
  });

  it.each(['ok', 'model_unavailable'])('never reflects service display strings for status %s', async (status) => {
    const secret = 'PRIVATE_FIXTURE_FROM_SERVICE';
    const data = validPrediction({
      status,
      model: secret,
      disclosure: secret,
      ...(status === 'model_unavailable' ? { prediction: null, confidence: null } : {})
    });
    const result = await classifyMessage(secret, { enabled: true, fetchFn: respondWith(data) });
    expect(result.model).toBe('configured-local-model');
    expect(JSON.stringify(result)).not.toContain(secret);
  });
});

describe('ML response validation and full-operation deadline', () => {
  it.each([
    null,
    [],
    'not an object',
    validPrediction({ status: 'unknown' }),
    validPrediction({ prediction: 'SAFE' }),
    validPrediction({ confidence: -0.1 }),
    validPrediction({ confidence: 1.1 }),
    validPrediction({ confidence: NaN }),
    validPrediction({ confidence: Infinity }),
    validPrediction({ confidence: '0.9' }),
    validPrediction({ model: {} }),
    validPrediction({ model: 'x'.repeat(201) }),
    validPrediction({ disclosure: {} }),
    validPrediction({ disclosure: 'x'.repeat(1001) }),
    validPrediction({ status: 'model_unavailable' })
  ])('falls back for malformed prediction data %#', async (data) => {
    const result = await classifyMessage('Local fixture', { enabled: true, fetchFn: respondWith(data) });
    expect(result.available).toBe(false);
    expect(result.status).toBe('unavailable');
    expect(result.confidence).toBeNull();
    expect(result.disclosure).toContain('invalid response schema');
  });

  it('times out and aborts when headers arrive but the JSON body never finishes', async () => {
    vi.useFakeTimers();
    const json = vi.fn(() => new Promise(() => {}));
    const fetchFn = vi.fn().mockResolvedValue({ ok: true, status: 200, json });
    const resultPromise = classifyMessage('Local fixture', { enabled: true, timeoutMs: 20, fetchFn });
    await vi.advanceTimersByTimeAsync(20);
    const result = await resultPromise;
    expect(json).toHaveBeenCalledOnce();
    expect(fetchFn.mock.calls[0][1].signal.aborted).toBe(true);
    expect(result.status).toBe('unavailable');
    expect(result.disclosure).toContain('timed out after 20ms');
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([[0, 1500], [-1, 1500], [Infinity, 1500], ['invalid', 1500], [100000, 5000], [0.2, 1]])(
    'bounds timeout setting %s to %sms', async (timeoutMs, expected) => {
      vi.useFakeTimers();
      const fetchFn = vi.fn(() => new Promise(() => {}));
      const resultPromise = classifyMessage('Local fixture', { enabled: true, timeoutMs, fetchFn });
      await vi.advanceTimersByTimeAsync(expected);
      expect((await resultPromise).disclosure).toContain(`timed out after ${expected}ms`);
      expect(vi.getTimerCount()).toBe(0);
    }
  );

  it('cleans up its deadline when inference completes normally', async () => {
    vi.useFakeTimers();
    const result = await classifyMessage('Local fixture', {
      enabled: true,
      fetchFn: respondWith(validPrediction())
    });
    expect(result.available).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('Express language normalization', () => {
  it('forwards accepted uppercase language values consistently to the local service', async () => {
    vi.stubEnv('ML_ENABLED', 'true');
    const fetchFn = respondWith(validPrediction());
    vi.stubGlobal('fetch', fetchFn);
    const app = createApp({ rateLimitMax: 100 });
    const response = await request(app).post('/api/analyze').send({ text: 'Local fixture', lang: 'HINGLISH' });
    expect(response.status).toBe(200);
    expect(JSON.parse(fetchFn.mock.calls[0][1].body).lang).toBe('hinglish');
  });
});
