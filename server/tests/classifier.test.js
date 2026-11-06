import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { classifyMessage, runLocalClassifier } from '../detection/classifier.js';
import { aggregateResults } from '../detection/aggregate.js';
import { analyzeMessage } from '../detection/analyzeMessage.js';

describe('Satark ML Classifier & Integration Suite', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
  });

  // 1. Synchronous Baseline
  describe('runLocalClassifier (Sync Baseline)', () => {
    it('returns not_used status with honest disclosure', () => {
      const res = runLocalClassifier('Any text');
      expect(res.available).toBe(false);
      expect(res.status).toBe('not_used');
      expect(res.prediction).toBeNull();
      expect(res.confidence).toBeNull();
      expect(res.disclosure).toContain('ML was not invoked');
    });
  });

  // 2. Feature Toggle (ML_ENABLED)
  describe('Feature Toggle behavior', () => {
    it('returns status: not_used when ML_ENABLED is false or unset', async () => {
      process.env.ML_ENABLED = 'false';
      const res = await classifyMessage('Test text');
      expect(res.available).toBe(false);
      expect(res.status).toBe('not_used');
      expect(res.disclosure).toContain('disabled in environment configuration');
    });

    it('honors options.enabled override over process.env', async () => {
      process.env.ML_ENABLED = 'true';
      const res = await classifyMessage('Test text', { enabled: false });
      expect(res.status).toBe('not_used');
    });
  });

  // 3. Successful Inference Calls
  describe('Successful Prediction Handling', () => {
    it('returns triggered when Python service predicts SUSPICIOUS', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          status: 'ok',
          model: 'satark-xlm-roberta-v1',
          prediction: 'SUSPICIOUS',
          confidence: 0.9412,
          latency_ms: 42.5,
          disclosure: 'Semantic ML classification result.'
        })
      });

      const res = await classifyMessage('Aapka KYC expire ho gaya hai', {
        enabled: true,
        fetchFn: mockFetch
      });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe('http://127.0.0.1:8000/predict');
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body)).toEqual({ text: 'Aapka KYC expire ho gaya hai' });

      expect(res.available).toBe(true);
      expect(res.status).toBe('triggered');
      expect(res.prediction).toBe('SUSPICIOUS');
      expect(res.confidence).toBe(0.9412);
      // Display identity comes from local configuration, never arbitrary service text.
      expect(res.model).toBe(process.env.ML_MODEL_NAME || 'FacebookAI/xlm-roberta-base');
    });

    it('returns not_triggered when Python service predicts BENIGN', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          status: 'ok',
          model: 'satark-xlm-roberta-v1',
          prediction: 'BENIGN',
          confidence: 0.8850,
          latency_ms: 38.1,
          disclosure: 'Semantic ML classification result.'
        })
      });

      const res = await classifyMessage('Dear customer, your salary of Rs 45,000 has been credited.', {
        enabled: true,
        fetchFn: mockFetch
      });

      expect(res.available).toBe(true);
      expect(res.status).toBe('not_triggered');
      expect(res.prediction).toBe('BENIGN');
      expect(res.confidence).toBe(0.8850);
    });
  });

  // 4. Missing Model Weights Handling in Python Service
  describe('Model Unavailable Handling', () => {
    it('returns status: unavailable when Python service reports model_unavailable', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          status: 'model_unavailable',
          model: 'satark-xlm-roberta-v1',
          prediction: null,
          confidence: null,
          latency_ms: 0.5,
          disclosure: 'Model weights not loaded in ML service.'
        })
      });

      const res = await classifyMessage('Some text', {
        enabled: true,
        fetchFn: mockFetch
      });

      expect(res.available).toBe(false);
      expect(res.status).toBe('unavailable');
      expect(res.prediction).toBeNull();
      expect(res.confidence).toBeNull();
    });
  });

  // 5. Failure and Error Handling
  describe('Resilience and Failover', () => {
    it('handles HTTP 500 error gracefully by returning unavailable', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500
      });

      const res = await classifyMessage('Some text', {
        enabled: true,
        fetchFn: mockFetch
      });

      expect(res.available).toBe(false);
      expect(res.status).toBe('unavailable');
      expect(res.disclosure).toContain('HTTP 500');
    });

    it('handles malformed JSON responses safely', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => {
          throw new SyntaxError('Unexpected token < in JSON');
        }
      });

      const res = await classifyMessage('Some text', {
        enabled: true,
        fetchFn: mockFetch
      });

      expect(res.available).toBe(false);
      expect(res.status).toBe('unavailable');
      expect(res.disclosure).toContain('malformed JSON');
    });

    it('handles network connection refusal (ECONNREFUSED) gracefully', async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error('connect ECONNREFUSED 127.0.0.1:8000'));

      const res = await classifyMessage('Some text', {
        enabled: true,
        fetchFn: mockFetch
      });

      expect(res.available).toBe(false);
      expect(res.status).toBe('unavailable');
      expect(res.disclosure).toContain('unreachable');
    });

    it('handles AbortError timeout safely', async () => {
      const abortError = new Error('The operation was aborted');
      abortError.name = 'AbortError';
      const mockFetch = vi.fn().mockRejectedValue(abortError);

      const res = await classifyMessage('Some text', {
        enabled: true,
        timeoutMs: 500,
        fetchFn: mockFetch
      });

      expect(res.available).toBe(false);
      expect(res.status).toBe('unavailable');
      expect(res.disclosure).toContain('timed out');
    });

    it('never leaks user message content in error disclosures', async () => {
      const sensitiveText = 'VERY_SECRET_AADHAAR_9999_8888';
      const mockFetch = vi.fn().mockRejectedValue(new Error('Network failure'));

      const res = await classifyMessage(sensitiveText, {
        enabled: true,
        fetchFn: mockFetch
      });

      expect(res.disclosure).not.toContain(sensitiveText);
    });
  });

  // 6. Aggregator & Evidence Ledger Integration
  describe('Aggregator & Evidence Ledger with ML signals', () => {
    it('records Classifier status in ledger when ML is not used', () => {
      const result = aggregateResults([], []);
      const classifierEntry = result.ledger.find(e => e.check === 'Classifier');
      expect(classifierEntry).toBeDefined();
      expect(classifierEntry.status).toBe('not_used');
      expect(result.category).toBe('No known red flags found');
    });

    it('records Classifier status in ledger when ML is unavailable', () => {
      const classifierResult = {
        available: false,
        status: 'unavailable',
        model: 'satark-xlm-roberta-v1',
        prediction: null,
        confidence: null,
        disclosure: 'Service offline'
      };

      const result = aggregateResults([], [], classifierResult);
      const classifierEntry = result.ledger.find(e => e.check === 'Classifier');
      expect(classifierEntry.status).toBe('unavailable');
      expect(result.category).toBe('No known red flags found');
    });

    it('elevates No known red flags found to Caution when ML flags SUSPICIOUS', () => {
      const classifierResult = {
        available: true,
        status: 'triggered',
        model: 'satark-xlm-roberta-v1',
        prediction: 'SUSPICIOUS',
        confidence: 0.91,
        disclosure: 'Semantic scam patterns detected'
      };

      const result = aggregateResults([], [], classifierResult);
      expect(result.category).toBe('Caution');
      const classifierEntry = result.ledger.find(e => e.check === 'Classifier');
      expect(classifierEntry.status).toBe('triggered');
    });

    it('NEVER downgrades deterministic Suspicious category even if ML predicts BENIGN', () => {
      const indicators = [
        { ruleId: 'OTP_REQUEST', weight: 3, start: 0, end: 10, text: 'send otp' },
        { ruleId: 'URGENCY', weight: 1, start: 15, end: 25, text: 'urgently' }
      ];

      const classifierResult = {
        available: true,
        status: 'not_triggered',
        model: 'satark-xlm-roberta-v1',
        prediction: 'BENIGN',
        confidence: 0.85,
        disclosure: 'Model classified as benign'
      };

      const result = aggregateResults(indicators, [], classifierResult);
      // Deterministic OTP + urgency = Suspicious (score >= 4)
      expect(result.category).toBe('Suspicious');
      expect(result.score).toBe(4);
      const classifierEntry = result.ledger.find(e => e.check === 'Classifier');
      expect(classifierEntry.status).toBe('not_triggered');
    });

    it('analyzeMessage passes options.classifierResult cleanly', () => {
      const classifierResult = {
        available: true,
        status: 'triggered',
        model: 'FacebookAI/xlm-roberta-base',
        prediction: 'SUSPICIOUS',
        confidence: 0.89,
        disclosure: 'ML flagged suspicious'
      };

      const result = analyzeMessage('Clean friendly note without red flags', undefined, { classifierResult });
      expect(result.category).toBe('Caution');
      expect(result.classifier).toEqual(classifierResult);
      expect(result.ledger.find(e => e.check === 'Classifier').status).toBe('triggered');
    });
  });

  // 7. Multilingual Input & Language Hinting
  describe('Multilingual Input & Language Hinting', () => {
    it.each(['en', 'hinglish', 'hi'])('passes language hint %s in POST payload', async (lang) => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          status: 'ok',
          model: 'FacebookAI/xlm-roberta-base',
          prediction: 'BENIGN',
          confidence: 0.95,
          latency_ms: 15.2,
          disclosure: 'Multilingual inference complete'
        })
      });

      await classifyMessage('Test text', {
        enabled: true,
        lang,
        fetchFn: mockFetch
      });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [, init] = mockFetch.mock.calls[0];
      const parsedBody = JSON.parse(init.body);
      expect(parsedBody.lang).toBe(lang);
      expect(parsedBody.text).toBe('Test text');
    });
  });

  // 8. Concurrency & High Query Volume Stress
  describe('Concurrent Inference & Isolation', () => {
    it('executes 25 concurrent prediction requests with zero state corruption', async () => {
      const mockFetch = vi.fn().mockImplementation(async (url, init) => {
        const body = JSON.parse(init.body);
        const idx = body.text.split(' ')[1];
        // Simulate random 5-20ms network delay
        await new Promise(r => setTimeout(r, Math.floor(Math.random() * 15) + 5));
        return {
          ok: true,
          status: 200,
          json: async () => ({
            status: 'ok',
            model: 'FacebookAI/xlm-roberta-base',
            prediction: Number(idx) % 2 === 0 ? 'SUSPICIOUS' : 'BENIGN',
            confidence: 0.90 + (Number(idx) * 0.002),
            latency_ms: 12.0,
            disclosure: 'Inference response'
          })
        };
      });

      const promises = Array.from({ length: 25 }, (_, i) =>
        classifyMessage(`Message ${i} content`, {
          enabled: true,
          fetchFn: mockFetch
        })
      );

      const results = await Promise.all(promises);

      expect(results).toHaveLength(25);
      results.forEach((res, i) => {
        expect(res.available).toBe(true);
        expect(res.model).toBe('FacebookAI/xlm-roberta-base');
        if (i % 2 === 0) {
          expect(res.status).toBe('triggered');
          expect(res.prediction).toBe('SUSPICIOUS');
        } else {
          expect(res.status).toBe('not_triggered');
          expect(res.prediction).toBe('BENIGN');
        }
      });
    });
  });

  // 9. Comprehensive Rule Engine Override Invariance (Regression Tests)
  describe('Rule Engine Override Invariance (ML Never Overrides Rules)', () => {
    it.each([
      {
        scenario: 'Payment lure + Urgency (Score = 4)',
        indicators: [
          { ruleId: 'PAYMENT_LURE', weight: 3, start: 0, end: 10, text: 'pay 500 rs' },
          { ruleId: 'URGENCY', weight: 1, start: 15, end: 25, text: 'immediately' }
        ],
        urls: []
      },
      {
        scenario: 'Electricity bill lure + Risky URL (Score = 6)',
        indicators: [
          { ruleId: 'ELECTRICITY_BILL_LURE', weight: 3, start: 0, end: 15, text: 'bijli bill due' }
        ],
        urls: [
          { url: 'http://bijli-bill-pay.xyz', status: 'analyzed', flags: ['suspicious_tld'] }
        ]
      },
      {
        scenario: 'KYC lure + OTP request (Score = 6)',
        indicators: [
          { ruleId: 'KYC_LURE', weight: 3, start: 0, end: 10, text: 'kyc expired' },
          { ruleId: 'OTP_REQUEST', weight: 3, start: 15, end: 25, text: 'share otp' }
        ],
        urls: []
      }
    ])('preserves Suspicious classification for $scenario when ML predicts BENIGN', ({ indicators, urls }) => {
      // Even if ML is 99.9% confident that message is BENIGN
      const benignClassifier = {
        available: true,
        status: 'not_triggered',
        model: 'FacebookAI/xlm-roberta-base',
        prediction: 'BENIGN',
        confidence: 0.999,
        disclosure: 'Model classified as benign'
      };

      const result = aggregateResults(indicators, urls, benignClassifier);

      expect(result.category).toBe('Suspicious');
      expect(result.score).toBeGreaterThanOrEqual(4);
      expect(result.classifier.status).toBe('not_triggered');
      expect(result.ledger.find(e => e.check === 'Classifier').status).toBe('not_triggered');
    });
  });
});

