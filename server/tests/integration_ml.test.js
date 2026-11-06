/**
 * End-to-End Integration Tests for Node.js Express & ML Classifier Pipeline.
 * 
 * Verifies:
 * 1. Safe default behavior (ML_ENABLED=false).
 * 2. Controlled ML activation (ML_ENABLED=true).
 * 3. FastAPI unavailable scenario (graceful failover to rule engine).
 * 4. FastAPI timeout scenario (AbortController aborts safely).
 * 5. Invalid ML response schema (safe fallback).
 * 6. Deterministic red-flag preservation (ML BENIGN never suppresses rule engine).
 * 7. ML supplementary signal (ML SUSPICIOUS elevates clean messages to Caution).
 * 8. Evidence Ledger conventions and schema preservation.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import { createApp } from '../app.js';

describe('Phase 4: Node.js Express & ML Classifier Integration Suite', () => {
  const originalEnv = { ...process.env };
  const allowedOrigin = 'http://localhost:5173';
  let app;

  beforeEach(() => {
    process.env = { ...originalEnv };
    // Maintain ML_ENABLED=false as base invariant
    process.env.ML_ENABLED = 'false';
    process.env.ML_SERVICE_URL = 'http://127.0.0.1:8000';
    process.env.ML_TIMEOUT_MS = '1500';
    process.env.ML_MODEL_NAME = 'FacebookAI/xlm-roberta-base';
    app = createApp({ clientOrigin: allowedOrigin });
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  // 1. Default Behavior (ML_ENABLED=false)
  describe('1. Default Environment Configuration', () => {
    it('keeps ML disabled and returns status: not_used in Evidence Ledger', async () => {
      const res = await request(app)
        .post('/api/analyze')
        .set('Origin', allowedOrigin)
        .send({ text: 'Normal friendly message without triggers' });

      expect(res.status).toBe(200);
      expect(res.body.category).toBe('No known red flags found');
      expect(res.body.classifier).toBeDefined();
      expect(res.body.classifier.available).toBe(false);
      expect(res.body.classifier.status).toBe('not_used');
      expect(res.body.classifier.prediction).toBeNull();

      const classifierLedger = res.body.ledger.find(e => e.check === 'Classifier');
      expect(classifierLedger).toBeDefined();
      expect(classifierLedger.status).toBe('not_used');
    });
  });

  // 2. ML Supplementary Signal (ML SUSPICIOUS elevates clean text)
  describe('2. ML Supplementary Signal', () => {
    it('elevates No known red flags found to Caution when ML predicts SUSPICIOUS', async () => {
      process.env.ML_ENABLED = 'true';

      // Mock ML microservice response with SUSPICIOUS prediction
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          status: 'ok',
          model: 'FacebookAI/xlm-roberta-base',
          prediction: 'SUSPICIOUS',
          confidence: 0.9854,
          latency_ms: 25.4,
          disclosure: 'Semantic scam patterns detected'
        })
      });
      vi.stubGlobal('fetch', mockFetch);

      const res = await request(app)
        .post('/api/analyze')
        .set('Origin', allowedOrigin)
        .send({ text: 'Cleverly disguised offer without explicit keyword triggers' });

      expect(res.status).toBe(200);
      expect(res.body.category).toBe('Caution');
      expect(res.body.classifier.available).toBe(true);
      expect(res.body.classifier.status).toBe('triggered');
      expect(res.body.classifier.prediction).toBe('SUSPICIOUS');
      expect(res.body.classifier.confidence).toBe(0.9854);

      const classifierLedger = res.body.ledger.find(e => e.check === 'Classifier');
      expect(classifierLedger.status).toBe('triggered');
    });

    it('retains No known red flags found when ML predicts BENIGN', async () => {
      process.env.ML_ENABLED = 'true';

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          status: 'ok',
          model: 'FacebookAI/xlm-roberta-base',
          prediction: 'BENIGN',
          confidence: 0.9912,
          latency_ms: 18.2,
          disclosure: 'Semantic benign content'
        })
      });
      vi.stubGlobal('fetch', mockFetch);

      const res = await request(app)
        .post('/api/analyze')
        .set('Origin', allowedOrigin)
        .send({ text: 'Are you free for coffee later this afternoon?' });

      expect(res.status).toBe(200);
      expect(res.body.category).toBe('No known red flags found');
      expect(res.body.classifier.available).toBe(true);
      expect(res.body.classifier.status).toBe('not_triggered');
      expect(res.body.classifier.prediction).toBe('BENIGN');

      const classifierLedger = res.body.ledger.find(e => e.check === 'Classifier');
      expect(classifierLedger.status).toBe('not_triggered');
    });
  });

  // 3. Deterministic Red-Flag Preservation (Rule Engine Authoritative)
  describe('3. Deterministic Red-Flag Preservation', () => {
    it('NEVER downgrades Suspicious to Caution or Safe when ML predicts BENIGN', async () => {
      process.env.ML_ENABLED = 'true';

      // ML predicts BENIGN with high confidence
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          status: 'ok',
          model: 'FacebookAI/xlm-roberta-base',
          prediction: 'BENIGN',
          confidence: 0.9999,
          latency_ms: 12.0,
          disclosure: 'Model classified as benign'
        })
      });
      vi.stubGlobal('fetch', mockFetch);

      // Message contains deterministic OTP + KYC triggers (Score >= 4)
      const res = await request(app)
        .post('/api/analyze')
        .set('Origin', allowedOrigin)
        .send({
          text: 'Aapka KYC expire ho gaya hai. Turant link kholein aur OTP share karein warna account block ho jayega.',
          lang: 'hinglish'
        });

      expect(res.status).toBe(200);
      expect(res.body.category).toBe('Suspicious');
      expect(res.body.score).toBeGreaterThanOrEqual(4);
      expect(res.body.indicators.length).toBeGreaterThan(0);
      expect(res.body.classifier.status).toBe('not_triggered');
      expect(res.body.classifier.prediction).toBe('BENIGN');

      const classifierLedger = res.body.ledger.find(e => e.check === 'Classifier');
      expect(classifierLedger.status).toBe('not_triggered');
    });

    it('preserves Caution category when message has low-risk rule and ML predicts BENIGN', async () => {
      process.env.ML_ENABLED = 'true';

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          status: 'ok',
          model: 'FacebookAI/xlm-roberta-base',
          prediction: 'BENIGN',
          confidence: 0.95,
          latency_ms: 15.0,
          disclosure: 'Clean'
        })
      });
      vi.stubGlobal('fetch', mockFetch);

      // Contains isolated urgency signal (weight 1 -> Caution)
      const res = await request(app)
        .post('/api/analyze')
        .set('Origin', allowedOrigin)
        .send({ text: 'Please act immediately to review the shared document.' });

      expect(res.status).toBe(200);
      expect(res.body.category).toBe('Caution');
      expect(res.body.score).toBe(1);
    });
  });

  // 4. FastAPI Microservice Unavailable / Error Scenarios
  describe('4. FastAPI Microservice Failure Resilience', () => {
    it('handles connection refusal (ECONNREFUSED) gracefully with safe fallback', async () => {
      process.env.ML_ENABLED = 'true';

      const mockFetch = vi.fn().mockRejectedValue(new Error('connect ECONNREFUSED 127.0.0.1:8000'));
      vi.stubGlobal('fetch', mockFetch);

      const res = await request(app)
        .post('/api/analyze')
        .set('Origin', allowedOrigin)
        .send({ text: 'Normal message while ML service is offline' });

      expect(res.status).toBe(200);
      expect(res.body.category).toBe('No known red flags found');
      expect(res.body.classifier.available).toBe(false);
      expect(res.body.classifier.status).toBe('unavailable');
      expect(res.body.classifier.disclosure).toContain('unreachable');

      const classifierLedger = res.body.ledger.find(e => e.check === 'Classifier');
      expect(classifierLedger.status).toBe('unavailable');
    });

    it('handles microservice timeout (AbortError) safely within threshold', async () => {
      process.env.ML_ENABLED = 'true';
      process.env.ML_TIMEOUT_MS = '100';

      const abortErr = new Error('The operation was aborted');
      abortErr.name = 'AbortError';
      const mockFetch = vi.fn().mockRejectedValue(abortErr);
      vi.stubGlobal('fetch', mockFetch);

      const res = await request(app)
        .post('/api/analyze')
        .set('Origin', allowedOrigin)
        .send({ text: 'Message during slow inference' });

      expect(res.status).toBe(200);
      expect(res.body.classifier.available).toBe(false);
      expect(res.body.classifier.status).toBe('unavailable');
      expect(res.body.classifier.disclosure).toContain('timed out');

      const classifierLedger = res.body.ledger.find(e => e.check === 'Classifier');
      expect(classifierLedger.status).toBe('unavailable');
    });

    it('handles HTTP 500 error from ML service safely', async () => {
      process.env.ML_ENABLED = 'true';

      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500
      });
      vi.stubGlobal('fetch', mockFetch);

      const res = await request(app)
        .post('/api/analyze')
        .set('Origin', allowedOrigin)
        .send({ text: 'Message during internal ML error' });

      expect(res.status).toBe(200);
      expect(res.body.classifier.available).toBe(false);
      expect(res.body.classifier.status).toBe('unavailable');
      expect(res.body.classifier.disclosure).toContain('HTTP 500');

      const classifierLedger = res.body.ledger.find(e => e.check === 'Classifier');
      expect(classifierLedger.status).toBe('unavailable');
    });

    it('handles malformed JSON from ML service safely', async () => {
      process.env.ML_ENABLED = 'true';

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => {
          throw new SyntaxError('Unexpected token < in JSON');
        }
      });
      vi.stubGlobal('fetch', mockFetch);

      const res = await request(app)
        .post('/api/analyze')
        .set('Origin', allowedOrigin)
        .send({ text: 'Message with corrupted ML response' });

      expect(res.status).toBe(200);
      expect(res.body.classifier.available).toBe(false);
      expect(res.body.classifier.status).toBe('unavailable');
      expect(res.body.classifier.disclosure).toContain('malformed JSON');

      const classifierLedger = res.body.ledger.find(e => e.check === 'Classifier');
      expect(classifierLedger.status).toBe('unavailable');
    });

    it('handles model_unavailable disclosure from ML service cleanly', async () => {
      process.env.ML_ENABLED = 'true';

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          status: 'model_unavailable',
          model: 'FacebookAI/xlm-roberta-base',
          prediction: null,
          confidence: null,
          latency_ms: 0.8,
          disclosure: 'Model weights not loaded in ML service.'
        })
      });
      vi.stubGlobal('fetch', mockFetch);

      const res = await request(app)
        .post('/api/analyze')
        .set('Origin', allowedOrigin)
        .send({ text: 'Message when weights are absent' });

      expect(res.status).toBe(200);
      expect(res.body.classifier.available).toBe(false);
      expect(res.body.classifier.status).toBe('unavailable');
      expect(res.body.classifier.prediction).toBeNull();
      expect(res.body.classifier.disclosure).toContain('Model weights not loaded');

      const classifierLedger = res.body.ledger.find(e => e.check === 'Classifier');
      expect(classifierLedger.status).toBe('unavailable');
    });
  });

  // 5. Response Contract & Security Audit
  describe('5. Response Schema & Security Contracts', () => {
    it('never reflects private message text in error responses or classifier disclosures', async () => {
      process.env.ML_ENABLED = 'true';
      const secret = 'AADHAAR_9988_7766_SECRET';

      const mockFetch = vi.fn().mockRejectedValue(new Error('Internal network error'));
      vi.stubGlobal('fetch', mockFetch);

      const res = await request(app)
        .post('/api/analyze')
        .set('Origin', allowedOrigin)
        .send({ text: `Confidential memo: ${secret}` });

      expect(res.status).toBe(200);
      expect(res.body.classifier.disclosure).not.toContain(secret);
      expect(JSON.stringify(res.body.classifier)).not.toContain(secret);
    });

    it('preserves complete public API response schema across ML outcomes', async () => {
      process.env.ML_ENABLED = 'true';

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          status: 'ok',
          model: 'FacebookAI/xlm-roberta-base',
          prediction: 'BENIGN',
          confidence: 0.96,
          latency_ms: 22.1,
          disclosure: 'Semantic inference complete'
        })
      });
      vi.stubGlobal('fetch', mockFetch);

      const res = await request(app)
        .post('/api/analyze')
        .set('Origin', allowedOrigin)
        .send({ text: 'Hello, this is a clean message.' });

      expect(res.status).toBe(200);
      const expectedKeys = [
        'category',
        'score',
        'detectedScript',
        'indicators',
        'ledger',
        'classifier',
        'urlEvidence',
        'explanation',
        'actions',
        'officialLinks',
        'disclaimer'
      ];
      for (const key of expectedKeys) {
        expect(res.body).toHaveProperty(key);
      }
    });
  });
});

