/**
 * Analyze & Health Routes for Satark API.
 * 
 * Rules:
 * - Strict payload validation without leaking input in error responses.
 * - Max length boundary: text <= 2000 chars, url <= 2048 chars.
 * - Allowed languages: en, hi, hinglish.
 */

import { Router } from 'express';
import { analyzeMessage } from '../detection/analyzeMessage.js';
import { classifyMessage } from '../detection/classifier.js';

const router = Router();

const ALLOWED_LANGUAGES = new Set(['en', 'hi', 'hinglish']);

// GET /api/health
router.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// POST /api/analyze
router.post('/analyze', async (req, res, next) => {
  const body = req.body;

  // 1. Plain object verification
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({ error: 'Invalid input payload', field: 'body' });
  }

  const { text = '', url, lang } = body;

  // 2. Text validation
  if (typeof text !== 'string') {
    return res.status(400).json({ error: 'Invalid input text', field: 'text' });
  }

  const trimmedText = text.trim();

  if (text.length > 2000) {
    return res.status(400).json({ error: 'Text exceeds maximum length of 2000 characters', field: 'text' });
  }

  // 3. URL validation (optional)
  if (url !== undefined && url !== null) {
    if (typeof url !== 'string' || url.length > 2048) {
      return res.status(400).json({ error: 'Invalid URL length or format', field: 'url' });
    }
  }

  if (!trimmedText && !(typeof url === 'string' && url.trim())) {
    return res.status(400).json({ error: 'A message or URL is required', field: 'text' });
  }

  // 4. Language validation (optional)
  if (lang !== undefined && lang !== null) {
    if (typeof lang !== 'string' || !ALLOWED_LANGUAGES.has(lang.toLowerCase())) {
      return res.status(400).json({ error: 'Invalid language selection', field: 'lang' });
    }
  }

  // 5. Execute detection pipeline (asynchronous classifier + deterministic rule engine)
  try {
    // URL-only requests use local URL checks, never an empty ML prediction.
    const classifierResult = await classifyMessage(text, {
      lang: typeof lang === 'string' ? lang.toLowerCase() : undefined,
      ...(!trimmedText ? { enabled: false } : {})
    });
    const result = analyzeMessage(text, url, { classifierResult });
    return res.json(result);
  } catch (err) {
    next(err);
  }
});

// Explicit rejection of other HTTP methods on /api/analyze
router.all('/analyze', (req, res) => {
  res.status(405).json({ error: 'Method not allowed' });
});

export default router;

