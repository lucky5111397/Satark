/**
 * Express application factory for Satark scam detector.
 * 
 * Rules:
 * - Exports createApp(options) without calling listen.
 * - Strict security defaults: Helmet, zero wildcard CORS, rate limiting, 10kb body limit.
 * - Central error handler with generic JSON messages and zero information leakage.
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import analyzeRouter from './routes/analyze.js';

/**
 * Parses and validates CLIENT_ORIGIN (single or comma-separated list).
 * Invariants:
 * - Must be valid http(s) origin without trailing path or slash.
 * - No wildcards or empty entries.
 * - Default is strictly ['http://localhost:5173'].
 */
export function parseAllowedOrigins(clientOriginOption) {
  const raw = clientOriginOption !== undefined && clientOriginOption !== null
    ? clientOriginOption
    : (process.env.CLIENT_ORIGIN || 'http://localhost:5173');

  if (typeof raw !== 'string') return new Set(['http://localhost:5173']);

  const origins = new Set();
  const parts = raw.split(',');

  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed || trimmed.includes('*')) continue;
    try {
      const u = new URL(trimmed);
      if ((u.protocol === 'http:' || u.protocol === 'https:') && u.origin === trimmed) {
        origins.add(trimmed);
      }
    } catch {
      // Ignore invalid URLs
    }
  }

  if (origins.size === 0) {
    origins.add('http://localhost:5173');
  }

  return origins;
}

export function createApp(options = {}) {
  const app = express();

  // 1. Disable X-Powered-By
  app.disable('x-powered-by');

  // 2. Enforce Helmet security headers
  app.use(helmet());

  // 3. Strict CORS configuration (exact-match allowlist, comma-separated support)
  const allowedOrigins = parseAllowedOrigins(options.clientOrigin);
  app.use(
    cors({
      origin: (origin, callback) => {
        // Allow requests with no origin (e.g. mobile apps, curl, server-to-server) or matching allowedOrigins
        if (!origin || allowedOrigins.has(origin)) {
          callback(null, true);
        } else {
          callback(null, false);
        }
      },
      methods: ['GET', 'POST', 'OPTIONS'],
      credentials: false
    })
  );

  // 4. Cache-Control: no-store for all /api endpoints
  app.use('/api', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  // 5. Rate limiting on /api routes
  const maxRequests = options.rateLimitMax !== undefined ? options.rateLimitMax : 30;
  const limiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: maxRequests,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' }
  });
  app.use('/api', limiter);

  // 6. Content-Type check for POST requests (require application/json)
  app.use('/api', (req, res, next) => {
    if (req.method === 'POST') {
      const contentType = req.headers['content-type'] || '';
      if (!contentType.toLowerCase().includes('application/json')) {
        return res.status(415).json({ error: 'Unsupported Media Type: application/json required' });
      }
    }
    next();
  });

  // 7. Strict JSON body parser with 10kb ceiling
  app.use(
    express.json({
      limit: '10kb',
      strict: true
    })
  );

  // 8. Mount API routes
  app.use('/api', analyzeRouter);

  // 9. Catch-all 404 handler for unknown routes
  app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  // 10. Centralized error handling middleware
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    // 413 Payload Too Large
    if (err.type === 'entity.too.large' || err.status === 413) {
      return res.status(413).json({ error: 'Payload too large (10kb maximum)' });
    }

    // 400 Bad JSON syntax
    if (err instanceof SyntaxError && (err.status === 400 || 'body' in err)) {
      return res.status(400).json({ error: 'Invalid JSON payload' });
    }

    // Default 500: generic message, never leak error details or stack traces
    return res.status(err.status || 500).json({ error: 'Internal server error' });
  });

  return app;
}

