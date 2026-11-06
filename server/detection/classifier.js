/**
 * Multilingual Machine Learning Classifier Interface for Satark Scam Detector.
 * 
 * Rules & Standing Project Directives:
 * - Deterministic, explainable heuristic rules remain the primary, authoritative baseline.
 * - Genuinely local processing only. Zero external network requests, zero downloads, zero telemetry.
 * - ML microservice binds strictly to local loopback (default: 127.0.0.1:8000).
 * - Safe fallback: If ML is disabled, offline, times out, or throws, the system
 *   falls back transparently and authoritatively to the deterministic Rule Engine.
 * - Zero user message logging in error traces or console.
 */

/**
 * Synchronous local classifier stub. Preserved for backwards compatibility with existing
 * tests and synchronous evaluation harnesses.
 * 
 * @param {string} [text]
 * @returns {{
 *   available: boolean,
 *   status: 'not_used' | 'unavailable' | 'triggered' | 'not_triggered',
 *   model: string | null,
 *   confidence: number | null,
 *   prediction: 'BENIGN' | 'SUSPICIOUS' | null,
 *   label: string | null,
 *   disclosure: string
 * }}
 */
export function runLocalClassifier(text) {
  return {
    available: false,
    status: 'not_used',
    model: null,
    confidence: null,
    prediction: null,
    label: null,
    disclosure: 'ML was not invoked for synchronous analysis. Local rule engine active.'
  };
}

/**
 * Asynchronously requests prediction from the local Python ML Microservice.
 * 
 * Invariants:
 * - Uses native global fetch with AbortController timeout.
 * - Never prints or logs raw text.
 * - Safely handles timeouts, ECONNREFUSED, malformed JSON, and 5xx errors.
 * 
 * @param {string} text - Message text to classify (1 to 2000 chars)
 * @param {object} [options]
 * @param {boolean} [options.enabled] - Override ML_ENABLED environment variable
 * @param {string} [options.serviceUrl] - Override ML_SERVICE_URL environment variable
 * @param {number} [options.timeoutMs] - Override ML_TIMEOUT_MS environment variable
 * @param {function} [options.fetchFn] - Custom fetch function for dependency injection in tests
 * @returns {Promise<{
 *   available: boolean,
 *   status: 'triggered' | 'not_triggered' | 'unavailable' | 'not_used',
 *   model: string | null,
 *   confidence: number | null,
 *   prediction: 'BENIGN' | 'SUSPICIOUS' | null,
 *   disclosure: string
 * }>}
 */
export async function classifyMessage(text, options = {}) {
  // 1. Check feature toggle
  const isEnabled = options.enabled !== undefined
    ? Boolean(options.enabled)
    : (process.env.ML_ENABLED === 'true');

  if (!isEnabled) {
    return {
      available: false,
      status: 'not_used',
      model: null,
      confidence: null,
      prediction: null,
      disclosure: 'ML classifier disabled in environment configuration. Local rule engine active.'
    };
  }

  // 2. Resolve Configuration
  const rawUrl = options.serviceUrl ?? process.env.ML_SERVICE_URL ?? 'http://127.0.0.1:8000';
  const serviceUrl = resolveLocalServiceOrigin(rawUrl);
  const configuredTimeout = Number(options.timeoutMs ?? process.env.ML_TIMEOUT_MS ?? 1500);
  const timeoutMs = Number.isFinite(configuredTimeout) && configuredTimeout > 0
    ? Math.min(5000, Math.max(1, Math.floor(configuredTimeout)))
    : 1500;
  const modelName = process.env.ML_MODEL_NAME || 'FacebookAI/xlm-roberta-base';
  const fetchFn = options.fetchFn || globalThis.fetch;
  const lang = options.lang;

  // Only local configuration controls display metadata. Never reflect service text.
  const unavailable = (disclosure) => ({
    available: false,
    status: 'unavailable',
    model: modelName,
    confidence: null,
    prediction: null,
    disclosure
  });

  if (!serviceUrl) {
    return unavailable('ML service must use a literal loopback origin. Fallback to rule engine active.');
  }

  // 3. Prepare Timeout & Request
  const controller = new AbortController();
  let timeoutId;
  let isTimedOut = false;
  // Race the whole operation, including JSON body consumption, against the deadline.
  const deadline = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      isTimedOut = true;
      controller.abort();
      const error = new Error('Local ML deadline exceeded');
      error.name = 'AbortError';
      reject(error);
    }, timeoutMs);
  });

  const payload = { text };
  if (lang && typeof lang === 'string') {
    payload.lang = lang;
  }

  const requestPrediction = async () => {
    const response = await fetchFn(`${serviceUrl}/predict`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
      // A local endpoint must never redirect a private message elsewhere.
      redirect: 'error'
    });

    // 4. Handle HTTP Error Statuses
    if (!response.ok) {
      const status = Number.isInteger(response.status) && response.status >= 100 && response.status <= 599
        ? response.status
        : 'error';
      return unavailable(`ML service returned HTTP ${status}. Fallback to rule engine active.`);
    }

    // 5. Parse & Validate Response JSON
    let data;
    try {
      data = await response.json();
    } catch (err) {
      if (controller.signal.aborted || err?.name === 'AbortError') throw err;
      return unavailable('ML service returned malformed JSON. Fallback to rule engine active.');
    }

    if (!isValidResponseMetadata(data)) {
      return unavailable('ML service returned invalid response schema. Fallback to rule engine active.');
    }

    // Handle 'model_unavailable' response from Python service
    if (data.status === 'model_unavailable') {
      if (data.prediction != null || data.confidence != null) {
        return unavailable('ML service returned invalid response schema. Fallback to rule engine active.');
      }
      return unavailable('Model weights not loaded in ML service. Rule engine active.');
    }

    // Validate standard successful response
    if (data.status === 'ok' && (data.prediction === 'BENIGN' || data.prediction === 'SUSPICIOUS') &&
        Number.isFinite(data.confidence) && data.confidence >= 0 && data.confidence <= 1) {
      const isSuspicious = data.prediction === 'SUSPICIOUS';

      return {
        available: true,
        status: isSuspicious ? 'triggered' : 'not_triggered',
        model: modelName,
        confidence: data.confidence,
        prediction: data.prediction,
        disclosure: 'Semantic ML classification result (uncalibrated confidence).'
      };
    }

    // Any other irregular schema
    return unavailable('ML service returned invalid response schema. Fallback to rule engine active.');
  };

  try {
    return await Promise.race([deadline, requestPrediction()]);
  } catch (err) {
    if (isTimedOut || err?.name === 'AbortError') {
      return unavailable(`ML classification timed out after ${timeoutMs}ms. Fallback to rule engine active.`);
    }

    // Network / Connection Refused (e.g. Python service not running)
    return unavailable('ML service unreachable at configured endpoint. Fallback to rule engine active.');
  } finally {
    clearTimeout(timeoutId);
  }
}

/** Accept literal loopback hosts only; localhost is mapped without a DNS lookup. */
function resolveLocalServiceOrigin(rawUrl) {
  if (typeof rawUrl !== 'string' ||
      !/^https?:\/\/(?:127\.0\.0\.1|\[::1\]|localhost)(?::\d{1,5})?\/?$/i.test(rawUrl)) {
    return null;
  }
  try {
    const url = new URL(rawUrl);
    if (url.hostname === 'localhost') url.hostname = '127.0.0.1';
    return url.origin;
  } catch {
    return null;
  }
}

/** Validate metadata even though display strings never leave this trust boundary. */
function isValidResponseMetadata(data) {
  return data !== null && typeof data === 'object' && !Array.isArray(data) &&
    (data.status === 'ok' || data.status === 'model_unavailable') &&
    typeof data.model === 'string' && data.model.length > 0 && data.model.length <= 200 &&
    typeof data.disclosure === 'string' && data.disclosure.length <= 1000;
}
