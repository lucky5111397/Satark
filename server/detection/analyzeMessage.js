/**
 * Core analysis pipeline orchestrator for Satark scam detector.
 * 
 * Invariants & Guarantees:
 * - Pure computation only. NO network calls, NO file writes, NO database access.
 * - Zero logging of raw user messages (console.log / info / warn / error never called).
 * - Full compliance with API Contract (docs/rules_spec.md Section 5).
 */

import { normalizeText, detectScript } from './normalize.js';
import { matchRules, suppressKycBranchReminders } from './rules.js';
import { checkUrls } from './urlCheck.js';
import { aggregateResults, IMPERSONATION_CONTEXT_ONLY } from './aggregate.js';
import { buildExplanation } from './explain.js';

/**
 * Analyzes a message (and optional URL) for fraud indicators and red flags.
 * 
 * @param {string} text - User message input (up to 2000 chars).
 * @param {string} [url] - Optional standalone URL string.
 * @param {object} [options] - Optional analysis options.
 * @param {object} [options.classifierResult] - Optional asynchronous ML classifier result.
 * @returns {{
 *   category: 'Suspicious' | 'Caution' | 'No known red flags found',
 *   score: number,
 *   detectedScript: 'roman' | 'devanagari' | 'mixed',
 *   indicators: Array<{ ruleId: string, start: number, end: number, text: string }>,
 *   ledger: Array<{ check: string, status: string }>,
 *   classifier?: object,
 *   urlEvidence: Array<{ url: string, status: string, flags: string[] }>,
 *   explanation: { en: string[], hi: string[], hinglish: string[] },
 *   actions: string[],
 *   officialLinks: string[],
 *   disclaimer: string
 * }}
 */
export function analyzeMessage(text, url, options = {}) {
  // 1. Boundary check and sanitization
  const safeText = typeof text === 'string' ? text.substring(0, 2000) : '';
  const safeUrl = typeof url === 'string' ? url.substring(0, 2048) : undefined;

  // 2. Length-preserving normalization and script detection
  const normalizedText = normalizeText(safeText);
  const detectedScript = detectScript(safeText);

  // 3. Rule heuristic matching (sentence-level negation guards applied)
  let indicators = matchRules(normalizedText);

  // 4. Local URL inspections
  const { urlEvidence } = checkUrls(safeText, safeUrl);

  // 4b. Contextual branch visit suppression for KYC_LURE (Group 8)
  indicators = suppressKycBranchReminders(indicators, normalizedText, urlEvidence);

  // 4c. Suppress IMPERSONATION if context-only and isolated
  if (IMPERSONATION_CONTEXT_ONLY) {
    const hasOtherNonContextRule = indicators.some(i => i.ruleId !== 'IMPERSONATION');
    const hasRiskyUrl = urlEvidence.some(u => (u.flags || []).some(f => f !== 'no_https'));
    if (!hasOtherNonContextRule && !hasRiskyUrl) {
      indicators = indicators.filter(i => i.ruleId !== 'IMPERSONATION');
    }
  }

  // 5. Aggregate scoring & categorization
  const { score, category, ledger, classifier } = aggregateResults(indicators, urlEvidence, options?.classifierResult);

  // 6. Build localized explanations and action steps
  const { explanation, actions, officialLinks, disclaimer } = buildExplanation(indicators, urlEvidence);

  // 7. Strip weight from output indicators to match the public API contract
  const cleanIndicators = indicators.map(({ ruleId, start, end, text: matchText }) => ({
    ruleId,
    start,
    end,
    text: matchText
  }));

  return {
    category,
    score,
    detectedScript,
    indicators: cleanIndicators,
    ledger,
    classifier,
    urlEvidence,
    explanation,
    actions,
    officialLinks,
    disclaimer
  };
}

