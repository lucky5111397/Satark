/**
 * Score aggregation and classification logic.
 * 
 * Sources:
 * - docs/rules_spec.md Section 6.4
 * - Standing rules: No 100% safe claim; unavailable evidence is never treated as safe.
 */

import { RULE_DEFINITIONS } from './rules.js';
import { runLocalClassifier } from './classifier.js';

/**
 * If true, IMPERSONATION is treated as a context-only signal:
 * its score (+2) is only counted if at least one other non-context rule
 * or a risky URL heuristic also triggers.
 */
export const IMPERSONATION_CONTEXT_ONLY = true;

/**
 * Calculates aggregate risk score and assigns category.
 * 
 * Rules:
 * - Count each rule ID once.
 * - +3 per risky URL (capped at +6).
 * - 0: "No known red flags found"
 * - 1 - 3: "Caution"
 * - 4+: "Suspicious"
 * - Special rule: OTP_REQUEST + any other signal = automatically "Suspicious".
 * 
 * @param {Array<{ ruleId: string, weight: number }>} indicators
 * @param {Array<{ url: string, status: string, flags: string[] }>} urlEvidence
 * @param {object} [classifierResult] - Optional asynchronous ML classifier result
 * @returns {{ score: number, category: string, ledger: Array<{ check: string, status: string }>, classifier: object }}
 */
export function aggregateResults(indicators, urlEvidence, classifierResult = null) {
  // Count each rule once
  const triggeredRuleMap = new Map();
  for (const ind of indicators) {
    if (!triggeredRuleMap.has(ind.ruleId)) {
      triggeredRuleMap.set(ind.ruleId, ind.weight);
    }
  }

  // Count risky URLs (+4 for 2+ independent causes, +3 for 1, capped at +6)
  // A URL is risky if it triggered security flags beyond simply missing HTTPS
  // Independent strong causes:
  // - brand_lookalike & typosquat count as ONE cause
  // - suspicious_tld, ip_address, punycode, shortener count separately
  let urlScore = 0;
  for (const item of urlEvidence) {
    const flags = item.flags || [];
    if (!flags.some(f => f !== 'no_https')) {
      continue;
    }

    let independentCauses = 0;
    if (flags.includes('brand_lookalike') || flags.includes('typosquat')) {
      independentCauses++;
    }
    if (flags.includes('suspicious_tld')) {
      independentCauses++;
    }
    if (flags.includes('ip_address')) {
      independentCauses++;
    }
    if (flags.includes('punycode')) {
      independentCauses++;
    }
    if (flags.includes('url_shortener') || flags.includes('shortener')) {
      independentCauses++;
    }

    if (independentCauses >= 2) {
      urlScore += 4;
    } else {
      urlScore += 3;
    }
  }

  urlScore = Math.min(6, urlScore);

  // Check context-only qualification for IMPERSONATION
  const hasOtherNonContextRule = Array.from(triggeredRuleMap.keys()).some(r => r !== 'IMPERSONATION');
  const hasRiskyUrl = urlScore > 0;
  const isImpersonationSuppressed = IMPERSONATION_CONTEXT_ONLY &&
    triggeredRuleMap.has('IMPERSONATION') &&
    !hasOtherNonContextRule &&
    !hasRiskyUrl;

  let ruleScore = 0;
  for (const [ruleId, weight] of triggeredRuleMap.entries()) {
    if (ruleId === 'IMPERSONATION' && isImpersonationSuppressed) {
      continue;
    }
    ruleScore += weight;
  }

  const totalScore = ruleScore + urlScore;

  // Determine Category
  let category;
  if (totalScore === 0) {
    category = 'No known red flags found';
  } else if (totalScore >= 4) {
    category = 'Suspicious';
  } else {
    category = 'Caution';
  }

  // Special rule: OTP_REQUEST plus any other signal (another rule or any URL flag) = Suspicious
  const hasOtp = triggeredRuleMap.has('OTP_REQUEST');
  const hasOtherSignal = triggeredRuleMap.size > 1 || urlScore > 0 || (urlEvidence.length > 0 && urlEvidence.some(u => u.flags.length > 0));
  if (hasOtp && hasOtherSignal) {
    category = 'Suspicious';
  }

  // Construct Evidence Ledger
  const ledger = [];
  
  // Rule entries in ledger
  for (const rule of RULE_DEFINITIONS) {
    let status = 'not_triggered';
    if (triggeredRuleMap.has(rule.id)) {
      if (rule.id === 'IMPERSONATION' && isImpersonationSuppressed) {
        status = 'not_triggered';
      } else {
        status = 'triggered';
      }
    }
    ledger.push({
      check: `Rule: ${rule.description}`,
      status
    });
  }

  // Deceptive link check entry if URLs were analyzed
  if (urlEvidence.length > 0) {
    ledger.push({
      check: 'URL heuristic analysis',
      status: urlScore > 0 ? 'triggered' : 'not_triggered'
    });
  }

  // Mandatory ledger entries from spec
  ledger.push({
    check: 'URL reputation',
    status: 'unavailable'
  });

  const activeClassifier = classifierResult || runLocalClassifier();

  // Elevate from "No known red flags found" to "Caution" if verified ML flags SUSPICIOUS
  // Deterministic rule red flags remain authoritative and are NEVER downgraded.
  if (activeClassifier.available && activeClassifier.prediction === 'SUSPICIOUS') {
    if (category === 'No known red flags found') {
      category = 'Caution';
    }
  }

  ledger.push({
    check: 'Classifier',
    status: activeClassifier.status
  });

  return {
    score: totalScore,
    category,
    ledger,
    classifier: activeClassifier
  };
}

