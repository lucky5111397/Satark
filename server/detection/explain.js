/**
 * Explanation assembly and civic advisories.
 * 
 * Sources:
 * - docs/rules_spec.md Section 6.5 & Safety Actions
 */

import { RULE_TEMPLATES, SAFETY_ACTIONS, OFFICIAL_LINKS, DISCLAIMER } from '../data/templates.js';

/**
 * Builds localized forensic explanations for triggered rules and flags.
 * @param {Array<{ ruleId: string }>} indicators 
 * @param {Array<{ flags: string[] }>} urlEvidence 
 * @returns {{
 *   explanation: { en: string[], hi: string[], hinglish: string[] },
 *   actions: string[],
 *   officialLinks: string[],
 *   disclaimer: string
 * }}
 */
export function buildExplanation(indicators, urlEvidence) {
  const triggeredRuleIds = new Set(indicators.map(i => i.ruleId));

  // If URL evidence flagged deceptive attributes, add DECEPTIVE_LINK
  const hasDeceptiveUrl = urlEvidence.some(u => u.flags.some(f => f !== 'no_https'));
  if (hasDeceptiveUrl) {
    triggeredRuleIds.add('DECEPTIVE_LINK');
  }

  const enList = [];
  const hinglishList = [];
  const hiList = [];

  for (const ruleId of triggeredRuleIds) {
    const template = RULE_TEMPLATES[ruleId];
    if (template) {
      if (template.en) enList.push(template.en);
      if (template.hinglish) hinglishList.push(template.hinglish);
      if (template.hi) hiList.push(template.hi);
    }
  }

  return {
    explanation: {
      en: enList,
      hi: hiList, // Populated with provisional drafts from RULE_TEMPLATES (flagged as unreviewed in UI)
      hinglish: hinglishList
    },
    actions: [...SAFETY_ACTIONS],
    officialLinks: [...OFFICIAL_LINKS],
    disclaimer: DISCLAIMER
  };
}

