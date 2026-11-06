/**
 * Safe phrases and negation patterns for false-positive prevention.
 * 
 * Source: docs/rules_spec.md Section 6.2
 * Negation guards are checked at the sentence level to distinguish genuine bank alerts
 * from scam instructions (e.g. "Do not share OTP" vs "OTP bhejein").
 */

export const NEGATION_GUARD_PHRASES = [
  'do not share',
  'never share',
  "don't share",
  'dont share',
  'never disclose',
  'do not disclose',
  'will never ask for',
  'never ask for',
  'never asks for',
  'never ask',
  'never requests',
  'never request',
  'will never request',
  'never solicit',
  'never demand',
  'kisi ke saath share na karein',
  'kisi ke sath share na karein',
  'kisi ke saath share na kare',
  'kisi ko na batayein',
  'kisi ko na bataye',
  'kisi ko mat batayein',
  'kisi ko mat batao',
  'share na karein',
  'share na kare',
  'mat share karein',
  'kabhi nahi maangta',
  'kabhi nahi mangta',
  'kabhi nahi maangti',
  'kabhi nahi mangti',
  'kabhi bhi nahi maangta',
  'kabhi bhi nahi mangta',
  'bank kabhi otp nahi maangta',
  'bank kabhi bhi otp nahi maangta',
  'otp share karna surakshit nahi',
  'not share with anyone',
  // Devanagari (Hindi) negation guards — same meaning, native script.
  // Source: docs/hindi_plan.md Section 1 & 2 (pending native speaker sign-off in docs/hindi_review.md)
  'साझा न करें',
  'साझा ना करें',
  'शेयर न करें',
  'न बताएं',
  'न बताए',
  'किसी को न बताएं',
  'किसी के साथ साझा न करें',
  'नहीं मांगता',
  'नहीं मांगती',
  'नहीं मांगते',
  'नहीं पूछता',
  'नहीं पूछती',
  'कभी नहीं मांगता',
  'गुप्त रखें',
  'पिन नहीं लगती',
  'पिन की आवश्यकता नहीं'
];

/**
 * Completed credit phrases for unsolicited refund false-positive prevention.
 */
export const COMPLETED_CREDIT_GUARD_PHRASES = [
  'has been credited',
  'has been refunded',
  'has been processed',
  'has been transferred',
  'will reflect in your account',
  'credited to your',
  'credited in your',
  'credit ho gaya',
  'transferred to your',
  'refund credited',
  // Devanagari (Hindi): completed-credit confirmations (past passive voice)
  'जमा कर दिया गया',
  'क्रेडिट कर दिया गया',
  'क्रेडिट हो गया',
  'भेज दिए गए हैं',
  'रिफंड जारी कर दिया',
  'सफलतापूर्वक जमा'
];

/**
 * Completed debit or credit phrases for advance fee false-positive prevention.
 */
export const COMPLETED_DEBIT_CREDIT_GUARD_PHRASES = [
  'debited',
  'deducted',
  'credited',
  'generated',
  'available for download',
  'ready for download',
  'maintenance charge',
  'annual fee',
  'maintenance fee',
  // Devanagari (Hindi): completed debit/credit confirmations (past passive voice)
  'डेबिट कर दिया गया',
  'कटौती कर दी गई',
  'दर्ज हो गया',
  'भुगतान किया गया',
  'जारी किया गया'
];

/**
 * Protective advisory and unauthorized incident reporting phrases.
 * In genuine bank, payment, and service alerts, phrases advising users to immediately
 * block accounts or report unauthorized attempts are defensive instructions,
 * not scam pressure tactics, and must not trigger artificial URGENCY flags.
 */
export const ADVISORY_GUARD_PHRASES = [
  'अनधिकृत प्रयास',
  'अनधिकृत गतिविधि',
  'अनुरोध नहीं किया',
  'अनुरोध ना किया',
  'यदि आपने नहीं किया',
  'अगर आपने नहीं किया',
  'if not requested',
  'if you did not request',
  'if not generated',
  'if you did not generate',
  'if not done by you',
  'if unauthorized',
  'report immediately to',
  'immediately report to'
];




