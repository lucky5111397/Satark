/**
 * Explanation templates and static safety guidance.
 * 
 * Sources:
 * - docs/rules_spec.md Sections 6.5 & Safety Actions
 * - Approved user decisions for extra rules (LOAN_FEE, UPI_COLLECT)
 * Note: 'hi' (Devanagari) contains unreviewed translations from docs/hindi_review.md Table 2,
 * clearly labeled as unverified in client presentation.
 */

export const RULE_TEMPLATES = {
  OTP_REQUEST: {
    en: 'The message asks you to share an OTP. Banks never ask for it.',
    hinglish: 'Is message mein OTP maanga ja raha hai. Bank kabhi OTP nahi maangta.',
    hi: 'संदेश में आपका गुप्त ओटीपी, पासवर्ड या पिन मांगा जा रहा है।'
  },
  SENSITIVE_INFO_REQUEST: {
    en: 'The message asks you to send sensitive personal credentials (like SIM number or Aadhaar). Never send identity details over SMS or chat.',
    hinglish: 'Is message mein SIM number ya Aadhaar jaisi sensitive details maangi ja rahi hain. Aisi details SMS ya chat par kabhi na bhejein.',
    hi: 'एसएमएस के जवाब में आधार, पैन या सिम कार्ड जैसे निजी दस्तावेज मांगे जा रहे हैं।'
  },
  URGENCY: {
    en: 'It pushes you to act immediately.',
    hinglish: 'Ye aapko turant action lene ke liye daba raha hai.',
    hi: 'संदेश में तुरंत कार्रवाई करने का अनुचित दबाव बनाया जा रहा है।'
  },
  KYC_LURE: {
    en: 'It uses a KYC expiry threat, a common scam pretext.',
    hinglish: 'Ye KYC expire hone ka darr dikha raha hai, jo common scam trick hai.',
    hi: 'केवाईसी समाप्त होने या खाता फ्रीज होने का डर दिखाकर फंसाने का प्रयास है।'
  },
  FEAR: {
    en: 'It threatens account blocking or legal action.',
    hinglish: 'Ye account band hone ya legal action ki dhamki de raha hai.',
    hi: 'खाता बंद करने, बिजली काटने या कानूनी कार्रवाई की धमकी दी जा रही है।'
  },
  FAKE_REWARD: {
    en: 'It promises a prize or reward you did not ask for.',
    hinglish: 'Ye bina maange inaam ya reward ka lalach de raha hai.',
    hi: 'लॉटरी, इनाम या अप्रत्याशित कैशबैक का झांसा दिया जा रहा है।'
  },
  JOB_FEE: {
    en: 'It asks for money upfront for a job.',
    hinglish: 'Ye job ke liye pehle paise maang raha hai. Asli job mein aisa nahi hota.',
    hi: 'घर बैठे काम या नौकरी के नाम पर पहले पैसे या पंजीकरण शुल्क मांगा जा रहा है।'
  },
  IMPERSONATION: {
    en: 'It pretends to be an official authority.',
    hinglish: 'Ye kisi sarkari/bank adhikari ban kar baat kar raha hai.',
    hi: 'बैंक, सरकारी विभाग, पुलिस या कूरियर अधिकारी होने का झूठा ढोंग किया जा रहा है।'
  },
  DECEPTIVE_LINK: {
    en: 'The link looks suspicious (see evidence).',
    hinglish: 'Link shak wala lag raha hai (evidence dekhein).',
    hi: 'संदेश में दिया गया लिंक संदिग्ध या भ्रामक लग रहा है।'
  },
  LOAN_FEE: {
    en: 'It offers an instant or pre-approved loan requiring advance processing fees.',
    hinglish: 'Ye bina documents turant loan ka lalach dekar advance processing fee maang raha hai.',
    hi: 'आसान ऋण देने के बहाने पहले फाइल चार्ज या प्रोसेसिंग फीस मांगी जा रही है।'
  },
  UPI_COLLECT: {
    en: 'It tricks you into entering a UPI PIN to receive money or accept a collect request.',
    hinglish: 'Paise paane ke naam par UPI PIN daalne ya collect request accept karne ko bol raha hai. Paise lene ke liye PIN nahi lagta.',
    hi: 'पैसे पाने के नाम पर यूपीआई पिन डालने या कलेक्ट रिक्वेस्ट स्वीकार करने को कहा जा रहा है।'
  },
  ADVANCE_FEE: {
    en: 'It demands advance fees or taxes to release a loan, courier package, or customs shipment.',
    hinglish: 'Ye parcel, loan ya customs release karane ke liye advance paise ya tax maang raha hai.',
    hi: 'पार्सल छुड़ाने, ऋण जारी करने या सेवा शुरू करने हेतु पहले शुल्क मांगा जा रहा है।'
  },
  UNSOLICITED_REFUND: {
    en: 'It offers an unexpected refund or subsidy requiring you to submit bank details or claim funds.',
    hinglish: 'Ye bina maange refund ya subsidy ka lalach dekar bank details verify karne ya claim karne ko bol raha hai.',
    hi: 'गलती से पैसे आने या सब्सिडी/रिफंड का झांसा देकर बैंक विवरण मांगे जा रहे हैं।'
  }
};

export const SAFETY_ACTIONS = [
  'Never share an OTP, PIN or CVV with anyone.',
  "Do not click the link. Open your bank's official app/website yourself.",
  'Money lost? Call 1930 and report at cybercrime.gov.in.',
  'Suspicious message/number? Report at sancharsaathi.gov.in/sfc (Chakshu).'
];

export const OFFICIAL_LINKS = [
  'https://cybercrime.gov.in',
  'https://sancharsaathi.gov.in/sfc'
];

export const DISCLAIMER = 'Red-flag guidance, not a guarantee of safety.';

