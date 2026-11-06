/**
 * Rule Engine for Satark Scam Message Detection.
 * 
 * Rules:
 * - 8 base categories + 2 extra categories (LOAN_FEE, UPI_COLLECT).
 * - Exact phrase and spelling variants with word boundaries.
 * - ReDoS safe: NO nested unbounded quantifiers.
 * - Sentence-level negation guard isolation.
 * - Returns start and end indices mapped directly to the ORIGINAL input text.
 */

import { 
  NEGATION_GUARD_PHRASES, 
  COMPLETED_CREDIT_GUARD_PHRASES,
  COMPLETED_DEBIT_CREDIT_GUARD_PHRASES,
  ADVISORY_GUARD_PHRASES
} from '../data/safe_phrases.js';

// Rule definitions with weights and regex patterns (case-insensitive)
export const RULE_DEFINITIONS = [
  {
    id: 'OTP_REQUEST',
    weight: 3,
    description: 'Demands OTP, PIN, or CVV credentials',
    patterns: [
      /\b(?:apna\s+)?otp\s+(?:bhejein|bhejiye|bhej\s+do|share\s+karein|share\s+kare|batayein|batao|share)\b/gi,
      /\b(?:share|send)\s+(?:your\s+)?otp\b/gi,
      /\b(?:pin|cvv)\s+(?:bhejein|bhejiye|batayein|batao)\b/gi,
      /\bcard\s+number\s+share\b/gi,
      /\botp\s+bhejo\b/gi,
      // SVO pattern: action verb + bounded gap (max 40 chars, no sentence breaks) + credential synonym
      /\b(?:share|sharing|send|sending|enter|tell|provide|give)\b[^\n.!?]{0,40}\b(?:otp|pin|cvv|verification\s+code|security\s+code|secret\s+code)\b/gi,
      // SOV pattern: credential synonym + bounded gap (max 40 chars, no sentence breaks) + action verb
      /\b(?:otp|pin|cvv|verification\s+code|security\s+code|secret\s+code)\b[^\n.!?]{0,40}\b(?:bhejein|bhejiye|bhej\s+do|bhejo|share\s+karein|share\s+kare|batayein|batao|tell|share|provide|send)\b/gi,
      // Devanagari (Hindi) — source: docs/hindi_plan.md Section 2.1 (pending native sign-off).
      // Uses Unicode lookarounds instead of ASCII \b (which fails on Devanagari) and the u flag.
      // Bounded gaps exclude danda (।) and double danda (॥) so matches never cross Hindi sentence boundaries.
      /(?<![\p{L}\p{M}])(?:ओटीपी|पिन|पासवर्ड|सीवीवी|सत्यापन\s+कोड|सुरक्षा\s+कोड)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,35}(?:भेजें|भेजिए|भेज\s+दो|भेज\s+दें|बताएं|बताइए|बता\s+दो|शेयर\s+करें|साझा\s+करें|दर्ज\s+करें)/giu,
      /(?:भेजें|भेजिए|भेज\s+दो|भेज\s+दें|बताएं|बताइए|शेयर\s+करें|साझा\s+करें|दर्ज\s+करें)[^।॥.!?\n\r]{0,25}(?<![\p{L}\p{M}])(?:ओटीपी|पिन|पासवर्ड|सीवीवी|सत्यापन\s+कोड|सुरक्षा\s+कोड)(?![\p{L}\p{M}])/giu,
      /अपना\s+(?:ओटीपी|पिन|पासवर्ड|सीवीवी)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,25}(?:भेजें|भेजिए|शेयर|साझा|बताएं|बताइए|दर्ज|बता)/giu
    ]
  },
  {
    id: 'SENSITIVE_INFO_REQUEST',
    weight: 3,
    description: 'Requests sensitive identity credentials (SIM, Aadhaar, PAN, card numbers)',
    patterns: [
      // SVO: action verb + bounded gap + sensitive identifier
      /\b(?:reply\s+with|reply\s+karein|send|bhejein|bhejiye|provide|share)\b[^\n.!?]{0,40}\b(?:sim\s+number|aadhaar|pan\s+(?:card\s+)?number|card\s+number|debit\s+card)\b/gi,
      // SOV: sensitive identifier + bounded gap + action verb
      /\b(?:sim\s+number|aadhaar(?:\s+last\s+\d+\s+digits|\s+digits|\s+number)?|pan\s+(?:card\s+)?number|card\s+number|debit\s+card)\b[^\n.!?]{0,40}\b(?:reply\s+karein|reply|send|bhejein|bhejiye|share\s+karein|share|batayein)\b/gi,
      // Devanagari (Hindi) — source: docs/hindi_plan.md Section 2.10 (pending native sign-off).
      // SOV: identifier + bounded gap + send/reply verb; digits accept Devanagari numerals too.
      /(?<![\p{L}\p{M}])(?:आधार(?:\s+(?:के?\s+)?अंतिम\s+[0-9०-९]{1,2}\s+अंक)?|आधार\s+नंबर|पैन\s+(?:कार्ड\s+)?नंबर|[0-9०-९]{1,2}\s+अंकीय\s+सिम\s+नंबर|सिम\s+नंबर|कार्ड\s+नंबर)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,30}(?:भेजें|भेजिए|भेज\s+दें|रिप्लाई\s+करें|लिखकर\s+भेजें|शेयर\s+करें|साझा\s+करें|बताएं)/giu,
      // SVO: send verb + bounded gap + identifier
      /(?:भेजें|भेजिए|रिप्लाई\s+करें|लिखकर\s+भेजें|शेयर\s+करें|साझा\s+करें)[^।॥.!?\n\r]{0,30}(?<![\p{L}\p{M}])(?:आधार(?:\s+नंबर)?|पैन\s+(?:कार्ड\s+)?नंबर|सिम\s+नंबर|कार्ड\s+नंबर|जन्मतिथि)(?![\p{L}\p{M}])/giu
    ]
  },
  {
    id: 'URGENCY',
    weight: 1,
    description: 'Artificial time pressure and coercive urgency markers',
    patterns: [
      /\bturant\b/gi,
      /\bjaldi\b/gi,
      /\babhi\s+ke\s+abhi\b/gi,
      /\baaj\s+hi\b/gi,
      /\b24\s+ghante(?:\s+mein)?\b/gi,
      /\baakhri\s+tarikh\s+aaj\b/gi,
      /\bimmediately\b/gi,
      /\burgent\b/gi,
      /\bwithin\s+2\s+hours\b/gi,
      /\blast\s+chance\b/gi,
      /\bact\s+now\b/gi,
      // Devanagari (Hindi) — urgency markers with common anusvara/nukta variants
      /(?<![\p{L}\p{M}])(?:तुरंत|तुरन्त|फ़ौरन|फौरन|जल्दी|अभी(?:\s+के\s+अभी)?|आज\s+ही)(?![\p{L}\p{M}])/giu,
      /(?:[0-9०-९]{1,2}\s+घंटे\s+के\s+(?:अंदर|भीतर))|(?:आखिरी\s+(?:मौका|तारीख(?:\s+आज)?))|(?:अंतिम\s+तारीख\s+आज)/giu
    ]
  },
  {
    id: 'KYC_LURE',
    weight: 2,
    description: 'Threat of service cancellation or KYC expiration',
    patterns: [
      /\bkyc\s+(?:aaj\s+)?(?:update|expire|pending|band|verification(?:\s+required)?)\b/gi,
      /\bpan\s+card\s+update\b/gi,
      /\baadhaar\s+link\b/gi,
      /\baccount\s+freeze(?:\s+hoga)?\b/gi,
      // Devanagari (Hindi) — KYC expiry / account freeze threats.
      // Mixed-script aware: Latin "KYC/PAN/Aadhaar" and transliterated केवाईसी/पैन/आधार both handled.
      /(?:केवाईसी|kyc)[^।॥.!?\n\r]{0,25}(?:अपडेट|अधूरी|पेंडिंग|समाप्त|एक्सपायर|बंद|नवीनीकरण)/giu,
      /(?:अपडेट|नवीनीकरण|लिंक)\s+कराएं|केवाईसी\s+(?:पूरी|करें)/giu,
      /(?:खाता|खाते)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,25}(?:फ्रीज|ब्लॉक|बंद)/giu,
      /(?:आधार|पैन\s+कार्ड)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,20}लिंक/giu
    ]
  },
  {
    id: 'FEAR',
    weight: 2,
    description: 'Intimidation via account blocking, police, or legal threats',
    patterns: [
      /\baccount\s+band(?:\s+ho\s+jayega)?\b/gi,
      /\b(?:account|sim)\s+block\b/gi,
      /\bblock\b/gi,
      /\blegal\s+action\b/gi,
      /\barrest\b/gi,
      /\bpolice\s+case\b/gi,
      /\bfir\b/gi,
      /\bsim\s+band\b/gi,
      /\bdigital\s+arrest\b/gi,
      /\bpenalty\s+lagega\b/gi,
      /\bsupply\s+band\b/gi,
      /\bpower\s+cut(?:\s+tonight)?\b/gi,
      /\bbijli\s+(?:cut|band)\b/gi,
      /\b(?:electricity|power|gas)\s+(?:supply\s+)?will\s+be\s+disconnected\b/gi,
      /\bdisconnection\s+of\s+(?:electricity|power|gas|utility)\b/gi,
      // Devanagari (Hindi) — intimidation: account/SIM block, legal action, arrest, utility cut.
      /(?:खाता|सिम\s+कार्ड|कनेक्शन)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,20}(?:बंद|ब्लॉक)/giu,
      /(?:बंद\s+कर\s+दिया\s+जाएगा|ब्लॉक\s+कर\s+दिया\s+जाएगा)/giu,
      /(?:कानूनी\s+(?:कार्रवाई|कार्यवाई)|गिरफ्तारी(?:\s+वारंट)?|पुलिस\s+केस|एफआईआर\s+दर्ज|न्यायालय\s+में)/giu,
      /(?:कार्रवाई|कार्यवाई)\s+होगी|कार्रवाई\s+की\s+जाएगी/giu,
      /(?:बिजली|विद्युत)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,25}(?:कट|बंद|विच्छेद|बाधित)/giu,
      /(?:आपूर्ति|लाइन)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,15}(?:बंद|बाधित|कट)/giu,
      /(?:विच्छेदित|विच्छेद)\s+की\s+जा\s+रही|कटौती\s+कर\s+दी\s+जाएगी/giu
    ]
  },
  {
    id: 'FAKE_REWARD',
    weight: 2,
    description: 'Unsolicited prize, lottery, or cashback claims',
    patterns: [
      /\blottery\b/gi,
      /\bjeet\s+gaye\b/gi,
      /\bprize\b/gi,
      /\bcashback\b/gi,
      /\breward\s+points\s+expire\b/gi,
      /\bgift\s+voucher\b/gi,
      /\bkbc\b/gi,
      /\bcongratulations(?:\s+you\s+won)?\b/gi,
      // Devanagari (Hindi) — lottery / prize / winner lures
      /(?:लॉटरी|लकी\s+ड्रा|कीमती\s+इनाम)/giu,
      /(?:जीत(?:े|ी|ा)\s+(?:गए|गई|है)|विजेता\s+चुने\s+गए|इनाम\s+जीता)/giu,
      /(?:बधाई(?:\s+हो)!?)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,30}(?:जीत|इनाम|पुरस्कार|पारितोषिक)/giu,
      /(?:नकद\s+पुरस्कार|कैश\s+प्राइज|केबीसी)/giu
    ]
  },
  {
    id: 'JOB_FEE',
    weight: 3,
    description: 'Advance fee work-from-home tasks or fake job deposits',
    patterns: [
      /\bregistration\s+fee\b/gi,
      /\bjoining\s+fee\b/gi,
      // Require payment/deposit context or job/work context within sentence for security deposit
      /\b(?:pay|deposit|jama\s+karein|bharein|bhejein)\b[^.!?\n\r]{0,35}\b(?:refundable\s+)?security\s+deposit\b/gi,
      /\b(?:refundable\s+)?security\s+deposit\b[^.!?\n\r]{0,35}\b(?:required|mandatory|needed|pay|deposit|jama\s+karein|bharein|bhejein|dena\s+hoga)\b/gi,
      /\b(?:work\s+from\s+home|part\s+time(?:\s+job)?|typing\s+job|data\s+entry)\b[^.!?\n\r]{0,40}\b(?:refundable\s+)?security\s+deposit\b/gi,
      /\b(?:refundable\s+)?security\s+deposit\b[^.!?\n\r]{0,40}\b(?:work\s+from\s+home|part\s+time(?:\s+job)?|typing\s+job|data\s+entry)\b/gi,
      /\bwork\s+from\s+home\b/gi,
      /\bpart\s+time\s+job\b/gi,
      /\bdaily\s+earning\b/gi,
      /\bdata\s+entry\s+job\b/gi,
      /\bpehle\s+paise\s+bhejein\b/gi,
      // Devanagari (Hindi) — fake job / registration fee / security deposit
      /(?:पंजीकरण\s+शुल्क|रजिस्ट्रेशन\s+फीस|जॉइनिंग\s+फीस)/giu,
      /(?:घर\s+बैठे\s+काम|वर्क\s+फ्रॉम\s+होम)/giu,
      /(?:भर्ती|नौकरी)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,35}(?:शुल्क|फीस|फर्जी)/giu,
      /(?:शुल्क|फीस)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,25}(?:जमा\s+करें|अदा\s+करें|भरें)/giu,
      /(?:सिक्योरिटी\s+डिपॉजिट|सुरक्षा\s+जमा\s+राशि)/giu,
      /(?:पहले\s+पैसे\s+भेजें|पैसा\s+जमा\s+करना\s+होगा)/giu
    ]
  },
  {
    id: 'IMPERSONATION',
    weight: 2,
    description: 'Pretends to represent an official regulatory or law enforcement agency',
    patterns: [
      /\brbi\b/gi,
      /\bcbi\b/gi,
      /\bcustoms\b/gi,
      /\btrai\b/gi,
      /\bincome\s+tax\s+department\b/gi,
      /\bbank\s+manager\b/gi,
      /\bcourier\s+company\b/gi,
      /\bbijli\s+vibhag\b/gi,
      /\bpolice\s+officer(?:\s+bol\s+raha\s+hu)?\b/gi,
      /\bsecurity\s+dept(?:artment)?\b/gi,
      /\bcyber\s+crime\s+(?:cell|branch|desk)\b/gi,
      /\b(?:customs\s+)?clearance\s+desk\b/gi,
      // Devanagari (Hindi) — authority impersonation (agency names in native script)
      /(?:भारतीय\s+रिज़र्व\s+बैंक|रिजर्व\s+बैंक|केंद्रीय\s+जांच\s+ब्यूरो|सीबीआई|प्रवर्तन\s+निदेशालय|आयकर\s+विभाग|दूरसंचार\s+विभाग|ट्राई|साइबर\s+क्राइम\s+(?:सेल|पुलिस)|नारकोटिक्स\s+कंट्रोल\s+ब्यूरो)/giu,
      /(?:सीमा\s+शुल्क|कस्टम्स)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,20}(?:विभाग|अधिकारी|कार्यालय|डेस्क)/giu,
      /(?:पुलिस\s+अधिकारी|बैंक\s+मैनेजर|जांच\s+अधिकारी|कूरियर\s+कंपनी|बिजली\s+विभाग)/giu
    ]
  },
  {
    id: 'LOAN_FEE',
    weight: 2,
    description: 'Instant or pre-approved loan requiring advance processing charges',
    patterns: [
      /\bpre-approved\s+loan\b/gi,
      /\bprocessing\s+fee\s+advance\b/gi,
      /\bloan\s+turant\s+approve\b/gi,
      /\bno\s+documents\s+loan\b/gi,
      // Devanagari (Hindi) — instant loan with upfront fee
      /(?:तत्काल\s+(?:ऋण|लोन)|आपातकालीन\s+क्रेडिट\s+सीमा|बिना\s+दस्तावेज़\s+ऋण|बिना\s+किसी\s+दस्तावेज़)/giu,
      /(?:ऋण|लोन|क्रेडिट\s+सीमा)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,45}(?:स्वीकृत|मंज़ूर|पास|मिलने)/giu,
      /(?:एग्रीमेंट\s+फीस|प्रोसेसिंग\s+शुल्क|फाइल\s+(?:चार्ज|शुल्क)|बीमा\s+शुल्क|स्टांप\s+(?:ड्यूटी|टैक्स))/giu
    ]
  },
  {
    id: 'UPI_COLLECT',
    weight: 3,
    description: 'Tricks victim into approving collect requests or entering PIN to receive funds',
    patterns: [
      /\bcollect\s+request(?:\s+accept\s+karein)?\b/gi,
      /\bpaise\s+receive\s+karne\s+ke\s+liye\s+pin\s+daalein\b/gi,
      /\brefund\s+ke\s+liye\s+upi\s+pin\b/gi,
      /\bqr\s+scan\s+karke\s+paise\s+pao\b/gi,
      /\bpin\s+daalein\b/gi,
      // Devanagari (Hindi) — UPI collect / PIN-to-receive traps
      /(?:पैसे\s+पाने|राशि\s+पाने|पैसे\s+प्राप्त\s+करने|रिफंड\s+पाने)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,30}(?:पिन|भुगतान\s+पिन)/giu,
      /(?:यूपीआई\s+पिन|पिन\s+दर्ज\s+करें|पिन\s+डालें)/giu,
      /(?:कलेक्ट\s+रिक्वेस्ट|स्कैन\s+करके\s+पैसे)/giu,
      /(?:पिन\s+लगाकर|पिन\s+डालकर)[^।॥.!?\n\r]{0,25}(?:पैसे|राशि|रिफंड)/giu
    ]
  },
  {
    id: 'ADVANCE_FEE',
    weight: 3,
    description: 'Advance fee demands for courier, loan, customs, or document clearance',
    patterns: [
      // 1. Payment verb + within-sentence gap (max 40 chars) + fee type + gap + precondition
      /\b(?:pay|deposit|remit|clear|settle)\b[^.!?\n\r]{0,40}\b(?:documentation|stamp(?:ing)?|statutory|legal|handling|transit|insurance|gate\s+pass|import|tariff|clearance|processing|file|agreement|registration|release|activation|unlock|verification|customs)\s*(?:and\s+[a-z]+\s+)?(?:charge|fee|duty|tax|payment)s?\b[^.!?\n\r]{0,40}\b(?:to\s+(?:release|dispatch|handover|proceed|activate|unlock|disburse)|before\s+(?:package\s+)?(?:handover|dispatch|delivery|disbursal)|must\s+be\s+cleared\s+before)\b/gi,
      // 2. Fee type + within-sentence gap + payment verb + gap + precondition (Hinglish/English)
      /\b(?:documentation|stamp(?:ing)?|statutory|legal|handling|transit|insurance|gate\s+pass|import|tariff|clearance|processing|file|agreement|registration|release|activation|unlock|verification|customs)\s*(?:and\s+[a-z]+\s+)?(?:charge|fee|duty|tax|payment)s?\b[^.!?\n\r]{0,40}\b(?:jama\s+karein|bharein|bhejein|pay\s+karein|pay|deposit)\b[^.!?\n\r]{0,40}\b(?:to\s+(?:release|activate|unlock|proceed|dispatch)|before\s+disbursal|disbursal\s+(?:pane|lene)\s+ke\s+liye)\b/gi,
      // 3. Fee type + within-sentence gap + precondition
      /\b(?:documentation|stamp(?:ing)?|statutory|legal|handling|transit|insurance|gate\s+pass|import|tariff|clearance|processing|file|agreement|registration|release|activation|unlock|verification|customs)\s*(?:and\s+[a-z]+\s+)?(?:charge|fee|duty|tax|payment)s?\b[^.!?\n\r]{0,40}\b(?:must\s+be\s+cleared|before\s+(?:package\s+)?(?:handover|dispatch|delivery|disbursal)|to\s+(?:release|activate|unlock|proceed|dispatch))\b/gi,
      // 4. Precondition + within-sentence gap + fee type + gap + payment verb
      /\b(?:disbursal\s+(?:pane|lene)\s+ke\s+liye)\b[^.!?\n\r]{0,40}\b(?:documentation|stamp(?:ing)?|statutory|legal|handling|transit|insurance|gate\s+pass|import|tariff|clearance|processing|file|agreement|registration|release|activation|unlock|verification|customs)\s*(?:and\s+[a-z]+\s+)?(?:charge|fee|duty|tax|payment)s?\b[^.!?\n\r]{0,40}\b(?:jama\s+karein|bharein|bhejein|pay|deposit)\b/gi,
      // 5. Classic pay customs/clearance/processing fee
      /\b(?:pay|deposit|clear)\b[^.!?\n\r]{0,40}\b(?:customs\s+duty|clearance\s+(?:fee|charge|tax)|file\s+(?:fee|charge|processing)|processing\s+(?:fee|charge)|agreement\s+fee|release\s+fee|disbursal\s+fee|registration\s+(?:fee|charge))\b/gi,
      // Devanagari (Hindi) — advance fee to release parcel / disburse loan.
      // Pair: release/precondition term + bounded gap + fee term + gap + pay verb (any order covered by three patterns).
      /(?:रिहाई|रिलीज|अनब्लॉक|छुड़ाने|छुड़ाएं|वितरण\s+से\s+पहले|पहले)[^।॥.!?\n\r]{0,40}(?:शुल्क|फीस|ड्यूटी|टैक्स|चार्ज)[^।॥.!?\n\r]{0,25}(?:जमा|अदा|भरें|भुगतान|दें)/giu,
      /(?:शुल्क|फीस|ड्यूटी|टैक्स|चार्ज)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,30}(?:जमा\s+करें|अदा\s+करें|भरें|जमा\s+करना\s+होगा|देना\s+होगा)/giu,
      /(?:पार्सल|कंसाइनमेंट|कोरियर|पैकेट)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,40}(?:रोक|होल्ड|अटक)/giu
    ]
  },
  {
    id: 'UNSOLICITED_REFUND',
    weight: 2,
    description: 'Unsolicited refund, subsidy, or mistaken credit lures requiring user action',
    patterns: [
      // 1. Benefit lure + within-sentence gap (max 45 chars, strictly within-sentence) + Action request
      /\b(?:refund|overpayment|excess\s+(?:tds|amount|balance|surcharge|meter\s+surcharge|money)?|subsidy(?:\s+voucher)?|installment|voucher|reimbursement|rebate|(?:by\s+mistake|galti\s+se)\s+(?:sent|transferred|bheja|bhej\s+diye)|extra\s+money)\b[^.!?\n\r]{0,45}\b(?:(?:submit|verify|update|confirm)\s+(?:your\s+)?(?:verified\s+)?(?:bank(?:ing)?\s+(?:account\s+)?(?:details|profile)|account|a\/?c|savings\s+account|receipt)|(?:bank(?:ing)?\s+(?:account\s+)?(?:details|profile)|account|a\/?c)\s+(?:submit|verify|update|confirm)\s*(?:karein|kare)?|claim\s*(?:karein|kare)?|return\s+(?:the\s+)?(?:extra|excess)?\s*(?:money|amount)?|send\s+back|refund\s+the\s+extra\s+money|wapas\s+(?:karein|bhejein))\b/gi,
      // 2. Action request + within-sentence gap + Benefit lure
      /\b(?:(?:submit|verify|update|confirm)\s+(?:your\s+)?(?:verified\s+)?(?:bank(?:ing)?\s+(?:account\s+)?(?:details|profile)|account|a\/?c|savings\s+account|receipt)|(?:bank(?:ing)?\s+(?:account\s+)?(?:details|profile)|account|a\/?c)\s+(?:submit|verify|update|confirm)\s*(?:karein|kare)?|claim|return)\b[^.!?\n\r]{0,45}\b(?:refund|overpayment|excess\s+(?:tds|amount|balance|money)?|subsidy|installment|voucher|reimbursement|rebate|extra\s+money|(?:direct\s+)?credit)\b/gi,
      // 3. Reverse transfer / mistaken credit request
      /\b(?:please\s+)?(?:refund|return|send\s+back)\b[^.!?\n\r]{0,35}\b(?:extra\s+money|excess\s+amount|it\s+via\s+(?:the\s+)?refund\s+link)\b/gi,
      // 4. Hinglish reverse-transfer / subsidy claim within sentence
      /\b(?:bank\s+a\/?c|account|bank\s+details)\s+verify\s+karke\s+(?:amount\s+)?claim\s+karein\b/gi,
      /\b(?:submit|verify)\s+bank\s+(?:account\s+)?details\s+to\s+claim\b/gi,
      // Devanagari (Hindi) — refund/subsidy lure + user action pair, and mistaken-credit reversal.
      /(?:रिफंड|सब्सिडी|प्रोत्साहन\s+राशि|वापसी|समायोजन|अतिरिक्त\s+(?:राशि|टैक्स|पैसे)|राशि\s+वापस)(?![\p{L}\p{M}])[^।॥.!?\n\r]{0,50}(?:स्वीकृत|मंज़ूर|प्राप्त|पाने|क्लेम|देने|लेने)/giu,
      /(?:गलती\s+से|भूल\s+से|अनजाने\s+में)[^।॥.!?\n\r]{0,40}(?:भेज|ट्रांसफर|जमा|आए|आये)/giu,
      /(?:खाता\s+नंबर|बैंक\s+विवरण|पासबुक|खाते\s+में\s+जमा)[^।॥.!?\n\r]{0,35}(?:करवाने|भेजें|साझा|शेयर|बताएं|व्हाट्सएप)/giu,
      /(?:राशि|पैसे)\s+वापस\s+(?:करें|भेजें|लौटाएं)/giu
    ]
  }
];

/**
 * Finds sentence spans in the text that contain negation guard phrases.
 * A negation guard in sentence A must NOT negate rules in sentence B.
 * @param {string} text 
 * @returns {Array<{ start: number, end: number }>}
 */
function findNegatedSentences(text) {
  const negatedSpans = [];
  // Split on sentence terminators: periods, exclamation marks, question marks, newlines, and Hindi danda (।) and double danda (॥)
  const sentenceRegex = /[^.!?।॥\n\r]+[.!?।॥\n\r]*/gu;
  let match;

  while ((match = sentenceRegex.exec(text)) !== null) {
    const sentenceText = match[0].toLowerCase();
    const sentenceStart = match.index;
    const sentenceEnd = sentenceStart + match[0].length;

    const hasNegation = NEGATION_GUARD_PHRASES.some(phrase => sentenceText.includes(phrase));
    if (hasNegation) {
      negatedSpans.push({ start: sentenceStart, end: sentenceEnd });
    }
  }

  return negatedSpans;
}

function findCompletedCreditSentences(text) {
  const spans = [];
  const sentenceRegex = /[^.!?।॥\n\r]+[.!?।॥\n\r]*/gu;
  let match;

  while ((match = sentenceRegex.exec(text)) !== null) {
    const sentenceText = match[0].toLowerCase();
    const sentenceStart = match.index;
    const sentenceEnd = sentenceStart + match[0].length;

    const hasCompletedCredit = COMPLETED_CREDIT_GUARD_PHRASES.some(phrase => sentenceText.includes(phrase));
    if (hasCompletedCredit) {
      spans.push({ start: sentenceStart, end: sentenceEnd });
    }
  }

  return spans;
}

function findCompletedDebitCreditSentences(text) {
  const spans = [];
  const sentenceRegex = /[^.!?।॥\n\r]+[.!?।॥\n\r]*/gu;
  let match;

  while ((match = sentenceRegex.exec(text)) !== null) {
    const sentenceText = match[0].toLowerCase();
    const sentenceStart = match.index;
    const sentenceEnd = sentenceStart + match[0].length;

    const hasCompletedDebitCredit = COMPLETED_DEBIT_CREDIT_GUARD_PHRASES.some(phrase => sentenceText.includes(phrase));
    if (hasCompletedDebitCredit) {
      spans.push({ start: sentenceStart, end: sentenceEnd });
    }
  }

  return spans;
}

function findAdvisorySentences(text) {
  const spans = [];
  const sentenceRegex = /[^.!?।॥\n\r]+[.!?।॥\n\r]*/gu;
  let match;

  while ((match = sentenceRegex.exec(text)) !== null) {
    const sentenceText = match[0].toLowerCase();
    const sentenceStart = match.index;
    const sentenceEnd = sentenceStart + match[0].length;

    const hasAdvisory = ADVISORY_GUARD_PHRASES.some(phrase => sentenceText.includes(phrase.toLowerCase()));
    if (hasAdvisory) {
      spans.push({ start: sentenceStart, end: sentenceEnd });
    }
  }

  return spans;
}

/**
 * Executes all detection rules across the text.
 * @param {string} text - Original input text
 * @returns {Array<{ ruleId: string, weight: number, start: number, end: number, text: string }>}
 */
export function matchRules(text) {
  if (!text || typeof text !== 'string') return [];

  const indicators = [];
  const negatedSpans = findNegatedSentences(text);
  const completedCreditSpans = findCompletedCreditSentences(text);
  const completedDebitCreditSpans = findCompletedDebitCreditSentences(text);
  const advisorySpans = findAdvisorySentences(text);

  for (const rule of RULE_DEFINITIONS) {
    for (const pattern of rule.patterns) {
      // Reset state for global regexes
      pattern.lastIndex = 0;
      let match;

      while ((match = pattern.exec(text)) !== null) {
        const start = match.index;
        const end = start + match[0].length;
        const matchedSubstring = text.substring(start, end);

        // If rule is OTP_REQUEST or SENSITIVE_INFO_REQUEST and the match falls within a negated sentence, skip it
        if (rule.id === 'OTP_REQUEST' || rule.id === 'SENSITIVE_INFO_REQUEST') {
          const isNegated = negatedSpans.some(span => start >= span.start && end <= span.end);
          if (isNegated) {
            continue;
          }
        }

        // If rule is URGENCY and falls within an advisory sentence or negated sentence, skip it
        if (rule.id === 'URGENCY') {
          const isGuarded = advisorySpans.some(span => start >= span.start && end <= span.end) ||
                            negatedSpans.some(span => start >= span.start && end <= span.end);
          if (isGuarded) {
            continue;
          }
        }

        // If rule is UNSOLICITED_REFUND or JOB_FEE and falls within a completed-credit sentence, skip it
        if (rule.id === 'UNSOLICITED_REFUND' || rule.id === 'JOB_FEE') {
          const isCompletedCredit = completedCreditSpans.some(span => start >= span.start && end <= span.end);
          if (isCompletedCredit) {
            continue;
          }
        }

        // If rule is ADVANCE_FEE and falls within a completed debit/credit sentence, skip it
        if (rule.id === 'ADVANCE_FEE') {
          const isCompletedDebitCredit = completedDebitCreditSpans.some(span => start >= span.start && end <= span.end);
          if (isCompletedDebitCredit) {
            continue;
          }
        }


        // Avoid duplicate overlapping spans for the same rule
        const alreadyFound = indicators.some(
          ind => ind.ruleId === rule.id && Math.max(ind.start, start) < Math.min(ind.end, end)
        );

        if (!alreadyFound) {
          indicators.push({
            ruleId: rule.id,
            weight: rule.weight,
            start,
            end,
            text: matchedSubstring
          });
        }
      }
    }
  }

  // Sort indicators by start position ascending
  return indicators.sort((a, b) => a.start - b.start);
}

/**
 * Suppresses KYC_LURE if the message is a genuine branch advisory:
 * 1. Instructs the user to visit or go to a branch (English or Hinglish)
 * 2. Contains NO URLs (neither in message nor explicit)
 * 3. Contains NO OTP, PIN, or card credential requests
 * 
 * @param {Array<object>} indicators
 * @param {string} text
 * @param {Array<object>} urlEvidence
 * @returns {Array<object>} Filtered indicators
 */
export function suppressKycBranchReminders(indicators, text, urlEvidence) {
  if (!indicators.some(i => i.ruleId === 'KYC_LURE')) {
    return indicators;
  }

  // Condition 1: Must contain NO URLs
  if (Array.isArray(urlEvidence) && urlEvidence.length > 0) {
    return indicators;
  }

  // Condition 2: Must contain NO OTP, PIN, or card credential requests
  const hasCredentialRequest = indicators.some(
    i => i.ruleId === 'OTP_REQUEST' || i.ruleId === 'SENSITIVE_INFO_REQUEST'
  );
  if (hasCredentialRequest) {
    return indicators;
  }

  // Additional check against raw credential request phrases in text
  const credentialActionRegex = /\b(?:share|send|enter|tell|bhejein|batayein)\s+(?:your\s+)?(?:otp|pin|cvv|card|password)\b/i;
  if (credentialActionRegex.test(text)) {
    return indicators;
  }

  // Condition 3: Must instruct physical branch visit in English or Hinglish (strictly bounded)
  const branchVisitRegex = /\b(?:(?:please\s+|kripya\s+)?(?:visit|go\s+to|reach|walk\s+in\s+to|visiting)\s+(?:[a-zA-Z\s]{0,30}\s+)?branch\b|\b(?:[a-zA-Z\s]{0,20}\s+)?branch\s*(?:me|mein|par)?\s*(?:visit\s+karein|visit\s+kare|jayein|jaayein|jao|sampark\s+karein)\b)/i;

  if (!branchVisitRegex.test(text)) {
    return indicators;
  }

  // Suppress KYC_LURE
  return indicators.filter(i => i.ruleId !== 'KYC_LURE');
}


