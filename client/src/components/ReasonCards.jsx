import React from 'react';
import { AlertCircle, AlertTriangle, Info } from 'lucide-react';

// Template string to rule ID lookup table for accurate forensic attribution
const TEMPLATE_TO_RULE = {
  // OTP_REQUEST
  'The message asks you to share an OTP. Banks never ask for it.': 'OTP_REQUEST',
  'Is message mein OTP maanga ja raha hai. Bank kabhi OTP nahi maangta.': 'OTP_REQUEST',
  'संदेश में आपका गुप्त ओटीपी, पासवर्ड या पिन मांगा जा रहा है।': 'OTP_REQUEST',
  // SENSITIVE_INFO_REQUEST
  'The message asks you to send sensitive personal credentials (like SIM number or Aadhaar). Never send identity details over SMS or chat.': 'SENSITIVE_INFO_REQUEST',
  'Is message mein SIM number ya Aadhaar jaisi sensitive details maangi ja rahi hain. Aisi details SMS ya chat par kabhi na bhejein.': 'SENSITIVE_INFO_REQUEST',
  'एसएमएस के जवाब में आधार, पैन या सिम कार्ड जैसे निजी दस्तावेज मांगे जा रहे हैं।': 'SENSITIVE_INFO_REQUEST',
  // URGENCY
  'It pushes you to act immediately.': 'URGENCY',
  'Ye aapko turant action lene ke liye daba raha hai.': 'URGENCY',
  'संदेश में तुरंत कार्रवाई करने का अनुचित दबाव बनाया जा रहा है।': 'URGENCY',
  // KYC_LURE
  'It uses a KYC expiry threat, a common scam pretext.': 'KYC_LURE',
  'Ye KYC expire hone ka darr dikha raha hai, jo common scam trick hai.': 'KYC_LURE',
  'केवाईसी समाप्त होने या खाता फ्रीज होने का डर दिखाकर फंसाने का प्रयास है।': 'KYC_LURE',
  // FEAR
  'It threatens account blocking or legal action.': 'FEAR',
  'Ye account band hone ya legal action ki dhamki de raha hai.': 'FEAR',
  'खाता बंद करने, बिजली काटने या कानूनी कार्रवाई की धमकी दी जा रही है।': 'FEAR',
  // FAKE_REWARD
  'It promises a prize or reward you did not ask for.': 'FAKE_REWARD',
  'Ye bina maange inaam ya reward ka lalach de raha hai.': 'FAKE_REWARD',
  'लॉटरी, इनाम या अप्रत्याशित कैशबैक का झांसा दिया जा रहा है।': 'FAKE_REWARD',
  // JOB_FEE
  'It asks for money upfront for a job.': 'JOB_FEE',
  'Ye job ke liye pehle paise maang raha hai. Asli job mein aisa nahi hota.': 'JOB_FEE',
  'घर बैठे काम या नौकरी के नाम पर पहले पैसे या पंजीकरण शुल्क मांगा जा रहा है।': 'JOB_FEE',
  // IMPERSONATION
  'It pretends to be an official authority.': 'IMPERSONATION',
  'Ye kisi sarkari/bank adhikari ban kar बात kar raha hai.': 'IMPERSONATION',
  'Ye kisi sarkari/bank adhikari ban kar baat kar raha hai.': 'IMPERSONATION',
  'बैंक, सरकारी विभाग, पुलिस या कूरियर अधिकारी होने का झूठा ढोंग किया जा रहा है।': 'IMPERSONATION',
  // DECEPTIVE_LINK
  'The link looks suspicious (see evidence).': 'DECEPTIVE_LINK',
  'Link shak wala lag raha hai (evidence dekhein).': 'DECEPTIVE_LINK',
  'संदेश में दिया गया लिंक संदिग्ध या भ्रामक लग रहा है।': 'DECEPTIVE_LINK',
  // LOAN_FEE
  'It offers an instant or pre-approved loan requiring advance processing fees.': 'LOAN_FEE',
  'Ye bina documents turant loan ka lalach dekar advance processing fee maang raha hai.': 'LOAN_FEE',
  'आसान ऋण देने के बहाने पहले फाइल चार्ज या प्रोसेसिंग फीस मांगी जा रही है।': 'LOAN_FEE',
  // UPI_COLLECT
  'It tricks you into entering a UPI PIN to receive money or accept a collect request.': 'UPI_COLLECT',
  'Paise paane ke naam par UPI PIN daalne ya collect request accept karne ko bol raha hai. Paise lene ke liye PIN nahi lagta.': 'UPI_COLLECT',
  'पैसे पाने के नाम पर यूपीआई पिन डालने या कलेक्ट रिक्वेस्ट स्वीकार करने को कहा जा रहा है।': 'UPI_COLLECT',
  // ADVANCE_FEE
  'It demands advance fees or taxes to release a loan, courier package, or customs shipment.': 'ADVANCE_FEE',
  'Ye parcel, loan ya customs release karane ke liye advance paise ya tax maang raha hai.': 'ADVANCE_FEE',
  'पार्सल छुड़ाने, ऋण जारी करने या सेवा शुरू करने हेतु पहले शुल्क मांगा जा रहा है।': 'ADVANCE_FEE',
  // UNSOLICITED_REFUND
  'It offers an unexpected refund or subsidy requiring you to submit bank details or claim funds.': 'UNSOLICITED_REFUND',
  'Ye bina maange refund ya subsidy ka lalach dekar bank details verify karne ya claim karne ko bol raha hai.': 'UNSOLICITED_REFUND',
  'गलती से पैसे आने या सब्सिडी/रिफंड का झांसा देकर बैंक विवरण मांगे जा रहे हैं।': 'UNSOLICITED_REFUND'
};

/**
 * ReasonCards component:
 * Displays plain-language explanation cards detailing why specific red flags were raised.
 * Supports English, Hinglish, and graceful fallback with a disclaimer badge when Hindi is selected.
 * 
 * Props:
 * - explanation: { en: string[], hi: string[], hinglish: string[] }
 * - lang: 'hinglish' | 'en' | 'hi'
 * - indicators: Array<{ ruleId: string, text: string }>
 */
export default function ReasonCards({ explanation, lang = 'hinglish', indicators = [] }) {
  if (!explanation) return null;

  // Determine lines to display based on active language
  let lines = explanation[lang] || [];
  let isHindiFallback = false;

  if (lang === 'hi' && (!lines || lines.length === 0)) {
    // Graceful fallback to English with advisory banner per spec
    lines = explanation.en || [];
    isHindiFallback = true;
  }

  // If genuine or no explanations, show calm empty state
  if (!lines || lines.length === 0) {
    return (
      <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 text-slate-600 text-sm flex items-center gap-3">
        <Info className="w-5 h-5 text-teal-600 shrink-0" />
        <span>No specific scam triggers or manipulative patterns detected in the analyzed text.</span>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-semibold text-slate-900 flex items-center gap-2">
          <AlertCircle className="w-5 h-5 text-rose-600" />
          <span>Why this was flagged ({lines.length} {lines.length === 1 ? 'reason' : 'reasons'})</span>
        </h3>
        {lang === 'hi' && !isHindiFallback && (
          <span className="text-xs bg-amber-100 text-amber-900 border border-amber-300 px-2.5 py-0.5 rounded-full font-medium inline-flex items-center gap-1">
            <span>⚠️ अप्रमाणित अनुवाद / Unreviewed Hindi</span>
          </span>
        )}
        {isHindiFallback && (
          <span className="text-xs bg-amber-100 text-amber-800 border border-amber-200 px-2.5 py-0.5 rounded-full font-medium">
            Hindi explanation unavailable (showing English)
          </span>
        )}
      </div>

      {lang === 'hi' && !isHindiFallback && (
        <div className="text-xs text-amber-900 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 leading-relaxed">
          <strong>भाषाई सूचना:</strong> नीचे दिए गए हिंदी विवरण अप्रमाणित प्रारूप हैं और किसी भाषा विशेषज्ञ द्वारा अंतिम रूप से सत्यापित नहीं हैं। (Hindi explanations are provisional unreviewed drafts).
        </div>
      )}


      <div className="grid gap-3">
        {lines.map((text, idx) => {
          // Accurately resolve ruleId and matching indicators for this specific reason
          const ruleId = TEMPLATE_TO_RULE[text] || null;
          const matchingIndicators = ruleId ? indicators.filter(i => i.ruleId === ruleId) : [];
          const uniquePhrases = Array.from(new Set(matchingIndicators.map(i => i.text)));

          return (
            <div 
              key={idx} 
              className="bg-white border border-rose-100 shadow-xs rounded-xl p-4 flex items-start gap-3.5 transition-all hover:border-rose-200"
            >
              <div className="mt-0.5 w-6 h-6 rounded-full bg-rose-50 text-rose-600 flex items-center justify-center shrink-0">
                <AlertTriangle className="w-3.5 h-3.5" />
              </div>

              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-slate-800 leading-snug">
                  {text}
                </p>

                {uniquePhrases.length > 0 && (
                  <div className="mt-2 text-xs text-slate-500 flex items-center gap-1.5 flex-wrap">
                    <span className="font-semibold text-slate-600">
                      {uniquePhrases.length === 1 ? 'Matched phrase:' : 'Matched phrases:'}
                    </span>
                    {uniquePhrases.map((phrase, pIdx) => (
                      <span key={pIdx} className="bg-rose-50 border border-rose-200 text-rose-900 px-2 py-0.5 rounded font-mono">
                        "{phrase}"
                      </span>
                    ))}
                    {ruleId && (
                      <span className="text-slate-400">({ruleId})</span>
                    )}
                  </div>
                )}

                {ruleId === 'DECEPTIVE_LINK' && uniquePhrases.length === 0 && (
                  <div className="mt-2 text-xs text-slate-500 italic flex items-center gap-1.5">
                    <span>Identified via offline URL heuristic inspection (see evidence ledger below).</span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

    </div>
  );
}

