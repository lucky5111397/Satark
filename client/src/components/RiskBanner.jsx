import React from 'react';
import { AlertTriangle, AlertCircle, ShieldCheck } from 'lucide-react';

export default function RiskBanner({ category, score }) {
  if (category === 'Suspicious') {
    return (
      <div
        className="w-full rounded-xl bg-[#FFDAD6] border border-[#BA1A1A]/30 p-5 sm:p-6 text-[#93000A] shadow-xs"
        role="alert"
        aria-live="assertive"
      >
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-full bg-[#BA1A1A] text-white flex items-center justify-center shrink-0">
            <AlertTriangle className="w-6 h-6" aria-hidden="true" />
          </div>
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs uppercase font-extrabold tracking-wider bg-[#BA1A1A] text-white px-2.5 py-0.5 rounded-full">
                High Risk • Suspicious
              </span>
              <span className="text-xs font-semibold text-[#93000A]/80">
                Risk Score: {score}
              </span>
            </div>
            <h2 className="text-lg sm:text-xl font-bold tracking-tight">
              Preliminary category: Suspicious
            </h2>
            <p className="text-xs sm:text-sm text-[#93000A]/90 leading-relaxed">
              Multiple critical scam signals identified in communication structure. Do not click links, share OTPs, or send money.
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (category === 'Caution') {
    return (
      <div
        className="w-full rounded-xl bg-[#FDF6E2] border border-[#B7791F]/30 p-5 sm:p-6 text-[#744210] shadow-xs"
        role="alert"
        aria-live="polite"
      >
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-full bg-[#B7791F] text-white flex items-center justify-center shrink-0">
            <AlertCircle className="w-6 h-6" aria-hidden="true" />
          </div>
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs uppercase font-extrabold tracking-wider bg-[#B7791F] text-white px-2.5 py-0.5 rounded-full">
                Moderate Risk • Caution
              </span>
              <span className="text-xs font-semibold text-[#744210]/80">
                Risk Score: {score}
              </span>
            </div>
            <h2 className="text-lg sm:text-xl font-bold tracking-tight">
              Preliminary category: Caution
            </h2>
            <p className="text-xs sm:text-sm text-[#744210]/90 leading-relaxed">
              Unverified patterns or urgency detected. Verify sender identity via your official mobile banking application before taking action.
            </p>
          </div>
        </div>
      </div>
    );
  }

  // Default: 'No known red flags found'
  return (
    <div
      className="w-full rounded-xl bg-[#E8F5F1] border border-[#0F6B5E]/30 p-5 sm:p-6 text-[#00201B] shadow-xs"
      role="status"
      aria-live="polite"
    >
      <div className="flex items-start gap-4">
        <div className="w-12 h-12 rounded-full bg-[#0F6B5E] text-white flex items-center justify-center shrink-0">
          <ShieldCheck className="w-6 h-6" aria-hidden="true" />
        </div>
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs uppercase font-extrabold tracking-wider bg-[#0F6B5E] text-white px-2.5 py-0.5 rounded-full">
              Standard Pattern Verified
            </span>
            <span className="text-xs font-semibold text-[#00201B]/80">
              Risk Score: {score}
            </span>
          </div>
          <h2 className="text-lg sm:text-xl font-bold tracking-tight">
            Preliminary category: No known red flags found
          </h2>
          <p className="text-xs sm:text-sm text-[#00201B]/80 leading-relaxed">
            This message matches regular institutional format and does not exhibit known scam triggers.
          </p>
          <p className="text-xs font-medium text-[#00201B]/70 pt-1">
            ⚠️ This is not a guarantee of safety. Verify through official channels if unsure.
          </p>
        </div>
      </div>
    </div>
  );
}

