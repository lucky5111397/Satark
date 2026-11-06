import React, { useState } from 'react';
import { PhoneCall, ExternalLink, Copy, Check, ShieldAlert } from 'lucide-react';
import { isOfficialLink, HELPLINE_1930_TEL } from '../lib/officialLinks.js';

/**
 * ReportCard component:
 * Provides direct civic reporting links for Indian citizens and a one-click button to
 * copy an incident summary for reporting to cybercrime authorities.
 * 
 * Props:
 * - result: Complete detection result object
 * - messageText: string (original analyzed message text)
 */
export default function ReportCard({ result, messageText }) {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);

  // Hidden on Genuine result
  if (!result || result.category === 'No known red flags found' || result.category === 'Genuine') {
    return null;
  }

  // Official portal destinations (vetted via officialLinks)
  const cybercrimeUrl = 'https://cybercrime.gov.in';
  const chakshuUrl = 'https://sancharsaathi.gov.in/sfc';

  const isCybercrimeValid = isOfficialLink(cybercrimeUrl);
  const isChakshuValid = isOfficialLink(chakshuUrl);

  const handleCopySummary = async () => {
    try {
      const summaryLines = [
        '=== SATARK SCAM INCIDENT REPORT SUMMARY ===',
        `Risk Category: ${result.category} (Score: ${result.score})`,
        `Timestamp: ${new Date().toISOString()}`,
        '',
        '--- Flagged Triggers ---',
        ...(result.indicators && result.indicators.length > 0 
          ? result.indicators.map(i => `• ${i.ruleId}: "${i.text}"`) 
          : ['• Heuristic structural warning']),
        '',
        '--- Suspicious URL Evidence ---',
        ...(result.urlEvidence && result.urlEvidence.length > 0
          ? result.urlEvidence.map(u => `• ${u.url} (Flags: ${u.flags.join(', ')})`)
          : ['• None detected']),
        '',
        '--- Analyzed Message Excerpt ---',
        messageText ? messageText.slice(0, 500) : '(No text provided)',
        '',
        'Generated securely via Satark (Explainable Message Safety Tool).'
      ];

      await navigator.clipboard.writeText(summaryLines.join('\n'));
      setCopied(true);
      setCopyError(false);
      setTimeout(() => setCopied(false), 2500);
    } catch (err) {
      setCopyError(true);
      setTimeout(() => setCopyError(false), 3000);
    }
  };

  return (
    <div className="bg-white border border-rose-200 rounded-2xl p-5 shadow-xs space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-semibold text-rose-950 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-rose-600" />
            <span>Report This Incident (Govt of India)</span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Report fraudulent messages and financial fraud to the official authorities immediately.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
        {/* National Cyber Crime Helpline */}
        <a 
          href={HELPLINE_1930_TEL}
          className="flex items-center justify-between p-3.5 rounded-xl border border-rose-100 bg-rose-50/50 hover:bg-rose-50 transition-colors group"
        >
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-full bg-rose-100 text-rose-700 flex items-center justify-center shrink-0">
              <PhoneCall className="w-4 h-4" />
            </div>
            <div>
              <span className="text-xs text-rose-600 font-semibold block uppercase tracking-wider">
                Financial Fraud Helpline
              </span>
              <span className="text-base font-bold text-slate-900 group-hover:text-rose-700">
                Call 1930
              </span>
            </div>
          </div>
          <span className="text-xs bg-white text-rose-700 font-semibold px-2.5 py-1 rounded-full border border-rose-200">
            Toll Free
          </span>
        </a>

        {/* Chakshu Portal */}
        {isChakshuValid && (
          <a 
            href={chakshuUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-between p-3.5 rounded-xl border border-slate-200 bg-slate-50/70 hover:bg-slate-100/70 transition-colors group"
          >
            <div>
              <span className="text-xs text-slate-500 font-semibold block uppercase tracking-wider">
                DoT Sanchar Saathi
              </span>
              <span className="text-sm font-bold text-slate-900 group-hover:text-teal-700">
                Chakshu Portal
              </span>
              <span className="text-[11px] text-slate-500 block">Report SMS & Call scams</span>
            </div>
            <ExternalLink className="w-4 h-4 text-slate-400 group-hover:text-teal-600" />
          </a>
        )}

        {/* National Cyber Crime Portal */}
        {isCybercrimeValid && (
          <a 
            href={cybercrimeUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-between p-3.5 rounded-xl border border-slate-200 bg-slate-50/70 hover:bg-slate-100/70 transition-colors group sm:col-span-2"
          >
            <div>
              <span className="text-xs text-slate-500 font-semibold block uppercase tracking-wider">
                Ministry of Home Affairs
              </span>
              <span className="text-sm font-bold text-slate-900 group-hover:text-teal-700">
                cybercrime.gov.in
              </span>
              <span className="text-[11px] text-slate-500 block">Report cybercrime and submit a complaint</span>
            </div>
            <ExternalLink className="w-4 h-4 text-slate-400 group-hover:text-teal-600" />
          </a>
        )}
      </div>

      {/* Copy Summary for reporting */}
      <div className="pt-2 border-t border-slate-100 flex items-center justify-between flex-wrap gap-2">
        <span className="text-xs text-slate-500">
          Prepare report evidence for police or cyber desk:
        </span>
        <button
          type="button"
          onClick={handleCopySummary}
          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors cursor-pointer"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-600" />
              <span className="text-emerald-700">Summary Copied!</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5 text-slate-500" />
              <span>Copy Report Summary</span>
            </>
          )}
        </button>
      </div>

      {copyError && (
        <p className="text-xs text-rose-600 text-right">
          Unable to copy automatically. Please copy the text manually.
        </p>
      )}
    </div>
  );
}

