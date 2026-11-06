import React from 'react';
import { ShieldCheck, AlertCircle, HelpCircle, CheckCircle2 } from 'lucide-react';

/**
 * EvidenceLedger component:
 * Displays the transparent checklist of every signal evaluated by the rules engine.
 * Emphasizes the standing safety principle: "Unavailable is not the same as safe".
 * 
 * Props:
 * - ledger: Array<{ check: string, status: 'triggered' | 'not_triggered' | 'unavailable' | 'not_used', note?: string }>
 * - urlEvidence: Array<{ url: string, status: string, flags: string[] }>
 */
export default function EvidenceLedger({ ledger = [], urlEvidence = [] }) {
  if (!ledger || ledger.length === 0) return null;

  return (
    <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-semibold text-slate-900 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-teal-700" />
            <span>Forensic Evidence Ledger</span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Full deterministic audit trail of rules and signals evaluated.
          </p>
        </div>
      </div>

      {/* Ledger Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-200">
        <table className="w-full text-left text-xs sm:text-sm">
          <thead className="bg-slate-50 text-slate-700 font-semibold border-b border-slate-200">
            <tr>
              <th scope="col" className="px-4 py-3">Signal / Security Check</th>
              <th scope="col" className="px-4 py-3 w-36 text-center">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 font-normal">
            {ledger.map((item, idx) => {
              const status = item.status || 'not_triggered';
              return (
                <tr key={idx} className="hover:bg-slate-50/70 transition-colors">
                  <td className="px-4 py-3 text-slate-800 font-medium">
                    {item.check}
                  </td>
                  <td className="px-4 py-3 text-center">
                    {status === 'triggered' && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200">
                        <AlertCircle className="w-3.5 h-3.5" />
                        Triggered
                      </span>
                    )}
                    {status === 'not_triggered' && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-100 text-slate-600">
                        <CheckCircle2 className="w-3.5 h-3.5 text-slate-400" />
                        Clear
                      </span>
                    )}
                    {status === 'unavailable' && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-sky-50 text-sky-700 border border-sky-200">
                        <HelpCircle className="w-3.5 h-3.5" />
                        Unavailable
                      </span>
                    )}
                    {status === 'not_used' && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-50 text-slate-400">
                        Not evaluated
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* URL Evidence Sub-block if any */}
      {urlEvidence && urlEvidence.length > 0 && (
        <div className="bg-slate-50 rounded-xl p-3 border border-slate-200 space-y-2">
          <span className="text-xs font-semibold text-slate-700 uppercase tracking-wider block">
            URL Inspection Details:
          </span>
          {urlEvidence.map((ev, uIdx) => (
            <div key={uIdx} className="text-xs space-y-1">
              <div className="font-mono text-slate-800 break-all bg-white px-2.5 py-1 rounded border border-slate-200">
                {ev.url}
              </div>
              <div className="flex flex-wrap gap-1.5 pt-1">
                {ev.flags && ev.flags.length > 0 ? (
                  ev.flags.map((flag, fIdx) => (
                    <span 
                      key={fIdx}
                      className="px-2 py-0.5 rounded text-[11px] font-mono bg-amber-100 text-amber-800 border border-amber-200"
                    >
                      {flag}
                    </span>
                  ))
                ) : (
                  <span className="text-slate-500 italic">No structural anomalies detected in URL.</span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Mandatory Standing Rule Footnote */}
      <div className="flex items-start gap-2 pt-2 text-xs text-slate-500 border-t border-slate-100">
        <InfoIcon className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
        <p>
          <strong className="text-slate-700">Forensic Disclosure:</strong> Status labeled <span className="font-semibold text-sky-800">Unavailable</span> indicates external reputation lookup was not performed (offline mode). Unavailable is not the same as safe.
        </p>
      </div>
    </div>
  );
}

function InfoIcon(props) {
  return (
    <svg fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" {...props}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z" />
    </svg>
  );
}

