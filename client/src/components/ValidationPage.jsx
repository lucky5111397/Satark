import React from 'react';
import { 
  ArrowLeft, Lock, AlertTriangle, 
  Layers, CheckCircle, Clock, Zap
} from 'lucide-react';

/**
 * Describes the local pipeline, recorded synthetic benchmark, and current limitations.
 * 
 * Props:
 * - onBack: () => void (switches view back to Analyzer)
 */
export default function ValidationPage({ onBack }) {
  return (
    <div className="max-w-4xl mx-auto space-y-8 pb-12 animate-in fade-in duration-200">
      {/* Top Header with Back Button */}
      <div className="flex items-center justify-between border-b border-slate-200 pb-5">
        <button
          type="button"
          onClick={onBack}
          className="inline-flex items-center gap-2 text-sm font-semibold text-teal-800 hover:text-teal-950 bg-teal-50 hover:bg-teal-100 px-3.5 py-2 rounded-xl transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Analyzer</span>
        </button>
        <span className="text-xs font-mono text-slate-500 bg-slate-100 px-2.5 py-1 rounded-md">
          Satark Architecture & Validation
        </span>
      </div>

      {/* Hero Intro */}
      <div className="bg-gradient-to-br from-teal-900 to-teal-950 text-white rounded-3xl p-6 sm:p-8 shadow-sm">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-teal-800/80 text-teal-200 text-xs font-medium mb-3">
          <Zap className="w-3.5 h-3.5 text-teal-300" />
          <span>Local Deterministic Scam Detection</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight">
          How Satark Works: Zero-Trust Forensic Pipeline
        </h1>
        <p className="mt-2 text-teal-100/90 text-sm sm:text-base leading-relaxed max-w-2xl">
          Satark runs a fully local, length-preserving rule engine that outputs transparent forensic evidence 
          with zero data retention.
        </p>
      </div>

      {/* Detection pipeline */}
      <section className="space-y-4">
        <div className="flex items-center gap-2">
          <Layers className="w-5 h-5 text-teal-700" />
          <h2 className="text-xl font-bold text-slate-900">7-Stage Detection Architecture</h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {[
            {
              step: '01',
              title: 'Input',
              desc: 'Boundary validation rejecting oversized payloads, strictly limiting input text to 2000 characters.'
            },
            {
              step: '02',
              title: 'Prepare',
              desc: 'NFC normalization is used only when the character count stays unchanged; otherwise original text is preserved for highlight offsets.'
            },
            {
              step: '03',
              title: 'Privacy Layer',
              desc: 'Strict volatile RAM processing with zero external network calls, zero message logging, and no persistence.'
            },
            {
              step: '04',
              title: 'Parallel Signals',
              desc: 'Rules inspect bounded message text with negation guards alongside local checks for look-alike domains.'
            },
            {
              step: '05',
              title: 'Aggregate',
              desc: 'Additive scoring mapping to Suspicious, Caution, or No known red flags found, with a forensic ledger.'
            },
            {
              step: '06',
              title: 'Explain',
              desc: 'Plain-language forensic breakdowns generated in English and Hinglish for full user comprehension.'
            },
            {
              step: '07',
              title: 'Results',
              desc: 'Actionable response payload paired with verified civic reporting channels (1930 & Chakshu).'
            }
          ].map((item, idx) => (
            <div 
              key={idx}
              className="bg-white border border-slate-200 rounded-2xl p-4 shadow-2xs relative flex flex-col justify-between"
            >
              <div>
                <span className="text-xs font-mono font-bold text-teal-700 bg-teal-50 px-2 py-0.5 rounded">
                  {item.step}
                </span>
                <h3 className="text-sm font-bold text-slate-900 mt-2">{item.title}</h3>
                <p className="text-xs text-slate-600 mt-1.5 leading-relaxed">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>
      {/* Security & privacy protocol */}
      <section className="bg-white border border-slate-200 rounded-3xl p-6 shadow-2xs space-y-4">
        <div className="flex items-center gap-2">
          <Lock className="w-5 h-5 text-teal-700" />
          <h2 className="text-xl font-bold text-slate-900">Security & Privacy Commitments</h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs sm:text-sm">
          <div className="space-y-1 p-3.5 rounded-xl bg-slate-50 border border-slate-100">
            <span className="font-bold text-slate-900 block flex items-center gap-1.5">
              <CheckCircle className="w-4 h-4 text-teal-600" />
              Zero Storage & Logging
            </span>
            <p className="text-slate-600">
              User messages are never written to disk, databases, or application server logs. Processed solely in volatile RAM.
            </p>
          </div>

          <div className="space-y-1 p-3.5 rounded-xl bg-slate-50 border border-slate-100">
            <span className="font-bold text-slate-900 block flex items-center gap-1.5">
              <CheckCircle className="w-4 h-4 text-teal-600" />
              Strict 10KB Request Boundary
            </span>
            <p className="text-slate-600">
              The HTTP API limits JSON request bodies to 10KB and rejects oversized requests with HTTP 413.
            </p>
          </div>

          <div className="space-y-1 p-3.5 rounded-xl bg-slate-50 border border-slate-100">
            <span className="font-bold text-slate-900 block flex items-center gap-1.5">
              <CheckCircle className="w-4 h-4 text-teal-600" />
              No Outbound Network Calls
            </span>
            <p className="text-slate-600">
              All URL heuristic and typographic scans are performed locally without pinging external domain servers.
            </p>
          </div>

          <div className="space-y-1 p-3.5 rounded-xl bg-slate-50 border border-slate-100">
            <span className="font-bold text-slate-900 block flex items-center gap-1.5">
              <CheckCircle className="w-4 h-4 text-teal-600" />
              Zero Dynamic HTML Injection
            </span>
            <p className="text-slate-600">
              All UI highlights use native React text node splitting with standard mark tags, strictly avoiding unescaped HTML injection.
            </p>
          </div>
        </div>
      </section>

      {/* Recorded synthetic development benchmark */}
      <section className="space-y-4">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <Clock className="w-5 h-5 text-teal-700" />
            <h2 className="text-xl font-bold text-slate-900">Recorded Development Benchmark</h2>
          </div>
          <span className="text-xs text-teal-900 bg-teal-100/80 border border-teal-300 px-2.5 py-0.5 rounded-full font-semibold">
            eval/dev_set.csv • 50 Samples
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: 'STRICT Precision', value: '100.0%', sub: '0 False Positives (FPR 0.0%)' },
            { label: 'LOOSE Recall', value: '100.0%', sub: '25 / 25 Scams Caught' },
            { label: 'LOOSE Accuracy', value: '100.0%', sub: '50 / 50 Correct (FPR 0.0%)' },
            { label: 'STRICT Accuracy', value: '82.0%', sub: '41 / 50 Correct (Recall 64.0%)' },
          ].map((metric, idx) => (
            <div key={idx} className="bg-white border border-slate-200 rounded-2xl p-4 text-center shadow-2xs">
              <span className="text-xs text-slate-500 font-medium block">{metric.label}</span>
              <span className="text-xl font-extrabold text-teal-900 font-mono block mt-1">
                {metric.value}
              </span>
              <span className="text-[11px] text-slate-600 block mt-0.5">{metric.sub}</span>
            </div>
          ))}
        </div>

        <div className="text-xs text-slate-700 bg-amber-50 border border-amber-200 rounded-xl p-3 text-center">
          <strong>Mandatory Scientific Disclosure:</strong> Synthetic data, not real-world accuracy. Recorded on 3 November 2026; these results are not a fresh validation of this checkout and do not reflect carrier-wide base rates.
        </div>
      </section>

      {/* Known limitations & disclosures */}
      <section className="bg-amber-50/50 border border-amber-200 rounded-3xl p-6 shadow-2xs space-y-3">
        <h3 className="text-base font-bold text-amber-950 flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-amber-700" />
          <span>Known Limitations & Forensic Disclosures</span>
        </h3>
        <ul className="space-y-2 text-xs sm:text-sm text-amber-900 list-disc list-inside">
          <li>
            <strong>Synthetic Evaluation Data:</strong> Evaluated on synthetic benchmark datasets (<code className="font-mono bg-white px-1 py-0.5 rounded border border-amber-200">dev_set.csv</code>). Figures represent synthetic benchmark performance, not real-world telecom fraud prevalence.
          </li>
          <li>
            <strong>URL Reputation Unavailable:</strong> By standing privacy architecture, live network calls to external Safe Browsing or WHOIS databases are disabled. URL reputation is reported as <span className="font-mono font-semibold">unavailable</span>, never as safe or negative.
          </li>
          <li>
            <strong>Optional ML Classifier:</strong> The repository includes a local ML service and training tools. The running app uses it only when explicitly enabled and compatible model assets are available; otherwise its evidence is marked <span className="font-mono font-semibold">not_used</span> or <span className="font-mono font-semibold">unavailable</span>. Deterministic rules remain the baseline.
          </li>
          <li>
            <strong>Scope:</strong> Satark analyzes text and URLs you submit. QR payloads remain inert text; the app does not open payment requests, scan your inbox, or confirm that a message or payment is safe.
          </li>
          <li>
            <strong>Screenshot OCR & QR Decoding:</strong> Images are processed in local browser memory. QR codes are decoded locally, and English/Hindi OCR uses locally hosted language data. You can edit the extracted text before confirming it. If OCR fails, manual transcription remains available. Images are never uploaded; confirmed text or URLs are sent to the local analyzer only when you request analysis.
          </li>
          <li>
            <strong>Provisional Hindi (Devanagari) Wording:</strong> Hindi detection rules and explanation templates are provisional unreviewed drafts pending final native linguistic sign-off, and are clearly tagged in the UI.
          </li>
        </ul>
      </section>
    </div>
  );
}
