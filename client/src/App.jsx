import React, { useState, useRef, useEffect } from 'react';
import Header from './components/Header.jsx';
import MessageInput from './components/MessageInput.jsx';
import RiskBanner from './components/RiskBanner.jsx';
import HighlightedText from './components/HighlightedText.jsx';
import ReasonCards from './components/ReasonCards.jsx';
import EvidenceLedger from './components/EvidenceLedger.jsx';
import SafetyActions from './components/SafetyActions.jsx';
import ReportCard from './components/ReportCard.jsx';
import ValidationPage from './components/ValidationPage.jsx';
import { analyze, ERROR_MESSAGES } from './lib/api.js';
import { canAnalyze } from './lib/media.js';
import { ArrowLeft, RefreshCw, ShieldCheck, AlertCircle, RotateCcw } from 'lucide-react';

/**
 * Main Application Component for Satark Frontend (Step 5 - API Integration)
 * 
 * Rules:
 * - Real API integration via POST VITE_API_URL/api/analyze.
 * - States: idle, loading, success, error.
 * - Double-click protection and aborting of previous requests.
 * - Preserves submittedText so subsequent textarea edits do not shift highlights.
 * - Strict zero-trust response validation.
 * - Never falls back to mock fixtures on error.
 */
export default function App() {
  const [view, setView] = useState('analyzer'); // 'analyzer' | 'validation'
  const [mediaMode, setMediaMode] = useState(null); // null | 'ocr' | 'qr'
  const [lang, setLang] = useState('hinglish'); // 'hinglish' | 'en' | 'hi'
  const [text, setText] = useState('');
  const [url, setUrl] = useState('');
  const [submittedText, setSubmittedText] = useState('');
  const [result, setResult] = useState(null);
  const [status, setStatus] = useState('idle'); // 'idle' | 'loading' | 'success' | 'error'
  const [errorCode, setErrorCode] = useState(null);

  const abortControllerRef = useRef(null);

  const cancelPendingAnalysis = () => {
    const controller = abortControllerRef.current;
    abortControllerRef.current = null;
    controller?.abort();
    return Boolean(controller);
  };

  // Navigation handler supporting direct routing to Analyzer, OCR, QR, and How It Works
  const handleNavigate = (target) => {
    if (cancelPendingAnalysis()) setStatus('idle');
    if (target === 'validation') {
      setView('validation');
      setMediaMode(null);
    } else if (target === 'ocr') {
      setView('analyzer');
      setMediaMode('ocr');
      if (result) {
        setResult(null);
        setStatus('idle');
      }
    } else if (target === 'qr') {
      setView('analyzer');
      setMediaMode('qr');
      if (result) {
        setResult(null);
        setStatus('idle');
      }
    } else {
      setView('analyzer');
      setMediaMode(null);
    }
  };

  const currentNav = view === 'validation' ? 'validation' : (mediaMode || 'analyzer');

  // Clean up any ongoing request on unmount
  useEffect(() => {
    return () => {
      cancelPendingAnalysis();
    };
  }, []);

  // Quick sample selection handler
  const handleSelectSample = (sample) => {
    cancelPendingAnalysis();
    setText(sample.text);
    setUrl(sample.url || '');
    setStatus('idle');
    setResult(null);
    setErrorCode(null);
  };

  // Primary analysis trigger
  const handleAnalyze = async () => {
    if (!canAnalyze(text, url) || status === 'loading') return;

    // Abort previous in-flight request if any
    cancelPendingAnalysis();

    const controller = new AbortController();
    abortControllerRef.current = controller;

    // Lock in the submitted text at the moment of request
    const currentSubmitted = text;
    setSubmittedText(currentSubmitted);
    setStatus('loading');
    setErrorCode(null);
    setResult(null);

    try {
      const response = await analyze({ text: currentSubmitted, url }, controller.signal);

      // If aborted, ignore
      if (controller.signal.aborted) return;

      if (response.ok && response.data) {
        setResult(response.data);
        setStatus('success');
      } else {
        setResult(null);
        setErrorCode(response.error || 'bad_response');
        setStatus('error');
      }
    } catch {
      if (!controller.signal.aborted) {
        setResult(null);
        setErrorCode('network_error');
        setStatus('error');
      }
    } finally {
      // A cancelled request must not clear a newer request's controller.
      if (abortControllerRef.current === controller) {
        abortControllerRef.current = null;
      }
    }
  };

  // Reset all state to analyze another message
  const handleReset = () => {
    cancelPendingAnalysis();
    setResult(null);
    setStatus('idle');
    setErrorCode(null);
    setSubmittedText('');
    setText('');
    setUrl('');
  };

  // Get localized error string
  const getErrorMessage = (code) => {
    const entry = ERROR_MESSAGES[code] || ERROR_MESSAGES.bad_response;
    if (lang === 'en') return entry.en;
    if (lang === 'hinglish') return entry.hinglish;
    // Hindi fallback to English per spec
    return entry.en;
  };

  return (
    <div className="min-h-screen bg-[#F4F1E8] text-[#0D1C2E] flex flex-col font-sans selection:bg-[#005147]/20">
      {/* Global Navigation Header */}
      <Header
        currentNav={currentNav}
        currentView={view}
        onNavigate={handleNavigate}
        lang={lang}
        onLanguageChange={setLang}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-5xl w-full mx-auto px-4 py-6 sm:py-8">
        {view === 'validation' ? (
          /* Screen 3: Architecture, Pipeline & Benchmarks */
          <ValidationPage onBack={() => handleNavigate('analyzer')} />
        ) : (
          /* Screen 1 & Screen 2: Analyzer & Forensic Results */
          <div className="space-y-8 animate-in fade-in duration-150">
            {/* Hero / Intro Title */}
            {!result && (
              <div className="text-center max-w-2xl mx-auto space-y-2 pt-2 pb-1">
                <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#005147]/10 text-[#005147] text-xs font-semibold">
                  <ShieldCheck className="w-4 h-4" />
                  <span>Explainable Scam Detection for India</span>
                </div>
                <h1 className="text-2xl sm:text-4xl font-extrabold text-[#0D1C2E] tracking-tight">
                  Verify Suspicious Messages Before You Click or Pay
                </h1>
                <p className="text-xs sm:text-sm text-[#0D1C2E]/70 max-w-xl mx-auto leading-relaxed">
                  Identify electricity bill threats, fake KYC alerts, work-from-home traps, and spoofed bank messages with transparent red-flag reasoning.
                </p>
              </div>
            )}

            {/* Error Banner State */}
            {status === 'error' && errorCode && (
              <div 
                role="alert" 
                aria-live="assertive"
                className="max-w-3xl mx-auto bg-rose-50 border border-rose-200 rounded-xl p-4 sm:p-5 text-rose-900 shadow-xs space-y-3"
              >
                <div className="flex items-start gap-3">
                  <AlertCircle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
                  <div className="flex-1 min-w-0">
                    <h3 className="text-sm font-bold text-rose-950">
                      Analysis Error / त्रुटि
                    </h3>
                    <p className="text-xs sm:text-sm text-rose-800 mt-1 leading-relaxed">
                      {getErrorMessage(errorCode)}
                    </p>
                    {lang === 'hi' && (
                      <span className="text-[11px] text-amber-800 bg-amber-100/70 border border-amber-200 px-2 py-0.5 rounded inline-block mt-1.5">
                        Hindi translation coming soon (showing English)
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex justify-end pt-1">
                  <button
                    type="button"
                    onClick={handleAnalyze}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-rose-700 hover:bg-rose-800 text-white text-xs font-semibold transition-colors cursor-pointer"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Try again</span>
                  </button>
                </div>
              </div>
            )}

            {/* Input Section (Screen 1) */}
            {!result ? (
              <MessageInput
                text={text}
                setText={setText}
                url={url}
                setUrl={setUrl}
                onAnalyze={handleAnalyze}
                onSelectSample={handleSelectSample}
                isLoading={status === 'loading'}
                mediaMode={mediaMode}
                onMediaModeChange={setMediaMode}
              />
            ) : (
              /* Forensic Result Display (Screen 2) */
              <div className="space-y-6 max-w-3xl mx-auto">
                {/* Top Reset and Edit Controls */}
                <div className="flex items-center justify-between pb-2 border-b border-[#0D1C2E]/10">
                  <button
                    type="button"
                    onClick={() => {
                      setStatus('idle');
                      setResult(null);
                    }}
                    className="inline-flex items-center gap-2 text-xs sm:text-sm font-semibold text-[#005147] hover:text-[#0B5248] bg-white border border-[#0D1C2E]/10 px-3.5 py-2 rounded-xl transition-all shadow-2xs hover:shadow-xs cursor-pointer"
                  >
                    <ArrowLeft className="w-4 h-4" />
                    <span>Edit message / Change input</span>
                  </button>

                  <button
                    type="button"
                    onClick={handleReset}
                    className="inline-flex items-center gap-1.5 text-xs font-medium text-[#0D1C2E]/70 hover:text-[#0D1C2E] px-2.5 py-1.5 rounded-lg hover:bg-black/5 transition-colors cursor-pointer"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Analyze another message</span>
                  </button>
                </div>

                {/* 1. Risk Category Banner */}
                <RiskBanner
                  category={result.category}
                  score={result.score}
                />

                {/* 2. Highlighted Message using submittedText */}
                <HighlightedText
                  text={submittedText}
                  indicators={result.indicators}
                />

                {/* 3. Forensic Reason Cards */}
                <ReasonCards
                  explanation={result.explanation}
                  lang={lang}
                  indicators={result.indicators}
                />

                {/* 4. Forensic Evidence Ledger */}
                <EvidenceLedger
                  ledger={result.ledger}
                  urlEvidence={result.urlEvidence}
                />

                {/* 5. Recommended Safety Actions */}
                <SafetyActions
                  actions={result.actions}
                />

                {/* 6. Civic Incident Reporting & Copy Summary */}
                <ReportCard
                  result={result}
                  messageText={submittedText}
                />

                {/* Bottom Reset Button */}
                <div className="pt-4 text-center">
                  <button
                    type="button"
                    onClick={handleReset}
                    className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[#005147] hover:bg-[#0B5248] text-white text-sm font-semibold transition-all shadow-xs cursor-pointer active:scale-98"
                  >
                    <RefreshCw className="w-4 h-4" />
                    <span>Check Another Message</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Global Standing Footer */}
      <footer className="border-t border-[#0D1C2E]/10 bg-white/70 py-6 text-center text-xs text-[#0D1C2E]/70 mt-12">
        <div className="max-w-5xl mx-auto px-4 space-y-2">
          <p className="font-semibold text-slate-800">
            Satark (सतर्क) • Independent Civic Scam Defense & Message Safety Tool
          </p>
          <p className="text-slate-600">
            Developer: <span className="font-medium text-slate-900">Lucky Gupta</span>
          </p>
          <p className="text-[11px] text-slate-500 max-w-xl mx-auto leading-relaxed pt-1">
            Standing Rule: Red-flag guidance, not a guarantee of safety. Unavailable evidence is never treated as safe or negative.
          </p>
        </div>
      </footer>
    </div>
  );
}
