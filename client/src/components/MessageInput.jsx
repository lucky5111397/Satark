import React, { useState } from 'react';
import { ScanSearch, Link as LinkIcon, X, Loader2, Camera } from 'lucide-react';
import SampleButtons from './SampleButtons.jsx';
import MediaInput from './MediaInput.jsx';
import { canAnalyze } from '../lib/media.js';

export default function MessageInput({
  text,
  setText,
  url,
  setUrl,
  onAnalyze,
  onSelectSample,
  isLoading,
  mediaMode,
  onMediaModeChange
}) {
  const [localMediaMode, setLocalMediaMode] = useState(null);
  const effectiveMediaMode = mediaMode !== undefined ? mediaMode : localMediaMode;
  const isDrawerOpen = Boolean(effectiveMediaMode);

  const setMedia = (val) => {
    if (onMediaModeChange) onMediaModeChange(val);
    setLocalMediaMode(val);
  };

  const handleToggleDrawer = () => {
    if (isDrawerOpen) {
      setMedia(null);
    } else {
      setMedia('ocr');
    }
  };

  const charCount = text.length;
  const isTooLong = charCount > 2000;
  const isSubmitDisabled = !canAnalyze(text, url) || isLoading;

  return (
    <section className="w-full max-w-3xl mx-auto bg-white rounded-xl shadow-xs border border-[#0D1C2E]/10 p-5 sm:p-7 space-y-5">
      {/* Textarea Header with Screenshot/QR toggle */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <label htmlFor="suspect-message" className="text-sm font-bold text-[#0D1C2E] flex items-center gap-2">
          <span>Suspect Message / संदिग्ध संदेश</span>
        </label>
        
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleToggleDrawer}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold text-[#005147] bg-[#005147]/10 hover:bg-[#005147]/20 transition-colors cursor-pointer"
            aria-expanded={isDrawerOpen}
          >
            <Camera className="w-3.5 h-3.5" />
            <span>{isDrawerOpen ? 'Close Media Tool' : 'Scan Screenshot / QR'}</span>
          </button>

          <span
            className={`font-mono text-xs font-semibold ${
              isTooLong ? 'text-red-600 font-bold' : 'text-[#0D1C2E]/60'
            }`}
            aria-live="polite"
          >
            {charCount} / 2000
          </span>
        </div>
      </div>

      {/* Expandable Media / Screenshot / QR Component */}
      {isDrawerOpen && (
        <MediaInput
          activeTab={effectiveMediaMode}
          onTabChange={(newTab) => setMedia(newTab)}
          onTextExtracted={(extracted) => {
            setText(extracted);
            setUrl('');
            setMedia(null);
          }}
          onUrlExtracted={(extractedUrl) => {
            setUrl(extractedUrl);
            setText('');
            setMedia(null);
          }}
          onClose={() => setMedia(null)}
        />
      )}

      {/* Main Textarea */}
      <div className="relative rounded-lg border border-[#0D1C2E]/20 bg-[#F4F1E8]/30 focus-within:bg-white focus-within:border-[#005147] focus-within:ring-2 focus-within:ring-[#005147]/20 transition-all p-3">
        <textarea
          id="suspect-message"
          rows={5}
          maxLength={2000}
          value={text}
          onChange={e => setText(e.target.value)}
          placeholder="Paste the suspicious message you received (SMS, WhatsApp alert, UPI claim, lottery notification)..."
          className="w-full bg-transparent resize-none border-0 p-0 text-sm sm:text-base text-[#0D1C2E] placeholder-[#0D1C2E]/40 focus:outline-hidden leading-relaxed"
        />
      </div>

      {/* Optional URL Input */}
      <div className="space-y-1">
        <label htmlFor="suspect-url" className="text-xs font-semibold text-[#0D1C2E]/70 flex items-center gap-1.5">
          <LinkIcon className="w-3.5 h-3.5" aria-hidden="true" />
          <span>Suspicious Link (Optional)</span>
        </label>
        <div className="relative flex items-center rounded-lg border border-[#0D1C2E]/20 bg-[#F4F1E8]/30 focus-within:bg-white focus-within:border-[#005147] focus-within:ring-2 focus-within:ring-[#005147]/20 transition-all px-3">
          <input
            id="suspect-url"
            type="text"
            maxLength={2048}
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="Paste link e.g. bit.ly/kyc-update, sbi-verify.xyz"
            className="w-full py-2.5 text-xs sm:text-sm bg-transparent border-0 focus:outline-hidden text-[#0D1C2E] placeholder-[#0D1C2E]/40"
          />
          {url && (
            <button
              type="button"
              onClick={() => setUrl('')}
              className="p-1 rounded-md text-[#0D1C2E]/50 hover:text-[#0D1C2E] min-w-[32px] min-h-[32px] flex items-center justify-center"
              aria-label="Clear URL input"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Primary Action Button */}
      <div className="pt-2">
        <button
          type="button"
          disabled={isSubmitDisabled}
          onClick={onAnalyze}
          className={`w-full min-h-[48px] rounded-lg font-semibold text-sm sm:text-base flex items-center justify-center gap-2 shadow-xs transition-all active:scale-[0.99] ${
            isSubmitDisabled
              ? 'bg-[#005147]/40 text-white/70 cursor-not-allowed'
              : 'bg-[#005147] hover:bg-[#0B5248] text-white cursor-pointer'
          }`}
        >
          {isLoading ? (
            <>
              <Loader2 className="w-5 h-5 animate-spin" aria-hidden="true" />
              <span>Analyzing Heuristics...</span>
            </>
          ) : (
            <>
              <ScanSearch className="w-5 h-5" aria-hidden="true" />
              <span>{!text.trim() && url.trim() ? 'Analyze URL' : 'Analyze message'}</span>
            </>
          )}
        </button>
      </div>

      {/* Sample Buttons Row */}
      <SampleButtons onSelectSample={onSelectSample} />

      {/* Privacy Line */}
      <div className="pt-2 text-center text-xs text-[#0D1C2E]/70 border-t border-[#0D1C2E]/10">
        <span>🔒 Your message is not stored. Satark is not 100% accurate.</span>
      </div>
    </section>
  );
}

