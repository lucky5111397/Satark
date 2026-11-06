import React from 'react';
import { splitByIndicators } from '../lib/highlight.js';

export default function HighlightedText({ text, indicators }) {
  if (!text) return null;

  const segments = splitByIndicators(text, indicators || []);

  return (
    <div className="bg-white rounded-xl border border-[#0D1C2E]/10 p-5 sm:p-6 space-y-3 shadow-xs">
      <div className="flex items-center justify-between border-b border-[#0D1C2E]/10 pb-3">
        <span className="text-xs font-bold uppercase tracking-wider text-[#0D1C2E]/70">
          Analyzed Message / संदेश विश्लेषण
        </span>
        <span className="text-xs text-[#0D1C2E]/60 font-mono">
          {text.length} characters
        </span>
      </div>

      <div className="text-sm sm:text-base leading-relaxed text-[#0D1C2E] break-words whitespace-pre-wrap font-medium">
        {segments.map((seg, idx) => {
          if (seg.marked) {
            return (
              <mark
                key={idx}
                className="bg-[#FFDAD6] text-[#93000A] font-bold px-1.5 py-0.5 rounded-sm border-b-2 border-[#BA1A1A] mx-0.5 shadow-2xs"
                title={`Triggered Rule: ${seg.ruleIds.join(', ')}`}
              >
                {seg.text}
              </mark>
            );
          }
          return <span key={idx}>{seg.text}</span>;
        })}
      </div>

      {indicators && indicators.length > 0 && (
        <div className="pt-2 text-xs text-[#0D1C2E]/60 flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-sm bg-[#FFDAD6] border border-[#BA1A1A] inline-block" aria-hidden="true" />
          <span>Highlighted spans indicate identified psychological pressure or credential traps.</span>
        </div>
      )}
    </div>
  );
}

