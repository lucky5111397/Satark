import React from 'react';
import { SAMPLE_MESSAGES } from '../lib/samples.js';

export default function SampleButtons({ onSelectSample }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center gap-2 pt-2">
      <span className="text-xs font-semibold text-[#0D1C2E]/70 shrink-0">Try a sample:</span>
      <div className="flex flex-wrap items-center gap-2">
        {SAMPLE_MESSAGES.map(sample => (
          <button
            key={sample.id}
            type="button"
            onClick={() => onSelectSample(sample)}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#E5EEFF]/70 hover:bg-[#E5EEFF] border border-[#0D1C2E]/10 text-xs font-medium text-[#0D1C2E] transition-all min-h-[44px] active:scale-98 shadow-xs"
          >
            <span className={`w-2 h-2 rounded-full ${sample.dotColor}`} aria-hidden="true" />
            <span>{sample.label}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

