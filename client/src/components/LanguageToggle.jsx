import React from 'react';

export default function LanguageToggle({ currentLang, onSelect }) {
  const options = [
    { id: 'en', label: 'EN' },
    { id: 'hi', label: 'हिंदी' },
    { id: 'hinglish', label: 'Hinglish' }
  ];

  return (
    <div
      className="inline-flex items-center p-1 bg-white rounded-full border border-[#0D1C2E]/15 shadow-xs"
      role="radiogroup"
      aria-label="Select explanation language"
    >
      {options.map(opt => {
        const isSelected = currentLang === opt.id;
        return (
          <button
            key={opt.id}
            type="button"
            role="radio"
            aria-checked={isSelected}
            onClick={() => onSelect(opt.id)}
            className={`px-3 py-1.5 rounded-full text-xs font-semibold transition-all min-h-[32px] sm:min-h-[36px] ${
              isSelected
                ? 'bg-[#005147] text-white shadow-xs'
                : 'text-[#0D1C2E]/70 hover:text-[#0D1C2E] hover:bg-black/5'
            }`}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

