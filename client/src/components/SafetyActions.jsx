import React from 'react';
import { ShieldAlert, CheckSquare } from 'lucide-react';

/**
 * SafetyActions component:
 * Highlights immediate, actionable safety steps users should take.
 * 
 * Props:
 * - actions: string[]
 */
export default function SafetyActions({ actions = [] }) {
  if (!actions || actions.length === 0) return null;

  return (
    <div className="bg-amber-50/60 border border-amber-200 rounded-2xl p-5 shadow-xs space-y-3">
      <h3 className="text-base font-semibold text-amber-950 flex items-center gap-2">
        <ShieldAlert className="w-5 h-5 text-amber-600" />
        <span>Recommended Immediate Actions</span>
      </h3>
      <p className="text-xs text-amber-800">
        Follow these steps right now to protect your banking credentials and device:
      </p>

      <ul className="space-y-2.5 pt-1">
        {actions.map((action, idx) => (
          <li 
            key={idx}
            className="flex items-start gap-3 bg-white/90 border border-amber-100 rounded-xl p-3 text-sm text-slate-800 font-medium shadow-2xs"
          >
            <div className="w-5 h-5 rounded-md bg-amber-100 text-amber-700 flex items-center justify-center shrink-0 mt-0.5">
              <CheckSquare className="w-3.5 h-3.5" />
            </div>
            <span className="leading-snug">{action}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

