import React, { useState } from 'react';
import { Shield, BookOpen, Search, Camera, QrCode, Menu, X } from 'lucide-react';
import LanguageToggle from './LanguageToggle.jsx';

export default function Header({ currentNav, currentView, onNavigate, lang, onLanguageChange }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const activeKey = currentNav || currentView || 'analyzer';

  const navItems = [
    { id: 'analyzer', label: 'Analyzer', icon: Search, hint: 'Analyze suspicious text & URLs' },
    { id: 'ocr', label: 'Screenshot / OCR', icon: Camera, hint: 'Import message screenshots' },
    { id: 'qr', label: 'QR Decoder', icon: QrCode, hint: 'Scan suspicious QR codes' },
    { id: 'validation', label: 'How Satark Works', icon: BookOpen, hint: 'Architecture, pipeline & benchmarks' },
  ];

  const handleItemClick = (id) => {
    onNavigate(id);
    setMobileMenuOpen(false);
  };

  return (
    <header className="sticky top-0 z-40 w-full bg-[#F4F1E8]/95 backdrop-blur-md border-b border-[#0D1C2E]/10 transition-colors">
      <div className="max-w-5xl mx-auto px-4 h-16 flex items-center justify-between">
        {/* Brand / Logo */}
        <div className="flex items-center gap-3 sm:gap-6">
          <button
            type="button"
            onClick={() => handleItemClick('analyzer')}
            className="flex items-center gap-2.5 text-left focus-visible:ring-2 focus-visible:ring-[#005147] rounded-lg p-1 transition-opacity hover:opacity-90 cursor-pointer"
            aria-label="Satark Home - Go to Analyzer"
          >
            <div className="w-10 h-10 rounded-lg bg-[#005147] flex items-center justify-center text-white shadow-xs">
              <Shield className="w-5 h-5" aria-hidden="true" />
            </div>
            <div className="flex flex-col leading-tight">
              <span className="font-bold text-lg text-[#005147] tracking-tight">Satark</span>
              <span className="text-[11px] sm:text-xs text-[#0D1C2E]/70 font-medium">सतर्क • Civic Scam Defense</span>
            </div>
          </button>

          {/* Desktop Navigation Links */}
          <nav className="hidden md:flex items-center gap-1.5 text-xs lg:text-sm font-medium" aria-label="Main Navigation">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeKey === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => handleItemClick(item.id)}
                  aria-current={isActive ? 'page' : undefined}
                  className={`flex items-center gap-1.5 px-3 py-2 rounded-lg transition-all min-h-[40px] cursor-pointer ${
                    isActive
                      ? 'text-[#005147] font-semibold bg-[#005147]/12 shadow-2xs'
                      : 'text-[#0D1C2E]/75 hover:text-[#0D1C2E] hover:bg-black/5'
                  }`}
                  title={item.hint}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-[#005147]' : 'text-[#0D1C2E]/60'}`} aria-hidden="true" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Right side: Global Language Toggle & Mobile Hamburger */}
        <div className="flex items-center gap-2 sm:gap-3">
          <LanguageToggle currentLang={lang} onSelect={onLanguageChange} />

          {/* Mobile Menu Hamburger Button */}
          <button
            type="button"
            onClick={() => setMobileMenuOpen(prev => !prev)}
            className="md:hidden p-2 rounded-lg text-[#0D1C2E]/70 hover:text-[#0D1C2E] hover:bg-black/5 min-w-[44px] min-h-[44px] flex items-center justify-center focus-visible:ring-2 focus-visible:ring-[#005147] cursor-pointer"
            aria-label={mobileMenuOpen ? 'Close Navigation Menu' : 'Open Navigation Menu'}
            aria-expanded={mobileMenuOpen}
            aria-controls="mobile-nav-menu"
          >
            {mobileMenuOpen ? (
              <X className="w-5 h-5" aria-hidden="true" />
            ) : (
              <Menu className="w-5 h-5" aria-hidden="true" />
            )}
          </button>
        </div>
      </div>

      {/* Mobile Navigation Dropdown Menu */}
      {mobileMenuOpen && (
        <div
          id="mobile-nav-menu"
          className="md:hidden border-t border-[#0D1C2E]/10 bg-[#FAF8F3] px-4 py-3 space-y-1 shadow-lg animate-in slide-in-from-top-2 duration-150"
        >
          <div className="text-[11px] font-bold uppercase tracking-wider text-[#0D1C2E]/50 px-2 pt-1 pb-1">
            Features & Navigation
          </div>
          <nav className="flex flex-col space-y-1" aria-label="Mobile Navigation">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeKey === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => handleItemClick(item.id)}
                  aria-current={isActive ? 'page' : undefined}
                  className={`flex items-center justify-between w-full px-3 py-2.5 rounded-lg text-left text-sm font-medium transition-colors min-h-[44px] cursor-pointer ${
                    isActive
                      ? 'text-[#005147] font-semibold bg-[#005147]/15'
                      : 'text-[#0D1C2E]/80 hover:text-[#0D1C2E] hover:bg-black/5'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-[#005147]' : 'text-[#0D1C2E]/60'}`} aria-hidden="true" />
                    <span>{item.label}</span>
                  </div>
                  {isActive && (
                    <span className="text-[10px] font-bold bg-[#005147] text-white px-2 py-0.5 rounded-full">
                      Active
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>
      )}
    </header>
  );
}
