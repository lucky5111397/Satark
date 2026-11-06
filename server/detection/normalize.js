/**
 * Normalization utilities for Satark detection engine.
 * 
 * Rules:
 * - NFC normalization only.
 * - MUST be strictly length-preserving so regex match indices map 1:1 to original text.
 * - Never strip whitespace, trim, or change casing in a way that shifts character offsets.
 */

/**
 * Normalizes text using Unicode Normalization Form C (NFC).
 * Note: If NFC alters length for any rare decomposed sequence, we preserve original characters
 * to ensure highlighting indices never drift.
 * @param {string} text - User input text.
 * @returns {string} - Length-preserving normalized text.
 */
export function normalizeText(text) {
  if (typeof text !== 'string') return '';
  const nfc = text.normalize('NFC');
  // Strict length preservation guard
  if (nfc.length === text.length) {
    return nfc;
  }
  return text;
}

/**
 * Detects the predominant script of the text.
 * - 'devanagari': text has Devanagari characters and no Latin letters.
 * - 'roman': text has Latin letters and no Devanagari characters.
 * - 'mixed': text contains both Devanagari and Latin letters.
 * @param {string} text
 * @returns {'roman' | 'devanagari' | 'mixed'}
 */
export function detectScript(text) {
  if (typeof text !== 'string') return 'roman';
  
  const hasDevanagari = /[\u0900-\u097F]/.test(text);
  const hasLatin = /[a-zA-Z]/.test(text);

  if (hasDevanagari && hasLatin) return 'mixed';
  if (hasDevanagari) return 'devanagari';
  return 'roman';
}

