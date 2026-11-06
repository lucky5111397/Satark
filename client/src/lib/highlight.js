/**
 * Pure highlighting utility for Satark scam detector.
 * 
 * Rules:
 * - Pure computation. Never injects unescaped HTML strings or unsafe code evaluators.
 * - Sorts indicators, clamps boundaries, merges overlapping or touching ranges.
 * - Invariant: segments.map(s => s.text).join('') strictly equals the original text.
 */

/**
 * Splits text into marked and unmarked spans for safe React rendering.
 * 
 * @param {string} text - Original input text.
 * @param {Array<{ ruleId: string, start: number, end: number }>} indicators - Detection indicators.
 * @returns {Array<{ text: string, marked: boolean, ruleIds: string[] }>}
 */
export function splitByIndicators(text, indicators) {
  if (typeof text !== 'string') return [];
  if (text.length === 0) return [];
  if (!Array.isArray(indicators) || indicators.length === 0) {
    return [{ text, marked: false, ruleIds: [] }];
  }

  const textLength = text.length;

  // 1. Sanitize and clamp intervals
  const validIntervals = [];
  for (const item of indicators) {
    if (!item || typeof item !== 'object') continue;

    const start = Number(item.start);
    const end = Number(item.end);

    // Filter invalid numeric boundaries
    if (Number.isNaN(start) || Number.isNaN(end)) continue;
    if (start >= end) continue;
    if (start >= textLength || end <= 0) continue;

    const clampedStart = Math.max(0, Math.floor(start));
    const clampedEnd = Math.min(textLength, Math.floor(end));

    if (clampedStart >= clampedEnd) continue;

    validIntervals.push({
      start: clampedStart,
      end: clampedEnd,
      ruleId: typeof item.ruleId === 'string' ? item.ruleId : 'FLAG'
    });
  }

  if (validIntervals.length === 0) {
    return [{ text, marked: false, ruleIds: [] }];
  }

  // 2. Sort intervals by start ascending, then by end descending
  validIntervals.sort((a, b) => a.start - b.start || b.end - a.end);

  // 3. Merge overlapping and touching intervals
  const merged = [];
  let current = {
    start: validIntervals[0].start,
    end: validIntervals[0].end,
    ruleIds: [validIntervals[0].ruleId]
  };

  for (let i = 1; i < validIntervals.length; i++) {
    const next = validIntervals[i];
    // If next overlaps or touches current
    if (next.start <= current.end) {
      current.end = Math.max(current.end, next.end);
      if (!current.ruleIds.includes(next.ruleId)) {
        current.ruleIds.push(next.ruleId);
      }
    } else {
      merged.push(current);
      current = {
        start: next.start,
        end: next.end,
        ruleIds: [next.ruleId]
      };
    }
  }
  merged.push(current);

  // 4. Construct contiguous alternating segments
  const segments = [];
  let cursor = 0;

  for (const span of merged) {
    if (span.start > cursor) {
      segments.push({
        text: text.substring(cursor, span.start),
        marked: false,
        ruleIds: []
      });
    }

    segments.push({
      text: text.substring(span.start, span.end),
      marked: true,
      ruleIds: span.ruleIds
    });

    cursor = span.end;
  }

  if (cursor < textLength) {
    segments.push({
      text: text.substring(cursor, textLength),
      marked: false,
      ruleIds: []
    });
  }

  return segments;
}
