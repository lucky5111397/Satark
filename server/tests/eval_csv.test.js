import { describe, it, expect } from 'vitest';
import { parseCSV } from '../../eval/csv.mjs';

describe('RFC-4180 CSV Parser (eval/csv.mjs)', () => {
  it('handles quoted commas properly', () => {
    const csv = 'id,text,label\n1,"Hello, world!",scam';
    const rows = parseCSV(csv);
    expect(rows).toEqual([
      { id: '1', text: 'Hello, world!', label: 'scam' },
    ]);
  });

  it('handles doubled quotes inside quoted fields', () => {
    const csv = 'id,text,label\n2,"He said ""Act now"" urgently",scam';
    const rows = parseCSV(csv);
    expect(rows).toEqual([
      { id: '2', text: 'He said "Act now" urgently', label: 'scam' },
    ]);
  });

  it('handles multi-line cells containing newlines', () => {
    const csv = 'id,text,label\n3,"Line 1\nLine 2\r\nLine 3",genuine';
    const rows = parseCSV(csv);
    expect(rows).toEqual([
      { id: '3', text: 'Line 1\nLine 2\r\nLine 3', label: 'genuine' },
    ]);
  });

  it('handles CRLF line terminators', () => {
    const csv = 'id,label\r\n10,scam\r\n20,genuine\r\n';
    const rows = parseCSV(csv);
    expect(rows).toEqual([
      { id: '10', label: 'scam' },
      { id: '20', label: 'genuine' },
    ]);
  });

  it('strips UTF-8 Byte Order Mark (BOM)', () => {
    const csv = '\uFEFFid,label\n1,scam';
    const rows = parseCSV(csv);
    expect(rows).toEqual([
      { id: '1', label: 'scam' },
    ]);
    expect(Object.keys(rows[0])).toEqual(['id', 'label']);
  });

  it('preserves Devanagari text correctly', () => {
    const csv = 'id,text,language\n4,"सरकारी नौकरी भर्ती 2026: आवेदन शुल्क ₹450 जमा करें",hi';
    const rows = parseCSV(csv);
    expect(rows).toEqual([
      { id: '4', text: 'सरकारी नौकरी भर्ती 2026: आवेदन शुल्क ₹450 जमा करें', language: 'hi' },
    ]);
  });

  it('handles empty cells', () => {
    const csv = 'id,text,notes\n5,"Sample text",\n6,,some note';
    const rows = parseCSV(csv);
    expect(rows).toEqual([
      { id: '5', text: 'Sample text', notes: '' },
      { id: '6', text: '', notes: 'some note' },
    ]);
  });

  it('throws on a malformed row with mismatched column count', () => {
    const csv = 'id,text,label\n1,too,many,columns,here';
    expect(() => parseCSV(csv)).toThrow(/expected 3 columns, got 5/i);
  });

  it('throws on unclosed quote', () => {
    const csv = 'id,text,label\n1,"Unclosed quote string,scam';
    expect(() => parseCSV(csv)).toThrow(/unclosed quote/i);
  });

  it('throws on missing required columns', () => {
    const csv = 'id,text\n1,Hello';
    expect(() => parseCSV(csv, { requiredColumns: ['id', 'text', 'label'] })).toThrow(
      /missing required column.*label/i
    );
  });
});

