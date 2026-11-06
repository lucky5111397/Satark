/**
 * eval/csv.mjs
 * 
 * Handcrafted RFC-4180 compliant CSV parser.
 * - Zero external dependencies.
 * - Preserves UTF-8 encoding (including Devanagari script).
 * - Strips UTF-8 Byte Order Mark (BOM) if present.
 * - Handles quoted fields, doubled quotes ("" -> "), commas and newlines inside quotes.
 * - Supports CRLF (\r\n) and LF (\n) row terminators.
 * - Returns an array of objects keyed by the header row.
 * - Throws descriptive errors on malformed rows or missing required columns.
 */

/**
 * Parses an RFC-4180 CSV string into an array of objects.
 * 
 * @param {string} input - Raw CSV text
 * @param {object} [options]
 * @param {string[]} [options.requiredColumns] - Optional list of column names that must exist in the header
 * @returns {Array<Record<string, string>>} Array of row objects
 */
export function parseCSV(input, options = {}) {
  if (typeof input !== 'string') {
    throw new TypeError('CSV input must be a string');
  }

  // 1. Strip UTF-8 Byte Order Mark (BOM) if present
  if (input.charCodeAt(0) === 0xFEFF) {
    input = input.slice(1);
  }

  const rows = [];
  let currentRow = [];
  let currentField = '';
  let inQuotes = false;
  let lineNum = 1;

  const len = input.length;

  for (let i = 0; i < len; i++) {
    const ch = input[i];

    if (inQuotes) {
      if (ch === '"') {
        if (i + 1 < len && input[i + 1] === '"') {
          // Doubled quote escapes to a single quote inside a quoted field
          currentField += '"';
          i++; // Skip the second quote
        } else {
          // Quote closes
          inQuotes = false;
        }
      } else {
        currentField += ch;
        if (ch === '\n') {
          lineNum++;
        }
      }
    } else {
      // Outside quotes
      if (ch === '"') {
        inQuotes = true;
      } else if (ch === ',') {
        currentRow.push(currentField);
        currentField = '';
      } else if (ch === '\r') {
        // Handle \r\n or standalone \r
        if (i + 1 < len && input[i + 1] === '\n') {
          i++;
        }
        currentRow.push(currentField);
        rows.push({ fields: currentRow, line: lineNum });
        currentRow = [];
        currentField = '';
        lineNum++;
      } else if (ch === '\n') {
        currentRow.push(currentField);
        rows.push({ fields: currentRow, line: lineNum });
        currentRow = [];
        currentField = '';
        lineNum++;
      } else {
        currentField += ch;
      }
    }
  }

  // Check for unclosed quotes
  if (inQuotes) {
    throw new Error(`Malformed CSV: unclosed quote at line ${lineNum}`);
  }

  // Flush the final field/row if any characters or fields remain
  if (currentField !== '' || currentRow.length > 0) {
    currentRow.push(currentField);
    rows.push({ fields: currentRow, line: lineNum });
  }

  // Handle empty file or trailing empty lines
  if (rows.length === 0) {
    return [];
  }

  // Filter out a single trailing empty row often left by a final newline
  if (
    rows.length > 1 &&
    rows[rows.length - 1].fields.length === 1 &&
    rows[rows.length - 1].fields[0] === ''
  ) {
    rows.pop();
  }

  // 2. Extract and validate headers
  const headerRecord = rows[0];
  const headers = headerRecord.fields.map(h => h.trim());
  const expectedColCount = headers.length;

  // Validate required columns if specified
  if (Array.isArray(options.requiredColumns)) {
    for (const reqCol of options.requiredColumns) {
      if (!headers.includes(reqCol)) {
        throw new Error(`Missing required column: "${reqCol}". Available columns: ${headers.join(', ')}`);
      }
    }
  }

  // 3. Map remaining data rows to objects
  const result = [];
  for (let r = 1; r < rows.length; r++) {
    const { fields, line } = rows[r];

    // If a completely blank line occurs in the middle, check if empty
    if (fields.length === 1 && fields[0] === '') {
      continue;
    }

    if (fields.length !== expectedColCount) {
      throw new Error(
        `Malformed CSV row at line ${line}: expected ${expectedColCount} columns, got ${fields.length}`
      );
    }

    const rowObj = {};
    for (let c = 0; c < expectedColCount; c++) {
      rowObj[headers[c]] = fields[c];
    }
    result.push(rowObj);
  }

  return result;
}

