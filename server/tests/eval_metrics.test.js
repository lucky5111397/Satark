import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { parseCSV } from '../../eval/csv.mjs';
import { evaluateDataset, calculateBinaryMetrics } from '../../eval/metrics.mjs';
import { analyzeMessage } from '../detection/analyzeMessage.js';

describe('Evaluation Metrics (eval/metrics.mjs)', () => {
  /**
   * HAND COMPUTATION for eval/fixtures/sample_eval.csv:
   * 
   * Rows in fixture (6 total):
   * S001: label=scam, amb=0, text="Dear customer..." -> predicted=Suspicious (score=7)
   * S002: label=scam, amb=0, text="Electricity bill..." -> predicted=Caution (score=1)
   * G001: label=genuine, amb=0, text="Your package..." -> predicted=No known red flags found (score=0)
   * G002: label=genuine, amb=0, text="Urgent notice..." -> predicted=Caution (score=1)
   * A001: label=genuine, amb=1, text="Please review..." -> EXCLUDED from all scored metrics!
   * G003: label=genuine, amb=0, text="Your order for ""Wireless Headphones, Pro Edition""..." -> predicted=No known red flags found (score=0)
   * 
   * Ground truth totals (excluding ambiguous):
   * Scored rows = 5
   * Scam rows (P) = 2 (S001, S002)
   * Genuine rows (N) = 3 (G001, G002, G003)
   * 
   * Flagged Definitions:
   * STRICT: category === 'Suspicious'
   *   S001 -> Suspicious -> Flagged (TP)
   *   S002 -> Caution    -> NOT Flagged (FN)
   *   G001 -> Clear      -> NOT Flagged (TN)
   *   G002 -> Caution    -> NOT Flagged (TN)
   *   G003 -> Clear      -> NOT Flagged (TN)
   *   TP = 1, FP = 0, TN = 3, FN = 1
   *   Precision = 1 / 1 = 1.0 (100.0%)
   *   Recall    = 1 / 2 = 0.5 (50.0%)
   *   FPR       = 0 / 3 = 0.0 (0.0%)
   *   F1        = 2 * (1.0 * 0.5) / (1.0 + 0.5) = 2/3 ≈ 0.6667 (66.7%)
   *   Accuracy  = (1 + 3) / 5 = 4/5 = 0.8 (80.0%)
   * 
   * LOOSE: category === 'Suspicious' || category === 'Caution'
   *   S001 -> Suspicious -> Flagged (TP)
   *   S002 -> Caution    -> Flagged (TP)
   *   G001 -> Clear      -> NOT Flagged (TN)
   *   G002 -> Caution    -> Flagged (FP)
   *   G003 -> Clear      -> NOT Flagged (TN)
   *   TP = 2, FP = 1, TN = 2, FN = 0
   *   Precision = 2 / 3 ≈ 0.6667 (66.7%)
   *   Recall    = 2 / 2 = 1.0 (100.0%)
   *   FPR       = 1 / 3 ≈ 0.3333 (33.3%)
   *   F1        = 2 * (2/3 * 1.0) / (2/3 + 1.0) = 4/5 = 0.8 (80.0%)
   *   Accuracy  = (2 + 2) / 5 = 4/5 = 0.8 (80.0%)
   */

  it('calculates exact hand-computed metrics on eval/fixtures/sample_eval.csv', () => {
    const fixturePath = path.resolve('../eval/fixtures/sample_eval.csv');
    const csvContent = fs.readFileSync(fixturePath, 'utf8');
    const rows = parseCSV(csvContent);

    expect(rows).toHaveLength(6);

    const evaluation = evaluateDataset(rows, analyzeMessage);

    // 1. Ambiguous filtering
    expect(evaluation.totalRows).toBe(6);
    expect(evaluation.scoredCount).toBe(5);
    expect(evaluation.ambiguousRows).toHaveLength(1);
    expect(evaluation.ambiguousRows[0].id).toBe('A001');

    // 2. STRICT metrics
    const { strict } = evaluation;
    expect(strict.tp).toBe(1);
    expect(strict.fp).toBe(0);
    expect(strict.tn).toBe(3);
    expect(strict.fn).toBe(1);
    expect(strict.precision).toBeCloseTo(1.0, 4);
    expect(strict.recall).toBeCloseTo(0.5, 4);
    expect(strict.fpr).toBeCloseTo(0.0, 4);
    expect(strict.f1).toBeCloseTo(2 / 3, 4);
    expect(strict.accuracy).toBeCloseTo(0.8, 4);

    // 3. LOOSE metrics
    const { loose } = evaluation;
    expect(loose.tp).toBe(2);
    expect(loose.fp).toBe(1);
    expect(loose.tn).toBe(2);
    expect(loose.fn).toBe(0);
    expect(loose.precision).toBeCloseTo(2 / 3, 4);
    expect(loose.recall).toBeCloseTo(1.0, 4);
    expect(loose.fpr).toBeCloseTo(1 / 3, 4);
    expect(loose.f1).toBeCloseTo(0.8, 4);
    expect(loose.accuracy).toBeCloseTo(0.8, 4);

    // 4. Separated False Positives and False Negatives
    expect(evaluation.strictFalsePositives).toHaveLength(0);
    expect(evaluation.strictFalseNegatives).toHaveLength(1);
    expect(evaluation.strictFalseNegatives[0].id).toBe('S002');

    expect(evaluation.looseFalsePositives).toHaveLength(1);
    expect(evaluation.looseFalsePositives[0].id).toBe('G002');
    expect(evaluation.looseFalseNegatives).toHaveLength(0);
  });

  it('handles zero denominators gracefully with "n/a"', () => {
    // When no samples are positive or flagged
    const metrics = calculateBinaryMetrics(0, 0, 5, 0); // TP=0, FP=0, TN=5, FN=0
    expect(metrics.precision).toBe('n/a'); // 0 / (0 + 0)
    expect(metrics.recall).toBe('n/a');    // 0 / (0 + 0)
    expect(metrics.fpr).toBeCloseTo(0.0, 4); // 0 / 5
    expect(metrics.f1).toBe('n/a');
    expect(metrics.accuracy).toBeCloseTo(1.0, 4);
  });
});

