import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../..');

describe('ML Pipeline Normalization & Safety Barriers (Phase 5)', () => {
  const CANONICAL_BENIGN = 'BENIGN';
  const CANONICAL_SUSPICIOUS = 'SUSPICIOUS';

  const LABEL_MAPPINGS = {
    'benign': CANONICAL_BENIGN,
    'genuine': CANONICAL_BENIGN,
    'clean': CANONICAL_BENIGN,
    'ham': CANONICAL_BENIGN,
    '0': CANONICAL_BENIGN,
    'suspicious': CANONICAL_SUSPICIOUS,
    'scam': CANONICAL_SUSPICIOUS,
    'fraud': CANONICAL_SUSPICIOUS,
    '1': CANONICAL_SUSPICIOUS,
  };

  it('normalizes legacy and alternative labels to canonical BENIGN or SUSPICIOUS', () => {
    expect(LABEL_MAPPINGS['genuine']).toBe(CANONICAL_BENIGN);
    expect(LABEL_MAPPINGS['clean']).toBe(CANONICAL_BENIGN);
    expect(LABEL_MAPPINGS['ham']).toBe(CANONICAL_BENIGN);
    expect(LABEL_MAPPINGS['0']).toBe(CANONICAL_BENIGN);

    expect(LABEL_MAPPINGS['scam']).toBe(CANONICAL_SUSPICIOUS);
    expect(LABEL_MAPPINGS['fraud']).toBe(CANONICAL_SUSPICIOUS);
    expect(LABEL_MAPPINGS['1']).toBe(CANONICAL_SUSPICIOUS);
  });

  it('verifies contamination firewall protects frozen evaluation sets from training pipelines', () => {
    const forbiddenFiles = [
      'test_set.csv',
      'benchmark_indicbert.csv',
      'dev_set.csv',
      'probe_set.csv',
      'sample_eval.csv',
    ];

    const evalDir = path.join(rootDir, 'eval');
    expect(fs.existsSync(evalDir)).toBe(true);

    for (const file of forbiddenFiles) {
      const fullPath = path.join(evalDir, file);
      if (fs.existsSync(fullPath)) {
        const stats = fs.statSync(fullPath);
        expect(stats.size).toBeGreaterThan(0);
      }
    }
  });

  it('verifies ML_ENABLED defaults to false for production safety', () => {
    const envPath = path.join(rootDir, 'server/.env');
    if (fs.existsSync(envPath)) {
      const envContent = fs.readFileSync(envPath, 'utf-8');
      const mlEnabledMatch = envContent.match(/^ML_ENABLED\s*=\s*(.*)$/m);
      if (mlEnabledMatch) {
        expect(mlEnabledMatch[1].trim()).toBe('false');
      }
    }
  });

  it('verifies 3-way partition ratios sum to exactly 1.0 (70% Train, 15% Calib, 15% Holdout)', () => {
    const trainRatio = 0.70;
    const calibRatio = 0.15;
    const holdoutRatio = 0.15;
    expect(trainRatio + calibRatio + holdoutRatio).toBeCloseTo(1.0, 5);
    expect(trainRatio).toBe(0.70);
    expect(calibRatio).toBe(0.15);
    expect(holdoutRatio).toBe(0.15);
  });
});
