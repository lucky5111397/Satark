import { describe, it, expect, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { runEvaluation } from '../../eval/run_eval.mjs';

describe('Evaluation Script Runner (eval/run_eval.mjs)', () => {
  const generatedReport = path.resolve('../eval/results_sample_test_run.md');
  const tempTestLog = path.resolve('../eval/temp_test_log_for_vitest.md');

  afterEach(() => {
    if (fs.existsSync(generatedReport)) {
      fs.unlinkSync(generatedReport);
    }
    if (fs.existsSync(tempTestLog)) {
      fs.unlinkSync(tempTestLog);
    }
  });

  it('runs evaluation on sample_eval.csv and writes report', async () => {
    const fixturePath = path.resolve('../eval/fixtures/sample_eval.csv');
    const result = await runEvaluation({
      filePath: fixturePath,
      setName: 'sample_test_run',
      isTestSet: false,
      writeReport: true
    });

    expect(result.evalResult.totalRows).toBe(6);
    expect(result.evalResult.scoredCount).toBe(5);
    expect(result.evalResult.ambiguousCount).toBe(1);
    expect(result.sha256).toMatch(/^[a-f0-9]{64}$/);

    // Verify report was written
    expect(fs.existsSync(generatedReport)).toBe(true);
    const content = fs.readFileSync(generatedReport, 'utf8');
    expect(content).toContain('Synthetic data, not real-world accuracy.');
    expect(content).toContain('**STRICT** (Suspicious)');
    expect(content).toContain('**LOOSE** (Suspicious or Caution)');
    expect(content).toContain('### STRICT False Positives');
    expect(content).toContain('### STRICT False Negatives');
    expect(content).toContain('### LOOSE False Positives');
    expect(content).toContain('### LOOSE False Negatives');
    expect(content).toContain(result.sha256);
  });

  it('enforces test-set discipline: never includes text in test set report', async () => {
    const fixturePath = path.resolve('../eval/fixtures/sample_eval.csv');
    const result = await runEvaluation({
      filePath: fixturePath,
      setName: 'sample_test_run',
      isTestSet: true,
      writeReport: true,
      logPath: tempTestLog
    });

    const content = fs.readFileSync(generatedReport, 'utf8');
    expect(content).toContain('Security & Test-Set Discipline:');
    // Ensure raw text of error rows is NOT leaked in test report
    expect(content).not.toContain('Electricity bill payment overdue');
  });

  it('throws an error if CSV file does not exist', async () => {
    await expect(runEvaluation({
      filePath: 'non_existent_file.csv',
      setName: 'missing'
    })).rejects.toThrow(/CSV file not found/i);
  });
});
