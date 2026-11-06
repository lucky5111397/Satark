/**
 * eval/run_eval.mjs
 * 
 * Evaluation execution harness for Satark scam detector.
 * 
 * Usage:
 *   node eval/run_eval.mjs --set dev
 *   node eval/run_eval.mjs --set test
 *   node eval/run_eval.mjs --file <path>
 * 
 * Invariants:
 * - Pure computation. Zero outbound network calls.
 * - Only text is passed to the detector; metadata (label, lang, category) is never leaked.
 * - Ambiguous=1 rows are excluded from scoring.
 * - Test-set discipline: NEVER logs or prints text for test-set rows; appends run log entry.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseCSV } from './csv.mjs';
import { evaluateDataset, getDetectorHash, buildMarkdownReport, formatPercent } from './metrics.mjs';
import { analyzeMessage } from '../server/detection/analyzeMessage.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');

/**
 * Executes evaluation on a dataset file.
 * 
 * @param {object} options
 * @param {string} options.filePath - Path to CSV file
 * @param {string} [options.setName] - Name identifier for dataset
 * @param {boolean} [options.isTestSet] - Whether this is a test set
 * @param {boolean} [options.writeReport=true] - Whether to write the markdown report to disk
 * @returns {Promise<{ evalResult: object, sha256: string, reportMarkdown: string }>}
 */
export async function runEvaluation(options) {
  const { filePath, setName = 'custom', isTestSet = false, writeReport = true, logPath: customLogPath } = options;

  if (!fs.existsSync(filePath)) {
    throw new Error(`CSV file not found: "${filePath}"`);
  }

  // 1. Read and parse CSV
  const rawCsv = fs.readFileSync(filePath, 'utf8');
  const requiredColumns = ['id', 'text', 'label', 'language', 'category', 'difficulty', 'ambiguous'];
  const rows = parseCSV(rawCsv, { requiredColumns });

  if (rows.length === 0) {
    throw new Error(`CSV file "${filePath}" contains no data rows.`);
  }

  // 2. Compute detector engine hash
  const sha256 = getDetectorHash(REPO_ROOT);
  const now = new Date().toISOString();

  // 3. Evaluate dataset
  const evalResult = evaluateDataset(rows, analyzeMessage);

  // 4. Test-set discipline logging if this is a test run
  if (isTestSet) {
    const logPath = customLogPath || path.resolve(__dirname, 'test_run_log.md');
    let runNumber = 1;

    if (fs.existsSync(logPath)) {
      const existingLog = fs.readFileSync(logPath, 'utf8');
      const lines = existingLog.split('\n').filter(l => l.startsWith('| 20'));
      runNumber = lines.length + 1;
    } else {
      const header = `# Satark Test Run Log\n\n` +
        `This file tracks official evaluation runs on the frozen test set.\n` +
        `**DISCIPLINE:** Rules must NEVER be tuned on test errors.\n\n` +
        `| Timestamp | Run # | SHA-256 | STRICT (P / R / FPR) | LOOSE (P / R / FPR) |\n` +
        `| :--- | :---: | :--- | :--- | :--- |\n`;
      fs.writeFileSync(logPath, header, 'utf8');
    }

    const strictSummary = `${formatPercent(evalResult.strict.precision)} / ${formatPercent(evalResult.strict.recall)} / ${formatPercent(evalResult.strict.fpr)}`;
    const looseSummary = `${formatPercent(evalResult.loose.precision)} / ${formatPercent(evalResult.loose.recall)} / ${formatPercent(evalResult.loose.fpr)}`;
    const logLine = `| ${now} | Run ${runNumber} | \`${sha256.substring(0, 16)}...\` | ${strictSummary} | ${looseSummary} |\n`;

    fs.appendFileSync(logPath, logLine, 'utf8');

    console.log(`\n========================================`);
    console.log(`Test run number ${runNumber}`);
    console.log(`WARNING: Rules must not be tuned using test errors!`);
    console.log(`========================================\n`);
  }

  // 5. Build report markdown
  const reportMarkdown = buildMarkdownReport(evalResult, {
    setName,
    sha256,
    date: now,
    isTestSet
  });

  // 6. Write report to disk
  if (writeReport) {
    const reportFileName = `results_${setName}.md`;
    const reportPath = path.resolve(__dirname, reportFileName);
    fs.writeFileSync(reportPath, reportMarkdown, 'utf8');
  }

  return { evalResult, sha256, reportMarkdown };
}

/**
 * Formats a terminal-friendly summary.
 */
function printTerminalSummary(evalResult, meta) {
  const { setName, sha256, isTestSet } = meta;
  const {
    strict, loose, byLanguage, byDifficulty, ambiguousRows,
    strictFalsePositives, strictFalseNegatives,
    looseFalsePositives, looseFalseNegatives
  } = evalResult;

  console.log(`\n======================================================================`);
  console.log(`SATARK EVALUATION RESULTS: ${setName.toUpperCase()}`);
  console.log(`======================================================================`);
  console.log(`Detector Engine SHA-256: ${sha256}`);
  console.log(`Total Rows: ${evalResult.totalRows} | Scored: ${evalResult.scoredCount} | Ambiguous (Excluded): ${evalResult.ambiguousCount}`);
  console.log(`Synthetic data, not real-world accuracy.\n`);

  console.log(`--- PRIMARY METRICS ---`);
  console.log(`STRICT Policy (Suspicious):`);
  console.log(`  TP: ${strict.tp} | FP: ${strict.fp} | TN: ${strict.tn} | FN: ${strict.fn}`);
  console.log(`  Precision: ${formatPercent(strict.precision)} | Recall: ${formatPercent(strict.recall)} | FPR: ${formatPercent(strict.fpr)} | F1: ${formatPercent(strict.f1)} | Accuracy: ${formatPercent(strict.accuracy)}`);

  console.log(`\nLOOSE Policy (Suspicious or Caution):`);
  console.log(`  TP: ${loose.tp} | FP: ${loose.fp} | TN: ${loose.tn} | FN: ${loose.fn}`);
  console.log(`  Precision: ${formatPercent(loose.precision)} | Recall: ${formatPercent(loose.recall)} | FPR: ${formatPercent(loose.fpr)} | F1: ${formatPercent(loose.f1)} | Accuracy: ${formatPercent(loose.accuracy)}`);

  console.log(`\n--- BREAKDOWN BY LANGUAGE ---`);
  for (const [lang, data] of Object.entries(byLanguage)) {
    console.log(`  [${lang}] Total: ${data.total} (Scam: ${data.scamCount}, Genuine: ${data.genuineCount})`);
    console.log(`    STRICT -> Recall: ${formatPercent(data.strict.recall)} | FPR: ${formatPercent(data.strict.fpr)}`);
    console.log(`    LOOSE  -> Recall: ${formatPercent(data.loose.recall)} | FPR: ${formatPercent(data.loose.fpr)}`);
  }

  console.log(`\n--- BREAKDOWN BY DIFFICULTY ---`);
  for (const [diff, data] of Object.entries(byDifficulty)) {
    console.log(`  [${diff}] Total: ${data.total} (Scam: ${data.scamCount}, Genuine: ${data.genuineCount})`);
    console.log(`    STRICT -> Acc: ${formatPercent(data.strict.accuracy)} | Recall: ${formatPercent(data.strict.recall)} | FPR: ${formatPercent(data.strict.fpr)}`);
    console.log(`    LOOSE  -> Acc: ${formatPercent(data.loose.accuracy)} | Recall: ${formatPercent(data.loose.recall)} | FPR: ${formatPercent(data.loose.fpr)}`);
  }

  if (ambiguousRows.length > 0) {
    console.log(`\n--- AMBIGUOUS ROWS (${ambiguousRows.length} excluded from metrics) ---`);
    for (const amb of ambiguousRows) {
      console.log(`  ${amb.id}: label guess="${amb.labelGuess}" => predicted="${amb.predictedCategory}" (score: ${amb.score})`);
    }
  }

  console.log(`\n--- ERROR BREAKDOWN ---`);
  console.log(`STRICT Policy:`);
  console.log(`  False Positives (Genuine flagged as Suspicious): ${strictFalsePositives.length}`);
  console.log(`  False Negatives (Scam missed as Clear/Caution):  ${strictFalseNegatives.length}`);
  console.log(`LOOSE Policy:`);
  console.log(`  False Positives (Genuine flagged as Suspicious/Caution): ${looseFalsePositives.length}`);
  console.log(`  False Negatives (Scam missed as Clear):                 ${looseFalseNegatives.length}`);

  if (isTestSet) {
    console.log(`\n[TEST SET DISCIPLINE]: Message texts are hidden to preserve test integrity.`);
    if (strictFalsePositives.length > 0) {
      console.log(`STRICT False Positives: ${strictFalsePositives.map(e => `${e.id}`).join(', ')}`);
    }
    if (strictFalseNegatives.length > 0) {
      console.log(`STRICT False Negatives: ${strictFalseNegatives.map(e => `${e.id}`).join(', ')}`);
    }
  } else {
    if (strictFalsePositives.length > 0) {
      console.log(`\nSTRICT False Positives (Genuine flagged as Suspicious - ${strictFalsePositives.length}):`);
      for (const err of strictFalsePositives) {
        const rules = err.ruleIds.length > 0 ? err.ruleIds.join(', ') : 'none';
        console.log(`  ${err.id} [${err.label} -> predicted ${err.predictedCategory}, score ${err.score}, rules: ${rules}]:`);
        console.log(`    "${err.text.replace(/\r?\n/g, ' ')}"`);
      }
    }
    if (strictFalseNegatives.length > 0) {
      console.log(`\nSTRICT False Negatives (Scam missed - ${strictFalseNegatives.length}):`);
      for (const err of strictFalseNegatives) {
        const rules = err.ruleIds.length > 0 ? err.ruleIds.join(', ') : 'none';
        console.log(`  ${err.id} [${err.label} -> predicted ${err.predictedCategory}, score ${err.score}, rules: ${rules}]:`);
        console.log(`    "${err.text.replace(/\r?\n/g, ' ')}"`);
      }
    }

    if (looseFalsePositives.length > 0) {
      console.log(`\nLOOSE False Positives (Genuine flagged as Suspicious/Caution - ${looseFalsePositives.length}):`);
      for (const err of looseFalsePositives) {
        const rules = err.ruleIds.length > 0 ? err.ruleIds.join(', ') : 'none';
        console.log(`  ${err.id} [${err.label} -> predicted ${err.predictedCategory}, score ${err.score}, rules: ${rules}]:`);
        console.log(`    "${err.text.replace(/\r?\n/g, ' ')}"`);
      }
    }
  }

  console.log(`\n======================================================================\n`);
}

/**
 * CLI Entrypoint
 */
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    console.log(`Satark Evaluation Harness\n`);
    console.log(`Usage:`);
    console.log(`  node eval/run_eval.mjs --set dev`);
    console.log(`  node eval/run_eval.mjs --set test`);
    console.log(`  node eval/run_eval.mjs --file <path>\n`);
    process.exit(args.length === 0 ? 1 : 0);
  }

  let filePath = '';
  let setName = '';
  let isTestSet = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--set') {
      const setArg = args[i + 1]?.toLowerCase();
      if (setArg === 'dev') {
        filePath = path.resolve(__dirname, 'dev_set.csv');
        setName = 'dev';
        isTestSet = false;
        i++;
      } else if (setArg === 'test') {
        filePath = path.resolve(__dirname, 'test_set.csv');
        setName = 'test';
        isTestSet = true;
        i++;
      } else {
        console.error(`Error: Unknown dataset "${args[i + 1]}". Use "dev" or "test".`);
        process.exit(1);
      }
    } else if (args[i] === '--file') {
      const fileArg = args[i + 1];
      if (!fileArg) {
        console.error(`Error: Missing file path for --file.`);
        process.exit(1);
      }
      filePath = path.resolve(fileArg);
      setName = path.basename(fileArg, path.extname(fileArg));
      isTestSet = setName.toLowerCase().includes('test');
      i++;
    }
  }

  if (!filePath) {
    console.error(`Error: No valid evaluation target specified. Use --set dev, --set test, or --file <path>.`);
    process.exit(1);
  }

  try {
    const { evalResult, sha256 } = await runEvaluation({
      filePath,
      setName,
      isTestSet,
      writeReport: true
    });

    printTerminalSummary(evalResult, { setName, sha256, isTestSet });
    console.log(`Evaluation report successfully written to eval/results_${setName}.md`);
  } catch (err) {
    console.error(`Evaluation failed: ${err.message}`);
    process.exit(1);
  }
}

// Run CLI when invoked directly
const isDirectCli = process.argv[1] && (
  path.resolve(process.argv[1]) === __filename ||
  process.argv[1].endsWith('run_eval.mjs')
);

if (isDirectCli) {
  main();
}
