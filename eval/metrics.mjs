/**
 * eval/metrics.mjs
 * 
 * Evaluation metrics computation and reporting for Satark datasets.
 * - Pure computation and analysis.
 * - Supports STRICT ("Suspicious") and LOOSE ("Suspicious" | "Caution") definitions.
 * - Calculates TP, FP, TN, FN, precision, recall, FPR, F1, accuracy with "n/a" safety for zero denominators.
 * - Handles ambiguous=1 exclusion and breakdown slicing (language, category, difficulty).
 * - Generates clean Markdown reports and CLI tables.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/**
 * Calculates binary classification metrics from confusion counts.
 * 
 * @param {number} tp - True Positives
 * @param {number} fp - False Positives
 * @param {number} tn - True Negatives
 * @param {number} fn - False Negatives
 * @returns {{
 *   tp: number, fp: number, tn: number, fn: number, total: number,
 *   precision: number | 'n/a',
 *   recall: number | 'n/a',
 *   fpr: number | 'n/a',
 *   f1: number | 'n/a',
 *   accuracy: number | 'n/a'
 * }}
 */
export function calculateBinaryMetrics(tp, fp, tn, fn) {
  const total = tp + fp + tn + fn;
  const precisionDenom = tp + fp;
  const recallDenom = tp + fn;
  const fprDenom = fp + tn;
  const accuracyDenom = total;

  const precision = precisionDenom === 0 ? 'n/a' : tp / precisionDenom;
  const recall = recallDenom === 0 ? 'n/a' : tp / recallDenom;
  const fpr = fprDenom === 0 ? 'n/a' : fp / fprDenom;
  const accuracy = accuracyDenom === 0 ? 'n/a' : (tp + tn) / accuracyDenom;

  let f1 = 'n/a';
  if (precision !== 'n/a' && recall !== 'n/a' && precision + recall > 0) {
    f1 = (2 * precision * recall) / (precision + recall);
  }

  return { tp, fp, tn, fn, total, precision, recall, fpr, f1, accuracy };
}

/**
 * Formats a metric value as a percentage string (e.g., 85.0%) or "n/a".
 * 
 * @param {number | string} val - Metric value
 * @returns {string} Formatted string
 */
export function formatPercent(val) {
  if (val === 'n/a' || val === null || val === undefined) return 'n/a';
  return (val * 100).toFixed(1) + '%';
}

/**
 * Evaluates an array of dataset rows against a detection function.
 * 
 * @param {Array<object>} rows - Parsed CSV rows
 * @param {Function} analyzeFn - analyzeMessage(text)
 * @returns {object} Evaluation results
 */
export function evaluateDataset(rows, analyzeFn) {
  const totalRows = rows.length;
  const ambiguousRows = [];
  const scoredEvaluations = [];

  for (const row of rows) {
    const isAmbiguous = String(row.ambiguous).trim() === '1';
    // Detector contract: ONLY text is provided to detector
    const res = analyzeFn(row.text);

    if (isAmbiguous) {
      ambiguousRows.push({
        id: row.id,
        labelGuess: row.label,
        predictedCategory: res.category,
        score: res.score,
        category: row.category,
        language: row.language,
        text: row.text
      });
      continue;
    }

    const isScam = String(row.label).trim().toLowerCase() === 'scam';
    const isStrict = res.category === 'Suspicious';
    const isLoose = res.category === 'Suspicious' || res.category === 'Caution';

    scoredEvaluations.push({
      id: row.id,
      label: row.label,
      isScam,
      category: row.category || 'unspecified',
      language: row.language || 'unspecified',
      difficulty: row.difficulty || 'unspecified',
      text: row.text,
      predictedCategory: res.category,
      score: res.score,
      ruleIds: Array.isArray(res.indicators) ? res.indicators.map(i => i.ruleId) : [],
      isStrict,
      isLoose
    });
  }

  // 1. Overall STRICT counts
  let sTP = 0, sFP = 0, sTN = 0, sFN = 0;
  // 2. Overall LOOSE counts
  let lTP = 0, lFP = 0, lTN = 0, lFN = 0;

  for (const item of scoredEvaluations) {
    if (item.isScam) {
      if (item.isStrict) sTP++; else sFN++;
      if (item.isLoose) lTP++; else lFN++;
    } else {
      if (item.isStrict) sFP++; else sTN++;
      if (item.isLoose) lFP++; else lTN++;
    }
  }

  const strictMetrics = calculateBinaryMetrics(sTP, sFP, sTN, sFN);
  const looseMetrics = calculateBinaryMetrics(lTP, lFP, lTN, lFN);

  // 3. Language breakdown
  const languages = [...new Set(scoredEvaluations.map(e => e.language))].sort();
  const byLanguage = {};

  for (const lang of languages) {
    const langRows = scoredEvaluations.filter(e => e.language === lang);
    let langSTP = 0, langSFP = 0, langSTN = 0, langSFN = 0;
    let langLTP = 0, langLFP = 0, langLTN = 0, langLFN = 0;

    for (const item of langRows) {
      if (item.isScam) {
        if (item.isStrict) langSTP++; else langSFN++;
        if (item.isLoose) langLTP++; else langLFN++;
      } else {
        if (item.isStrict) langSFP++; else langSTN++;
        if (item.isLoose) langLFP++; else langLTN++;
      }
    }

    const sM = calculateBinaryMetrics(langSTP, langSFP, langSTN, langSFN);
    const lM = calculateBinaryMetrics(langLTP, langLFP, langLTN, langLFN);

    byLanguage[lang] = {
      total: langRows.length,
      scamCount: langSTP + langSFN,
      genuineCount: langSFP + langSTN,
      strict: { recall: sM.recall, fpr: sM.fpr, tp: langSTP, fn: langSFN, fp: langSFP, tn: langSTN },
      loose: { recall: lM.recall, fpr: lM.fpr, tp: langLTP, fn: langLFN, fp: langLFP, tn: langLTN }
    };
  }

  // 4. Difficulty breakdown
  const difficulties = [...new Set(scoredEvaluations.map(e => e.difficulty))].sort();
  const byDifficulty = {};

  for (const diff of difficulties) {
    const diffRows = scoredEvaluations.filter(e => e.difficulty === diff);
    let dSTP = 0, dSFP = 0, dSTN = 0, dSFN = 0;
    let dLTP = 0, dLFP = 0, dLTN = 0, dLFN = 0;

    for (const item of diffRows) {
      if (item.isScam) {
        if (item.isStrict) dSTP++; else dSFN++;
        if (item.isLoose) dLTP++; else dLFN++;
      } else {
        if (item.isStrict) dSFP++; else dSTN++;
        if (item.isLoose) dLFP++; else dLTN++;
      }
    }

    byDifficulty[diff] = {
      total: diffRows.length,
      scamCount: dSTP + dSFN,
      genuineCount: dSFP + dSTN,
      strict: calculateBinaryMetrics(dSTP, dSFP, dSTN, dSFN),
      loose: calculateBinaryMetrics(dLTP, dLFP, dLTN, dLFN)
    };
  }

  // 5. Category breakdown
  const categories = [...new Set(scoredEvaluations.map(e => e.category))].sort();
  const byCategory = {};

  for (const cat of categories) {
    const catRows = scoredEvaluations.filter(e => e.category === cat);
    let cSTP = 0, cSFP = 0, cSTN = 0, cSFN = 0;
    let cLTP = 0, cLFP = 0, cLTN = 0, cLFN = 0;

    for (const item of catRows) {
      if (item.isScam) {
        if (item.isStrict) cSTP++; else cSFN++;
        if (item.isLoose) cLTP++; else cLFN++;
      } else {
        if (item.isStrict) cSFP++; else cSTN++;
        if (item.isLoose) cLFP++; else cLTN++;
      }
    }

    byCategory[cat] = {
      total: catRows.length,
      scamCount: cSTP + cSFN,
      genuineCount: cSFP + cSTN,
      strict: calculateBinaryMetrics(cSTP, cSFP, cSTN, cSFN),
      loose: calculateBinaryMetrics(cLTP, cLFP, cLTN, cLFN)
    };
  }

  // 6. Errors list
  // An error is any false negative (scam not flagged) or false positive (genuine flagged)
  const strictErrors = scoredEvaluations.filter(e => (e.isScam && !e.isStrict) || (!e.isScam && e.isStrict));
  const looseErrors = scoredEvaluations.filter(e => (e.isScam && !e.isLoose) || (!e.isScam && e.isLoose));

  // Separated False Positives (genuine flagged) and False Negatives (scam missed)
  const strictFalsePositives = scoredEvaluations.filter(e => !e.isScam && e.isStrict);
  const strictFalseNegatives = scoredEvaluations.filter(e => e.isScam && !e.isStrict);
  const looseFalsePositives = scoredEvaluations.filter(e => !e.isScam && e.isLoose);
  const looseFalseNegatives = scoredEvaluations.filter(e => e.isScam && !e.isLoose);

  return {
    totalRows,
    scoredCount: scoredEvaluations.length,
    ambiguousCount: ambiguousRows.length,
    ambiguousRows,
    scoredEvaluations,
    strict: strictMetrics,
    loose: looseMetrics,
    byLanguage,
    byDifficulty,
    byCategory,
    strictErrors,
    looseErrors,
    strictFalsePositives,
    strictFalseNegatives,
    looseFalsePositives,
    looseFalseNegatives
  };
}

/**
 * Calculates SHA-256 of concatenated contents of server/detection/*.js and server/data/*.js.
 * Files sorted alphabetically by path/filename.
 * 
 * @param {string} baseDir - Workspace root directory
 * @returns {string} Hex SHA-256 string
 */
export function getDetectorHash(baseDir) {
  const dirs = [
    path.join(baseDir, 'server', 'data'),
    path.join(baseDir, 'server', 'detection')
  ];

  const filePaths = [];
  for (const dir of dirs) {
    if (fs.existsSync(dir)) {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isFile() && entry.name.endsWith('.js')) {
          filePaths.push(path.join(dir, entry.name));
        }
      }
    }
  }

  // Sort deterministically by filename
  filePaths.sort((a, b) => path.basename(a).localeCompare(path.basename(b)));

  const hash = crypto.createHash('sha256');
  for (const f of filePaths) {
    const content = fs.readFileSync(f);
    hash.update(content);
  }

  return hash.digest('hex');
}

/**
 * Builds the Markdown report text.
 * 
 * @param {object} evalResult - Output of evaluateDataset()
 * @param {object} meta - { setName, sha256, date, isTestSet }
 * @returns {string} Markdown text
 */
export function buildMarkdownReport(evalResult, meta) {
  const { setName, sha256, date, isTestSet } = meta;
  const {
    totalRows, scoredCount, ambiguousCount, ambiguousRows,
    strict, loose, byLanguage, byDifficulty, byCategory,
    strictErrors, looseErrors
  } = evalResult;

  let md = `# Satark Evaluation Report: ${setName.toUpperCase()}\n\n`;
  md += `**Date:** ${date}\n`;
  md += `**Dataset:** \`${setName}\` (${totalRows} total rows: ${scoredCount} scored, ${ambiguousCount} ambiguous)\n`;
  md += `**Detector Engine SHA-256:** \`${sha256}\`\n\n`;
  md += `> **Synthetic data, not real-world accuracy.**\n\n`;

  // 1. Primary Metrics Table
  md += `## 1. Overall Performance Metrics\n\n`;
  md += `| Threshold Policy | TP | FP | TN | FN | Precision | Recall | False Pos Rate | F1 Score | Accuracy |\n`;
  md += `| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n`;
  md += `| **STRICT** (Suspicious) | ${strict.tp} | ${strict.fp} | ${strict.tn} | ${strict.fn} | ${formatPercent(strict.precision)} | ${formatPercent(strict.recall)} | ${formatPercent(strict.fpr)} | ${formatPercent(strict.f1)} | ${formatPercent(strict.accuracy)} |\n`;
  md += `| **LOOSE** (Suspicious or Caution) | ${loose.tp} | ${loose.fp} | ${loose.tn} | ${loose.fn} | ${formatPercent(loose.precision)} | ${formatPercent(loose.recall)} | ${formatPercent(loose.fpr)} | ${formatPercent(loose.f1)} | ${formatPercent(loose.accuracy)} |\n\n`;

  // 2. Language Breakdown
  md += `## 2. Language Breakdown\n\n`;
  md += `| Language | Total | Scam | Genuine | STRICT Recall (Scam) | STRICT FPR (Genuine) | LOOSE Recall (Scam) | LOOSE FPR (Genuine) |\n`;
  md += `| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n`;
  for (const [lang, data] of Object.entries(byLanguage)) {
    md += `| \`${lang}\` | ${data.total} | ${data.scamCount} | ${data.genuineCount} | ${formatPercent(data.strict.recall)} | ${formatPercent(data.strict.fpr)} | ${formatPercent(data.loose.recall)} | ${formatPercent(data.loose.fpr)} |\n`;
  }
  md += `\n`;

  // 3. Difficulty Breakdown
  md += `## 3. Difficulty Breakdown\n\n`;
  md += `| Difficulty | Scored | Scam | Genuine | STRICT Recall | STRICT FPR | STRICT Acc | LOOSE Recall | LOOSE FPR | LOOSE Acc |\n`;
  md += `| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n`;
  for (const [diff, data] of Object.entries(byDifficulty)) {
    md += `| \`${diff}\` | ${data.total} | ${data.scamCount} | ${data.genuineCount} | ${formatPercent(data.strict.recall)} | ${formatPercent(data.strict.fpr)} | ${formatPercent(data.strict.accuracy)} | ${formatPercent(data.loose.recall)} | ${formatPercent(data.loose.fpr)} | ${formatPercent(data.loose.accuracy)} |\n`;
  }
  md += `\n`;

  // 4. Category Breakdown
  md += `## 4. Category Breakdown\n\n`;
  md += `| Category | Total | Scam | Genuine | STRICT Acc | STRICT Recall | LOOSE Acc | LOOSE Recall |\n`;
  md += `| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n`;
  for (const [cat, data] of Object.entries(byCategory)) {
    md += `| \`${cat}\` | ${data.total} | ${data.scamCount} | ${data.genuineCount} | ${formatPercent(data.strict.accuracy)} | ${formatPercent(data.strict.recall)} | ${formatPercent(data.loose.accuracy)} | ${formatPercent(data.loose.recall)} |\n`;
  }
  md += `\n`;

  // 5. Ambiguous Rows
  md += `## 5. Ambiguous Rows (Excluded from Metrics)\n\n`;
  if (ambiguousRows.length === 0) {
    md += `*None (0 ambiguous rows)*\n\n`;
  } else {
    md += `| ID | Ground Truth Guess | Predicted Category | Score | Language | Category |\n`;
    md += `| :--- | :--- | :--- | :---: | :---: | :--- |\n`;
    for (const amb of ambiguousRows) {
      md += `| \`${amb.id}\` | \`${amb.labelGuess}\` | **${amb.predictedCategory}** | ${amb.score} | \`${amb.language}\` | \`${amb.category}\` |\n`;
    }
    md += `\n`;
  }

  // 6. Error Analysis
  md += `## 6. Error Analysis\n\n`;

  function renderErrorSection(title, list) {
    let out = `### ${title} (${list.length})\n\n`;
    if (list.length === 0) {
      out += `*None (0 rows)*\n\n`;
      return out;
    }
    if (isTestSet) {
      out += `> **Security & Test-Set Discipline:** Message texts are omitted for the frozen test set.\n\n`;
      out += `| ID | Truth | Predicted Category | Category | Language | Triggered Rules |\n`;
      out += `| :--- | :--- | :--- | :--- | :---: | :--- |\n`;
      for (const err of list) {
        const rules = err.ruleIds.length > 0 ? err.ruleIds.join(', ') : '*(none)*';
        out += `| \`${err.id}\` | \`${err.label}\` | **${err.predictedCategory}** | \`${err.category}\` | \`${err.language}\` | ${rules} |\n`;
      }
      out += `\n`;
    } else {
      out += `| ID | Truth | Predicted | Score | Rules | Text |\n`;
      out += `| :--- | :--- | :--- | :---: | :--- | :--- |\n`;
      for (const err of list) {
        const rules = err.ruleIds.length > 0 ? err.ruleIds.join(', ') : '*(none)*';
        const safeText = err.text.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
        out += `| \`${err.id}\` | \`${err.label}\` | **${err.predictedCategory}** | ${err.score} | ${rules} | ${safeText} |\n`;
      }
      out += `\n`;
    }
    return out;
  }

  md += renderErrorSection('STRICT False Positives (Genuine Flagged as Suspicious)', evalResult.strictFalsePositives);
  md += renderErrorSection('STRICT False Negatives (Scam Missed)', evalResult.strictFalseNegatives);
  md += renderErrorSection('LOOSE False Positives (Genuine Flagged as Suspicious or Caution)', evalResult.looseFalsePositives);
  md += renderErrorSection('LOOSE False Negatives (Scam Missed)', evalResult.looseFalseNegatives);

  return md;
}

