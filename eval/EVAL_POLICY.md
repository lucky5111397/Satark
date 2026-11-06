# Satark Evaluation Policy & Methodology

This document outlines the evaluation integrity rules for the Satark project. Adherence to these principles ensures that our evaluation metrics remain trustworthy, reproducible, and uncorrupted by data leakage.

---

## 1. Role of the Datasets

### A. The Development Set (`eval/dev_set.csv`)
- **Purpose:** Tuning and iteration.
- You can inspect errors, tune regular expressions, adjust heuristics, tweak weights, and iterate on detection rules based on the development set.
- All engineering experiments and feature engineering must be done on this set.

### B. The Frozen Test Set (`eval/test_set.csv`)
- **Purpose:** Final validation and benchmark measurement only.
- The test set is strictly **frozen**.
- It must **never** be used to write rules, adjust weights, or tune thresholds.
- Only run against the test set when an evaluation milestone is reached.

---

## 2. Cardinal Rules of Evaluation Discipline

1. **Never copy test texts into rules or unit tests:**
   - Test set phrases, brands, or wording must never appear in `server/detection/`, `server/data/`, or test assertions.
   - Any rule pattern written specifically to match a test set row is considered dataset contamination.

2. **Never inspect test errors to tune rules:**
   - The evaluation harness intentionally conceals raw message texts when reporting on the test set.
   - If an error is noticed on the test set, do NOT write a targeted rule for that specific message.

3. **Mandatory logging of post-test changes:**
   - Every official run against the test set (`--set test`) is cryptographically fingerprinted (SHA-256 of all detection engine code) and logged in `eval/test_run_log.md`.
   - Any detector modification made *after* a test set run must be formally documented as a **post-test change** along with the rationale.

4. **Synthetic data disclosure:**
   - All evaluation samples in `dev_set.csv` and `test_set.csv` are synthetic examples created for hackathon prototype evaluation.
   - The reported accuracy, precision, and recall numbers are synthetic benchmark indicators and **do not represent real-world telecommunication accuracy, prevalence, or base-rate distribution across Indian carrier networks.**
   - All reports, presentations, and documentation must include the disclaimer:
     > *"Synthetic data, not real-world accuracy."*

---

## 3. Ambiguous Messages Protocol

- Messages where ground truth intent cannot be definitively verified without out-of-band context are flagged with `ambiguous = 1`.
- Ambiguous messages are **strictly excluded** from all scored metrics (precision, recall, false-positive rate, F1 score, and accuracy).
- They are tracked and displayed in a dedicated diagnostic table to highlight real-world grey areas.

---

## 4. Evaluation CLI Usage

Run the development set baseline:
```bash
node eval/run_eval.mjs --set dev
```

Run the frozen test set (only when explicitly authorized):
```bash
node eval/run_eval.mjs --set test
```

Evaluate any custom CSV dataset:
```bash
node eval/run_eval.mjs --file <path/to/dataset.csv>
```

