# Satark Evaluation Framework

This directory contains evaluation datasets, metrics calculation harnesses, and recorded benchmark reports for the Satark scam detection engine.

> [!IMPORTANT]
> **Synthetic Data Disclosure:** All evaluation samples in this directory are fully synthetic examples created specifically for hackathon prototype benchmarking. No real user messages, personal identifiable information (PII), or live carrier network traffic was used.
>
> Reported metrics reflect synthetic test performance and do not represent real-world telecommunication base rates across Indian carrier networks.

## Directory Contents

| File | Purpose |
|------|---------|
| `EVAL_POLICY.md` | Core evaluation integrity rules and frozen-test-set protocol |
| `POST_TEST_CHANGES.md` | Formal audit log of all code changes made after official test runs |
| `test_run_log.md` | Cryptographically signed (SHA-256) log of official benchmark runs |
| `run_eval.mjs` | Evaluation runner CLI (`--set dev`, `--set test`, `--file <csv>`) |
| `metrics.mjs` | Multi-class and binary metrics computation (Precision, Recall, FPR, F1) |
| `csv.mjs` | Streaming CSV parser with column validation |
| `dev_set.csv` | Development partition (50 rows) for active tuning and rule refinement |
| `test_set.csv` | **Frozen** test partition (66 rows) reserved for benchmark validation only |
| `probe_set.csv` | Challenging edge-case probes (40 rows) |
| `benchmark_indicbert.csv` | Comparative evaluation set (120 rows) against IndicBERT baseline |
| `results_*.md` | Recorded evaluation reports (message texts omitted for publication safety) |

## Evaluation Philosophy

1. **Zero Contamination:** Rules are never tuned on frozen test errors. Test phrases are never copied into detector code.
2. **Conservative Detection:** The detector prioritizes zero false positives on genuine banking and utility messages over aggressive scam flags.
3. **Dual-Threshold Evaluation:**
   - **STRICT** (`Suspicious` only) — High precision, conservative alerts
   - **LOOSE** (`Suspicious` or `Caution`) — High recall safety net
