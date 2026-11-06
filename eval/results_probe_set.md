# Satark Evaluation Report: PROBE_SET

**Date:** 2026-11-01T09:20:36.193Z
**Dataset:** `probe_set` (40 total rows: 40 scored, 0 ambiguous)
**Detector Engine SHA-256:** `013217665e794320190a4c18a8c0133c04e2ee8555eeba03112c680876c2f1f5`

> **Synthetic data, not real-world accuracy.**

## 1. Overall Performance Metrics

| Threshold Policy | TP | FP | TN | FN | Precision | Recall | False Pos Rate | F1 Score | Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **STRICT** (Suspicious) | 8 | 0 | 20 | 12 | 100.0% | 40.0% | 0.0% | 57.1% | 70.0% |
| **LOOSE** (Suspicious or Caution) | 15 | 2 | 18 | 5 | 88.2% | 75.0% | 10.0% | 81.1% | 82.5% |

## 2. Language Breakdown

| Language | Total | Scam | Genuine | STRICT Recall (Scam) | STRICT FPR (Genuine) | LOOSE Recall (Scam) | LOOSE FPR (Genuine) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `en` | 12 | 6 | 6 | 16.7% | 0.0% | 66.7% | 16.7% |
| `hi` | 14 | 7 | 7 | 57.1% | 0.0% | 85.7% | 14.3% |
| `hinglish` | 14 | 7 | 7 | 42.9% | 0.0% | 71.4% | 0.0% |

## 3. Difficulty Breakdown

| Difficulty | Scored | Scam | Genuine | STRICT Recall | STRICT FPR | STRICT Acc | LOOSE Recall | LOOSE FPR | LOOSE Acc |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `easy` | 16 | 10 | 6 | 40.0% | 0.0% | 62.5% | 80.0% | 0.0% | 87.5% |
| `hard` | 24 | 10 | 14 | 40.0% | 0.0% | 75.0% | 70.0% | 14.3% | 79.2% |

## 4. Category Breakdown

| Category | Total | Scam | Genuine | STRICT Acc | STRICT Recall | LOOSE Acc | LOOSE Recall |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `bank_debit_credit` | 3 | 0 | 3 | 100.0% | n/a | 100.0% | n/a |
| `bank_otp` | 3 | 0 | 3 | 100.0% | n/a | 100.0% | n/a |
| `bijli_threat` | 3 | 3 | 0 | 33.3% | 33.3% | 66.7% | 66.7% |
| `bill_reminder` | 2 | 0 | 2 | 100.0% | n/a | 100.0% | n/a |
| `courier_fee` | 3 | 0 | 3 | 100.0% | n/a | 100.0% | n/a |
| `customs_parcel` | 3 | 3 | 0 | 66.7% | 66.7% | 100.0% | 100.0% |
| `fake_refund` | 1 | 1 | 0 | 0.0% | 0.0% | 100.0% | 100.0% |
| `gas_subsidy` | 1 | 1 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `genuine_kyc_reminder` | 3 | 0 | 3 | 100.0% | n/a | 33.3% | n/a |
| `impersonation` | 2 | 2 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `income_tax_refund` | 1 | 1 | 0 | 0.0% | 0.0% | 100.0% | 100.0% |
| `loan_fee` | 3 | 3 | 0 | 33.3% | 33.3% | 33.3% | 33.3% |
| `otp` | 3 | 3 | 0 | 0.0% | 0.0% | 33.3% | 33.3% |
| `planned_maintenance` | 3 | 0 | 3 | 100.0% | n/a | 100.0% | n/a |
| `security_awareness` | 3 | 0 | 3 | 100.0% | n/a | 100.0% | n/a |
| `sim_swap` | 3 | 3 | 0 | 33.3% | 33.3% | 100.0% | 100.0% |

## 5. Ambiguous Rows (Excluded from Metrics)

*None (0 ambiguous rows)*

## 6. Error Analysis

### STRICT False Positives (Genuine Flagged as Suspicious) (0)

*None (0 rows)*

### STRICT False Negatives (Scam Missed) (12)

| ID | Truth | Predicted | Score | Rules |
| :--- | :--- | :--- | :---: | :--- |
| `P001` | `scam` | **No known red flags found** | 0 | *(none)* |
| `P003` | `scam` | **No known red flags found** | 0 | *(none)* |
| `P010` | `scam` | **Caution** | 3 | *(none)* |
| `P013` | `scam` | **Caution** | 3 | *(none)* |
| `P017` | `scam` | **Caution** | 2 | UNSOLICITED_REFUND, UNSOLICITED_REFUND |
| `P020` | `scam` | **Caution** | 1 | URGENCY |
| `P024` | `scam` | **Caution** | 3 | SENSITIVE_INFO_REQUEST |
| `P025` | `scam` | **No known red flags found** | 0 | *(none)* |
| `P027` | `scam` | **Caution** | 1 | URGENCY |
| `P029` | `scam` | **No known red flags found** | 0 | *(none)* |
| `P032` | `scam` | **Caution** | 3 | *(none)* |
| `P034` | `scam` | **No known red flags found** | 0 | *(none)* |

### LOOSE False Positives (Genuine Flagged as Suspicious or Caution) (2)

| ID | Truth | Predicted | Score | Rules |
| :--- | :--- | :--- | :---: | :--- |
| `P035` | `genuine` | **Caution** | 2 | KYC_LURE |
| `P040` | `genuine` | **Caution** | 2 | KYC_LURE |

### LOOSE False Negatives (Scam Missed) (5)

| ID | Truth | Predicted | Score | Rules |
| :--- | :--- | :--- | :---: | :--- |
| `P001` | `scam` | **No known red flags found** | 0 | *(none)* |
| `P003` | `scam` | **No known red flags found** | 0 | *(none)* |
| `P025` | `scam` | **No known red flags found** | 0 | *(none)* |
| `P029` | `scam` | **No known red flags found** | 0 | *(none)* |
| `P034` | `scam` | **No known red flags found** | 0 | *(none)* |

