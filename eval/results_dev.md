# Satark Evaluation Report: DEV

**Date:** 2026-11-03T06:24:27.439Z
**Dataset:** `dev` (50 total rows: 50 scored, 0 ambiguous)
**Detector Engine SHA-256:** `6f4e44102423032e8ce404740852eac7d49fb7647f83b960100ad30f01633a62`

> **Synthetic data, not real-world accuracy.**

## 1. Overall Performance Metrics

| Threshold Policy | TP | FP | TN | FN | Precision | Recall | False Pos Rate | F1 Score | Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **STRICT** (Suspicious) | 16 | 0 | 25 | 9 | 100.0% | 64.0% | 0.0% | 78.0% | 82.0% |
| **LOOSE** (Suspicious or Caution) | 25 | 0 | 25 | 0 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% |

## 2. Language Breakdown

| Language | Total | Scam | Genuine | STRICT Recall (Scam) | STRICT FPR (Genuine) | LOOSE Recall (Scam) | LOOSE FPR (Genuine) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `en` | 16 | 8 | 8 | 75.0% | 0.0% | 100.0% | 0.0% |
| `hi` | 17 | 8 | 9 | 75.0% | 0.0% | 100.0% | 0.0% |
| `hinglish` | 17 | 9 | 8 | 44.4% | 0.0% | 100.0% | 0.0% |

## 3. Difficulty Breakdown

| Difficulty | Scored | Scam | Genuine | STRICT Recall | STRICT FPR | STRICT Acc | LOOSE Recall | LOOSE FPR | LOOSE Acc |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `easy` | 30 | 15 | 15 | 73.3% | 0.0% | 86.7% | 100.0% | 0.0% | 100.0% |
| `hard` | 20 | 10 | 10 | 50.0% | 0.0% | 75.0% | 100.0% | 0.0% | 100.0% |

## 4. Category Breakdown

| Category | Total | Scam | Genuine | STRICT Acc | STRICT Recall | LOOSE Acc | LOOSE Recall |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `appointment_reminder` | 2 | 0 | 2 | 100.0% | n/a | 100.0% | n/a |
| `bank_debit_credit` | 2 | 0 | 2 | 100.0% | n/a | 100.0% | n/a |
| `bank_otp` | 2 | 0 | 2 | 100.0% | n/a | 100.0% | n/a |
| `bank_statement_notice` | 2 | 0 | 2 | 100.0% | n/a | 100.0% | n/a |
| `bijli_threat` | 2 | 2 | 0 | 0.0% | 0.0% | 100.0% | 100.0% |
| `bill_reminder` | 2 | 0 | 2 | 100.0% | n/a | 100.0% | n/a |
| `courier_fee` | 2 | 2 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `customs_parcel` | 2 | 2 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `delivery_update` | 2 | 0 | 2 | 100.0% | n/a | 100.0% | n/a |
| `ecommerce_offer` | 2 | 0 | 2 | 100.0% | n/a | 100.0% | n/a |
| `fake_refund` | 1 | 1 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `gas_subsidy` | 1 | 1 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `genuine_kyc_reminder` | 2 | 0 | 2 | 100.0% | n/a | 100.0% | n/a |
| `government_notice` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |
| `impersonation` | 2 | 2 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `income_tax_refund` | 1 | 1 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `insurance_lapse` | 1 | 1 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `insurance_premium_reminder` | 2 | 0 | 2 | 100.0% | n/a | 100.0% | n/a |
| `job_fee` | 2 | 2 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `kyc` | 2 | 2 | 0 | 0.0% | 0.0% | 100.0% | 100.0% |
| `link_only_phishing` | 1 | 1 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `loan_fee` | 2 | 2 | 0 | 50.0% | 50.0% | 100.0% | 100.0% |
| `lottery_reward` | 1 | 1 | 0 | 0.0% | 0.0% | 100.0% | 100.0% |
| `otp` | 2 | 2 | 0 | 50.0% | 50.0% | 100.0% | 100.0% |
| `otp_for_login_other_app` | 2 | 0 | 2 | 100.0% | n/a | 100.0% | n/a |
| `recharge_reminder` | 2 | 0 | 2 | 100.0% | n/a | 100.0% | n/a |
| `sim_swap` | 2 | 2 | 0 | 0.0% | 0.0% | 100.0% | 100.0% |
| `travel_ticket` | 2 | 0 | 2 | 100.0% | n/a | 100.0% | n/a |
| `upi_collect` | 1 | 1 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |

## 5. Ambiguous Rows (Excluded from Metrics)

*None (0 ambiguous rows)*

## 6. Error Analysis

### STRICT False Positives (Genuine Flagged as Suspicious) (0)

*None (0 rows)*

### STRICT False Negatives (Scam Missed) (9)

> **Evaluation Discipline:** Message texts are omitted from published reports. All examples are fully synthetic — generated for hackathon prototype evaluation, not sourced from real user messages.

| ID | Truth | Predicted | Score | Rules |
| :--- | :--- | :--- | :---: | :--- |
| `D001` | `scam` | **Caution** | 3 | *(none)* |
| `D005` | `scam` | **Caution** | 3 | SENSITIVE_INFO_REQUEST |
| `D009` | `scam` | **Caution** | 2 | FEAR |
| `D011` | `scam` | **Caution** | 3 | OTP_REQUEST |
| `D017` | `scam` | **Caution** | 3 | ADVANCE_FEE |
| `D027` | `scam` | **Caution** | 3 | SENSITIVE_INFO_REQUEST |
| `D035` | `scam` | **Caution** | 2 | FEAR |
| `D039` | `scam` | **Caution** | 3 | *(none)* |
| `D043` | `scam` | **Caution** | 2 | FAKE_REWARD |

### LOOSE False Positives (Genuine Flagged as Suspicious or Caution) (0)

*None (0 rows)*

### LOOSE False Negatives (Scam Missed) (0)

*None (0 rows)*

