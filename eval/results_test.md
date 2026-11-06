# Satark Evaluation Report: TEST

**Date:** 2026-11-03T06:24:33.985Z
**Dataset:** `test` (66 total rows: 60 scored, 6 ambiguous)
**Detector Engine SHA-256:** `6f4e44102423032e8ce404740852eac7d49fb7647f83b960100ad30f01633a62`

> **Synthetic data, not real-world accuracy.**

## 1. Overall Performance Metrics

| Threshold Policy | TP | FP | TN | FN | Precision | Recall | False Pos Rate | F1 Score | Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **STRICT** (Suspicious) | 15 | 1 | 29 | 15 | 93.8% | 50.0% | 3.3% | 65.2% | 73.3% |
| **LOOSE** (Suspicious or Caution) | 26 | 8 | 22 | 4 | 76.5% | 86.7% | 26.7% | 81.3% | 80.0% |

## 2. Language Breakdown

| Language | Total | Scam | Genuine | STRICT Recall (Scam) | STRICT FPR (Genuine) | LOOSE Recall (Scam) | LOOSE FPR (Genuine) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `en` | 20 | 10 | 10 | 40.0% | 0.0% | 90.0% | 20.0% |
| `hi` | 20 | 10 | 10 | 70.0% | 10.0% | 90.0% | 30.0% |
| `hinglish` | 20 | 10 | 10 | 40.0% | 0.0% | 80.0% | 30.0% |

## 3. Difficulty Breakdown

| Difficulty | Scored | Scam | Genuine | STRICT Recall | STRICT FPR | STRICT Acc | LOOSE Recall | LOOSE FPR | LOOSE Acc |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `easy` | 40 | 22 | 18 | 59.1% | 0.0% | 77.5% | 95.5% | 5.6% | 95.0% |
| `hard` | 20 | 8 | 12 | 25.0% | 8.3% | 65.0% | 62.5% | 58.3% | 50.0% |

## 4. Category Breakdown

| Category | Total | Scam | Genuine | STRICT Acc | STRICT Recall | LOOSE Acc | LOOSE Recall |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `appointment_reminder` | 3 | 0 | 3 | 100.0% | n/a | 100.0% | n/a |
| `bank_debit_credit` | 3 | 0 | 3 | 100.0% | n/a | 33.3% | n/a |
| `bank_otp` | 3 | 0 | 3 | 100.0% | n/a | 100.0% | n/a |
| `bijli_threat` | 3 | 3 | 0 | 0.0% | 0.0% | 66.7% | 66.7% |
| `bill_reminder` | 3 | 0 | 3 | 100.0% | n/a | 66.7% | n/a |
| `courier_fee` | 3 | 3 | 0 | 66.7% | 66.7% | 100.0% | 100.0% |
| `delivery_update` | 3 | 0 | 3 | 100.0% | n/a | 100.0% | n/a |
| `ecommerce_offer` | 3 | 0 | 3 | 100.0% | n/a | 33.3% | n/a |
| `genuine_kyc_reminder` | 3 | 0 | 3 | 100.0% | n/a | 66.7% | n/a |
| `government_notice` | 3 | 0 | 3 | 66.7% | n/a | 66.7% | n/a |
| `impersonation` | 3 | 3 | 0 | 0.0% | 0.0% | 66.7% | 66.7% |
| `job_fee` | 3 | 3 | 0 | 33.3% | 33.3% | 100.0% | 100.0% |
| `kyc` | 3 | 3 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `link_only_phishing` | 3 | 3 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `loan_fee` | 3 | 3 | 0 | 33.3% | 33.3% | 66.7% | 66.7% |
| `lottery_reward` | 3 | 3 | 0 | 33.3% | 33.3% | 100.0% | 100.0% |
| `otp` | 3 | 3 | 0 | 66.7% | 66.7% | 66.7% | 66.7% |
| `recharge_reminder` | 3 | 0 | 3 | 100.0% | n/a | 66.7% | n/a |
| `travel_ticket` | 3 | 0 | 3 | 100.0% | n/a | 100.0% | n/a |
| `upi_collect` | 3 | 3 | 0 | 66.7% | 66.7% | 100.0% | 100.0% |

## 5. Ambiguous Rows (Excluded from Metrics)

| ID | Ground Truth Guess | Predicted Category | Score | Language | Category |
| :--- | :--- | :--- | :---: | :---: | :--- |
| `T012` | `scam` | **Suspicious** | 4 | `en` | `courier_fee` |
| `T023` | `scam` | **Suspicious** | 4 | `hinglish` | `bijli_threat` |
| `T035` | `genuine` | **No known red flags found** | 0 | `hi` | `genuine_kyc_reminder` |
| `T036` | `genuine` | **No known red flags found** | 0 | `hinglish` | `delivery_update` |
| `T044` | `genuine` | **No known red flags found** | 0 | `en` | `appointment_reminder` |
| `T053` | `scam` | **Caution** | 3 | `hi` | `government_notice` |

## 6. Error Analysis

### STRICT False Positives (Genuine Flagged as Suspicious) (1)

> **Security & Test-Set Discipline:** Message texts are omitted for the frozen test set.

| ID | Truth | Predicted Category | Category | Language | Triggered Rules |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `T063` | `genuine` | **Suspicious** | `government_notice` | `hi` | IMPERSONATION, KYC_LURE, FEAR |

### STRICT False Negatives (Scam Missed) (15)

> **Security & Test-Set Discipline:** Message texts are omitted for the frozen test set.

| ID | Truth | Predicted Category | Category | Language | Triggered Rules |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `T004` | `scam` | **Caution** | `lottery_reward` | `en` | FAKE_REWARD, FAKE_REWARD, FAKE_REWARD, FAKE_REWARD, FAKE_REWARD, URGENCY |
| `T007` | `scam` | **No known red flags found** | `loan_fee` | `en` | *(none)* |
| `T009` | `scam` | **No known red flags found** | `otp` | `hi` | *(none)* |
| `T010` | `scam` | **No known red flags found** | `impersonation` | `hinglish` | *(none)* |
| `T015` | `scam` | **Caution** | `bijli_threat` | `hi` | URGENCY |
| `T019` | `scam` | **Caution** | `courier_fee` | `en` | *(none)* |
| `T026` | `scam` | **Caution** | `impersonation` | `hi` | FEAR, URGENCY |
| `T027` | `scam` | **Caution** | `job_fee` | `en` | JOB_FEE |
| `T033` | `scam` | **Caution** | `bijli_threat` | `en` | URGENCY, FEAR, URGENCY |
| `T038` | `scam` | **Caution** | `job_fee` | `hinglish` | URGENCY |
| `T043` | `scam` | **No known red flags found** | `bijli_threat` | `hinglish` | *(none)* |
| `T049` | `scam` | **Caution** | `impersonation` | `en` | IMPERSONATION, IMPERSONATION, URGENCY |
| `T052` | `scam` | **Caution** | `upi_collect` | `hinglish` | URGENCY |
| `T055` | `scam` | **Caution** | `lottery_reward` | `hinglish` | FAKE_REWARD, FAKE_REWARD, FAKE_REWARD |
| `T057` | `scam` | **Caution** | `loan_fee` | `hinglish` | *(none)* |

### LOOSE False Positives (Genuine Flagged as Suspicious or Caution) (8)

> **Security & Test-Set Discipline:** Message texts are omitted for the frozen test set.

| ID | Truth | Predicted Category | Category | Language | Triggered Rules |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `T008` | `genuine` | **Caution** | `recharge_reminder` | `en` | URGENCY |
| `T034` | `genuine` | **Caution** | `ecommerce_offer` | `hinglish` | FAKE_REWARD |
| `T037` | `genuine` | **Caution** | `bank_debit_credit` | `en` | FEAR, URGENCY, FEAR |
| `T047` | `genuine` | **Caution** | `bill_reminder` | `hinglish` | URGENCY, FEAR |
| `T056` | `genuine` | **Caution** | `ecommerce_offer` | `hi` | URGENCY |
| `T059` | `genuine` | **Caution** | `bank_debit_credit` | `hi` | URGENCY |
| `T062` | `genuine` | **Caution** | `genuine_kyc_reminder` | `hinglish` | KYC_LURE |
| `T063` | `genuine` | **Suspicious** | `government_notice` | `hi` | IMPERSONATION, KYC_LURE, FEAR |

### LOOSE False Negatives (Scam Missed) (4)

> **Security & Test-Set Discipline:** Message texts are omitted for the frozen test set.

| ID | Truth | Predicted Category | Category | Language | Triggered Rules |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `T007` | `scam` | **No known red flags found** | `loan_fee` | `en` | *(none)* |
| `T009` | `scam` | **No known red flags found** | `otp` | `hi` | *(none)* |
| `T010` | `scam` | **No known red flags found** | `impersonation` | `hinglish` | *(none)* |
| `T043` | `scam` | **No known red flags found** | `bijli_threat` | `hinglish` | *(none)* |

