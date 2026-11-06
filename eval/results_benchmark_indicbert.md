# Satark Evaluation Report: BENCHMARK_INDICBERT

**Date:** 2026-11-01T11:16:23.749Z
**Dataset:** `benchmark_indicbert` (120 total rows: 110 scored, 10 ambiguous)
**Detector Engine SHA-256:** `49dce32196a172186651fac8e53e3ccc26598c68f062bddf01817e9123899df1`

> **Synthetic data, not real-world accuracy.**

## 1. Overall Performance Metrics

| Threshold Policy | TP | FP | TN | FN | Precision | Recall | False Pos Rate | F1 Score | Accuracy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **STRICT** (Suspicious) | 23 | 1 | 59 | 27 | 95.8% | 46.0% | 1.7% | 62.2% | 74.5% |
| **LOOSE** (Suspicious or Caution) | 40 | 6 | 54 | 10 | 87.0% | 80.0% | 10.0% | 83.3% | 85.5% |

## 2. Language Breakdown

| Language | Total | Scam | Genuine | STRICT Recall (Scam) | STRICT FPR (Genuine) | LOOSE Recall (Scam) | LOOSE FPR (Genuine) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `en` | 41 | 18 | 23 | 38.9% | 0.0% | 77.8% | 4.3% |
| `hi` | 35 | 16 | 19 | 50.0% | 0.0% | 87.5% | 10.5% |
| `hinglish` | 34 | 16 | 18 | 50.0% | 5.6% | 75.0% | 16.7% |

## 3. Difficulty Breakdown

| Difficulty | Scored | Scam | Genuine | STRICT Recall | STRICT FPR | STRICT Acc | LOOSE Recall | LOOSE FPR | LOOSE Acc |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `easy` | 82 | 44 | 38 | 50.0% | 0.0% | 73.2% | 79.5% | 2.6% | 87.8% |
| `hard` | 28 | 6 | 22 | 16.7% | 4.5% | 78.6% | 83.3% | 22.7% | 78.6% |

## 4. Category Breakdown

| Category | Total | Scam | Genuine | STRICT Acc | STRICT Recall | LOOSE Acc | LOOSE Recall |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `aadhaar_alert` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |
| `advance_fee` | 1 | 1 | 0 | 0.0% | 0.0% | 100.0% | 100.0% |
| `appointment` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |
| `bank_credit` | 4 | 0 | 4 | 100.0% | n/a | 100.0% | n/a |
| `bank_debit` | 3 | 0 | 3 | 100.0% | n/a | 66.7% | n/a |
| `bank_service` | 2 | 0 | 2 | 100.0% | n/a | 100.0% | n/a |
| `bank_statement` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |
| `bijli_threat` | 1 | 1 | 0 | 0.0% | 0.0% | 100.0% | 100.0% |
| `civic_notice` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |
| `contextual_negation` | 10 | 0 | 10 | 100.0% | n/a | 80.0% | n/a |
| `customs_fee` | 1 | 1 | 0 | 0.0% | 0.0% | 100.0% | 100.0% |
| `deceptive_link` | 2 | 2 | 0 | 0.0% | 0.0% | 50.0% | 50.0% |
| `delivery_otp` | 1 | 0 | 1 | 100.0% | n/a | 0.0% | n/a |
| `digital_arrest` | 1 | 1 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `ecommerce` | 2 | 0 | 2 | 100.0% | n/a | 100.0% | n/a |
| `fake_kyc` | 10 | 10 | 0 | 60.0% | 60.0% | 80.0% | 80.0% |
| `fake_reward` | 3 | 3 | 0 | 66.7% | 66.7% | 66.7% | 66.7% |
| `fear` | 3 | 3 | 0 | 33.3% | 33.3% | 100.0% | 100.0% |
| `food_delivery` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |
| `gov_subsidy` | 1 | 1 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `health_advisory` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |
| `impersonation` | 1 | 1 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `insurance_due` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |
| `job_fee` | 3 | 3 | 0 | 33.3% | 33.3% | 100.0% | 100.0% |
| `kyc_lure` | 1 | 1 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `kyc_threat` | 1 | 1 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `loan_fee` | 3 | 3 | 0 | 33.3% | 33.3% | 66.7% | 66.7% |
| `lottery_prize` | 1 | 1 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `mandate_update` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |
| `otp_negation` | 10 | 0 | 10 | 90.0% | n/a | 80.0% | n/a |
| `otp_request` | 2 | 2 | 0 | 50.0% | 50.0% | 100.0% | 100.0% |
| `otp_theft` | 1 | 1 | 0 | 100.0% | 100.0% | 100.0% | 100.0% |
| `recharge_reminder` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |
| `sensitive_info` | 1 | 1 | 0 | 0.0% | 0.0% | 100.0% | 100.0% |
| `service_booking` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |
| `sim_swap` | 1 | 1 | 0 | 0.0% | 0.0% | 0.0% | 0.0% |
| `statement_alert` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |
| `telco_usage` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |
| `transactional` | 10 | 0 | 10 | 100.0% | n/a | 100.0% | n/a |
| `travel_alert` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |
| `travel_ticket` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |
| `unsolicited_refund` | 1 | 1 | 0 | 0.0% | 0.0% | 100.0% | 100.0% |
| `upi_collect` | 11 | 11 | 0 | 36.4% | 36.4% | 63.6% | 63.6% |
| `utility_bill` | 2 | 0 | 2 | 100.0% | n/a | 100.0% | n/a |
| `utility_booking` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |
| `utility_receipt` | 1 | 0 | 1 | 100.0% | n/a | 100.0% | n/a |

## 5. Ambiguous Rows (Excluded from Metrics)

| ID | Ground Truth Guess | Predicted Category | Score | Language |
| :--- | :--- | :--- | :---: | :---: |
| `BM111` | `genuine` | **No known red flags found** | 0 | `en` |
| `BM112` | `genuine` | **No known red flags found** | 0 | `en` |
| `BM113` | `genuine` | **Caution** | 1 | `hi` |
| `BM114` | `genuine` | **No known red flags found** | 0 | `hi` |
| `BM115` | `genuine` | **No known red flags found** | 0 | `hinglish` |
| `BM116` | `genuine` | **No known red flags found** | 0 | `hinglish` |
| `BM117` | `genuine` | **No known red flags found** | 0 | `en` |
| `BM118` | `genuine` | **No known red flags found** | 0 | `hi` |
| `BM119` | `genuine` | **No known red flags found** | 0 | `hinglish` |
| `BM120` | `genuine` | **No known red flags found** | 0 | `en` |

## 6. Error Analysis

### STRICT False Positives (Genuine Flagged as Suspicious) (1)

| ID | Truth | Predicted | Score | Rules |
| :--- | :--- | :--- | :---: | :--- |
| `BM066` | `genuine` | **Suspicious** | 5 | FAKE_REWARD, OTP_REQUEST |

### STRICT False Negatives (Scam Missed) (27)

| ID | Truth | Predicted | Score | Rules |
| :--- | :--- | :--- | :---: | :--- |
| `BM003` | `scam` | **Caution** | 3 | IMPERSONATION, URGENCY |
| `BM004` | `scam` | **Caution** | 3 | JOB_FEE |
| `BM005` | `scam` | **Caution** | 3 | IMPERSONATION, URGENCY |
| `BM007` | `scam` | **Caution** | 3 | *(none)* |
| `BM008` | `scam` | **Caution** | 1 | URGENCY |
| `BM009` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM021` | `scam` | **Caution** | 2 | FEAR |
| `BM028` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM029` | `scam` | **Caution** | 3 | FEAR, URGENCY |
| `BM030` | `scam` | **Caution** | 3 | LOAN_FEE, URGENCY |
| `BM042` | `scam` | **Caution** | 2 | FEAR |
| `BM044` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM045` | `scam` | **Caution** | 3 | JOB_FEE |
| `BM048` | `scam` | **Caution** | 3 | *(none)* |
| `BM049` | `scam` | **Caution** | 3 | OTP_REQUEST |
| `BM050` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM082` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM083` | `scam` | **Caution** | 3 | UPI_COLLECT, UPI_COLLECT |
| `BM085` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM087` | `scam` | **Caution** | 3 | UPI_COLLECT |
| `BM088` | `scam` | **Caution** | 3 | UPI_COLLECT |
| `BM089` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM090` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM092` | `scam` | **Caution** | 1 | URGENCY |
| `BM094` | `scam` | **Caution** | 3 | *(none)* |
| `BM098` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM100` | `scam` | **No known red flags found** | 0 | *(none)* |

### LOOSE False Positives (Genuine Flagged as Suspicious or Caution) (6)

| ID | Truth | Predicted | Score | Rules |
| :--- | :--- | :--- | :---: | :--- |
| `BM018` | `genuine` | **Caution** | 3 | OTP_REQUEST |
| `BM052` | `genuine` | **Caution** | 2 | FEAR |
| `BM063` | `genuine` | **Caution** | 3 | UPI_COLLECT |
| `BM066` | `genuine` | **Suspicious** | 5 | FAKE_REWARD, OTP_REQUEST |
| `BM075` | `genuine` | **Caution** | 2 | KYC_LURE |
| `BM079` | `genuine` | **Caution** | 3 | JOB_FEE |

### LOOSE False Negatives (Scam Missed) (10)

| ID | Truth | Predicted | Score | Rules |
| :--- | :--- | :--- | :---: | :--- |
| `BM009` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM028` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM044` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM050` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM082` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM085` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM089` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM090` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM098` | `scam` | **No known red flags found** | 0 | *(none)* |
| `BM100` | `scam` | **No known red flags found** | 0 | *(none)* |

