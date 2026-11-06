# Satark Development Set (Synthetic SMS & WhatsApp Messages)

This directory contains the development set for **Satark**, an explainable scam-message detector designed for India.

---

## 1. Purpose

This set (`dev_set.csv`) is the **ONLY** dataset used to **write, tune, and iterate on detection rules, heuristics, and model thresholds**. It exists so that the evaluation test set (`test_set.csv`) stays uncontaminated.

> **Never mix dev_set.csv with test_set.csv.** Rules must be developed and tuned only on this dev set. The test set is frozen and used only for final evaluation.

---

## 2. Origin

- **Synthetic Benchmark Examples**: All 50 messages are synthetic examples curated for this benchmark under a **blind protocol** — without using the detector code in `server/`, `client/`, `docs/`, `design/`, or any project PDF.
- **No Overlap**: No message text is copied or lightly paraphrased from `test_set.csv`. The two sets use different brands, amounts, sentence structures, and wording.
- **Human Review Required**: Every row has `source="synthetic-ai-dev-draft"` and an empty `reviewed_by` field. A team member must manually inspect each message and fill `reviewed_by` before the set is trusted for rule development.

---

## 3. Row Counts and Distributions

### Total
- **50 rows** (D001–D050, shuffled order)
- **25 scam, 25 genuine**
- **All rows: ambiguous = 0**

### By Language
| Language | Total | Scam | Genuine |
| :--- | :---: | :---: | :---: |
| `en` (English) | 16 | 8 | 8 |
| `hinglish` (Roman-script Hindi-English) | 17 | 9 | 8 |
| `hi` (Devanagari Hindi) | 17 | 8 | 9 |

### By Difficulty
| Difficulty | Total | Scam | Genuine |
| :--- | :---: | :---: | :---: |
| `easy` | 30 | 15 | 15 |
| `hard` | 20 | 10 | 10 |

Hard = 40% of the set.

### By Category

**Scam categories (25 rows):**

| Category | Count | Notes |
| :--- | :---: | :--- |
| `kyc` | 2 | Also in test_set |
| `otp` | 2 | Also in test_set |
| `job_fee` | 2 | Also in test_set |
| `lottery_reward` | 1 | Also in test_set |
| `impersonation` | 2 | Also in test_set |
| `loan_fee` | 2 | Also in test_set |
| `upi_collect` | 1 | Also in test_set |
| `bijli_threat` | 2 | Also in test_set |
| `courier_fee` | 2 | Also in test_set |
| `link_only_phishing` | 1 | Also in test_set |
| `sim_swap` | 2 | **New** — not in test_set |
| `insurance_lapse` | 1 | **New** — not in test_set |
| `gas_subsidy` | 1 | **New** — not in test_set |
| `income_tax_refund` | 1 | **New** — not in test_set |
| `customs_parcel` | 2 | **New** — not in test_set |
| `fake_refund` | 1 | **New** — not in test_set |

**Genuine categories (25 rows):**

| Category | Count | Notes |
| :--- | :---: | :--- |
| `bank_otp` | 2 | Also in test_set |
| `bank_debit_credit` | 2 | Also in test_set |
| `delivery_update` | 2 | Also in test_set |
| `recharge_reminder` | 2 | Also in test_set |
| `ecommerce_offer` | 2 | Also in test_set |
| `bill_reminder` | 2 | Also in test_set |
| `appointment_reminder` | 2 | Also in test_set |
| `travel_ticket` | 2 | Also in test_set |
| `government_notice` | 1 | Also in test_set |
| `genuine_kyc_reminder` | 2 | Also in test_set |
| `insurance_premium_reminder` | 2 | **New** — not in test_set |
| `bank_statement_notice` | 2 | **New** — not in test_set |
| `otp_for_login_other_app` | 2 | **New** — not in test_set |

### By URL Presence
| `has_url` | Count |
| :--- | :---: |
| `1` | 20 |
| `0` | 30 |

- Scam rows with URLs: 11 (invented hostile domains or bit.ly-style shorteners)
- Genuine rows with URLs: 9 (official domains like portal.bsnl.in, meesho.com, yatra.com, djb.gov.in)

---

## 4. Difficulty Definitions

- **Hard Scam**: Paraphrased scams that avoid the four obvious English keywords (`OTP`, `KYC`, `urgent`, `lottery`) but are clearly fraudulent to a careful human reader.
- **Hard Genuine**: Legitimate messages that naturally contain scam-like trigger words (e.g., `OTP`, `KYC`, `expire`, `block`, `lapse`, `verification code`) which naive keyword filters would flag as false positives.

---

## 5. Privacy and Data Hygiene

- **No real personal data.** All phone numbers, account IDs, OTPs, and reference codes are synthetic.
- **Phone numbers are pre-masked** using `XX` patterns (e.g., `98XXXXXX44`, `1800-XXX-XXXX`, `011-XXXXX63`). No unmasked 10-digit mobile number appears anywhere.
- **Scam links use invented hostnames** (e.g., `federalbank-verify.xyz`, `hpgas-subsidy-claim.top`). Real official domains appear only in genuine rows.
- **No CSV formula injection.** No cell begins with `=`, `+`, `-`, or `@`.
- **Encoding**: UTF-8 without BOM.
