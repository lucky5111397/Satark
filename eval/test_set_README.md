# Satark Evaluation Test Set (Synthetic SMS & WhatsApp Messages)

This directory contains the frozen evaluation test set for **Satark**, an explainable scam-message detector designed for India.

---

## 1. Overview and Purpose

- **Synthetic Benchmark Examples**: All 66 messages in `test_set.csv` are synthetic examples curated for this benchmark under a **blind protocol**—without using the detector implementation, heuristics, models, or feature extraction rules in `server/`, `client/`, `docs/`, `design/`, or project PDFs. This maintains a clean separation between detection engineering and evaluation.
- **Strictly Frozen**: This evaluation set is **FROZEN**. It must **never** be used to write, prompt, tune, or optimize detection rules or thresholds. All model exploration and rule development must occur only on a separate development/training set.
- **Human Verification Required**: Every row currently has `source="synthetic-ai-draft"` with an empty `reviewed_by` field. A team member must manually inspect each message and fill `reviewed_by` before evaluation metrics on this set are cited or trusted.
- **Not Real-World Accuracy**: Performance metrics measured on this synthetic test set do not reflect real-world telecommunication accuracy, prevalence, or base-rate distribution across Indian carrier networks.

---

## 2. Dataset Schema

The CSV file `test_set.csv` follows this exact header:
`id,text,label,language,category,has_url,difficulty,ambiguous,source,reviewed_by,notes`

| Column | Description | Allowed Values |
| :--- | :--- | :--- |
| `id` | Unique sample identifier (T001 to T066, shuffled) | `T001` .. `T066` |
| `text` | Synthetic SMS / WhatsApp message body | Text (UTF-8, CSV quoted) |
| `label` | Target classification label | `scam`, `genuine` |
| `language` | Language/script used | `en`, `hinglish`, `hi` |
| `category` | Specific message intent / scenario | See category list below |
| `has_url` | Whether the message contains any URL or web link | `0`, `1` |
| `difficulty` | Complexity of classification | `easy`, `hard` |
| `ambiguous` | Flag for messages lacking definitive ground truth | `0`, `1` |
| `source` | Origin of the data row | `synthetic-ai-draft` |
| `reviewed_by` | Identifier of the human reviewer (empty until reviewed) | Text / empty |
| `notes` | Rationale for hard/ambiguous classification (empty for easy) | Text / empty |

---

## 3. Row Counts and Distributions

### Total Counts
- **Total rows**: 66
- **Main rows**: 60 (30 scam, 30 genuine)
- **Ambiguous rows**: 6 (3 scam guess, 3 genuine guess)

### Breakdown by Label
- `scam`: 33 rows (30 main + 3 ambiguous)
- `genuine`: 33 rows (30 main + 3 ambiguous)

### Breakdown by Language
- `en` (English): 22 rows (20 main + 2 ambiguous)
- `hinglish` (Roman-script Hindi-English mix): 22 rows (20 main + 2 ambiguous)
- `hi` (Devanagari Hindi): 22 rows (20 main + 2 ambiguous)

### Breakdown by Difficulty
- `easy`: 40 rows
- `hard`: 26 rows
  - Hard Scam: 11 rows (8 main + 3 ambiguous)
  - Hard Genuine: 15 rows (12 main + 3 ambiguous)

### Breakdown by Ambiguity Flag
- `ambiguous = 0`: 60 rows
- `ambiguous = 1`: 6 rows

### Breakdown by URL Presence (`has_url`)
- `has_url = 0`: 25 rows
- `has_url = 1`: 41 rows

### Breakdown by Category

| Category | Primary Label | Main Rows | Ambiguous Rows | Total Count |
| :--- | :--- | :---: | :---: | :---: |
| `kyc` | Scam | 3 | 0 | 3 |
| `otp` | Scam | 3 | 0 | 3 |
| `job_fee` | Scam | 3 | 0 | 3 |
| `lottery_reward` | Scam | 3 | 0 | 3 |
| `impersonation` | Scam | 3 | 0 | 3 |
| `loan_fee` | Scam | 3 | 0 | 3 |
| `upi_collect` | Scam | 3 | 0 | 3 |
| `bijli_threat` | Scam | 3 | 1 | 4 |
| `courier_fee` | Scam | 3 | 1 | 4 |
| `link_only_phishing` | Scam | 3 | 0 | 3 |
| `bank_otp` | Genuine | 3 | 0 | 3 |
| `bank_debit_credit` | Genuine | 3 | 0 | 3 |
| `delivery_update` | Genuine | 3 | 1 | 4 |
| `recharge_reminder` | Genuine | 3 | 0 | 3 |
| `ecommerce_offer` | Genuine | 3 | 0 | 3 |
| `bill_reminder` | Genuine | 3 | 0 | 3 |
| `appointment_reminder` | Genuine | 3 | 1 | 4 |
| `travel_ticket` | Genuine | 3 | 0 | 3 |
| `government_notice` | Genuine | 3 | 1 | 4 |
| `genuine_kyc_reminder` | Genuine | 3 | 1 | 4 |
| **Total** | | **60** | **6** | **66** |

---

## 4. Definitions: Difficulty and Ambiguity

### What `difficulty=hard` Means:
1. **For Scam rows**: Paraphrased scams designed without common obvious keywords (explicitly avoiding `"OTP"`, `"KYC"`, `"urgent"`, and `"lottery"`). These rely on realistic advance-fee patterns (e.g., job registration fees, courier re-attempt fees, loan stamp charges, UPI collect fraud) that a human recognizes as fraudulent despite the absence of classic trigger words.
2. **For Genuine rows**: Legitimate messages that naturally include high-risk keywords (e.g., `"urgent"`, `"OTP"`, `"KYC"`, `"congratulations"`, `"link"`, `"expire"`, `"block"`) that naive lexical filters frequently flag as false positives. These messages represent valid bank OTPs, fraud warning debit alerts, carrier validity expiration reminders, or official KYC compliance notices.

### What `ambiguous=1` Means:
Messages where even a diligent human cannot determine the true sender or intent without external out-of-band context (such as knowing whether the recipient actually ordered a package, has an appointment, or uses that bank). In these rows, `label` reflects the annotator's best guess, and `notes` explains the conflicting indicators.

---

## 5. Security & Data Hygiene
- **Zero Real Personal Data**: All phone numbers, account identifiers, reference codes, names, and OTPs are synthetic placeholders (e.g., `XX8192`, `482913`).
- **Deceptive Hostnames**: Scam rows containing URLs use fabricated domains (e.g., `sbi-kyc-verify.xyz`, `phonepe-reward-claim.top`, `instant-loan-seva.xyz`). Real official domains (e.g., `sbi.co.in`, `amazon.in`, `tatapower.com`) appear only in genuine rows.
- **CSV Formula Injection Safeguard**: No cell begins with `=`, `+`, `-`, or `@`.
- **Character Encoding**: Clean UTF-8 without BOM, supporting standard Devanagari Hindi script.
