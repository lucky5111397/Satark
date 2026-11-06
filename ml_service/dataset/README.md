# Satark Training Dataset Specification & Acquisition Protocol

## 1. Overview
This directory defines the data requirements, schema standards, and validation protocols for training the **XLM-RoBERTa** multilingual scam detection model.

---

## 2. Canonical Dataset Schema

Every training and validation dataset CSV must conform strictly to the following 8 columns:

| Column Name | Type | Allowed Values / Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | String | Unique regex `^[A-Za-z0-9_-]+$` | Unique identifier for the example. |
| `text` | String | 1 to 2000 characters | Raw message body in English, Hindi, or Hinglish. |
| `label` | String | `BENIGN` or `SUSPICIOUS` | Binary ground-truth classification target. |
| `language` | String | `en`, `hi`, `hinglish` | Detected or verified primary language of the text. |
| `category` | String | e.g. `kyc_phishing`, `transaction_alert`, `lottery_fraud`, `job_scam`, `utility_scam`, etc. | Sub-category of fraud or benign communication. |
| `source` | String | e.g. `curated_synthetic`, `citizen_report`, `public_corpus` | Provenance / origin of the sample. |
| `reviewed_by` | String | Reviewer initials or team ID | Human auditor who verified label accuracy. |
| `notes` | String | Free-form text | Contextual annotations or justification. |

---

## 3. Strict Label Definitions

1. **`BENIGN`**:
   - Informational, transactional, or conversational messages that do not solicit credentials, sensitive identifiers, urgent unauthorized payments, or malicious link clicks.
   - Includes actual bank transaction alerts, balance summaries, OTP delivery messages (from legitimate senders that warn *not* to share), delivery notices, and general civic advisories.

2. **`SUSPICIOUS`**:
   - Messages that attempt fraud, credential theft, advance-fee extortion, impersonation of authorities (police, CBI, RBI, tax dept), false KYC expiration threats, fake job processing fees, or deceptive UPI collect requests.

> **CRITICAL RULE ON SPAM VS SCAM:**
> Unsolicited commercial advertising or marketing spam (e.g. "50% off on shoes at nearby store") is NOT automatically a scam. Do not convert generic commercial spam datasets into scam labels without manual review. Only messages with fraudulent intent or credential harvesting are labeled `SUSPICIOUS`.

---

## 4. Frozen Evaluation Protocol

Under NO circumstances may `eval/test_set.csv` be combined with, sampled for, or used in training, fine-tuning, or hyperparameter selection. Doing so constitutes catastrophic data leakage and invalidates benchmark integrity.

---

## 5. Dataset Validation CLI

Before initiating training, run the dataset validation script:

```powershell
python -m ml_service.training.validate_dataset --file ml_service/dataset/raw_dataset.csv
```

This tool audits:
- Schema conformance.
- Null or whitespace-only messages.
- Exact and near duplicates.
- Class balance ratio (BENIGN vs SUSPICIOUS).
- Language representation (`en`, `hi`, `hinglish`).
- Text length distributions.

---

## 6. Privacy & Ethics
- Never include personally identifiable information (PII) such as real phone numbers, real Aadhaar numbers, real debit/credit card numbers, or real full names in training datasets. Mask identifiers (e.g., `98XXXXXX12`, `XX3489`).
- Ensure all collected datasets have appropriate licensing or rights for machine learning research.

