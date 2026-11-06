# Satark Generalization Probe Set (Synthetic SMS & WhatsApp Messages)

This directory contains the generalization probe set for **Satark**, an explainable scam-message detector designed for India.

---

## 1. Purpose and Role

- **Generalization Testing Only**: This probe set (`eval/probe_set.csv`) is **used only to check whether rules generalize; never to copy sentences into rules**.
- **Dataset Separation**:
  - `dev_set.csv`: The active development set used to inspect errors, engineer features, tune thresholds, and iterate on heuristics.
  - `test_set.csv`: The strictly frozen benchmark test set used exclusively for milestone score reporting.
  - `probe_set.csv`: An independent probe set written with fresh sentence structures, alternate vocabulary, different regional entities, and distinct amounts to test whether detection rules generalize beyond the development patterns without overfitting.
- **Zero Rule Contamination**: Under no circumstances should phrases, brand names, or specific sentences from this probe set be copied or hardcoded into detection heuristics, regexes, or unit tests.
- **Human Review Required**: All rows originate from `source="synthetic-ai-probe-draft"` with an empty `reviewed_by` field. A human reviewer should inspect and sign off on rows prior to official benchmark citation.
- **Evaluation Disclaimer**: Synthetic benchmark data; does not represent real-world base-rate carrier distribution or real-world prevalence.

---

## 2. Dataset Schema

The file `eval/probe_set.csv` uses the exact same header as `dev_set.csv`:

`id,text,label,language,category,has_url,difficulty,ambiguous,source,reviewed_by,notes`

| Column | Description | Allowed / Recorded Values |
| :--- | :--- | :--- |
| `id` | Unique sample identifier | `P001` through `P040` |
| `text` | Synthetic SMS or WhatsApp message body | Text (UTF-8, CSV quoted) |
| `label` | Target classification label | `scam`, `genuine` |
| `language` | Language and script | `en`, `hinglish`, `hi` (Devanagari) |
| `category` | Specific intent or scenario | See breakdown below |
| `has_url` | Whether message contains a URL or link | `0`, `1` |
| `difficulty` | Complexity of classification | `easy`, `hard` |
| `ambiguous` | Ground truth ambiguity flag | `0` (all 40 rows are non-ambiguous) |
| `source` | Generation provenance | `synthetic-ai-probe-draft` |
| `reviewed_by` | Human reviewer initials / ID | Empty until verified |
| `notes` | Diagnostic rationale for hard classifications | Text / empty for easy |

---

## 3. Summary Counts and Distributions

### Total
- **Total rows**: 40
- **Scam**: 20 rows (50%)
- **Genuine**: 20 rows (50%)
- **Ambiguous**: 0 rows (`ambiguous = 0` for all 40 rows)

### Breakdown by Language
| Language | Total | Scam | Genuine |
| :--- | :---: | :---: | :---: |
| `en` (English) | 12 | 6 | 6 |
| `hinglish` (Roman-script Hindi-English) | 14 | 7 | 7 |
| `hi` (Devanagari Hindi) | 14 | 7 | 7 |
| **Total** | **40** | **20** | **20** |

### Breakdown by URL Presence (`has_url`)
| `has_url` | Total | Scam | Genuine |
| :--- | :---: | :---: | :---: |
| `0` (No URL) | 19 | 8 | 11 |
| `1` (Contains URL) | 21 | 12 | 9 |
| **Total** | **40** | **20** | **20** |

- **Scam rows with no URL**: 8 rows (satisfies the requirement of at least 6 link-less scam rows).
- **Scam hostnames**: Invented lookalike / hostile domains (e.g., `fast-capital-disbursal.biz`, `customs-cargo-clearance.org`, `torrentpower-quickbillpay.top`, `mpeb-online-billpay.net`).
- **Genuine hostnames**: Real official domains (e.g., `tatapower-ddl.com`, `indiapost.gov.in`, `bluedart.com`, `iglonline.net`, `uhbvn.org.in`, `unionbankofindia.co.in`, `punjabandsindbank.co.in`, `centralbankofindia.co.in`).

### Breakdown by Difficulty
| Difficulty | Total | Scam | Genuine | Notes |
| :--- | :---: | :---: | :---: | :--- |
| `easy` | 16 | 10 | 6 | Standard indicators or straightforward messages |
| `hard` | 24 | 10 | 14 | Avoids standard scam keywords or contains legitimate warning triggers |
| **Total** | **40** | **20** | **20** | |

---

## 4. Scenario Coverage

### Scam Scenarios (20 Rows)
1. **Advance fee before loan** (P001, P003, P005): Stamping charge, legal fee, or insurance deposit demanded before loan disbursal.
2. **Parcel / customs release fee** (P008, P010, P012): Demand to pay gate pass or clearance duty to "unlock" or "release" held consignments.
3. **Refund, subsidy, or tax-refund bank capture** (P013, P015, P017): Direct benefit transfer, gas subsidy, or tax refund lures harvesting account details.
4. **SIM, Aadhaar, or PAN credential extraction by reply** (P020, P022, P024): Network upgrade or telecom deactivation threats demanding sensitive IDs via SMS reply without links.
5. **OTP / authentication code phishing** (P025, P027, P029): Call-center or cancellation lures asking users to state or forward their one-time passcode.
6. **Utility connection cutoff threats** (P032, P034, P036): Power, piped gas, or water disconnection threats with strict deadlines.
7. **Authority and agency impersonation** (P019, P037, P039): Cyber Crime Cell, Narcotics Control Bureau (NCB), and Enforcement Directorate (ED) notices.
8. **Lookalike deceptive links**: Unofficial TLDs and typo-squatted domains.

### Genuine Look-Alike Scenarios (20 Rows)
1. **Refund credited confirmations** (P002, P004, P006): Real ticket cancellation and merchant refunds credited to customer accounts.
2. **Planned maintenance & outage notices** (P007, P009, P011): Legitimate grid maintenance and water treatment plant shutdown alerts.
3. **Official customs & postal notices** (P014, P016, P018): Real India Post and Blue Dart tracking and customs receipt notifications.
4. **Bank security-awareness advisories** (P019, P021, P023): Educational messages reminding customers never to disclose PINs, passcodes, or credentials.
5. **Legitimate transaction & login OTPs** (P026, P028, P030): Authentic one-time authorization codes with expiry and security reminders.
6. **Utility monthly bills** (P031, P033): Routine billing notices with consumer IDs and payment links to verified utility portals.
7. **Branch KYC refresh reminders** (P035, P038, P040): In-person branch visit requests for periodic re-KYC with original documents.

---

## 5. Security & Data Integrity Controls

- **Formula Injection Immunity**: No cell in any column begins with `=`, `+`, `-`, or `@`.
- **Zero Real Phone Numbers**: All phone references use masks such as `98XXXXXX81` or legitimate toll-free prefixes like `1800-XXX-XXXX`.
- **Safe Reference Numbers**: All tracking and transaction references are alphanumeric (e.g., `CR/908124/REV`, `AWB-94021`, `EA892018421IN`, `CA-982103`) to ensure they cannot be confused with mobile phone numbers.
- **Encoding**: Clean UTF-8 without Byte Order Mark (BOM).

