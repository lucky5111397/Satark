"""
Unit Tests for SATARK Synthetic Dataset Pilot Generator (Phase 6C.1).

Verifies:
1. Exact record count (150).
2. Class balance (75 BENIGN, 75 SUSPICIOUS).
3. Language distribution (53 en, 52 hinglish, 45 hi).
4. Category coverage (all 12 canonical categories present and balanced).
5. Deterministic reproducibility via fixed seed.
6. Seed sensitivity (different seeds produce different slot assignments).
7. 15-column schema and governance metadata integrity.
8. Zero exact or normalized duplicates.
9. Zero PII violations under regex scanner.
10. Benchmark overlap checks using a synthetic fixture.
11. Script consistency (Devanagari in hi, Latin in en/hinglish).
12. Fictional / generic entity compliance (no real banks, agencies, or utilities).
13. Audit function verification statuses.
"""

import re
import csv
import tempfile
import unittest
from pathlib import Path

from ml_service.curation.synthetic_generator import (
    generate_pilot_dataset,
    audit_pilot_dataset,
    compute_token_jaccard,
    build_template_catalog
)
from ml_service.training.validate_dataset import (
    REQUIRED_COLUMNS,
    GOVERNANCE_COLUMNS,
    CANONICAL_BENIGN,
    CANONICAL_SUSPICIOUS
)
from ml_service.curation.pii_scrubber import has_unmasked_pii


class TestSyntheticGenerator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records_seed42 = generate_pilot_dataset(seed=42)
        # Routine unit tests must not read the real frozen benchmark.
        cls.fixture_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.fixture_dir.cleanup)
        cls.test_set_path = Path(cls.fixture_dir.name) / "synthetic_benchmark.csv"
        with cls.test_set_path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=["text"])
            writer.writeheader()
            writer.writerow({"text": "Unrelated synthetic benchmark fixture for overlap checking."})

    def test_exact_150_records(self):
        """Verifies generator produces exactly 150 records."""
        self.assertEqual(len(self.records_seed42), 150)

    def test_class_balance(self):
        """Verifies exact 50/50 balance: 75 BENIGN and 75 SUSPICIOUS."""
        benign_count = sum(1 for r in self.records_seed42 if r["label"] == CANONICAL_BENIGN)
        suspicious_count = sum(1 for r in self.records_seed42 if r["label"] == CANONICAL_SUSPICIOUS)
        self.assertEqual(benign_count, 75)
        self.assertEqual(suspicious_count, 75)

    def test_language_distribution(self):
        """Verifies 53 English, 52 Hinglish, and 45 Hindi records."""
        en_count = sum(1 for r in self.records_seed42 if r["language"] == "en")
        hn_count = sum(1 for r in self.records_seed42 if r["language"] == "hinglish")
        hi_count = sum(1 for r in self.records_seed42 if r["language"] == "hi")
        self.assertEqual(en_count, 53)
        self.assertEqual(hn_count, 52)
        self.assertEqual(hi_count, 45)

    def test_category_coverage(self):
        """Verifies all 12 categories are present and balanced (11-14 records each)."""
        expected_categories = {
            "otp_negation", "otp_operational", "bank_transactional",
            "utility_service_notice", "service_informational", "commercial_promo_ham",
            "kyc_phishing", "digital_arrest_impersonation", "electricity_disconnection",
            "part_time_job_scam", "lottery_advance_fee", "malicious_apk_qr_scam"
        }
        actual_categories = {r["category"] for r in self.records_seed42}
        self.assertEqual(actual_categories, expected_categories)

        for cat in expected_categories:
            count = sum(1 for r in self.records_seed42 if r["category"] == cat)
            self.assertGreaterEqual(count, 11, f"Category {cat} has only {count} rows (< 11)")
            self.assertLessEqual(count, 14, f"Category {cat} has {count} rows (> 14)")

    def test_deterministic_reproducibility(self):
        """Verifies two runs with the same seed yield identical outputs."""
        second_run = generate_pilot_dataset(seed=42)
        self.assertEqual(len(self.records_seed42), len(second_run))
        for r1, r2 in zip(self.records_seed42, second_run):
            self.assertEqual(r1["id"], r2["id"])
            self.assertEqual(r1["text"], r2["text"])
            self.assertEqual(r1["label"], r2["label"])
            self.assertEqual(r1["category"], r2["category"])

    def test_different_seeds_vary(self):
        """Verifies that different seeds change slot selection without altering count."""
        diff_run = generate_pilot_dataset(seed=99)
        self.assertEqual(len(diff_run), 150)
        # Texts should vary due to RNG choice of slot fillers
        same_text_count = sum(1 for r1, r2 in zip(self.records_seed42, diff_run) if r1["text"] == r2["text"])
        self.assertLess(same_text_count, 150, "Different seed should produce different slot choices")

    def test_schema_and_governance_integrity(self):
        """Verifies all 15 columns exist and carry valid governance properties."""
        all_cols = REQUIRED_COLUMNS + GOVERNANCE_COLUMNS
        for r in self.records_seed42:
            for col in all_cols:
                self.assertIn(col, r, f"Missing column {col} in record {r.get('id')}")
            self.assertEqual(r["provenance_type"], "synthetic")
            self.assertEqual(r["source_id"], "SRC-09")
            self.assertEqual(r["reviewer_status"], "pending_review")
            self.assertEqual(r["reviewed_by"], "none")
            self.assertEqual(r["review_timestamp"], "none")
            self.assertEqual(r["license"], "MIT")
            self.assertEqual(r["source"], "synthetic_pilot_generator")
            self.assertEqual(r["label_confidence"], "1.0")

    def test_zero_exact_and_normalized_duplicates(self):
        """Verifies no exact or whitespace/punctuation-collapsed duplicate texts."""
        texts = [r["text"] for r in self.records_seed42]
        self.assertEqual(len(texts), len(set(texts)), "Found exact duplicate texts")

        norm_texts = [re.sub(r'\s+', ' ', re.sub(r'[^\w\s]', '', t.lower())).strip() for t in texts]
        self.assertEqual(len(norm_texts), len(set(norm_texts)), "Found normalized duplicate texts")

    def test_zero_pii_violations(self):
        """Verifies that all records pass the PII safety scanner."""
        violations = [r["id"] for r in self.records_seed42 if has_unmasked_pii(r["text"])]
        self.assertEqual(violations, [], f"Records with unmasked PII: {violations}")

    def test_zero_benchmark_contamination(self):
        """Verifies zero overlap with an unrelated synthetic benchmark."""
        with open(self.test_set_path, mode="r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            benchmark_texts = {re.sub(r'\s+', ' ', row.get("text", "").lower()).strip() for row in reader if "text" in row}

        for r in self.records_seed42:
            cand_norm = re.sub(r'\s+', ' ', r["text"].lower()).strip()
            self.assertNotIn(cand_norm, benchmark_texts, f"Record {r['id']} collides with benchmark!")

    def test_explicit_benchmark_detects_matching_synthetic_record(self):
        benchmark = Path(self.fixture_dir.name) / "matching_synthetic_benchmark.csv"
        with benchmark.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=["text"])
            writer.writeheader()
            writer.writerow({"text": self.records_seed42[0]["text"]})
        audit = audit_pilot_dataset(self.records_seed42, benchmark_file=benchmark)
        self.assertEqual(audit["benchmark_contamination"], 1)
        self.assertEqual(audit["verifications"]["benchmark_isolation"], "FAIL")

    def test_script_consistency(self):
        """Verifies Hindi records have Devanagari; en/hinglish do not."""
        devanagari_regex = re.compile(r'[\u0900-\u097F]')
        for r in self.records_seed42:
            has_devanagari = bool(devanagari_regex.search(r["text"]))
            if r["language"] == "hi":
                self.assertTrue(has_devanagari, f"Hindi record {r['id']} lacks Devanagari script")
            else:
                self.assertFalse(has_devanagari, f"Non-Hindi record {r['id']} contains Devanagari script")

    def test_fictional_entities_only(self):
        """Verifies no real bank or government agency names appear in generated text."""
        prohibited_entities = [
            r'\bSBI\b', r'\bHDFC\b', r'\bICICI\b', r'\bPNB\b', r'\bAxis Bank\b',
            r'\bBESCOM\b', r'\bTata Power\b', r'\bMumbai Police\b', r'\bCBI\b',
            r'\bKaun Banega Crorepati\b', r'\bKBC\b'
        ]
        for r in self.records_seed42:
            for pattern in prohibited_entities:
                match = re.search(pattern, r["text"], re.IGNORECASE)
                self.assertIsNone(match, f"Record {r['id']} contains prohibited real entity matching '{pattern}'")

    def test_audit_function_output(self):
        """Verifies audit_pilot_dataset accurately reports check statuses."""
        audit = audit_pilot_dataset(self.records_seed42, benchmark_file=self.test_set_path)
        self.assertEqual(audit["verifications"]["exact_duplicates"], "PASS")
        self.assertEqual(audit["verifications"]["normalized_duplicates"], "PASS")
        self.assertEqual(audit["verifications"]["pii_absence"], "PASS")
        self.assertEqual(audit["verifications"]["script_consistency"], "PASS")
        self.assertEqual(audit["verifications"]["benchmark_isolation"], "PASS")
        self.assertEqual(audit["verifications"]["class_balance"], "PASS")
        self.assertEqual(audit["verifications"]["language_balance"], "PASS")
        self.assertEqual(audit["verifications"]["semantic_diversity"], "UNVERIFIED")
        self.assertEqual(audit["verifications"]["human_ground_truth"], "UNVERIFIED")


if __name__ == "__main__":
    unittest.main()

