"""
Unit and Integration Tests for SATARK Dataset Curation & PII Scrubbing Pipeline (Phase 6A).

Covers:
1. PII detection and regex scrubbing for Indian telecom & financial entities.
2. Contamination firewall integration in curation pipeline.
3. Record sanitization and duplicate detection.
4. Validation and schema conformance of sample_curated_corpus.csv.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Reconfigure stdout/stderr encoding on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from ml_service.curation.pii_scrubber import (
    scrub_text,
    has_unmasked_pii,
    sanitize_record
)
from ml_service.curation.curation_pipeline import (
    process_curated_record,
    curate_corpus
)
from ml_service.training.validate_dataset import (
    CANONICAL_BENIGN,
    CANONICAL_SUSPICIOUS,
    ContaminationError,
    audit_dataset
)


class TestPiiScrubber(unittest.TestCase):
    """Test Suite 1: Indian PII Entity Detection and Scrubbing."""

    def test_scrub_indian_phone_numbers(self):
        sample = "Please call manager Sharma at +91 9876543210 or 8123456789 immediately."
        scrubbed, counts = scrub_text(sample)
        self.assertNotIn("9876543210", scrubbed)
        self.assertNotIn("8123456789", scrubbed)
        self.assertIn("<phone>", scrubbed)
        self.assertEqual(counts.get("phone"), 2)

    def test_scrub_pan_numbers(self):
        sample = "Your PAN card ABCDE1234F is unlinked. Submit it today."
        scrubbed, counts = scrub_text(sample)
        self.assertNotIn("ABCDE1234F", scrubbed)
        self.assertIn("<pan>", scrubbed)
        self.assertEqual(counts.get("pan"), 1)

    def test_scrub_aadhaar_numbers(self):
        sample = "Aadhaar verified: 4892 1092 8374 on file."
        scrubbed, counts = scrub_text(sample)
        self.assertNotIn("4892 1092 8374", scrubbed)
        self.assertIn("<aadhaar>", scrubbed)
        self.assertEqual(counts.get("aadhaar"), 1)

    def test_scrub_bank_account_numbers(self):
        sample = "Amount debited from A/c 1092837465 on 02-Nov-26."
        scrubbed, counts = scrub_text(sample)
        self.assertNotIn("1092837465", scrubbed)
        self.assertIn("A/c <acct>", scrubbed)
        self.assertEqual(counts.get("account"), 1)

    def test_scrub_payment_cards(self):
        sample = "Transaction on card 4111 2222 3333 4444 approved."
        scrubbed, counts = scrub_text(sample)
        self.assertNotIn("4111 2222 3333 4444", scrubbed)
        self.assertIn("<card>", scrubbed)
        self.assertEqual(counts.get("card"), 1)

    def test_scrub_upi_vpa(self):
        sample = "Sent INR 500 to rahul.kumar@oksbi successfully."
        scrubbed, counts = scrub_text(sample)
        self.assertNotIn("rahul.kumar@oksbi", scrubbed)
        self.assertIn("<upi>", scrubbed)
        self.assertEqual(counts.get("upi"), 1)

    def test_scrub_urls(self):
        sample = "Update KYC at http://sbi-secure-update.xyz/login immediately."
        scrubbed, counts = scrub_text(sample)
        self.assertNotIn("sbi-secure-update.xyz", scrubbed)
        self.assertIn("<url>", scrubbed)
        self.assertEqual(counts.get("url"), 1)

    def test_scrub_names_with_honorifics(self):
        sample = "Contact Mr. Rajesh Verma for account release."
        scrubbed, counts = scrub_text(sample)
        self.assertNotIn("Rajesh Verma", scrubbed)
        self.assertIn("<name>", scrubbed)
        self.assertEqual(counts.get("name"), 1)

    def test_has_unmasked_pii_detector(self):
        self.assertTrue(has_unmasked_pii("Call 9876543210 immediately"))
        self.assertTrue(has_unmasked_pii("PAN is ABCDE1234F"))
        self.assertTrue(has_unmasked_pii("Pay to user@oksbi"))
        self.assertFalse(has_unmasked_pii("Call <phone> or visit branch A/c <acct>"))


class TestCurationPipeline(unittest.TestCase):
    """Test Suite 2: Curation Pipeline Validation and Ingestion."""

    def test_process_valid_curated_record(self):
        raw = {
            "id": "RAW_001",
            "text": "Call officer at 9876543210 to unlock your A/c 1092837465.",
            "label": "scam",
            "language": "hi-latn",
            "category": "kyc_phishing",
            "source": "curated_source",
            "reviewed_by": "auditor_1",
            "notes": "Unmasked raw report"
        }
        processed, err = process_curated_record(raw, auto_scrub_pii=True)
        self.assertIsNone(err)
        self.assertIsNotNone(processed)
        self.assertEqual(processed["label"], CANONICAL_SUSPICIOUS)
        self.assertEqual(processed["language"], "hinglish")
        self.assertIn("<phone>", processed["text"])
        self.assertIn("A/c <acct>", processed["text"])
        self.assertNotIn("9876543210", processed["text"])

    def test_reject_malformed_curated_record(self):
        bad_label = {"id": "1", "text": "Some text", "label": "invalid_label", "language": "en"}
        processed, err = process_curated_record(bad_label)
        self.assertIsNone(processed)
        self.assertIn("label error", err)

        bad_lang = {"id": "2", "text": "Some text", "label": "genuine", "language": "latin"}
        processed, err = process_curated_record(bad_lang)
        self.assertIsNone(processed)
        self.assertIn("language error", err)

    def test_curation_pipeline_blocks_frozen_benchmark(self):
        eval_path = Path("eval/test_set.csv")
        with self.assertRaises(ContaminationError):
            curate_corpus(input_file=eval_path)


class TestSampleCuratedCorpus(unittest.TestCase):
    """Test Suite 3: Verification of sample_curated_corpus.csv Exemplar."""

    def setUp(self):
        self.sample_corpus_path = Path("ml_service/dataset/sample_curated_corpus.csv")

    def test_sample_corpus_exists_and_validates(self):
        self.assertTrue(self.sample_corpus_path.exists())
        audit = audit_dataset(self.sample_corpus_path)
        self.assertTrue(audit["valid"])
        self.assertEqual(audit["total_rows"], 30)

    def test_sample_corpus_balance_and_pii_clean(self):
        stats = curate_corpus(input_file=self.sample_corpus_path, auto_scrub_pii=False)
        self.assertEqual(stats["valid_records"], 30)
        self.assertEqual(stats["errors_count"], 0)
        self.assertEqual(stats["pii_violations_remaining"], 0)

        # 50% Benign, 50% Suspicious
        self.assertEqual(stats["class_distribution"][CANONICAL_BENIGN], 15)
        self.assertEqual(stats["class_distribution"][CANONICAL_SUSPICIOUS], 15)

        # Trilingual distribution
        self.assertEqual(stats["language_distribution"]["en"], 10)
        self.assertEqual(stats["language_distribution"]["hi"], 10)
        self.assertEqual(stats["language_distribution"]["hinglish"], 10)

        # Truthful governance: Synthetic exemplars are recorded without fake reviewer attribution
        self.assertEqual(stats["human_reviewed_count"], 0)
        self.assertEqual(stats["human_review_percentage"], 0.0)


if __name__ == "__main__":
    unittest.main()

