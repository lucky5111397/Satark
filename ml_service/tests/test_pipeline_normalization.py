"""
Automated Test Suite for SATARK Phase 5 ML Pipeline Normalization.

Covers:
1. Canonical schema & label mapping (BENIGN / SUSPICIOUS, rejection of unknown).
2. Data contamination protection (blocking eval/test_set.csv, eval/dev_set.csv, etc.).
3. Template fingerprinting & 3-way leakage-free partitioning (70/15/15).
4. Subgroup and hard-negative metrics calculation.
5. Architecture-aware ONNX signature inspection and tokenizer resolution.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# Reconfigure stdout/stderr encoding on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from ml_service.training.validate_dataset import (
    CANONICAL_BENIGN,
    CANONICAL_SUSPICIOUS,
    ContaminationError,
    check_contamination,
    normalize_label,
    normalize_language,
    normalize_row,
    audit_dataset,
)
from ml_service.training.prepare_dataset import (
    extract_template_fingerprint,
    split_three_way_grouped,
)
from ml_service.training.metrics import (
    calculate_binary_metrics,
    compute_subgroup_metrics,
    format_metrics_report,
)
from ml_service.training.export_onnx import inspect_model_inputs
from ml_service.training.evaluate import resolve_tokenizer_target


class TestLabelAndLanguageNormalization(unittest.TestCase):
    """Test Suite 1: Canonical Label and Language Normalization."""

    def test_canonical_label_constants(self):
        self.assertEqual(CANONICAL_BENIGN, "BENIGN")
        self.assertEqual(CANONICAL_SUSPICIOUS, "SUSPICIOUS")

    def test_normalize_label_benign_variants(self):
        valid_benign = [
            "BENIGN", "benign", "Benign",
            "genuine", "GENUINE", " Genuine ",
            "clean", "CLEAN",
            "ham", "HAM",
            "0", 0
        ]
        for val in valid_benign:
            self.assertEqual(
                normalize_label(val),
                CANONICAL_BENIGN,
                f"Failed to normalize benign variant: {val}"
            )

    def test_normalize_label_suspicious_variants(self):
        valid_suspicious = [
            "SUSPICIOUS", "suspicious", "Suspicious",
            "scam", "SCAM", " Scam ",
            "fraud", "FRAUD",
            "1", 1
        ]
        for val in valid_suspicious:
            self.assertEqual(
                normalize_label(val),
                CANONICAL_SUSPICIOUS,
                f"Failed to normalize suspicious variant: {val}"
            )

    def test_reject_invalid_or_ambiguous_labels(self):
        invalid_labels = [
            "unknown", "maybe", "suspiciously_benign",
            "", "   ", None, 2, -1, "2", "safe", "danger", "phish"
        ]
        for invalid in invalid_labels:
            with self.assertRaises(ValueError, msg=f"Should reject label: {invalid}"):
                normalize_label(invalid)

    def test_normalize_language_variants(self):
        self.assertEqual(normalize_language("en"), "en")
        self.assertEqual(normalize_language("EN"), "en")
        self.assertEqual(normalize_language("english"), "en")

        self.assertEqual(normalize_language("hi"), "hi")
        self.assertEqual(normalize_language("hindi"), "hi")

        self.assertEqual(normalize_language("hinglish"), "hinglish")
        self.assertEqual(normalize_language("hi-latn"), "hinglish")
        self.assertEqual(normalize_language("roman-hindi"), "hinglish")
        self.assertEqual(normalize_language("roman-hinglish"), "hinglish")
        self.assertEqual(normalize_language("hindi-english"), "hinglish")

    def test_reject_unsupported_languages(self):
        for lang in ["esperanto", "fr", "de", "es", ""]:
            with self.assertRaises(ValueError):
                normalize_language(lang)

    def test_normalize_row_validation(self):
        valid_row = {
            "id": "TR_001",
            "text": "Your OTP is 493021. Never share your OTP with anyone.",
            "label": "genuine",
            "language": "en",
            "category": "otp",
            "source": "synthetic_seed",
            "reviewed_by": "qa_team",
            "notes": "Advisory text"
        }
        normalized = normalize_row(valid_row)
        self.assertEqual(normalized["label"], CANONICAL_BENIGN)
        self.assertEqual(normalized["language"], "en")
        self.assertEqual(normalized["id"], "TR_001")

    def test_reject_oversized_or_empty_text_in_row(self):
        empty_row = {"id": "1", "text": "   ", "label": "genuine", "language": "en"}
        with self.assertRaises(ValueError):
            normalize_row(empty_row)

        oversized_row = {"id": "2", "text": "A" * 2001, "label": "genuine", "language": "en"}
        with self.assertRaises(ValueError):
            normalize_row(oversized_row)


class TestContaminationProtection(unittest.TestCase):
    """Test Suite 2: Data Contamination Barrier."""

    def test_block_frozen_test_set(self):
        with self.assertRaises(ContaminationError):
            check_contamination(Path("eval/test_set.csv"))

    def test_block_benchmark_indicbert(self):
        with self.assertRaises(ContaminationError):
            check_contamination(Path("eval/benchmark_indicbert.csv"))

    def test_block_dev_and_probe_sets(self):
        with self.assertRaises(ContaminationError):
            check_contamination(Path("eval/dev_set.csv"))
        with self.assertRaises(ContaminationError):
            check_contamination(Path("eval/probe_set.csv"))

    def test_block_eval_and_fixtures_directories(self):
        with self.assertRaises(ContaminationError):
            check_contamination(Path("eval/some_new_eval.csv"))
        with self.assertRaises(ContaminationError):
            check_contamination(Path("tests/fixtures/eval.csv"))

    def test_block_benchmark_row_provenance(self):
        with self.assertRaises(ContaminationError):
            check_contamination(
                file_path=Path("ml_service/dataset/custom.csv"),
                rows=[{"id": "TR_100", "source": "frozen_test_set"}]
            )
        with self.assertRaises(ContaminationError):
            check_contamination(
                file_path=Path("ml_service/dataset/custom.csv"),
                rows=[{"id": "BM_0042", "source": "synthetic"}]
            )
        with self.assertRaises(ContaminationError):
            check_contamination(
                file_path=Path("ml_service/dataset/custom.csv"),
                rows=[{"id": "T001", "source": "synthetic"}]
            )

    def test_allow_valid_training_filepath(self):
        # Should not raise
        check_contamination(file_path=Path("ml_service/dataset/train.csv"))
        check_contamination(
            file_path=Path("ml_service/dataset/train.csv"),
            rows=[{"id": "TR_999", "source": "synthetic_seed"}]
        )


class TestTemplateExtractionAndThreeWaySplit(unittest.TestCase):
    """Test Suite 3: Template Fingerprint Extraction & Grouped 3-Way Split."""

    def test_template_fingerprint_normalization(self):
        msg1 = "Dear Customer, INR 1,500 debited for acct XX1234 on 02-11-2026. Ref: 9876543210. Call 9876543210."
        msg2 = "Dear Customer, INR 9,999 debited for acct XX5678 on 03-11-2026. Ref: 9123456789. Call 9123456789."
        
        fp1 = extract_template_fingerprint(msg1)
        fp2 = extract_template_fingerprint(msg2)
        self.assertEqual(fp1, fp2, "Different amounts/phones/dates should map to identical template fingerprint.")

    def test_template_fingerprint_url_normalization(self):
        msg1 = "Update your KYC immediately at https://bank-login.fake.in/verify"
        msg2 = "Update your KYC immediately at http://secure-update.xyz/login"

        fp1 = extract_template_fingerprint(msg1)
        fp2 = extract_template_fingerprint(msg2)
        self.assertEqual(fp1, fp2, "Different URLs should map to identical [URL] placeholder.")

    def test_three_way_grouped_split_ratio_and_zero_leakage(self):
        # Create a synthetic dataset of 100 rows with 20 distinct templates
        dataset = []
        for i in range(100):
            template_id = i % 20
            label = CANONICAL_BENIGN if template_id < 10 else CANONICAL_SUSPICIOUS
            lang = "en" if template_id % 3 == 0 else ("hi" if template_id % 3 == 1 else "hinglish")
            dataset.append({
                "id": f"TR_{i:04d}",
                "text": f"TemplateGroup{template_id} message variation with unique code {i * 7 + 13} at http://link{i}.com",
                "label": label,
                "language": lang,
                "category": "test",
                "source": "synthetic"
            })

        train_set, cal_set, holdout_set, stats = split_three_way_grouped(
            dataset,
            train_ratio=0.70,
            calib_ratio=0.15,
            holdout_ratio=0.15,
            seed=42
        )

        total_rows = len(train_set) + len(cal_set) + len(holdout_set)
        self.assertEqual(total_rows, 100)

        # Check proportions (within reasonable rounding bounds of grouping)
        self.assertTrue(60 <= len(train_set) <= 80, f"Train count {len(train_set)} out of expected range")
        self.assertTrue(10 <= len(cal_set) <= 25, f"Cal count {len(cal_set)} out of expected range")
        self.assertTrue(10 <= len(holdout_set) <= 25, f"Holdout count {len(holdout_set)} out of expected range")

        # CRITICAL TEST: 0% Template Leakage across partitions
        train_templates = {extract_template_fingerprint(r["text"]) for r in train_set}
        cal_templates = {extract_template_fingerprint(r["text"]) for r in cal_set}
        holdout_templates = {extract_template_fingerprint(r["text"]) for r in holdout_set}

        self.assertEqual(len(train_templates.intersection(cal_templates)), 0, "Train and Cal share templates!")
        self.assertEqual(len(train_templates.intersection(holdout_templates)), 0, "Train and Holdout share templates!")
        self.assertEqual(len(cal_templates.intersection(holdout_templates)), 0, "Cal and Holdout share templates!")

        # ID disjointness
        train_ids = {r["id"] for r in train_set}
        cal_ids = {r["id"] for r in cal_set}
        holdout_ids = {r["id"] for r in holdout_set}
        self.assertEqual(len(train_ids.intersection(cal_ids)), 0)
        self.assertEqual(len(train_ids.intersection(holdout_ids)), 0)
        self.assertEqual(len(cal_ids.intersection(holdout_ids)), 0)


class TestMetricsComputation(unittest.TestCase):
    """Test Suite 4: Metrics & Hard-Negative Subgroup Computation."""

    def test_calculate_binary_metrics(self):
        # 10 examples: 5 benign (0), 5 suspicious (1)
        y_true = [0, 0, 0, 0, 0, 1, 1, 1, 1, 1]
        # Preds: 4 TN, 1 FP, 1 FN, 4 TP
        y_pred = [0, 0, 0, 0, 1, 0, 1, 1, 1, 1]

        m = calculate_binary_metrics(y_true, y_pred)
        self.assertEqual(m["total"], 10)
        self.assertEqual(m["tp"], 4)
        self.assertEqual(m["fp"], 1)
        self.assertEqual(m["tn"], 4)
        self.assertEqual(m["fn"], 1)
        self.assertEqual(m["accuracy"], 0.8)
        self.assertEqual(m["precision"], 0.8) # 4 / (4+1)
        self.assertEqual(m["recall"], 0.8)    # 4 / (4+1)
        self.assertEqual(m["fpr"], 0.2)       # 1 / (1+4)
        self.assertEqual(m["f1"], 0.8)

    def test_subgroup_and_hard_negative_metrics(self):
        y_true = [0, 0, 0, 1, 1, 1]
        y_pred = [0, 1, 0, 1, 1, 0]
        languages = ["en", "hinglish", "hi", "en", "hi", "hinglish"]
        categories = ["otp_negation", "otp_negation", "bank_credit", "lottery", "lottery", "fraud"]

        subgroups = compute_subgroup_metrics(y_true, y_pred, languages, categories)

        # Global metrics
        self.assertIn("overall", subgroups)
        self.assertEqual(subgroups["overall"]["total"], 6)

        # Language breakdown
        self.assertIn("per_language", subgroups)
        self.assertIn("en", subgroups["per_language"])
        self.assertIn("hi", subgroups["per_language"])
        self.assertIn("hinglish", subgroups["per_language"])

        # English: 1 TN (row 0), 1 TP (row 3) -> 0% FPR
        self.assertEqual(subgroups["per_language"]["en"]["fpr"], 0.0)

        # Hinglish: 1 FP (row 1), 1 FN (row 5) -> FPR = 1.0 (1 FP, 0 TN)
        self.assertEqual(subgroups["per_language"]["hinglish"]["fpr"], 1.0)

        # Hard-negative metrics
        self.assertIn("hard_negatives", subgroups)
        self.assertIn("otp_negation", subgroups["hard_negatives"])
        # In OTP negation, there are 2 rows (row 0 & row 1), 1 TN and 1 FP -> FPR = 0.5
        self.assertEqual(subgroups["hard_negatives"]["otp_negation"]["total"], 2)
        self.assertEqual(subgroups["hard_negatives"]["otp_negation"]["fpr"], 0.5)

        # Format report should not raise
        report = format_metrics_report(subgroups)
        self.assertIn("SATARK EVALUATION METRICS", report)
        self.assertIn("Hard-Negative False Positive Rate", report)


class TestModelArchitectureAndTokenizerConfig(unittest.TestCase):
    """Test Suite 5: Architecture-Aware Inputs and Tokenizer Resolution."""

    def test_inspect_model_inputs_with_token_type_ids(self):
        # Simulate BERT / Hing-BERT model with token_type_ids
        mock_model = MagicMock()
        mock_model.forward = MagicMock()
        mock_model.__class__.__name__ = "HingBertForSequenceClassification"
        import inspect
        sig = inspect.Signature([
            inspect.Parameter("input_ids", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            inspect.Parameter("attention_mask", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            inspect.Parameter("token_type_ids", inspect.Parameter.POSITIONAL_OR_KEYWORD),
        ])
        mock_tokenizer = MagicMock()
        mock_tokenizer.model_input_names = ["input_ids", "token_type_ids", "attention_mask"]

        with unittest.mock.patch("inspect.signature", return_value=sig):
            dummy_inputs, input_names, dynamic_axes, uses_token_type = inspect_model_inputs(mock_model, mock_tokenizer)
            self.assertTrue(uses_token_type)
            self.assertIn("token_type_ids", input_names)
            self.assertIn("token_type_ids", dynamic_axes)
            self.assertEqual(len(input_names), 3)

    def test_inspect_model_inputs_without_token_type_ids(self):
        # Simulate XLM-RoBERTa model without token_type_ids
        mock_model = MagicMock()
        mock_model.forward = MagicMock()
        mock_model.__class__.__name__ = "XLMRobertaForSequenceClassification"
        import inspect
        sig = inspect.Signature([
            inspect.Parameter("input_ids", inspect.Parameter.POSITIONAL_OR_KEYWORD),
            inspect.Parameter("attention_mask", inspect.Parameter.POSITIONAL_OR_KEYWORD),
        ])
        mock_tokenizer = MagicMock()
        mock_tokenizer.model_input_names = ["input_ids", "attention_mask"]

        with unittest.mock.patch("inspect.signature", return_value=sig):
            dummy_inputs, input_names, dynamic_axes, uses_token_type = inspect_model_inputs(mock_model, mock_tokenizer)
            self.assertFalse(uses_token_type)
            self.assertNotIn("token_type_ids", input_names)
            self.assertNotIn("token_type_ids", dynamic_axes)
            self.assertEqual(len(input_names), 2)

    def test_resolve_tokenizer_explicit_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            tok_dir = tmppath / "custom_tok"
            tok_dir.mkdir()
            (tok_dir / "tokenizer_config.json").write_text("{}", encoding="utf-8")

            resolved = resolve_tokenizer_target(model_path=tmppath, tokenizer_path=str(tok_dir))
            self.assertEqual(resolved, str(tok_dir))

    def test_resolve_tokenizer_from_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            meta = {"tokenizer_name": "l3cube-pune/hing-bert"}
            (tmppath / "model_metadata.json").write_text(json.dumps(meta), encoding="utf-8")

            resolved = resolve_tokenizer_target(model_path=tmppath)
            self.assertEqual(resolved, "l3cube-pune/hing-bert")

    def test_resolve_tokenizer_raises_when_unmatched(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            # Empty dir without metadata or tokenizer files
            with self.assertRaises(RuntimeError):
                resolve_tokenizer_target(model_path=tmppath)


if __name__ == "__main__":
    unittest.main()
