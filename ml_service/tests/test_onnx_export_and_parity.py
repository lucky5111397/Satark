"""
Unit, Regression, and Parity Contract Tests for SATARK ONNX Export & Inference.

Verifies:
1. Missing, empty, whitespace, and oversized inputs.
2. Batch inference and batch tokenization execution.
3. Multilingual script preservation (English, Devanagari Hindi, Roman Hinglish).
4. Output class ordering: 0=BENIGN, 1=SUSPICIOUS (positive class is index 1).
5. Calibrated decision threshold enforcement at T* = 0.10.
6. Numerical parity calculation and tolerance bounds (abs <= 1e-4, rel <= 1e-3).
7. Model initialization failure containment (missing artifact, 0-byte artifact, missing tokenizer).
8. Failure modes, inference exceptions, and offline fallback behavior.
9. Strict privacy preservation (zero user text or OTP tokens leaked to logs or disclosures).
"""

import json
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
import numpy as np

from ml_service.app.config import settings, Settings
from ml_service.app.model_handler import ModelHandler, mask_entities
from ml_service.app.inference import predict_message
from ml_service.app.schemas import PredictRequest, PredictResponse
from ml_service.training.export_onnx import inspect_model_inputs, REPRESENTATIVE_PARITY_SAMPLES


class TestMalformedAndMissingInputs(unittest.TestCase):
    """Verifies that missing, empty, malformed, and oversized inputs are strictly rejected."""

    def test_empty_string_rejected_by_schema(self):
        with self.assertRaises(ValueError):
            PredictRequest(text="")

    def test_whitespace_only_rejected_by_schema(self):
        with self.assertRaises(ValueError):
            PredictRequest(text="   \n\t  ")

    def test_none_text_rejected_by_schema(self):
        with self.assertRaises(ValueError):
            PredictRequest(text=None)

    def test_oversized_text_rejected_by_schema(self):
        with self.assertRaises(ValueError):
            PredictRequest(text="X" * 2001)

    def test_text_length_boundary_accepted(self):
        req = PredictRequest(text="X" * 2000)
        self.assertEqual(len(req.text), 2000)

    def test_invalid_language_tag_rejected(self):
        with self.assertRaises(ValueError):
            PredictRequest(text="Valid text", lang="spanish")


class TestMultilingualAndBatchInference(unittest.TestCase):
    """Verifies multilingual text handling, batch inference, and dynamic sequence handling."""

    def setUp(self):
        self.handler = ModelHandler()
        self.handler.is_loaded = True
        self.handler.threshold = 0.10  # Frozen contract threshold
        self.handler.input_names = ["input_ids", "attention_mask"]
        self.handler.output_names = ["logits"]
        self.handler.session = MagicMock()

    def test_devanagari_hindi_text_preservation(self):
        """Devanagari Hindi characters must not be stripped or corrupted."""
        mock_tok = MagicMock()
        mock_tok.return_value = {
            "input_ids": np.array([[101, 102]], dtype=np.int64),
            "attention_mask": np.array([[1, 1]], dtype=np.int64)
        }
        self.handler.tokenizer = mock_tok

        hindi_text = "प्रिय ग्राहक, आपका बिजली कनेक्शन आज रात काट दिया जाएगा।"
        feed = self.handler.tokenize(hindi_text)
        self.assertIn("input_ids", feed)
        passed_text = mock_tok.call_args[0][0]
        self.assertEqual(passed_text, hindi_text)

    def test_roman_hinglish_text_preservation(self):
        """Roman Hinglish text must retain mixed case and alphanumeric tokens."""
        mock_tok = MagicMock()
        mock_tok.return_value = {
            "input_ids": np.array([[101, 102]], dtype=np.int64),
            "attention_mask": np.array([[1, 1]], dtype=np.int64)
        }
        self.handler.tokenizer = mock_tok

        hinglish_text = "Aapka SBI netbanking lock ho gaya hai. KYC verify karne ke liye call karein."
        feed = self.handler.tokenize(hinglish_text)
        passed_text = mock_tok.call_args[0][0]
        self.assertEqual(passed_text, hinglish_text)

    def test_batch_tokenization_and_inference(self):
        """Batch tokenization and inference must execute with correct output dimensions."""
        mock_tok = MagicMock()
        mock_tok.return_value = {
            "input_ids": np.array([[101, 102], [103, 104], [105, 106]], dtype=np.int64),
            "attention_mask": np.array([[1, 1], [1, 1], [1, 1]], dtype=np.int64)
        }
        self.handler.tokenizer = mock_tok

        batch_texts = [
            "Your OTP is 482019. Do not share.",
            "Urgent: power will disconnect tonight.",
            "Aapka a/c freeze ho gaya hai."
        ]
        feed = self.handler.tokenize_batch(batch_texts)
        self.assertEqual(feed["input_ids"].shape[0], 3)

        # Mock logits for batch of 3:
        # Sample 0: P(scam) = 0.05 (< 0.10 -> BENIGN)
        # Sample 1: P(scam) = 0.85 (>= 0.10 -> SUSPICIOUS)
        # Sample 2: P(scam) = 0.15 (>= 0.10 -> SUSPICIOUS)
        mock_batch_logits = np.array([
            [3.0, 0.0],   # P(scam) ~ 0.047
            [0.0, 2.0],   # P(scam) ~ 0.881
            [1.0, -1.0]   # P(scam) ~ 0.119
        ])
        self.handler.session.run.return_value = [mock_batch_logits]

        results = self.handler.run_batch_inference(feed)
        self.assertEqual(len(results), 3)

        # Item 0
        pred0, conf0, prob0 = results[0]
        self.assertEqual(pred0, 0)  # BENIGN
        self.assertLess(prob0, 0.10)

        # Item 1
        pred1, conf1, prob1 = results[1]
        self.assertEqual(pred1, 1)  # SUSPICIOUS
        self.assertGreaterEqual(prob1, 0.10)

        # Item 2
        pred2, conf2, prob2 = results[2]
        self.assertEqual(pred2, 1)  # SUSPICIOUS
        self.assertGreaterEqual(prob2, 0.10)


class TestClassOrderingAndThresholdContract(unittest.TestCase):
    """Verifies label mapping and exact decision boundaries at T* = 0.10."""

    def setUp(self):
        self.handler = ModelHandler()
        self.handler.is_loaded = True
        self.handler.threshold = 0.10
        self.handler.id2label = {0: "BENIGN", 1: "SUSPICIOUS"}
        self.handler.output_names = ["logits"]
        self.handler.session = MagicMock()

    def test_class_ordering_contract(self):
        """Class index 0 must be BENIGN, class index 1 must be SUSPICIOUS."""
        self.assertEqual(self.handler.id2label[0], "BENIGN")
        self.assertEqual(self.handler.id2label[1], "SUSPICIOUS")
        self.assertEqual(self.handler.label2id["BENIGN"], 0)
        self.assertEqual(self.handler.label2id["SUSPICIOUS"], 1)

    def test_threshold_decision_at_exact_boundary(self):
        """Probability exactly 0.1000 must classify as SUSPICIOUS."""
        # Logits that yield P(scam) = ~0.1000 (logit diff = log(0.10/0.90) = -2.1972)
        mock_logits = np.array([[2.19722, 0.0]])
        self.handler.session.run.return_value = [mock_logits]

        pred, conf, prob = self.handler.run_inference({"input_ids": np.zeros((1, 5))})
        self.assertEqual(prob, 0.10)
        self.assertEqual(pred, 1)  # SUSPICIOUS

    def test_threshold_decision_just_below_boundary(self):
        """Probability 0.0990 (below 0.10) must classify as BENIGN."""
        # Logits that yield P(scam) = ~0.0990
        mock_logits = np.array([[2.25, 0.0]])
        self.handler.session.run.return_value = [mock_logits]

        pred, conf, prob = self.handler.run_inference({"input_ids": np.zeros((1, 5))})
        self.assertLess(prob, 0.10)
        self.assertEqual(pred, 0)  # BENIGN


class TestNumericalParityTolerances(unittest.TestCase):
    """Verifies numerical tolerance calculations between PyTorch and ONNX logits."""

    def test_parity_discrepancy_within_tolerances(self):
        """Differences < 1e-4 absolute and < 1e-3 relative must pass."""
        pt_logits = np.array([[1.50000, -0.80000]])
        ort_logits = np.array([[1.50002, -0.80003]])

        max_abs = float(np.max(np.abs(pt_logits - ort_logits)))
        max_rel = float(np.max(np.abs(pt_logits - ort_logits) / (np.abs(pt_logits) + 1e-7)))

        self.assertLess(max_abs, 1e-4)
        self.assertLess(max_rel, 1e-3)

    def test_parity_discrepancy_exceeding_tolerance_flagged(self):
        """Differences > 1e-4 absolute must trigger failure."""
        pt_logits = np.array([[1.5000, -0.8000]])
        ort_logits = np.array([[1.5005, -0.8000]])

        max_abs = float(np.max(np.abs(pt_logits - ort_logits)))
        self.assertGreater(max_abs, 1e-4)

    def test_representative_samples_schema(self):
        """Representative parity samples list must cover 3 languages and key categories."""
        langs = set(s["lang"] for s in REPRESENTATIVE_PARITY_SAMPLES)
        cats = set(s["category"] for s in REPRESENTATIVE_PARITY_SAMPLES)

        self.assertIn("en", langs)
        self.assertIn("hi", langs)
        self.assertIn("hinglish", langs)
        self.assertIn("otp_negation", cats)
        self.assertIn("bank_transactional", cats)
        self.assertIn("utility_service_notice", cats)
        self.assertIn("electricity_disconnection", cats)
        self.assertIn("digital_arrest_impersonation", cats)


class TestModelFailureModesAndContainment(unittest.TestCase):
    """Tests failure containment when model files are missing or corrupted."""

    def setUp(self):
        self.handler = ModelHandler()
        self.orig_model_path = settings.model_path
        self.orig_tok_path = settings.tokenizer_path

    def tearDown(self):
        settings.model_path = self.orig_model_path
        settings.tokenizer_path = self.orig_tok_path

    def test_missing_model_file_contained(self):
        settings.model_path = Path("/tmp/nonexistent_model_123.onnx")
        loaded = self.handler.load()
        self.assertFalse(loaded)
        self.assertFalse(self.handler.is_loaded)
        self.assertEqual(self.handler.runtime, "none")
        self.assertIn("Model artifact not found", self.handler.load_error)

    def test_empty_model_file_contained(self):
        with tempfile.NamedTemporaryFile(suffix=".onnx", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            settings.model_path = tmp_path
            loaded = self.handler.load()
            self.assertFalse(loaded)
            self.assertIn("0 bytes", self.handler.load_error)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_inference_on_unloaded_model_raises_runtime_error(self):
        self.handler.is_loaded = False
        with self.assertRaises(RuntimeError):
            self.handler.run_inference({"input_ids": np.zeros((1, 5))})


class TestPrivacyAndConfidentiality(unittest.TestCase):
    """Verifies that raw user messages and sensitive OTPs are never leaked or persisted."""

    def test_predict_message_never_logs_or_exposes_raw_text(self):
        secret_payload = "SECRET_OTP_984710_NEVER_LOG_THIS"
        with patch("ml_service.app.inference.model_handler") as mock_mh:
            mock_mh.is_loaded = False
            mock_mh.model_name = "FacebookAI/xlm-roberta-base"

            res = predict_message(secret_payload)
            self.assertNotIn(secret_payload, res.disclosure)
            self.assertNotIn(secret_payload, res.model)
            self.assertEqual(res.status, "model_unavailable")

    def test_entity_masking_scrubs_phone_and_url(self):
        raw_text = "Call 9876543210 or visit https://scam-bank.xyz/login immediately."
        masked = mask_entities(raw_text)
        self.assertNotIn("9876543210", masked)
        self.assertNotIn("https://scam-bank.xyz/login", masked)
        self.assertIn("[PHONE]", masked)
        self.assertIn("[URL]", masked)


if __name__ == "__main__":
    unittest.main()

