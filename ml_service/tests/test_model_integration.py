"""
Production Integration, Concurrency, and Failure Mode Tests for Satark ML Microservice.
Tests ModelHandler lifecycle, artifact integrity, calibrated threshold application,
multilingual preservation, privacy guarantees, concurrency, and error containment.
"""

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
import numpy as np

from ml_service.app.config import settings, Settings, BASE_DIR
from ml_service.app.model_handler import ModelHandler, mask_entities
from ml_service.app.inference import predict_message
from ml_service.app.schemas import PredictRequest, PredictResponse, HealthResponse


class TestModelHandlerLifecycle(unittest.TestCase):
    """Tests model handler loading, integrity verification, and failure containment."""

    def setUp(self):
        self.handler = ModelHandler()
        self.orig_model_path = settings.model_path
        self.orig_tok_path = settings.tokenizer_path

    def tearDown(self):
        settings.model_path = self.orig_model_path
        settings.tokenizer_path = self.orig_tok_path

    def test_initial_state(self):
        """Initial state must be uninitialized and safe."""
        self.assertFalse(self.handler.is_loaded)
        self.assertEqual(self.handler.runtime, "none")
        self.assertIsNone(self.handler.session)
        self.assertIsNone(self.handler.tokenizer)
        self.assertIsNone(self.handler.load_error)

    def test_missing_artifact_fails_safely(self):
        """Non-existent model path must set is_loaded=False with informative error."""
        settings.model_path = Path("/tmp/non_existent_model.onnx")
        loaded = self.handler.load()
        self.assertFalse(loaded)
        self.assertFalse(self.handler.is_loaded)
        self.assertEqual(self.handler.runtime, "none")
        self.assertIn("Model artifact not found", self.handler.load_error)

    def test_corrupted_zero_byte_artifact_fails_safely(self):
        """0-byte corrupted model artifact must be rejected during integrity check."""
        with tempfile.NamedTemporaryFile(suffix=".onnx", delete=False) as tmp_file:
            tmp_path = Path(tmp_file.name)
        try:
            settings.model_path = tmp_path
            loaded = self.handler.load()
            self.assertFalse(loaded)
            self.assertFalse(self.handler.is_loaded)
            self.assertIn("0 bytes", self.handler.load_error)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_metadata_parsing_extracts_calibrated_threshold(self):
        """When model_metadata.json is present, optimal_threshold and model_name must be loaded."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            meta_path = Path(tmp_dir) / "model_metadata.json"
            meta_content = {
                "model_name": "FacebookAI/xlm-roberta-base",
                "optimal_threshold": 0.62,
                "input_names": ["input_ids", "attention_mask"],
                "validation_status": "PASSED"
            }
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta_content, f)

            with patch.object(Settings, "resolve_metadata_path", return_value=meta_path):
                self.handler._load_metadata()
                self.assertEqual(self.handler.threshold, 0.62)
                self.assertEqual(self.handler.model_name, "FacebookAI/xlm-roberta-base")
                self.assertFalse(self.handler.uses_entity_masking)

    def test_offline_tokenizer_missing_fails_safely(self):
        """Missing local tokenizer directory must fail safely without network egress."""
        import sys
        with tempfile.NamedTemporaryFile(suffix=".onnx", delete=False) as tmp_file:
            tmp_file.write(b"dummy_onnx_content")
            tmp_path = Path(tmp_file.name)

        try:
            settings.model_path = tmp_path
            settings.tokenizer_path = Path("/tmp/missing_tokenizer_dir")

            mock_ort = MagicMock()
            mock_ort.InferenceSession.return_value.get_inputs.return_value = [MagicMock(name="input_ids")]
            mock_ort.InferenceSession.return_value.get_outputs.return_value = [MagicMock(name="logits")]
            mock_transformers = MagicMock()

            with patch.dict("sys.modules", {"onnxruntime": mock_ort, "transformers": mock_transformers}):
                loaded = self.handler.load()
                self.assertFalse(loaded)
                self.assertIn("Local tokenizer directory not found", self.handler.load_error)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


class TestCalibratedInference(unittest.TestCase):
    """Tests calibrated threshold logic (T* = 0.62) to prevent false positives on genuine traffic."""

    def setUp(self):
        self.handler = ModelHandler()
        self.handler.is_loaded = True
        self.handler.threshold = 0.62  # Calibrated optimal threshold
        self.handler.output_names = ["logits"]
        self.handler.session = MagicMock()

    def test_sub_threshold_scam_probability_classified_as_benign(self):
        """
        If scam probability is 0.55 (above naive 0.5 but below calibrated 0.62),
        model must classify as BENIGN, preventing false alarm on legitimate banking/OTP notices.
        """
        # Logits that yield P(scam) = ~0.55 and P(benign) = ~0.45
        mock_logits = np.array([[0.0, 0.20]])
        self.handler.session.run.return_value = [mock_logits]

        pred_class, conf, scam_prob = self.handler.run_inference({"input_ids": np.zeros((1, 10))})
        self.assertEqual(pred_class, 0)  # BENIGN
        self.assertLess(scam_prob, 0.62)
        self.assertGreaterEqual(conf, 0.40)

    def test_super_threshold_scam_probability_classified_as_suspicious(self):
        """
        If scam probability is 0.85 (well above calibrated 0.62),
        model must classify as SUSPICIOUS.
        """
        mock_logits = np.array([[0.0, 2.50]])
        self.handler.session.run.return_value = [mock_logits]

        pred_class, conf, scam_prob = self.handler.run_inference({"input_ids": np.zeros((1, 10))})
        self.assertEqual(pred_class, 1)  # SUSPICIOUS
        self.assertGreaterEqual(scam_prob, 0.62)
        self.assertAlmostEqual(conf, scam_prob, places=2)


class TestMultilingualTokenization(unittest.TestCase):
    """Tests multilingual input preservation (English, Hinglish, Hindi Devanagari)."""

    def setUp(self):
        self.handler = ModelHandler()
        self.handler.is_loaded = True
        self.handler.input_names = ["input_ids", "attention_mask"]

    def test_multilingual_inputs_preserves_unicode(self):
        """Tokenize must process Hindi Devanagari without unicode mangling."""
        mock_tok = MagicMock()
        mock_tok.return_value = {
            "input_ids": np.array([[101, 102]], dtype=np.int64),
            "attention_mask": np.array([[1, 1]], dtype=np.int64)
        }
        self.handler.tokenizer = mock_tok

        hindi_text = "प्रिय ग्राहक, आपका बिजली बिल बकाया है।"
        feed = self.handler.tokenize(hindi_text)

        self.assertIn("input_ids", feed)
        self.assertIn("attention_mask", feed)
        mock_tok.assert_called_once()
        passed_text = mock_tok.call_args[0][0]
        self.assertEqual(passed_text, hindi_text)

    def test_text_length_is_strictly_bounded(self):
        """Text exceeding max_text_length (2000) must be safely truncated."""
        mock_tok = MagicMock()
        mock_tok.return_value = {
            "input_ids": np.array([[1, 2]], dtype=np.int64),
            "attention_mask": np.array([[1, 1]], dtype=np.int64)
        }
        self.handler.tokenizer = mock_tok

        oversized_text = "A" * 3000
        feed = self.handler.tokenize(oversized_text)
        passed_text = mock_tok.call_args[0][0]
        self.assertEqual(len(passed_text), 2000)


class TestPredictMessagePipeline(unittest.TestCase):
    """Tests end-to-end predict_message coordinator function."""

    def test_model_unavailable_response(self):
        """When handler is not loaded, returns status: model_unavailable without crash."""
        with patch("ml_service.app.inference.model_handler") as mock_mh:
            mock_mh.is_loaded = False
            mock_mh.model_name = "FacebookAI/xlm-roberta-base"

            res = predict_message("Some message text")
            self.assertEqual(res.status, "model_unavailable")
            self.assertIsNone(res.prediction)
            self.assertIsNone(res.confidence)
            self.assertGreaterEqual(res.latency_ms, 0)
            self.assertIn("Express backend will rely authoritatively", res.disclosure)

    def test_successful_prediction_does_not_leak_user_text(self):
        """Successful prediction must never leak raw input text in disclosure or response."""
        sensitive_text = "SECRET_OTP_729104_CONFIDENTIAL"
        with patch("ml_service.app.inference.model_handler") as mock_mh:
            mock_mh.is_loaded = True
            mock_mh.model_name = "FacebookAI/xlm-roberta-base"
            mock_mh.threshold = 0.62
            mock_mh.id2label = {0: "BENIGN", 1: "SUSPICIOUS"}
            mock_mh.tokenize.return_value = {"input_ids": np.array([[1, 2]])}
            mock_mh.run_inference.return_value = (0, 0.95, 0.05)

            res = predict_message(sensitive_text)
            self.assertEqual(res.status, "ok")
            self.assertEqual(res.prediction, "BENIGN")
            self.assertNotIn(sensitive_text, res.disclosure)


class TestConcurrentInference(unittest.TestCase):
    """Tests thread-safety and concurrent execution under high query volume."""

    def test_concurrent_predict_calls_thread_safety(self):
        """20 concurrent threads calling predict_message must execute cleanly with zero race conditions."""
        with patch("ml_service.app.inference.model_handler") as mock_mh:
            mock_mh.is_loaded = True
            mock_mh.model_name = "FacebookAI/xlm-roberta-base"
            mock_mh.threshold = 0.62
            mock_mh.id2label = {0: "BENIGN", 1: "SUSPICIOUS"}
            mock_mh.tokenize.return_value = {"input_ids": np.array([[1, 2]])}
            mock_mh.run_inference.return_value = (1, 0.92, 0.92)

            results = []
            errors = []

            def worker(msg_idx):
                try:
                    res = predict_message(f"Concurrent message payload number {msg_idx}")
                    results.append(res)
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(len(errors), 0, f"Thread errors encountered: {errors}")
            self.assertEqual(len(results), 20)
            for r in results:
                self.assertEqual(r.status, "ok")
                self.assertEqual(r.prediction, "SUSPICIOUS")


class TestPydanticSchemas(unittest.TestCase):
    """Tests input validation schemas and rejection boundaries."""

    def test_valid_request(self):
        req = PredictRequest(text="Valid input message", lang="hinglish")
        self.assertEqual(req.text, "Valid input message")
        self.assertEqual(req.lang, "hinglish")

    def test_empty_text_rejected(self):
        with self.assertRaises(ValueError):
            PredictRequest(text="")

    def test_whitespace_text_rejected(self):
        with self.assertRaises(ValueError):
            PredictRequest(text="   \n\t  ")

    def test_oversized_text_rejected(self):
        with self.assertRaises(ValueError):
            PredictRequest(text="A" * 2001)

    def test_unsupported_language_rejected(self):
        with self.assertRaises(ValueError):
            PredictRequest(text="Hello", lang="german")


if __name__ == "__main__":
    unittest.main()
