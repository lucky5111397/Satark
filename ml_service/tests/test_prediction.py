"""
Tests for Prediction Endpoint Schema and Mocked Inference Pipeline.
"""

import unittest
from unittest.mock import MagicMock

try:
    from fastapi.testclient import TestClient
    from ml_service.app.main import app
    from ml_service.app.model_handler import model_handler
    client = TestClient(app)
    HAS_FASTAPI = True
except (ImportError, RuntimeError):
    client = None
    model_handler = None
    HAS_FASTAPI = False


@unittest.skipUnless(HAS_FASTAPI, "fastapi or httpx not installed in environment")
class TestPrediction(unittest.TestCase):

    def test_predict_schema_with_mocked_model(self):
        """Verify successful prediction schema conforms to specification."""
        original_loaded = model_handler.is_loaded
        original_session = model_handler.session
        original_tokenizer = model_handler.tokenizer

        try:
            model_handler.is_loaded = True
            # Mock tokenizer
            mock_tokenizer = MagicMock()
            mock_tokenizer.return_value = {
                "input_ids": MagicMock(astype=lambda x: [[1, 2, 3]]),
                "attention_mask": MagicMock(astype=lambda x: [[1, 1, 1]])
            }
            model_handler.tokenizer = mock_tokenizer

            # Mock forward pass
            model_handler.run_inference = MagicMock(return_value=(1, 0.9421, 0.9421))

            response = client.post(
                "/predict",
                json={"text": "URGENT: Your KYC has expired. Update now.", "lang": "en"}
            )
            self.assertEqual(response.status_code, 200)

            data = response.json()
            self.assertEqual(data["status"], "ok")
            self.assertEqual(data["prediction"], "SUSPICIOUS")
            self.assertEqual(data["confidence"], 0.9421)
            self.assertGreaterEqual(data["latency_ms"], 0)
            self.assertIn("Multilingual semantic classification score", data["disclosure"])

        finally:
            model_handler.is_loaded = original_loaded
            model_handler.session = original_session
            model_handler.tokenizer = original_tokenizer

    def test_predict_handles_inference_exception_gracefully(self):
        """Verify internal inference exceptions return status: error without crashing."""
        original_loaded = model_handler.is_loaded

        try:
            model_handler.is_loaded = True
            model_handler.tokenize = MagicMock(side_effect=RuntimeError("Simulated tokenization crash"))

            response = client.post(
                "/predict",
                json={"text": "Some text payload"}
            )
            self.assertEqual(response.status_code, 200)

            data = response.json()
            self.assertEqual(data["status"], "error")
            self.assertIsNone(data["prediction"])
            self.assertIsNone(data["confidence"])
            self.assertIn("Tokenization error", data["disclosure"])

        finally:
            model_handler.is_loaded = original_loaded


if __name__ == "__main__":
    unittest.main()
