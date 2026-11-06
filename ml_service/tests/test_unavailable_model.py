"""
Tests for Honest Handling of Missing or Unloaded Model Weights.
Guarantees the system never substitutes a fake or mock prediction
when trained weights are absent.
"""

import unittest

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
class TestUnavailableModel(unittest.TestCase):

    def test_missing_model_returns_model_unavailable(self):
        """
        When model weights are not loaded, /predict must return
        status: 'model_unavailable' with null prediction and confidence.
        """
        original_state = model_handler.is_loaded
        model_handler.is_loaded = False

        try:
            response = client.post("/predict", json={"text": "URGENT: Verify your account immediately."})
            self.assertEqual(response.status_code, 200)

            data = response.json()
            self.assertEqual(data["status"], "model_unavailable")
            self.assertIsNone(data["prediction"])
            self.assertIsNone(data["confidence"])
            self.assertIn("latency_ms", data)
            self.assertIsInstance(data["latency_ms"], (int, float))
            self.assertIn("model", data)
            self.assertIn("Express backend will rely authoritatively", data["disclosure"])

        finally:
            model_handler.is_loaded = original_state

    def test_missing_model_does_not_crash_health(self):
        """Health check must continue to respond 200 even when weights are missing."""
        original_state = model_handler.is_loaded
        model_handler.is_loaded = False

        try:
            response = client.get("/health")
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertFalse(data["model_loaded"])
        finally:
            model_handler.is_loaded = original_state


if __name__ == "__main__":
    unittest.main()
