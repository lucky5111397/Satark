"""
Tests for Satark ML Microservice Health Probe.
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
class TestHealth(unittest.TestCase):

    def test_health_endpoint_structure(self):
        """Verify GET /health returns valid schema and security headers."""
        response = client.get("/health")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["service"], "satark-ml-service")
        self.assertIn("model_loaded", data)
        self.assertIn("model_name", data)
        self.assertIn("runtime", data)
        self.assertIn("disclosure", data)
        self.assertIsInstance(data["model_loaded"], bool)

        # Security Headers Verification
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")

    def test_health_reports_accurate_model_status(self):
        """Health check must accurately reflect whether weights are loaded."""
        response = client.get("/health")
        data = response.json()
        self.assertEqual(data["model_loaded"], model_handler.is_loaded)


if __name__ == "__main__":
    unittest.main()
