"""
Tests for Request Validation and Privacy Boundaries in ML Microservice.
"""

import asyncio
import unittest

try:
    from fastapi.testclient import TestClient
    from fastapi.exceptions import RequestValidationError
    from ml_service.app.main import app, validation_exception_handler
    client = TestClient(app)
    HAS_FASTAPI = True
except (ImportError, RuntimeError):
    client = None
    HAS_FASTAPI = False


@unittest.skipUnless(HAS_FASTAPI, "fastapi or httpx not installed in environment")
class TestValidation(unittest.TestCase):

    def test_reject_empty_text(self):
        """Verify empty string returns 422 Unprocessable Entity."""
        response = client.post("/predict", json={"text": ""})
        self.assertEqual(response.status_code, 422)
        data = response.json()
        self.assertIn("error", data)

    def test_reject_whitespace_only_text(self):
        """Verify whitespace-only string returns 422."""
        response = client.post("/predict", json={"text": "   \n\t  "})
        self.assertEqual(response.status_code, 422)

    def test_reject_oversized_text(self):
        """Verify text exceeding 2000 characters is rejected."""
        long_text = "A" * 2001
        response = client.post("/predict", json={"text": long_text})
        self.assertEqual(response.status_code, 422)

    def test_reject_invalid_language(self):
        """Verify unsupported language parameter is rejected."""
        response = client.post("/predict", json={"text": "Valid message", "lang": "esperanto"})
        self.assertEqual(response.status_code, 422)

    def test_validation_error_does_not_leak_payload(self):
        """Verify validation error messages do not echo private message content."""
        private_text = "SECRET_OTP_PASSWORD_9999"
        response = client.post("/predict", json={"text": private_text, "lang": "invalid_lang"})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(private_text, response.text)

    def test_invalid_language_is_never_echoed(self):
        for language in ("PRIVATE", "SECRET_LANGUAGE_VALUE" * 100, 123, {"PRIVATE_KEY": "PRIVATE_VALUE"}):
            with self.subTest(language_type=type(language).__name__):
                response = client.post("/predict", json={"text": "Synthetic message", "lang": language})
                self.assertEqual(response.status_code, 422)
                self.assertNotIn("PRIVATE", response.text)
                self.assertNotIn("SECRET_LANGUAGE_VALUE", response.text)
                self.assertEqual(response.json()["details"][0]["field"], "lang")

    def test_unknown_validation_location_and_message_are_sanitized(self):
        error = RequestValidationError([{
            "type": "value_error",
            "loc": ("body", "PRIVATE_JSON_KEY"),
            "msg": "PRIVATE_ERROR_VALUE",
            "input": "PRIVATE_INPUT"
        }])
        response = asyncio.run(validation_exception_handler(None, error))
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(b"PRIVATE", response.body)
        self.assertIn(b'"field":"body"', response.body)

    def test_malformed_json_does_not_echo_user_keys(self):
        response = client.post(
            "/predict", content='{"PRIVATE_JSON_KEY":}',
            headers={"Content-Type": "application/json"}
        )
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("PRIVATE_JSON_KEY", response.text)


if __name__ == "__main__":
    unittest.main()
