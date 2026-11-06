"""Publication regressions using synthetic inputs and a fake inference runtime."""

import csv
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ml_service.curation.synthetic_generator import parse_args, audit_pilot_dataset
from ml_service.training.evaluate import evaluate_model, resolve_tokenizer

try:
    import numpy as np
except ImportError:
    np = None

try:
    from pydantic import ValidationError
    from ml_service.app.config import Settings
except ImportError:
    Settings = None


class TestSyntheticBenchmarkOptIn(unittest.TestCase):
    def test_default_cli_does_not_select_frozen_benchmark(self):
        self.assertIsNone(parse_args([]).benchmark)

    def test_explicit_benchmark_is_preserved(self):
        self.assertEqual(parse_args(["--benchmark", "synthetic-fixture.csv"]).benchmark, "synthetic-fixture.csv")

    def test_omitted_benchmark_is_reported_as_not_run(self):
        self.assertEqual(audit_pilot_dataset([])["verifications"]["benchmark_isolation"], "NOT_RUN")


class TestOfflineEvaluationTokenizer(unittest.TestCase):
    def test_evaluation_forbids_remote_downloads_and_custom_code(self):
        loader = Mock()
        fake_transformers = SimpleNamespace(AutoTokenizer=SimpleNamespace(from_pretrained=loader))
        with patch.dict(sys.modules, {"transformers": fake_transformers}), patch(
            "ml_service.training.evaluate.resolve_tokenizer_target", return_value="cached-model-fixture"
        ):
            resolve_tokenizer(Path("synthetic-model-fixture"))
        loader.assert_called_once_with(
            "cached-model-fixture", local_files_only=True, trust_remote_code=False
        )


@unittest.skipUnless(Settings is not None, "pydantic and python-dotenv are required")
class TestLoopbackSettings(unittest.TestCase):
    def test_reject_non_loopback_explicit_host(self):
        for host in ("0.0.0.0", "192.0.2.1", "example.invalid"):
            with self.subTest(host=host), self.assertRaises(ValidationError):
                Settings(host=host)

    def test_environment_default_is_validated(self):
        with patch.dict(os.environ, {"HOST": "0.0.0.0"}):
            with self.assertRaises(ValidationError):
                Settings()
        with patch.dict(os.environ, {"HOST": "127.0.0.1"}):
            self.assertEqual(Settings().host, "127.0.0.1")


@unittest.skipUnless(np is not None, "numpy is required for synthetic inference tensors")
class TestEvaluationReportPrivacy(unittest.TestCase):
    def test_misclassification_report_omits_message_text(self):
        private_marker = "PRIVATE_SYNTHETIC_MESSAGE_MARKER"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            model_path = root / "fixture.onnx"
            model_path.write_bytes(b"not a real model; runtime is mocked")
            data_file = root / "synthetic.csv"
            with data_file.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=["id", "text", "label", "language", "category"])
                writer.writeheader()
                writer.writerows([
                    {"id": "SYNTHETIC_FP", "text": private_marker, "label": "BENIGN", "language": "en", "category": "otp_negation"},
                    {"id": "SYNTHETIC_FN", "text": private_marker, "label": "SUSPICIOUS", "language": "en", "category": "job_scam"}
                ])

            outputs = iter([np.array([[0.0, 2.0]]), np.array([[2.0, 0.0]])])
            session = SimpleNamespace(
                get_inputs=lambda: [SimpleNamespace(name="input_ids")],
                get_outputs=lambda: [SimpleNamespace(name="logits")],
                run=lambda *_: [next(outputs)]
            )
            runtime = SimpleNamespace(InferenceSession=lambda *_args, **_kwargs: session)
            tokenizer = lambda *_args, **_kwargs: {"input_ids": np.array([[1]], dtype=np.int64)}
            output_file = root / "report.json"
            with patch.dict(sys.modules, {"onnxruntime": runtime}), patch(
                "ml_service.training.evaluate.resolve_tokenizer", return_value=tokenizer
            ):
                report = evaluate_model(model_path, data_file, output_file, threshold=0.5)

            serialized = output_file.read_text(encoding="utf-8")
            self.assertNotIn(private_marker, serialized)
            self.assertNotIn("text_snippet", serialized)
            self.assertEqual(report["false_positive_analysis"]["false_positives_sample"][0]["id"], "SYNTHETIC_FP")
            self.assertEqual(report["false_negative_analysis"]["false_negatives_sample"][0]["id"], "SYNTHETIC_FN")
            self.assertEqual(json.loads(serialized)["total_evaluated"], 2)


if __name__ == "__main__":
    unittest.main()
