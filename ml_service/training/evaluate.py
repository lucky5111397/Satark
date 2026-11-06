"""
Evaluation and Metrics Reporting Utility for SATARK ML.
Computes Precision, Recall, F1, Accuracy, FPR, FNR, Per-Language Performance,
Per-Category Performance, and Hard-Negative FPR on holdout evaluation sets.
Supports both PyTorch checkpoints and exported ONNX models.
Measures latency (P50, P95, mean) and model size.
Extracts false-positive analysis for legitimate OTP warnings, bank transactions, and utility notices.
"""

import argparse
import csv
import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional, Dict, Any, List

from .metrics import compute_subgroup_metrics, format_metrics_report
from .validate_dataset import normalize_label, CANONICAL_BENIGN, CANONICAL_SUSPICIOUS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("satark.ml.evaluate")

LABEL2ID = {CANONICAL_BENIGN: 0, CANONICAL_SUSPICIOUS: 1}
ID2LABEL = {0: CANONICAL_BENIGN, 1: CANONICAL_SUSPICIOUS}

CRITICAL_HARD_NEGATIVE_CATEGORIES = {
    "otp_negation",
    "bank_transactional",
    "utility_service_notice"
}


def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate an exported ONNX model or PyTorch checkpoint.")
    parser.add_argument("--model_path", required=True, type=str, help="Path to ONNX model file or PyTorch checkpoint directory.")
    parser.add_argument("--data_file", required=True, type=str, help="Path to evaluation CSV dataset.")
    parser.add_argument("--output_file", default="ml_service/artifacts/eval_report.json", type=str, help="Path to write JSON evaluation metrics report.")
    parser.add_argument("--tokenizer_path", default=None, type=str, help="Explicit path to tokenizer directory (optional).")
    parser.add_argument("--model_name", default=None, type=str, help="Explicit Hugging Face base model identifier for tokenizer resolution (optional).")
    parser.add_argument("--threshold", default=None, type=float, help="Decision threshold for scam classification (default: from metadata or 0.5).")
    parser.add_argument("--device", default="cpu", type=str, help="Device for PyTorch evaluation ('cpu' or 'cuda').")
    return parser.parse_args()


def resolve_tokenizer_target(
    model_path: Path,
    tokenizer_path: Optional[str] = None,
    model_name: Optional[str] = None
) -> str:
    """
    Resolves the exact tokenizer directory or Hugging Face model identifier
    without relying on hardcoded fallbacks.
    Raises RuntimeError if tokenizer cannot be definitively matched.
    """
    model_dir = model_path if model_path.is_dir() else model_path.parent

    # 1. Explicit CLI tokenizer path
    if tokenizer_path:
        t_path = Path(tokenizer_path)
        if t_path.exists():
            logger.info(f"Resolved tokenizer from explicit path: {t_path}")
            return str(t_path)

    # 2. Local tokenizer directory alongside model
    local_tokenizer_dir = model_dir / "tokenizer"
    if local_tokenizer_dir.exists() and local_tokenizer_dir.is_dir():
        logger.info(f"Resolved local matching tokenizer from: {local_tokenizer_dir}")
        return str(local_tokenizer_dir)

    # 3. Model directory itself (if tokenizer files are directly inside it)
    if (model_dir / "tokenizer_config.json").exists() or (model_dir / "vocab.json").exists():
        logger.info(f"Resolved tokenizer directly from checkpoint directory: {model_dir}")
        return str(model_dir)

    # 4. Model metadata file alongside model
    metadata_path = model_dir / "model_metadata.json"
    if metadata_path.exists():
        try:
            with open(metadata_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            inferred_model = (
                meta.get("tokenizer_name") or
                meta.get("model_name") or
                meta.get("base_model") or
                meta.get("model_name_or_path")
            )
            if inferred_model:
                logger.info(f"Resolved tokenizer from model metadata: '{inferred_model}'")
                return inferred_model
        except Exception as e:
            logger.warning(f"Could not read model_metadata.json: {e}")

    # 5. Explicit CLI model identifier
    if model_name:
        logger.info(f"Resolved tokenizer from explicit model identifier: '{model_name}'")
        return model_name

    # 6. Prohibit blind fallback
    raise RuntimeError(
        f"Cannot resolve matching tokenizer for model at '{model_path}'. "
        "Checkpoint must be accompanied by a local 'tokenizer/' directory, 'model_metadata.json', "
        "or explicit --tokenizer_path / --model_name arguments. Hardcoded tokenizer fallback is strictly prohibited."
    )


def resolve_tokenizer(
    model_path: Path,
    tokenizer_path: Optional[str] = None,
    model_name: Optional[str] = None
):
    """
    Resolves matching tokenizer for model checkpoint without hardcoded fallbacks.
    """
    target = resolve_tokenizer_target(model_path, tokenizer_path=tokenizer_path, model_name=model_name)
    from transformers import AutoTokenizer
    # Evaluation must use local assets or an already cached model identifier.
    return AutoTokenizer.from_pretrained(target, local_files_only=True, trust_remote_code=False)


def resolve_threshold(model_path: Path, explicit_threshold: Optional[float] = None) -> float:
    """Resolves decision threshold from explicit arg, model_metadata.json, or default 0.5."""
    if explicit_threshold is not None:
        logger.info(f"Using explicit decision threshold: {explicit_threshold}")
        return float(explicit_threshold)

    model_dir = model_path if model_path.is_dir() else model_path.parent
    meta_path = model_dir / "model_metadata.json"
    if meta_path.exists():
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            threshold = meta.get("optimal_threshold") or meta.get("threshold")
            if threshold is not None:
                logger.info(f"Resolved optimal calibrated threshold from metadata: {threshold}")
                return float(threshold)
        except Exception as e:
            logger.warning(f"Could not read threshold from metadata: {e}")

    logger.info("Using default decision threshold: 0.50")
    return 0.50


def compute_model_size_mb(model_path: Path) -> float:
    """Computes total file size of model artifact in MB."""
    if model_path.is_file():
        return round(model_path.stat().st_size / (1024 * 1024), 2)
    elif model_path.is_dir():
        total_bytes = sum(f.stat().st_size for f in model_path.glob("**/*") if f.is_file())
        return round(total_bytes / (1024 * 1024), 2)
    return 0.0


def evaluate_model(
    model_path: Path,
    data_file: Path,
    output_file: Path,
    tokenizer_path: Optional[str] = None,
    model_name: Optional[str] = None,
    threshold: Optional[float] = None,
    device: str = "cpu"
) -> Dict[str, Any]:
    """
    Evaluates either an ONNX model (.onnx) or a PyTorch checkpoint directory.
    Profiles latency, measures size, computes subgroups, and extracts false positives.
    """
    is_onnx = model_path.is_file() and model_path.suffix.lower() == ".onnx"
    active_threshold = resolve_threshold(model_path, threshold)
    model_size_mb = compute_model_size_mb(model_path)

    # Read dataset
    rows = []
    with open(data_file, mode="r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)

    if not rows:
        logger.error(f"No rows found in evaluation dataset: {data_file}")
        sys.exit(1)

    tokenizer = resolve_tokenizer(model_path, tokenizer_path=tokenizer_path, model_name=model_name)

    latencies_ms: List[float] = []
    y_true: List[int] = []
    y_pred: List[int] = []
    y_probs: List[float] = []
    languages: List[str] = []
    categories: List[str] = []
    sample_ids: List[str] = []

    if is_onnx:
        try:
            import onnxruntime as ort
            import numpy as np
        except ImportError as e:
            logger.error(f"Missing ONNX evaluation dependencies: {e}")
            sys.exit(1)

        logger.info(f"Loading ONNX model from: {model_path}")
        session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
        input_names = [inp.name for inp in session.get_inputs()]
        output_names = [out.name for out in session.get_outputs()]

        logger.info(f"Running ONNX evaluation on {len(rows)} samples (Threshold={active_threshold:.2f})...")
        for idx, row in enumerate(rows):
            text = row.get("text", "")
            raw_label = row.get("label", "").strip()
            lang = (row.get("language") or "unknown").strip().lower()
            cat = (row.get("category") or "general").strip().lower()

            try:
                norm_label = normalize_label(raw_label)
            except ValueError:
                continue

            true_label_id = LABEL2ID[norm_label]

            encoded = tokenizer(
                text,
                max_length=128,
                padding="max_length",
                truncation=True,
                return_tensors="np"
            )

            feed_dict = {}
            if "input_ids" in input_names:
                feed_dict["input_ids"] = encoded["input_ids"].astype(np.int64)
            if "attention_mask" in input_names:
                feed_dict["attention_mask"] = encoded["attention_mask"].astype(np.int64)
            if "token_type_ids" in input_names:
                if "token_type_ids" in encoded:
                    feed_dict["token_type_ids"] = encoded["token_type_ids"].astype(np.int64)
                else:
                    feed_dict["token_type_ids"] = np.zeros_like(encoded["input_ids"], dtype=np.int64)

            t0 = time.perf_counter()
            outputs = session.run(output_names, feed_dict)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies_ms.append(elapsed_ms)

            logits = outputs[0]
            exp_l = np.exp(logits - np.max(logits, axis=-1, keepdims=True))
            probs = exp_l / np.sum(exp_l, axis=-1, keepdims=True)
            scam_prob = float(probs[0][1])

            pred_label_id = 1 if scam_prob >= active_threshold else 0

            y_true.append(true_label_id)
            y_pred.append(pred_label_id)
            y_probs.append(scam_prob)
            languages.append(lang)
            categories.append(cat)
            sample_ids.append(row.get("id", ""))

    else:
        # PyTorch Checkpoint Evaluation
        try:
            import torch
            import numpy as np
            from transformers import AutoModelForSequenceClassification
        except ImportError as e:
            logger.error(f"Missing PyTorch evaluation dependencies: {e}")
            sys.exit(1)

        logger.info(f"Loading PyTorch checkpoint from: {model_path} (device={device})")
        model = AutoModelForSequenceClassification.from_pretrained(
            str(model_path), local_files_only=True, trust_remote_code=False, use_safetensors=True
        )
        torch_device = torch.device(device if torch.cuda.is_available() and device == "cuda" else "cpu")
        model.to(torch_device)
        model.eval()

        logger.info(f"Running PyTorch evaluation on {len(rows)} samples (Threshold={active_threshold:.2f})...")
        with torch.no_grad():
            for idx, row in enumerate(rows):
                text = row.get("text", "")
                raw_label = row.get("label", "").strip()
                lang = (row.get("language") or "unknown").strip().lower()
                cat = (row.get("category") or "general").strip().lower()

                try:
                    norm_label = normalize_label(raw_label)
                except ValueError:
                    continue

                true_label_id = LABEL2ID[norm_label]

                encoded = tokenizer(
                    text,
                    max_length=128,
                    padding="max_length",
                    truncation=True,
                    return_tensors="pt"
                )
                encoded = {k: v.to(torch_device) for k, v in encoded.items()}

                t0 = time.perf_counter()
                out = model(**encoded)
                if torch_device.type == "cuda":
                    torch.cuda.synchronize()
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                latencies_ms.append(elapsed_ms)

                logits = out.logits.detach().cpu().numpy()
                exp_l = np.exp(logits - np.max(logits, axis=-1, keepdims=True))
                probs = exp_l / np.sum(exp_l, axis=-1, keepdims=True)
                scam_prob = float(probs[0][1])

                pred_label_id = 1 if scam_prob >= active_threshold else 0

                y_true.append(true_label_id)
                y_pred.append(pred_label_id)
                y_probs.append(scam_prob)
                languages.append(lang)
                categories.append(cat)
                sample_ids.append(row.get("id", ""))

    # Compute Latency Statistics
    try:
        import numpy as np
        lat_arr = np.array(latencies_ms)
        p50_lat = float(np.percentile(lat_arr, 50))
        p95_lat = float(np.percentile(lat_arr, 95))
        p99_lat = float(np.percentile(lat_arr, 99))
        mean_lat = float(np.mean(lat_arr))
        total_time_s = sum(latencies_ms) / 1000.0
        throughput = float(len(latencies_ms) / max(total_time_s, 0.001))
    except Exception:
        mean_lat = sum(latencies_ms) / max(len(latencies_ms), 1)
        p50_lat, p95_lat, p99_lat = mean_lat, mean_lat, mean_lat
        throughput = 0.0

    latency_stats = {
        "mean_latency_ms": round(mean_lat, 2),
        "p50_latency_ms": round(p50_lat, 2),
        "p95_latency_ms": round(p95_lat, 2),
        "p99_latency_ms": round(p99_lat, 2),
        "throughput_samples_sec": round(throughput, 2),
        "total_samples": len(latencies_ms)
    }

    # Extract False Positives and False Negatives
    false_positives: List[Dict[str, Any]] = []
    false_negatives: List[Dict[str, Any]] = []
    critical_hard_neg_fps: List[Dict[str, Any]] = []

    for i in range(len(y_true)):
        t_label = y_true[i]
        p_label = y_pred[i]
        prob = round(y_probs[i], 4)
        cat = categories[i]
        lng = languages[i]

        if t_label == 0 and p_label == 1:
            fp_entry = {
                "index": i,
                "id": sample_ids[i],
                "category": cat,
                "language": lng,
                "scam_probability": prob,
                "threshold": round(active_threshold, 2)
            }
            false_positives.append(fp_entry)
            if cat in CRITICAL_HARD_NEGATIVE_CATEGORIES:
                critical_hard_neg_fps.append(fp_entry)

        elif t_label == 1 and p_label == 0:
            fn_entry = {
                "index": i,
                "id": sample_ids[i],
                "category": cat,
                "language": lng,
                "scam_probability": prob,
                "threshold": round(active_threshold, 2)
            }
            false_negatives.append(fn_entry)

    # Compute comprehensive metrics
    metrics = compute_subgroup_metrics(
        y_true=y_true,
        y_pred=y_pred,
        languages=languages,
        categories=categories,
        probs=y_probs
    )

    report = {
        "model_name": model_path.stem if model_path.is_file() else model_path.name,
        "model_format": "ONNX" if is_onnx else "PyTorch",
        "model_size_mb": model_size_mb,
        "dataset_name": data_file.name,
        "total_evaluated": len(y_true),
        "decision_threshold": round(active_threshold, 2),
        "latency_profile": latency_stats,
        "metrics": metrics,
        "false_positive_analysis": {
            "total_false_positives": len(false_positives),
            "critical_hard_negative_fps_count": len(critical_hard_neg_fps),
            "critical_hard_negative_fps": critical_hard_neg_fps,
            "false_positives_sample": false_positives[:10]
        },
        "false_negative_analysis": {
            "total_false_negatives": len(false_negatives),
            "false_negatives_sample": false_negatives[:10]
        }
    }

    report_str = format_metrics_report(
        metrics,
        title=f"SATARK EVALUATION: {model_path.name} (Threshold={active_threshold:.2f}, Size={model_size_mb:.1f}MB)"
    )
    print("\n" + report_str + "\n")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Evaluation report written to: {output_file}")

    return report


def main():
    args = parse_args()
    model_path = Path(args.model_path)
    data_file = Path(args.data_file)
    output_file = Path(args.output_file)

    if not model_path.exists():
        logger.error(f"Model artifact not found at: {model_path}")
        sys.exit(1)

    if not data_file.exists():
        logger.error(f"Evaluation dataset not found at: {data_file}")
        sys.exit(1)

    evaluate_model(
        model_path=model_path,
        data_file=data_file,
        output_file=output_file,
        tokenizer_path=args.tokenizer_path,
        model_name=args.model_name,
        threshold=args.threshold,
        device=args.device
    )


if __name__ == "__main__":
    main()
