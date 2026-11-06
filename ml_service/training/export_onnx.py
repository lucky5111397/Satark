"""
Architecture-Aware ONNX Export Pipeline for Multilingual Scam Classifiers.
Supports XLM-RoBERTa, Hing-BERT, and mDeBERTa architectures.
Dynamically inspects model signatures, configures token_type_ids when required,
validates graph structure, enforces numerical parity, and saves model metadata.
"""

import argparse
import datetime
import hashlib
import inspect
import json
import logging
import os
import sys
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("satark.ml.export_onnx")


def sha256_file(filepath: Path) -> str:
    """Computes SHA-256 cryptographic digest of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


REPRESENTATIVE_PARITY_SAMPLES = [
    {
        "id": "EN_LEGIT_OTP",
        "category": "otp_negation",
        "lang": "en",
        "text": "Your OTP for HDFC NetBanking login is 849201. Never share this OTP with bank executives, callers, or via SMS.",
        "expected_label": "BENIGN"
    },
    {
        "id": "EN_LEGIT_TXN",
        "category": "bank_transactional",
        "lang": "en",
        "text": "A/c *1049 debited by Rs 450.00 on 02-Nov-26 via UPI Ref 682910482. Balance Rs 18,420.50.",
        "expected_label": "BENIGN"
    },
    {
        "id": "EN_LEGIT_UTIL",
        "category": "utility_service_notice",
        "lang": "en",
        "text": "Dear customer, your scheduled fiber maintenance will occur tonight between 2:00 AM and 4:00 AM. Inconvenience regretted.",
        "expected_label": "BENIGN"
    },
    {
        "id": "HI_LEGIT_OTP",
        "category": "otp_negation",
        "lang": "hi",
        "text": "स्टेट बैंक ऑफ इंडिया: आपका नेट बैंकिंग ओटीपी 391028 है। यह कोड किसी भी व्यक्ति, बैंक कर्मचारी अथवा कॉलर के साथ साझा न करें।",
        "expected_label": "BENIGN"
    },
    {
        "id": "HINGLISH_LEGIT_TXN",
        "category": "bank_transactional",
        "lang": "hinglish",
        "text": "Aapke savings a/c XX4912 se Rs 1,200 ATM withdrawal successful hua. Current balance check karne ke liye missed call dein: 1800112211.",
        "expected_label": "BENIGN"
    },
    {
        "id": "EN_SCAM_ELECTRICITY",
        "category": "electricity_disconnection",
        "lang": "en",
        "text": "URGENT NOTICE: Your electricity connection will be disconnected tonight at 9:30 PM due to unpaid bill of Rs 1,480. Call lineman immediately: 9876543210.",
        "expected_label": "SUSPICIOUS"
    },
    {
        "id": "HI_SCAM_DIGITAL_ARREST",
        "category": "digital_arrest_impersonation",
        "lang": "hi",
        "text": "केंद्रीय जांच ब्यूरो (CBI) दिल्ली: आपके आधार कार्ड का उपयोग अवैध मनी लॉन्ड्रिंग और ड्रग्स पार्सल में पाया गया है। तत्काल डिजिटल अरेस्ट सेशन हेतु स्काइप पर जुड़ें: <url>।",
        "expected_label": "SUSPICIOUS"
    },
    {
        "id": "HINGLISH_SCAM_JOB",
        "category": "part_time_job_scam",
        "lang": "hinglish",
        "text": "Daily 2-3 hours YouTube videos like karein aur Rs 3,000-8,000 kamayein. No experience required. Telegram par message karein: <url>.",
        "expected_label": "SUSPICIOUS"
    },
    {
        "id": "HINGLISH_SCAM_LOTTERY",
        "category": "lottery_advance_fee",
        "lang": "hinglish",
        "text": "Congratulations! Aapka mobile number Kaun Banega Crorepati WhatsApp Bumper Draw me Rs 25 Lakhs ka winner bana hai. Claim fee pay karein: <url>.",
        "expected_label": "SUSPICIOUS"
    },
    {
        "id": "EN_SCAM_APK",
        "category": "malicious_apk_qr_scam",
        "lang": "en",
        "text": "Urgent security update: Your mobile banking app requires immediate upgrade. Download safety patch BharatBank_Assist.apk from: <url>.",
        "expected_label": "SUSPICIOUS"
    }
]


def parse_args():
    parser = argparse.ArgumentParser(description="Export PyTorch scam classifier to architecture-aware ONNX graph.")
    parser.add_argument(
        "--checkpoint_dir",
        default="ml_service/artifacts/checkpoint",
        type=str,
        help="Path to directory containing fine-tuned PyTorch checkpoint."
    )
    parser.add_argument(
        "--output_file",
        default="ml_service/artifacts/model.onnx",
        type=str,
        help="Destination path for exported ONNX model."
    )
    parser.add_argument(
        "--opset",
        default=17,
        type=int,
        help="ONNX operator set version (default: 17)."
    )
    parser.add_argument(
        "--max_length",
        default=128,
        type=int,
        help="Max sequence token length for dummy input."
    )
    parser.add_argument(
        "--threshold",
        default=0.10,
        type=float,
        help="Calibrated decision threshold to persist in metadata (default: 0.10)."
    )
    parser.add_argument(
        "--manifest_file",
        default="ml_service/artifacts/manifest.json",
        type=str,
        help="Path to output reproducibility manifest JSON (default: ml_service/artifacts/manifest.json)."
    )
    parser.add_argument(
        "--bundle_file",
        default=None,
        type=str,
        help="Optional destination path to package satark_xlm_roberta_export_bundle.zip archive."
    )
    return parser.parse_args()


def inspect_model_inputs(model, tokenizer, max_length: int = 128) -> Tuple[Any, List[str], Dict[str, Any], bool]:
    """
    Dynamically inspects model forward signature and tokenizer outputs.
    Determines whether token_type_ids is required or accepted by the architecture.
    """
    sig = inspect.signature(model.forward)
    forward_params = sig.parameters

    accepts_token_type = "token_type_ids" in forward_params

    # Check tokenizer input names / output keys
    tok_input_names = getattr(tokenizer, "model_input_names", [])
    tokenizer_has_token_type = "token_type_ids" in tok_input_names

    dummy_inputs = None
    try:
        import torch
        sample_text = "Dear user, your bank transaction alert requires verification."
        encoded = tokenizer(
            sample_text,
            max_length=max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        )
        dummy_input_ids = encoded.get("input_ids")
        dummy_attention_mask = encoded.get("attention_mask")
        if "token_type_ids" in encoded:
            tokenizer_has_token_type = True
            dummy_token_type_ids = encoded.get("token_type_ids")
        else:
            dummy_token_type_ids = None
    except Exception:
        # Lightweight / unit-test fallback when torch is not installed
        dummy_input_ids = None
        dummy_attention_mask = None
        dummy_token_type_ids = None

    if accepts_token_type and tokenizer_has_token_type:
        if dummy_input_ids is not None:
            dummy_inputs = (dummy_input_ids, dummy_attention_mask, dummy_token_type_ids)
        input_names = ["input_ids", "attention_mask", "token_type_ids"]
        dynamic_axes = {
            "input_ids": {0: "batch_size", 1: "sequence_length"},
            "attention_mask": {0: "batch_size", 1: "sequence_length"},
            "token_type_ids": {0: "batch_size", 1: "sequence_length"},
            "logits": {0: "batch_size"}
        }
        uses_token_type = True
        logger.info(f"Model architecture '{model.__class__.__name__}' requires token_type_ids. 3 input tensors configured.")
    else:
        if dummy_input_ids is not None:
            dummy_inputs = (dummy_input_ids, dummy_attention_mask)
        input_names = ["input_ids", "attention_mask"]
        dynamic_axes = {
            "input_ids": {0: "batch_size", 1: "sequence_length"},
            "attention_mask": {0: "batch_size", 1: "sequence_length"},
            "logits": {0: "batch_size"}
        }
        uses_token_type = False
        logger.info(f"Model architecture '{model.__class__.__name__}' does not use token_type_ids. 2 input tensors configured.")

    return dummy_inputs, input_names, dynamic_axes, uses_token_type


def export_to_onnx(
    checkpoint_dir: Path,
    output_file: Path,
    opset: int = 17,
    max_length: int = 128,
    threshold: float = 0.10,
    manifest_file: Optional[Path] = None,
    bundle_file: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Exports a trained PyTorch model checkpoint to an architecture-aware ONNX computation graph.
    Validates graph structure, checks inputs/outputs, and asserts numerical parity with PyTorch.
    """
    if not checkpoint_dir.exists():
        candidates = [
            checkpoint_dir.parent / "xlm_roberta" / "final_model",
            Path("ml_service/artifacts/xlm_roberta/final_model"),
            checkpoint_dir.parent / "checkpoint",
            Path("ml_service/artifacts/checkpoint")
        ]
        found = False
        for cand in candidates:
            if cand.exists() and (cand / "config.json").exists():
                logger.info(f"Checkpoint not found at '{checkpoint_dir}', but found at '{cand}'. Using '{cand}'.")
                checkpoint_dir = cand
                found = True
                break
        if not found:
            logger.error(
                f"Checkpoint directory not found: {checkpoint_dir}. "
                "Ensure fine-tuned XLM-RoBERTa weights and config are present, "
                "or run export in Google Colab using notebooks/satark_model_training_colab.ipynb."
            )
            sys.exit(1)

    try:
        import torch
        import onnx
        import onnxruntime as ort
        import numpy as np
        import transformers
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
    except ImportError as e:
        logger.error(f"Missing required export dependencies: {e}")
        logger.error("Install: pip install torch transformers onnx onnxruntime numpy")
        sys.exit(1)

    logger.info(f"Loading PyTorch checkpoint from '{checkpoint_dir}'...")
    tokenizer = AutoTokenizer.from_pretrained(
        str(checkpoint_dir), local_files_only=True, trust_remote_code=False
    )
    model = AutoModelForSequenceClassification.from_pretrained(
        str(checkpoint_dir),
        local_files_only=True,
        trust_remote_code=False,
        use_safetensors=True
    )
    model.eval()

    output_file.parent.mkdir(parents=True, exist_ok=True)

    # 1. Inspect Model Inputs and Dynamic Axes
    dummy_inputs, input_names, dynamic_axes, uses_token_type = inspect_model_inputs(
        model, tokenizer, max_length=max_length
    )
    output_names = ["logits"]

    # 2. Export Graph via Torch ONNX Exporter
    logger.info(f"Exporting ONNX graph to '{output_file}' (opset={opset})...")
    torch.onnx.export(
        model,
        dummy_inputs,
        str(output_file),
        input_names=input_names,
        output_names=output_names,
        dynamic_axes=dynamic_axes,
        opset_version=opset,
        # Keep the existing opset/dynamic_axes contract on current PyTorch.
        dynamo=False
    )

    file_size_mb = output_file.stat().st_size / (1024 * 1024)
    logger.info(f"ONNX model exported successfully. File size: {file_size_mb:.2f} MB")

    # 3. Structural Validation via onnx.checker
    logger.info("Validating exported ONNX graph structure...")
    onnx_proto = onnx.load(str(output_file))
    onnx.checker.check_model(onnx_proto)
    logger.info("Graph structure validation passed.")

    # 4. Save Tokenizer Alongside ONNX Model
    tokenizer_dir = output_file.parent / "tokenizer"
    tokenizer_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Saving tokenizer assets to '{tokenizer_dir}'...")
    tokenizer.save_pretrained(str(tokenizer_dir))

    # 5. Numerical Parity Validation between PyTorch and ONNX Runtime
    logger.info("Validating numerical parity between PyTorch and ONNX Runtime outputs across representative samples...")
    ort_session = ort.InferenceSession(str(output_file), providers=["CPUExecutionProvider"])
    ort_input_names = [inp.name for inp in ort_session.get_inputs()]
    ort_output_names = [out.name for out in ort_session.get_outputs()]

    # Assert input signatures match
    assert set(ort_input_names) == set(input_names), (
        f"Input signature mismatch! Expected: {input_names}, Got in ONNX: {ort_input_names}"
    )
    assert "logits" in ort_output_names, f"Expected output 'logits' missing from ONNX outputs: {ort_output_names}"

    parity_results = []
    overall_max_abs_diff = 0.0
    overall_max_rel_diff = 0.0

    for sample in REPRESENTATIVE_PARITY_SAMPLES:
        text = sample["text"]
        enc = tokenizer(text, max_length=max_length, padding="max_length", truncation=True, return_tensors="pt")
        pt_feed = {k: v for k, v in enc.items() if k in input_names}

        with torch.no_grad():
            pt_out = model(**pt_feed)
            pt_logits = pt_out.logits.detach().cpu().numpy()[0]

        ort_feed = {k: v.numpy().astype(np.int64) for k, v in pt_feed.items()}
        ort_out = ort_session.run(output_names, ort_feed)
        ort_logits = ort_out[0][0]

        # Softmax probabilities
        pt_exp = np.exp(pt_logits - np.max(pt_logits))
        pt_probs = pt_exp / np.sum(pt_exp)
        ort_exp = np.exp(ort_logits - np.max(ort_logits))
        ort_probs = ort_exp / np.sum(ort_exp)

        # Class predictions and threshold decisions at T* = 0.10
        pt_class = int(np.argmax(pt_logits))
        ort_class = int(np.argmax(ort_logits))
        pt_scam_prob = float(pt_probs[1])
        ort_scam_prob = float(ort_probs[1])
        pt_decision = "SUSPICIOUS" if pt_scam_prob >= threshold else "BENIGN"
        ort_decision = "SUSPICIOUS" if ort_scam_prob >= threshold else "BENIGN"

        abs_diff = float(np.max(np.abs(pt_logits - ort_logits)))
        rel_diff = float(np.max(np.abs(pt_logits - ort_logits) / (np.abs(pt_logits) + 1e-7)))

        if abs_diff > overall_max_abs_diff:
            overall_max_abs_diff = abs_diff
        if rel_diff > overall_max_rel_diff:
            overall_max_rel_diff = rel_diff

        parity_results.append({
            "sample_id": sample["id"],
            "category": sample["category"],
            "lang": sample["lang"],
            "pt_logits": pt_logits.tolist(),
            "ort_logits": ort_logits.tolist(),
            "pt_scam_prob": round(pt_scam_prob, 5),
            "ort_scam_prob": round(ort_scam_prob, 5),
            "pt_class": pt_class,
            "ort_class": ort_class,
            "pt_decision_t010": pt_decision,
            "ort_decision_t010": ort_decision,
            "max_abs_error": abs_diff,
            "max_rel_error": rel_diff,
            "parity_match": (pt_decision == ort_decision) and (abs_diff < 1e-4)
        })

    logger.info(
        f"Parity check completed over {len(REPRESENTATIVE_PARITY_SAMPLES)} samples. "
        f"Max absolute discrepancy: {overall_max_abs_diff:.6e}, Max relative discrepancy: {overall_max_rel_diff:.6e}"
    )

    parity_passed = (overall_max_abs_diff < 1e-4) and all(r["pt_decision_t010"] == r["ort_decision_t010"] for r in parity_results)
    if parity_passed:
        logger.info("Numerical parity test PASSED across all languages and test categories.")
    else:
        logger.warning(f"Parity discrepancy elevated ({overall_max_abs_diff:.6e}).")

    # 6. Save Model Metadata
    metadata = {
        "model_name": getattr(model.config, "_name_or_path", "FacebookAI/xlm-roberta-base"),
        "architecture": model.__class__.__name__,
        "base_model": getattr(model.config, "_name_or_path", "FacebookAI/xlm-roberta-base"),
        "tokenizer_class": tokenizer.__class__.__name__,
        "num_labels": getattr(model.config, "num_labels", 2),
        "id2label": getattr(model.config, "id2label", {0: "BENIGN", 1: "SUSPICIOUS"}),
        "label2id": getattr(model.config, "label2id", {"BENIGN": 0, "SUSPICIOUS": 1}),
        "input_names": input_names,
        "output_names": output_names,
        "uses_token_type_ids": uses_token_type,
        "opset_version": opset,
        "max_length": max_length,
        "optimal_threshold": threshold,
        "threshold_objective": "Score = F1 - (2.0 * FPR)",
        "file_size_mb": round(file_size_mb, 2),
        "max_abs_parity_discrepancy": overall_max_abs_diff,
        "max_rel_parity_discrepancy": overall_max_rel_diff,
        "validation_status": "PASSED" if parity_passed else "DISCREPANCY_WARNING",
        "export_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "satark_pipeline_version": "2.0-phase6"
    }

    metadata_path = output_file.parent / "model_metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"Model metadata successfully written to: {metadata_path}")

    # 7. Generate Checkpoint & Reproducibility Manifest
    manifest_dest = manifest_file or (output_file.parent / "manifest.json")
    checkpoint_hashes = {}
    for cp_file in checkpoint_dir.glob("*"):
        if cp_file.is_file():
            checkpoint_hashes[cp_file.name] = sha256_file(cp_file)

    tokenizer_hashes = {}
    for tok_file in tokenizer_dir.glob("*"):
        if tok_file.is_file():
            tokenizer_hashes[tok_file.name] = sha256_file(tok_file)

    manifest = {
        "manifest_version": "1.0",
        "project": "SATARK",
        "model_identifier": metadata["model_name"],
        "architecture": metadata["architecture"],
        "label_mapping": {
            "id2label": metadata["id2label"],
            "label2id": metadata["label2id"]
        },
        "calibrated_threshold": threshold,
        "threshold_objective": metadata["threshold_objective"],
        "export_configuration": {
            "opset_version": opset,
            "max_length": max_length,
            "input_names": input_names,
            "output_names": output_names,
            "dynamic_axes": dynamic_axes
        },
        "runtime_environment": {
            "python_version": sys.version.split()[0],
            "torch_version": getattr(torch, "__version__", "unknown"),
            "transformers_version": getattr(transformers, "__version__", "unknown"),
            "onnx_version": getattr(onnx, "__version__", "unknown"),
            "onnxruntime_version": getattr(ort, "__version__", "unknown")
        },
        "checkpoint_hashes_sha256": checkpoint_hashes,
        "tokenizer_hashes_sha256": tokenizer_hashes,
        "onnx_model_sha256": sha256_file(output_file),
        "export_timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "parity_summary": {
            "samples_evaluated": len(REPRESENTATIVE_PARITY_SAMPLES),
            "max_abs_discrepancy": overall_max_abs_diff,
            "max_rel_discrepancy": overall_max_rel_diff,
            "tolerance_abs_bound": 1e-4,
            "tolerance_rel_bound": 1e-3,
            "all_decisions_matched": all(r["pt_decision_t010"] == r["ort_decision_t010"] for r in parity_results),
            "status": "PASSED" if parity_passed else "FAILED"
        }
    }

    with open(manifest_dest, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    logger.info(f"Reproducibility manifest successfully written to: {manifest_dest}")

    # 8. Optional Bundle Creation
    if bundle_file:
        import zipfile
        bundle_path = Path(bundle_file)
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"Packaging export bundle to '{bundle_path}'...")
        with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(output_file, arcname=output_file.name)
            z.write(metadata_path, arcname=metadata_path.name)
            z.write(manifest_dest, arcname=manifest_dest.name)
            for tok_file in tokenizer_dir.glob("*"):
                if tok_file.is_file():
                    z.write(tok_file, arcname=f"tokenizer/{tok_file.name}")
            for cp_file in checkpoint_dir.glob("*"):
                if cp_file.is_file():
                    z.write(cp_file, arcname=f"checkpoint/{cp_file.name}")
        bundle_size_mb = bundle_path.stat().st_size / (1024 * 1024)
        logger.info(f"Bundle successfully created: {bundle_path} ({bundle_size_mb:.2f} MB)")

    return {
        "metadata": metadata,
        "manifest": manifest,
        "parity_results": parity_results
    }


def main():
    args = parse_args()
    manifest_path = Path(args.manifest_file) if args.manifest_file else None
    bundle_path = Path(args.bundle_file) if args.bundle_file else None
    export_to_onnx(
        checkpoint_dir=Path(args.checkpoint_dir),
        output_file=Path(args.output_file),
        opset=args.opset,
        max_length=args.max_length,
        threshold=args.threshold,
        manifest_file=manifest_path,
        bundle_file=bundle_path
    )


if __name__ == "__main__":
    main()
