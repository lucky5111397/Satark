"""
INT8 Dynamic Quantization and Optimization Pipeline.
Quantizes FP32 ONNX graph into lightweight INT8 representations for fast,
low-memory CPU execution on standard laptop and student hackathon hardware.
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("satark.ml.quantize_onnx")


def parse_args():
    parser = argparse.ArgumentParser(description="Quantize ONNX model to INT8 for optimized CPU inference.")
    parser.add_argument(
        "--input_file",
        default="ml_service/artifacts/model.onnx",
        type=str,
        help="Path to FP32 ONNX model file."
    )
    parser.add_argument(
        "--output_file",
        default="ml_service/artifacts/model_quantized.onnx",
        type=str,
        help="Destination path for INT8 quantized ONNX model."
    )
    return parser.parse_args()


def quantize_model(input_file: Path, output_file: Path):
    if not input_file.exists():
        logger.error(f"Input ONNX model not found: {input_file}")
        sys.exit(1)

    try:
        import onnxruntime as ort
        from onnxruntime.quantization import quantize_dynamic, QuantType
        import numpy as np
    except ImportError as e:
        logger.error(f"Missing quantization dependencies: {e}")
        logger.error("Install: pip install onnxruntime")
        sys.exit(1)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    orig_size_mb = input_file.stat().st_size / (1024 * 1024)
    logger.info(f"Applying INT8 dynamic quantization to '{input_file}' ({orig_size_mb:.2f} MB)...")

    # 1. Apply Dynamic Quantization
    quantize_dynamic(
        model_input=str(input_file),
        model_output=str(output_file),
        weight_type=QuantType.QInt8,
        op_types_to_quantize=["MatMul", "Gemm", "Gather"]
    )

    quant_size_mb = output_file.stat().st_size / (1024 * 1024)
    compression_ratio = orig_size_mb / max(quant_size_mb, 0.001)
    logger.info(f"Quantized model generated: {quant_size_mb:.2f} MB (Compression: {compression_ratio:.1f}x)")

    # 2. Benchmark Latency and Verify Parity
    logger.info("Benchmarking CPU latency (FP32 vs INT8)...")

    sess_fp32 = ort.InferenceSession(str(input_file), providers=["CPUExecutionProvider"])
    sess_int8 = ort.InferenceSession(str(output_file), providers=["CPUExecutionProvider"])

    input_names = [inp.name for inp in sess_fp32.get_inputs()]

    # Create dummy batch of shape [1, 128]
    dummy_input_ids = np.ones((1, 128), dtype=np.int64)
    dummy_attention_mask = np.ones((1, 128), dtype=np.int64)
    feed_dict = {"input_ids": dummy_input_ids, "attention_mask": dummy_attention_mask}
    if "token_type_ids" in input_names:
        feed_dict["token_type_ids"] = np.zeros((1, 128), dtype=np.int64)

    # Warmup
    for _ in range(5):
        sess_fp32.run(["logits"], feed_dict)
        sess_int8.run(["logits"], feed_dict)

    # Benchmark FP32
    start = time.perf_counter()
    n_runs = 20
    for _ in range(n_runs):
        out_fp32 = sess_fp32.run(["logits"], feed_dict)
    fp32_latency = ((time.perf_counter() - start) / n_runs) * 1000.0

    # Benchmark INT8
    start = time.perf_counter()
    for _ in range(n_runs):
        out_int8 = sess_int8.run(["logits"], feed_dict)
    int8_latency = ((time.perf_counter() - start) / n_runs) * 1000.0

    speedup = fp32_latency / max(int8_latency, 0.001)

    # Logits parity check
    logits_fp32 = out_fp32[0]
    logits_int8 = out_int8[0]
    class_fp32 = int(np.argmax(logits_fp32, axis=-1)[0])
    class_int8 = int(np.argmax(logits_int8, axis=-1)[0])
    label_match = class_fp32 == class_int8

    report = {
        "original_size_mb": round(orig_size_mb, 2),
        "quantized_size_mb": round(quant_size_mb, 2),
        "compression_ratio": round(compression_ratio, 2),
        "fp32_avg_latency_ms": round(fp32_latency, 2),
        "int8_avg_latency_ms": round(int8_latency, 2),
        "speedup": round(speedup, 2),
        "label_parity_verified": label_match
    }

    report_path = output_file.parent / "quantization_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 70)
    print("SATARK ONNX QUANTIZATION REPORT")
    print("=" * 70)
    print(f"FP32 Size:     {orig_size_mb:.2f} MB")
    print(f"INT8 Size:     {quant_size_mb:.2f} MB (Reduced by {(1 - quant_size_mb/orig_size_mb)*100:.1f}%)")
    print(f"FP32 Latency:  {fp32_latency:.2f} ms")
    print(f"INT8 Latency:  {int8_latency:.2f} ms ({speedup:.1f}x speedup)")
    print(f"Parity Match:  {'✅ PASSED' if label_match else '⚠️ Label Mismatch'}")
    print("=" * 70 + "\n")


def main():
    args = parse_args()
    quantize_model(Path(args.input_file), Path(args.output_file))


if __name__ == "__main__":
    main()

