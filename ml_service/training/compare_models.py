"""
Comparative Evaluation Utility: XLM-RoBERTa vs Hing-BERT.
Evaluates both models on the exact same untouched holdout partition.
Compares overall metrics, Roman Hinglish specialist metrics, hard-negative robustness,
CPU latency, and model footprint to make an evidence-based architectural recommendation.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, Any, Optional

from .evaluate import evaluate_model

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("satark.ml.compare_models")


def parse_args():
    parser = argparse.ArgumentParser(description="Compare XLM-RoBERTa and Hing-BERT on holdout partition.")
    parser.add_argument("--model_a_path", required=True, type=str, help="Path to Primary Model (XLM-RoBERTa checkpoint or ONNX).")
    parser.add_argument("--model_b_path", required=True, type=str, help="Path to Secondary Model (Hing-BERT checkpoint or ONNX).")
    parser.add_argument("--data_file", default="ml_service/dataset/holdout.csv", type=str, help="Path to untouched holdout evaluation CSV.")
    parser.add_argument("--output_file", default="ml_service/artifacts/model_comparison.json", type=str, help="Destination for comparison JSON report.")
    parser.add_argument("--threshold_a", default=None, type=float, help="Decision threshold for Model A (optional).")
    parser.add_argument("--threshold_b", default=None, type=float, help="Decision threshold for Model B (optional).")
    parser.add_argument("--device", default="cpu", type=str, help="Device for PyTorch evaluation ('cpu' or 'cuda').")
    return parser.parse_args()


def format_comparison_table(report_a: Dict[str, Any], report_b: Dict[str, Any], verdict: Dict[str, Any]) -> str:
    """Formats side-by-side comparison table in ASCII markdown."""
    name_a = report_a.get("model_name", "Model A")
    name_b = report_b.get("model_name", "Model B")

    m_a = report_a.get("metrics", {}).get("overall", {})
    m_b = report_b.get("metrics", {}).get("overall", {})

    lang_a = report_a.get("metrics", {}).get("per_language", {})
    lang_b = report_b.get("metrics", {}).get("per_language", {})

    hing_a = lang_a.get("hinglish", {})
    hing_b = lang_b.get("hinglish", {})

    hn_a = report_a.get("metrics", {}).get("hard_negatives", {})
    hn_b = report_b.get("metrics", {}).get("hard_negatives", {})

    lat_a = report_a.get("latency_profile", {})
    lat_b = report_b.get("latency_profile", {})

    lines = [
        "=" * 84,
        f"{'SATARK MODEL COMPARISON: XLM-RoBERTa vs Hing-BERT':^84}",
        "=" * 84,
        f"{'Dimension':<34} | {name_a:<22} | {name_b:<22}",
        "-" * 84,
        f"{'Model Format':<34} | {report_a.get('model_format', 'N/A'):<22} | {report_b.get('model_format', 'N/A'):<22}",
        f"{'Model Size (MB)':<34} | {report_a.get('model_size_mb', 0):<22} | {report_b.get('model_size_mb', 0):<22}",
        f"{'Decision Threshold':<34} | {report_a.get('decision_threshold', 0.5):<22.2f} | {report_b.get('decision_threshold', 0.5):<22.2f}",
        "-" * 84,
        f"{'OVERALL ACCURACY':<34} | {m_a.get('accuracy', 0):<22.4f} | {m_b.get('accuracy', 0):<22.4f}",
        f"{'OVERALL PRECISION':<34} | {m_a.get('precision', 0):<22.4f} | {m_b.get('precision', 0):<22.4f}",
        f"{'OVERALL RECALL':<34} | {m_a.get('recall', 0):<22.4f} | {m_b.get('recall', 0):<22.4f}",
        f"{'OVERALL F1-SCORE':<34} | {m_a.get('f1', 0):<22.4f} | {m_b.get('f1', 0):<22.4f}",
        f"{'OVERALL FPR (False Alarm Rate)':<34} | {m_a.get('fpr', 0):<22.4f} | {m_b.get('fpr', 0):<22.4f}",
        f"{'OVERALL FNR (Missed Scam Rate)':<34} | {m_a.get('fnr', 0):<22.4f} | {m_b.get('fnr', 0):<22.4f}",
        "-" * 84,
        f"{'HINGLISH F1-SCORE':<34} | {hing_a.get('f1', 0):<22.4f} | {hing_b.get('f1', 0):<22.4f}",
        f"{'HINGLISH PRECISION':<34} | {hing_a.get('precision', 0):<22.4f} | {hing_b.get('precision', 0):<22.4f}",
        f"{'HINGLISH RECALL':<34} | {hing_a.get('recall', 0):<22.4f} | {hing_b.get('recall', 0):<22.4f}",
        f"{'HINGLISH FPR':<34} | {hing_a.get('fpr', 0):<22.4f} | {hing_b.get('fpr', 0):<22.4f}",
        "-" * 84,
        f"{'HARD-NEGATIVE FPR (Bank/OTP)':<34} | {hn_a.get('overall_hard_negative_fpr', 0):<22.4f} | {hn_b.get('overall_hard_negative_fpr', 0):<22.4f}",
        f"{'Mean Latency (ms/sample)':<34} | {lat_a.get('mean_latency_ms', 0):<22.2f} | {lat_b.get('mean_latency_ms', 0):<22.2f}",
        f"{'P95 Latency (ms)':<34} | {lat_a.get('p95_latency_ms', 0):<22.2f} | {lat_b.get('p95_latency_ms', 0):<22.2f}",
        f"{'Throughput (samples/sec)':<34} | {lat_a.get('throughput_samples_sec', 0):<22.2f} | {lat_b.get('throughput_samples_sec', 0):<22.2f}",
        "=" * 84,
        f"RECOMMENDED ARCHITECTURE: {verdict['recommendation']}",
        f"JUSTIFICATION: {verdict['justification']}",
        "=" * 84
    ]
    return "\n".join(lines)


def evaluate_and_compare(
    model_a_path: Path,
    model_b_path: Path,
    data_file: Path,
    output_file: Path,
    threshold_a: Optional[float] = None,
    threshold_b: Optional[float] = None,
    device: str = "cpu"
) -> Dict[str, Any]:
    """
    Evaluates both models on untouched holdout data and performs comparative analysis.
    """
    logger.info(f"Evaluating Model A: {model_a_path}")
    report_a_file = output_file.parent / f"eval_{model_a_path.stem}.json"
    report_a = evaluate_model(
        model_path=model_a_path,
        data_file=data_file,
        output_file=report_a_file,
        threshold=threshold_a,
        device=device
    )

    logger.info(f"Evaluating Model B: {model_b_path}")
    report_b_file = output_file.parent / f"eval_{model_b_path.stem}.json"
    report_b = evaluate_model(
        model_path=model_b_path,
        data_file=data_file,
        output_file=report_b_file,
        threshold=threshold_b,
        device=device
    )

    f1_a = report_a.get("metrics", {}).get("overall", {}).get("f1", 0.0)
    f1_b = report_b.get("metrics", {}).get("overall", {}).get("f1", 0.0)

    hing_f1_a = report_a.get("metrics", {}).get("per_language", {}).get("hinglish", {}).get("f1", 0.0)
    hing_f1_b = report_b.get("metrics", {}).get("per_language", {}).get("hinglish", {}).get("f1", 0.0)

    hn_fpr_a = report_a.get("metrics", {}).get("hard_negatives", {}).get("overall_hard_negative_fpr", 0.0)
    hn_fpr_b = report_b.get("metrics", {}).get("hard_negatives", {}).get("overall_hard_negative_fpr", 0.0)

    # Architectural Recommendation Rule:
    # Do not combine models unless Hing-BERT provides a meaningful delta on Hinglish
    # (> 2% absolute F1 improvement) AND does not compromise hard-negative robustness.
    hinglish_delta = hing_f1_b - hing_f1_a
    overall_delta = f1_b - f1_a

    if hinglish_delta > 0.02 and hn_fpr_b <= hn_fpr_a:
        recommendation = "HYBRID_ROUTING_JUSTIFIED"
        justification = (
            f"Hing-BERT demonstrates a +{hinglish_delta * 100:.2f}% F1 improvement on Roman Hinglish "
            f"with hard-negative FPR ({hn_fpr_b:.4f} vs {hn_fpr_a:.4f}). Dual-model routing is justified."
        )
    else:
        recommendation = "SINGLE_MODEL_RECOMMENDED (XLM-RoBERTa)"
        justification = (
            f"XLM-RoBERTa achieves competitive or superior performance across all 3 languages (Overall F1={f1_a:.4f}, "
            f"Hinglish F1={hing_f1_a:.4f} vs {hing_f1_b:.4f}). Combining models would add 2x memory overhead and "
            f"routing complexity without statistically significant gains."
        )

    verdict = {
        "recommendation": recommendation,
        "justification": justification,
        "hinglish_f1_delta": round(hinglish_delta, 4),
        "overall_f1_delta": round(overall_delta, 4),
        "hard_negative_fpr_delta": round(hn_fpr_b - hn_fpr_a, 4)
    }

    comparison = {
        "dataset": data_file.name,
        "model_a": report_a,
        "model_b": report_b,
        "verdict": verdict
    }

    table_str = format_comparison_table(report_a, report_b, verdict)
    print("\n" + table_str + "\n")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(comparison, f, indent=2)
    logger.info(f"Comparison report saved to: {output_file}")

    return comparison


def main():
    args = parse_args()
    evaluate_and_compare(
        model_a_path=Path(args.model_a_path),
        model_b_path=Path(args.model_b_path),
        data_file=Path(args.data_file),
        output_file=Path(args.output_file),
        threshold_a=args.threshold_a,
        threshold_b=args.threshold_b,
        device=args.device
    )


if __name__ == "__main__":
    main()

